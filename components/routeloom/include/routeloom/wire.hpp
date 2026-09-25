#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

// "Wire v2" frame format for the CORE_FIXED_250 profile. All fields are
// fixed-width big-endian (network byte order). The crypto suite itself is still
// pending (G-SEC); the layout below does not depend on the chosen suite.
//
// v2 vs v1 (issue #29): epochs widen 16 -> 32 bits so a per-boot epoch can
// never wrap in a device lifetime, and the crypto counters narrow 64 -> 48
// bits (2.8e14 frames per epoch) so the header stays 88 bytes and the full
// 128-byte payload still fits the 250-byte ESP-NOW body.
//
// Header layout (kHeaderSize = 88 bytes):
//   offset  size  field                        end-immutable / hop-mutable
//   0       2     magic 0x524C "RL"            immutable
//   2       1     major version (= 1)          immutable
//   3       1     minor version (= 0)          immutable
//   4       1     frame type                   immutable
//   5       1     flags                        immutable
//   6       1     delivery class               immutable (delivery contract)
//   7       1     delivery round               hop-mutable
//   8       1     hop remaining                hop-mutable
//   9       1     reserved, must be 0          -
//   10      2     payload length               immutable (excludes AEAD tags)
//   12      4     network id (low 32 bits)     immutable
//   16      8     origin node id               immutable
//   24      8     destination node id          immutable (bound destination)
//   32      8     previous hop                 hop-mutable
//   40      8     next hop                     hop-mutable
//   48      4     message session (boot session of the origin)   immutable
//   52      8     message sequence             immutable
//   60      4     remaining deadline ms        hop-mutable (forwarding budget)
//   64      4     original lifetime ms         immutable
//   68      4     link epoch                   hop-mutable
//   72      4     end epoch                    immutable
//   76      6     link crypto counter (u48)    hop-mutable
//   82      6     end crypto counter (u48)     immutable
//   88      n     link ciphertext: payload [+ end tag if kFlagEndProtected]
//   88+n    16    link AEAD tag (AAD covers the complete 88-byte header)
//
// Message ID = origin + session + sequence, delivery round, crypto counters and
// the boot session are distinct fields and must not be conflated.
//
// The link (hop) AEAD authenticates the entire header plus the link plaintext.
// The end-to-end AEAD, when kFlagEndProtected is set, authenticates only the
// end-immutable subset listed above (see protocol/semantics.json end_immutable)
// plus version, frame type, flags, end epoch/counter and payload length — the
// exact ordered layout is protocol/semantics.json end_aad_fields, checked
// against make_end_aad() by tools/check_review_contracts.py. Hop-mutable
// fields must never enter the end AAD, or relays could not update them.
namespace routeloom::wire {

constexpr std::uint16_t kMagic = 0x524c;  // "RL"
constexpr std::uint8_t kMajor = 2;
constexpr std::uint8_t kMinor = 0;
constexpr std::size_t kHeaderSize = 88;
constexpr std::uint8_t kFlagEndProtected = 0x01;  // all other flag bits reserved, must be 0
// Crypto counters are u48 on the wire: routeloom::kMaxCryptoCounter.
using routeloom::kMaxCryptoCounter;

// A 128-byte application payload plus the header, the end-to-end tag and the
// link tag must fit the 250-byte ESP-NOW body (248 bytes total).
static_assert(kHeaderSize + kMaxApplicationPayload + 2 * kAeadTagSize <= kMaxEspNowBody,
              "wire v2 envelope must fit the 250-byte ESP-NOW body");

struct Header {
  FrameType type{FrameType::Data};
  std::uint8_t flags{0};
  DeliveryClass delivery{DeliveryClass::Reliable};
  std::uint8_t delivery_round{0};
  std::uint8_t hop_remaining{kDefaultHopLimit};
  std::uint16_t payload_length{0};
  NetworkId network{0};  // v1 encodes the low 32 bits; upper bits must be zero.
  NodeId origin{kInvalidNodeId};
  NodeId destination{kInvalidNodeId};
  NodeId previous_hop{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  MessageId message{};
  std::uint32_t remaining_deadline_ms{0};
  std::uint32_t original_lifetime_ms{0};
  std::uint32_t link_epoch{0};
  std::uint32_t end_epoch{0};
  std::uint64_t link_counter{0};  // <= kMaxCryptoCounter
  std::uint64_t end_counter{0};   // <= kMaxCryptoCounter
};

struct PlainFrame {
  Header header{};
  std::array<std::uint8_t, kMaxApplicationPayload> payload{};
  std::size_t payload_size{0};
};

struct LinkOpenedFrame {
  Header header{};
  std::array<std::uint8_t, kMaxApplicationPayload + kAeadTagSize> protected_payload{};
  std::size_t protected_payload_size{0};
};

using EncodedFrame = ByteBuffer<kMaxEspNowBody>;

Status validate_header(const Header& header) noexcept;
// Parses and validates the unauthenticated header (shape only, no crypto)
// so the receiver can route a broadcast-route frame to its dedicated,
// sender-gated dispatch before spending a GroupLink open on it. Fails on
// short/unknown/malformed headers exactly like open_link would.
Status peek_header(ByteView encoded, Header& header) noexcept;
// The security contexts a header is sealed/opened under: link
// (Link, network, previous_hop, next_hop, link_epoch); end (EndToEnd,
// network, origin, destination, end_epoch), or for GROUP_DATA (Group,
// network, origin, kBroadcastNodeId, end_epoch).
SecurityContext link_context(const Header& header) noexcept;
SecurityContext end_context(const Header& header) noexcept;
// Provider-owned epochs (sdk-v1/03 §8): replace header.link_epoch /
// header.end_epoch with SecurityProvider::tx_epoch() for the context's
// (scope, receiver). A provider that does not own epochs leaves the
// configured value. encode_new(), forward() and seal_group() call these
// before drawing any counter; AuthRequired means "no session yet".
Status stamp_link_epoch(Header& header, SecurityProvider& security) noexcept;
Status stamp_end_epoch(Header& header, SecurityProvider& security) noexcept;
Status encode_new(const PlainFrame& frame,
                  SecurityProvider& security,
                  EncodedFrame& output) noexcept;
// open_link authenticates a unicast immediate peer under Link. The explicit
// broadcast-route path uses GroupLink instead: it does not prove sender
// identity and must never enter the ordinary pairwise receive/telemetry path.
// Success here does NOT verify the claimed
// origin, the origin-to-destination binding or the payload end-to-end: a
// relay must never treat a link-opened frame as origin-verified. End-to-end
// origin verification exists only through open_end success at the bound
// destination.
Status open_link(ByteView encoded,
                 NodeId local_node,
                 SecurityProvider& security,
                 LinkOpenedFrame& output,
                 bool allow_broadcast_route = false) noexcept;
// open_end verifies the end-immutable header fields and payload under the
// SecurityScope::EndToEnd context bound to (origin, destination). It must be
// called only by the bound destination — it returns AuthorizationFailed for
// any other node, including relays that already opened the link layer.
Status open_end(const LinkOpenedFrame& frame,
                NodeId local_node,
                SecurityProvider& security,
                PlainFrame& output) noexcept;
// `link_epoch` is this node's configured link epoch; the provider may
// replace it with the outgoing hop's context id (stamp_link_epoch).
Status forward(const LinkOpenedFrame& input,
               NodeId local_node,
               NodeId next_hop,
               std::uint32_t link_epoch,
               std::uint32_t remaining_deadline_ms,
               SecurityProvider& security,
               EncodedFrame& output) noexcept;

// Group delivery (docs/design/sdk-v1/group-delivery.md). seal_group seals
// the end layer of a GROUP_DATA frame ONCE under SecurityScope::Group
// (end counter assigned here) and returns it shaped like a frame received by
// `local_node` (previous_hop = next_hop = local_node, hop_remaining + 1), so
// forward() re-wraps only the link layer for every child and every repair
// round: all copies of one group message share one end ciphertext.
Status seal_group(const PlainFrame& input, NodeId local_node, SecurityProvider& security,
                  LinkOpenedFrame& output) noexcept;
// Opens the group end layer of a link-opened GROUP_DATA frame. Any holder of
// the group key may call it (no destination binding to the local node); it
// proves membership of the sealer, never the origin's identity.
Status open_group(const LinkOpenedFrame& input, SecurityProvider& security,
                  PlainFrame& output) noexcept;

// TransitFailure fingerprint (m1-completion 04 §4.2): SHA256 over
// "RouteLoom/transit-fingerprint/v1" || NUL || the exact end-AAD encoding ||
// the protected payload including its end tag. Hop-mutable fields are
// excluded, so every relay on the path computes the SAME fingerprint for
// the same protected bytes — a report cannot be retargeted to a different
// operation without invalidating the fingerprint.
Status transit_fingerprint(const LinkOpenedFrame& frame,
                           std::array<std::uint8_t, 32>& out) noexcept;

}  // namespace routeloom::wire
