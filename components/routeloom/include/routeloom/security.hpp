#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// Largest crypto counter a context may issue: Wire v2 carries u48 counters
// (2.8e14 frames per epoch). A context that reaches it must move to a new
// epoch; counters are never wrapped under the same key.
constexpr std::uint64_t kMaxCryptoCounter = 0xFFFFFFFFFFFFULL;

struct SecurityContext {
  SecurityScope scope{SecurityScope::Link};
  NetworkId network{0};
  NodeId sender{kInvalidNodeId};
  NodeId receiver{kInvalidNodeId};
  std::uint32_t epoch{0};  // Wire v2: 32-bit, never wraps in a device lifetime
  std::uint32_t group_epoch{0};  // GroupLink: end_epoch (GK generation)
  std::uint32_t sender_boot{0};  // GroupEnd: message.session
  NodeId group_id{0};           // GroupEnd: full wire destination
};

// Deployment assurance level a provider is allowed to claim. The default is
// Development: only a provider implementing the qualified production profile
// (G-SEC: EDHOC/RPK device identity, audited entropy contract) may return
// Production. Anything else — including the development PSK — is EXPERIMENTAL
// and must be surfaced to operators as such.
enum class SecurityProfile : std::uint8_t {
  Development = 0,  // EXPERIMENTAL; never advertise as production-secure
  Production = 1,
};

// State of the provider-owned context a frame would be sealed under
// (sdk-v1/03 §8). Zero is None, so a zero-initialised value never claims a
// usable session.
enum class ContextState : std::uint8_t {
  None = 0,          // no context and no establishment in flight
  Establishing = 1,  // a handshake for it is in flight
  Ready = 2,         // installed and usable
  Rekeying = 3,      // usable; a replacement is being established in parallel
};

constexpr bool context_usable(const ContextState state) noexcept {
  return state == ContextState::Ready || state == ContextState::Rekeying;
}

class SecurityProvider {
 public:
  virtual ~SecurityProvider() = default;

  virtual bool ready() const noexcept = 0;
  // Deliberately defaults to Development so a provider cannot accidentally
  // claim production status by omission.
  virtual SecurityProfile security_profile() const noexcept {
    return SecurityProfile::Development;
  }
  // Session-owning providers (sdk-v1/03 §8, plan P4-1). `peer` is always the
  // receiver of the context the frame is sealed under: the next hop for
  // Link, the destination for EndToEnd, kBroadcastNodeId (the site group
  // domain) for Group.
  //
  // tx_epoch() picks the epoch stamped into an outgoing header (link_epoch
  // for Link, end_epoch for EndToEnd/Group). `epoch` enters holding the
  // caller's configured value (NodeConfig::link_epoch / end_epoch as stamped
  // in the header); a provider that does not own epochs leaves it untouched,
  // which is the default and keeps every byte on the wire unchanged. A
  // session provider writes its context id, or returns AuthRequired when no
  // usable context exists — the wire layer calls it BEFORE next_counter(),
  // so a refused frame consumes no counter. Any other error refuses the
  // frame (e.g. a context at its counter limit, 03 §9).
  virtual Status tx_epoch(SecurityScope /*scope*/, NodeId /*peer*/,
                          std::uint32_t& /*epoch*/) noexcept {
    return Status::success();
  }
  // Session owners report the current receive context independently of
  // tx_epoch(): the peer's choice for our outgoing frames is generally not
  // the context this node chose for its incoming frames. Development
  // providers with ordered boot epochs can leave this Unsupported; the
  // radio Owner then learns the peer epoch from authenticated RX.
  virtual Status current_rx_epoch(SecurityScope /*scope*/, NodeId /*peer*/,
                                  std::uint32_t& /*epoch*/) const noexcept {
    return Status::error(StatusCode::Unsupported, "RX_CONTEXT_UNAVAILABLE");
  }
  // Reports the context behind tx_epoch(). The node consults it only after
  // an AuthRequired refusal: None/Establishing defers the frame (bounded by
  // its deadline); a usable state makes the refusal an ordinary failure.
  // The default (Ready) is a provider whose keys are always available.
  virtual ContextState context_state(SecurityScope /*scope*/,
                                     NodeId /*peer*/) const noexcept {
    return ContextState::Ready;
  }
  // GroupLink needs one atomic boot/GK snapshot; unicast providers do not
  // implement this scope. A retired generation is never accepted on repair.
  virtual Status tx_group_link_epochs(std::uint32_t& /*boot*/,
                                      std::uint32_t& /*g*/) noexcept {
    return Status::error(StatusCode::Unsupported, "group link unavailable");
  }
  virtual bool accepts_group_epoch(std::uint32_t /*g*/) const noexcept { return true; }
  virtual Status next_counter(const SecurityContext& context,
                              std::uint64_t& counter) noexcept = 0;
  virtual Status seal(const SecurityContext& context,
                      std::uint64_t counter,
                      ByteView aad,
                      ByteView plaintext,
                      MutableByteView ciphertext,
                      std::array<std::uint8_t, kAeadTagSize>& tag) noexcept = 0;
  virtual Status open(const SecurityContext& context,
                      std::uint64_t counter,
                      ByteView aad,
                      ByteView ciphertext,
                      const std::array<std::uint8_t, kAeadTagSize>& tag,
                      MutableByteView plaintext) noexcept = 0;
};

// Per-direction AEAD material of one installed context (sdk-v1/03 §3:
// AES-GCM-128, nonce = base IV XOR (zero6 || counter u48)).
constexpr std::size_t kSessionKeySize = 16;
constexpr std::size_t kSessionIvSize = 12;

// What a handshake engine hands the provider when a context is established
// (EDHOC exporter or RLRES1, sdk-v1/03 §4–§5, plan P4-2). Holds secrets: the
// engine clears its copy (secure_clear) after install(). Context ids are the
// receiver-chosen ids of 03 §4.2 — `tx_context_id` is the peer's choice and
// is stamped into frames this node sends (tx_epoch()), `rx_context_id` is
// this node's choice and selects the key for frames the peer sends.
struct ContextKeys {
  SecurityScope scope{SecurityScope::Link};
  NetworkId network{0};
  NodeId peer{kInvalidNodeId};
  std::uint32_t tx_context_id{0};
  std::uint32_t rx_context_id{0};
  std::array<std::uint8_t, kSessionKeySize> tx_key{};
  std::array<std::uint8_t, kSessionIvSize> tx_iv{};
  std::array<std::uint8_t, kSessionKeySize> rx_key{};
  std::array<std::uint8_t, kSessionIvSize> rx_iv{};
  // Verified peer summary: first8(SHA-256(peer MemberCert)) and its
  // assignment generation (sdk-v1/04 §1), for later RRS1 enforcement.
  std::array<std::uint8_t, 8> peer_cert_id{};
  std::uint32_t peer_generation{0};
};

// Structural checks every installer applies before touching its tables:
// a unicast scope (group keys come from the GK schedule, 03 §6), a real
// peer and network, non-zero context ids.
inline Status check_context_keys(const ContextKeys& keys) noexcept {
  if (keys.scope != SecurityScope::Link && keys.scope != SecurityScope::EndToEnd) {
    return Status::error(StatusCode::Unsupported, "SESSION_SCOPE_UNSUPPORTED");
  }
  if (keys.network == 0 || keys.peer == kInvalidNodeId || keys.peer == kBroadcastNodeId) {
    return Status::error(StatusCode::InvalidArgument, "SESSION_IDENTITY_INVALID");
  }
  if (keys.tx_context_id == 0 || keys.rx_context_id == 0) {
    return Status::error(StatusCode::InvalidArgument, "SESSION_CONTEXT_ID_ZERO");
  }
  return Status::success();
}

// The only way session keys enter a provider (sdk-v1/03 §8): the handshake
// engine holds this interface; the node and the application never see keys.
// A provider that owns sessions implements it next to SecurityProvider and
// the firmware hands that object to its engine. Rules for implementations:
// - install() replaces the (scope, peer) context: each installed key starts
//   its counter at 0, and must be fresh per handshake — never re-install a
//   key a previous context used (nonce uniqueness rests on key freshness,
//   03 §3). It rejects an rx_context_id already live for another context
//   (Conflict) and a full table (NoCapacity) without disturbing live state.
// - retire() drops one context; retire_all() drops every context of a peer
//   (revocation, sdk-v1/04 §5). Both are idempotent. Both return Status so
//   a re-entrant call (from a crypto/storage callback) can refuse with Busy
//   instead of mutating half an exchange (P4 §2.2).
class SessionInstaller {
 public:
  virtual ~SessionInstaller() = default;
  virtual Status install(const ContextKeys& keys) noexcept = 0;
  virtual Status retire(SecurityScope scope, NodeId peer) noexcept = 0;
  virtual Status retire_all(NodeId peer) noexcept = 0;
};

}  // namespace routeloom
