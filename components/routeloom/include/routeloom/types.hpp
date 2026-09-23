#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace routeloom {

using NodeId = std::uint64_t;
using NetworkId = std::uint64_t;
using MonotonicMs = std::uint64_t;

// A link-layer radio address (ESP-NOW/Wi-Fi MAC). Distinct from NodeId: a
// NodeId is a provisioned identity, a MacAddress is a transport address that
// can change across hardware swaps and must never be used as an identity.
using MacAddress = std::array<std::uint8_t, 6>;

constexpr NodeId kInvalidNodeId = 0;
constexpr NodeId kBroadcastNodeId = UINT64_MAX;
constexpr std::size_t kMaxApplicationPayload = 128;
// Normal message lifetime ceiling (crash-time-resources §3,
// resource-profiles max_message_lifetime_ms). Origin sends above it are
// refused, never clamped: dedup retention (lifetime + late result) is
// sized on this bound, so a longer-lived message could outlive the
// receiver's duplicate suppression.
constexpr std::uint32_t kMaxMessageLifetimeMs = 30000;
// Late-result window (crash-time-resources §4, resource-profiles
// late_result_ttl_ms): how long after a message's own expiry the terminal
// side still answers retransmissions/queries from its stored record.
constexpr std::uint32_t kLateResultTtlMs = 30000;
// Terminal duplicate-suppression design value (crash-time-resources §4):
// max lifetime + late result. Every "held from first acceptance" terminal
// record (node dedup hard cap, APPLIED result hold, gateway receipt hold)
// derives from this one bound instead of repeating the literal.
constexpr std::uint32_t kTerminalRetentionMs = kMaxMessageLifetimeMs + kLateResultTtlMs;
static_assert(kTerminalRetentionMs == 60000,
              "crash-time-resources §4 pins the terminal retention at 60 s");
constexpr std::size_t kMaxEspNowBody = 250;
constexpr std::size_t kAeadTagSize = 16;
constexpr std::uint8_t kDefaultHopLimit = 10;

struct MessageId {
  std::uint32_t session{0};
  std::uint64_t sequence{0};

  friend constexpr bool operator==(const MessageId& left, const MessageId& right) noexcept {
    return left.session == right.session && left.sequence == right.sequence;
  }
  friend constexpr bool operator!=(const MessageId& left, const MessageId& right) noexcept {
    return !(left == right);
  }
};

struct MessageKey {
  NodeId origin{kInvalidNodeId};
  MessageId id{};

  friend constexpr bool operator==(const MessageKey& left, const MessageKey& right) noexcept {
    return left.origin == right.origin && left.id == right.id;
  }
  friend constexpr bool operator!=(const MessageKey& left, const MessageKey& right) noexcept {
    return !(left == right);
  }
};

enum class DeliveryClass : std::uint8_t {
  BestEffort = 0,
  Reliable = 1,
  Applied = 2,
};

enum class DeliveryState : std::uint8_t {
  Empty = 0,
  Accepted,
  WaitingForRoute,
  Queued,
  WaitingForMac,
  WaitingForHopAccept,
  WaitingForEndReceipt,
  Delivered,
  Failed,
  Expired,
  CancelledBeforeTx,
  Indeterminate,
};

enum class Priority : std::uint8_t {
  Bulk = 0,
  Normal = 1,
  Management = 2,
  Urgent = 3,
};

// Frozen Wire v1 frame type IDs (see protocol/semantics.json frame_numeric_ids).
// Gaps between groups are reserved for future types in the same class.
enum class FrameType : std::uint8_t {
  Discover = 1,
  Offer = 2,
  BootstrapAuth = 3,
  MembershipResult = 4,
  BootstrapChunk = 5,
  BootstrapReply = 6,
  MembershipQuery = 7,
  Data = 16,
  HopAccept = 17,
  EndReceipt = 18,
  AppResult = 19,
  Busy = 20,
  Service = 21,
  Control = 22,
  TimeSync = 23,
  ChannelNotice = 24,
  // Group delivery (docs/design/sdk-v1/group-delivery.md): end-protected
  // group data travelling the gateway tree, and the link-only aggregated
  // confirmation a child returns to its tree parent.
  GroupData = 25,
  GroupReport = 26,
  RouteUpdate = 32,
  RouteWithdraw = 33,
  SeqnoRequest = 34,
  RouteRequest = 35,
  NeighborProbe = 40,
  NeighborResult = 41,
  Diagnostic = 48,
  ControlObject = 49,
  ObjectChunk = 50,
  ObjectAck = 51,
};

enum class SecurityScope : std::uint8_t {
  Link = 0,
  EndToEnd = 1,
  // Group end protection (GROUP_DATA): sender = the group message's origin,
  // receiver = the group address (group.hpp). Every node that holds the
  // group key material may open it — it proves "a current member sealed
  // this", never the origin's identity (sdk-v1/03 §6.5). A provider MUST
  // key each (origin, group, epoch) separately (a per-sender subkey): the
  // 12-byte nonce carries no sender, so independent per-sender counters
  // under one shared key would collide (group-delivery.md §7).
  // This is the design's "GroupEnd" (sdk-v1/03 §8); its value 2 is already
  // on the wire (nonce byte 0, key derivation, golden vectors) and is kept.
  Group = 2,
  // Reserved (sdk-v1/03 §6.2, §8, plan P5-1): one-hop broadcast link
  // protection under the network group key, context (GroupLink, network,
  // transmitter, kBroadcastNodeId, transmitter boot session). The design
  // draft numbered it 2; it takes 3 because 2 is Group above. No provider
  // implements it yet and the node never issues it: a provider MUST refuse
  // it (Unsupported) until it does.
  GroupLink = 3,
};

struct ByteView {
  const std::uint8_t* data{nullptr};
  std::size_t size{0};
};

struct MutableByteView {
  std::uint8_t* data{nullptr};
  std::size_t size{0};
};

template <std::size_t Capacity>
struct ByteBuffer {
  std::array<std::uint8_t, Capacity> bytes{};
  std::size_t size{0};

  ByteView view() const noexcept { return ByteView{bytes.data(), size}; }
  MutableByteView writable() noexcept { return MutableByteView{bytes.data(), bytes.size()}; }
  void clear() noexcept { size = 0; }
};

struct SendOptions {
  DeliveryClass delivery{DeliveryClass::Reliable};
  Priority priority{Priority::Normal};
  std::uint32_t lifetime_ms{5000};
  std::uint8_t hop_limit{kDefaultHopLimit};
  // Request durability across deep sleep: the power coordinator persists the
  // delivery into the sleep image instead of failing it at drain.
  bool persist_across_sleep{false};
  // Per-source ordering (group-delivery.md §6): a RELIABLE delivery with this
  // flag is not transmitted until the previous ordered delivery from this
  // node to the same destination is Delivered or past its own deadline, so
  // the destination's application sees them in send order. A lost
  // predecessor delays its successors by at most the predecessor's lifetime.
  bool ordered{false};
};

struct DeliveryResult {
  MessageId id{};
  DeliveryState state{DeliveryState::Empty};
  const char* reason{"NONE"};
};

}  // namespace routeloom
