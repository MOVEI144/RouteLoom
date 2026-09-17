#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace routeloom {

using NodeId = std::uint64_t;
using NetworkId = std::uint64_t;
using MonotonicMs = std::uint64_t;

constexpr NodeId kInvalidNodeId = 0;
constexpr NodeId kBroadcastNodeId = UINT64_MAX;
constexpr std::size_t kMaxApplicationPayload = 128;
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

enum class FrameType : std::uint8_t {
  Discover = 1,
  Offer = 2,
  BootstrapAuth = 3,
  MembershipResult = 4,
  Data = 16,
  HopAccept = 17,
  EndReceipt = 18,
  AppResult = 19,
  Busy = 20,
  RouteUpdate = 32,
  RouteWithdraw = 33,
  SeqnoRequest = 34,
  NeighborProbe = 40,
  NeighborResult = 41,
  Diagnostic = 48,
};

enum class SecurityScope : std::uint8_t {
  Link = 0,
  EndToEnd = 1,
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
};

struct DeliveryResult {
  MessageId id{};
  DeliveryState state{DeliveryState::Empty};
  const char* reason{"NONE"};
};

}  // namespace routeloom
