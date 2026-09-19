#include "routeloom/node.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>

#include "routeloom/byte_io.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kControlLifetimeMs = 1000;
constexpr std::uint32_t kMinimumEndToEndRetryMs = 250;
// ROUTE_UPDATE record: destination(8) + origin generation(2) + sequence(2) + metric(2)
constexpr std::size_t kRouteRecordBytes = 14;
// ROUTE_UPDATE payload = 1-byte count + N records; the 128-byte payload caps
// N at floor((128 - 1) / kRouteRecordBytes) = 9.
constexpr std::size_t kMaxRouteRecordsPerFrame =
    (kMaxApplicationPayload - 1) / kRouteRecordBytes;
constexpr std::uint32_t kSeqnoRequestLifetimeMs = 2000;
constexpr std::uint32_t kSeqnoRequestCooldownMs = 2000;
constexpr std::uint32_t kSeqnoRequestMaxCooldownMs = 30000;
constexpr std::uint8_t kSeqnoRequestMaxAttempts = 8;
constexpr std::size_t kSeqnoMaxInflight = 4;
constexpr std::uint32_t kSeqnoStateDwellMs = 30000;
constexpr std::uint8_t kSeqnoRequestMaxTtl = kDefaultHopLimit;
constexpr std::size_t kSeqnoRequestPayloadBytes = 8 + 8 + 2 + 4 + 1;
// Triggered updates: at most one full-neighbor burst per min-interval, each
// burst delayed by a small deterministic jitter.
constexpr std::uint32_t kTriggeredUpdateMinIntervalMs = 1000;
constexpr std::uint32_t kTriggeredJitterMs = 64;

}  // namespace

MeshNode::MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
                   NodeObserver& observer) noexcept
    : config_(config), radio_(radio), security_(security), observer_(observer) {}

Status MeshNode::validate_config() const noexcept {
  if (config_.network == 0 || config_.network > UINT32_MAX ||
      config_.node == kInvalidNodeId || config_.node == kBroadcastNodeId ||
      config_.message_session == 0 || config_.route_generation == 0 ||
      config_.route_advertisement_period_ms == 0 ||
      config_.route_lifetime_ms <= config_.route_advertisement_period_ms ||
      config_.hop_accept_timeout_ms == 0 || config_.callback_watchdog_ms == 0 ||
      config_.max_link_attempts == 0 || config_.max_end_to_end_rounds == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid node configuration");
  }
  return Status::success();
}

Status MeshNode::start(const MonotonicMs now_ms) noexcept {
  if (started_) return Status::error(StatusCode::AlreadyExists, "node already started");
  const auto status = validate_config();
  if (!status) return status;
  if (!security_.ready()) {
    return Status::error(StatusCode::InvalidState, "security provider is not ready");
  }
  started_ = true;
  next_route_advertisement_ms_ = now_ms;
  // A development-profile provider is allowed to run but is always surfaced
  // as EXPERIMENTAL; nothing in this node claims production security status.
  if (security_.security_profile() != SecurityProfile::Production) {
    observer_.on_diagnostic("SECURITY_PROFILE_EXPERIMENTAL", kInvalidNodeId, nullptr);
  }
  return Status::success();
}

MeshNode::Neighbor* MeshNode::find_neighbor(const NodeId node) noexcept {
  return neighbors_.find([&](const Neighbor& value) { return value.node == node; });
}

const MeshNode::Neighbor* MeshNode::find_neighbor(const NodeId node) const noexcept {
  return neighbors_.find([&](const Neighbor& value) { return value.node == node; });
}

Status MeshNode::add_neighbor(const NodeId neighbor, const RouteMetric link_metric,
                              const MonotonicMs now_ms) noexcept {
  if (!started_ || neighbor == kInvalidNodeId || neighbor == config_.node || link_metric == 0 ||
      link_metric == kInfiniteRouteMetric) {
    return Status::error(StatusCode::InvalidArgument, "invalid neighbor");
  }
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) {
    record = neighbors_.allocate();
    if (record == nullptr) return Status::error(StatusCode::NoCapacity, "neighbor table full");
    record->generation = 0;  // last-seen origin generation; survives re-adds
  }
  record->node = neighbor;
  record->metric = link_metric;
  record->consecutive_failures = 0;
  record->active = true;
  // Direct route to the neighbor itself, seeded at the last-seen generation
  // (0 for a brand-new peer); it upgrades as soon as its self record arrives.
  const RouteAdvertisement direct{neighbor, record->generation, 0, 0};
  const auto result = routes_.consider(direct, neighbor, link_metric, now_ms,
                                       config_.route_lifetime_ms);
  if (result == RouteUpdateResult::NoCapacity) {
    record->active = false;
    return Status::error(StatusCode::NoCapacity, "route table full");
  }
  ++config_revision_;
  next_route_advertisement_ms_ = now_ms;
  return Status::success();
}

Status MeshNode::remove_neighbor(const NodeId neighbor, const MonotonicMs now_ms) noexcept {
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) return Status::error(StatusCode::NotFound, "neighbor not found");
  record->active = false;
  routes_.invalidate_next_hop(neighbor, now_ms);
  ++self_route_sequence_;
  ++config_revision_;
  trigger_route_advertisement(now_ms);
  return Status::success();
}

MeshNode::Delivery* MeshNode::find_delivery(const MessageId& id) noexcept {
  return deliveries_.find([&](const Delivery& value) { return value.id == id; });
}

const MeshNode::Delivery* MeshNode::find_delivery(const MessageId& id) const noexcept {
  return deliveries_.find([&](const Delivery& value) { return value.id == id; });
}

MeshNode::DedupEntry* MeshNode::find_dedup(const MessageKey& key, const FrameType type,
                                           const std::uint8_t round) noexcept {
  return dedup_.find([&](const DedupEntry& value) {
    return value.key == key && value.type == type && value.round == round;
  });
}

MeshNode::DedupEntry* MeshNode::allocate_dedup(const MessageKey& key, const FrameType type,
                                               const std::uint8_t round,
                                               const MonotonicMs expires_at_ms) noexcept {
  if (auto* existing = find_dedup(key, type, round)) return existing;
  auto* entry = dedup_.allocate();
  if (entry == nullptr) return nullptr;
  entry->key = key;
  entry->type = type;
  entry->round = round;
  entry->expires_at_ms = expires_at_ms;
  return entry;
}

void MeshNode::set_delivery_state(Delivery& delivery, const DeliveryState state,
                                  const char* reason) noexcept {
  if (delivery.state == state && delivery.reason == reason) return;
  delivery.state = state;
  delivery.reason = reason;
  observer_.on_delivery(DeliveryResult{delivery.id, state, reason});
}

Status MeshNode::send(const NodeId destination, const ByteView payload,
                      const SendOptions& options, const MonotonicMs now_ms,
                      MessageId& id) noexcept {
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  // Any application TX intent is activity: it must invalidate an outstanding
  // sleep ticket even when the request itself is rejected below.
  ++work_generation_;
  if (draining_) {
    return Status::error(StatusCode::InvalidState, "NODE_DRAINING");
  }
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      options.lifetime_ms == 0 || options.hop_limit == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid send request");
  }
  if (options.delivery == DeliveryClass::Applied) {
    return Status::error(StatusCode::Unsupported, "APPLIED is not implemented in CORE_FIXED_250");
  }
  return enqueue_delivery(
      MessageId{config_.message_session, next_message_sequence_}, destination,
      payload, options, now_ms, id);
}

Status MeshNode::resume_delivery(const MessageId& id, const NodeId destination,
                                 const ByteView payload, const SendOptions& options,
                                 const MonotonicMs now_ms) noexcept {
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (draining_) {
    return Status::error(StatusCode::InvalidState, "NODE_DRAINING");
  }
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      options.lifetime_ms == 0 || options.hop_limit == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid send request");
  }
  if (options.delivery == DeliveryClass::Applied) {
    return Status::error(StatusCode::Unsupported, "APPLIED is not implemented in CORE_FIXED_250");
  }
  if (auto* existing = find_delivery(id)) {
    if (!sleep_terminal(existing->state)) {
      return Status::error(StatusCode::AlreadyExists, "delivery id already live");
    }
    // The terminal record is this delivery's previous incarnation
    // (SLEEP_SAVED in the in-process model): replace it so resume keeps the
    // same logical id instead of failing on the stale slot.
    deliveries_.release(existing);
  }
  MessageId out{};
  return enqueue_delivery(id, destination, payload, options, now_ms, out);
}

bool MeshNode::sleep_terminal(const DeliveryState state) noexcept {
  switch (state) {
    case DeliveryState::Empty:
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::CancelledBeforeTx:
    case DeliveryState::Indeterminate:
      return true;
    default:
      return false;
  }
}

Status MeshNode::enqueue_delivery(const MessageId& id, const NodeId destination,
                                  const ByteView payload, const SendOptions& options,
                                  const MonotonicMs now_ms, MessageId& out) noexcept {
  auto* record = deliveries_.allocate();
  if (record == nullptr) {
    // Terminal entries are history, not live work: evict the oldest one
    // before reporting the table full so sends are not wedged forever.
    Delivery* oldest_terminal = nullptr;
    deliveries_.for_each([&](Delivery& delivery) {
      switch (delivery.state) {
        case DeliveryState::Delivered:
        case DeliveryState::Failed:
        case DeliveryState::Expired:
        case DeliveryState::CancelledBeforeTx:
        case DeliveryState::Indeterminate:
          if (oldest_terminal == nullptr ||
              delivery.created_at_ms < oldest_terminal->created_at_ms) {
            oldest_terminal = &delivery;
          }
          break;
        default:
          break;
      }
    });
    if (oldest_terminal != nullptr) {
      deliveries_.release(oldest_terminal);
      record = deliveries_.allocate();
    }
    if (record == nullptr) {
      return Status::error(StatusCode::NoCapacity, "delivery table full");
    }
  }
  record->id = id;
  // Keep the sequence space disjoint: a later send() must never reissue a
  // logical id that a resumed delivery still owns.
  if (id.session == config_.message_session && id.sequence >= next_message_sequence_ &&
      id.sequence != UINT64_MAX) {
    next_message_sequence_ = id.sequence + 1;
  }
  record->destination = destination;
  record->options = options;
  record->payload_size = payload.size;
  if (payload.size > 0) std::memcpy(record->payload.data(), payload.data, payload.size);
  record->created_at_ms = now_ms;
  record->expires_at_ms = now_ms + options.lifetime_ms;
  record->round = 0;
  set_delivery_state(*record, DeliveryState::Accepted, "TX_ACCEPTED");
  out = record->id;

  const auto status = queue_origin_data(*record, now_ms);
  if (!status) {
    if (status.code == StatusCode::NoRoute || status.code == StatusCode::WouldBlock) {
      set_delivery_state(*record, DeliveryState::WaitingForRoute, status.detail);
      record->next_round_at_ms = now_ms + 50;
      return Status::success();
    }
    deliveries_.release(record);
    return status;
  }
  return Status::success();
}

Status MeshNode::cancel(const MessageId& id) noexcept {
  auto* record = find_delivery(id);
  if (record == nullptr) return Status::error(StatusCode::NotFound, "delivery not found");
  switch (record->state) {
    case DeliveryState::Accepted:
    case DeliveryState::WaitingForRoute:
    case DeliveryState::Queued:
      set_delivery_state(*record, DeliveryState::CancelledBeforeTx, "CANCELLED_BEFORE_TX");
      return Status::success();
    case DeliveryState::WaitingForMac:
    case DeliveryState::WaitingForHopAccept:
    case DeliveryState::WaitingForEndReceipt:
      set_delivery_state(*record, DeliveryState::Indeterminate, "CANCEL_AFTER_TX_INDETERMINATE");
      return Status::success();
    default:
      return Status::error(StatusCode::InvalidState, "delivery is already terminal");
  }
}

DeliveryResult MeshNode::delivery(const MessageId& id) const noexcept {
  const auto* record = find_delivery(id);
  return record == nullptr ? DeliveryResult{id, DeliveryState::Empty, "NOT_FOUND"}
                           : DeliveryResult{id, record->state, record->reason};
}

Status MeshNode::queue_origin_data(Delivery& delivery, const MonotonicMs now_ms) noexcept {
  if (now_ms >= delivery.expires_at_ms) {
    return Status::error(StatusCode::Expired, "DEADLINE_EXPIRED");
  }
  const auto route = routes_.best(delivery.destination);
  if (!route.valid || find_neighbor(route.next_hop) == nullptr) {
    return Status::error(StatusCode::NoRoute, "NO_ROUTE");
  }
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::OriginDelivery;
  job.peer = route.next_hop;
  job.requires_hop_accept = delivery.options.delivery == DeliveryClass::Reliable;
  job.max_attempts = config_.max_link_attempts;
  job.deadline_ms = delivery.expires_at_ms;
  job.ack = AckKey{FrameType::Data, MessageKey{config_.node, delivery.id}, delivery.round};
  job.plain.header.type = FrameType::Data;
  // Application DATA is always end-to-end protected: no code path may queue a
  // plaintext DATA frame (receivers reject it with END_PROTECTION_REQUIRED).
  job.plain.header.flags = wire::kFlagEndProtected;
  job.plain.header.delivery = delivery.options.delivery;
  job.plain.header.delivery_round = delivery.round;
  job.plain.header.hop_remaining = delivery.options.hop_limit;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = delivery.destination;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = route.next_hop;
  job.plain.header.message = delivery.id;
  job.plain.header.remaining_deadline_ms = static_cast<std::uint32_t>(delivery.expires_at_ms - now_ms);
  job.plain.header.original_lifetime_ms = delivery.options.lifetime_ms;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  job.plain.payload_size = delivery.payload_size;
  if (delivery.payload_size > 0) {
    std::memcpy(job.plain.payload.data(), delivery.payload.data(), delivery.payload_size);
  }
  if (!tx_queue_.push(std::move(job))) {
    return Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
  }
  set_delivery_state(delivery, DeliveryState::Queued, "QUEUED");
  return Status::success();
}

Status MeshNode::queue_forward(const wire::LinkOpenedFrame& frame, const NodeId next_hop,
                               const MonotonicMs now_ms) noexcept {
  TxJob job{};
  job.form = JobForm::Forwarded;
  job.owner = JobOwner::Transit;
  job.forwarded = frame;
  job.peer = next_hop;
  job.requires_hop_accept = true;
  job.max_attempts = config_.max_link_attempts;
  job.deadline_ms = now_ms + frame.header.remaining_deadline_ms;
  job.ack = AckKey{frame.header.type,
                   MessageKey{frame.header.origin, frame.header.message},
                   frame.header.delivery_round};
  return tx_queue_.push(std::move(job)) ? Status::success()
                                        : Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
}

Status MeshNode::encode_ack_payload(const AckKey& key,
                                    std::array<std::uint8_t, kMaxApplicationPayload>& payload,
                                    std::size_t& size) noexcept {
  ByteWriter writer(MutableByteView{payload.data(), payload.size()});
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(key.accepted_type)));
  RL_WRITE(writer.write_u64(key.key.origin));
  RL_WRITE(writer.write_u32(key.key.id.session));
  RL_WRITE(writer.write_u64(key.key.id.sequence));
  RL_WRITE(writer.write_u8(key.round));
#undef RL_WRITE
  size = writer.size();
  return Status::success();
}

Status MeshNode::decode_ack_payload(const ByteView payload, AckKey& key) noexcept {
  ByteReader reader(payload);
  std::uint8_t type = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u8(type));
  RL_READ(reader.read_u64(key.key.origin));
  RL_READ(reader.read_u32(key.key.id.session));
  RL_READ(reader.read_u64(key.key.id.sequence));
  RL_READ(reader.read_u8(key.round));
#undef RL_READ
  const bool known_type = type == static_cast<std::uint8_t>(FrameType::Data) ||
      type == static_cast<std::uint8_t>(FrameType::EndReceipt) ||
      type == static_cast<std::uint8_t>(FrameType::RouteUpdate) ||
      type == static_cast<std::uint8_t>(FrameType::SeqnoRequest);
  if (reader.remaining() != 0 || !known_type) {
    return Status::error(StatusCode::ProtocolError, "invalid hop accept payload");
  }
  key.accepted_type = static_cast<FrameType>(type);
  return Status::success();
}

Status MeshNode::queue_hop_accept(const wire::Header& accepted,
                                  const MonotonicMs now_ms) noexcept {
  TxJob job{};
  job.form = JobForm::Plain;
  job.peer = accepted.previous_hop;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::HopAccept;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.delivery_round = accepted.delivery_round;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = accepted.previous_hop;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = accepted.previous_hop;
  job.plain.header.message = accepted.message;
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  job.ack = AckKey{accepted.type, MessageKey{accepted.origin, accepted.message},
                   accepted.delivery_round};
  auto status = encode_ack_payload(job.ack, job.plain.payload, job.plain.payload_size);
  if (!status) return status;
  return tx_queue_.push(std::move(job)) ? Status::success()
                                        : Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
}

Status MeshNode::encode_receipt_payload(
    const wire::Header& data, std::array<std::uint8_t, kMaxApplicationPayload>& payload,
    std::size_t& size) noexcept {
  ByteWriter writer(MutableByteView{payload.data(), payload.size()});
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u64(data.origin));
  RL_WRITE(writer.write_u64(data.destination));
  RL_WRITE(writer.write_u32(data.message.session));
  RL_WRITE(writer.write_u64(data.message.sequence));
  RL_WRITE(writer.write_u8(data.delivery_round));
  RL_WRITE(writer.write_u8(0));
#undef RL_WRITE
  size = writer.size();
  return Status::success();
}

Status MeshNode::decode_receipt_payload(const ByteView payload, MessageKey& key,
                                        std::uint8_t& round) noexcept {
  ByteReader reader(payload);
  NodeId original_destination = 0;
  std::uint8_t result = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u64(key.origin));
  RL_READ(reader.read_u64(original_destination));
  RL_READ(reader.read_u32(key.id.session));
  RL_READ(reader.read_u64(key.id.sequence));
  RL_READ(reader.read_u8(round));
  RL_READ(reader.read_u8(result));
#undef RL_READ
  if (reader.remaining() != 0 || result != 0) {
    return Status::error(StatusCode::ProtocolError, "invalid end receipt payload");
  }
  return original_destination == kInvalidNodeId
             ? Status::error(StatusCode::ProtocolError, "invalid receipt destination")
             : Status::success();
}

Status MeshNode::queue_end_receipt(const wire::Header& data,
                                   const MonotonicMs now_ms) noexcept {
  const auto route = routes_.best(data.origin);
  if (!route.valid) return Status::error(StatusCode::NoRoute, "NO_RETURN_ROUTE");
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::Transit;
  job.peer = route.next_hop;
  job.requires_hop_accept = true;
  job.max_attempts = config_.max_link_attempts;
  job.deadline_ms = now_ms + data.remaining_deadline_ms;
  job.plain.header.type = FrameType::EndReceipt;
  job.plain.header.flags = wire::kFlagEndProtected;
  job.plain.header.delivery = DeliveryClass::Reliable;
  job.plain.header.delivery_round = data.delivery_round;
  // The receipt gets its own full hop budget — the DATA's remainder is often
  // 1 at the end of a long path, which would strand the return trip.
  job.plain.header.hop_remaining = kDefaultHopLimit;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = data.origin;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = route.next_hop;
  job.plain.header.message = data.message;
  job.plain.header.remaining_deadline_ms = data.remaining_deadline_ms;
  job.plain.header.original_lifetime_ms = data.original_lifetime_ms;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  job.ack = AckKey{FrameType::EndReceipt, MessageKey{config_.node, data.message},
                   data.delivery_round};
  auto status = encode_receipt_payload(data, job.plain.payload, job.plain.payload_size);
  if (!status) return status;
  return tx_queue_.push(std::move(job)) ? Status::success()
                                        : Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
}

Status MeshNode::queue_route_update(const NodeId neighbor,
                                    const MonotonicMs now_ms) noexcept {
  TxJob job{};
  job.form = JobForm::Plain;
  job.peer = neighbor;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::RouteUpdate;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = neighbor;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = neighbor;
  job.plain.header.message = MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;

  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  auto status = writer.write_u8(0);  // patched after records are appended
  if (!status) return status;
  std::uint8_t count = 0;
  auto append = [&](const NodeId destination, const RouteGeneration generation,
                    const RouteSequence sequence, const RouteMetric metric) -> bool {
    if (count >= kMaxRouteRecordsPerFrame) return false;
    if (writer.write_u64(destination) && writer.write_u16(generation) &&
        writer.write_u16(sequence) && writer.write_u16(metric)) {
      ++count;
      return true;
    }
    return false;
  };
  append(config_.node, config_.route_generation, self_route_sequence_, 0);
  // A frame holds at most kMaxRouteRecordsPerFrame records. Rotate a
  // per-neighbor cursor through the selected routes so a full dump spans
  // successive updates instead of permanently starving the tail entries.
  auto* neighbor_record = find_neighbor(neighbor);
  const std::size_t skip =
      neighbor_record != nullptr ? neighbor_record->route_cursor : 0;
  std::size_t index = 0;
  std::size_t advertised_count = 0;
  bool writer_full = false;
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (selection.destination == config_.node) return;
    if (index++ < skip || writer_full) return;
    const RouteMetric advertised =
        selection.next_hop == neighbor ? kInfiniteRouteMetric : selection.metric;
    if (!append(selection.destination, selection.generation, selection.sequence,
                advertised)) {
      writer_full = true;
      return;
    }
    ++advertised_count;
    // FD is refreshed only when a finite advertisement actually leaves; a
    // split-horizon retraction (infinity) must not touch feasibility state.
    if (advertised != kInfiniteRouteMetric) routes_.mark_advertised(selection.destination);
  });
  if (neighbor_record != nullptr) {
    const std::size_t next = skip + advertised_count;
    neighbor_record->route_cursor =
        static_cast<std::uint8_t>(next >= index ? 0 : next);
  }
  // Retractions: destinations that lost their last feasible route are
  // advertised as infinity so neighbors withdraw promptly instead of waiting
  // out the lease (RFC 8966 §3.7.2). The record budget bounds the burst.
  routes_.for_each_lost([&](const RouteTable::LostRoute& lost) {
    if (writer_full || lost.destination == config_.node) return;
    if (!append(lost.destination, lost.generation, lost.sequence,
                kInfiniteRouteMetric)) {
      writer_full = true;
    }
  });
  job.plain.payload[0] = count;
  job.plain.payload_size = writer.size();
  return tx_queue_.push(std::move(job)) ? Status::success()
                                        : Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
}

Status MeshNode::queue_seqno_request(const NodeId peer, const NodeId requester,
                                         const NodeId destination,
                                         const RouteSequence requested_sequence,
                                         const std::uint32_t request_id,
                                         const std::uint8_t ttl,
                                         const MonotonicMs now_ms) noexcept {
  if (ttl == 0 || peer == kInvalidNodeId || destination == kInvalidNodeId ||
      requester == kInvalidNodeId) {
    return Status::error(StatusCode::InvalidArgument, "invalid sequence request");
  }
  TxJob job{};
  job.form = JobForm::Plain;
  job.peer = peer;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kSeqnoRequestLifetimeMs;
  job.plain.header.type = FrameType::SeqnoRequest;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = peer;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = peer;
  job.plain.header.message = MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = kSeqnoRequestLifetimeMs;
  job.plain.header.original_lifetime_ms = kSeqnoRequestLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;

  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  Status status;
#define RL_WRITE_SEQNO(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE_SEQNO(writer.write_u64(requester));
  RL_WRITE_SEQNO(writer.write_u64(destination));
  RL_WRITE_SEQNO(writer.write_u16(requested_sequence));
  RL_WRITE_SEQNO(writer.write_u32(request_id));
  RL_WRITE_SEQNO(writer.write_u8(ttl));
#undef RL_WRITE_SEQNO
  job.plain.payload_size = writer.size();
  return tx_queue_.push(std::move(job)) ? Status::success()
                                        : Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
}

Status MeshNode::encode_job(TxJob& job, const MonotonicMs now_ms) noexcept {
  if (job.encoded_valid) return Status::success();
  if (now_ms >= job.deadline_ms) return Status::error(StatusCode::Expired, "JOB_EXPIRED");
  const auto remaining = static_cast<std::uint32_t>(job.deadline_ms - now_ms);
  Status status;
  if (job.form == JobForm::Plain) {
    job.plain.header.previous_hop = config_.node;
    job.plain.header.next_hop = job.peer;
    job.plain.header.remaining_deadline_ms = std::min(job.plain.header.remaining_deadline_ms,
                                                      remaining);
    status = wire::encode_new(job.plain, security_, job.encoded);
  } else {
    status = wire::forward(job.forwarded, config_.node, job.peer, remaining, security_,
                           job.encoded);
  }
  if (status) job.encoded_valid = true;
  return status;
}

void MeshNode::dispatch_next(const MonotonicMs now_ms) noexcept {
  if (physical_.active) {
    if (now_ms - physical_.submitted_at_ms >= config_.callback_watchdog_ms) {
      TxJob job = physical_.job;
      physical_ = PhysicalInflight{};
      observer_.on_diagnostic("DRIVER_RESULT_UNKNOWN", job.peer, &job.ack.key.id);
      (void)radio_.recover();
      retry_or_fail(job, "DRIVER_RESULT_UNKNOWN", now_ms);
    }
    return;
  }

  while (auto* queued = tx_queue_.front()) {
    if (queued->owner == JobOwner::OriginDelivery) {
      auto* delivery = find_delivery(queued->ack.key.id);
      if (delivery == nullptr || delivery->state == DeliveryState::CancelledBeforeTx ||
          delivery->state == DeliveryState::Expired || delivery->state == DeliveryState::Failed) {
        TxJob discarded{};
        tx_queue_.pop(discarded);
        continue;
      }
    }
    auto status = encode_job(*queued, now_ms);
    if (!status) {
      TxJob failed{};
      tx_queue_.pop(failed);
      fail_job(failed, status.detail, now_ms);
      continue;
    }
    const std::uint64_t token = next_physical_token_++;
    status = radio_.send(queued->peer, token, queued->encoded.view());
    if (status.code == StatusCode::WouldBlock || status.code == StatusCode::Busy) return;
    TxJob submitted{};
    tx_queue_.pop(submitted);
    if (!status) {
      retry_or_fail(submitted, status.detail, now_ms);
      continue;
    }
    physical_.job = std::move(submitted);
    physical_.token = token;
    physical_.submitted_at_ms = now_ms;
    physical_.active = true;
    if (physical_.job.owner == JobOwner::OriginDelivery) {
      if (auto* delivery = find_delivery(physical_.job.ack.key.id)) {
        set_delivery_state(*delivery, DeliveryState::WaitingForMac, "TX_MAC_PENDING");
      }
    }
    return;
  }
}

void MeshNode::on_radio_tx_result(const std::uint64_t token, const bool success,
                                  const MonotonicMs now_ms) noexcept {
  ++work_generation_;
  if (!physical_.active || physical_.token != token) {
    observer_.on_diagnostic("STALE_TX_CALLBACK", kInvalidNodeId, nullptr);
    return;
  }
  TxJob job = physical_.job;
  physical_ = PhysicalInflight{};
  auto* neighbor = find_neighbor(job.peer);
  if (!success) {
    if (neighbor != nullptr && neighbor->consecutive_failures < UINT8_MAX) {
      ++neighbor->consecutive_failures;
      if (neighbor->consecutive_failures >= 2) {
        routes_.invalidate_next_hop(job.peer, now_ms);
        trigger_route_advertisement(now_ms);
      }
    }
    retry_or_fail(job, "MAC_SEND_FAILED", now_ms);
    return;
  }
  if (neighbor != nullptr) neighbor->consecutive_failures = 0;
  if (!job.requires_hop_accept) {
    complete_job(job, false, now_ms);
    return;
  }
  auto* awaiting = awaiting_hop_.allocate();
  if (awaiting == nullptr) {
    retry_or_fail(job, "HOP_WAIT_TABLE_FULL", now_ms);
    return;
  }
  awaiting->job = std::move(job);
  awaiting->expires_at_ms = now_ms + config_.hop_accept_timeout_ms;
  if (awaiting->job.owner == JobOwner::OriginDelivery) {
    if (auto* delivery = find_delivery(awaiting->job.ack.key.id)) {
      set_delivery_state(*delivery, DeliveryState::WaitingForHopAccept, "HOP_ACCEPT_PENDING");
    }
  }
}

void MeshNode::complete_job(TxJob& job, const bool hop_accepted,
                            const MonotonicMs now_ms) noexcept {
  (void)hop_accepted;
  if (job.owner != JobOwner::OriginDelivery) return;
  auto* delivery = find_delivery(job.ack.key.id);
  if (delivery == nullptr) return;
  if (job.plain.header.type != FrameType::Data) return;
  if (delivery->options.delivery == DeliveryClass::BestEffort) {
    set_delivery_state(*delivery, DeliveryState::Delivered, "TX_MAC_DONE");
    return;
  }
  const auto retry_window = static_cast<std::uint32_t>(std::max<std::uint64_t>(
      kMinimumEndToEndRetryMs,
      std::min<std::uint64_t>(
          std::numeric_limits<std::uint32_t>::max(),
          static_cast<std::uint64_t>(delivery->options.hop_limit) *
              config_.hop_accept_timeout_ms * 2U)));
  delivery->next_round_at_ms = std::min(delivery->expires_at_ms, now_ms + retry_window);
  set_delivery_state(*delivery, DeliveryState::WaitingForEndReceipt, "END_RECEIPT_PENDING");
}

void MeshNode::fail_job(TxJob& job, const char* reason,
                        const MonotonicMs now_ms) noexcept {
  if (job.owner != JobOwner::OriginDelivery) return;
  auto* delivery = find_delivery(job.ack.key.id);
  if (delivery == nullptr) return;
  if (delivery->options.delivery == DeliveryClass::Reliable &&
      now_ms < delivery->expires_at_ms &&
      static_cast<std::uint8_t>(delivery->round + 1U) < config_.max_end_to_end_rounds) {
    ++delivery->round;
    delivery->next_round_at_ms = now_ms + 50;
    set_delivery_state(*delivery, DeliveryState::WaitingForRoute, reason);
    return;
  }
  set_delivery_state(*delivery, DeliveryState::Failed, reason);
}

void MeshNode::retry_or_fail(TxJob& job, const char* reason,
                             const MonotonicMs now_ms) noexcept {
  if (now_ms >= job.deadline_ms) {
    fail_job(job, "DEADLINE_EXPIRED", now_ms);
    return;
  }
  ++job.attempts;
  if (job.attempts < job.max_attempts) {
    // Each SDK retry receives a fresh link counter. Reusing a captured frame would
    // make strict anti-replay incompatible with reliable delivery.
    job.encoded_valid = false;
    TxJob pending = std::move(job);
    if (!tx_queue_.push(std::move(pending))) {
      fail_job(pending, "TX_QUEUE_FULL", now_ms);
    }
    return;
  }
  fail_job(job, reason, now_ms);
}

void MeshNode::handle_hop_accept(const wire::PlainFrame& frame, const NodeId peer,
                                 const MonotonicMs now_ms) noexcept {
  AckKey key{};
  const auto status = decode_ack_payload(ByteView{frame.payload.data(), frame.payload_size}, key);
  if (!status) {
    observer_.on_diagnostic(status.detail, peer, nullptr);
    return;
  }
  auto* awaiting = awaiting_hop_.find([&](const AwaitingHop& value) {
    return value.job.peer == peer && value.job.ack.accepted_type == key.accepted_type &&
           value.job.ack.key == key.key && value.job.ack.round == key.round;
  });
  if (awaiting == nullptr) {
    observer_.on_diagnostic("UNMATCHED_HOP_ACCEPT", peer, &key.key.id);
    return;
  }
  TxJob job = awaiting->job;
  awaiting_hop_.release(awaiting);
  complete_job(job, true, now_ms);
}

void MeshNode::handle_data(const wire::LinkOpenedFrame& frame, const NodeId peer,
                           const MonotonicMs now_ms) noexcept {
  const MessageKey key{frame.header.origin, frame.header.message};

  // END_RECEIPT loss may cause a later E2E round with the same logical Message ID.
  // A terminal recipient must acknowledge the new round without applying the payload twice.
  if (frame.header.destination == config_.node) {
    auto* terminal = dedup_.find([&](const DedupEntry& value) {
      return value.key == key && value.type == FrameType::Data && value.delivered;
    });
    if (terminal != nullptr) {
      terminal->expires_at_ms = std::max(terminal->expires_at_ms, now_ms + 60000);
      if (tx_queue_.capacity() - tx_queue_.size() >= 2) {
        (void)queue_hop_accept(frame.header, now_ms);
        (void)queue_end_receipt(frame.header, now_ms);
      }
      return;
    }
  }

  if (auto* duplicate = find_dedup(key, FrameType::Data, frame.header.delivery_round)) {
    if (tx_queue_.size() < tx_queue_.capacity()) (void)queue_hop_accept(frame.header, now_ms);
    if (duplicate->delivered && frame.header.destination == config_.node &&
        tx_queue_.size() < tx_queue_.capacity()) {
      (void)queue_end_receipt(frame.header, now_ms);
    }
    return;
  }

  if (frame.header.destination == config_.node) {
    wire::PlainFrame plain{};
    const auto status = wire::open_end(frame, config_.node, security_, plain);
    if (!status) {
      observer_.on_diagnostic(status.detail, peer, &frame.header.message);
      return;
    }
    if (tx_queue_.capacity() - tx_queue_.size() < 1) {
      observer_.on_diagnostic("ADMISSION_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    auto* entry = allocate_dedup(key, FrameType::Data, frame.header.delivery_round,
                                 now_ms + 60000);
    if (entry == nullptr) {
      observer_.on_diagnostic("ADMISSION_NO_DEDUP_SLOT", peer, &frame.header.message);
      return;
    }
    if (!queue_hop_accept(frame.header, now_ms)) {
      dedup_.release(entry);
      return;
    }
    entry->delivered = true;
    observer_.on_message(key, frame.header.origin,
                         ByteView{plain.payload.data(), plain.payload_size});
    const auto receipt_status = queue_end_receipt(frame.header, now_ms);
    if (!receipt_status) observer_.on_diagnostic(receipt_status.detail, peer, &frame.header.message);
    return;
  }

  const auto route = routes_.best(frame.header.destination);
  if (!route.valid || route.next_hop == peer ||
      tx_queue_.capacity() - tx_queue_.size() < 2) {
    observer_.on_diagnostic("TRANSIT_NO_ROUTE_OR_CAPACITY", peer, &frame.header.message);
    return;
  }
  auto* entry = allocate_dedup(key, FrameType::Data, frame.header.delivery_round,
                               now_ms + 60000);
  if (entry == nullptr) {
    observer_.on_diagnostic("ADMISSION_NO_DEDUP_SLOT", peer, &frame.header.message);
    return;
  }
  if (!queue_hop_accept(frame.header, now_ms) ||
      !queue_forward(frame, route.next_hop, now_ms)) {
    dedup_.release(entry);
    observer_.on_diagnostic("TRANSIT_RESERVATION_FAILED", peer, &frame.header.message);
    return;
  }
  entry->forwarded = true;
}

void MeshNode::handle_end_receipt(const wire::LinkOpenedFrame& frame, const NodeId peer,
                                  const MonotonicMs now_ms) noexcept {
  const MessageKey frame_key{frame.header.origin, frame.header.message};
  if (auto* duplicate = find_dedup(frame_key, FrameType::EndReceipt,
                                   frame.header.delivery_round)) {
    (void)duplicate;
    if (tx_queue_.size() < tx_queue_.capacity()) (void)queue_hop_accept(frame.header, now_ms);
    return;
  }

  if (frame.header.destination != config_.node) {
    const auto route = routes_.best(frame.header.destination);
    if (!route.valid || route.next_hop == peer ||
        tx_queue_.capacity() - tx_queue_.size() < 2) {
      observer_.on_diagnostic("RECEIPT_TRANSIT_NO_ROUTE", peer, &frame.header.message);
      return;
    }
    auto* entry = allocate_dedup(frame_key, FrameType::EndReceipt,
                                 frame.header.delivery_round, now_ms + 60000);
    if (entry == nullptr) return;
    if (!queue_hop_accept(frame.header, now_ms) ||
        !queue_forward(frame, route.next_hop, now_ms)) {
      dedup_.release(entry);
      return;
    }
    entry->forwarded = true;
    return;
  }

  wire::PlainFrame plain{};
  const auto status = wire::open_end(frame, config_.node, security_, plain);
  if (!status) {
    observer_.on_diagnostic(status.detail, peer, &frame.header.message);
    return;
  }
  MessageKey original{};
  std::uint8_t round = 0;
  const auto parse = decode_receipt_payload(ByteView{plain.payload.data(), plain.payload_size},
                                            original, round);
  if (!parse || original.origin != config_.node || original.id != frame.header.message) {
    observer_.on_diagnostic("INVALID_END_RECEIPT", peer, &frame.header.message);
    return;
  }
  if (tx_queue_.size() >= tx_queue_.capacity()) return;
  auto* entry = allocate_dedup(frame_key, FrameType::EndReceipt, frame.header.delivery_round,
                               now_ms + 60000);
  if (entry == nullptr) return;
  if (!queue_hop_accept(frame.header, now_ms)) {
    dedup_.release(entry);
    return;
  }
  entry->delivered = true;
  if (auto* delivery = find_delivery(original.id)) {
    set_delivery_state(*delivery, DeliveryState::Delivered, "END_RECEIVED");
  }
  (void)round;
}

void MeshNode::handle_route_update(const wire::PlainFrame& frame, const NodeId peer,
                                   const MonotonicMs now_ms) noexcept {
  auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return;
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  std::uint8_t count = 0;
  if (!reader.read_u8(count) || count > kMaxRouteRecordsPerFrame ||
      reader.remaining() != static_cast<std::size_t>(count) * kRouteRecordBytes) {
    observer_.on_diagnostic("INVALID_ROUTE_UPDATE", peer, &frame.header.message);
    return;
  }
  std::array<RouteAdvertisement, kMaxRouteRecordsPerFrame> records{};
  for (std::uint8_t i = 0; i < count; ++i) {
    if (!reader.read_u64(records[i].destination) ||
        !reader.read_u16(records[i].generation) ||
        !reader.read_u16(records[i].sequence) ||
        !reader.read_u16(records[i].metric)) {
      return;
    }
  }

  // Relay restart: the peer's self record (destination == peer) carries a
  // higher origin generation than we last saw. The restarted relay lost its
  // routing state, so every route learned from its previous incarnation is
  // stale. Drop via-peer candidates without hold-down — post-restart
  // advertisements are legitimate fresh state.
  bool restarted = false;
  for (std::uint8_t i = 0; i < count; ++i) {
    if (records[i].destination == peer && records[i].generation > neighbor->generation) {
      restarted = neighbor->generation != 0;
      neighbor->generation = records[i].generation;
    }
  }
  if (restarted) {
    routes_.invalidate_next_hop(peer, now_ms, false);
    trigger_route_advertisement(now_ms);
    observer_.on_diagnostic("PEER_RESTARTED_ROUTES_FLUSHED", peer, nullptr);
  }

  for (std::uint8_t i = 0; i < count; ++i) {
    const auto& advertisement = records[i];
    if (advertisement.destination == config_.node) continue;
    const auto result = routes_.consider(advertisement, peer, neighbor->metric, now_ms,
                                         config_.route_lifetime_ms);
    if (result == RouteUpdateResult::Infeasible) {
      observer_.on_diagnostic("ROUTE_INFEASIBLE_SEQNO_NEEDED", peer, nullptr);
    } else if (result == RouteUpdateResult::StaleGeneration) {
      observer_.on_diagnostic("ROUTE_STALE_GENERATION", peer, nullptr);
    } else if (result == RouteUpdateResult::HeldDown) {
      observer_.on_diagnostic("ROUTE_HELD_DOWN", peer, nullptr);
    } else if (result != RouteUpdateResult::Accepted &&
               result != RouteUpdateResult::Updated &&
               result != RouteUpdateResult::Ignored) {
      observer_.on_diagnostic("ROUTE_UPDATE_REJECTED", peer, nullptr);
    }
  }
}

void MeshNode::handle_seqno_request(const wire::PlainFrame& frame, const NodeId peer,
                                        const MonotonicMs now_ms) noexcept {
  if (frame.payload_size != kSeqnoRequestPayloadBytes) {
    observer_.on_diagnostic("INVALID_SEQNO_REQUEST", peer, &frame.header.message);
    return;
  }
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  NodeId requester = kInvalidNodeId;
  NodeId destination = kInvalidNodeId;
  RouteSequence requested_sequence = 0;
  std::uint32_t request_id = 0;
  std::uint8_t ttl = 0;
  if (!reader.read_u64(requester) || !reader.read_u64(destination) ||
      !reader.read_u16(requested_sequence) || !reader.read_u32(request_id) ||
      !reader.read_u8(ttl) || reader.remaining() != 0 || ttl == 0 ||
      ttl > kSeqnoRequestMaxTtl ||
      requester == kInvalidNodeId || destination == kInvalidNodeId) {
    observer_.on_diagnostic("INVALID_SEQNO_REQUEST", peer, &frame.header.message);
    return;
  }

  auto* seen = seqno_seen_.find([&](const SeqnoSeen& value) {
    return value.requester == requester && value.destination == destination &&
           value.request_id == request_id;
  });
  if (seen != nullptr) return;
  seen = seqno_seen_.allocate();
  if (seen == nullptr) {
    observer_.on_diagnostic("SEQNO_DEDUP_FULL", peer, &frame.header.message);
    return;
  }
  *seen = SeqnoSeen{requester, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};

  if (destination == config_.node) {
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, self_route_sequence_, ambiguous) ||
        ambiguous) {
      // RFC 8966 §3.8.1.2: an origin MUST NOT increase its sequence number by
      // more than 1 in reaction to a single seqno request. If one bump is not
      // enough, the requester's bounded retries converge instead.
      self_route_sequence_ = static_cast<RouteSequence>(self_route_sequence_ + 1U);
    }
    trigger_route_advertisement(now_ms);
    observer_.on_diagnostic("SEQNO_REQUEST_SATISFIED", peer, &frame.header.message);
    return;
  }

  if (ttl <= 1) return;
  // RFC 8966 §3.8.1.2: a node holding a route with a sequence at least as new
  // as the requested one answers from its own table instead of forwarding the
  // request toward the origin. Broadcast reaches the requester's path and
  // every other neighbor that may share the gap.
  const RouteSelection selected = routes_.best(destination);
  if (selected.valid) {
    bool ambiguous = false;
    const bool requested_newer =
        route_sequence_newer(requested_sequence, selected.sequence, ambiguous);
    if (!requested_newer && !ambiguous) {
      trigger_route_advertisement(now_ms);
      return;
    }
  }
  // One received request forwards along exactly one path (spec: a forwarder
  // must not branch). The selected route is preferred; an infeasible-but-live
  // candidate may carry it when feasibility blocks all forwarding.
  const NodeId next = routes_.request_next_hop(destination, 0, peer, requester);
  if (next == kInvalidNodeId || next == config_.node) {
    observer_.on_diagnostic("SEQNO_REQUEST_NO_PATH", peer, &frame.header.message);
    return;
  }
  (void)queue_seqno_request(next, requester, destination, requested_sequence,
                            request_id, static_cast<std::uint8_t>(ttl - 1U), now_ms);
}

void MeshNode::on_radio_receive(const NodeId peer, const ByteView encoded,
                                const RadioRxMetadata& metadata,
                                const MonotonicMs now_ms) noexcept {
  (void)metadata;
  if (!started_) return;
  // Any received frame — even one that fails decode — is radio activity and
  // must invalidate outstanding sleep tickets.
  ++work_generation_;
  wire::LinkOpenedFrame frame{};
  auto status = wire::open_link(encoded, config_.node, security_, frame);
  if (!status) {
    observer_.on_diagnostic(status.detail, peer, nullptr);
    return;
  }
  if (frame.header.network != config_.network || frame.header.previous_hop != peer) {
    observer_.on_diagnostic("LINK_IDENTITY_MISMATCH", peer, &frame.header.message);
    return;
  }
  // Only authenticated, well-formed traffic from our network confirms a
  // resume: junk or foreign frames still count as work (ticket invalidation
  // above) but must never satisfy the saved-peer confirmation window.
  ++rx_generation_;
  // A link-authenticated DATA or END_RECEIPT without end-to-end protection is
  // never valid in normal operation: the link open only proves the immediate
  // peer, so an unprotected payload could be injected or altered by any relay
  // on the path. Drop it before any deliver-or-forward decision; the wire
  // codec itself still accepts such frames for link-only control types.
  if ((frame.header.type == FrameType::Data || frame.header.type == FrameType::EndReceipt) &&
      (frame.header.flags & wire::kFlagEndProtected) == 0) {
    observer_.on_diagnostic("END_PROTECTION_REQUIRED", peer, &frame.header.message);
    return;
  }

  switch (frame.header.type) {
    case FrameType::Data:
      handle_data(frame, peer, now_ms);
      break;
    case FrameType::EndReceipt:
      handle_end_receipt(frame, peer, now_ms);
      break;
    case FrameType::HopAccept:
    case FrameType::RouteUpdate:
    case FrameType::SeqnoRequest: {
      wire::PlainFrame plain{};
      status = wire::open_end(frame, config_.node, security_, plain);
      if (!status) {
        observer_.on_diagnostic(status.detail, peer, &frame.header.message);
        return;
      }
      if (frame.header.type == FrameType::HopAccept) {
        handle_hop_accept(plain, peer, now_ms);
      } else if (frame.header.type == FrameType::RouteUpdate) {
        handle_route_update(plain, peer, now_ms);
      } else {
        handle_seqno_request(plain, peer, now_ms);
      }
      break;
    }
    case FrameType::NeighborProbe:
    case FrameType::NeighborResult:
      // Link-scoped autonomy control (02-discovery.md §3): strictly 1-hop,
      // bound to the immediate peer, never end-protected. The sink
      // re-validates against the verified binding/phase — open_link alone is
      // not evidence (06 §3.1).
      if (autonomy_sink_ != nullptr && frame.header.destination == config_.node &&
          (frame.header.flags & wire::kFlagEndProtected) == 0) {
        autonomy_sink_->on_autonomy_frame(
            peer, frame.header.type,
            ByteView{frame.protected_payload.data(), frame.header.payload_length},
            now_ms);
      } else {
        observer_.on_diagnostic("AUTONOMY_FRAME_REJECTED", peer,
                                &frame.header.message);
      }
      break;
    default:
      observer_.on_diagnostic("FRAME_TYPE_UNSUPPORTED_IN_CORE_FIXED_250", peer,
                              &frame.header.message);
      break;
  }
}

void MeshNode::process_awaiting_hop(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* expired = awaiting_hop_.find(
        [&](const AwaitingHop& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    TxJob job = expired->job;
    awaiting_hop_.release(expired);
    retry_or_fail(job, "HOP_ACCEPT_TIMEOUT", now_ms);
  }
}

void MeshNode::process_delivery_timeouts(const MonotonicMs now_ms) noexcept {
  deliveries_.for_each([&](Delivery& delivery) {
    if (delivery.state == DeliveryState::Delivered || delivery.state == DeliveryState::Failed ||
        delivery.state == DeliveryState::Expired ||
        delivery.state == DeliveryState::CancelledBeforeTx ||
        delivery.state == DeliveryState::Indeterminate) {
      return;
    }
    if (now_ms >= delivery.expires_at_ms) {
      set_delivery_state(delivery, DeliveryState::Expired, "DEADLINE_EXPIRED");
      return;
    }
    // While draining, retry rounds do not re-enqueue: the deliveries wait for
    // their sleep disposition (fail/save/defer) instead of making new work.
    if (!draining_ &&
        (delivery.state == DeliveryState::WaitingForRoute ||
         delivery.state == DeliveryState::WaitingForEndReceipt) &&
        now_ms >= delivery.next_round_at_ms) {
      if (delivery.state == DeliveryState::WaitingForEndReceipt) {
        if (static_cast<std::uint8_t>(delivery.round + 1U) >=
            config_.max_end_to_end_rounds) {
          set_delivery_state(delivery, DeliveryState::Failed, "END_RECEIPT_TIMEOUT");
          return;
        }
        ++delivery.round;
      }
      const auto status = queue_origin_data(delivery, now_ms);
      if (!status) {
        delivery.next_round_at_ms = now_ms + 100;
        set_delivery_state(delivery, DeliveryState::WaitingForRoute, status.detail);
      }
    }
  });
}

void MeshNode::expire_dedup(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* expired = dedup_.find(
        [&](const DedupEntry& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    dedup_.release(expired);
  }
}

void MeshNode::schedule_route_advertisements(const MonotonicMs now_ms) noexcept {
  if (now_ms < next_route_advertisement_ms_ || tx_queue_.full()) return;
  std::array<NodeId, kNeighborCapacity> active{};
  std::size_t count = 0;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (neighbor.active && count < active.size()) active[count++] = neighbor.node;
  });
  if (count == 0) {
    next_route_advertisement_ms_ = now_ms + config_.route_advertisement_period_ms;
    return;
  }
  const NodeId peer = active[route_neighbor_cursor_ % count];
  route_neighbor_cursor_ = (route_neighbor_cursor_ + 1) % count;
  (void)queue_route_update(peer, now_ms);
  const auto interval = std::max<std::uint32_t>(
      50, config_.route_advertisement_period_ms / static_cast<std::uint32_t>(count));
  next_route_advertisement_ms_ = now_ms + interval;
}

void MeshNode::expire_sequence_requests(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* expired = seqno_seen_.find(
        [&](const SeqnoSeen& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    seqno_seen_.release(expired);
  }
  while (true) {
    auto* expired = seqno_state_.find(
        [&](const SeqnoState& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    seqno_state_.release(expired);
  }
}

void MeshNode::schedule_sequence_requests(const MonotonicMs now_ms) noexcept {
  // Outstanding = requests sent inside the dedup window, still waiting for a
  // fresh advertisement. Bounded so a dead origin cannot pile up requests.
  std::size_t inflight = 0;
  seqno_state_.for_each([&](const SeqnoState& value) {
    if (value.last_sent_ms != 0 &&
        value.last_sent_ms + kSeqnoRequestLifetimeMs > now_ms) {
      ++inflight;
    }
  });

  routes_.for_each_sequence_request([&](const NodeId destination,
                                        const RouteSequence requested_sequence) {
    auto* state = seqno_state_.find(
        [&](const SeqnoState& value) { return value.destination == destination; });
    if (state == nullptr) {
      state = seqno_state_.allocate();
      if (state == nullptr) return;
      state->destination = destination;
      state->requested_sequence = requested_sequence;
      state->next_request_ms = now_ms;
    }
    state->expires_at_ms = now_ms + kSeqnoStateDwellMs;
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, state->requested_sequence, ambiguous) ||
        ambiguous) {
      state->next_request_ms = now_ms;  // newer need: fresh retry window
      state->attempts = 0;
    }
    state->requested_sequence = requested_sequence;
    if (now_ms < state->next_request_ms || tx_queue_.full()) return;
    // Retry cap survives dedup expiry in seqno_state_: after the cap the
    // destination simply waits for organic fresh advertisements.
    if (state->attempts >= kSeqnoRequestMaxAttempts || inflight >= kSeqnoMaxInflight) {
      return;
    }

    const NodeId next = routes_.request_next_hop(destination, state->attempts);
    if (next == kInvalidNodeId || next == config_.node) return;
    const std::uint32_t request_id = next_seqno_request_id_++;
    auto* seen = seqno_seen_.allocate();
    if (seen == nullptr) return;
    *seen = SeqnoSeen{config_.node, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};
    if (queue_seqno_request(next, config_.node, destination, requested_sequence,
                            request_id, kDefaultHopLimit, now_ms)) {
      ++state->attempts;
      ++inflight;
      state->last_sent_ms = now_ms;
      // Linear backoff keeps retries bounded without a growing flood.
      state->next_request_ms = now_ms + std::min<std::uint32_t>(
          kSeqnoRequestMaxCooldownMs, kSeqnoRequestCooldownMs * state->attempts);
      char detail[64];
      std::snprintf(detail, sizeof detail, "SEQNO_REQUEST_SENT dest=%llu seq=%u att=%u",
                    static_cast<unsigned long long>(destination), requested_sequence,
                    state->attempts);
      observer_.on_diagnostic(detail, next, nullptr);
    } else {
      seqno_seen_.release(seen);
    }
  });
}

void MeshNode::trigger_route_advertisement(const MonotonicMs now_ms) noexcept {
  // Deterministic jitter decorrelates bursts across nodes without a RNG.
  const MonotonicMs jitter = (config_.node * 31ULL + ++trigger_counter_ * 7ULL) %
                             (kTriggeredJitterMs + 1ULL);
  const MonotonicMs earliest = std::max(now_ms, next_triggered_ms_) + jitter;
  if (!triggered_advertisement_ || earliest < triggered_at_ms_) {
    triggered_advertisement_ = true;
    triggered_at_ms_ = earliest;
  }
}

void MeshNode::run_triggered_advertisement(const MonotonicMs now_ms) noexcept {
  if (!triggered_advertisement_ || now_ms < triggered_at_ms_) return;
  triggered_advertisement_ = false;
  next_triggered_ms_ = now_ms + kTriggeredUpdateMinIntervalMs;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (!neighbor.active || tx_queue_.full()) return;
    (void)queue_route_update(neighbor.node, now_ms);
  });
}

void MeshNode::poll(const MonotonicMs now_ms) noexcept {
  if (!started_) return;
  routes_.expire(now_ms);
  expire_dedup(now_ms);
  expire_sequence_requests(now_ms);
  process_awaiting_hop(now_ms);
  process_delivery_timeouts(now_ms);
  routes_.for_each_selected_change(
      [&](const RouteSelection&) { trigger_route_advertisement(now_ms); });
  if (!draining_) {
    // Background work stops while draining; in-flight queue entries still
    // dispatch below so the TX path can settle.
    run_triggered_advertisement(now_ms);
    schedule_sequence_requests(now_ms);
    schedule_route_advertisements(now_ms);
  }
  dispatch_next(now_ms);
}

}  // namespace routeloom
