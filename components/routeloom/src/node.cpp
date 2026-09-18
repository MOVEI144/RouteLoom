#include "routeloom/node.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "routeloom/byte_io.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kControlLifetimeMs = 1000;
constexpr std::uint32_t kMinimumEndToEndRetryMs = 250;
constexpr std::size_t kRouteRecordBytes = 12;
constexpr std::size_t kMaxRouteRecordsPerFrame = 10;
constexpr std::uint32_t kSeqnoRequestLifetimeMs = 2000;
constexpr std::uint32_t kSeqnoRequestCooldownMs = 250;
constexpr std::size_t kSeqnoRequestPayloadBytes = 8 + 8 + 2 + 4 + 1;

}  // namespace

MeshNode::MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
                   NodeObserver& observer) noexcept
    : config_(config), radio_(radio), security_(security), observer_(observer) {}

Status MeshNode::validate_config() const noexcept {
  if (config_.network == 0 || config_.network > UINT32_MAX ||
      config_.node == kInvalidNodeId || config_.node == kBroadcastNodeId ||
      config_.message_session == 0 || config_.route_advertisement_period_ms == 0 ||
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
  }
  record->node = neighbor;
  record->metric = link_metric;
  record->consecutive_failures = 0;
  record->active = true;
  const RouteAdvertisement direct{neighbor, 0, 0};
  const auto result = routes_.consider(direct, neighbor, link_metric, now_ms,
                                       config_.route_lifetime_ms);
  if (result == RouteUpdateResult::NoCapacity) {
    record->active = false;
    return Status::error(StatusCode::NoCapacity, "route table full");
  }
  next_route_advertisement_ms_ = now_ms;
  return Status::success();
}

Status MeshNode::remove_neighbor(const NodeId neighbor) noexcept {
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) return Status::error(StatusCode::NotFound, "neighbor not found");
  record->active = false;
  routes_.invalidate_next_hop(neighbor);
  ++self_route_sequence_;
  next_route_advertisement_ms_ = 0;
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
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      options.lifetime_ms == 0 || options.hop_limit == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid send request");
  }
  if (options.delivery == DeliveryClass::Applied) {
    return Status::error(StatusCode::Unsupported, "APPLIED is not implemented in CORE_FIXED_250");
  }
  auto* record = deliveries_.allocate();
  if (record == nullptr) return Status::error(StatusCode::NoCapacity, "delivery table full");
  record->id = MessageId{config_.message_session, next_message_sequence_++};
  record->destination = destination;
  record->options = options;
  record->payload_size = payload.size;
  if (payload.size > 0) std::memcpy(record->payload.data(), payload.data, payload.size);
  record->created_at_ms = now_ms;
  record->expires_at_ms = now_ms + options.lifetime_ms;
  record->round = 0;
  set_delivery_state(*record, DeliveryState::Accepted, "TX_ACCEPTED");
  id = record->id;

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
  job.plain.header.hop_remaining = data.hop_remaining;
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
  auto append = [&](const NodeId destination, const RouteSequence sequence,
                    const RouteMetric metric) {
    if (count >= kMaxRouteRecordsPerFrame) return;
    if (writer.write_u64(destination) && writer.write_u16(sequence) && writer.write_u16(metric)) {
      ++count;
    }
  };
  append(config_.node, self_route_sequence_, 0);
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (selection.destination == config_.node || count >= kMaxRouteRecordsPerFrame) return;
    append(selection.destination, selection.sequence,
           selection.next_hop == neighbor ? kInfiniteRouteMetric : selection.metric);
    routes_.mark_advertised(selection.destination);
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
      if (neighbor->consecutive_failures >= 2) routes_.invalidate_next_hop(job.peer);
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
  const auto retry_window = std::max<std::uint32_t>(
      kMinimumEndToEndRetryMs,
      static_cast<std::uint32_t>(delivery->options.hop_limit) *
          config_.hop_accept_timeout_ms * 2U);
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
    if (!tx_queue_.push(std::move(job))) fail_job(job, "TX_QUEUE_FULL", now_ms);
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
  const auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return;
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  std::uint8_t count = 0;
  if (!reader.read_u8(count) || count > kMaxRouteRecordsPerFrame ||
      reader.remaining() != static_cast<std::size_t>(count) * kRouteRecordBytes) {
    observer_.on_diagnostic("INVALID_ROUTE_UPDATE", peer, &frame.header.message);
    return;
  }
  for (std::uint8_t i = 0; i < count; ++i) {
    RouteAdvertisement advertisement{};
    if (!reader.read_u64(advertisement.destination) ||
        !reader.read_u16(advertisement.sequence) ||
        !reader.read_u16(advertisement.metric)) {
      return;
    }
    if (advertisement.destination == config_.node) continue;
    const auto result = routes_.consider(advertisement, peer, neighbor->metric, now_ms,
                                         config_.route_lifetime_ms);
    if (result == RouteUpdateResult::Infeasible) {
      observer_.on_diagnostic("ROUTE_INFEASIBLE_SEQNO_NEEDED", peer, nullptr);
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
    if (requested_sequence == self_route_sequence_ ||
        route_sequence_newer(requested_sequence, self_route_sequence_, ambiguous)) {
      self_route_sequence_ = static_cast<RouteSequence>(requested_sequence + 1U);
    } else if (ambiguous) {
      self_route_sequence_ = static_cast<RouteSequence>(self_route_sequence_ + 1U);
    }
    next_route_advertisement_ms_ = now_ms;
    observer_.on_diagnostic("SEQNO_REQUEST_SATISFIED", peer, &frame.header.message);
    return;
  }

  if (ttl <= 1) return;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (!neighbor.active || neighbor.node == peer || tx_queue_.full()) return;
    (void)queue_seqno_request(neighbor.node, requester, destination, requested_sequence,
                              request_id, static_cast<std::uint8_t>(ttl - 1U), now_ms);
  });
}

void MeshNode::on_radio_receive(const NodeId peer, const ByteView encoded,
                                const RadioRxMetadata& metadata,
                                const MonotonicMs now_ms) noexcept {
  (void)metadata;
  if (!started_) return;
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
    if ((delivery.state == DeliveryState::WaitingForRoute ||
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
}

void MeshNode::schedule_sequence_requests(const MonotonicMs now_ms) noexcept {
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
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, state->requested_sequence, ambiguous) ||
        ambiguous) {
      state->next_request_ms = now_ms;
    }
    state->requested_sequence = requested_sequence;
    if (now_ms < state->next_request_ms || tx_queue_.full()) return;

    const std::uint32_t request_id = next_seqno_request_id_++;
    auto* seen = seqno_seen_.allocate();
    if (seen == nullptr) return;
    *seen = SeqnoSeen{config_.node, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};
    neighbors_.for_each([&](const Neighbor& neighbor) {
      if (!neighbor.active || tx_queue_.full()) return;
      (void)queue_seqno_request(neighbor.node, config_.node, destination,
                                requested_sequence, request_id, kDefaultHopLimit, now_ms);
    });
    state->next_request_ms = now_ms + kSeqnoRequestCooldownMs;
    observer_.on_diagnostic("SEQNO_REQUEST_SENT", kInvalidNodeId, nullptr);
  });
}

void MeshNode::poll(const MonotonicMs now_ms) noexcept {
  if (!started_) return;
  routes_.expire(now_ms);
  expire_dedup(now_ms);
  expire_sequence_requests(now_ms);
  process_awaiting_hop(now_ms);
  process_delivery_timeouts(now_ms);
  schedule_sequence_requests(now_ms);
  schedule_route_advertisements(now_ms);
  dispatch_next(now_ms);
}

}  // namespace routeloom
