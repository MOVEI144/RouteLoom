#include "routeloom/app_object.hpp"

#include <algorithm>
#include <cstring>
#include "routeloom/discovery_scope.hpp"

namespace routeloom {
namespace {
using object_wire::Ack;
using object_wire::AckStatus;
constexpr std::uint8_t kManifest = 255;
constexpr MonotonicMs kNoProgressMs = 10000;
constexpr MonotonicMs kRecordSlackMs = 30000;
bool same_start(const object_wire::Start& a, const object_wire::Start& b) noexcept {
  return a.id == b.id && a.total == b.total && a.chunks == b.chunks &&
         a.app_tag == b.app_tag && a.encoding == b.encoding && a.digest == b.digest;
}
std::uint64_t all_bits(std::uint8_t chunks) noexcept { return (std::uint64_t{1} << chunks) - 1; }
MonotonicMs retry_delay(std::uint8_t sends, ObjectId id) noexcept {
  const MonotonicMs base = std::min<MonotonicMs>(4000, 1000ULL << (sends - 1));
  return base * (90 + id % 21) / 100;
}
}

bool AppObject::Key::operator==(const Key& o) const noexcept {
  return peer == o.peer && network == o.network && boot == o.boot && epoch == o.epoch && id == o.id && self == o.self && self_boot == o.self_boot;
}
AppObject::AppObject(MeshNode& node, SecurityProvider& security, ObjectObserver& observer) noexcept
    : node_(node), security_(security), observer_(observer) {}
AppObject::~AppObject() {
  for (auto& rx : rx_) rx.assembler.reset();
}
Status AppObject::attach() noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "object callback");
  if (node_.config_sink() == this) return Status::success();
  fallback_ = node_.config_sink();
  return node_.set_config_sink(this);
}
bool AppObject::accepts_extension(FrameType type) const noexcept {
  return type == FrameType::AppObjectStart || type == FrameType::AppObjectChunk ||
         type == FrameType::AppObjectAck;
}
std::uint32_t AppObject::permit_profile_bits() const noexcept {
  return fallback_ == nullptr ? 0 : fallback_->permit_profile_bits();
}
Status AppObject::register_buffer(MutableByteView buffer) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "object callback");
  if (buffer.data == nullptr || buffer.size < object_wire::kMaxBytes) {
    return Status::error(StatusCode::InvalidArgument, "object receive buffer requires 4096 bytes");
  }
  // Reject overlapping loans, including a repeated registration.
  const auto first = reinterpret_cast<std::uintptr_t>(buffer.data);
  if (buffer.size > UINTPTR_MAX - first) return Status::error(StatusCode::InvalidArgument, "buffer bounds");
  if (tx_.active) {
    const auto loan = reinterpret_cast<std::uintptr_t>(tx_.data.data);
    if (first < loan + tx_.data.size && loan < first + buffer.size) {
      return Status::error(StatusCode::Conflict, "object loans overlap");
    }
  }
  for (const auto& rx : rx_) {
    if (rx.storage.data == nullptr) continue;
    const auto other = reinterpret_cast<std::uintptr_t>(rx.storage.data);
    if (first < other + rx.storage.size && other < first + buffer.size) {
      return Status::error(StatusCode::Conflict, "object buffers overlap");
    }
  }
  for (auto& rx : rx_) {
    if (rx.storage.data == nullptr) { rx.storage = buffer; return Status::success(); }
  }
  return Status::error(StatusCode::Busy, "object receive slots full");
}
Status AppObject::send(NodeId destination, ByteView data, const ObjectOptions& options,
                      MonotonicMs now_ms, ObjectId& id) noexcept {
  id = 0;
  if (in_call_ || tx_.active || result_ready_) return Status::error(StatusCode::Busy, "object sender busy");
  if (data.size > object_wire::kMaxBytes) return Status::error(StatusCode::TooLarge, "object exceeds 4096 bytes");
  if (destination == 0 || destination == node_.node_id() || data.data == nullptr ||
      data.size == 0 || options.deadline_ms == 0 ||
      options.deadline_ms > 120000) {
    return Status::error(StatusCode::InvalidArgument, "object send bounds");
  }
  if (next_id_ == 0) return Status::error(StatusCode::CounterExhausted, "object ids exhausted");
  std::uint32_t tx_epoch = node_.config().end_epoch, rx_epoch = 0;
  if (!security_.tx_epoch(SecurityScope::EndToEnd, destination, tx_epoch) ||
      !security_.current_rx_epoch(SecurityScope::EndToEnd, destination, rx_epoch) ||
      !context_usable(security_.context_state(SecurityScope::EndToEnd, destination))) {
    return Status::error(StatusCode::AuthRequired, "object requires established end session");
  }
  // An immutable TX loan must not alias a buffer the endpoint can overwrite.
  const auto begin = reinterpret_cast<std::uintptr_t>(data.data);
  if (data.size > UINTPTR_MAX - begin) return Status::error(StatusCode::InvalidArgument, "object loan bounds");
  for (const auto& rx : rx_) {
    const auto other = reinterpret_cast<std::uintptr_t>(rx.storage.data);
    if (rx.storage.data != nullptr && begin < other + rx.storage.size && other < begin + data.size) {
      return Status::error(StatusCode::Conflict, "object loans overlap");
    }
  }
  tx_ = {};
  tx_.active = true; tx_.data = data; tx_.destination = destination;
  tx_.tx_epoch = tx_epoch; tx_.rx_epoch = rx_epoch;
  tx_.self = node_.node_id(); tx_.network = node_.config().network;
  tx_.self_boot = node_.config().message_session;
  tx_.deadline_ms = now_ms + options.deadline_ms; tx_.progress_ms = now_ms;
  tx_.start.id = next_id_++; tx_.start.total = static_cast<std::uint16_t>(data.size);
  tx_.start.chunks = static_cast<std::uint8_t>((data.size + object_wire::kChunkBytes - 1) / object_wire::kChunkBytes);
  tx_.start.app_tag = options.app_tag; tx_.start.encoding = options.content_encoding;
  tx_.start.lifetime_ms = options.deadline_ms;
  ScopeDigest digest{}; sha256(data, digest);
  std::copy_n(digest.begin(), tx_.start.digest.size(), tx_.start.digest.begin());
  id = tx_.start.id;
  return Status::success();
}
Status AppObject::cancel(ObjectId id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "object callback");
  if (!tx_.active || tx_.start.id != id) return Status::error(StatusCode::NotFound, "object not active");
  // The receiver may already have completed; no post-transmission cancellation
  // promises that the application did not see the object.
  finish_tx(tx_.ever_sent ? ObjectState::Indeterminate : ObjectState::CancelledBeforeTx,
            StatusCode::Ok);
  return Status::success();
}
AppObject::Key AppObject::key(const wire::PlainFrame& frame, ObjectId id) const noexcept {
  return {frame.header.origin, node_.config().network, node_.node_id(),
          frame.header.message.session, frame.header.end_epoch, id, node_.config().message_session};
}
bool AppObject::live(const Key& k) const noexcept {
  std::uint32_t epoch = 0;
  return k.self == node_.node_id() && k.self_boot == node_.config().message_session &&
         k.network == node_.config().network &&
         security_.current_rx_epoch(SecurityScope::EndToEnd, k.peer, epoch).ok() && epoch == k.epoch &&
         context_usable(security_.context_state(SecurityScope::EndToEnd, k.peer));
}
bool AppObject::live_tx() noexcept {
  std::uint32_t epoch = node_.config().end_epoch, rx_epoch = 0;
  return tx_.self == node_.node_id() && tx_.network == node_.config().network &&
         tx_.self_boot == node_.config().message_session &&
         security_.tx_epoch(SecurityScope::EndToEnd, tx_.destination, epoch).ok() && epoch == tx_.tx_epoch &&
         security_.current_rx_epoch(SecurityScope::EndToEnd, tx_.destination, rx_epoch).ok() && rx_epoch == tx_.rx_epoch &&
         context_usable(security_.context_state(SecurityScope::EndToEnd, tx_.destination));
}
std::uint64_t AppObject::bits(const Rx& rx) const noexcept {
  std::uint64_t out = 0;
  for (unsigned i = 0; i < rx.bitmap.size(); ++i) out |= std::uint64_t{rx.bitmap[i]} << (8 * i);
  return out;
}
void AppObject::on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                               MonotonicMs now_ms) noexcept {
  if (!accepts_extension(frame.header.type)) {
    if (fallback_ != nullptr) fallback_->on_config_frame(peer, frame, now_ms);
    return;
  }
  if (in_call_ || (frame.header.flags & wire::kFlagEndProtected) == 0 ||
      frame.header.destination != node_.node_id()) return;
  if (!live(key(frame, 0))) return;
  switch (frame.header.type) {
    case FrameType::AppObjectStart: start_rx(frame, now_ms); break;
    case FrameType::AppObjectChunk: chunk_rx(frame, now_ms); break;
    case FrameType::AppObjectAck: ack_rx(frame, now_ms); break;
    default: break;
  }
}
void AppObject::start_rx(const wire::PlainFrame& frame, MonotonicMs now_ms) noexcept {
  object_wire::Start start{};
  if (!object_wire::decode({frame.payload.data(), frame.payload_size}, start)) return;
  const Key k = key(frame, start.id);
  for (auto& record : records_) {
    if (!record.used || !(record.key == k)) continue;
    if (!same_start(record.start, start)) {
      for (auto& rx : rx_) {
        if (rx.assembler.active() && rx.key == k) finish_rx(rx, AckStatus::Conflict);
      }
      queue_ack(k.peer, {k.id, AckStatus::Conflict, 0, 0}, now_ms);
    } else { record.ack_pending = true; }
    return;
  }
  std::size_t floor_index = floors_.size();
  std::size_t vacant = floors_.size();
  for (std::size_t i = 0; i < floors_.size(); ++i) {
    auto& candidate = floors_[i];
    auto& peer = floor_peers_[i];
    std::uint32_t epoch = 0;
    if (peer != 0 && (!security_.current_rx_epoch(SecurityScope::EndToEnd, peer, epoch) ||
                     epoch != candidate.epoch)) {
      peer = 0;
      candidate = {};
    }
    if (peer == k.peer && candidate.epoch == k.epoch) floor_index = i;
    if (peer == 0 && vacant == floors_.size()) vacant = i;
  }
  Floor* floor = floor_index == floors_.size() ? nullptr : &floors_[floor_index];
  if (floor != nullptr && (k.boot < floor->boot || (k.boot == floor->boot && start.id <= floor->highest))) {
    queue_ack(k.peer, {k.id, AckStatus::Expired, 0, 0}, now_ms); return;
  }
  // A newer authenticated boot retires old receive work even when every
  // slot is occupied. Retain the boot floor if new admission is Busy.
  if (floor != nullptr && k.boot > floor->boot) {
    for (auto& rx : rx_) {
      if (rx.assembler.active() && rx.key.peer == k.peer) finish_rx(rx, AckStatus::Failed);
    }
    floor->boot = k.boot;
    floor->highest = 0;
  }
  std::size_t record_index = records_.size();
  for (std::size_t i = 0; i < records_.size(); ++i) {
    if (!records_[i].used) { record_index = i; break; }
  }
  std::size_t active = 0;
  for (const auto& rx : rx_) if (rx.assembler.active()) ++active;
  if (!observer_.object_receive_ready() || active >= observer_.object_receive_slots()) {
    queue_ack(k.peer, {k.id, AckStatus::Busy, 0, 0}, now_ms); return;
  }
  Rx* slot = nullptr;
  bool buffer_present = false;
  for (auto& rx : rx_) {
    buffer_present |= rx.storage.data != nullptr;
    if (rx.assembler.active() && rx.key.peer == k.peer) {
      queue_ack(k.peer, {k.id, AckStatus::Busy, 0, 0}, now_ms); return;
    }
    if (rx.storage.data != nullptr && !rx.assembler.active()) slot = &rx;
  }
  if (slot == nullptr || record_index == records_.size() ||
      (floor == nullptr && vacant == floors_.size())) {
    queue_ack(k.peer, {k.id, buffer_present ? AckStatus::Busy : AckStatus::NoBuffer, 0, 0}, now_ms); return;
  }
  if (floor == nullptr) {
    floor_peers_[vacant] = k.peer;
    floor = &floors_[vacant];
    *floor = {k.epoch, 0, k.boot};
  }
  // Routed TTL accounts for time already spent queued and in transit.
  // The object's remaining lifetime must consume that same elapsed time.
  const auto elapsed = frame.header.original_lifetime_ms - frame.header.remaining_deadline_ms;
  if (elapsed >= start.lifetime_ms) {
    queue_ack(k.peer, {k.id, AckStatus::Expired, 0, 0}, now_ms); return;
  }
  const auto deadline = now_ms + start.lifetime_ms - elapsed;
  if (!slot->assembler.begin(slot->storage, {slot->bitmap.data(), slot->bitmap.size()},
                             start.total, object_wire::kChunkBytes, deadline)) return;
  floor->highest = start.id; floor->boot = k.boot;
  slot->key = k; slot->start = start; slot->progress_ms = now_ms;
  slot->deadline_ms = deadline; slot->record = static_cast<std::uint8_t>(record_index);
  slot->ready = false;
  records_[record_index] = {k, start, slot->deadline_ms + kRecordSlackMs, AckStatus::Incomplete, 0, true, true};
}
void AppObject::chunk_rx(const wire::PlainFrame& frame, MonotonicMs now_ms) noexcept {
  object_wire::Chunk chunk{};
  if (!object_wire::decode({frame.payload.data(), frame.payload_size}, chunk)) return;
  const Key k = key(frame, chunk.id);
  for (auto& rx : rx_) {
    if (!rx.assembler.active() || !(rx.key == k)) continue;
    if (now_ms >= rx.deadline_ms || now_ms - rx.progress_ms >= kNoProgressMs) {
      finish_rx(rx, AckStatus::Expired); return;
    }
    const auto before = rx.assembler.received();
    const Status added = rx.assembler.insert(static_cast<std::uint16_t>(chunk.index * object_wire::kChunkBytes),
                                             chunk.data, now_ms);
    if (!added) { finish_rx(rx, AckStatus::Conflict); return; }
    if (rx.assembler.received() != before) rx.progress_ms = now_ms;
    auto& record = records_[rx.record]; record.bitmap = bits(rx); record.ack_pending = true;
    if (rx.assembler.complete()) {
      if (!rx.assembler.verify({rx.start.digest.data(), rx.start.digest.size()})) {
        finish_rx(rx, AckStatus::Failed); return;
      }
      rx.ready = true;
    }
    return;
  }
  for (auto& record : records_) {
    if (record.used && record.key == k) { record.ack_pending = true; return; }
  }
  queue_ack(k.peer, {k.id, AckStatus::Expired, 0, 0}, now_ms);
}
void AppObject::ack_rx(const wire::PlainFrame& frame, MonotonicMs now_ms) noexcept {
  Ack ack{};
  if (!object_wire::decode({frame.payload.data(), frame.payload_size}, ack) || !tx_.active ||
      frame.header.origin != tx_.destination || frame.header.end_epoch != tx_.rx_epoch ||
      ack.id != tx_.start.id || now_ms >= tx_.deadline_ms ||
      (ack.bitmap & ~tx_.emitted) != 0) return;
  if (!live_tx()) {
    finish_tx(ObjectState::Failed, StatusCode::AuthRequired); return;
  }
  if (now_ms - tx_.progress_ms >= kNoProgressMs) return;
  if (tx_.destination_boot != 0 && tx_.destination_boot != frame.header.message.session) {
    finish_tx(ObjectState::Failed, StatusCode::AuthRequired); return;
  }
  tx_.destination_boot = frame.header.message.session;
  if (ack.status == AckStatus::Complete) {
    if (ack.bitmap == all_bits(tx_.start.chunks)) finish_tx(ObjectState::Delivered, StatusCode::Ok);
    return;
  }
  if (ack.status != AckStatus::Incomplete) {
    finish_tx(ack.status == AckStatus::Unsupported ? ObjectState::Unsupported : ObjectState::Failed,
              ack.status == AckStatus::Busy ? StatusCode::RemoteBusy :
              ack.status == AckStatus::NoBuffer ? StatusCode::NoCapacity :
              ack.status == AckStatus::Expired ? StatusCode::Expired :
              ack.status == AckStatus::Unsupported ? StatusCode::Unsupported : StatusCode::ProtocolError);
    return;
  }
  if (!tx_.manifest_acked || (ack.bitmap & ~tx_.acked) != 0) tx_.progress_ms = now_ms;
  tx_.manifest_acked = true; tx_.acked |= ack.bitmap;
  for (auto& flight : tx_.flight) {
    if (flight.used && (flight.index == kManifest || (tx_.acked & (std::uint64_t{1} << flight.index)) != 0)) flight = {};
  }
}
void AppObject::finish_rx(Rx& rx, AckStatus status) noexcept {
  auto& record = records_[rx.record]; record.status = status;
  record.bitmap = bits(rx); record.ack_pending = true;
  rx.assembler.reset(); rx.ready = false;
}
void AppObject::finish_tx(ObjectState state, StatusCode reason) noexcept {
  result_ = {tx_.start.id, state, reason}; result_ready_ = true;
  tx_ = {};
}
bool AppObject::send_frame(FrameType type, NodeId peer, ByteView payload,
                           MonotonicMs now_ms, MessageId& id, std::uint32_t lifetime_ms) noexcept {
  if (now_ms < send_after_ms_) return false;
  if (!node_.send_typed(type, peer, payload, lifetime_ms, now_ms, id)) return false;
  // Bound queue production as well as physical dispatch, including ACKs.
  const MonotonicMs cost_us = (payload.size + 88 + 32 + kTxFrameFixedCostBytes) * 32;
  send_after_ms_ = now_ms + (cost_us + 49) / 50;
  return true;
}
void AppObject::queue_ack(NodeId peer, const Ack& ack, MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, object_wire::kAckBytes> bytes{}; std::size_t size = 0; MessageId id{};
  if (object_wire::encode(ack, {bytes.data(), bytes.size()}, size)) {
    (void)send_frame(FrameType::AppObjectAck, peer, {bytes.data(), size}, now_ms, id);
  }
}
void AppObject::on_config_job_done(const MessageId& id, bool accepted, const char* reason,
                                 MonotonicMs now_ms) noexcept {
  if (tx_.active) {
    for (auto& flight : tx_.flight) {
      if (!flight.used || !(flight.job == id)) continue;
      flight.queued = false;
      flight.sent_ms = now_ms;
      tx_.ever_sent |= accepted;
      if (!accepted && reason != nullptr && std::strcmp(reason, "UNSUPPORTED") == 0) {
        finish_tx(ObjectState::Unsupported, StatusCode::Unsupported);
      }
      return;
    }
  }
  if (fallback_ != nullptr) fallback_->on_config_job_done(id, accepted, reason, now_ms);
}
void AppObject::pump(MonotonicMs now_ms) noexcept {
  for (auto& flight : tx_.flight) {
    if (!flight.used) continue;
    if (flight.queued || (flight.sent_ms != 0 && now_ms - flight.sent_ms < retry_delay(flight.sends, tx_.start.id))) continue;
    if (flight.sends >= 5) { finish_tx(ObjectState::Failed, StatusCode::Expired); return; }
    std::array<std::uint8_t, kMaxApplicationPayload> bytes{}; std::size_t size = 0;
    FrameType type = FrameType::AppObjectChunk;
    if (flight.index == kManifest) {
      type = FrameType::AppObjectStart;
      auto start = tx_.start; start.lifetime_ms = static_cast<std::uint32_t>(tx_.deadline_ms - now_ms);
      (void)object_wire::encode(start, {bytes.data(), bytes.size()}, size);
    } else {
      const std::size_t offset = flight.index * object_wire::kChunkBytes;
      const std::size_t count = std::min<std::size_t>(object_wire::kChunkBytes, tx_.data.size - offset);
      (void)object_wire::encode(object_wire::Chunk{tx_.start.id, flight.index, {tx_.data.data + offset, count}},
                                {bytes.data(), bytes.size()}, size);
    }
    if (send_frame(type, tx_.destination, {bytes.data(), size}, now_ms, flight.job,
                   static_cast<std::uint32_t>(std::min<MonotonicMs>(4000, tx_.deadline_ms - now_ms)))) {
      flight.queued = true; ++flight.sends; tx_.ever_sent = true;
      if (flight.index != kManifest) tx_.emitted |= std::uint64_t{1} << flight.index;
    }
    return;
  }
  if (!tx_.manifest_acked) {
    for (const auto& flight : tx_.flight) if (flight.used) return;
    tx_.flight[0] = {}; tx_.flight[0].used = true; tx_.flight[0].index = kManifest;
    return;
  }
  for (auto& flight : tx_.flight) {
    if (flight.used) continue;
    for (std::uint8_t i = 0; i < tx_.start.chunks; ++i) {
      if ((tx_.acked & (std::uint64_t{1} << i)) != 0) continue;
      bool inflight = false;
      for (const auto& other : tx_.flight) inflight |= other.used && other.index == i;
      if (inflight) continue;
      flight = {}; flight.used = true; flight.index = i; break;
    }
  }
  // All chunks were selectively acked but COMPLETE was lost: retry START
  // against the reserved completion record, never notify the app again.
  if (tx_.acked == all_bits(tx_.start.chunks)) {
    for (const auto& flight : tx_.flight) if (flight.used) return;
    tx_.flight[0] = {}; tx_.flight[0].used = true; tx_.flight[0].index = kManifest;
  }
}
void AppObject::poll(MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  if (fallback_ != nullptr) fallback_->poll(now_ms);
  for (auto& rx : rx_) {
    if (!rx.assembler.active()) continue;
    if (!live(rx.key)) { finish_rx(rx, AckStatus::Failed); continue; }
    if (now_ms >= rx.deadline_ms || now_ms - rx.progress_ms >= kNoProgressMs) {
      finish_rx(rx, AckStatus::Expired); continue;
    }
    if (rx.ready && observer_.object_receive_ready()) {
      const ObjectRxInfo info{rx.key.peer, rx.start.id, rx.key.boot, rx.key.epoch,
                              rx.start.app_tag, rx.start.encoding};
      in_call_ = true; observer_.on_object(info, rx.assembler.data()); in_call_ = false;
      finish_rx(rx, AckStatus::Complete);
    }
  }
  for (auto& record : records_) {
    if (!record.used) continue;
    if (now_ms >= record.until_ms || !live(record.key)) { record = {}; continue; }
    if (!record.ack_pending || now_ms < send_after_ms_) continue;
    std::uint8_t missing = 0;
    while (missing < record.start.chunks && (record.bitmap & (std::uint64_t{1} << missing)) != 0) ++missing;
    std::array<std::uint8_t, object_wire::kAckBytes> bytes{}; std::size_t size = 0; MessageId id{};
    if (object_wire::encode(Ack{record.key.id, record.status, missing, record.bitmap},
                            {bytes.data(), bytes.size()}, size) &&
        send_frame(FrameType::AppObjectAck, record.key.peer, {bytes.data(), size}, now_ms, id)) record.ack_pending = false;
  }
  if (tx_.active) {
    if (!live_tx()) {
      finish_tx(ObjectState::Failed, StatusCode::AuthRequired);
    } else if (now_ms >= tx_.deadline_ms || now_ms - tx_.progress_ms >= kNoProgressMs) {
      finish_tx(ObjectState::Expired, StatusCode::Expired);
    } else { pump(now_ms); }
  }
  if (result_ready_) {
    const auto result = result_; result_ready_ = false;
    in_call_ = true; observer_.on_object_result(result); in_call_ = false;
  }
}
bool AppObject::quiescent() const noexcept {
  if (tx_.active || result_ready_) return false;
  for (const auto& rx : rx_) if (rx.assembler.active()) return false;
  return true;
}
}  // namespace routeloom
