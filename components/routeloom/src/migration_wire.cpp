#include "routeloom/migration_wire.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

#include "routeloom/byte_io.hpp"

namespace routeloom {
namespace {

constexpr Status reject(const StatusCode code, const char* detail) noexcept {
  return Status::error(code, detail);
}

// Same field order as the durable-record codec in migration.cpp — the
// signing input and stored records serialize the operation identically.
Status write_operation_fields(ByteWriter& writer,
                              const AuthorityOperation& op) noexcept {
  Status status = writer.write_u64(op.network);
  if (status) status = writer.write_u64(op.authority);
  if (status) status = writer.write_u32(op.generation);
  if (status) status = writer.write_u64(op.sequence);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(op.kind));
  if (status) {
    status = writer.write_bytes(ByteView{op.previous_state_hash.data(), 32});
  }
  if (status) {
    status = writer.write_bytes(ByteView{op.operation_hash.data(), 32});
  }
  return status;
}

Status read_operation_fields(ByteReader& reader,
                             AuthorityOperation& out) noexcept {
  std::uint8_t kind = 0;
  Status status = reader.read_u64(out.network);
  if (status) status = reader.read_u64(out.authority);
  if (status) status = reader.read_u32(out.generation);
  if (status) status = reader.read_u64(out.sequence);
  if (status) status = reader.read_u8(kind);
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.previous_state_hash.data(), 32});
  }
  if (status) {
    status =
        reader.read_bytes(MutableByteView{out.operation_hash.data(), 32});
  }
  if (status) out.kind = static_cast<AuthorityOperationKind>(kind);
  return status;
}

}  // namespace

// --- object-content codecs ----------------------------------------------------

Status commit_signing_input(const AuthorityOperation& operation,
                            const Digest256& plan_hash,
                            const ChannelEpoch new_epoch,
                            const MutableByteView target,
                            std::size_t& out_size) noexcept {
  out_size = 0;
  ByteWriter writer(target);
  Status status = writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>("RLCMT1"), 6});
  if (status) status = write_operation_fields(writer, operation);
  if (status) status = writer.write_bytes(ByteView{plan_hash.data(), 32});
  if (status) status = writer.write_u32(new_epoch.value);
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status commit_evidence_encode(const CommitEvidence& evidence,
                              const MutableByteView target,
                              std::size_t& out_size) noexcept {
  out_size = 0;
  if (evidence.signature_size > evidence.signature.size()) {
    return reject(StatusCode::InvalidArgument, "COMMIT_EVIDENCE_SIG_BOUND");
  }
  ByteWriter writer(target);
  Status status = write_operation_fields(writer, evidence.operation);
  if (status) {
    status =
        writer.write_bytes(ByteView{evidence.plan_hash.data(), 32});
  }
  if (status) status = writer.write_u32(evidence.new_epoch.value);
  if (status) status = writer.write_u16(evidence.signature_size);
  if (status) {
    status = writer.write_bytes(
        ByteView{evidence.signature.data(), evidence.signature_size});
  }
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status commit_evidence_decode(const ByteView encoded,
                              CommitEvidence& out) noexcept {
  out = CommitEvidence{};
  ByteReader reader(encoded);
  Status status = read_operation_fields(reader, out.operation);
  if (status) {
    status = reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  }
  if (status) status = reader.read_u32(out.new_epoch.value);
  std::uint16_t signature_size = 0;
  if (status) status = reader.read_u16(signature_size);
  if (status &&
      (signature_size == 0 ||
       signature_size > migration_const::kMaxCommitSignature)) {
    status = reject(StatusCode::ProtocolError, "COMMIT_EVIDENCE_SIG");
  }
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.signature.data(), signature_size});
  }
  if (!status || reader.remaining() != 0) {
    return reject(StatusCode::ProtocolError, "COMMIT_EVIDENCE_DECODE");
  }
  out.signature_size = static_cast<std::uint8_t>(signature_size);
  return Status::success();
}

Status ready_report_encode(const ReadyReport& report,
                           const MutableByteView target,
                           std::size_t& out_size) noexcept {
  out_size = 0;
  ByteWriter writer(target);
  Status status =
      writer.write_bytes(ByteView{report.plan_hash.data(), 32});
  if (status) status = writer.write_u32(report.new_epoch.value);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(report.status));
  }
  std::uint8_t flags = 0;
  if (report.migration_capable) flags |= 0x01U;
  if (report.sleep_lease_valid) flags |= 0x02U;
  if (report.rediscovery_capable) flags |= 0x04U;
  if (report.storage_ok) flags |= 0x08U;
  if (report.clock_ok) flags |= 0x10U;
  if (report.drain_ok) flags |= 0x20U;
  if (status) status = writer.write_u8(flags);
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status ready_report_decode(const ByteView encoded, ReadyReport& out) noexcept {
  out = ReadyReport{};
  ByteReader reader(encoded);
  std::uint8_t status = 0, flags = 0;
  Status result =
      reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  if (result) result = reader.read_u32(out.new_epoch.value);
  if (result) result = reader.read_u8(status);
  if (result) result = reader.read_u8(flags);
  if (!result || reader.remaining() != 0 || status == 0 || status > 3) {
    return reject(StatusCode::ProtocolError, "READY_REPORT_DECODE");
  }
  out.status = static_cast<ReadyStatus>(status);
  out.migration_capable = (flags & 0x01U) != 0;
  out.sleep_lease_valid = (flags & 0x02U) != 0;
  out.rediscovery_capable = (flags & 0x04U) != 0;
  out.storage_ok = (flags & 0x08U) != 0;
  out.clock_ok = (flags & 0x10U) != 0;
  out.drain_ok = (flags & 0x20U) != 0;
  return Status::success();
}

Status result_report_encode(const ResultReport& report,
                            const MutableByteView target,
                            std::size_t& out_size) noexcept {
  out_size = 0;
  ByteWriter writer(target);
  Status status =
      writer.write_bytes(ByteView{report.plan_hash.data(), 32});
  if (status) status = writer.write_u32(report.epoch.value);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(report.outcome));
  }
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status result_report_decode(const ByteView encoded,
                            ResultReport& out) noexcept {
  out = ResultReport{};
  ByteReader reader(encoded);
  std::uint8_t outcome = 0;
  Status status =
      reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  if (status) status = reader.read_u32(out.epoch.value);
  if (status) status = reader.read_u8(outcome);
  if (!status || reader.remaining() != 0 || outcome == 0 || outcome > 4) {
    return reject(StatusCode::ProtocolError, "RESULT_REPORT_DECODE");
  }
  out.outcome = static_cast<ResultOutcome>(outcome);
  return Status::success();
}

Status snapshot_request_encode(const SnapshotRequest& request,
                               const MutableByteView target,
                               std::size_t& out_size) noexcept {
  out_size = 0;
  ByteWriter writer(target);
  Status status = writer.write_u32(request.known_epoch.value);
  if (status) {
    status = writer.write_bytes(ByteView{request.plan_hash.data(), 32});
  }
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status snapshot_request_decode(const ByteView encoded,
                               SnapshotRequest& out) noexcept {
  out = SnapshotRequest{};
  ByteReader reader(encoded);
  Status status = reader.read_u32(out.known_epoch.value);
  if (status) {
    status = reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  }
  if (!status || reader.remaining() != 0) {
    return reject(StatusCode::ProtocolError, "SNAPSHOT_REQUEST_DECODE");
  }
  return Status::success();
}

Status signed_snapshot_wrap(const ByteView snapshot_body,
                            const ByteView signature,
                            const MutableByteView target,
                            std::size_t& out_size) noexcept {
  out_size = 0;
  if (signature.size == 0 ||
      signature.size > migration_const::kMaxCommitSignature ||
      snapshot_body.size == 0 ||
      snapshot_body.size > migration_const::kSnapshotMax) {
    return reject(StatusCode::InvalidArgument, "SNAPSHOT_WRAP_BOUND");
  }
  ByteWriter writer(target);
  Status status =
      writer.write_u16(static_cast<std::uint16_t>(signature.size));
  if (status) status = writer.write_bytes(signature);
  if (status) status = writer.write_bytes(snapshot_body);
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status signed_snapshot_unwrap(const ByteView object,
                              ByteView& snapshot_body,
                              ByteView& signature) noexcept {
  snapshot_body = ByteView{};
  signature = ByteView{};
  if (object.data == nullptr || object.size < 3) {
    return reject(StatusCode::ProtocolError, "SNAPSHOT_UNWRAP");
  }
  const std::uint16_t signature_size =
      static_cast<std::uint16_t>((static_cast<std::uint16_t>(object.data[0])
                                  << 8U) |
                                 object.data[1]);
  if (signature_size == 0 ||
      signature_size > migration_const::kMaxCommitSignature ||
      object.size <= 2U + signature_size) {
    return reject(StatusCode::ProtocolError, "SNAPSHOT_SIG_BOUND");
  }
  signature = ByteView{object.data + 2, signature_size};
  snapshot_body = ByteView{object.data + 2 + signature_size,
                           object.size - 2 - signature_size};
  return Status::success();
}

// --- PlanExchange -----------------------------------------------------------------

PlanExchange::PlanExchange(const PlanExchangeConfig& config,
                           MigrationWirePort& wire,
                           MigrationObjectSink& sink) noexcept
    : config_(config), wire_(wire), sink_(sink) {}

PlanExchange::Inbound* PlanExchange::find_inbound(
    const NodeId peer, const autonomy::ObjectHash& hash) noexcept {
  for (auto& slot : inbound_) {
    if (slot.used && slot.peer == peer && slot.hash == hash) return &slot;
  }
  return nullptr;
}

PlanExchange::Outbound* PlanExchange::find_outbound(
    const NodeId dest, const autonomy::ObjectHash& hash) noexcept {
  for (auto& slot : outbound_) {
    if (slot.used && slot.dest == dest && slot.hash == hash) return &slot;
  }
  return nullptr;
}

bool PlanExchange::delivered_before(
    const autonomy::ObjectHash& hash) const noexcept {
  for (const auto& entry : delivered_) {
    if (entry == hash) return true;
  }
  return false;
}

void PlanExchange::note_delivered(
    const autonomy::ObjectHash& hash) noexcept {
  delivered_[delivered_next_] = hash;
  delivered_next_ = (delivered_next_ + 1) % delivered_.size();
}

void PlanExchange::send_ack(const NodeId peer,
                            const autonomy::ObjectHash& hash,
                            const std::uint16_t received_len,
                            const autonomy::ObjectAckStatus status) noexcept {
  autonomy::ObjectAckPayload ack{};
  ack.object_hash = hash;
  ack.received_len = received_len;
  ack.status = status;
  autonomy::EncodedPayload payload{};
  if (!object_ack_encode(ack, payload).ok()) return;
  // Best-effort: a lost ack is recovered by the sender's bounded resend.
  (void)wire_.migration_send(peer, FrameType::ObjectAck, payload.view());
}

void PlanExchange::on_manifest(
    const NodeId peer, const autonomy::ControlObjectPayload& manifest,
    const MonotonicMs now_ms) noexcept {
  if (manifest.subtype != autonomy::ControlObjectSubtype::Manifest ||
      manifest.total_len == 0 ||
      manifest.total_len > migration_wire_const::kMigrationObjectMax) {
    send_ack(peer, manifest.object_hash, 0, autonomy::ObjectAckStatus::Failed);
    return;
  }
  if (delivered_before(manifest.object_hash)) {
    // Duplicate transfer of an object already dispatched: re-ack, never
    // re-run the semantic layer.
    send_ack(peer, manifest.object_hash, manifest.total_len,
             autonomy::ObjectAckStatus::Ok);
    return;
  }
  Inbound* slot = find_inbound(peer, manifest.object_hash);
  if (slot == nullptr) {
    for (auto& candidate : inbound_) {
      if (!candidate.used) {
        slot = &candidate;
        break;
      }
    }
  }
  if (slot == nullptr) {
    for (auto& candidate : inbound_) {
      if (candidate.deadline_ms <= now_ms) {
        candidate.used = false;
        slot = &candidate;
        break;
      }
    }
  }
  if (slot == nullptr) return;  // bounded: sender's resend retries later
  slot->used = true;
  slot->peer = peer;
  slot->kind = manifest.kind;
  slot->hash = manifest.object_hash;
  slot->total_len = manifest.total_len;
  slot->received = 0;
  slot->deadline_ms = now_ms + config_.inbound_expiry_ms;
}

void PlanExchange::on_chunk(const NodeId peer,
                            const autonomy::ObjectChunkPayload& chunk,
                            const MonotonicMs now_ms) noexcept {
  Inbound* slot = find_inbound(peer, chunk.object_hash);
  if (slot == nullptr) {
    send_ack(peer, chunk.object_hash, 0,
             autonomy::ObjectAckStatus::Incomplete);
    return;
  }
  // In-order reassembly: the offset must continue the contiguous prefix.
  if (chunk.offset != slot->received) {
    send_ack(peer, chunk.object_hash, slot->received,
             autonomy::ObjectAckStatus::Incomplete);
    return;
  }
  if (static_cast<std::uint32_t>(chunk.offset) + chunk.data_size >
          slot->total_len ||
      chunk.data_size > chunk.data.size()) {
    send_ack(peer, chunk.object_hash, slot->received,
             autonomy::ObjectAckStatus::Failed);
    slot->used = false;
    return;
  }
  std::memcpy(slot->data.data() + chunk.offset, chunk.data.data(),
              chunk.data_size);
  slot->received = static_cast<std::uint16_t>(slot->received + chunk.data_size);
  slot->deadline_ms = now_ms + config_.inbound_expiry_ms;
  if (slot->received == slot->total_len) complete_inbound(*slot, now_ms);
}

void PlanExchange::complete_inbound(Inbound& slot,
                                    const MonotonicMs now_ms) noexcept {
  const Digest256 digest =
      plan_digest(ByteView{slot.data.data(), slot.total_len});
  if (digest != slot.hash) {
    send_ack(slot.peer, slot.hash, slot.received,
             autonomy::ObjectAckStatus::Failed);
    slot.used = false;
    return;
  }
  note_delivered(slot.hash);
  ++delivered_count_;
  send_ack(slot.peer, slot.hash, slot.total_len,
           autonomy::ObjectAckStatus::Ok);
  const autonomy::ControlObjectKind kind = slot.kind;
  const NodeId peer = slot.peer;
  const ByteView object{slot.data.data(), slot.total_len};
  slot.used = false;
  sink_.on_object(peer, kind, object, now_ms);
}

void PlanExchange::on_ack(const NodeId peer,
                          const autonomy::ObjectAckPayload& ack,
                          const MonotonicMs now_ms) noexcept {
  Outbound* slot = find_outbound(peer, ack.object_hash);
  if (slot == nullptr) return;
  switch (ack.status) {
    case autonomy::ObjectAckStatus::Ok:
      if (ack.received_len >= slot->total_len) slot->used = false;
      break;
    case autonomy::ObjectAckStatus::Incomplete:
      // Bounded whole-object resend: chunks are in-order so a gap means
      // restarting the transfer.
      ++slot->attempts;
      if (slot->attempts > config_.send_attempts_max) {
        slot->used = false;
        ++failed_count_;
      } else {
        slot->manifest_sent = false;
        slot->sent = 0;
        slot->ack_deadline_ms = 0;
      }
      break;
    case autonomy::ObjectAckStatus::Failed:
      slot->used = false;
      ++failed_count_;
      break;
    default:
      break;
  }
  (void)now_ms;
}

Status PlanExchange::publish(const NodeId dest,
                             const autonomy::ControlObjectKind kind,
                             const ByteView content,
                             const MonotonicMs now_ms,
                             const bool visit_channel) noexcept {
  (void)now_ms;
  if (dest == kInvalidNodeId || content.data == nullptr ||
      content.size == 0 ||
      content.size > migration_wire_const::kMigrationObjectMax) {
    return reject(StatusCode::InvalidArgument, "OBJECT_PUBLISH_BOUND");
  }
  const autonomy::ObjectHash hash = plan_digest(content);
  if (find_outbound(dest, hash) != nullptr) {
    return Status::success();  // identical transfer already in flight
  }
  Outbound* slot = nullptr;
  for (auto& candidate : outbound_) {
    if (!candidate.used) {
      slot = &candidate;
      break;
    }
  }
  if (slot == nullptr) {
    return Status::error(StatusCode::NoCapacity, "object transfers full");
  }
  slot->used = true;
  slot->dest = dest;
  slot->kind = kind;
  slot->hash = hash;
  slot->total_len = static_cast<std::uint16_t>(content.size);
  slot->sent = 0;
  slot->attempts = 0;
  slot->manifest_sent = false;
  slot->visit_channel = visit_channel;
  slot->ack_deadline_ms = 0;
  std::memcpy(slot->data.data(), content.data, content.size);
  return Status::success();
}

std::uint8_t PlanExchange::outbound_busy() const noexcept {
  std::uint8_t count = 0;
  for (const auto& slot : outbound_) {
    if (slot.used) ++count;
  }
  return count;
}

void PlanExchange::poll(const MonotonicMs now_ms,
                        const ExchangeChannel channel) noexcept {
  for (auto& slot : inbound_) {
    if (slot.used && slot.deadline_ms <= now_ms) slot.used = false;
  }
  if (channel == ExchangeChannel::Blocked) {
    // The serialized op owns the radio: freeze ack deadlines so the blocked
    // interval never consumes a resend attempt.
    for (auto& slot : outbound_) {
      if (slot.used && slot.ack_deadline_ms != 0 &&
          slot.ack_deadline_ms <= now_ms) {
        slot.ack_deadline_ms = now_ms + config_.ack_timeout_ms;
      }
    }
    return;
  }
  std::size_t budget = migration_wire_const::kPumpFramesPerPoll;
  for (auto& slot : outbound_) {
    if (!slot.used || budget == 0) continue;
    if (channel == ExchangeChannel::Visit && !slot.visit_channel) continue;
    if (channel == ExchangeChannel::Home && slot.visit_channel) continue;
    if (!slot.manifest_sent) {
      autonomy::ControlObjectPayload manifest{};
      manifest.kind = slot.kind;
      manifest.total_len = slot.total_len;
      manifest.object_hash = slot.hash;
      autonomy::EncodedPayload payload{};
      if (!control_object_encode(manifest, payload).ok()) {
        slot.used = false;
        ++failed_count_;
        continue;
      }
      if (!wire_
               .migration_send(slot.dest, FrameType::ControlObject,
                              payload.view())
               .ok()) {
        continue;  // TX busy/failed: retry next poll, no attempt consumed
      }
      slot.manifest_sent = true;
      --budget;
      continue;
    }
    if (slot.sent < slot.total_len) {
      const std::uint16_t remaining =
          static_cast<std::uint16_t>(slot.total_len - slot.sent);
      const std::uint16_t amount =
          remaining > migration_wire_const::kChunkDataMax
              ? static_cast<std::uint16_t>(
                    migration_wire_const::kChunkDataMax)
              : remaining;
      autonomy::ObjectChunkPayload chunk{};
      chunk.object_hash = slot.hash;
      chunk.offset = slot.sent;
      chunk.data_size = amount;
      std::memcpy(chunk.data.data(), slot.data.data() + slot.sent, amount);
      autonomy::EncodedPayload payload{};
      if (!object_chunk_encode(chunk, payload).ok()) {
        slot.used = false;
        ++failed_count_;
        continue;
      }
      if (!wire_
               .migration_send(slot.dest, FrameType::ObjectChunk,
                              payload.view())
               .ok()) {
        continue;
      }
      slot.sent = static_cast<std::uint16_t>(slot.sent + amount);
      --budget;
      if (slot.sent == slot.total_len) {
        slot.ack_deadline_ms = now_ms + config_.ack_timeout_ms;
      }
      continue;
    }
    // All chunks sent: bounded wait for the ack, then a full resend.
    if (slot.ack_deadline_ms == 0) {
      slot.ack_deadline_ms = now_ms + config_.ack_timeout_ms;
    } else if (now_ms >= slot.ack_deadline_ms) {
      ++slot.attempts;
      if (slot.attempts > config_.send_attempts_max) {
        slot.used = false;
        ++failed_count_;
      } else {
        slot.manifest_sent = false;
        slot.sent = 0;
        slot.ack_deadline_ms = 0;
      }
    }
  }
}

// --- MigrationAgent -----------------------------------------------------------------

MigrationAgent::MigrationAgent(
    const MigrationAgentConfig& config, MigrationWirePort& wire,
    MigrationOwnerPort& owner, PlanStorage& storage,
    MigrationAuthority& authority, ChannelOperationRunner& runner,
    ChannelCoordinator* coordinator) noexcept
    : config_(config),
      wire_(wire),
      owner_(owner),
      storage_(storage),
      authority_(authority),
      runner_(runner),
      coordinator_(coordinator),
      participant_(config.participant, storage, authority, runner, this),
      exchange_(PlanExchangeConfig{}, wire, *this) {}

// MigrationHooks — the engine owns the order; the Owner owns the mechanism.
void MigrationAgent::hold_data(const bool held) noexcept {
  owner_.hold_data(held);
}

void MigrationAgent::note_cutover_generation(
    const std::uint32_t radio_generation) noexcept {
  owner_.note_radio_generation(radio_generation);
}

void MigrationAgent::helper_visit(const bool active,
                                  const std::uint8_t old_channel) noexcept {
  serving_ = active;
  owner_.on_migration_event(
      active ? "HELPER_VISIT_BEGIN" : "HELPER_VISIT_END", kInvalidNodeId);
  if (active) {
    // Bounded old-channel absence notice to current home-channel peers.
    std::uint32_t dwell = migration_const::kHelperDwellMs;
    const MigrationPlan* plan = participant_.pending_plan();
    if (plan != nullptr && plan->recovery.present &&
        plan->recovery.dwell_ms != 0) {
      dwell = plan->recovery.dwell_ms;
    }
    emit_notice_all(autonomy::AbsenceReason::HelperVisit,
                    participant_.active_epoch(), 0, dwell, 0);
  }
  (void)old_channel;
}

ExchangeChannel MigrationAgent::channel_context() const noexcept {
  if (!runner_.busy()) return ExchangeChannel::Home;
  return runner_.visiting() ? ExchangeChannel::Visit
                            : ExchangeChannel::Blocked;
}

void MigrationAgent::emit_notice(const NodeId dest,
                                 const autonomy::AbsenceReason reason,
                                 const ChannelEpoch epoch,
                                 const std::uint32_t starts_in_ms,
                                 const std::uint32_t duration_ms,
                                 const std::uint16_t protected_cut_id) noexcept {
  autonomy::ChannelNoticePayload notice{};
  notice.subject = config_.participant.node;
  notice.channel_epoch = epoch;
  notice.starts_in_ms = starts_in_ms;
  notice.duration_ms = duration_ms;
  notice.reason = reason;
  notice.protected_cut_id = protected_cut_id;
  autonomy::EncodedPayload payload{};
  if (!channel_notice_encode(notice, payload).ok()) return;
  (void)wire_.migration_send(dest, FrameType::ChannelNotice, payload.view());
}

void MigrationAgent::emit_notice_all(const autonomy::AbsenceReason reason,
                                     const ChannelEpoch epoch,
                                     const std::uint32_t starts_in_ms,
                                     const std::uint32_t duration_ms,
                                     const std::uint16_t protected_cut_id) noexcept {
  if (channel_context() != ExchangeChannel::Home) return;
  std::array<NodeId, 24> peers{};
  const std::size_t count = wire_.migration_peers(peers.data(), peers.size());
  for (std::size_t i = 0; i < count; ++i) {
    emit_notice(peers[i], reason, epoch, starts_in_ms, duration_ms,
                protected_cut_id);
  }
}

void MigrationAgent::enqueue_pending(const PendingSend& send) noexcept {
  if (!pending_.push(send)) {
    // Bounded work queue full: drop the NEW item, never an old one silently.
    owner_.on_migration_event("PENDING_SEND_DROPPED", send.dest);
  }
}

void MigrationAgent::queue_inline(const NodeId dest,
                                  const autonomy::ControlObjectKind kind,
                                  const ByteView content,
                                  const MonotonicMs deadline_ms,
                                  const bool visit_channel) noexcept {
  if (content.size > migration_wire_const::kInlineObjectMax) return;
  PendingSend send{};
  send.dest = dest;
  send.tag = PendingTag::Inline;
  send.kind = kind;
  send.deadline_ms = deadline_ms;
  send.visit_channel = visit_channel;
  std::memcpy(send.inline_body.data(), content.data, content.size);
  send.inline_size = static_cast<std::uint8_t>(content.size);
  enqueue_pending(send);
}

void MigrationAgent::distribute(const PendingTag tag,
                                const MonotonicMs deadline_ms) noexcept {
  std::array<NodeId, 24> peers{};
  const std::size_t count = wire_.migration_peers(peers.data(), peers.size());
  for (std::size_t i = 0; i < count; ++i) {
    PendingSend send{};
    send.dest = peers[i];
    send.tag = tag;
    send.kind = tag == PendingTag::DistributeSnapshot
                    ? autonomy::ControlObjectKind::RecoverySnapshot
                    : autonomy::ControlObjectKind::ChannelPlan;
    send.deadline_ms = deadline_ms;
    enqueue_pending(send);
  }
}

void MigrationAgent::emit_ready_report(const Digest256& plan_hash,
                                       const ChannelEpoch epoch,
                                       const ReadyStatus status,
                                       const MonotonicMs now_ms) noexcept {
  ReadyReport report{};
  report.plan_hash = plan_hash;
  report.new_epoch = epoch;
  report.status = status;
  report.migration_capable = true;
  report.sleep_lease_valid = config_.self_sleep_lease_valid;
  report.rediscovery_capable = config_.self_rediscovery_capable;
  report.storage_ok = status == ReadyStatus::Ready;
  report.clock_ok = participant_.clock_valid();
  report.drain_ok = true;
  std::array<std::uint8_t, migration_wire_const::kInlineObjectMax> content{};
  std::size_t size = 0;
  MutableByteView body{content.data() + 1, content.size() - 1};
  if (!ready_report_encode(report, body, size).ok()) return;
  content[0] = static_cast<std::uint8_t>(PlanMessage::ReadyReport);
  queue_inline(config_.participant.authority,
               autonomy::ControlObjectKind::ChannelPlan,
               ByteView{content.data(), size + 1},
               now_ms + migration_wire_const::kPendingTtlMs, false);
}

void MigrationAgent::emit_result_report(const ResultOutcome outcome,
                                        const MonotonicMs now_ms) noexcept {
  ResultReport report{};
  report.plan_hash = participant_.pending_hash();
  const MigrationPlan* plan = participant_.pending_plan();
  report.epoch = plan != nullptr ? plan->new_epoch : ChannelEpoch{};
  report.outcome = outcome;
  std::array<std::uint8_t, migration_wire_const::kInlineObjectMax> content{};
  std::size_t size = 0;
  MutableByteView body{content.data() + 1, content.size() - 1};
  if (!result_report_encode(report, body, size).ok()) return;
  content[0] = static_cast<std::uint8_t>(PlanMessage::ResultReport);
  queue_inline(config_.participant.authority,
               autonomy::ControlObjectKind::ChannelPlan,
               ByteView{content.data(), size + 1},
               now_ms + migration_wire_const::kPendingTtlMs, false);
}

void MigrationAgent::on_phase_transition(const ParticipantPhase from,
                                         const ParticipantPhase to,
                                         const MonotonicMs now_ms) noexcept {
  // Operation state is observable: every transition emits a bounded
  // PHASE_* event the owner can surface (USB diagnostics, host UX).
  owner_.on_migration_event(
      to == ParticipantPhase::Stable        ? "PHASE_STABLE"
      : to == ParticipantPhase::Assess      ? "PHASE_ASSESS"
      : to == ParticipantPhase::Survey      ? "PHASE_SURVEY"
      : to == ParticipantPhase::Preparing   ? "PHASE_PREPARING"
      : to == ParticipantPhase::Committed   ? "PHASE_COMMITTED"
      : to == ParticipantPhase::Switching   ? "PHASE_SWITCHING"
      : to == ParticipantPhase::Verifying   ? "PHASE_VERIFYING"
      : to == ParticipantPhase::Recovering  ? "PHASE_RECOVERING"
      : to == ParticipantPhase::Aborted     ? "PHASE_ABORTED"
                                            : "PHASE_RECOVERY_REQUIRED",
      kInvalidNodeId);
  switch (to) {
    case ParticipantPhase::Committed: {
      // Scheduled-switch notice (04 §8): warn bound peers ahead of the
      // bounded outage. Cutover order/drain itself is engine+runner work.
      const MonotonicMs switch_ms = participant_.pending_switch_local();
      const std::uint32_t starts_in =
          switch_ms > now_ms ? switch_ms - now_ms : 0;
      const MigrationPlan* plan = participant_.pending_plan();
      emit_notice_all(autonomy::AbsenceReason::Cutover,
                      participant_.committed_epoch(), starts_in,
                      plan != nullptr ? plan->guard_ms : 0, 0);
      break;
    }
    case ParticipantPhase::Stable:
      if (from == ParticipantPhase::Verifying) {
        emit_result_report(ResultOutcome::Applied, now_ms);
      }
      break;
    case ParticipantPhase::Aborted:
      emit_result_report(ResultOutcome::Aborted, now_ms);
      break;
    case ParticipantPhase::Recovering:
      if (from == ParticipantPhase::Switching ||
          from == ParticipantPhase::Verifying) {
        emit_result_report(ResultOutcome::Recovering, now_ms);
      }
      break;
    case ParticipantPhase::RecoveryRequired:
      emit_result_report(ResultOutcome::RecoveryRequired, now_ms);
      break;
    default:
      break;
  }
}

void MigrationAgent::record_readiness(const NodeId peer,
                                      const ReadyReport& report) noexcept {
  ParticipantReadiness* entry = nullptr;
  readiness_.for_each([&](ParticipantReadiness& value) {
    if (value.node == peer) entry = &value;
  });
  if (entry == nullptr) entry = readiness_.allocate();
  if (entry == nullptr) {
    owner_.on_migration_event("READINESS_TABLE_FULL", peer);
    return;
  }
  entry->node = peer;
  entry->required = false;
  for (std::size_t i = 0; i < config_.required_count; ++i) {
    if (config_.required[i] == peer) entry->required = true;
  }
  // The report is bound to the plan it answered — a delayed READY for an
  // older offer must not count toward the next plan's gate (04 §7).
  entry->plan_hash = report.plan_hash;
  entry->answered = true;
  // READY is evidence of the full condition set — an unarmed clock is not
  // ready even when the blob stored fine (04 §7).
  entry->ready = report.status == ReadyStatus::Ready && report.clock_ok;
  entry->migration_capable = report.migration_capable;
  entry->sleep_lease_valid = report.sleep_lease_valid;
  entry->rediscovery_capable = report.rediscovery_capable;
}

void MigrationAgent::record_result(const NodeId peer,
                                   const ResultReport& report) noexcept {
  ResultEntry* slot = nullptr;
  for (auto& entry : results_) {
    if (entry.used && entry.node == peer) slot = &entry;
  }
  if (slot == nullptr) {
    for (auto& entry : results_) {
      if (!entry.used) {
        slot = &entry;
        break;
      }
    }
  }
  if (slot == nullptr) {
    owner_.on_migration_event("RESULT_TABLE_FULL", peer);
    return;
  }
  slot->used = true;
  slot->node = peer;
  slot->plan_hash = report.plan_hash;
  slot->epoch = report.epoch;
  slot->outcome = report.outcome;
}

void MigrationAgent::check_terminal(const MonotonicMs now_ms) noexcept {
  if (!terminal_armed_) return;
  std::size_t reported = 0;
  bool all_applied = true;
  for (std::size_t i = 0; i < config_.required_count; ++i) {
    bool seen = false;
    for (const auto& entry : results_) {
      if (entry.used && entry.node == config_.required[i] &&
          entry.plan_hash == issued_plan_hash_) {
        seen = true;
      }
    }
    if (seen) ++reported;
  }
  // Any non-Applied outcome for the issued hash fails the plan regardless
  // of which node reported it.
  for (const auto& entry : results_) {
    if (entry.used && entry.plan_hash == issued_plan_hash_ &&
        entry.outcome != ResultOutcome::Applied) {
      all_applied = false;
    }
  }
  const bool all_reported =
      config_.required_count == 0 || reported == config_.required_count;
  if (!all_reported && now_ms < terminal_deadline_ms_) return;
  // Every required node reported, or the bounded wait ended: feed the
  // terminal outcome once — the authority latches cooldown/rollback credit.
  authority_.note_plan_terminal(all_reported && all_applied, now_ms);
  terminal_armed_ = false;
  owner_.on_migration_event("PLAN_TERMINAL", kInvalidNodeId);
}

RequiredSetVerdict MigrationAgent::readiness_verdict() const noexcept {
  std::array<ParticipantReadiness, migration_wire_const::kRequiredCapacity>
      set{};
  std::size_t count = 0;
  readiness_.for_each([&](const ParticipantReadiness& value) {
    for (std::size_t i = 0; i < config_.required_count; ++i) {
      // Only reports bound to the currently issued plan count — a stale
      // READY from an earlier offer is not evidence for this gate.
      if (value.node == config_.required[i] &&
          value.plan_hash == issued_plan_hash_ && count < set.size()) {
        set[count] = value;
        set[count].required = true;
        ++count;
      }
    }
  });
  // Required nodes that never reported appear as unanswered entries —
  // evaluate_required_set then applies the lease+rediscovery rule (D5-09).
  for (std::size_t i = 0; i < config_.required_count; ++i) {
    bool present = false;
    for (std::size_t j = 0; j < count; ++j) {
      if (set[j].node == config_.required[i]) present = true;
    }
    if (!present && count < set.size()) {
      set[count] = ParticipantReadiness{};
      set[count].node = config_.required[i];
      set[count].required = true;
      ++count;
    }
  }
  return evaluate_required_set(set.data(), count, issued_recovery_present_);
}

bool MigrationAgent::readiness_of(const NodeId node,
                                  ParticipantReadiness& out) const noexcept {
  bool found = false;
  readiness_.for_each([&](const ParticipantReadiness& value) {
    if (value.node == node) {
      out = value;
      found = true;
    }
  });
  return found;
}

// --- AutoGuarded gate (P6) --------------------------------------------------------

void MigrationAgent::compose_autoguarded(
    AutoGuardedEvidence& evidence, const MonotonicMs now_ms) const noexcept {
  const NodeId authority_id = config_.participant.authority;
  const bool self_authority = authority_id == config_.participant.node;
  // Explicit configured Authority: unset/broadcast ids are not authorities.
  evidence.authority_configured =
      authority_id != kInvalidNodeId && authority_id != kBroadcastNodeId;
  ParticipantReadiness authority_ready{};
  const bool authority_answered =
      !self_authority && readiness_of(authority_id, authority_ready);
  // A remote authority is available only when it answered READY this
  // session — silence is not availability. For a self-authority node the
  // local availability flag rules (D5-04).
  evidence.authority_available =
      self_authority ? authority_.available()
                     : authority_answered && authority_ready.ready;
  // Real verifier readiness — a placeholder object is not verification.
  evidence.verifier_ready = authority_.verifier_ready();
  // Verified path: the authority answered readiness this session, it IS
  // this node, or it already reached us through a verified signed commit
  // (committed epoch or a pending verified plan prove the interaction).
  evidence.authority_path_verified =
      self_authority || authority_answered ||
      participant_.committed_epoch().value != 0 ||
      participant_.pending_plan() != nullptr;
  // Required-set accounting over the READY/lease ledger (04 §7): an
  // unanswered endpoint has no report and therefore no lease/rediscovery
  // deferral — it is unobserved, never reclassed as "asleep" or "ready".
  // A reported not-migration-capable required node is the legacy block.
  std::size_t unobserved = 0;
  std::size_t not_ready = 0;
  bool legacy = false;
  for (std::size_t i = 0; i < config_.required_count; ++i) {
    ParticipantReadiness entry{};
    if (!readiness_of(config_.required[i], entry)) {
      ++unobserved;
      continue;
    }
    if (!entry.migration_capable) {
      legacy = true;
      continue;
    }
    if (!entry.ready) ++not_ready;
  }
  evidence.required_count = config_.required_count;
  evidence.required_unobserved = unobserved;
  evidence.required_not_ready = not_ready;
  evidence.required_legacy_present =
      evidence.required_legacy_present || legacy;
  // Participant measurables: armed clock (never zero-uncertainty when
  // unarmed) and the plan-terminal cooldown latch.
  evidence.clock_valid = participant_.clock_valid();
  evidence.clock_uncertainty_ms = participant_.clock_uncertainty_ms();
  evidence.clock_uncertainty_max_ms =
      config_.participant.clock_uncertainty_max_ms;
  evidence.cooldown_active = participant_.cooldown_active(now_ms);
  // A pending verified plan or an issued plan's recovery flag proves the
  // committed recovery schedule on this node; the caller-asserted field
  // covers deployment-wide issuance policy.
  const MigrationPlan* pending = participant_.pending_plan();
  if ((pending != nullptr && pending->recovery.present) ||
      issued_recovery_present_) {
    evidence.recovery_plan_present = true;
  }
}

AutoGuardedVerdict MigrationAgent::evaluate_autoguarded(
    AutoGuardedEvidence evidence, const MonotonicMs now_ms) const noexcept {
  compose_autoguarded(evidence, now_ms);
  if (coordinator_ != nullptr) {
    // The coordinator stamps its own conditions (required-legacy, survey
    // freshness) and applies snapshot staleness, then runs the same gate.
    return coordinator_->evaluate_autoguarded(evidence, now_ms);
  }
  // No coordinator: this node cannot vouch for survey screening at all —
  // the evidence stays unknown and the gate fails it honestly.
  evidence.survey_evidence_known = false;
  evidence.survey_evidence_fresh = false;
  return routeloom::evaluate_autoguarded(evidence);
}

AutoGuardedVerdict MigrationAgent::request_autoguarded(
    const AutoGuardedEvidence& evidence, const MonotonicMs now_ms) noexcept {
  AutoGuardedEvidence composed = evidence;
  compose_autoguarded(composed, now_ms);
  if (coordinator_ == nullptr) {
    // No gate keeper: nothing can latch AutoGuarded. The composed evidence
    // is still evaluated so the caller sees every unmet condition — survey
    // evidence included, which cannot be vouched without a coordinator.
    composed.survey_evidence_known = false;
    composed.survey_evidence_fresh = false;
    return routeloom::evaluate_autoguarded(composed);
  }
  AutoGuardedVerdict verdict =
      coordinator_->request_autoguarded(composed, now_ms);
  // The gate outcome is observable: the latch announces the new mode, a
  // refusal carries its bounded detail string to the owner.
  owner_.on_migration_event(
      verdict.permitted ? "MIGRATION_MODE_AUTOGUARDED" : verdict.detail,
      kInvalidNodeId);
  return verdict;
}

void MigrationAgent::auto_survey(const ChannelAssessment& assessment,
                                 const MonotonicMs now_ms) noexcept {
  if (survey_pending_ || runner_.busy()) return;
  if (assessment.candidate_count == 0) return;
  const auto note = [&](const char* reason, const NodeId peer) noexcept {
    // Skip/refuse notes are latched per streak: one owner event, not one
    // per poll while the proposal persists.
    if (autosurvey_noted_) return;
    autosurvey_noted_ = true;
    owner_.on_migration_event(reason, peer);
  };
  // The survey peer is the configured Authority: it is the one remote end
  // this participant holds an armed bounded clock mapping for. Without an
  // armed mapping there is no common time base — the visit is skipped, not
  // faked.
  if (!participant_.clock_valid()) {
    note("AUTOSURVEY_CLOCK_UNARMED", kInvalidNodeId);
    return;
  }
  const NodeId peer = config_.participant.authority;
  if (peer == kInvalidNodeId || peer == kBroadcastNodeId ||
      peer == config_.participant.node) {
    note("AUTOSURVEY_NO_PEER", kInvalidNodeId);
    return;
  }
  SurveyRequest request{};
  request.peer = peer;
  request.channel = assessment.candidates[0];
  request.begin_ms = now_ms;
  request.duration_ms = migration_const::kSurveyVisitMaxMs;
  request.mapping = participant_.clock_mapping();
  request.exchanges_per_direction =
      migration_const::kSurveyExchangeMaxPerDirection;
  // The visit IS a bounded home-channel outage (single radio) — the lease
  // records it as such; outage permission is inherent to the mode's opt-in.
  request.outage_permitted = true;
  request.cut_without_alternative = false;
  std::array<NodeId, 24> peers{};
  const std::size_t count = wire_.migration_peers(peers.data(), peers.size());
  for (std::size_t i = 0; i < count &&
                         request.absence_notify_count <
                             request.absence_notify.size();
       ++i) {
    request.absence_notify[request.absence_notify_count++] = peers[i];
  }
  OperationToken token{kInvalidOperationToken};
  const Status status = request_survey(request, now_ms, token);
  // A refusal is not retried here — the next assessment proposal retries on
  // its own cadence (the revisit gap bounds the rate regardless).
  if (status) {
    autosurvey_noted_ = false;
    owner_.on_migration_event("AUTOSURVEY_ISSUED", peer);
  } else {
    // The refusal detail is the bounded reason string — gate verdicts like
    // AUTOGUARDED_EVIDENCE_STALE or SURVEY_REVISIT_GAP reach the owner
    // verbatim instead of a generic "refused".
    note(status.detail, peer);
  }
}

void MigrationAgent::materialize_serve(const NodeId dest,
                                       const MonotonicMs now_ms) noexcept {
  // Serve the NEWEST durably committed state (D5-07): commit evidence (when
  // the persisted signature exists), the addressed blob, and the cached
  // signed snapshot when it is at least as new.
  std::array<std::uint8_t, migration_const::kCommitRecordSize> raw{};
  std::size_t size = 0;
  Status status = storage_.read_commit_record(
      MutableByteView{raw.data(), raw.size()}, size);
  if (!status) return;  // nothing committed -> nothing to serve
  CommitRecord record{};
  if (!commit_record_decode(ByteView{raw.data(), size}, record).ok() ||
      !record.present) {
    return;
  }
  const bool visit = channel_context() == ExchangeChannel::Visit;
  std::array<std::uint8_t,
             migration_wire_const::kCommitEvidenceObjectMax>
      evidence{};
  if (record.signature_size > 0) {
    CommitEvidence body{};
    body.operation = record.operation;
    body.plan_hash = record.plan_hash;
    body.new_epoch = record.new_epoch;
    std::memcpy(body.signature.data(), record.signature.data(),
                record.signature_size);
    body.signature_size = record.signature_size;
    std::size_t body_size = 0;
    evidence[0] = static_cast<std::uint8_t>(PlanMessage::CommitEvidence);
    if (commit_evidence_encode(
            body, MutableByteView{evidence.data() + 1, evidence.size() - 1},
            body_size)
            .ok() &&
        !exchange_
             .publish(dest, autonomy::ControlObjectKind::ChannelPlan,
                      ByteView{evidence.data(), body_size + 1}, now_ms, visit)
             .ok()) {
      // Transfer slots full: the next visit (or the requester's retry)
      // serves again — bounded, never a fake serve.
      return;
    }
  }
  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size = 0;
  if (storage_
          .read_blob(record.plan_hash,
                     MutableByteView{blob.data(), blob.size()}, blob_size)
          .ok()) {
    std::array<std::uint8_t, migration_const::kPlanBlobMax + 1> content{};
    content[0] = static_cast<std::uint8_t>(PlanMessage::PlanBlob);
    std::memcpy(content.data() + 1, blob.data(), blob_size);
    (void)exchange_.publish(dest, autonomy::ControlObjectKind::ChannelPlan,
                            ByteView{content.data(), blob_size + 1}, now_ms,
                            visit);
  }
  if (cached_snapshot_valid_ &&
      cached_snapshot_epoch_.value >= record.new_epoch.value) {
    (void)exchange_.publish(
        dest, autonomy::ControlObjectKind::RecoverySnapshot,
        ByteView{cached_snapshot_.data(), cached_snapshot_size_}, now_ms,
        visit);
  }
}

void MigrationAgent::pump_pending(const MonotonicMs now_ms) noexcept {
  std::size_t budget = pending_.size();
  PendingSend send{};
  while (budget-- > 0 && pending_.pop(send)) {
    if (now_ms >= send.deadline_ms) {
      owner_.on_migration_event("PENDING_SEND_EXPIRED", send.dest);
      continue;
    }
    Status status = Status::success();
    switch (send.tag) {
      case PendingTag::Inline:
        status = exchange_.publish(
            send.dest, send.kind,
            ByteView{send.inline_body.data(), send.inline_size}, now_ms,
            send.visit_channel);
        break;
      case PendingTag::DistributeBlob: {
        std::array<std::uint8_t, migration_const::kPlanBlobMax + 1>
            content{};
        content[0] = static_cast<std::uint8_t>(PlanMessage::PlanBlob);
        std::memcpy(content.data() + 1, issued_blob_.data(),
                    issued_blob_size_);
        status = exchange_.publish(
            send.dest, autonomy::ControlObjectKind::ChannelPlan,
            ByteView{content.data(), issued_blob_size_ + 1}, now_ms, false);
        break;
      }
      case PendingTag::DistributeEvidence:
        status = exchange_.publish(
            send.dest, autonomy::ControlObjectKind::ChannelPlan,
            ByteView{issued_evidence_.data(), issued_evidence_size_},
            now_ms, false);
        break;
      case PendingTag::DistributeSnapshot:
        status = exchange_.publish(
            send.dest, autonomy::ControlObjectKind::RecoverySnapshot,
            ByteView{issued_snapshot_.data(), issued_snapshot_size_},
            now_ms, false);
        break;
      case PendingTag::ServeSnapshot:
        materialize_serve(send.dest, now_ms);
        break;
    }
    if (status.code == StatusCode::NoCapacity) {
      send.deadline_ms = now_ms + migration_wire_const::kPendingTtlMs;
      enqueue_pending(send);  // requeue at the tail; retry next poll
    }
  }
}

// --- MigrationFrameSink --------------------------------------------------------

void MigrationAgent::on_migration_frame(const NodeId peer,
                                        const FrameType type,
                                        const ByteView payload,
                                        const MonotonicMs now_ms,
                                        const MonotonicMs captured_ms) noexcept {
  switch (type) {
    case FrameType::ControlObject: {
      autonomy::ControlObjectPayload manifest{};
      if (!control_object_decode(payload, manifest).ok()) {
        owner_.on_migration_event("CONTROL_OBJECT_DECODE", peer);
        return;
      }
      exchange_.on_manifest(peer, manifest, now_ms);
      break;
    }
    case FrameType::ObjectChunk: {
      autonomy::ObjectChunkPayload chunk{};
      if (!object_chunk_decode(payload, chunk).ok()) {
        owner_.on_migration_event("OBJECT_CHUNK_DECODE", peer);
        return;
      }
      exchange_.on_chunk(peer, chunk, now_ms);
      break;
    }
    case FrameType::ObjectAck: {
      autonomy::ObjectAckPayload ack{};
      if (!object_ack_decode(payload, ack).ok()) {
        owner_.on_migration_event("OBJECT_ACK_DECODE", peer);
        return;
      }
      exchange_.on_ack(peer, ack, now_ms);
      break;
    }
    case FrameType::ChannelNotice: {
      autonomy::ChannelNoticePayload notice{};
      if (!channel_notice_decode(payload, notice).ok()) {
        owner_.on_migration_event("CHANNEL_NOTICE_DECODE", peer);
        return;
      }
      if (coordinator_ != nullptr) {
        // Authenticated scheduled-absence bookkeeping (04 §3): the peer's
        // absence must not collide with a protected cut we plan.
        const MonotonicMs until =
            now_ms + notice.starts_in_ms + notice.duration_ms;
        // The cut id is authenticated wire content: remote cut-level
        // absence protection only works when it survives the hop.
        (void)coordinator_->note_absence(notice.subject,
                                         notice.protected_cut_id, until,
                                         now_ms);
      }
      owner_.on_migration_event("CHANNEL_NOTICE", peer);
      break;
    }
    case FrameType::TimeSync: {
      autonomy::TimeSyncPayload sample{};
      if (!time_sync_decode(payload, sample).ok()) {
        owner_.on_migration_event("TIME_SYNC_DECODE", peer);
        return;
      }
      if (sample.source != config_.participant.authority) {
        // Only the configured authority re-arms the migration clock
        // (D5-03). Other samples are valid wire traffic, not clock evidence.
        return;
      }
      if (peer != sample.source) {
        // TimeSync is strictly 1-hop: the claimed source must be the
        // link-authenticated sender itself, anything else is a forgery.
        owner_.on_migration_event("TIME_SYNC_SOURCE_MISMATCH", peer);
        return;
      }
      // Queue residence sits inside the verified bound (04 §8): measure the
      // offset at capture and debit capture-to-processing time from the same
      // uncertainty budget, so an over-bound sample is refused by note_clock.
      const MonotonicMs captured =
          captured_ms != 0 ? captured_ms : now_ms;
      ClockMapping mapping{};
      mapping.peer_offset_ms =
          static_cast<std::int64_t>(sample.reference_ms) -
          static_cast<std::int64_t>(captured);
      mapping.uncertainty_ms = static_cast<std::uint32_t>(
          std::min<std::uint64_t>(
              static_cast<std::uint64_t>(sample.uncertainty_ms) +
                  (now_ms - captured) + config_.rx_clock_slack_ms,
              std::numeric_limits<std::uint32_t>::max()));
      if (participant_.note_clock(mapping, now_ms).ok() &&
          participant_.phase() == ParticipantPhase::Preparing) {
        // The READY gate only accepts clock_ok evidence: a node that armed
        // after its first report re-reports READY, or it would look unready
        // for the rest of the prepare window.
        const MigrationPlan* plan = participant_.pending_plan();
        emit_ready_report(participant_.pending_hash(),
                          plan != nullptr ? plan->new_epoch : ChannelEpoch{},
                          ReadyStatus::Ready, now_ms);
      }
      break;
    }
    default:
      break;
  }
}

void MigrationAgent::note_link_activity(const NodeId peer,
                                        const MonotonicMs now_ms) noexcept {
  const ParticipantPhase before = participant_.phase();
  participant_.note_link_activity(now_ms);
  if (before == ParticipantPhase::Verifying &&
      participant_.phase() == ParticipantPhase::Stable) {
    owner_.on_migration_event("VERIFY_PASSED", peer);
  }
}

void MigrationAgent::on_object(const NodeId peer,
                               const autonomy::ControlObjectKind kind,
                               const ByteView object,
                               const MonotonicMs now_ms) noexcept {
  if (kind == autonomy::ControlObjectKind::RecoverySnapshot) {
    ByteView body{}, signature{};
    if (!signed_snapshot_unwrap(object, body, signature).ok()) {
      owner_.on_migration_event("SNAPSHOT_OBJECT_DECODE", peer);
      return;
    }
    if (!participant_.adopt_snapshot(body, signature, now_ms).ok()) {
      owner_.on_migration_event("SNAPSHOT_REJECTED", peer);
      return;
    }
    // Cache the newest verified signed snapshot for later serving. RAM-only:
    // durability is the commit record + blob the adoption wrote.
    const MigrationPlan* plan = participant_.pending_plan();
    if (plan != nullptr && object.size <= cached_snapshot_.size() &&
        (!cached_snapshot_valid_ ||
         plan->new_epoch.value > cached_snapshot_epoch_.value)) {
      std::memcpy(cached_snapshot_.data(), object.data, object.size);
      cached_snapshot_size_ = object.size;
      cached_snapshot_epoch_ = plan->new_epoch;
      cached_snapshot_valid_ = true;
    }
    return;
  }
  if (kind != autonomy::ControlObjectKind::ChannelPlan || object.size == 0) {
    return;
  }
  const ByteView body{object.data + 1, object.size - 1};
  switch (static_cast<PlanMessage>(object.data[0])) {
    case PlanMessage::PlanBlob: {
      const Digest256 hash = plan_digest(body);
      ChannelEpoch epoch{};
      MigrationPlan plan{};
      if (plan_decode(body, plan).ok()) epoch = plan.new_epoch;
      // The engine re-validates everything: wrong scope, stale epoch, bad
      // guard/lead, missing storage — a transport delivery never skips it.
      const Status stored =
          participant_.prepare(body, config_.measurements, now_ms);
      emit_ready_report(hash, epoch,
                        stored.ok() ? ReadyStatus::Ready
                                    : ReadyStatus::NotReady,
                        now_ms);
      break;
    }
    case PlanMessage::CommitEvidence: {
      CommitEvidence evidence{};
      if (!commit_evidence_decode(body, evidence).ok()) {
        owner_.on_migration_event("COMMIT_EVIDENCE_DECODE", peer);
        return;
      }
      // Real verifier path — forged/unsigned evidence is rejected inside
      // the engine exactly like a forged local call (D5-01).
      if (!participant_
               .note_commit_evidence(
                   evidence.operation, evidence.plan_hash,
                   evidence.new_epoch,
                   ByteView{evidence.signature.data(),
                            evidence.signature_size},
                   now_ms)
               .ok()) {
        owner_.on_migration_event("COMMIT_EVIDENCE_REJECTED", peer);
      }
      break;
    }
    case PlanMessage::ReadyReport: {
      if (!config_.authority_role) return;
      ReadyReport report{};
      if (ready_report_decode(body, report).ok()) {
        record_readiness(peer, report);
      }
      break;
    }
    case PlanMessage::ResultReport: {
      if (!config_.authority_role) return;
      ResultReport report{};
      if (result_report_decode(body, report).ok()) {
        record_result(peer, report);
      }
      break;
    }
    case PlanMessage::SnapshotRequest: {
      SnapshotRequest request{};
      if (!snapshot_request_decode(body, request).ok()) {
        owner_.on_migration_event("SNAPSHOT_REQUEST_DECODE", peer);
        return;
      }
      PendingSend send{};
      send.dest = peer;
      send.tag = PendingTag::ServeSnapshot;
      send.deadline_ms = now_ms + migration_wire_const::kPendingTtlMs;
      send.visit_channel = channel_context() == ExchangeChannel::Visit;
      enqueue_pending(send);
      break;
    }
    default:
      owner_.on_migration_event("PLAN_MESSAGE_UNKNOWN", peer);
      break;
  }
}

// --- issuance ------------------------------------------------------------------

Status MigrationAgent::offer_plan(
    const MigrationPlan& plan, const ByteView plan_blob,
    const AuthorityOperation& operation, const ByteView commit_signature,
    const Digest256& resulting_state_hash, const ByteView snapshot_body,
    const ByteView snapshot_signature, const bool is_rollback,
    const MonotonicMs now_ms, VerifiedAuthorityPlan& out) noexcept {
  if (!config_.authority_role) {
    return reject(StatusCode::InvalidState, "NOT_AUTHORITY_ROLE");
  }
  if (plan_blob.size == 0 ||
      plan_blob.size > migration_const::kPlanBlobMax) {
    return reject(StatusCode::InvalidArgument, "PLAN_BLOB_BOUND");
  }
  // The real issuer path: signature verify + ledger commit + scope checks.
  Status status = authority_.commit_plan(plan, plan_blob, operation,
                                       commit_signature,
                                       resulting_state_hash, is_rollback,
                                       now_ms, out);
  if (!status) return status;

  // Stage the distribution set. Commit evidence is HELD for release_commit
  // so the READY gate stays an explicit decision (04 §7).
  issued_ = true;
  commit_released_ = false;
  terminal_armed_ = false;
  issued_plan_hash_ = out.plan_hash();
  issued_epoch_ = out.new_epoch();
  issued_recovery_present_ = plan.recovery.present;
  issued_blob_size_ = plan_blob.size;
  std::memcpy(issued_blob_.data(), plan_blob.data, plan_blob.size);

  CommitEvidence evidence{};
  evidence.operation = operation;
  evidence.plan_hash = out.plan_hash();
  evidence.new_epoch = out.new_epoch();
  if (commit_signature.size > evidence.signature.size()) {
    return reject(StatusCode::InvalidArgument, "COMMIT_SIGNATURE_BOUND");
  }
  std::memcpy(evidence.signature.data(), commit_signature.data,
              commit_signature.size);
  evidence.signature_size = static_cast<std::uint8_t>(commit_signature.size);
  issued_evidence_[0] =
      static_cast<std::uint8_t>(PlanMessage::CommitEvidence);
  status = commit_evidence_encode(
      evidence,
      MutableByteView{issued_evidence_.data() + 1,
                      issued_evidence_.size() - 1},
      issued_evidence_size_);
  if (!status) return status;
  ++issued_evidence_size_;  // include the message byte

  issued_snapshot_size_ = 0;
  if (snapshot_body.size > 0) {
    // The distributed snapshot must bind exactly this operation + blob.
    RecoverySnapshot snap{};
    if (!snapshot_decode(snapshot_body, snap).ok() ||
        snap.plan_hash != out.plan_hash() ||
        snap.operation.operation_hash != operation.operation_hash ||
        snap.operation.sequence != operation.sequence) {
      return reject(StatusCode::IntegrityError, "SNAPSHOT_MISMATCH");
    }
    std::size_t wrapped = 0;
    status = signed_snapshot_wrap(
        snapshot_body, snapshot_signature,
        MutableByteView{issued_snapshot_.data(), issued_snapshot_.size()},
        wrapped);
    if (!status) return status;
    issued_snapshot_size_ = wrapped;
  }

  // The authority's own node is a plan participant too: it can never hear
  // its own TimeSync, so it self-arms once here — identity mapping, the
  // authority's clock IS the authority domain (needed for its own
  // feasibility check, issued_switch_local_ms_ and its own cutover).
  (void)participant_.note_clock(
      ClockMapping{0, config_.timesync_uncertainty_ms}, now_ms);
  (void)participant_.prepare(plan_blob, config_.measurements, now_ms);
  issued_switch_local_ms_ = participant_.pending_switch_local();

  const MonotonicMs deadline =
      now_ms + migration_wire_const::kPendingTtlMs;
  distribute(PendingTag::DistributeBlob, deadline);
  if (issued_snapshot_size_ > 0) {
    distribute(PendingTag::DistributeSnapshot, deadline);
  }
  readiness_.clear();
  for (auto& entry : results_) entry.used = false;
  return Status::success();
}

Status MigrationAgent::release_commit(const MonotonicMs now_ms) noexcept {
  if (!config_.authority_role || !issued_ || commit_released_) {
    return reject(StatusCode::InvalidState, "NO_ISSUED_PLAN");
  }
  // The READY gate is enforced AT release, not only at issue (04 §7): a
  // required participant that never produced accepted READY evidence —
  // and cannot be legitimately sleep-deferred — must not have commit
  // evidence distributed to it or anyone else.
  const RequiredSetVerdict verdict = readiness_verdict();
  if (!verdict.commit_permitted) {
    owner_.on_migration_event("COMMIT_RELEASE_DENIED", verdict.blocker);
    return reject(verdict.reason, "REQUIRED_SET_NOT_READY");
  }
  commit_released_ = true;
  const MonotonicMs deadline =
      now_ms + migration_wire_const::kPendingTtlMs;
  std::array<NodeId, 24> peers{};
  const std::size_t count = wire_.migration_peers(peers.data(), peers.size());
  for (std::size_t i = 0; i < count; ++i) {
    PendingSend send{};
    send.dest = peers[i];
    send.tag = PendingTag::DistributeEvidence;
    send.kind = autonomy::ControlObjectKind::ChannelPlan;
    send.deadline_ms = deadline;
    enqueue_pending(send);
  }
  // Feed the local participant the same verified evidence.
  ByteView body{issued_evidence_.data() + 1, issued_evidence_size_ - 1};
  CommitEvidence evidence{};
  if (commit_evidence_decode(body, evidence).ok()) {
    (void)participant_.note_commit_evidence(
        evidence.operation, evidence.plan_hash, evidence.new_epoch,
        ByteView{evidence.signature.data(), evidence.signature_size},
        now_ms);
  }
  // Terminal accounting: bounded wait for required-node results after the
  // scheduled switch + verify window.
  terminal_armed_ = true;
  const MonotonicMs switch_ms =
      issued_switch_local_ms_ != 0 ? issued_switch_local_ms_ : now_ms;
  terminal_deadline_ms_ = switch_ms + config_.participant.verify_ms +
                          config_.terminal_margin_ms;
  return Status::success();
}

Status MigrationAgent::request_survey(const SurveyRequest& request,
                                      const MonotonicMs now_ms,
                                      OperationToken& out) noexcept {
  out = kInvalidOperationToken;
  if (coordinator_ == nullptr ||
      (coordinator_->mode() != MigrationMode::Manual &&
       coordinator_->mode() != MigrationMode::AutoGuarded)) {
    return reject(StatusCode::InvalidState, "SURVEY_MANUAL_ONLY");
  }
  SurveyLease lease{};
  Status status =
      coordinator_->request_survey_lease(request, now_ms, lease);
  if (!status) return status;
  (void)participant_.note_survey_begin();  // bookkeeping; survey still runs
  // Authenticated scheduled-absence notices BEFORE the visit (04 §3).
  const std::uint32_t starts_in =
      lease.begin_ms > now_ms ? lease.begin_ms - now_ms : 0;
  for (std::size_t i = 0; i < lease.absence_notify_count; ++i) {
    emit_notice(lease.absence_notify[i], autonomy::AbsenceReason::SurveyVisit,
                participant_.active_epoch(), starts_in,
                lease.end_ms - lease.begin_ms, lease.protected_cut_id);
  }
  RadioOperation op{};
  op.kind = RadioOperationKind::SurveyVisit;
  op.deadline_ms = lease.end_ms;
  op.constraints.channel = lease.channel;
  op.constraints.max_duration_ms = lease.end_ms - lease.begin_ms;
  op.constraints.outage_permitted = lease.outage_permitted;
  out = runner_.request(op, now_ms);
  survey_token_ = out;
  survey_lease_id_ = lease.lease_id;
  survey_pending_ = true;
  return Status::success();
}

Status MigrationAgent::resume(const MonotonicMs now_ms) noexcept {
  const Status status = participant_.resume(now_ms);
  if (!status) return status;
  last_phase_ = participant_.phase();
  // Durable active record vs physical committed channel: firmware normally
  // already booted onto the record's channel; a mismatch means the
  // boot-time read was unavailable — reconcile through a real verified
  // ChannelCutover, never a bare assignment.
  reconcile_needed_ =
      participant_.active_channel() != runner_.committed_channel();
  next_snapshot_request_ms_ = now_ms + config_.snapshot_request_period_ms;
  next_timesync_ms_ = now_ms + config_.timesync_period_ms;
  return Status::success();
}

void MigrationAgent::poll(const MonotonicMs now_ms) noexcept {
  participant_.poll(now_ms);
  if (coordinator_ != nullptr) {
    coordinator_->poll(now_ms);
    const MigrationMode mode = coordinator_->mode();
    // The judgment runs in every mode — Observe exists to produce it.
    // Verdict changes surface as owner events, never per-poll spam.
    const ChannelAssessment assessment = coordinator_->assess(now_ms);
    if (assessment.verdict != last_assess_verdict_) {
      last_assess_verdict_ = assessment.verdict;
      autosurvey_noted_ = false;
      owner_.on_migration_event(
          assessment.verdict == AssessVerdict::SurveyProposed
              ? "ASSESS_SURVEY_PROPOSED"
              : assessment.verdict == AssessVerdict::InsufficientEvidence
                    ? "ASSESS_INSUFFICIENT_EVIDENCE"
                    : assessment.verdict == AssessVerdict::Disabled
                          ? "ASSESS_DISABLED"
                          : "ASSESS_STABLE",
          kInvalidNodeId);
    }
    if (assessment.verdict == AssessVerdict::SurveyProposed) {
      // §7 bookkeeping only where a survey may actually follow — Observe
      // must never move the participant off Stable (Assess is sticky and
      // would otherwise freeze the pure-observation state).
      if (participant_.phase() == ParticipantPhase::Stable &&
          mode != MigrationMode::Disabled &&
          mode != MigrationMode::Observe) {
        (void)participant_.note_assess();
      }
      // AutoGuarded acts on the proposal through the gated lease path —
      // the coordinator re-checks the stored evidence snapshot, so a lost
      // precondition refuses the visit with the explainable verdict.
      if (mode == MigrationMode::AutoGuarded &&
          participant_.phase() == ParticipantPhase::Assess) {
        auto_survey(assessment, now_ms);
      }
    }
  }
  const ParticipantPhase phase = participant_.phase();
  if (phase != last_phase_) {
    on_phase_transition(last_phase_, phase, now_ms);
    last_phase_ = phase;
  }

  // Resume-time channel reconcile: one bounded verified re-apply, never
  // while a plan is mid-flight (the engine's own cutover owns the runner).
  if (reconcile_needed_ && !reconcile_pending_op_ &&
      !participant_.in_progress()) {
    if (!runner_.busy()) {
      RadioOperation op{};
      op.kind = RadioOperationKind::ChannelCutover;
      op.deadline_ms = now_ms + migration_const::kGuardFloorMs * 20U;
      op.constraints.channel = participant_.active_channel();
      op.constraints.outage_permitted = true;
      reconcile_token_ = runner_.request(op, now_ms);
      reconcile_pending_op_ = true;
    }
  } else if (reconcile_pending_op_) {
    OperationResult result{};
    if (runner_.result(reconcile_token_, result) &&
        result.outcome != OperationOutcome::Pending) {
      reconcile_pending_op_ = false;
      reconcile_needed_ = false;
      if (result.outcome != OperationOutcome::Applied) {
        owner_.on_migration_event("RESUME_CHANNEL_DIVERGED",
                                  kInvalidNodeId);
      }
    }
  }
  if (survey_pending_) {
    OperationResult result{};
    if (runner_.result(survey_token_, result) &&
        result.outcome != OperationOutcome::Pending) {
      survey_pending_ = false;
      if (coordinator_ != nullptr) {
        (void)coordinator_->complete_survey(survey_lease_id_, now_ms);
      }
      (void)participant_.note_survey_end();
    }
  }

  // Stranded-node scout traffic: while Recovering, periodically ask every
  // bound peer for the newest signed state (04 §9.2). Bounded cadence; the
  // strong SLO ends when the engine reaches RECOVERY_REQUIRED.
  if (phase == ParticipantPhase::Recovering &&
      now_ms >= next_snapshot_request_ms_) {
    SnapshotRequest request{};
    request.known_epoch = participant_.committed_epoch();
    std::array<std::uint8_t, migration_wire_const::kInlineObjectMax>
        content{};
    std::size_t size = 0;
    content[0] = static_cast<std::uint8_t>(PlanMessage::SnapshotRequest);
    if (snapshot_request_encode(
            request,
            MutableByteView{content.data() + 1, content.size() - 1}, size)
            .ok()) {
      std::array<NodeId, 24> peers{};
      const std::size_t count =
          wire_.migration_peers(peers.data(), peers.size());
      for (std::size_t i = 0; i < count; ++i) {
        queue_inline(peers[i], autonomy::ControlObjectKind::ChannelPlan,
                     ByteView{content.data(), size + 1},
                     now_ms + migration_wire_const::kPendingTtlMs, false);
      }
    }
    next_snapshot_request_ms_ = now_ms + config_.snapshot_request_period_ms;
  }

  if (config_.authority_role) {
    if (config_.timesync_period_ms != 0 &&
        now_ms >= next_timesync_ms_) {
      // Fresh authenticated clock samples keep participant clocks armed
      // after a restart (D5-03): a stored mapping is never reused.
      autonomy::TimeSyncPayload sample{};
      sample.source = config_.participant.node;
      sample.sequence = ++timesync_sequence_;
      sample.reference_ms = now_ms;
      sample.uncertainty_ms = config_.timesync_uncertainty_ms;
      autonomy::EncodedPayload payload{};
      if (time_sync_encode(sample, payload).ok() &&
          channel_context() == ExchangeChannel::Home) {
        std::array<NodeId, 24> peers{};
        const std::size_t count =
            wire_.migration_peers(peers.data(), peers.size());
        for (std::size_t i = 0; i < count; ++i) {
          (void)wire_.migration_send(peers[i], FrameType::TimeSync,
                                     payload.view());
        }
      }
      next_timesync_ms_ = now_ms + config_.timesync_period_ms;
    }
    check_terminal(now_ms);
  }

  pump_pending(now_ms);
  exchange_.poll(now_ms, channel_context());
}

}  // namespace routeloom
