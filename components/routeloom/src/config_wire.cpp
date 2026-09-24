// Routed config transport glue — see config_wire.hpp for the contract map.

#include "routeloom/config_wire.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256

namespace routeloom {

namespace {

// Control payload subtype (the byte after the version prelude).
constexpr std::uint8_t kSubChallengeQuery = 1;
constexpr std::uint8_t kSubChallenge = 2;
constexpr std::uint8_t kSubStatusQuery = 3;
constexpr std::uint8_t kSubStatus = 4;

// USB HostOps config subcommands the gateway reports under.
constexpr std::uint8_t kSubConfigPermit = 0x21;
constexpr std::uint8_t kSubConfigStatus = 0x22;
constexpr std::uint8_t kSubConfigChallenge = 0x23;
constexpr std::uint8_t kSubConfigRecover = 0x24;

// The two-byte Control prelude: version | subtype.
std::uint8_t control_subtype(const wire::PlainFrame& frame) noexcept {
  return frame.payload_size >= 2 ? frame.payload[1] : 0;
}

}  // namespace

// --- ConfigTarget --------------------------------------------------------------

Status ConfigTarget::add_journal(const std::uint16_t config_namespace,
                                 ConfigJournal& journal) noexcept {
  if (journal_count_ >= config_wire_const::kMaxJournals ||
      !endpoint::config_namespace_valid(config_namespace) ||
      find_journal(config_namespace) != nullptr) {
    return Status::error(StatusCode::InvalidArgument, "config journal add invalid");
  }
  namespaces_[journal_count_] = config_namespace;
  journals_[journal_count_] = &journal;
  ++journal_count_;
  return Status::success();
}

ConfigJournal* ConfigTarget::find_journal(const std::uint16_t config_namespace) noexcept {
  for (std::size_t i = 0; i < journal_count_; ++i) {
    if (namespaces_[i] == config_namespace) return journals_[i];
  }
  return nullptr;
}

void ConfigTarget::on_config_frame(const NodeId peer, const wire::PlainFrame& frame,
                                   const MonotonicMs now_ms) noexcept {
  switch (frame.header.type) {
    case FrameType::Control:
      handle_control(peer, frame, now_ms);
      break;
    case FrameType::ControlObject:
      handle_manifest(peer, frame, now_ms);
      break;
    case FrameType::ObjectChunk:
      handle_chunk(peer, frame, now_ms);
      break;
    case FrameType::ObjectAck:
      // A target only RECEIVES permit objects; an ObjectAck addressed to it
      // is unexpected (a sender-role frame on the wrong node). Ignore it.
      break;
    default:
      break;
  }
}

void ConfigTarget::handle_control(const NodeId peer, const wire::PlainFrame& frame,
                                  const MonotonicMs now_ms) noexcept {
  (void)peer;  // replies go to the end-authenticated origin, not the hop
  const std::uint8_t subtype = control_subtype(frame);
  const NodeId origin = frame.header.origin;
  endpoint::EncodedServicePayload reply{};
  Status status;
  switch (subtype) {
    case kSubChallengeQuery: {
      endpoint::ControlChallengeQuery query{};
      status = endpoint::control_challenge_query_decode(
          ByteView{frame.payload.data(), frame.payload_size}, query);
      if (!status) {
        ++control_denied_;
        return;
      }
      ConfigJournal* journal = find_journal(query.config_namespace);
      if (journal == nullptr) {
        ++control_denied_;
        return;
      }
      status = journal->handle_challenge_query(query, now_ms, reply);
      break;
    }
    case kSubStatusQuery: {
      endpoint::ControlStatusQuery query{};
      status = endpoint::control_status_query_decode(
          ByteView{frame.payload.data(), frame.payload_size}, query);
      if (!status) {
        ++control_denied_;
        return;
      }
      ConfigJournal* journal = find_journal(query.config_namespace);
      if (journal == nullptr) {
        ++control_denied_;
        return;
      }
      status = journal->handle_status_query(query, now_ms, reply);
      break;
    }
    default:
      // Challenge2/Status4 are replies TO a query — they belong on the
      // issuer (gateway), not a target. Unknown subtypes are denied.
      ++control_denied_;
      return;
  }
  if (!status || reply.size == 0) {
    ++control_denied_;
    return;
  }
  // Reply goes to the end-authenticated origin, not the immediate peer.
  (void)wire_.config_send(origin, FrameType::Control, reply.view(), now_ms);
}

void ConfigTarget::handle_manifest(const NodeId peer, const wire::PlainFrame& frame,
                                   const MonotonicMs now_ms) noexcept {
  (void)peer;
  const NodeId origin = frame.header.origin;
  autonomy::ControlObjectPayload manifest{};
  Status status = autonomy::control_object_decode(
      ByteView{frame.payload.data(), frame.payload_size}, manifest);
  if (!status || manifest.total_len == 0 ||
      manifest.total_len > kConfigPermitObjectMax) {
    ++control_denied_;
    return;
  }
  // Kind-4 recovery runs through a dedicated lane: the journal's
  // recovery-side entry points keep accepting while quarantined, and a
  // stalled kind-3 assembly can never occupy its slot.
  if (manifest.kind == autonomy::ControlObjectKind::ConfigPermit) {
    handle_manifest_for(intake_, false, origin, frame, now_ms);
    return;
  }
  if (manifest.kind == autonomy::ControlObjectKind::ConfigRecovery) {
    handle_manifest_for(recovery_intake_, true, origin, frame, now_ms);
    return;
  }
  ++control_denied_;
}

void ConfigTarget::handle_manifest_for(
    Intake& lane, const bool recovery, const NodeId origin,
    const wire::PlainFrame& frame, const MonotonicMs now_ms) noexcept {
  autonomy::ControlObjectPayload manifest{};
  Status status = autonomy::control_object_decode(
      ByteView{frame.payload.data(), frame.payload_size}, manifest);
  if (!status) {
    ++control_denied_;
    return;
  }

  ConfigJournal* journal = nullptr;
  if (lane.active) {
    // One reassembly per lane: a manifest for a different object is
    // refused — and so is one carrying the same object hash but a
    // different declared length. Only a byte-consistent duplicate of the
    // live manifest is re-acked by the owning journal.
    if (lane.hash != manifest.object_hash ||
        manifest.total_len != lane.total_len) {
      send_ack(origin, manifest.object_hash, lane.received,
               autonomy::ObjectAckStatus::Failed, now_ms);
      return;
    }
    journal = lane.journal;
  } else {
    // v1 manifests carry no namespace: offer the object to the journals in
    // registration order; the first to accept it owns the reassembly (the
    // primary journal in the common single-namespace build). An object
    // whose decoded namespace does not match is refused by that journal's
    // own validation at submit time.
    for (std::size_t i = 0; i < journal_count_; ++i) {
      const Status accepted =
          recovery ? journals_[i]->note_recovery_manifest(manifest, now_ms)
                   : journals_[i]->note_object_manifest(manifest, now_ms);
      if (accepted) {
        journal = journals_[i];
        break;
      }
    }
    if (journal == nullptr) {
      send_ack(origin, manifest.object_hash, 0, autonomy::ObjectAckStatus::Failed,
               now_ms);
      return;
    }
    lane.active = true;
    lane.journal = journal;
    lane.hash = manifest.object_hash;
    lane.total_len = manifest.total_len;
    lane.received = 0;
    lane.started_ms = now_ms;
    std::memset(lane.bitmap.data(), 0, lane.bitmap.size());
    send_ack(origin, manifest.object_hash, 0, autonomy::ObjectAckStatus::Incomplete,
             now_ms);
    return;
  }

  // Duplicate manifest for the live object: hand it back to the owning
  // journal (which dedups) and re-ack the current progress.
  status = recovery ? journal->note_recovery_manifest(manifest, now_ms)
                    : journal->note_object_manifest(manifest, now_ms);
  send_ack(origin, manifest.object_hash, lane.received,
           status ? autonomy::ObjectAckStatus::Incomplete
                  : autonomy::ObjectAckStatus::Failed,
           now_ms);
}

void ConfigTarget::handle_chunk(const NodeId peer, const wire::PlainFrame& frame,
                                const MonotonicMs now_ms) noexcept {
  (void)peer;
  const NodeId origin = frame.header.origin;
  autonomy::ObjectChunkPayload chunk{};
  Status status = autonomy::object_chunk_decode(
      ByteView{frame.payload.data(), frame.payload_size}, chunk);
  if (!status) {
    ++control_denied_;
    return;
  }
  // Chunks bind to whichever lane's manifest hash they match — the two
  // lanes can never share a hash (a manifest conflict would have Failed).
  if (intake_.active && chunk.object_hash == intake_.hash &&
      intake_.journal != nullptr) {
    handle_chunk_for(intake_, false, origin, frame, now_ms);
    return;
  }
  if (recovery_intake_.active && chunk.object_hash == recovery_intake_.hash &&
      recovery_intake_.journal != nullptr) {
    handle_chunk_for(recovery_intake_, true, origin, frame, now_ms);
    return;
  }
  ++control_denied_;
}

void ConfigTarget::handle_chunk_for(
    Intake& lane, const bool recovery, const NodeId origin,
    const wire::PlainFrame& frame, const MonotonicMs now_ms) noexcept {
  autonomy::ObjectChunkPayload chunk{};
  Status status = autonomy::object_chunk_decode(
      ByteView{frame.payload.data(), frame.payload_size}, chunk);
  if (!status) {
    ++control_denied_;
    return;
  }
  status = recovery ? lane.journal->note_recovery_chunk(chunk, now_ms)
                    : lane.journal->note_object_chunk(chunk, now_ms);
  // Update the honest received-byte mirror only for bytes the journal
  // accepted inside the manifest window (dedup is tracked by the bitmap).
  if (status && chunk.offset + chunk.data_size <= lane.total_len) {
    for (std::uint16_t i = 0; i < chunk.data_size; ++i) {
      const std::uint16_t byte_index = chunk.offset + i;
      const std::uint8_t mask = static_cast<std::uint8_t>(1u << (byte_index & 7u));
      if ((lane.bitmap[byte_index >> 3] & mask) == 0) {
        lane.bitmap[byte_index >> 3] |= mask;
        ++lane.received;
      }
    }
  }
  const bool complete = lane.received >= lane.total_len;
  send_ack(origin, chunk.object_hash, lane.received,
           !status ? autonomy::ObjectAckStatus::Failed
                   : (complete ? autonomy::ObjectAckStatus::Ok
                               : autonomy::ObjectAckStatus::Incomplete),
           now_ms);
  if (complete || !status) {
    // Assembly finished (Ok) or the journal rejected the object (Failed):
    // either way this intake slot frees for the next manifest.
    lane.active = false;
    lane.journal = nullptr;
  }
}

void ConfigTarget::send_ack(const NodeId dest, const autonomy::ObjectHash& hash,
                            const std::uint16_t received_len,
                            const autonomy::ObjectAckStatus status,
                            const MonotonicMs now_ms) noexcept {
  autonomy::ObjectAckPayload ack{};
  ack.subtype = autonomy::ObjectAckSubtype::Ack;
  ack.object_hash = hash;
  ack.received_len = received_len;
  ack.status = status;
  autonomy::EncodedPayload encoded{};
  if (!autonomy::object_ack_encode(ack, encoded)) return;
  if (wire_.config_send(dest, FrameType::ObjectAck, encoded.view(), now_ms)) {
    ++object_acks_;
  }
}

std::uint16_t ConfigTarget::bitmap_count() const noexcept {
  return intake_.received + recovery_intake_.received;
}

void ConfigTarget::on_config_job_done(const MessageId& id, const bool hop_accepted,
                                      const char* reason,
                                      const MonotonicMs now_ms) noexcept {
  // A target emits replies and acks fire-and-forget: their hop-level
  // completion is the sender's concern, not evidence the endpoint needs.
  (void)id;
  (void)hop_accepted;
  (void)reason;
  (void)now_ms;
}

void ConfigTarget::poll(const MonotonicMs now_ms) noexcept {
  for (std::size_t i = 0; i < journal_count_; ++i) {
    journals_[i]->poll(now_ms);
  }
  // Mirror the journal's own reassembly timeout so each intake slot frees
  // in step with the assembler's 10 s bound (same monotonic clock).
  if (intake_.active &&
      now_ms - intake_.started_ms >= kConfigReassemblyTimeoutMs) {
    intake_.active = false;
    intake_.journal = nullptr;
  }
  if (recovery_intake_.active &&
      now_ms - recovery_intake_.started_ms >= kConfigReassemblyTimeoutMs) {
    recovery_intake_.active = false;
    recovery_intake_.journal = nullptr;
  }
}

// --- ConfigGateway -------------------------------------------------------------

Status ConfigGateway::submit_status_query(
    const std::uint64_t request, const NodeId target,
    const std::uint16_t config_namespace,
    const std::array<std::uint8_t, 16>& operation_id,
    const MonotonicMs now_ms) noexcept {
  if (query_.active) {
    return Status::error(StatusCode::WouldBlock, "config query busy");
  }
  if (target == kInvalidNodeId ||
      !endpoint::config_namespace_valid(config_namespace)) {
    return Status::error(StatusCode::InvalidArgument, "config query target invalid");
  }
  endpoint::ControlStatusQuery query{};
  query.config_namespace = config_namespace;
  query.operation_id = operation_id;
  endpoint::EncodedServicePayload encoded{};
  Status status = endpoint::control_status_query_encode(query, encoded);
  if (!status) return status;
  status = wire_.config_send(target, FrameType::Control, encoded.view(), now_ms);
  if (!status) return status;
  query_.active = true;
  query_.request = request;
  query_.target = target;
  query_.usb_sub = kSubConfigStatus;
  query_.expect = QueryExpect::Status;
  query_.deadline_ms = now_ms + config_wire_const::kQueryTimeoutMs;
  query_.echo = operation_id;
  query_.config_namespace = config_namespace;
  return Status::success();
}

Status ConfigGateway::submit_challenge(
    const std::uint64_t request, const NodeId target,
    const std::uint16_t config_namespace, const std::uint16_t schema,
    const std::array<std::uint8_t, 16>& client_nonce,
    const MonotonicMs now_ms) noexcept {
  if (query_.active) {
    return Status::error(StatusCode::WouldBlock, "config query busy");
  }
  if (target == kInvalidNodeId ||
      !endpoint::config_namespace_valid(config_namespace) || schema == 0) {
    return Status::error(StatusCode::InvalidArgument, "config challenge target invalid");
  }
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = config_namespace;
  query.schema = schema;
  query.client_nonce = client_nonce;
  endpoint::EncodedServicePayload encoded{};
  Status status = endpoint::control_challenge_query_encode(query, encoded);
  if (!status) return status;
  status = wire_.config_send(target, FrameType::Control, encoded.view(), now_ms);
  if (!status) return status;
  query_.active = true;
  query_.request = request;
  query_.target = target;
  query_.usb_sub = kSubConfigChallenge;
  query_.expect = QueryExpect::Challenge;
  query_.deadline_ms = now_ms + config_wire_const::kQueryTimeoutMs;
  query_.echo = client_nonce;
  query_.config_namespace = config_namespace;
  return Status::success();
}

Status ConfigGateway::submit_permit(const std::uint64_t request, const NodeId target,
                                    const ByteView permit,
                                    const MonotonicMs now_ms) noexcept {
  if (transfer_.active) {
    return Status::error(StatusCode::WouldBlock, "config permit transfer busy");
  }
  Status status;
  start_transfer(transfer_, request, target, autonomy::ControlObjectKind::ConfigPermit,
                 permit, now_ms, status);
  if (status) transfer_.usb_sub = kSubConfigPermit;
  return status;
}

Status ConfigGateway::submit_recovery(const std::uint64_t request,
                                      const NodeId target, const ByteView object,
                                      const MonotonicMs now_ms) noexcept {
  if (recovery_transfer_.active) {
    return Status::error(StatusCode::WouldBlock, "config recovery transfer busy");
  }
  Status status;
  start_transfer(recovery_transfer_, request, target,
                 autonomy::ControlObjectKind::ConfigRecovery, object, now_ms,
                 status);
  if (status) recovery_transfer_.usb_sub = kSubConfigRecover;
  return status;
}

void ConfigGateway::start_transfer(
    PermitTransfer& transfer, const std::uint64_t request, const NodeId target,
    const autonomy::ControlObjectKind kind, const ByteView object,
    const MonotonicMs now_ms, Status& out) noexcept {
  if (target == kInvalidNodeId || object.size == 0 ||
      object.size > kConfigPermitObjectMax || object.data == nullptr) {
    out = Status::error(StatusCode::InvalidArgument, "config object invalid");
    return;
  }
  autonomy::ControlObjectPayload manifest{};
  manifest.subtype = autonomy::ControlObjectSubtype::Manifest;
  manifest.kind = kind;
  manifest.total_len = static_cast<std::uint16_t>(object.size);
  sha256(object, manifest.object_hash);
  autonomy::EncodedPayload encoded{};
  out = autonomy::control_object_encode(manifest, encoded);
  if (!out) return;
  out = wire_.config_send(target, FrameType::ControlObject, encoded.view(), now_ms);
  if (!out) return;
  transfer.active = true;
  transfer.request = request;
  transfer.target = target;
  transfer.hash = manifest.object_hash;
  transfer.object.size = object.size;
  std::memcpy(transfer.object.bytes.data(), object.data, object.size);
  transfer.object_size = static_cast<std::uint16_t>(object.size);
  transfer.next_offset = 0;
  transfer.phase = TransferPhase::Chunks;
  transfer.deadline_ms = now_ms + config_wire_const::kPermitTimeoutMs;
  // Push the first chunk immediately; the rest ride poll() so a full TX
  // queue slows the pump instead of dropping a chunk into a timeout.
  pump_transfer(transfer, now_ms);
  out = Status::success();
}

void ConfigGateway::pump_transfer(PermitTransfer& transfer,
                                  const MonotonicMs now_ms) noexcept {
  if (!transfer.active || transfer.phase != TransferPhase::Chunks) return;
  // Bounded pump: one chunk per call keeps the manifest+chunk burst inside
  // the scheduler's bounded queue; a WouldBlock/NoRoute send is retried on
  // the next poll until the transfer deadline makes it honest.
  while (transfer.active && transfer.next_offset < transfer.object_size) {
    const std::uint16_t offset = transfer.next_offset;
    const std::uint16_t len = static_cast<std::uint16_t>(std::min<std::size_t>(
        config_wire_const::kChunkDataMax, transfer.object_size - offset));
    autonomy::ObjectChunkPayload chunk{};
    chunk.subtype = autonomy::ObjectChunkSubtype::Chunk;
    chunk.object_hash = transfer.hash;
    chunk.offset = offset;
    chunk.data_size = len;
    std::memcpy(chunk.data.data(), transfer.object.bytes.data() + offset, len);
    autonomy::EncodedPayload encoded{};
    if (!autonomy::object_chunk_encode(chunk, encoded)) {
      finish_transfer(transfer, ConfigOpsResult::Indeterminate, now_ms);
      return;
    }
    const Status sent =
        wire_.config_send(transfer.target, FrameType::ObjectChunk,
                          encoded.view(), now_ms);
    if (!sent) {
      // Queue full / transient: stop pumping, retry on the next poll. A
      // permanent NoRoute surfaces at the deadline as Indeterminate.
      return;
    }
    transfer.next_offset = static_cast<std::uint16_t>(offset + len);
  }
  if (transfer.active && transfer.next_offset >= transfer.object_size) {
    transfer.phase = TransferPhase::AwaitAck;
  }
}

void ConfigGateway::on_config_frame(const NodeId peer, const wire::PlainFrame& frame,
                                    const MonotonicMs now_ms) noexcept {
  (void)peer;  // replies/acks are matched on the end-authenticated origin
  const NodeId origin = frame.header.origin;
  switch (frame.header.type) {
    case FrameType::Control: {
      if (!query_.active || origin != query_.target) return;
      const std::uint8_t subtype = control_subtype(frame);
      const ByteView body{frame.payload.data(), frame.payload_size};
      if (query_.expect == QueryExpect::Challenge && subtype == kSubChallenge) {
        endpoint::ControlChallenge challenge{};
        // The reply must echo THIS query's nonce and namespace — any other
        // end-authenticated frame from the target is foreign, not ours.
        if (endpoint::control_challenge_decode(body, challenge) &&
            challenge.client_nonce == query_.echo &&
            challenge.config_namespace == query_.config_namespace) {
          finish_query(ConfigOpsResult::Ok, body, now_ms);
        }
      } else if (query_.expect == QueryExpect::Status && subtype == kSubStatus) {
        endpoint::ControlStatus status{};
        if (endpoint::control_status_decode(body, status) &&
            status.operation_id == query_.echo &&
            status.config_namespace == query_.config_namespace) {
          finish_query(ConfigOpsResult::Ok, body, now_ms);
        }
      }
      break;
    }
    case FrameType::ObjectAck: {
      autonomy::ObjectAckPayload ack{};
      if (!autonomy::object_ack_decode(
              ByteView{frame.payload.data(), frame.payload_size}, ack)) {
        return;
      }
      // An ack binds to whichever in-flight transfer owns the object hash —
      // permit and recovery transfers run on separate slots.
      PermitTransfer* lane = nullptr;
      if (transfer_.active && origin == transfer_.target &&
          ack.object_hash == transfer_.hash) {
        lane = &transfer_;
      } else if (recovery_transfer_.active && origin == recovery_transfer_.target &&
                 ack.object_hash == recovery_transfer_.hash) {
        lane = &recovery_transfer_;
      }
      if (lane == nullptr) return;
      if (ack.status == autonomy::ObjectAckStatus::Failed) {
        finish_transfer(*lane, ConfigOpsResult::Denied, now_ms);
      } else if (ack.status == autonomy::ObjectAckStatus::Ok &&
                 ack.received_len >= lane->object_size) {
        // Assembly completed at the target — the object verdict itself is
        // a separate status query, never implied by transport success.
        finish_transfer(*lane, ConfigOpsResult::Ok, now_ms);
      }
      // Incomplete acks are progress; the deadline bounds the wait.
      break;
    }
    default:
      break;
  }
}

void ConfigGateway::on_config_job_done(const MessageId& id, const bool hop_accepted,
                                       const char* reason,
                                       const MonotonicMs now_ms) noexcept {
  // Per-hop outcomes are the scheduler's retry concern: an ack that never
  // arrives resolves at the operation deadline as Indeterminate, which is
  // the honest terminal state — a failed hop attempt is not itself proof
  // the transfer failed.
  (void)id;
  (void)hop_accepted;
  (void)reason;
  (void)now_ms;
}

void ConfigGateway::finish_query(const ConfigOpsResult result, const ByteView body,
                                 const MonotonicMs now_ms) noexcept {
  const std::uint64_t request = query_.request;
  const std::uint8_t sub = query_.usb_sub;
  const NodeId target = query_.target;
  query_.active = false;
  query_.expect = QueryExpect::None;
  ++replies_reported_;
  host_.on_config_reply(request, sub, result, target, body, now_ms);
}

void ConfigGateway::finish_transfer(PermitTransfer& transfer,
                                    const ConfigOpsResult result,
                                    const MonotonicMs now_ms) noexcept {
  const std::uint64_t request = transfer.request;
  const NodeId target = transfer.target;
  const std::uint8_t sub = transfer.usb_sub;
  transfer.active = false;
  ++replies_reported_;
  host_.on_config_reply(request, sub, result, target, ByteView{}, now_ms);
}

void ConfigGateway::poll(const MonotonicMs now_ms) noexcept {
  pump_transfer(transfer_, now_ms);
  pump_transfer(recovery_transfer_, now_ms);
  if (query_.active && now_ms >= query_.deadline_ms) {
    finish_query(ConfigOpsResult::Timeout, ByteView{}, now_ms);
  }
  if (transfer_.active && now_ms >= transfer_.deadline_ms) {
    finish_transfer(transfer_, ConfigOpsResult::Indeterminate, now_ms);
  }
  if (recovery_transfer_.active && now_ms >= recovery_transfer_.deadline_ms) {
    finish_transfer(recovery_transfer_, ConfigOpsResult::Indeterminate, now_ms);
  }
}

}  // namespace routeloom
