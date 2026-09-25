// Routed config transport glue — see config_wire.hpp for the contract map.

#include "routeloom/config_wire.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/sdkv1_authority_transport.hpp"

namespace routeloom {

namespace {

// Control payload subtype (the byte after the version prelude).
constexpr std::uint8_t kSubChallengeQuery = 1;
constexpr std::uint8_t kSubChallenge = 2;
constexpr std::uint8_t kSubStatusQuery = 3;
constexpr std::uint8_t kSubStatus = 4;
constexpr std::uint8_t kSubTrustStatusQuery = 5;
constexpr std::uint8_t kSubTrustStatus = 6;
constexpr std::uint8_t kSubRecoveryInfoQuery = 7;
constexpr std::uint8_t kSubRecoveryInfo = 8;

// USB HostOps config subcommands the gateway reports under.
constexpr std::uint8_t kSubConfigPermit = 0x21;
constexpr std::uint8_t kSubConfigStatus = 0x22;
constexpr std::uint8_t kSubConfigChallenge = 0x23;
constexpr std::uint8_t kSubConfigRecover = 0x24;
constexpr std::uint8_t kSubConfigTrust = 0x25;
constexpr std::uint8_t kSubConfigTrustStatus = 0x26;
constexpr std::uint8_t kSubConfigRecoveryInfo = 0x27;

// The two-byte Control prelude: version | subtype.
std::uint8_t control_subtype(const wire::PlainFrame& frame) noexcept {
  return frame.payload_size >= 2 ? frame.payload[1] : 0;
}

bool all_zero(const ByteView view) noexcept {
  for (std::size_t i = 0; i < view.size; ++i) {
    if (view.data[i] != 0) return false;
  }
  return true;
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

void ConfigTarget::attach_trust_store(TrustStore& store,
                                      SecurityFloorStore& floor) noexcept {
  trust_ = &store;
  trust_floor_ = &floor;
}

void ConfigTarget::attach_authority(sdkv1::AuthorityMeshDemux* demux) noexcept {
  authority_ = demux;
}

void ConfigTarget::on_config_frame(const NodeId peer, const wire::PlainFrame& frame,
                                   const MonotonicMs now_ms) noexcept {
  // The authority lane claims its frames before the config path: subtype 9
  // carriers, kind-7 manifests, and the chunks/acks of a live authority
  // transfer (chunks carry no kind, so they route by origin and hash).
  if (authority_ != nullptr) {
    const ByteView payload{frame.payload.data(), frame.payload_size};
    switch (frame.header.type) {
      case FrameType::Control:
        if (authority_->claim_control(control_subtype(frame))) {
          authority_->on_control(frame.header.origin, payload, now_ms);
          return;
        }
        break;
      case FrameType::ControlObject: {
        autonomy::ControlObjectPayload manifest{};
        if (autonomy::control_object_decode(payload, manifest) &&
            authority_->claim_kind(manifest.kind)) {
          if (assembly_.active && assembly_.origin == frame.header.origin &&
              assembly_.hash == manifest.object_hash) {
            send_ack(frame.header.origin, manifest.object_hash, 0,
                     autonomy::ObjectAckStatus::Failed, now_ms);
            return;
          }
          authority_->on_manifest(frame.header.origin, manifest, now_ms);
          return;
        }
        break;
      }
      case FrameType::ObjectChunk: {
        autonomy::ObjectChunkPayload chunk{};
        if (autonomy::object_chunk_decode(payload, chunk) &&
            authority_->claim_transfer(frame.header.origin, chunk.object_hash)) {
          authority_->on_chunk(frame.header.origin, chunk, now_ms);
          return;
        }
        break;
      }
      case FrameType::ObjectAck: {
        autonomy::ObjectAckPayload ack{};
        if (autonomy::object_ack_decode(payload, ack) &&
            authority_->claim_transfer(frame.header.origin, ack.object_hash)) {
          authority_->on_ack(frame.header.origin, ack, now_ms);
          return;
        }
        break;
      }
      default:
        break;
    }
  }
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
    case kSubTrustStatusQuery:
      // Device-global: answered from the trust store, not a journal.
      handle_trust_status_query(origin, frame, now_ms);
      return;
    case kSubRecoveryInfoQuery: {
      endpoint::RecoveryInfoQuery query{};
      status = endpoint::recovery_info_query_decode(
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
      status = journal->handle_recovery_info_query(query, now_ms, reply);
      break;
    }
    default:
      // Challenge2/Status4/TrustStatus6/RecoveryInfo8 are replies TO a
      // query — they belong on the issuer (gateway), not a target.
      // Unknown subtypes are denied.
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

void ConfigTarget::handle_trust_status_query(const NodeId origin,
                                             const wire::PlainFrame& frame,
                                             const MonotonicMs now_ms) noexcept {
  if (trust_ == nullptr || trust_floor_ == nullptr || !trust_->initialized()) {
    ++control_denied_;
    return;
  }
  endpoint::TrustStatusQuery query{};
  if (!endpoint::trust_status_query_decode(
          ByteView{frame.payload.data(), frame.payload_size}, query)) {
    ++control_denied_;
    return;
  }
  // Public fields only — epoch, generation floor, network, fingerprint,
  // counts and impairment. No image means zeros plus whatever impairment
  // the store reports (quarantine without an anchor still answers).
  endpoint::TrustStatus status{};
  status.nonce_echo = query.nonce;
  if (trust_->has_active()) {
    status.store_epoch = trust_->store_epoch();
    status.min_authority_generation = trust_->min_authority_generation();
    status.network = trust_->network();
    status.image_fingerprint = trust_->image_fingerprint();
    const TrustImage& image = trust_->image();
    status.anchor_count = image.anchor_count;
    status.key_count = image.key_count;
    status.revocation_count = image.revocation_count;
    status.flags |= endpoint::kTrustStatusFlagHasActive;
  }
  if (trust_->uncertain()) status.flags |= endpoint::kTrustStatusFlagUncertain;
  if (trust_->quarantined()) {
    status.flags |= endpoint::kTrustStatusFlagQuarantined;
  }
  endpoint::EncodedServicePayload reply{};
  if (!endpoint::trust_status_encode(status, reply) || reply.size == 0) {
    ++control_denied_;
    return;
  }
  (void)wire_.config_send(origin, FrameType::Control, reply.view(), now_ms);
}

void ConfigTarget::handle_manifest(const NodeId peer, const wire::PlainFrame& frame,
                                   const MonotonicMs now_ms) noexcept {
  (void)peer;
  const NodeId origin = frame.header.origin;
  autonomy::ControlObjectPayload manifest{};
  if (!autonomy::control_object_decode(
          ByteView{frame.payload.data(), frame.payload_size}, manifest)) {
    ++control_denied_;
    return;
  }
  // Kind caps differ: kind 3/4 ride the 1024 B permit bound, kind 5 the
  // full 2048 B carrier. Migration kinds 1/2 never route here, and any
  // other kind is denied without an ack.
  const bool is_trust = manifest.kind == autonomy::ControlObjectKind::TrustManifest;
  const bool known_kind =
      is_trust || manifest.kind == autonomy::ControlObjectKind::ConfigPermit ||
      manifest.kind == autonomy::ControlObjectKind::ConfigRecovery;
  const std::uint16_t cap =
      is_trust ? kConfigTrustObjectMax : kConfigPermitObjectMax;
  if (!known_kind || manifest.total_len == 0 || manifest.total_len > cap ||
      all_zero(ByteView{manifest.object_hash.data(),
                        manifest.object_hash.size()})) {
    ++control_denied_;
    return;
  }
  if (authority_ != nullptr &&
      authority_->claim_transfer(origin, manifest.object_hash)) {
    send_ack(origin, manifest.object_hash, 0,
             autonomy::ObjectAckStatus::Failed, now_ms);
    return;
  }
  Assembly& slot = assembly_;
  if (slot.active) {
    // One assembly at a time, keyed by the pinned (origin, kind, hash,
    // total_len) tuple: a manifest for anything else is refused, and only
    // a byte-consistent duplicate of the live manifest is re-acked — with
    // current progress, never a deadline extension.
    if (slot.origin != origin || slot.kind != manifest.kind ||
        slot.hash != manifest.object_hash ||
        slot.total_len != manifest.total_len) {
      send_ack(origin, manifest.object_hash, slot.received,
               autonomy::ObjectAckStatus::Failed, now_ms);
      return;
    }
    send_ack(origin, manifest.object_hash, slot.received,
             autonomy::ObjectAckStatus::Incomplete, now_ms);
    return;
  }
  // Idle slot: admit by kind. Kind 3/4 offer to the journals in
  // registration order — each gates on its own state, so an impaired
  // journal refuses kind 3 and kind 3 can never reserve while impaired.
  // Kind 5 only needs the trust connection; completion re-checks
  // everything through trust_manifest_accept().
  ConfigJournal* journal = nullptr;
  if (is_trust) {
    if (trust_ == nullptr || trust_floor_ == nullptr) {
      send_ack(origin, manifest.object_hash, 0,
               autonomy::ObjectAckStatus::Failed, now_ms);
      return;
    }
  } else {
    for (std::size_t i = 0; i < journal_count_; ++i) {
      const Status accepted =
          journals_[i]->note_object_manifest(manifest, now_ms);
      if (accepted) {
        journal = journals_[i];
        break;
      }
    }
    if (journal == nullptr) {
      send_ack(origin, manifest.object_hash, 0,
               autonomy::ObjectAckStatus::Failed, now_ms);
      return;
    }
  }
  slot.active = true;
  slot.kind = manifest.kind;
  slot.origin = origin;
  slot.journal = journal;  // null for kind 5 — the trust store owns it
  slot.hash = manifest.object_hash;
  slot.total_len = manifest.total_len;
  slot.received = 0;
  slot.started_ms = now_ms;
  std::memset(slot.bitmap.data(), 0, slot.bitmap.size());
  send_ack(origin, manifest.object_hash, 0,
           autonomy::ObjectAckStatus::Incomplete, now_ms);
}

void ConfigTarget::handle_chunk(const NodeId peer, const wire::PlainFrame& frame,
                                const MonotonicMs now_ms) noexcept {
  (void)peer;
  const NodeId origin = frame.header.origin;
  autonomy::ObjectChunkPayload chunk{};
  if (!autonomy::object_chunk_decode(
          ByteView{frame.payload.data(), frame.payload_size}, chunk)) {
    ++control_denied_;
    return;
  }
  Assembly& slot = assembly_;
  // Chunks bind to the pinned tuple — a foreign origin or hash is not
  // this assembly's next byte.
  if (!slot.active || origin != slot.origin ||
      chunk.object_hash != slot.hash) {
    ++control_denied_;
    return;
  }
  if (now_ms - slot.started_ms > kConfigReassemblyTimeoutMs) {
    const std::uint16_t progress = slot.received;
    drop_assembly();
    send_ack(origin, chunk.object_hash, progress,
             autonomy::ObjectAckStatus::Failed, now_ms);
    return;
  }
  if (chunk.data_size == 0 ||
      static_cast<std::uint32_t>(chunk.offset) + chunk.data_size >
          slot.total_len) {
    // Out-of-window bytes poison the assembly (05 §5.5).
    const std::uint16_t progress = slot.received;
    drop_assembly();
    send_ack(origin, chunk.object_hash, progress,
             autonomy::ObjectAckStatus::Failed, now_ms);
    return;
  }
  for (std::uint16_t i = 0; i < chunk.data_size; ++i) {
    const std::uint16_t at = static_cast<std::uint16_t>(chunk.offset + i);
    const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at & 7U));
    if ((slot.bitmap[at >> 3U] & mask) != 0) {
      if (slot.buffer[at] != chunk.data[i]) {
        // Same offset, different bytes — reject the whole assembly.
        const std::uint16_t progress = slot.received;
        drop_assembly();
        send_ack(origin, chunk.object_hash, progress,
                 autonomy::ObjectAckStatus::Failed, now_ms);
        return;
      }
      continue;
    }
    slot.bitmap[at >> 3U] =
        static_cast<std::uint8_t>(slot.bitmap[at >> 3U] | mask);
    slot.buffer[at] = chunk.data[i];
    ++slot.received;
  }
  if (slot.received >= slot.total_len) {
    dispatch_complete(now_ms);
    return;
  }
  send_ack(origin, chunk.object_hash, slot.received,
           autonomy::ObjectAckStatus::Incomplete, now_ms);
}

void ConfigTarget::dispatch_complete(const MonotonicMs now_ms) noexcept {
  Assembly& slot = assembly_;
  const NodeId origin = slot.origin;
  const autonomy::ObjectHash hash = slot.hash;
  const std::uint16_t total = slot.total_len;
  Digest256 digest{};
  sha256(ByteView{slot.buffer.data(), total}, digest);
  if (!constant_time_equal(ByteView{digest.data(), digest.size()},
                           ByteView{hash.data(), hash.size()})) {
    // Every byte landed, but the object is not what the manifest named.
    drop_assembly();
    send_ack(origin, hash, total, autonomy::ObjectAckStatus::Failed, now_ms);
    return;
  }
  const ByteView object{slot.buffer.data(), total};
  Status status;
  if (slot.kind == autonomy::ControlObjectKind::ConfigPermit) {
    ConfigVerdict verdict{};
    status = slot.journal == nullptr
                 ? Status::error(StatusCode::InvalidState,
                                "config assembly without owner")
                 : slot.journal->submit_permit(object, now_ms, true, verdict);
    static_cast<void>(verdict);
  } else if (slot.kind == autonomy::ControlObjectKind::ConfigRecovery) {
    ConfigVerdict verdict{};
    status = slot.journal == nullptr
                 ? Status::error(StatusCode::InvalidState,
                                "config assembly without owner")
                 : slot.journal->submit_recovery(object, now_ms, verdict);
    static_cast<void>(verdict);
  } else {
    // Kind 5: the shared expensive-verify gate FIRST — a manifest costs
    // the same P-256 as a permit, and failures charge the budget too, so
    // a manifest storm cannot starve the permit path (or vice versa).
    if (trust_ == nullptr || trust_floor_ == nullptr) {
      status = Status::error(StatusCode::InvalidState,
                             "config trust not attached");
    } else if (!limiter_.consume_expensive_verify(now_ms)) {
      status = Status::error(StatusCode::Busy, "trust verify intake budget");
    } else {
      status = trust_manifest_accept(*trust_, object, *trust_floor_);
    }
  }
  drop_assembly();
  // Assembly finished (Ok) or the object refused (Failed): either way the
  // slot frees — a refused completion is not resumable.
  send_ack(origin, hash, total,
           status ? autonomy::ObjectAckStatus::Ok
                  : autonomy::ObjectAckStatus::Failed,
           now_ms);
}

void ConfigTarget::drop_assembly() noexcept {
  assembly_.active = false;
  assembly_.journal = nullptr;
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
  // The single slot frees at the 10 s assembly bound (same monotonic
  // clock the journals run on).
  if (assembly_.active &&
      now_ms - assembly_.started_ms >= kConfigReassemblyTimeoutMs) {
    drop_assembly();
  }
  // A journal that became impaired invalidates an in-progress NORMAL
  // permit assembly — the submit it feeds could never succeed anyway —
  // while kind-4/5 assemblies stay servable (that is their point).
  if (assembly_.active &&
      assembly_.kind == autonomy::ControlObjectKind::ConfigPermit &&
      assembly_.journal != nullptr &&
      (assembly_.journal->quarantined() || assembly_.journal->uncertain())) {
    drop_assembly();
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

Status ConfigGateway::submit_trust_status_query(
    const std::uint64_t request, const NodeId target, const NetworkId network,
    const std::array<std::uint8_t, 16>& nonce,
    const MonotonicMs now_ms) noexcept {
  if (query_.active) {
    return Status::error(StatusCode::WouldBlock, "config query busy");
  }
  if (target == kInvalidNodeId) {
    return Status::error(StatusCode::InvalidArgument, "config query target invalid");
  }
  endpoint::TrustStatusQuery query{};
  query.nonce = nonce;
  endpoint::EncodedServicePayload encoded{};
  Status status = endpoint::trust_status_query_encode(query, encoded);
  if (!status) return status;
  status = wire_.config_send(target, FrameType::Control, encoded.view(), now_ms);
  if (!status) return status;
  query_.active = true;
  query_.request = request;
  query_.target = target;
  query_.usb_sub = kSubConfigTrustStatus;
  query_.expect = QueryExpect::TrustStatus;
  query_.deadline_ms = now_ms + config_wire_const::kQueryTimeoutMs;
  query_.echo = nonce;
  query_.network = network;
  return Status::success();
}

Status ConfigGateway::submit_recovery_info_query(
    const std::uint64_t request, const NodeId target, const NetworkId network,
    const std::uint16_t config_namespace,
    const std::array<std::uint8_t, 16>& nonce,
    const MonotonicMs now_ms) noexcept {
  if (query_.active) {
    return Status::error(StatusCode::WouldBlock, "config query busy");
  }
  if (target == kInvalidNodeId ||
      !endpoint::config_namespace_valid(config_namespace)) {
    return Status::error(StatusCode::InvalidArgument, "config query target invalid");
  }
  endpoint::RecoveryInfoQuery query{};
  query.config_namespace = config_namespace;
  query.nonce = nonce;
  endpoint::EncodedServicePayload encoded{};
  Status status = endpoint::recovery_info_query_encode(query, encoded);
  if (!status) return status;
  status = wire_.config_send(target, FrameType::Control, encoded.view(), now_ms);
  if (!status) return status;
  query_.active = true;
  query_.request = request;
  query_.target = target;
  query_.usb_sub = kSubConfigRecoveryInfo;
  query_.expect = QueryExpect::RecoveryInfo;
  query_.deadline_ms = now_ms + config_wire_const::kQueryTimeoutMs;
  query_.echo = nonce;
  query_.config_namespace = config_namespace;
  query_.network = network;
  return Status::success();
}

Status ConfigGateway::submit_permit(const std::uint64_t request, const NodeId target,
                                    const ByteView permit,
                                    const MonotonicMs now_ms) noexcept {
  if (transfer_.active) {
    return Status::error(StatusCode::WouldBlock, "config permit transfer busy");
  }
  Status status;
  start_transfer(request, target, autonomy::ControlObjectKind::ConfigPermit,
                 permit, now_ms, status);
  return status;
}

Status ConfigGateway::submit_recovery(const std::uint64_t request,
                                      const NodeId target, const ByteView object,
                                      const MonotonicMs now_ms) noexcept {
  if (transfer_.active) {
    return Status::error(StatusCode::WouldBlock, "config transfer busy");
  }
  Status status;
  start_transfer(request, target,
                 autonomy::ControlObjectKind::ConfigRecovery, object, now_ms,
                 status);
  return status;
}

Status ConfigGateway::submit_trust(const std::uint64_t request,
                                   const NodeId target, const ByteView object,
                                   const MonotonicMs now_ms) noexcept {
  if (transfer_.active) {
    return Status::error(StatusCode::WouldBlock, "config transfer busy");
  }
  Status status;
  start_transfer(request, target,
                 autonomy::ControlObjectKind::TrustManifest, object, now_ms,
                 status);
  return status;
}

void ConfigGateway::start_transfer(
    const std::uint64_t request, const NodeId target,
    const autonomy::ControlObjectKind kind, const ByteView object,
    const MonotonicMs now_ms, Status& out) noexcept {
  const std::size_t cap = kind == autonomy::ControlObjectKind::TrustManifest
                              ? kConfigTrustObjectMax : kConfigPermitObjectMax;
  if (target == kInvalidNodeId || object.size == 0 || object.size > cap ||
      object.data == nullptr) {
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
  TransferSlot& transfer = transfer_;
  transfer.active = true;
  transfer.request = request;
  transfer.target = target;
  transfer.usb_sub = kind == autonomy::ControlObjectKind::ConfigPermit
                         ? kSubConfigPermit
                         : kind == autonomy::ControlObjectKind::ConfigRecovery
                               ? kSubConfigRecover
                               : kSubConfigTrust;
  transfer.hash = manifest.object_hash;
  transfer.object.size = object.size;
  std::memcpy(transfer.object.bytes.data(), object.data, object.size);
  transfer.object_size = static_cast<std::uint16_t>(object.size);
  transfer.next_offset = 0;
  transfer.phase = TransferPhase::Chunks;
  transfer.deadline_ms = now_ms + config_wire_const::kPermitTimeoutMs;
  // Push the first chunk immediately; the rest ride poll() so a full TX
  // queue slows the pump instead of dropping a chunk into a timeout.
  pump_transfer(now_ms);
  out = Status::success();
}

void ConfigGateway::pump_transfer(const MonotonicMs now_ms) noexcept {
  TransferSlot& transfer = transfer_;
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
      finish_transfer(ConfigOpsResult::Indeterminate, now_ms);
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
      } else if (query_.expect == QueryExpect::TrustStatus &&
                 subtype == kSubTrustStatus) {
        // Nonce echo + full network bind this reply.
        endpoint::TrustStatus status{};
        if (endpoint::trust_status_decode(body, status) &&
            status.nonce_echo == query_.echo &&
            status.network == query_.network) {
          finish_query(ConfigOpsResult::Ok, body, now_ms);
        }
      } else if (query_.expect == QueryExpect::RecoveryInfo &&
                 subtype == kSubRecoveryInfo) {
        // Nonce echo + namespace + full network bind this reply.
        endpoint::RecoveryInfo info{};
        if (endpoint::recovery_info_decode(body, info) &&
            info.nonce_echo == query_.echo &&
            info.config_namespace == query_.config_namespace &&
            info.network == query_.network) {
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
      // An ack binds to the active transfer's origin and object hash.
      if (transfer_.active && origin == transfer_.target &&
          ack.object_hash == transfer_.hash) {
        resolve_transfer_ack(ack, now_ms);
      }
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

void ConfigGateway::finish_transfer(const ConfigOpsResult result,
                                    const MonotonicMs now_ms) noexcept {
  const std::uint64_t request = transfer_.request;
  const NodeId target = transfer_.target;
  const std::uint8_t sub = transfer_.usb_sub;
  transfer_.active = false;
  ++replies_reported_;
  host_.on_config_reply(request, sub, result, target, ByteView{}, now_ms);
}

void ConfigGateway::resolve_transfer_ack(const autonomy::ObjectAckPayload& ack,
                                         const MonotonicMs now_ms) noexcept {
  if (ack.status == autonomy::ObjectAckStatus::Failed) {
    finish_transfer(ConfigOpsResult::Denied, now_ms);
  } else if (ack.status == autonomy::ObjectAckStatus::Ok &&
             ack.received_len >= transfer_.object_size) {
    // Assembly completed at the target — the object verdict itself is
    // a separate status query, never implied by transport success.
    finish_transfer(ConfigOpsResult::Ok, now_ms);
  }
  // Incomplete acks are progress; the deadline bounds the wait.
}

void ConfigGateway::poll(const MonotonicMs now_ms) noexcept {
  pump_transfer(now_ms);
  if (query_.active && now_ms >= query_.deadline_ms) {
    finish_query(ConfigOpsResult::Timeout, ByteView{}, now_ms);
  }
  if (transfer_.active && now_ms >= transfer_.deadline_ms) {
    finish_transfer(ConfigOpsResult::Indeterminate, now_ms);
  }
}

}  // namespace routeloom
