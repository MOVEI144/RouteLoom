// P6 revocation lifecycle, PR A: gossip/authority codecs, the kind-6 object
// exchange and the MembershipLifecycle (BootGate/Active/ApplyingRrs/
// SelfRevoked/Recovering). See sdkv1_revocation.hpp.

#include "routeloom/sdkv1_revocation.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/sdkv1_join_handshake.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

Status reject() { return Status::error(StatusCode::ProtocolError, "rrs wire rejected"); }

// Saturating deadline arithmetic: a MonotonicMs near UINT64_MAX pins the
// deadline instead of wrapping into the past.
MonotonicMs add_sat(const MonotonicMs base, const std::uint32_t delta) noexcept {
  const MonotonicMs sum = base + delta;
  return sum < base ? 0xFFFFFFFFFFFFFFFFULL : sum;
}

bool valid_node(const NodeId node) noexcept { return node != 0 && node != 0xFFFFFFFFFFFFFFFFULL; }

void hash_object(const ByteView object, autonomy::ObjectHash& out) noexcept {
  ScopeDigest digest{};
  sha256(object, digest);
  out = digest;
}

}  // namespace

// --- 1-hop gossip bodies ----------------------------------------------------------

Status state_epochs_encode(const StateEpochs& epochs,
                           std::array<std::uint8_t, kStateEpochsSize>& out) noexcept {
  out[0] = kRrsControlVersion;
  out[1] = kRrsSubStateEpochs;
  ByteWriter writer{MutableByteView{out.data() + 2, out.size() - 2}};
  Status status = writer.write_u32(epochs.site_epoch);
  if (status) status = writer.write_u32(epochs.applied_rs_epoch);
  if (status) status = writer.write_u32(epochs.gk_epoch);
  return status;
}

Status state_epochs_decode(const ByteView body, StateEpochs& out) noexcept {
  out = StateEpochs{};
  if (body.data == nullptr || body.size != kStateEpochsSize || body.data[0] != kRrsControlVersion ||
      body.data[1] != kRrsSubStateEpochs) {
    return reject();
  }
  ByteReader reader{ByteView{body.data + 2, body.size - 2}};
  Status status = reader.read_u32(out.site_epoch);
  if (status) status = reader.read_u32(out.applied_rs_epoch);
  if (status) status = reader.read_u32(out.gk_epoch);
  if (!status) out = StateEpochs{};
  return status;
}

Status rrs_request_encode(const RrsRequest& request,
                          std::array<std::uint8_t, kRrsRequestSize>& out) noexcept {
  out[0] = kRrsControlVersion;
  out[1] = kRrsSubRequest;
  ByteWriter writer{MutableByteView{out.data() + 2, out.size() - 2}};
  Status status = writer.write_u32(request.site_epoch);
  if (status) status = writer.write_u32(request.have_rs_epoch);
  return status;
}

Status rrs_request_decode(const ByteView body, RrsRequest& out) noexcept {
  out = RrsRequest{};
  if (body.data == nullptr || body.size != kRrsRequestSize || body.data[0] != kRrsControlVersion ||
      body.data[1] != kRrsSubRequest) {
    return reject();
  }
  ByteReader reader{ByteView{body.data + 2, body.size - 2}};
  Status status = reader.read_u32(out.site_epoch);
  if (status) status = reader.read_u32(out.have_rs_epoch);
  if (!status) out = RrsRequest{};
  return status;
}

// --- Authority type-5 bodies --------------------------------------------------------

namespace {
constexpr std::uint8_t kSubApplied = 1;
constexpr std::uint8_t kSubGet = 2;
constexpr std::uint8_t kSubNoticeAccepted = 3;

Status head_read(ByteReader& reader, const std::uint8_t sub) noexcept {
  std::uint8_t ver = 0, got = 0;
  std::uint16_t reserved = 0;
  Status status = reader.read_u8(ver);
  if (status) status = reader.read_u8(got);
  if (status) status = reader.read_u16(reserved);
  if (!status || ver != kRrsControlVersion || got != sub || reserved != 0) return reject();
  return Status::success();
}

void head_write(ByteWriter& writer, const std::uint8_t sub) noexcept {
  (void)writer.write_u8(kRrsControlVersion);
  (void)writer.write_u8(sub);
  (void)writer.write_u16(0);
}
}  // namespace

Status rrs_applied_encode(const RrsApplied& applied,
                          std::array<std::uint8_t, kRrsAppliedSize>& out) noexcept {
  ByteWriter writer{MutableByteView{out.data(), out.size()}};
  head_write(writer, kSubApplied);
  Status status = writer.write_u32(applied.rs_epoch);
  if (status) {
    status = writer.write_bytes(ByteView{applied.object_sha256.data(), 32});
  }
  return status;
}

Status rrs_applied_decode(const ByteView body, RrsApplied& out) noexcept {
  out = RrsApplied{};
  if (body.data == nullptr || body.size != kRrsAppliedSize) return reject();
  ByteReader reader{body};
  Status status = head_read(reader, kSubApplied);
  if (status) status = reader.read_u32(out.rs_epoch);
  for (std::size_t i = 0; status && i < 32; ++i) {
    std::uint8_t byte = 0;
    status = reader.read_u8(byte);
    out.object_sha256[i] = byte;
  }
  if (!status) out = RrsApplied{};
  return status;
}

Status rrs_get_encode(const RrsGet& get, std::array<std::uint8_t, kRrsGetSize>& out) noexcept {
  ByteWriter writer{MutableByteView{out.data(), out.size()}};
  head_write(writer, kSubGet);
  return writer.write_u32(get.wanted_rs_epoch);
}

Status rrs_get_decode(const ByteView body, RrsGet& out) noexcept {
  out = RrsGet{};
  if (body.data == nullptr || body.size != kRrsGetSize) return reject();
  ByteReader reader{body};
  Status status = head_read(reader, kSubGet);
  if (status) status = reader.read_u32(out.wanted_rs_epoch);
  if (!status) out = RrsGet{};
  return status;
}

Status rrs_notice_accepted_encode(const RrsNoticeAccepted& accepted,
                                 std::array<std::uint8_t, kRrsNoticeAcceptedSize>& out) noexcept {
  ByteWriter writer{MutableByteView{out.data(), out.size()}};
  head_write(writer, kSubNoticeAccepted);
  Status status = writer.write_u32(accepted.rs_epoch);
  if (status) {
    status = writer.write_bytes(ByteView{accepted.notice_sha256.data(), 32});
  }
  return status;
}

Status rrs_notice_accepted_decode(const ByteView body, RrsNoticeAccepted& out) noexcept {
  out = RrsNoticeAccepted{};
  if (body.data == nullptr || body.size != kRrsNoticeAcceptedSize) return reject();
  ByteReader reader{body};
  Status status = head_read(reader, kSubNoticeAccepted);
  if (status) status = reader.read_u32(out.rs_epoch);
  for (std::size_t i = 0; status && i < 32; ++i) {
    std::uint8_t byte = 0;
    status = reader.read_u8(byte);
    out.notice_sha256[i] = byte;
  }
  if (!status) out = RrsNoticeAccepted{};
  return status;
}

// --- Kind-6 object exchange ----------------------------------------------------------

RrsExchange::RrsExchange(LifecyclePeerPort& port, RrsObjectSink& sink) noexcept
    : port_(port), sink_(sink) {}

void RrsExchange::send_ack(const NodeId peer, const autonomy::ObjectHash& hash,
                           const std::uint16_t received_len,
                           const autonomy::ObjectAckStatus status) noexcept {
  autonomy::ObjectAckPayload ack{};
  ack.object_hash = hash;
  ack.received_len = received_len;
  ack.status = status;
  autonomy::EncodedPayload encoded{};
  if (!autonomy::object_ack_encode(ack, encoded)) return;
  (void)port_.peer_send(peer, FrameType::ObjectAck, encoded.view());
}

bool RrsExchange::recent_total(const NodeId peer, const std::uint32_t binding,
                               const autonomy::ObjectHash& hash,
                               std::uint16_t& total) const noexcept {
  for (const Recent& entry : recent_) {
    if (entry.used && entry.peer == peer && entry.binding == binding && entry.hash == hash) {
      total = entry.total;
      return true;
    }
  }
  return false;
}

void RrsExchange::note_delivered(const NodeId peer, const std::uint32_t binding,
                                const autonomy::ObjectHash& hash,
                                const std::uint16_t total) noexcept {
  for (Recent& entry : recent_) {
    if (entry.used && entry.peer == peer && entry.binding == binding && entry.hash == hash) {
      entry.total = total;
      return;
    }
  }
  for (Recent& entry : recent_) {
    if (!entry.used) {
      entry.peer = peer;
      entry.binding = binding;
      entry.hash = hash;
      entry.total = total;
      entry.used = true;
      return;
    }
  }
  recent_[0].peer = peer;
  recent_[0].binding = binding;
  recent_[0].hash = hash;
  recent_[0].total = total;
  recent_[0].used = true;
}

void RrsExchange::on_manifest(const NodeId peer, const std::uint32_t binding,
                              const autonomy::ControlObjectPayload& manifest,
                              const MonotonicMs now_ms) noexcept {
  if (manifest.kind != autonomy::ControlObjectKind::RevocationSet) return;
  if (manifest.total_len == 0 || manifest.total_len > kRevocationObjectMax) {
    send_ack(peer, manifest.object_hash, 0, autonomy::ObjectAckStatus::Failed);
    return;
  }
  std::uint16_t known = 0;
  if (recent_total(peer, binding, manifest.object_hash, known)) {
    // Duplicate of a completed object: re-ACK, no new work, no extension.
    send_ack(peer, manifest.object_hash, known, autonomy::ObjectAckStatus::Ok);
    return;
  }
  if (rx_.used) {
    if (rx_.peer == peer && rx_.binding == binding && rx_.hash == manifest.object_hash) {
      send_ack(peer, manifest.object_hash, rx_.received,
               autonomy::ObjectAckStatus::Incomplete);
    } else {
      // One fetch at a time: refuse honestly so the sender stops early.
      send_ack(peer, manifest.object_hash, 0, autonomy::ObjectAckStatus::Failed);
    }
    return;
  }
  rx_.used = true;
  rx_.peer = peer;
  rx_.binding = binding;
  rx_.hash = manifest.object_hash;
  rx_.total_len = manifest.total_len;
  rx_.received = 0;
  rx_.deadline_ms = add_sat(now_ms, rrs_const::kAssembleDeadlineMs);
}

void RrsExchange::on_chunk(const NodeId peer, const std::uint32_t binding,
                           const autonomy::ObjectChunkPayload& chunk,
                           const MonotonicMs now_ms) noexcept {
  std::uint16_t known = 0;
  if (!rx_.used) {
    if (recent_total(peer, binding, chunk.object_hash, known)) {
      send_ack(peer, chunk.object_hash, known, autonomy::ObjectAckStatus::Ok);
    }
    return;
  }
  if (rx_.peer != peer || rx_.binding != binding || rx_.hash != chunk.object_hash) return;
  if (now_ms >= rx_.deadline_ms) {
    send_ack(peer, rx_.hash, rx_.received, autonomy::ObjectAckStatus::Failed);
    rx_.used = false;
    ++failed_;
    return;
  }
  if (chunk.offset != rx_.received ||
      static_cast<std::uint32_t>(chunk.offset) + chunk.data_size > rx_.total_len) {
    // Duplicate/out-of-order/out-of-range: re-ACK progress, never rewind or
    // extend the deadline.
    send_ack(peer, rx_.hash, rx_.received, autonomy::ObjectAckStatus::Incomplete);
    return;
  }
  if (chunk.data_size > 0) {
    std::memcpy(rx_.data.data() + rx_.received, chunk.data.data(), chunk.data_size);
    rx_.received = static_cast<std::uint16_t>(rx_.received + chunk.data_size);
  }
  if (rx_.received == rx_.total_len) {
    complete_rx(now_ms);
  } else {
    send_ack(peer, rx_.hash, rx_.received, autonomy::ObjectAckStatus::Incomplete);
  }
}

void RrsExchange::complete_rx(const MonotonicMs now_ms) noexcept {
  autonomy::ObjectHash hash{};
  hash_object(ByteView{rx_.data.data(), rx_.total_len}, hash);
  if (hash != rx_.hash) {
    send_ack(rx_.peer, rx_.hash, rx_.received, autonomy::ObjectAckStatus::Failed);
    rx_.used = false;
    ++failed_;
    return;
  }
  // The sink copies during the call; the Owner re-feeds the bytes through
  // dispatch() on a later call — no store or publish happens in here.
  sink_.on_rrs_object(rx_.peer, ByteView{rx_.data.data(), rx_.total_len}, now_ms);
  send_ack(rx_.peer, rx_.hash, rx_.total_len, autonomy::ObjectAckStatus::Ok);
  note_delivered(rx_.peer, rx_.binding, rx_.hash, rx_.total_len);
  rx_.used = false;
  ++delivered_;
}

void RrsExchange::on_ack(const NodeId peer, const std::uint32_t binding,
                         const autonomy::ObjectAckPayload& ack,
                         const MonotonicMs now_ms) noexcept {
  if (!tx_.used || tx_.dest != peer || tx_.binding != binding || tx_.hash != ack.object_hash) {
    return;
  }
  if (ack.status == autonomy::ObjectAckStatus::Failed) {
    tx_.used = false;
    ++failed_;
    return;
  }
  if (ack.received_len > tx_.total_len) return;
  if (ack.status == autonomy::ObjectAckStatus::Ok) {
    if (ack.received_len == tx_.total_len) {
      tx_.used = false;  // transport ACK only — application ACKs are separate
    }
    return;
  }
  if (ack.status != autonomy::ObjectAckStatus::Incomplete) return;
  if (ack.received_len < tx_.sent) {
    // The peer is progressing: rewind to its frontier and retransmit from
    // the next poll. Progress never consumes an attempt.
    tx_.sent = ack.received_len;
    tx_.ack_deadline_ms = add_sat(now_ms, rrs_const::kAckTimeoutMs);
  }
}

Status RrsExchange::publish(const NodeId dest, const std::uint32_t binding, const ByteView object,
                            const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (tx_.used) {
    return Status::error(StatusCode::NoCapacity, "rrs tx busy");
  }
  if (object.data == nullptr || object.size == 0 || object.size > kRevocationObjectMax) {
    return Status::error(StatusCode::InvalidArgument, "rrs object size");
  }
  std::memcpy(tx_.data.data(), object.data, object.size);
  hash_object(object, tx_.hash);
  tx_.used = true;
  tx_.dest = dest;
  tx_.binding = binding;
  tx_.total_len = static_cast<std::uint16_t>(object.size);
  tx_.sent = 0;
  tx_.attempts = 0;
  tx_.manifest_sent = false;
  tx_.ack_deadline_ms = 0;
  return Status::success();
}

void RrsExchange::transmit_tx(const MonotonicMs now_ms) noexcept {
  if (!tx_.manifest_sent) {
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::RevocationSet;
    manifest.total_len = tx_.total_len;
    manifest.object_hash = tx_.hash;
    autonomy::EncodedPayload encoded{};
    if (!autonomy::control_object_encode(manifest, encoded)) {
      tx_.used = false;
      ++failed_;
      return;
    }
    if (!port_.peer_send(tx_.dest, FrameType::ControlObject, encoded.view())) {
      return;  // backpressure: retry next poll without spending an attempt
    }
    tx_.manifest_sent = true;
    ++tx_.attempts;
  }
  while (tx_.sent < tx_.total_len) {
    constexpr std::uint16_t kChunk =
        kMaxApplicationPayload - autonomy::kObjectChunkHeaderSize;
    static_assert(kChunk == 90, "04 §4: max chunk data is 90 B");
    std::uint16_t rest = static_cast<std::uint16_t>(tx_.total_len - tx_.sent);
    const std::uint16_t take = rest > kChunk ? kChunk : rest;
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = tx_.hash;
    chunk.offset = tx_.sent;
    std::memcpy(chunk.data.data(), tx_.data.data() + tx_.sent, take);
    chunk.data_size = take;
    autonomy::EncodedPayload encoded{};
    if (!autonomy::object_chunk_encode(chunk, encoded)) {
      tx_.used = false;
      ++failed_;
      return;
    }
    if (!port_.peer_send(tx_.dest, FrameType::ObjectChunk, encoded.view())) {
      return;  // resume at tx_.sent next poll
    }
    tx_.sent = static_cast<std::uint16_t>(tx_.sent + take);
  }
  tx_.ack_deadline_ms = add_sat(now_ms, rrs_const::kAckTimeoutMs);
}

void RrsExchange::poll(const MonotonicMs now_ms) noexcept {
  if (rx_.used && now_ms >= rx_.deadline_ms) {
    send_ack(rx_.peer, rx_.hash, rx_.received, autonomy::ObjectAckStatus::Failed);
    rx_.used = false;
    ++failed_;
  }
  if (!tx_.used) return;
  if (!tx_.manifest_sent || tx_.sent < tx_.total_len) {
    transmit_tx(now_ms);
    return;
  }
  if (now_ms >= tx_.ack_deadline_ms) {
    if (tx_.attempts >= rrs_const::kSendAttemptsMax) {
      tx_.used = false;
      ++failed_;
    } else {
      // Resend the whole round; the peer re-ACKs its frontier.
      tx_.manifest_sent = false;
      tx_.sent = 0;
    }
  }
}

bool RrsExchange::owns_transfer(const NodeId peer, const std::uint32_t binding,
                                const autonomy::ObjectHash& hash) const noexcept {
  if (rx_.used && rx_.peer == peer && rx_.binding == binding && rx_.hash == hash) return true;
  if (tx_.used && tx_.dest == peer && tx_.binding == binding && tx_.hash == hash) return true;
  std::uint16_t known = 0;
  return recent_total(peer, binding, hash, known);
}

void RrsExchange::abort() noexcept {
  rx_.used = false;
  tx_.used = false;
}

MonotonicMs RrsExchange::next_deadline() const noexcept {
  if (tx_.used && (!tx_.manifest_sent || tx_.sent < tx_.total_len)) return 0;
  MonotonicMs next = 0xFFFFFFFFFFFFFFFFULL;
  if (rx_.used) next = rx_.deadline_ms;
  if (tx_.used && tx_.manifest_sent && tx_.sent >= tx_.total_len && tx_.ack_deadline_ms < next) {
    next = tx_.ack_deadline_ms;
  }
  return next;
}

// --- Membership lifecycle ------------------------------------------------------------

namespace {
constexpr std::size_t kResumeSlotsNode = 16;
constexpr std::size_t kResumeSlotsGateway = 160;

struct CallGuard {
  explicit CallGuard(bool& flag) noexcept : flag_(flag) { flag_ = true; }
  ~CallGuard() noexcept { flag_ = false; }
  CallGuard(const CallGuard&) = delete;
  CallGuard& operator=(const CallGuard&) = delete;

 private:
  bool& flag_;
};
}  // namespace

MembershipLifecycle::MembershipLifecycle(
    const LifecycleConfig& config, IdentityStore& identity, SiteStore& site,
    RevocationStore& revocations, ResumeCache& resume, LifecyclePorts& ports,
    const Es256Verifier& verifier, LifecycleStore* journal) noexcept
    : config_(config),
      identity_(identity),
      site_(site),
      revocations_(revocations),
      resume_(resume),
      journal_(journal),
      ports_(ports),
      verifier_(verifier),
      exchange_(ports.peer, ports.object_sink) {
  refresh_snapshot();
}

Status MembershipLifecycle::dispatch(const LifecycleInput& input, const MonotonicMs now_ms) noexcept {
  // Re-entry from any port/storage/observer callback: Busy with zero state
  // change — not even counters. The Owner queues the input and retries
  // after the outer call returns.
  if (in_call_) return Status::error(StatusCode::Busy, "lifecycle re-entry");
  if (config_.self == 0 || config_.self == 0xFFFFFFFFFFFFFFFFULL) {
    return Status::error(StatusCode::InvalidState, "lifecycle self id");
  }
  const CallGuard guard(in_call_);
  if (input.tag == LifecycleInputTag::Boot) {
    last_now_ = now_ms;  // new monotonic domain; holdoff restarts below
  } else if (now_ms < last_now_) {
    saturate_inc(counters_.clock_regressions);
    if (phase_ == LifecyclePhase::Holdoff) last_now_ = now_ms;
  } else {
    last_now_ = now_ms;
  }
  Status status{};
  switch (input.tag) {
    case LifecycleInputTag::Boot:
      status = on_boot(input.payload.boot, now_ms);
      break;
    case LifecycleInputTag::Poll:
      status = on_poll(now_ms);
      break;
    case LifecycleInputTag::MemberReady:
      status = on_member_ready(input.payload.member_ready, now_ms);
      break;
    case LifecycleInputTag::VerifiedAuthorityMessage:
      status = on_authority(input.payload.authority, now_ms);
      break;
    case LifecycleInputTag::VerifiedPeerControl:
      status = on_peer_control(input.payload.peer_control, now_ms);
      break;
    case LifecycleInputTag::CompletedRrsObject:
      status = on_completed(input.payload.completed, now_ms);
      break;
    case LifecycleInputTag::LinkFailure:
      status = on_link_failure(input.payload.link_failure, now_ms);
      break;
    case LifecycleInputTag::JoinRecoveryComplete:
      status = on_recovery(input.payload.recovery, now_ms);
      break;
    case LifecycleInputTag::ActionComplete:
      status = on_action_complete(input.payload.action_complete, now_ms);
      break;
    case LifecycleInputTag::RemovalRequired:
      status = on_removal(input.payload.removal_required, now_ms);
      break;
    case LifecycleInputTag::Stop:
      status = on_stop(now_ms);
      break;
  }
  refresh_snapshot();
  return status;
}

Status MembershipLifecycle::take_action(LifecycleAction& action) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "lifecycle re-entry");
  action = LifecycleAction{};
  if (!action_pending_) return Status::error(StatusCode::NotFound, "no lifecycle action");
  action = action_;
  return Status::success();
}

LifecycleSnapshot MembershipLifecycle::snapshot() const noexcept { return snapshot_; }

bool MembershipLifecycle::permits(const PeerCredentialStamp& stamp,
                                 const TrafficUse use) const noexcept {
  if (!valid_node(stamp.peer) || stamp.role == 0 || stamp.assignment_generation == 0) return false;
  if (!adopted_.site_ok || stamp.network != adopted_.network) return false;
  // Recovery-control-only establishment while the membership binding is
  // healthy: BootGate (boot recovery fetch), Active, ApplyingRrs and
  // Recovering. Never for a certainly self-revoked device, a blocked
  // store, or a stopped lifecycle — those need the zero-touch proof or
  // maintenance, not a peer shortcut.
  if (use == TrafficUse::RecoveryControl) {
    if (self_revoked_ || self_rejected()) return false;
    if (adopted_.has_rrs && revocations_.set().network == adopted_.network &&
        revocation_rejects(revocations_.set(), stamp.peer, stamp.assignment_generation,
                           site_epoch())) return false;
    if (phase_ == LifecyclePhase::ApplyingRrs && apply_step_ != ApplyStep::Verify &&
        candidate_set_.network == adopted_.network &&
        (revocation_rejects(candidate_set_, config_.self, adopted_.generation, site_epoch()) ||
         revocation_rejects(candidate_set_, stamp.peer, stamp.assignment_generation,
                            site_epoch()))) return false;
    return phase_ == LifecyclePhase::BootGate || phase_ == LifecyclePhase::Active ||
           phase_ == LifecyclePhase::ApplyingRrs || phase_ == LifecyclePhase::Recovering;
  }
  if ((phase_ != LifecyclePhase::Active && phase_ != LifecyclePhase::Prepared) ||
      equivocated_ || !adopted_.has_rrs ||
      adopted_.rs_epoch < adopted_.rs_floor ||
      revocations_.set().network != adopted_.network ||
      revocations_.set().site_id != adopted_.site_id) return false;
  return !revocation_rejects(revocations_.set(), stamp.peer, stamp.assignment_generation,
                             site_epoch());
}

bool MembershipLifecycle::quiescent() const noexcept {
  if (in_call_) return false;
  return !action_pending_ && !exchange_.busy() && !fetch_outstanding_ && !need_rrs() &&
         !pending_ack_ && phase_ != LifecyclePhase::ApplyingRrs;
}

MonotonicMs MembershipLifecycle::next_deadline() const noexcept {
  MonotonicMs next = 0xFFFFFFFFFFFFFFFFULL;
  if (phase_ == LifecyclePhase::ApplyingRrs || phase_ == LifecyclePhase::Removing) return 0;
  if (phase_ == LifecyclePhase::Holdoff) {
    return holdoff_start_ <= 0xFFFFFFFFFFFFFFFFULL - 600000
               ? holdoff_start_ + 600000 : 0xFFFFFFFFFFFFFFFFULL;
  }
  if (need_rrs() && next_get_allowed_ < next) next = next_get_allowed_;
  if (pending_ack_ && pending_ack_due_ < next) next = pending_ack_due_;
  if (fetch_outstanding_ && fetch_deadline_ < next) next = fetch_deadline_;
  if (phase_ == LifecyclePhase::Active) {
    for (const Neighbor& neighbor : neighbors_) {
      if (neighbor.used && neighbor.notify_due < next) next = neighbor.notify_due;
    }
  }
  const MonotonicMs exchange_due = exchange_.next_deadline();
  if (exchange_due < next) next = exchange_due;
  return next;
}

bool MembershipLifecycle::need_rrs() const noexcept {
  if (!adopted_.site_ok) return false;
  if (phase_ != LifecyclePhase::BootGate && phase_ != LifecyclePhase::Active &&
      phase_ != LifecyclePhase::Prepared && phase_ != LifecyclePhase::Recovering) {
    return false;
  }
  if (!adopted_.has_rrs || revocations_.set().network != adopted_.network ||
      revocations_.set().site_id != adopted_.site_id ||
      adopted_.rs_epoch < adopted_.rs_floor ||
      adopted_.rs_epoch < rs_to_fetch_ || equivocated_) {
    return true;
  }
  return false;
}

void MembershipLifecycle::notify(const LifecycleEventKind kind, const NodeId peer,
                                 const std::uint32_t epoch, const std::uint32_t detail,
                                 const MonotonicMs now_ms) noexcept {
  if (ports_.observer == nullptr) return;
  const LifecycleEvent event{kind, peer, epoch, detail};
  ports_.observer->on_lifecycle_event(event, now_ms);
}

bool MembershipLifecycle::bump_policy() noexcept {
  if (policy_revision_ == 0xFFFFFFFFFFFFFFFFULL) return false;
  ++policy_revision_;
  return true;
}

void MembershipLifecycle::refresh_snapshot() noexcept {
  snapshot_.phase = phase_;
  snapshot_.adopted_network = adopted_.site_ok ? adopted_.network : 0;
  snapshot_.site_commit_seq = adopted_.site_commit_seq;
  snapshot_.own_generation = adopted_.generation;
  snapshot_.applied_rs_epoch = adopted_.rs_epoch;
  snapshot_.applied_gk_epoch = adopted_.gk_epoch;
  snapshot_.rs_epoch_to_fetch =
      rs_to_fetch_ > adopted_.rs_epoch ? rs_to_fetch_ : 0;
  snapshot_.policy_revision = policy_revision_;
  snapshot_.stores_healthy = adopted_.identity_ok && adopted_.site_ok;
  snapshot_.action_pending = action_pending_;
  snapshot_.equivocated = equivocated_;
  snapshot_.rrs_applied = counters_.rrs_applied;
  snapshot_.rrs_duplicates = counters_.rrs_duplicates;
  snapshot_.rrs_stale = counters_.rrs_stale;
  snapshot_.rrs_failed = counters_.rrs_failed;
  snapshot_.equivocations = counters_.equivocations;
  snapshot_.gossip_state_sent = counters_.gossip_state_sent;
  snapshot_.gossip_requests_sent = counters_.gossip_requests_sent;
  snapshot_.gossip_dropped = counters_.gossip_dropped;
  snapshot_.fetches_started = counters_.fetches_started;
  snapshot_.fetches_done = counters_.fetches_done;
  snapshot_.fetch_failures = counters_.fetch_failures;
  snapshot_.authority_gets_sent = counters_.authority_gets_sent;
  snapshot_.authority_acks_sent = counters_.authority_acks_sent;
  snapshot_.recoveries = counters_.recoveries;
  snapshot_.clock_regressions = counters_.clock_regressions;
  snapshot_.holdoff_remaining_ms = 0;
  if (phase_ == LifecyclePhase::Holdoff) {
    const MonotonicMs elapsed = last_now_ >= holdoff_start_ ? last_now_ - holdoff_start_ : 0;
    snapshot_.holdoff_remaining_ms = elapsed < 600000 ? 600000 - elapsed : 0;
  }
}

LifecycleBlockReason MembershipLifecycle::adopt_stores() noexcept {
  adopted_ = Adopted{};
  sak_valid_ = false;
  if (!identity_.has_identity() || identity_.quarantined() || identity_.uncertain() ||
      identity_.identity().node_id != config_.self) {
    return LifecycleBlockReason::Identity;
  }
  adopted_.identity_ok = true;
  // The P6 profile pins the 05 §3.2 fixed RLP1 geometry (16 node slots,
  // 160 gateway slots); anything else is a provisioning mismatch the
  // sweep cursors must not silently accept.
  const std::size_t resume_slots = resume_.slot_count();
  const std::size_t want_slots =
      config_.profile == LifecycleProfile::Gateway ? kResumeSlotsGateway : kResumeSlotsNode;
  if (resume_slots != want_slots) return LifecycleBlockReason::ResumeGeometry;
  if (!site_.has_site() || site_.quarantined() || site_.uncertain()) {
    return LifecycleBlockReason::Site;
  }
  const SiteRecord& site = site_.site();
  const IdentityRecord& identity = identity_.identity();
  if (!site_matches_identity(site, identity)) return LifecycleBlockReason::Site;
  CertClaims claims{};
  bool verified = false;
  const Status chain = identity_verify_site_cert(identity, site.site_cert.view(), claims, verified,
                                                 verifier_);
  if (!chain || !verified) return LifecycleBlockReason::Site;
  if (static_cast<std::uint32_t>(site.network >> 32U) != claims.site_epoch) {
    return LifecycleBlockReason::Site;
  }
  sak_ = claims.pubkey;
  sak_valid_ = true;
  adopted_.site_ok = true;
  adopted_.site_id = site.site_id;
  adopted_.network = site.network;
  adopted_.generation = site.assignment_generation;
  adopted_.site_commit_seq = site_.commit_seq();
  adopted_.rs_floor = site.rs_epoch_floor;
  adopted_.gk_epoch = site.gk_epoch_current;
  if (revocations_.quarantined() || revocations_.uncertain()) {
    return LifecycleBlockReason::RevocationStore;
  }
  if (revocations_.has_set()) {
    stored_object_.clear();
    if (!revocations_.load_object(stored_object_)) return LifecycleBlockReason::RevocationStore;
    verified_store_set_ = RevocationSet{};
    bool verified = false;
    const Status checked = revocation_object_verify(stored_object_.view(), sak_, adopted_.site_id,
                                                     revocations_.set().network, verified_store_set_,
                                                     verified, verifier_);
    if (!checked || !verified ||
        verified_store_set_.rs_epoch != revocations_.rs_epoch() ||
        verified_store_set_.site_epoch_floor != revocations_.set().site_epoch_floor ||
        verified_store_set_.count != revocations_.set().count) {
      return LifecycleBlockReason::RevocationStore;
    }
    for (std::uint8_t i = 0; i < verified_store_set_.count; ++i) {
      const RevocationEntry& verified_entry = verified_store_set_.entries[i];
      const RevocationEntry& stored_entry = revocations_.set().entries[i];
      if (verified_entry.node_id != stored_entry.node_id ||
          verified_entry.min_generation != stored_entry.min_generation ||
          verified_entry.reason != stored_entry.reason) {
        return LifecycleBlockReason::RevocationStore;
      }
    }
    adopted_.has_rrs = true;
    adopted_.rs_epoch = revocations_.rs_epoch();
  }
  if (!bump_policy()) {
    adopted_ = Adopted{};
    sak_valid_ = false;
    return LifecycleBlockReason::PolicyExhausted;
  }
  return LifecycleBlockReason::None;
}

Status MembershipLifecycle::adopt_and_enter(const MonotonicMs now_ms) noexcept {
  const LifecycleBlockReason blocked = adopt_stores();
  if (blocked != LifecycleBlockReason::None) {
    enter_storage_blocked(blocked, now_ms);
    return Status::success();
  }
  if (!adopted_.has_rrs || adopted_.rs_epoch < adopted_.rs_floor ||
      revocations_.set().network != adopted_.network) {
    // No set, a set behind the floor, or a set for another network: stay
    // closed in BootGate; the Poll loop fetches a fresh set from the
    // authority (gossip may also supply it).
    phase_ = LifecyclePhase::BootGate;
    return Status::success();
  }
  if (adopted_.rs_epoch > adopted_.rs_floor) {
    // The set runs ahead of the floor (an interrupted earlier apply): run
    // the enforcement again and catch the floor up before opening.
    stored_object_.clear();
    if (!revocations_.load_object(stored_object_)) {
      enter_storage_blocked(LifecycleBlockReason::RevocationStore, now_ms);
      return Status::success();
    }
    return begin_apply(stored_object_.view(), CandidateSource::Stored, 0, now_ms);
  }
  if (self_rejected()) {
    phase_ = LifecyclePhase::SelfRevoked;
    self_revoked_ = true;
    emit_action(LifecycleActionTag::RecoveryRequired, LifecycleActionReason::SelfRevocation);
    notify(LifecycleEventKind::SelfRevoked, config_.self, adopted_.rs_epoch, 0, now_ms);
    return Status::success();
  }
  phase_ = LifecyclePhase::Active;
  return Status::success();
}

bool MembershipLifecycle::self_rejected() const noexcept {
  if (!adopted_.site_ok || !adopted_.has_rrs) return false;
  return revocation_rejects(revocations_.set(), config_.self, adopted_.generation, site_epoch());
}

Status MembershipLifecycle::begin_apply(const ByteView object, const CandidateSource source,
                                        const NodeId peer, const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!adopted_.site_ok || !sak_valid_) return Status::success();  // nothing to verify against
  if (object.data == nullptr || object.size == 0 || object.size > kRevocationObjectMax) {
    return Status::error(StatusCode::InvalidArgument, "rrs candidate size");
  }
  if (phase_ == LifecyclePhase::ApplyingRrs) {
    // One reception at a time, no overwrite: the sender's retry covers it.
    saturate_inc(counters_.gossip_dropped);
    return Status::error(StatusCode::NoCapacity, "rrs apply busy");
  }
  std::memcpy(candidate_object_.bytes.data(), object.data, object.size);
  candidate_object_.size = object.size;
  candidate_set_ = RevocationSet{};
  candidate_source_ = source;
  candidate_peer_ = peer;
  apply_step_ = ApplyStep::Verify;
  sweep_cursor_ = 0;
  sweep_attempts_ = 0;
  resume_phase_ = phase_;  // RRS cleanup must not discard a staged grant.
  phase_ = LifecyclePhase::ApplyingRrs;
  return Status::success();
}

void MembershipLifecycle::abort_apply(const LifecyclePhase resume) noexcept {
  secure_clear(candidate_object_.bytes.data(), candidate_object_.bytes.size());
  candidate_object_.clear();
  candidate_set_ = RevocationSet{};
  candidate_source_ = CandidateSource::None;
  candidate_peer_ = kInvalidNodeId;
  phase_ = resume;
}

void MembershipLifecycle::clear_fetch(const bool failed, const MonotonicMs now_ms) noexcept {
  if (!fetch_outstanding_) return;
  if (failed) {
    saturate_inc(counters_.fetch_failures);
    notify(LifecycleEventKind::GossipStalled, fetch_peer_, fetch_wanted_, 0, now_ms);
  } else {
    saturate_inc(counters_.fetches_done);
  }
  fetch_outstanding_ = false;
  fetch_peer_ = kInvalidNodeId;
  fetch_wanted_ = 0;
}

Status MembershipLifecycle::apply_poll(const MonotonicMs now_ms) noexcept {
  switch (apply_step_) {
    case ApplyStep::Verify:
      return apply_verify(now_ms);
    case ApplyStep::Store:
      return apply_store(now_ms);
    case ApplyStep::Enforce:
      return apply_enforce(now_ms);
    case ApplyStep::Sweep:
      return apply_sweep(now_ms);
    case ApplyStep::Floor:
      return apply_floor(now_ms);
    case ApplyStep::Done:
      return apply_done(now_ms);
  }
  return Status::error(StatusCode::InternalError, "apply step");
}

Status MembershipLifecycle::apply_verify(const MonotonicMs now_ms) noexcept {
  candidate_set_ = RevocationSet{};
  bool verified = false;
  const Status checked = revocation_object_verify(candidate_object_.view(), sak_,
                                                  adopted_.site_id, adopted_.network,
                                                  candidate_set_, verified, verifier_);
  if (!checked || !verified) {
    // A stored set that no longer verifies is not recoverable by refetch
    // (it claims to be ours already): maintenance must take over.
    if (candidate_source_ == CandidateSource::Stored) {
      enter_storage_blocked(LifecycleBlockReason::RevocationStore, now_ms);
      return Status::success();
    }
    saturate_inc(counters_.rrs_failed);
    notify(LifecycleEventKind::RrsRejected, candidate_peer_, 0,
           static_cast<std::uint32_t>(checked.code), now_ms);
    if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
    abort_apply(resume_phase_);
    return Status::success();
  }
  if (candidate_source_ == CandidateSource::Stored) {
    // The set is already adopted (boot catch-up): re-run the enforcement
    // and the floor commit without re-storing it.
    apply_step_ = ApplyStep::Enforce;
    return Status::success();
  }
  const std::uint32_t epoch = candidate_set_.rs_epoch;
  if (candidate_set_.network != adopted_.network) {
    saturate_inc(counters_.rrs_stale);
    if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
    abort_apply(resume_phase_);
    return Status::success();
  }
  if (adopted_.has_rrs && epoch == adopted_.rs_epoch) {
    stored_object_.clear();
    Status loaded = revocations_.load_object(stored_object_);
    if (!loaded) {
      // A read error proves nothing about the bytes: take a fresh view
      // and compare once more before crying equivocation.
      (void)revocations_.initialize();
      stored_object_.clear();
      loaded = revocations_.load_object(stored_object_);
    }
    if (!loaded) {
      enter_storage_blocked(LifecycleBlockReason::RevocationStore, now_ms);
      return Status::success();
    }
    if (stored_object_.size == candidate_object_.size &&
        std::memcmp(stored_object_.bytes.data(), candidate_object_.bytes.data(),
                    candidate_object_.size) == 0) {
      // Idempotent duplicate: no write, no timer extension; the ACK may be
      // re-sent so a retried sender converges.
      saturate_inc(counters_.rrs_duplicates);
      if (candidate_source_ == CandidateSource::Gossip) clear_fetch(false, now_ms);
      autonomy::ObjectHash hash{};
      hash_object(stored_object_.view(), hash);
      queue_applied_ack(epoch, hash, now_ms);
      for (Neighbor& neighbor : neighbors_) {
        if (neighbor.used) neighbor.notify_due = 0;
      }
      abort_apply(resume_phase_);
      return Status::success();
    }
    // Same epoch, different validly-signed bytes: close the gate and let
    // the authority break the tie. The gossip copy is never adopted.
    equivocated_ = true;
    if (!bump_policy()) {
      enter_storage_blocked(LifecycleBlockReason::PolicyExhausted, now_ms);
      return Status::success();
    }
    saturate_inc(counters_.equivocations);
    notify(LifecycleEventKind::RrsRejected, candidate_peer_, epoch,
           static_cast<std::uint32_t>(StatusCode::Conflict), now_ms);
    if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
    abort_apply(resume_phase_);
    return Status::success();
  }
  const bool stale = adopted_.has_rrs
                         ? (epoch < adopted_.rs_epoch || epoch <= adopted_.rs_floor)
                         : (epoch < adopted_.rs_floor);
  if (stale) {
    // Older than adopted, or still below the RLS1 floor: ignore and keep
    // asking the authority for the current set. (With no set adopted, a
    // candidate equal to the floor is the bootstrap set — adopt it.)
    saturate_inc(counters_.rrs_stale);
    if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
    abort_apply(resume_phase_);
    return Status::success();
  }
  apply_step_ = ApplyStep::Store;
  return Status::success();
}

Status MembershipLifecycle::apply_store(const MonotonicMs now_ms) noexcept {
  // Close the admission barrier before the durable write; the barrier only
  // re-opens through the Done step or a fresh adoption.
  if (!bump_policy()) {
    enter_storage_blocked(LifecycleBlockReason::PolicyExhausted, now_ms);
    return Status::success();
  }
  const Status stored = revocations_.accept(candidate_object_.view(), sak_, adopted_.site_id,
                                            adopted_.network, verifier_);
  if (!stored) {
    if (stored.code == StatusCode::Conflict &&
        revocations_.has_set() && revocations_.rs_epoch() >= candidate_set_.rs_epoch) {
      // A changed store needs fresh adoption and enforcement before any
      // ACK; its epoch alone does not prove this candidate was applied.
      enter_storage_blocked(LifecycleBlockReason::RevocationStore, now_ms);
      return Status::success();
    }
    if (stored.code == StatusCode::Conflict) {
      // Newer epoch but dropped/weakened history: the Host must compress
      // through a verified cutover, not a plain replacement.
      saturate_inc(counters_.rrs_failed);
      notify(LifecycleEventKind::RrsRejected, candidate_peer_, candidate_set_.rs_epoch,
             static_cast<std::uint32_t>(StatusCode::Conflict), now_ms);
      if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
      abort_apply(resume_phase_);
      return Status::success();
    }
    // A failed write proves nothing either way: take a fresh view. If the
    // set landed despite the error, enforcement still runs; otherwise the
    // barrier stays closed in StorageBlocked until a reboot re-runs us.
    (void)revocations_.initialize();
    stored_object_.clear();
    if (revocations_.has_set() && revocations_.rs_epoch() == candidate_set_.rs_epoch &&
        revocations_.load_object(stored_object_) &&
        stored_object_.size == candidate_object_.size &&
        std::memcmp(stored_object_.bytes.data(), candidate_object_.bytes.data(),
                    candidate_object_.size) == 0) {
      adopted_.has_rrs = true;
      adopted_.rs_epoch = candidate_set_.rs_epoch;
      apply_step_ = ApplyStep::Enforce;
      return Status::success();
    }
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return Status::success();
  }
  adopted_.has_rrs = true;
  adopted_.rs_epoch = candidate_set_.rs_epoch;
  apply_step_ = ApplyStep::Enforce;
  return Status::success();
}

Status MembershipLifecycle::apply_enforce(const MonotonicMs now_ms) noexcept {
  // The runtime enforcement (§6.2 contexts/handshakes/routes/Discovery/
  // queue/group/RTC) runs through the single side-effecting adapter after
  // the RRS1 commit and before the resume sweep; a refusal retries next
  // Poll with the barrier closed.
  const Status enforced =
      ports_.runtime.enforce_revocation(revocations_.set(), site_epoch(), now_ms);
  if (!enforced) return Status::success();
  apply_step_ = ApplyStep::Sweep;
  sweep_cursor_ = 0;
  sweep_attempts_ = 0;
  return Status::success();
}

Status MembershipLifecycle::apply_sweep(const MonotonicMs now_ms) noexcept {
  ResumeContext context{};
  context.network = adopted_.network;
  context.gk_epoch = adopted_.gk_epoch;
  context.revocations = &revocations_.set();
  bool done = false;
  const Status swept = resume_.sweep_revoked(context, sweep_cursor_, done);
  if (!swept) {
    // The cursor did not move: retry next Poll, then park in
    // StorageBlocked — lookups stay guarded by the RRS predicate either
    // way, so a half-swept cache cannot mint a revoked context.
    ++sweep_attempts_;
    if (sweep_attempts_ >= rrs_const::kSweepAttemptsMax) {
      enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    }
    return Status::success();
  }
  sweep_attempts_ = 0;
  if (done) apply_step_ = ApplyStep::Floor;
  return Status::success();
}

Status MembershipLifecycle::apply_floor(const MonotonicMs now_ms) noexcept {
  // The floor commits last, after the set and its enforcement are durable
  // — never before. A moved RLS1 (P5/GK write) re-adopts first so an old
  // copy never wipes a newer floor.
  if (site_.commit_seq() != adopted_.site_commit_seq) {
    const LifecycleBlockReason blocked = adopt_stores();
    if (blocked != LifecycleBlockReason::None) {
      enter_storage_blocked(blocked, now_ms);
      return Status::success();
    }
  }
  if (adopted_.network != candidate_set_.network ||
      adopted_.rs_floor > candidate_set_.rs_epoch) {
    if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
    abort_apply(LifecyclePhase::BootGate);
    return Status::success();
  }
  const Status raised = site_.raise_rs_floor(candidate_set_.rs_epoch);
  if (!raised && raised.code != StatusCode::Conflict) {
    // A failed write has an unknown result: re-read before deciding whether
    // the floor is durable. Done rechecks the binding and exact epoch.
    (void)site_.initialize();
    if (!site_.has_site() || site_.site().rs_epoch_floor < candidate_set_.rs_epoch) {
      enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
      return Status::success();
    }
  }
  adopted_.rs_floor = site_.site().rs_epoch_floor;
  adopted_.site_commit_seq = site_.commit_seq();
  apply_step_ = ApplyStep::Done;
  return Status::success();
}

Status MembershipLifecycle::apply_done(const MonotonicMs now_ms) noexcept {
  if (!revocations_.has_set() || revocations_.rs_epoch() != candidate_set_.rs_epoch ||
      !site_.has_site() || site_.site().network != candidate_set_.network ||
      site_.site().rs_epoch_floor != candidate_set_.rs_epoch) {
    if (candidate_source_ == CandidateSource::Gossip) clear_fetch(true, now_ms);
    abort_apply(LifecyclePhase::BootGate);
    return adopt_and_enter(now_ms);
  }
  saturate_inc(counters_.rrs_applied);
  notify(LifecycleEventKind::RrsApplied, candidate_peer_, candidate_set_.rs_epoch, 0, now_ms);
  if (candidate_source_ == CandidateSource::Gossip) clear_fetch(false, now_ms);
  // New set applied: advertise promptly (the rate gate paces the burst)
  // and report to the authority; a refused ACK port retries next Poll.
  for (Neighbor& neighbor : neighbors_) {
    if (neighbor.used) neighbor.notify_due = 0;
  }
  autonomy::ObjectHash hash{};
  hash_object(candidate_object_.view(), hash);
  queue_applied_ack(candidate_set_.rs_epoch, hash, now_ms);
  const LifecyclePhase resume = resume_phase_;
  abort_apply(resume);
  if (self_rejected()) {
    phase_ = LifecyclePhase::SelfRevoked;
    self_revoked_ = true;
    emit_action(LifecycleActionTag::RecoveryRequired, LifecycleActionReason::SelfRevocation);
    notify(LifecycleEventKind::SelfRevoked, config_.self, adopted_.rs_epoch, 0, now_ms);
    return Status::success();
  }
  phase_ = (resume == LifecyclePhase::BootGate) ? LifecyclePhase::Active : resume;
  if (phase_ == LifecyclePhase::Active && journal_ && journal_->has_record() &&
      journal_->record().mode == LifecycleMode::Prepared)
    phase_ = LifecyclePhase::Prepared;
  return Status::success();
}

void MembershipLifecycle::queue_applied_ack(const std::uint32_t rs_epoch,
                                            const autonomy::ObjectHash& hash,
                                            const MonotonicMs now_ms) noexcept {
  pending_ack_ = true;
  pending_ack_epoch_ = rs_epoch;
  pending_ack_hash_ = hash;
  pending_ack_due_ = 0;
  send_pending_ack(now_ms);
}

void MembershipLifecycle::send_pending_ack(const MonotonicMs now_ms) noexcept {
  if (!pending_ack_) return;
  RrsApplied applied{};
  applied.rs_epoch = pending_ack_epoch_;
  applied.object_sha256 = pending_ack_hash_;
  std::array<std::uint8_t, kRrsAppliedSize> body{};
  if (!rrs_applied_encode(applied, body)) return;
  if (!ports_.authority.authority_send(kAuthorityTypeRevocation,
                                       ByteView{body.data(), body.size()})) {
    pending_ack_due_ = add_sat(now_ms, rrs_const::kGossipControlGapMs);
    return;
  }
  pending_ack_ = false;
  saturate_inc(counters_.authority_acks_sent);
}

void MembershipLifecycle::send_authority_get(const MonotonicMs now_ms) noexcept {
  RrsGet get{};  // wanted = 0: the authority's latest set
  std::array<std::uint8_t, kRrsGetSize> body{};
  if (!rrs_get_encode(get, body)) return;
  if (!ports_.authority.authority_send(kAuthorityTypeRevocation,
                                       ByteView{body.data(), body.size()})) {
    next_get_allowed_ = add_sat(now_ms, rrs_const::kAuthorityGetRetryMs);
    return;
  }
  next_get_allowed_ = add_sat(now_ms, rrs_const::kAuthorityGetCooldownMs);
  saturate_inc(counters_.authority_gets_sent);
}

void MembershipLifecycle::send_state_epochs(Neighbor& neighbor, const MonotonicMs now_ms) noexcept {
  StateEpochs epochs{};
  epochs.site_epoch = site_epoch();
  epochs.applied_rs_epoch = adopted_.rs_epoch;
  epochs.gk_epoch = adopted_.gk_epoch;
  std::array<std::uint8_t, kStateEpochsSize> body{};
  if (!state_epochs_encode(epochs, body)) return;
  if (!ports_.peer.peer_send(neighbor.node, FrameType::Control,
                             ByteView{body.data(), body.size()})) {
    next_gossip_allowed_ = add_sat(now_ms, rrs_const::kGossipControlGapMs);
    saturate_inc(counters_.gossip_dropped);
    return;
  }
  next_gossip_allowed_ = add_sat(now_ms, rrs_const::kGossipControlGapMs);
  saturate_inc(counters_.gossip_state_sent);
  // Idle refresh 5 s + 0..1 s jitter; a dead entropy source still sends
  // (jitter 0) rather than wedging the gossip lane.
  std::uint32_t jitter = 0;
  std::uint8_t raw[2] = {0, 0};
  if (ports_.entropy.fill(MutableByteView{raw, sizeof(raw)})) {
    jitter = (static_cast<std::uint32_t>(raw[0]) << 8U | raw[1]) %
             (rrs_const::kGossipJitterMs + 1U);
  }
  neighbor.notify_due = add_sat(add_sat(now_ms, rrs_const::kGossipRefreshMs), jitter);
}

void MembershipLifecycle::send_request(Neighbor& neighbor, const MonotonicMs now_ms) noexcept {
  if (!gossip_tx_enabled()) return;  // receive/apply only: fetch via Get
  RrsRequest request{};
  request.site_epoch = site_epoch();
  request.have_rs_epoch = adopted_.has_rrs ? adopted_.rs_epoch : adopted_.rs_floor;
  std::array<std::uint8_t, kRrsRequestSize> body{};
  if (!rrs_request_encode(request, body)) return;
  if (!ports_.peer.peer_send(neighbor.node, FrameType::Control,
                             ByteView{body.data(), body.size()})) {
    next_gossip_allowed_ = add_sat(now_ms, rrs_const::kGossipControlGapMs);
    saturate_inc(counters_.gossip_dropped);
    return;
  }
  next_gossip_allowed_ = add_sat(now_ms, rrs_const::kGossipControlGapMs);
  // The 60 s rate starts on the send, and survives rebinds (the deadline
  // is per table entry, not per binding incarnation).
  neighbor.request_not_before = add_sat(now_ms, rrs_const::kRequestCooldownMs);
  fetch_outstanding_ = true;
  fetch_peer_ = neighbor.node;
  fetch_wanted_ = neighbor.advertised_rs;
  fetch_deadline_ = add_sat(now_ms, rrs_const::kFetchWindowMs);
  saturate_inc(counters_.gossip_requests_sent);
  saturate_inc(counters_.fetches_started);
}

void MembershipLifecycle::observe_epochs(const NodeId peer, const std::uint32_t binding,
                                         const StateEpochs& epochs,
                                         const MonotonicMs now_ms) noexcept {
  if (epochs.site_epoch != site_epoch()) return;
  Neighbor* found = nullptr;
  for (Neighbor& neighbor : neighbors_) {
    if (neighbor.used && neighbor.node == peer) {
      found = &neighbor;
      break;
    }
  }
  if (found == nullptr) {
    for (Neighbor& neighbor : neighbors_) {
      if (!neighbor.used) {
        found = &neighbor;
        *found = Neighbor{};
        found->used = true;
        found->node = peer;
        break;
      }
    }
  }
  if (found == nullptr) {
    // Table full: refuse the new work, never evict live rate history.
    saturate_inc(counters_.gossip_dropped);
    return;
  }
  found->binding = binding;
  found->advertised_rs = epochs.applied_rs_epoch;
  found->advertised_gk = epochs.gk_epoch;
  const std::uint32_t have = adopted_.has_rrs ? adopted_.rs_epoch : adopted_.rs_floor;
  if (epochs.applied_rs_epoch > have && !fetch_outstanding_ &&
      now_ms >= found->request_not_before) {
    send_request(*found, now_ms);
  } else if (epochs.applied_rs_epoch < have && phase_ == LifecyclePhase::Active) {
    // A lagging peer: advertise promptly so it can pull from us.
    found->notify_due = 0;
  }
}

void MembershipLifecycle::on_request(const NodeId peer, const std::uint32_t binding,
                                     const RrsRequest& request,
                                     const MonotonicMs now_ms) noexcept {
  if (!gossip_tx_enabled()) return;
  if (request.site_epoch != site_epoch() || !adopted_.has_rrs) return;
  Neighbor* found = nullptr;
  for (Neighbor& neighbor : neighbors_) {
    if (neighbor.used && neighbor.node == peer) {
      found = &neighbor;
      break;
    }
  }
  if (found == nullptr) {
    for (Neighbor& neighbor : neighbors_) {
      if (!neighbor.used) {
        found = &neighbor;
        *found = Neighbor{};
        found->used = true;
        found->node = peer;
        break;
      }
    }
  }
  if (found == nullptr) {
    saturate_inc(counters_.gossip_dropped);
    return;
  }
  found->binding = binding;
  found->advertised_rs = request.have_rs_epoch;
  if (request.have_rs_epoch >= adopted_.rs_epoch) return;  // nothing newer to serve
  stored_object_.clear();
  if (!revocations_.load_object(stored_object_)) {
    // Serving is best-effort gossip: drop, never block on a read error.
    saturate_inc(counters_.gossip_dropped);
    return;
  }
  if (!exchange_.publish(peer, binding, stored_object_.view(), now_ms)) {
    saturate_inc(counters_.gossip_dropped);  // TX busy: the peer retries
  }
}

void MembershipLifecycle::gossip_poll(const MonotonicMs now_ms) noexcept {
  if (phase_ != LifecyclePhase::Active) return;
  if (!gossip_tx_enabled()) return;
  if (now_ms < next_gossip_allowed_) return;
  // At most one peer per Poll, round-robin from the cursor for fairness.
  for (std::size_t step = 0; step < neighbors_.size(); ++step) {
    const std::size_t index = (gossip_cursor_ + step) % neighbors_.size();
    Neighbor& neighbor = neighbors_[index];
    if (neighbor.used && now_ms >= neighbor.notify_due) {
      gossip_cursor_ = (index + 1) % neighbors_.size();
      send_state_epochs(neighbor, now_ms);
      return;
    }
  }
}

void MembershipLifecycle::enter_recovering(const LifecycleActionReason reason,
                                           const MonotonicMs now_ms) noexcept {
  phase_ = LifecyclePhase::Recovering;
  emit_action(LifecycleActionTag::RecoveryRequired, reason);
  notify(LifecycleEventKind::RecoveryStarted, 0, adopted_.rs_epoch,
         static_cast<std::uint32_t>(reason), now_ms);
}

void MembershipLifecycle::enter_storage_blocked(const LifecycleBlockReason reason,
                                                const MonotonicMs now_ms) noexcept {
  abort_apply(LifecyclePhase::StorageBlocked);
  fetch_outstanding_ = false;
  pending_ack_ = false;
  equivocated_ = false;
  notify(LifecycleEventKind::StorageBlocked, 0, adopted_.rs_epoch,
         static_cast<std::uint32_t>(reason), now_ms);
}

void MembershipLifecycle::emit_action(const LifecycleActionTag tag,
                                      const LifecycleActionReason reason) noexcept {
  if (action_pending_) return;  // one slot: an untaken action blocks the next
  LifecycleAction action{};
  action.tag = tag;
  action.token = next_token_;
  if (next_token_ == 0xFFFFFFFFFFFFFFFFULL) {
    next_token_ = 1;  // 2^64 wraps are unreachable; tokens stay nonzero
  } else {
    ++next_token_;
    if (next_token_ == 0) next_token_ = 1;
  }
  action.expected_site_commit_seq = adopted_.site_commit_seq;
  action.site_id = adopted_.site_id;
  action.network = adopted_.network;
  action.reason = reason;
  action_ = action;
  action_pending_ = true;
}

Status MembershipLifecycle::on_boot(const LifecycleBootEvidence& evidence,
                                    const MonotonicMs now_ms) noexcept {
  if (!evidence.boot_trace_healthy) {
    // The durable boot trace is unreadable: the boot-witness binding is
    // unverifiable, so no membership opens on this boot.
    enter_storage_blocked(LifecycleBlockReason::Site, now_ms);
    return Status::success();
  }
  for (Neighbor& neighbor : neighbors_) neighbor = Neighbor{};
  gossip_cursor_ = 0;
  next_gossip_allowed_ = 0;
  fetch_outstanding_ = false;
  rs_to_fetch_ = 0;
  next_get_allowed_ = 0;
  pending_ack_ = false;
  equivocated_ = false;
  self_revoked_ = false;
  candidate_source_ = CandidateSource::None;
  candidate_object_.clear();
  applied_receipt_pending_ = false;
  applied_receipt_ = GrantReceipt{};
  phase_ = LifecyclePhase::BootGate;
  adopted_ = Adopted{};
  sak_valid_ = false;
  if (journal_ != nullptr) {
    const Status loaded = journal_->initialize();
    if (!loaded || journal_->quarantined() || journal_->uncertain()) {
      // Never treat an impaired journal as absent; a valid Removing survivor
      // can be repaired only after its signature and identity are rechecked.
      if (journal_->uncertain() && !journal_->unknown_sibling() &&
          removal_proof_valid(journal_->record()) &&
          journal_->resume_removal(journal_->record())) {
        // The same durable intent is now a proven twin.
      } else if (journal_->uncertain() && !journal_->unknown_sibling() &&
                 journal_->record().mode == LifecycleMode::Switching) {
        SiteRecord staged{};
        RevocationSet rrs{};
        if (!switching_proof(journal_->record(), staged, rrs) ||
            !journal_->resume_switch(journal_->record())) {
          enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          return Status::success();
        }
      } else {
        enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
        return Status::success();
      }
    }
    if (journal_->has_record()) {
      const LifecycleRecord& record = journal_->record();
      // Switching is an irreversible intent. Until signed roll-forward and
      // the Owner's context fence are wired, never adopt either store as Member.
      if (record.mode == LifecycleMode::Switching) {
        SiteRecord staged{};
        RevocationSet rrs{};
        if (!switching_proof(record, staged, rrs)) {
          enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          return Status::success();
        }
        phase_ = LifecyclePhase::Switching;
        switch_step_ = 0;
        switch_cursor_ = 0;
        return Status::success();
      }
      if (record.mode == LifecycleMode::Prepared) {
        SiteRecord staged{};
        if (adopt_stores() != LifecycleBlockReason::None ||
            !staged_site(record, staged) || !site_.has_site() ||
            site_.site().network != record.old_network ||
            site_.site().assignment_generation != record.generation) {
          enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          return Status::success();
        }
        const Status status = adopt_and_enter(now_ms);
        if (phase_ == LifecyclePhase::Active) phase_ = LifecyclePhase::Prepared;
        return status;
      }
      if (record.mode == LifecycleMode::Removing || record.mode == LifecycleMode::Holdoff) {
        if (!removal_proof_valid(record)) {
          enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          return Status::success();
        }
        adopted_ = Adopted{};
        phase_ = record.mode == LifecycleMode::Removing ? LifecyclePhase::Removing
                                                         : LifecyclePhase::Holdoff;
        removal_step_ = RemovalStep::Runtime;
        removal_cursor_ = 0;
        holdoff_start_ = now_ms;  // lost monotonic continuity: start 600 s again
        if (phase_ == LifecyclePhase::Holdoff) {
          const SiteStoreHealth health = site_.health();
          if (!health.initialized || health.has_site || health.quarantined ||
              health.uncertain || health.unsupported_mask != 0 ||
              health.read_error_mask != 0 || health.active_load_failed ||
              !revocations_.clean_empty()) {
            enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          }
        }
        return Status::success();
      }
      if (record.mode == LifecycleMode::Idle) {
        // A cold boot still needs the Owner to install a fresh network
        // binding; an RLS1 marked Member alone cannot reopen traffic.
        if (adopt_stores() != LifecycleBlockReason::None || !adopted_.has_rrs ||
            adopted_.network != record.old_network ||
            adopted_.site_id != record.site_id ||
            adopted_.generation != record.generation ||
            adopted_.rs_epoch < record.rs_floor ||
            adopted_.gk_epoch < record.gk_floor || self_rejected() ||
            !journal_->scrub_idle()) {
          enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          return Status::success();
        }
        phase_ = LifecyclePhase::Switching;
        emit_action(LifecycleActionTag::AdoptNetwork, LifecycleActionReason::None);
        return Status::success();
      }
      if (record.mode == LifecycleMode::UnassignedReady) {
        const SiteStoreHealth health = site_.health();
        if (!identity_.has_identity() || identity_.quarantined() || identity_.uncertain() ||
            identity_.identity().node_id != config_.self || record.self != config_.self ||
            !health.initialized || health.quarantined ||
            health.uncertain || health.unsupported_mask != 0 ||
            health.read_error_mask != 0 || health.active_load_failed ||
            (health.has_site ? !reassigned_after_removal() : !revocations_.clean_empty())) {
          enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
          return Status::success();
        }
        if (health.has_site) return adopt_and_enter(now_ms);
        phase_ = LifecyclePhase::UnassignedReady;
        emit_action(LifecycleActionTag::RestartUnassigned, LifecycleActionReason::None);
        return Status::success();
      }
    }
  }
  return adopt_and_enter(now_ms);
}

Status MembershipLifecycle::on_poll(const MonotonicMs now_ms) noexcept {
  if (phase_ == LifecyclePhase::Stopped) return Status::success();
  if (phase_ == LifecyclePhase::ApplyingRrs) return apply_poll(now_ms);
  if (phase_ == LifecyclePhase::Switching) return switch_poll(now_ms);
  if (phase_ == LifecyclePhase::Removing) return removal_poll(now_ms);
  if (phase_ == LifecyclePhase::Holdoff) {
    if (now_ms < holdoff_start_) holdoff_start_ = now_ms;
    if (now_ms - holdoff_start_ >= 600000) {
      if (journal_ != nullptr && journal_->unassigned_ready()) {
        phase_ = LifecyclePhase::UnassignedReady;
        emit_action(LifecycleActionTag::RestartUnassigned, LifecycleActionReason::None);
      } else {
        enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
      }
    }
    return Status::success();
  }
  if (phase_ == LifecyclePhase::UnassignedReady || phase_ == LifecyclePhase::StorageBlocked)
    return Status::success();
  if (phase_ == LifecyclePhase::Active && applied_receipt_pending_) {
    std::array<std::uint8_t, kGrantReceiptSize> bytes{};
    if (grant_receipt_encode(applied_receipt_, bytes) &&
        ports_.authority.authority_send(7, ByteView{bytes.data(), bytes.size()}))
      applied_receipt_pending_ = false;
  }
  exchange_.poll(now_ms);
  if (fetch_outstanding_ && now_ms >= fetch_deadline_) {
    // Silent peer: free the single fetch slot so another peer can serve.
    clear_fetch(true, now_ms);
  }
  if (need_rrs() && now_ms >= next_get_allowed_) send_authority_get(now_ms);
  if (pending_ack_ && now_ms >= pending_ack_due_) send_pending_ack(now_ms);
  gossip_poll(now_ms);
  return Status::success();
}

Status MembershipLifecycle::on_member_ready(const LifecycleMemberReady& ready,
                                            const MonotonicMs now_ms) noexcept {
  if (phase_ == LifecyclePhase::Stopped || phase_ == LifecyclePhase::Removing ||
      phase_ == LifecyclePhase::Holdoff || phase_ == LifecyclePhase::StorageBlocked ||
      phase_ == LifecyclePhase::Switching ||
      (journal_ && journal_->has_record() &&
       (journal_->record().mode == LifecycleMode::Switching ||
        (journal_->record().mode == LifecycleMode::Idle &&
         phase_ != LifecyclePhase::Active &&
         phase_ != LifecyclePhase::Recovering &&
         phase_ != LifecyclePhase::SelfRevoked)))) {
    return Status::error(StatusCode::InvalidState, "lifecycle not accepting member");
  }
  if (phase_ == LifecyclePhase::UnassignedReady) {
    if (!reassigned_after_removal()) {
      return Status::error(StatusCode::InvalidState, "reassignment below removal watermark");
    }
    rs_to_fetch_ = ready.rs_epoch_to_fetch;
    phase_ = LifecyclePhase::BootGate;
    return adopt_and_enter(now_ms);
  }
  if (phase_ == LifecyclePhase::ApplyingRrs) {
    // Do not disturb the running apply; the Floor step re-checks the RLS1
    // sequence. Only the fetch target is recorded.
    if (ready.rs_epoch_to_fetch > rs_to_fetch_) rs_to_fetch_ = ready.rs_epoch_to_fetch;
    return Status::success();
  }
  const bool changed = site_.commit_seq() != ready.site_commit_seq ||
                       site_.commit_seq() != adopted_.site_commit_seq;
  if (ready.rs_epoch_to_fetch > adopted_.rs_epoch) {
    rs_to_fetch_ = ready.rs_epoch_to_fetch;
  } else if (ready.rs_epoch_to_fetch <= adopted_.rs_epoch) {
    rs_to_fetch_ = 0;
  }
  if (changed || phase_ == LifecyclePhase::BootGate) {
    const bool was_prepared = phase_ == LifecyclePhase::Prepared;
    phase_ = LifecyclePhase::BootGate;
    const Status status = adopt_and_enter(now_ms);
    if (was_prepared && phase_ == LifecyclePhase::Active) {
      SiteRecord staged{};
      if (!journal_ || !staged_site(journal_->record(), staged) ||
          !site_.has_site() || site_.site().network != journal_->record().old_network ||
          site_.site().assignment_generation != journal_->record().generation)
        enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
      else phase_ = LifecyclePhase::Prepared;
    }
    return status;
  }
  if (phase_ == LifecyclePhase::SelfRevoked || phase_ == LifecyclePhase::Recovering) {
    // A re-issue (or a completed recovery) may have moved our generation
    // past the revocation: re-check before staying closed.
    if (adopted_.has_rrs && adopted_.rs_epoch >= adopted_.rs_floor && !self_rejected()) {
      phase_ = LifecyclePhase::Active;
      self_revoked_ = false;
      saturate_inc(counters_.recoveries);
      notify(LifecycleEventKind::RecoveryFinished, 0, adopted_.rs_epoch, 0, now_ms);
    }
    return Status::success();
  }
  if (phase_ == LifecyclePhase::Active && self_rejected()) {
    phase_ = LifecyclePhase::SelfRevoked;
    self_revoked_ = true;
    emit_action(LifecycleActionTag::RecoveryRequired, LifecycleActionReason::SelfRevocation);
    notify(LifecycleEventKind::SelfRevoked, config_.self, adopted_.rs_epoch, 0, now_ms);
  }
  return Status::success();
}

Status MembershipLifecycle::on_authority(const LifecycleAuthorityMessage& message,
                                         const MonotonicMs now_ms) noexcept {
  if (message.authority_type == 6) {
    if (!adopted_.site_ok || message.authority.network != adopted_.network)
      return Status::success();
    return on_removal(message.body, now_ms);
  }
  if (message.authority_type == 7) {
    if (!adopted_.site_ok || message.authority.network != adopted_.network)
      return Status::error(StatusCode::InvalidState, "renew authority binding");
    return on_renew(message.body, now_ms);
  }
  if (message.authority_type != kAuthorityTypeRevocation) {
    return Status::error(StatusCode::Unsupported, "authority type");
  }
  if (message.body.data == nullptr || message.body.size == 0 ||
      message.body.size > rrs_const::kInputBodyMax) {
    return Status::error(StatusCode::InvalidArgument, "authority body");
  }
  if (phase_ == LifecyclePhase::Stopped) {
    return Status::error(StatusCode::InvalidState, "lifecycle stopped");
  }
  if (!adopted_.site_ok || message.authority.network != adopted_.network) {
    return Status::success();  // unadopted or a stale context: ignore
  }
  if (phase_ != LifecyclePhase::Active && phase_ != LifecyclePhase::Prepared &&
      phase_ != LifecyclePhase::BootGate && phase_ != LifecyclePhase::Recovering) {
    return Status::success();  // closed phases take no authority objects
  }
  return begin_apply(message.body, CandidateSource::Authority, message.authority.peer, now_ms);
}

Status MembershipLifecycle::on_peer_control(const LifecyclePeerControl& control,
                                            const MonotonicMs now_ms) noexcept {
  if (control.carrier != FrameType::Control && control.carrier != FrameType::ControlObject &&
      control.carrier != FrameType::ObjectChunk && control.carrier != FrameType::ObjectAck) {
    return Status::error(StatusCode::InvalidArgument, "p6 carrier");
  }
  if (control.body.data == nullptr || control.body.size == 0 ||
      control.body.size > rrs_const::kInputBodyMax) {
    return Status::error(StatusCode::InvalidArgument, "p6 body");
  }
  if (phase_ == LifecyclePhase::Stopped) {
    return Status::error(StatusCode::InvalidState, "lifecycle stopped");
  }
  const PeerCredentialStamp& stamp = control.peer;
  if (!valid_node(stamp.peer) || stamp.peer == config_.self || stamp.role == 0) {
    return Status::error(StatusCode::InvalidArgument, "p6 stamp");
  }
  if (!adopted_.site_ok || stamp.network != adopted_.network) {
    return Status::success();  // unadopted or foreign overhearing: ignore
  }
  if (phase_ == LifecyclePhase::StorageBlocked || phase_ == LifecyclePhase::SelfRevoked) {
    return Status::success();  // closed: no gossip while blocked or revoked
  }
  if (control.carrier == FrameType::Control) {
    StateEpochs epochs{};
    if (state_epochs_decode(control.body, epochs)) {
      observe_epochs(stamp.peer, stamp.binding_incarnation, epochs, now_ms);
      return Status::success();
    }
    RrsRequest request{};
    if (rrs_request_decode(control.body, request)) {
      on_request(stamp.peer, stamp.binding_incarnation, request, now_ms);
      return Status::success();
    }
    saturate_inc(counters_.gossip_dropped);
    return Status::success();
  }
  if (control.carrier == FrameType::ControlObject) {
    autonomy::ControlObjectPayload manifest{};
    if (!autonomy::control_object_decode(control.body, manifest) ||
        manifest.kind != autonomy::ControlObjectKind::RevocationSet) {
      saturate_inc(counters_.gossip_dropped);
      return Status::success();
    }
    exchange_.on_manifest(stamp.peer, stamp.binding_incarnation, manifest, now_ms);
    return Status::success();
  }
  if (control.carrier == FrameType::ObjectChunk) {
    autonomy::ObjectChunkPayload chunk{};
    if (!autonomy::object_chunk_decode(control.body, chunk) ||
        !exchange_.owns_transfer(stamp.peer, stamp.binding_incarnation, chunk.object_hash)) {
      return Status::success();  // someone else's chunk: ignore silently
    }
    exchange_.on_chunk(stamp.peer, stamp.binding_incarnation, chunk, now_ms);
    return Status::success();
  }
  autonomy::ObjectAckPayload ack{};
  if (!autonomy::object_ack_decode(control.body, ack) ||
      !exchange_.owns_transfer(stamp.peer, stamp.binding_incarnation, ack.object_hash)) {
    return Status::success();
  }
  exchange_.on_ack(stamp.peer, stamp.binding_incarnation, ack, now_ms);
  return Status::success();
}

Status MembershipLifecycle::on_completed(const LifecycleCompletedObject& completed,
                                         const MonotonicMs now_ms) noexcept {
  if (completed.object.data == nullptr || completed.object.size == 0 ||
      completed.object.size > kRevocationObjectMax) {
    return Status::error(StatusCode::InvalidArgument, "rrs object size");
  }
  if (phase_ == LifecyclePhase::Stopped) {
    return Status::error(StatusCode::InvalidState, "lifecycle stopped");
  }
  if (phase_ != LifecyclePhase::Active && phase_ != LifecyclePhase::BootGate &&
      phase_ != LifecyclePhase::Recovering) {
    return Status::success();
  }
  return begin_apply(completed.object, CandidateSource::Gossip, completed.peer, now_ms);
}

Status MembershipLifecycle::on_link_failure(const LifecycleLinkFailure& failure,
                                            const MonotonicMs now_ms) noexcept {
  if (phase_ == LifecyclePhase::Stopped) {
    return Status::error(StatusCode::InvalidState, "lifecycle stopped");
  }
  if (phase_ == LifecyclePhase::Active &&
      failure.consecutive_failures >= rrs_const::kLinkFailureThreshold &&
      failure.usable_neighbors == 0) {
    enter_recovering(LifecycleActionReason::LinkFailure, now_ms);
  }
  return Status::success();
}

Status MembershipLifecycle::on_recovery(const LifecycleJoinRecovery& recovery,
                                        const MonotonicMs now_ms) noexcept {
  if (phase_ == LifecyclePhase::Stopped || phase_ == LifecyclePhase::Removing ||
      phase_ == LifecyclePhase::Holdoff || phase_ == LifecyclePhase::UnassignedReady ||
      phase_ == LifecyclePhase::Prepared || phase_ == LifecyclePhase::StorageBlocked ||
      phase_ == LifecyclePhase::Switching ||
      (journal_ && journal_->has_record() &&
       (journal_->record().mode == LifecycleMode::Prepared ||
        journal_->record().mode == LifecycleMode::Switching ||
        (journal_->record().mode == LifecycleMode::Idle &&
         phase_ != LifecyclePhase::Recovering &&
         phase_ != LifecyclePhase::SelfRevoked)))) {
    return Status::error(StatusCode::InvalidState, "lifecycle not recovering");
  }
  if (!recovery.success) return Status::success();  // the Owner retries
  if (phase_ == LifecyclePhase::ApplyingRrs) return Status::success();  // deferred to Floor
  phase_ = LifecyclePhase::BootGate;
  (void)adopt_and_enter(now_ms);
  if (phase_ == LifecyclePhase::Active) {
    self_revoked_ = false;
    saturate_inc(counters_.recoveries);
    notify(LifecycleEventKind::RecoveryFinished, 0, adopted_.rs_epoch, 0, now_ms);
  }
  return Status::success();
}

bool MembershipLifecycle::reassigned_after_removal() const noexcept {
  if (journal_ == nullptr || !journal_->has_record() ||
      journal_->record().mode != LifecycleMode::UnassignedReady || !site_.has_site()) return false;
  const SiteStoreHealth health = site_.health();
  if (!health.initialized || health.quarantined || health.uncertain ||
      health.unsupported_mask != 0 || health.read_error_mask != 0 ||
      health.active_load_failed) return false;
  const LifecycleRecord& previous = journal_->record();
  const SiteRecord& current = site_.site();
  if (previous.self != config_.self) return false;
  if (current.site_id != previous.site_id) return true;
  return current.assignment_generation > previous.generation &&
         static_cast<std::uint32_t>(current.network) ==
             static_cast<std::uint32_t>(previous.old_network) &&
         (current.network >> 32U) >= (previous.old_network >> 32U);
}

bool MembershipLifecycle::removal_proof_valid(const LifecycleRecord& record) noexcept {
  if (!identity_.has_identity() || identity_.quarantined() || identity_.uncertain() ||
      identity_.identity().node_id != config_.self ||
      (record.mode != LifecycleMode::Removing && record.mode != LifecycleMode::Holdoff) ||
      record.self != config_.self || record.payload.size < 4) return false;
  const auto* p = record.payload.bytes.data();
  const std::size_t cert_len = (static_cast<std::size_t>(p[0]) << 8U) | p[1];
  const std::size_t notice_len = (static_cast<std::size_t>(p[2]) << 8U) | p[3];
  if (cert_len > kRlcw1CertMax || cert_len == 0 ||
      notice_len != kRemovalNoticeObjectSize ||
      cert_len + notice_len + 4 != record.payload.size) return false;
  CertClaims cert{};
  bool verified = false;
  if (!identity_verify_site_cert(identity_.identity(), ByteView{p + 4, cert_len},
                                 cert, verified, verifier_) || !verified ||
      cert.subject != record.site_id ||
      cert.site_epoch != static_cast<std::uint32_t>(record.old_network >> 32U) ||
      cert.network_low32 != static_cast<std::uint32_t>(record.old_network)) return false;
  RemovalNotice notice{};
  verified = false;
  if (!removal_notice_verify(ByteView{p + 4 + cert_len, notice_len}, cert.pubkey,
                             record.site_id, record.old_network, record.self,
                             record.generation, notice, verified, verifier_) || !verified ||
      notice.generation != record.generation || notice.rs_epoch > record.rs_floor) return false;
  if (site_.has_site()) {
    const SiteRecord& site = site_.site();
    if (site.site_id != record.site_id || site.network != record.old_network ||
        site.assignment_generation > record.generation ||
        site.rs_epoch_floor > record.rs_floor ||
        site.boot_witness != record.boot_witness ||
        site.gk_epoch_current != record.gk_floor || site.site_cert.size != cert_len ||
        std::memcmp(site.site_cert.bytes.data(), p + 4, cert_len) != 0) return false;
  }
  // A cut during the twin tombstone can leave an adopted tombstone and one
  // corrupt sibling. Without a valid slot, deletion progress is unproven.
  const SiteStoreHealth health = site_.health();
  if (!health.initialized || health.quarantined || health.unsupported_mask != 0 ||
      health.read_error_mask != 0 || health.active_load_failed) return false;
  return true;
}

Status MembershipLifecycle::on_removal(ByteView object, MonotonicMs now_ms) noexcept {
  if (journal_ == nullptr) return Status::error(StatusCode::Unsupported, "removal not wired");
  if (phase_ == LifecyclePhase::Removing || phase_ == LifecyclePhase::Holdoff ||
      phase_ == LifecyclePhase::UnassignedReady) return Status::success();
  if (phase_ != LifecyclePhase::Active && phase_ != LifecyclePhase::Prepared &&
      phase_ != LifecyclePhase::SelfRevoked && phase_ != LifecyclePhase::Recovering &&
      phase_ != LifecyclePhase::BootGate) {
    return Status::success();
  }
  if (!adopted_.site_ok || !site_.has_site() || !sak_valid_ ||
      object.data == nullptr || object.size != kRemovalNoticeObjectSize) {
    return Status::success();
  }
  RemovalNotice notice{};
  bool verified = false;
  const Status checked = removal_notice_verify(object, sak_, adopted_.site_id,
                                                adopted_.network, config_.self,
                                                adopted_.generation, notice, verified, verifier_);
  if (!checked || !verified) return Status::success();  // invalid proofs never erase
  LifecycleRecord intent{};
  intent.mode = LifecycleMode::Removing;
  intent.self = config_.self;
  intent.site_id = adopted_.site_id;
  intent.old_network = adopted_.network;
  intent.generation = notice.generation;
  intent.rs_floor = notice.rs_epoch > adopted_.rs_epoch ? notice.rs_epoch : adopted_.rs_epoch;
  if (site_.site().rs_epoch_floor > intent.rs_floor) {
    intent.rs_floor = site_.site().rs_epoch_floor;
  }
  intent.gk_floor = adopted_.gk_epoch;
  intent.boot_witness = site_.site().boot_witness;
  const auto& cert = site_.site().site_cert;
  if (cert.size == 0 || cert.size > kRlcw1CertMax) return Status::success();
  auto* p = intent.payload.bytes.data();
  p[0] = static_cast<std::uint8_t>(cert.size >> 8U);
  p[1] = static_cast<std::uint8_t>(cert.size);
  p[2] = 0;
  p[3] = static_cast<std::uint8_t>(object.size);
  std::memcpy(p + 4, cert.bytes.data(), cert.size);
  std::memcpy(p + 4 + cert.size, object.data, object.size);
  intent.payload.size = 4 + cert.size + object.size;
  if (!removal_proof_valid(intent) || !bump_policy()) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return Status::success();
  }
  phase_ = LifecyclePhase::Removing;  // close admission before the first write
  if (!journal_->begin_removal(intent)) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return Status::success();
  }
  RrsNoticeAccepted accepted{};
  accepted.rs_epoch = notice.rs_epoch;
  sha256(object, accepted.notice_sha256);
  std::array<std::uint8_t, kRrsNoticeAcceptedSize> ack{};
  if (rrs_notice_accepted_encode(accepted, ack)) {
    // The port copies a sealed report before runtime secrets are destroyed.
    // Delivery is best effort; erasure never waits for transport progress.
    (void)ports_.authority.authority_send(kAuthorityTypeRevocation,
                                          ByteView{ack.data(), ack.size()});
  }
  pending_ack_ = false;
  fetch_outstanding_ = false;
  exchange_.abort();
  action_pending_ = false;
  removal_cursor_ = 0;
  removal_step_ = RemovalStep::Runtime;
  return Status::success();
}

Status MembershipLifecycle::removal_poll(MonotonicMs now_ms) noexcept {
  if (journal_ == nullptr || !journal_->has_record() ||
      journal_->record().mode != LifecycleMode::Removing) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return Status::success();
  }
  Status result{};
  switch (removal_step_) {
    case RemovalStep::Runtime:
      result = ports_.runtime.remove_member_runtime();
      if (result) removal_step_ = RemovalStep::Resume;
      break;
    case RemovalStep::Resume: {
      bool done = false;
      result = resume_.clear_step(removal_cursor_, done);
      if (result && done) removal_step_ = RemovalStep::Trust;
      break;
    }
    case RemovalStep::Trust:
      result = ports_.runtime.erase_site_trust();
      if (result) removal_step_ = RemovalStep::Site;
      break;
    case RemovalStep::Site:
      {
        const SiteStoreHealth health = site_.health();
        result = health.initialized && health.unsupported_mask == 0 &&
                         health.read_error_mask == 0 && !health.active_load_failed
                     ? site_.clear()
                     : Status::error(StatusCode::RecoveryRequired, "site erasure unproven");
      }
      if (result) removal_step_ = RemovalStep::Revocation;
      break;
    case RemovalStep::Revocation:
      result = revocations_.erasure_safe()
                   ? revocations_.clear()
                   : Status::error(StatusCode::RecoveryRequired, "rrs erasure unproven");
      if (result) removal_step_ = RemovalStep::Finish;
      break;
    case RemovalStep::Finish:
      result = site_.initialize();
      if (result) result = revocations_.initialize();
      const SiteStoreHealth health = site_.health();
      if (result && health.initialized && !health.has_site && !health.quarantined &&
          !health.uncertain && health.unsupported_mask == 0 &&
          health.read_error_mask == 0 && !health.active_load_failed &&
          revocations_.clean_empty()) result = journal_->holdoff();
      else if (result) result = Status::error(StatusCode::IntegrityError, "removal postcondition");
      if (result) {
        phase_ = LifecyclePhase::Holdoff;
        holdoff_start_ = now_ms;
        adopted_ = Adopted{};
        sak_valid_ = false;
      }
      break;
  }
  // An error during a store commit can mean the write actually landed.
  // Re-read from a new instance on boot instead of continuing from a stale
  // in-memory slot ordinal. The Removing intent keeps the gate closed.
  if (!result && (removal_step_ == RemovalStep::Site ||
                  removal_step_ == RemovalStep::Revocation ||
                  removal_step_ == RemovalStep::Finish)) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
  }
  return Status::success();
}

// The journal is only a staging container: signatures and the identity/epoch
// binding must be checked again after every boot before using its contents.
bool MembershipLifecycle::staged_site(const LifecycleRecord& record, SiteRecord& out) noexcept {
  if (record.mode != LifecycleMode::Prepared && record.mode != LifecycleMode::Switching) return false;
  if (!identity_.has_identity() || identity_.quarantined() || identity_.uncertain() ||
      record.self != config_.self || record.generation == 0) return false;
  const auto* p = record.payload.bytes.data();
  const std::size_t size = (static_cast<std::size_t>(p[0]) << 8U) | p[1];
  const std::size_t offset = record.mode == LifecycleMode::Prepared ? 2 : 6;
  if (size == 0 || size > kSiteRecordMax || size + offset > record.payload.size ||
      !site_record_decode(ByteView{p + offset, size}, out) ||
      !site_matches_identity(out, identity_.identity()) ||
      out.site_id != record.site_id || out.network != record.new_network ||
      out.assignment_generation != record.generation ||
      out.rs_epoch_floor < record.rs_floor || out.gk_epoch_current != record.gk_floor ||
      out.boot_witness != record.boot_witness || out.gk_epoch_next != 0) return false;
  CertClaims next{};
  bool verified = false;
  if (!identity_verify_site_cert(identity_.identity(), out.site_cert.view(), next,
                                 verified, verifier_) || !verified ||
      (sak_valid_ && next.pubkey != sak_) ||
      next.site_epoch != static_cast<std::uint32_t>(record.new_network >> 32U) ||
      !join_membership_verify(out, identity_.identity(), verified, verifier_) || !verified)
    return false;
  return true;
}

bool MembershipLifecycle::switching_proof(const LifecycleRecord& record, SiteRecord& out,
                                          RevocationSet& rrs) noexcept {
  if (record.mode != LifecycleMode::Switching || !staged_site(record, out)) return false;
  const auto* p = record.payload.bytes.data();
  const std::size_t site_len = (static_cast<std::size_t>(p[0]) << 8U) | p[1];
  const std::size_t rrs_len = (static_cast<std::size_t>(p[2]) << 8U) | p[3];
  const std::size_t proof_len = (static_cast<std::size_t>(p[4]) << 8U) | p[5];
  const ByteView rrs_bytes{p + 6 + site_len, rrs_len};
  const ByteView proof_bytes{rrs_bytes.data + rrs_len, proof_len};
  CutoverCommit proof{};
  bool verified = false;
  CertClaims next{};
  if (!cert_decode(out.site_cert.view(), next)) return false;
  if (!cutover_commit_verify(proof_bytes, next.pubkey, record.old_network, proof, verified,
                             verifier_) || !verified ||
      !revocation_object_verify(rrs_bytes, next.pubkey, record.site_id, record.new_network,
                                rrs, verified, verifier_) || !verified) return false;
  Digest256 hash{};
  sha256(rrs_bytes, hash);
  return proof.site_id == record.site_id && proof.new_network == record.new_network &&
         proof.cutover_id == record.cutover_id && proof.revision == record.revision &&
         proof.gk_epoch == out.gk_epoch_current && proof.rs_epoch == rrs.rs_epoch &&
         proof.rrs_sha256 == hash && rrs.site_epoch_floor ==
             static_cast<std::uint32_t>(record.new_network >> 32U) &&
         rrs.rs_epoch == out.rs_epoch_floor;
}

Status MembershipLifecycle::renew_prepare(ByteView body) noexcept {
  if (phase_ != LifecyclePhase::Active && phase_ != LifecyclePhase::Prepared)
    return Status::error(StatusCode::InvalidState, "renew prepare phase");
  if (!journal_ || !site_.has_site() || !sak_valid_ ||
      (identity_.identity().flags & kIdentityFlagStrictAssignment) != 0)
    return Status::error(StatusCode::Unsupported, "renew assignment verification unavailable");
  GrantPrepare prepare{};
  Status st = grant_prepare_decode(body, prepare);
  if (!st) return st;
  const SiteRecord& old = site_.site();
  if (prepare.head.old_network != old.network || prepare.package.site_id != old.site_id ||
      prepare.package.gk == old.gk_current ||
      (old.gk_epoch_next && prepare.package.gk == old.gk_next) ||
      prepare.package.gk_epoch <= old.gk_epoch_current ||
      (old.gk_epoch_next && prepare.package.gk_epoch <= old.gk_epoch_next) ||
      prepare.package.channel != old.channel ||
      prepare.package.channel_epoch != old.channel_epoch ||
      prepare.package.gateway_count != old.gateway_count ||
      prepare.package.gateways != old.gateways ||
      prepare.package.role != old.role || prepare.package.authority_time_s != 0 ||
      prepare.package.time_uncertainty_ms != 0)
    return Status::error(StatusCode::Conflict, "renew prepare floors");
  SiteRecord next = old;
  next.network = prepare.new_network;
  next.site_cert = prepare.site_cert;
  next.member_cert = prepare.member_cert;
  next.gk_epoch_current = prepare.package.gk_epoch;
  next.gk_current = prepare.package.gk;
  next.gk_epoch_next = 0;
  next.gk_next.fill(0);
  next.dams = prepare.dams;
  CertClaims claims{};
  bool verified = false;
  if (!identity_verify_site_cert(identity_.identity(), next.site_cert.view(), claims,
                                 verified, verifier_) || !verified || claims.pubkey != sak_ ||
      claims.site_epoch != static_cast<std::uint32_t>(next.network >> 32U) ||
      !join_membership_verify(next, identity_.identity(), verified, verifier_) || !verified)
    return Status::error(StatusCode::AuthenticationFailed, "renew certificate chain");
  LifecycleRecord record{};
  record.mode = LifecycleMode::Prepared;
  record.self = config_.self;
  record.site_id = old.site_id;
  record.old_network = old.network;
  record.new_network = next.network;
  record.generation = old.assignment_generation;
  record.rs_floor = old.rs_epoch_floor;
  record.gk_floor = next.gk_epoch_current;
  record.boot_witness = old.boot_witness;
  record.cutover_id = prepare.head.cutover_id;
  record.revision = prepare.head.revision;
  ByteBuffer<kSiteSlotBytes> encoded{};
  st = site_record_encode(next, kSiteSealCommitted, 1, encoded);
  if (!st) return st;
  record.payload.size = 2 + encoded.size + 32;
  record.payload.bytes[0] = static_cast<std::uint8_t>(encoded.size >> 8U);
  record.payload.bytes[1] = static_cast<std::uint8_t>(encoded.size);
  std::memcpy(record.payload.bytes.data() + 2, encoded.bytes.data(), encoded.size);
  Digest256 prepare_hash{};
  sha256(body, prepare_hash); // exact PREPARE digest is bound into RLX1
  std::memcpy(record.payload.bytes.data() + 2 + encoded.size, prepare_hash.data(), 32);
  if (journal_->has_record() && journal_->record().mode == LifecycleMode::Prepared &&
      journal_->record().cutover_id == record.cutover_id &&
      journal_->record().revision == record.revision) {
    const LifecycleRecord& staged = journal_->record();
    if (staged.self != record.self || staged.site_id != record.site_id ||
        staged.old_network != record.old_network || staged.new_network != record.new_network ||
        staged.generation != record.generation || staged.payload.size < prepare_hash.size() ||
        std::memcmp(staged.payload.bytes.data() + staged.payload.size - prepare_hash.size(),
                    prepare_hash.data(), prepare_hash.size()) != 0)
      return Status::error(StatusCode::Conflict, "renew prepare equivocation");
  } else {
    st = journal_->prepare(record);
    if (!st) {
      if (st.code != StatusCode::Conflict)
        enter_storage_blocked(LifecycleBlockReason::StoreCommit, last_now_);
      return st;
    }
  }
  phase_ = LifecyclePhase::Prepared;
  send_renew_receipt(GrantRenewPhase::Prepared,
                     ByteView{prepare_hash.data(), prepare_hash.size()});
  return Status::success();
}

void MembershipLifecycle::send_renew_receipt(GrantRenewPhase phase, ByteView digest) noexcept {
  const LifecycleRecord& record = journal_->record();
  GrantReceipt receipt{};
  receipt.head = {phase, record.cutover_id, record.revision, record.old_network};
  receipt.new_network = record.new_network;
  receipt.gk_epoch = record.gk_floor;
  receipt.rs_epoch = phase == GrantRenewPhase::Applied ? record.rs_floor : 0;
  if (digest.size == receipt.digest.size())
    std::memcpy(receipt.digest.data(), digest.data, digest.size);
  std::array<std::uint8_t, kGrantReceiptSize> bytes{};
  if (grant_receipt_encode(receipt, bytes))
    (void)ports_.authority.authority_send(7, ByteView{bytes.data(), bytes.size()});
}

Status MembershipLifecycle::on_renew(ByteView body, MonotonicMs now_ms) noexcept {
  GrantRenewHead head{};
  Status st = grant_renew_head_decode(body, head);
  if (!st) return st;
  if (head.old_network != adopted_.network) return Status::error(StatusCode::Conflict, "renew old binding");
  if (head.phase == GrantRenewPhase::Prepare) return renew_prepare(body);
  if (head.phase == GrantRenewPhase::Commit) return renew_commit(body, now_ms);
  return Status::error(StatusCode::ProtocolError, "renew response from authority");
}

Status MembershipLifecycle::renew_commit(ByteView body, MonotonicMs now_ms) noexcept {
  if (phase_ != LifecyclePhase::Prepared || !journal_ || !journal_->has_record() ||
      journal_->record().mode != LifecycleMode::Prepared)
    return Status::error(StatusCode::InvalidState, "renew commit without prepare");
  GrantCommit commit{};
  Status st = grant_commit_decode(body, commit);
  if (!st) return st;
  const LifecycleRecord& prepared = journal_->record();
  if (commit.head.cutover_id != prepared.cutover_id ||
      commit.head.revision != prepared.revision ||
      commit.head.old_network != prepared.old_network) {
    return Status::error(StatusCode::Conflict, "renew revision");
  }
  SiteRecord next{};
  if (!staged_site(prepared, next))
    return Status::error(StatusCode::AuthenticationFailed, "renew staged site");
  CutoverCommit proof{};
  RevocationSet rrs{};
  bool verified = false;
  st = cutover_commit_verify(commit.proof.view(), sak_, prepared.old_network,
                             proof, verified, verifier_);
  if (!st || !verified) return Status::error(StatusCode::AuthenticationFailed, "renew proof");
  st = revocation_object_verify(commit.revocations.view(), sak_, prepared.site_id,
                                prepared.new_network, rrs, verified, verifier_);
  if (!st || !verified) return Status::error(StatusCode::AuthenticationFailed, "renew rrs");
  Digest256 hash{};
  sha256(commit.revocations.view(), hash);
  if (proof.site_id != prepared.site_id || proof.new_network != prepared.new_network ||
      proof.cutover_id != prepared.cutover_id || proof.revision != prepared.revision ||
      proof.gk_epoch != next.gk_epoch_current || proof.rs_epoch != rrs.rs_epoch ||
      proof.rrs_sha256 != hash || rrs.rs_epoch < prepared.rs_floor ||
      rrs.rs_epoch < site_.site().rs_epoch_floor ||
      (revocations_.has_set() && rrs.rs_epoch <= revocations_.rs_epoch()) ||
      next.gk_epoch_current <= site_.site().gk_epoch_current ||
      (site_.site().gk_epoch_next && next.gk_epoch_current <= site_.site().gk_epoch_next) ||
      rrs.site_epoch_floor != static_cast<std::uint32_t>(prepared.new_network >> 32U)) {
    return Status::error(StatusCode::Conflict, "renew commit binding");
  }
  next.rs_epoch_floor = rrs.rs_epoch;
  LifecycleRecord switching = prepared;
  switching.mode = LifecycleMode::Switching;
  switching.rs_floor = rrs.rs_epoch;
  ByteBuffer<kSiteSlotBytes> encoded{};
  st = site_record_encode(next, kSiteSealCommitted, 1, encoded);
  if (!st) return st;
  const std::size_t length = 6 + encoded.size + commit.revocations.size + commit.proof.size + 32;
  if (length > switching.payload.bytes.size())
    return Status::error(StatusCode::NoCapacity, "renew switching journal");
  std::array<std::uint8_t, 32> prepare_hash{};
  std::memcpy(prepare_hash.data(), prepared.payload.bytes.data() + prepared.payload.size - 32, 32);
  switching.payload.clear();
  switching.payload.size = length;
  auto* p = switching.payload.bytes.data();
  p[0] = static_cast<std::uint8_t>(encoded.size >> 8U); p[1] = static_cast<std::uint8_t>(encoded.size);
  p[2] = static_cast<std::uint8_t>(commit.revocations.size >> 8U);
  p[3] = static_cast<std::uint8_t>(commit.revocations.size);
  p[4] = static_cast<std::uint8_t>(commit.proof.size >> 8U);
  p[5] = static_cast<std::uint8_t>(commit.proof.size);
  std::size_t at = 6;
  std::memcpy(p + at, encoded.bytes.data(), encoded.size); at += encoded.size;
  std::memcpy(p + at, commit.revocations.bytes.data(), commit.revocations.size);
  at += commit.revocations.size;
  std::memcpy(p + at, commit.proof.bytes.data(), commit.proof.size); at += commit.proof.size;
  std::memcpy(p + at, prepare_hash.data(), prepare_hash.size());
  // Once the barrier closes, any ambiguous journal write remains closed
  // until a cold boot rechecks the durable signed intent.
  phase_ = LifecyclePhase::Switching;
  if (!bump_policy()) {
    enter_storage_blocked(LifecycleBlockReason::PolicyExhausted, now_ms);
    return Status::error(StatusCode::RecoveryRequired, "policy exhausted");
  }
  st = journal_->switch_network(switching);
  if (!st) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return st;
  }
  switch_step_ = 0;
  switch_cursor_ = 0;
  return Status::success();
}

Status MembershipLifecycle::switch_poll(MonotonicMs now_ms) noexcept {
  if (switch_step_ == 7) {
    if (!journal_ || journal_->record().mode != LifecycleMode::Idle)
      return Status::error(StatusCode::InvalidState, "renew incomplete journal");
    adopted_.site_commit_seq = site_.commit_seq();
    adopted_.network = site_.site().network;
    emit_action(LifecycleActionTag::AdoptNetwork, LifecycleActionReason::None);
    switch_step_ = 8;
    return Status::success();
  }
  if (!journal_ || !journal_->has_record() || journal_->record().mode != LifecycleMode::Switching)
    return Status::error(StatusCode::InvalidState, "renew missing intent");
  SiteRecord next{};
  RevocationSet rrs{};
  const LifecycleRecord& record = journal_->record();
  const SiteStoreHealth site_health = site_.health();
  if (!site_health.initialized || site_health.unsupported_mask != 0 ||
      site_health.read_error_mask != 0 || !revocations_.erasure_safe() ||
      !switching_proof(record, next, rrs) || !site_.has_site() ||
      site_.site().site_id != record.site_id ||
      (site_.site().network != record.old_network &&
       site_.site().network != record.new_network) ||
      site_.site().assignment_generation != record.generation ||
      !site_matches_identity(site_.site(), identity_.identity())) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return Status::error(StatusCode::IntegrityError, "renew signed intent invalid");
  }
  CertClaims current_cert{};
  bool current_verified = false;
  if (!identity_verify_site_cert(identity_.identity(), site_.site().site_cert.view(),
                                 current_cert, current_verified, verifier_) ||
      !current_verified || !join_membership_verify(site_.site(), identity_.identity(),
                                                   current_verified, verifier_) ||
      !current_verified) {
    enter_storage_blocked(LifecycleBlockReason::Site, now_ms);
    return Status::error(StatusCode::AuthenticationFailed, "renew current membership");
  }
  if (revocation_rejects(rrs, config_.self, record.generation,
                         static_cast<std::uint32_t>(record.new_network >> 32U))) {
    // The signed COMMIT is durable evidence that this grant is excluded.
    // Keep its irreversible intent and close the old membership on every boot.
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return Status::error(StatusCode::Conflict, "renew self excluded");
  }
  const auto* p = record.payload.bytes.data();
  const std::size_t site_len = (static_cast<std::size_t>(p[0]) << 8U) | p[1];
  const std::size_t rrs_len = (static_cast<std::size_t>(p[2]) << 8U) | p[3];
  const ByteView rrs_bytes{p + 6 + site_len, rrs_len};
  CertClaims next_cert{};
  if (!cert_decode(next.site_cert.view(), next_cert) ||
      current_cert.pubkey != next_cert.pubkey) {
    enter_storage_blocked(LifecycleBlockReason::Site, now_ms);
    return Status::error(StatusCode::IntegrityError, "renew site cert");
  }
  Status st{};
  switch (switch_step_) {
    case 0: st = ports_.runtime.retire_network(); break;
    case 1: {
      bool done = false;
      st = resume_.clear_step(switch_cursor_, done);
      if (st && !done) return st;
      break;
    }
    case 2:
      if (!site_.has_site() || site_.site().site_id != record.site_id ||
          (site_.site().network != record.old_network &&
           site_.site().network != record.new_network) ||
          site_.site().assignment_generation != record.generation ||
          site_.site().rs_epoch_floor > next.rs_epoch_floor ||
          site_.site().gk_epoch_current > next.gk_epoch_current) {
        st = Status::error(StatusCode::Conflict, "renew store binding");
      } else if (site_.site().network != record.new_network) {
        st = site_.uncertain() || site_.quarantined() ? site_.recover(next) : site_.commit(next);
      } else {
        Digest256 current_hash{}, expected_hash{};
        st = site_.fingerprint(site_.site(), current_hash);
        if (st) st = site_.fingerprint(next, expected_hash);
        if (st && current_hash != expected_hash)
          st = Status::error(StatusCode::Conflict, "renew changed site record");
        if (st && (site_.uncertain() || site_.quarantined())) st = site_.recover(next);
      }
      break;
    case 3:
      if (revocations_.has_set() && revocations_.set().network == record.new_network) {
        if (revocations_.rs_epoch() != rrs.rs_epoch) st = Status::error(StatusCode::Conflict, "renew rrs mismatch");
        else {
          ByteBuffer<kRevocationObjectMax> stored{};
          st = revocations_.load_object(stored);
          if (st && (stored.size != rrs_len ||
                     std::memcmp(stored.bytes.data(), rrs_bytes.data, rrs_len) != 0))
            st = Status::error(StatusCode::Conflict, "renew rrs equivocation");
          if (st && (revocations_.uncertain() || revocations_.quarantined()))
            st = revocations_.recover(rrs_bytes, next_cert.pubkey, record.site_id,
                                      record.new_network, verifier_);
        }
      } else {
        st = revocations_.uncertain() || revocations_.quarantined()
                 ? revocations_.recover(rrs_bytes, next_cert.pubkey, record.site_id, record.new_network, verifier_)
                 : revocations_.accept(rrs_bytes, next_cert.pubkey, record.site_id, record.new_network, verifier_);
      }
      break;
    case 4: st = site_.consolidate(next); break;
    case 5: st = ports_.runtime.install_site_trust(next); break;
    case 6: {
      const std::size_t proof_len = (static_cast<std::size_t>(p[4]) << 8U) | p[5];
      const ByteView proof{rrs_bytes.data + rrs_len, proof_len};
      Digest256 digest{};
      sha256(proof, digest);
      st = journal_->finish_switch(digest);
      break;
    }
    default: return Status::error(StatusCode::InvalidState, "renew step");
  }
  if (!st) {
    enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
    return st;
  }
  ++switch_step_;
  return Status::success();
}

bool MembershipLifecycle::restore_applied_receipt() noexcept {
  if (!journal_ || !journal_->has_record()) return false;
  const LifecycleRecord& record = journal_->record();
  if (record.mode != LifecycleMode::Idle || record.payload.size != 32) return false;
  applied_receipt_ = GrantReceipt{};
  applied_receipt_.head = {GrantRenewPhase::Applied, record.cutover_id,
                           record.revision, record.old_network - (1ULL << 32U)};
  applied_receipt_.new_network = record.old_network;
  applied_receipt_.gk_epoch = record.gk_floor;
  applied_receipt_.rs_epoch = record.rs_floor;
  std::memcpy(applied_receipt_.digest.data(), record.payload.bytes.data(), 32);
  return true;
}

Status MembershipLifecycle::on_action_complete(const LifecycleActionComplete& done,
                                               const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!action_pending_ || done.token == 0 || done.token != action_.token) {
    return Status::error(StatusCode::NotFound, "unknown action token");
  }
  if (!done.result) return Status::success();  // failed: the Owner retakes it
  if (action_.tag == LifecycleActionTag::AdoptNetwork) {
    if (phase_ != LifecyclePhase::Switching || !journal_ ||
        journal_->record().mode != LifecycleMode::Idle ||
        site_.commit_seq() != action_.expected_site_commit_seq ||
        site_.site().network != action_.network) {
      return Status::error(StatusCode::InvalidState, "stale adoption completion");
    }
    if (adopt_stores() != LifecycleBlockReason::None || !adopted_.has_rrs ||
        adopted_.rs_epoch < adopted_.rs_floor || self_rejected()) {
      enter_storage_blocked(LifecycleBlockReason::StoreCommit, now_ms);
      return Status::success();
    }
    phase_ = LifecyclePhase::Active;
    applied_receipt_pending_ = restore_applied_receipt();
  }
  action_pending_ = false;
  return Status::success();
}

Status MembershipLifecycle::on_stop(const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  secure_clear(candidate_object_.bytes.data(), candidate_object_.bytes.size());
  candidate_object_.clear();
  candidate_set_ = RevocationSet{};
  candidate_source_ = CandidateSource::None;
  secure_clear(stored_object_.bytes.data(), stored_object_.bytes.size());
  stored_object_.clear();
  secure_clear(pending_ack_hash_.data(), pending_ack_hash_.size());
  exchange_.abort();
  action_pending_ = false;
  fetch_outstanding_ = false;
  pending_ack_ = false;
  applied_receipt_pending_ = false;
  applied_receipt_ = GrantReceipt{};
  equivocated_ = false;
  self_revoked_ = false;
  phase_ = LifecyclePhase::Stopped;
  return Status::success();
}

}  // namespace routeloom::sdkv1
