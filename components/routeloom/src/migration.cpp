#include "routeloom/migration.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"

namespace routeloom {
namespace {

constexpr Status reject(const StatusCode code, const char* detail) noexcept {
  return Status::error(code, detail);
}

constexpr std::uint32_t kCommitMagic = 0x524C4331U;   // "RLC1"
constexpr std::uint32_t kActiveMagic = 0x524C5031U;   // "RLP1"
constexpr std::uint8_t kRecordVersion = 1;

// Signed authority->local conversion shared by validation (before the plan
// is adopted) and runtime paths. peer_offset = authority - local, so
// local = authority - offset. Negative results clamp to 0; they mean the
// reference precedes the local clock origin, which is safely "in the past".
MonotonicMs map_to_local(const ClockMapping& mapping,
                         const MonotonicMs authority_ms) noexcept {
  const std::int64_t value =
      static_cast<std::int64_t>(authority_ms) - mapping.peer_offset_ms;
  return value <= 0 ? 0 : static_cast<MonotonicMs>(value);
}

MonotonicMs map_to_authority(const ClockMapping& mapping,
                             const MonotonicMs local_ms) noexcept {
  const std::int64_t value =
      static_cast<std::int64_t>(local_ms) + mapping.peer_offset_ms;
  return value <= 0 ? 0 : static_cast<MonotonicMs>(value);
}

Status write_operation(ByteWriter& writer,
                       const AuthorityOperation& operation) noexcept {
  Status status = writer.write_u64(operation.network);
  if (status) status = writer.write_u64(operation.authority);
  if (status) status = writer.write_u32(operation.generation);
  if (status) status = writer.write_u64(operation.sequence);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(operation.kind));
  if (status) {
    status = writer.write_bytes(
        ByteView{operation.previous_state_hash.data(), 32});
  }
  if (status) {
    status =
        writer.write_bytes(ByteView{operation.operation_hash.data(), 32});
  }
  return status;
}

Status read_operation(ByteReader& reader, AuthorityOperation& out) noexcept {
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
  out.kind = static_cast<AuthorityOperationKind>(kind);
  return status;
}

}  // namespace

// --- plan codec -----------------------------------------------------------------

Status plan_encode(const MigrationPlan& plan, const MutableByteView target,
                   std::size_t& out_size) noexcept {
  out_size = 0;
  if (plan.recovery.helper_count > plan.recovery.helpers.size()) {
    return reject(StatusCode::InvalidArgument, "helper count overflow");
  }
  ByteWriter writer(target);
  Status status = writer.write_u8(kMigrationPlanVersion);
  if (status) status = writer.write_u64(plan.network);
  if (status) status = writer.write_u64(plan.authority);
  if (status) status = writer.write_u32(plan.authority_generation);
  if (status) status = writer.write_u64(plan.operation_sequence);
  if (status) {
    status = writer.write_bytes(
        ByteView{plan.previous_state_hash.data(), 32});
  }
  if (status) status = writer.write_u32(plan.old_epoch.value);
  if (status) status = writer.write_u32(plan.new_epoch.value);
  if (status) status = writer.write_u8(plan.old_channel);
  if (status) status = writer.write_u8(plan.new_channel);
  if (status) status = writer.write_u32(plan.participant_capability_mask);
  if (status) {
    status = writer.write_bytes(
        ByteView{plan.required_participant_digest.data(), 32});
  }
  if (status) {
    status = writer.write_bytes(
        ByteView{plan.candidate_evidence_digest.data(), 32});
  }
  if (status) status = writer.write_u64(plan.authority_session);
  if (status) status = writer.write_u64(plan.switch_reference_ms);
  if (status) {
    status = writer.write_u64(
        static_cast<std::uint64_t>(plan.mapping.peer_offset_ms));
  }
  if (status) status = writer.write_u32(plan.mapping.uncertainty_ms);
  if (status) status = writer.write_u64(plan.expiry_ms);
  if (status) status = writer.write_u32(plan.guard_ms);
  if (status) {
    status =
        writer.write_u8(plan.recovery.present ? 1U : 0U);
  }
  if (status) status = writer.write_u32(plan.recovery.visit_period_ms);
  if (status) status = writer.write_u32(plan.recovery.dwell_ms);
  if (status) status = writer.write_u64(plan.recovery.window_begin_ms);
  if (status) status = writer.write_u64(plan.recovery.window_end_ms);
  if (status) status = writer.write_u16(plan.recovery.object_bytes_max);
  if (status) {
    status = writer.write_u8(
        static_cast<std::uint8_t>(plan.recovery.helper_count));
  }
  for (std::size_t i = 0; status && i < plan.recovery.helper_count; ++i) {
    status = writer.write_u64(plan.recovery.helpers[i]);
  }
  if (status) status = writer.write_u32(plan.protected_services_mask);
  if (status) status = writer.write_u32(plan.max_outage_ms);
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status plan_decode(const ByteView encoded, MigrationPlan& out) noexcept {
  out = MigrationPlan{};
  ByteReader reader(encoded);
  std::uint8_t version = 0;
  Status status = reader.read_u8(version);
  if (!status || version != kMigrationPlanVersion) {
    return reject(StatusCode::InvalidArgument, "PLAN_VERSION_UNKNOWN");
  }
  std::uint64_t offset = 0;
  std::uint8_t recovery_present = 0;
  std::uint8_t helper_count = 0;
  if (status) status = reader.read_u64(out.network);
  if (status) status = reader.read_u64(out.authority);
  if (status) status = reader.read_u32(out.authority_generation);
  if (status) status = reader.read_u64(out.operation_sequence);
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.previous_state_hash.data(), 32});
  }
  if (status) status = reader.read_u32(out.old_epoch.value);
  if (status) status = reader.read_u32(out.new_epoch.value);
  if (status) status = reader.read_u8(out.old_channel);
  if (status) status = reader.read_u8(out.new_channel);
  if (status) status = reader.read_u32(out.participant_capability_mask);
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.required_participant_digest.data(), 32});
  }
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.candidate_evidence_digest.data(), 32});
  }
  if (status) status = reader.read_u64(out.authority_session);
  if (status) status = reader.read_u64(out.switch_reference_ms);
  if (status) status = reader.read_u64(offset);
  if (status) status = reader.read_u32(out.mapping.uncertainty_ms);
  if (status) status = reader.read_u64(out.expiry_ms);
  if (status) status = reader.read_u32(out.guard_ms);
  if (status) status = reader.read_u8(recovery_present);
  if (status) status = reader.read_u32(out.recovery.visit_period_ms);
  if (status) status = reader.read_u32(out.recovery.dwell_ms);
  if (status) status = reader.read_u64(out.recovery.window_begin_ms);
  if (status) status = reader.read_u64(out.recovery.window_end_ms);
  if (status) status = reader.read_u16(out.recovery.object_bytes_max);
  if (status) status = reader.read_u8(helper_count);
  if (status && helper_count > out.recovery.helpers.size()) {
    return reject(StatusCode::InvalidArgument, "PLAN_HELPERS_OVERFLOW");
  }
  for (std::size_t i = 0; status && i < helper_count; ++i) {
    status = reader.read_u64(out.recovery.helpers[i]);
  }
  if (status) status = reader.read_u32(out.protected_services_mask);
  if (status) status = reader.read_u32(out.max_outage_ms);
  if (!status || reader.remaining() != 0) {
    return reject(StatusCode::InvalidArgument, "PLAN_DECODE");
  }
  out.mapping.peer_offset_ms = static_cast<std::int64_t>(offset);
  out.recovery.present = recovery_present != 0;
  out.recovery.helper_count = helper_count;
  return Status::success();
}

Digest256 plan_digest(const ByteView encoded_plan) noexcept {
  // Deterministic domain-separated binding ("RLMP" lanes). Same construction
  // as bind_operation_payload: content addressing + integrity, NOT a
  // cryptographic digest — the signature verifier is the authenticity check.
  Digest256 out{};
  std::uint64_t lanes[4] = {0x524C4D50526F7574ULL, 0xBB67AE8584CAA73BULL,
                            0x3C6EF372FE94F82BULL, 0x54A9D1E7F5B8C3A2ULL};
  for (std::size_t i = 0; i < encoded_plan.size; ++i) {
    std::uint64_t& lane = lanes[i % 4];
    lane ^= encoded_plan.data[i];
    lane *= 0x100000001B3ULL;
    lane ^= lane >> 29U;
  }
  for (int lane = 0; lane < 4; ++lane) {
    for (int byte = 0; byte < 8; ++byte) {
      out[lane * 8 + byte] =
          static_cast<std::uint8_t>(lanes[lane] >> (56 - byte * 8));
    }
  }
  return out;
}

// --- MigrationAuthority ------------------------------------------------------------

MigrationAuthority::MigrationAuthority(const MigrationAuthorityConfig& config,
                                       CommitSignatureVerifier& verifier,
                                       SingleAuthority* ledger) noexcept
    : config_(config), verifier_(verifier), ledger_(ledger) {}

Status MigrationAuthority::check_scope(
    const AuthorityOperation& operation, const Digest256& plan_hash) const noexcept {
  if (operation.network != config_.network ||
      operation.authority != config_.authority) {
    return reject(StatusCode::AuthorizationFailed, "AUTHORITY_SCOPE_MISMATCH");
  }
  if (operation.kind != AuthorityOperationKind::ChannelMigration) {
    return reject(StatusCode::InvalidArgument, "COMMIT_KIND_MISMATCH");
  }
  // The operation digest must reference the plan blob hash: the ledger
  // commit then transitively binds every plan field (04 §6 step 2).
  const Digest256 bound =
      bind_operation_payload(AuthorityOperationKind::ChannelMigration,
                             ByteView{plan_hash.data(), plan_hash.size()});
  if (operation.operation_hash != bound) {
    return reject(StatusCode::IntegrityError, "COMMIT_PLAN_BINDING_MISMATCH");
  }
  return Status::success();
}

Status MigrationAuthority::commit_plan(
    const MigrationPlan& plan, const ByteView plan_blob,
    const AuthorityOperation& operation, const ByteView signature,
    const Digest256& resulting_state_hash, const bool is_rollback,
    const MonotonicMs now_ms, VerifiedAuthorityPlan& out) noexcept {
  out = VerifiedAuthorityPlan{};
  if (!verifier_.ready()) {
    // No qualified verifier: no verified plan, no commit — never a stubbed
    // pass (04 §5).
    return reject(StatusCode::AuthProfileUnavailable, "COMMIT_VERIFIER_UNAVAILABLE");
  }
  if (!available_) {
    // A stopped single Authority issues NO new commits; already-committed
    // plans keep executing on participants (D5-04).
    return reject(StatusCode::ApprovalRequired, "AUTHORITY_STOPPED_NO_NEW_COMMIT");
  }
  if (ledger_ == nullptr) {
    return reject(StatusCode::InvalidState, "VERIFY_ONLY_AUTHORITY");
  }
  const Digest256 hash = plan_digest(plan_blob);
  if (operation.sequence != plan.operation_sequence ||
      operation.generation != plan.authority_generation) {
    return reject(StatusCode::Conflict, "PLAN_OPERATION_MISMATCH");
  }
  Status status = check_scope(operation, hash);
  if (!status) return status;
  if (plan.new_epoch.value <= last_epoch_.value) {
    return reject(StatusCode::Conflict, "EPOCH_NOT_MONOTONIC");
  }
  if (is_rollback) {
    // Rollback = a new authority operation + a new channel epoch. The single
    // automatic credit comes from the last failed plan (04 §10); without it
    // this is just another plan gated by cooldown.
    if (rollback_credit_ == 0) {
      return reject(StatusCode::InvalidState, "ROLLBACK_BUDGET_EXHAUSTED");
    }
  } else if (cooldown_active(now_ms)) {
    return reject(StatusCode::Busy, "PLAN_COOLDOWN");
  }
  // Real verification is the ONLY source of the ledger's cryptographic flag.
  const Status verified =
      verifier_.verify_commit(operation, hash, signature);
  if (!verified) return verified;
  status = ledger_->commit(operation, resulting_state_hash, verified.ok());
  if (!status) return status;
  if (is_rollback) --rollback_credit_;
  last_epoch_ = plan.new_epoch;
  out = VerifiedAuthorityPlan::issue(
      hash, operation, plan.new_epoch,
      verifier_.security_profile() != SecurityProfile::Production);
  return Status::success();
}

Status MigrationAuthority::verify_commit(
    const AuthorityOperation& operation, const Digest256& plan_hash,
    const ChannelEpoch new_epoch, const ByteView signature,
    VerifiedAuthorityPlan& out) noexcept {
  out = VerifiedAuthorityPlan{};
  if (!verifier_.ready()) {
    return reject(StatusCode::AuthProfileUnavailable, "COMMIT_VERIFIER_UNAVAILABLE");
  }
  const Status scoped = check_scope(operation, plan_hash);
  if (!scoped) return scoped;
  const Status verified =
      verifier_.verify_commit(operation, plan_hash, signature);
  if (!verified) return verified;
  // Signed material keeps verifying while the authority is stopped:
  // verification is local cryptography, not an authority round-trip (D5-04).
  out = VerifiedAuthorityPlan::issue(
      plan_hash, operation, new_epoch,
      verifier_.security_profile() != SecurityProfile::Production);
  return Status::success();
}

Status MigrationAuthority::verify_snapshot(const ByteView snapshot,
                                           const ByteView signature) noexcept {
  if (!verifier_.ready()) {
    return reject(StatusCode::AuthProfileUnavailable, "SNAPSHOT_VERIFIER_UNAVAILABLE");
  }
  return verifier_.verify_snapshot(snapshot, signature);
}

void MigrationAuthority::note_plan_terminal(const bool succeeded,
                                            const MonotonicMs now_ms) noexcept {
  cooldown_until_ms_ = now_ms + config_.cooldown_ms;
  // A failed plan earns exactly one automatic rollback credit; a success
  // clears it. Failed plans never ping-pong (04 §10).
  rollback_credit_ = succeeded ? 0 : config_.automatic_rollbacks_max;
}

// --- required-set gating -------------------------------------------------------------

RequiredSetVerdict evaluate_required_set(
    const ParticipantReadiness* participants, const std::size_t count,
    const bool recovery_schedule_present) noexcept {
  RequiredSetVerdict verdict{};
  // Pass 1: a required participant without migration capability blocks the
  // whole plan outright — it is never reclassed as deferred sleep (D5-09).
  for (std::size_t i = 0; i < count; ++i) {
    const ParticipantReadiness& p = participants[i];
    if (p.required && !p.migration_capable) {
      verdict.reason = StatusCode::LegacyParticipant;
      verdict.blocker = p.node;
      return verdict;
    }
  }
  // Pass 2: READY evidence or a legitimate sleep deferral.
  for (std::size_t i = 0; i < count; ++i) {
    const ParticipantReadiness& p = participants[i];
    if (!p.required) continue;
    if (p.answered) {
      if (!p.ready) {
        verdict.reason = StatusCode::WouldBlock;
        verdict.blocker = p.node;
        return verdict;  // answered but without accepted READY evidence
      }
      ++verdict.ready_count;
      continue;
    }
    // Unanswered is never conveniently "asleep": only a valid availability
    // lease AND rediscovery capability earn the deferred set (04 §7).
    if (p.sleep_lease_valid && p.rediscovery_capable) {
      ++verdict.deferred_count;
      continue;
    }
    verdict.reason = StatusCode::WouldBlock;
    verdict.blocker = p.node;
    return verdict;
  }
  if (verdict.deferred_count > 0 && !recovery_schedule_present) {
    // requires_recovery_plan: deferred nodes are only safe while the plan
    // commits to a recovery schedule that can reach them.
    verdict.reason = StatusCode::PlanNotCommitted;
    return verdict;
  }
  verdict.commit_permitted = true;
  return verdict;
}

// --- durable record codecs ------------------------------------------------------------

Status commit_record_encode(const CommitRecord& record,
                            const MutableByteView target,
                            std::size_t& out_size) noexcept {
  out_size = 0;
  ByteWriter writer(target);
  Status status = writer.write_u32(kCommitMagic);
  if (status) status = writer.write_u8(kRecordVersion);
  if (status) status = writer.write_u8(record.present ? 1U : 0U);
  if (status) status = writer.write_u16(0);
  if (status) status = write_operation(writer, record.operation);
  if (status) {
    status = writer.write_bytes(ByteView{record.plan_hash.data(), 32});
  }
  if (status) status = writer.write_u32(record.new_epoch.value);
  if (!status) return status;
  const std::size_t body = writer.size();
  status = writer.write_u32(
      crc32_iso_hdlc(ByteView{target.data, body}));
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status commit_record_decode(const ByteView encoded, CommitRecord& out) noexcept {
  out = CommitRecord{};
  ByteReader reader(encoded);
  std::uint32_t magic = 0, crc = 0;
  std::uint8_t version = 0, present = 0;
  std::uint16_t reserved = 0;
  Status status = reader.read_u32(magic);
  if (status) status = reader.read_u8(version);
  if (status) status = reader.read_u8(present);
  if (status) status = reader.read_u16(reserved);
  if (!status || magic != kCommitMagic || version != kRecordVersion ||
      reserved != 0) {
    return reject(StatusCode::IntegrityError, "COMMIT_RECORD_DECODE");
  }
  if (status) status = read_operation(reader, out.operation);
  if (status) {
    status = reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  }
  if (status) status = reader.read_u32(out.new_epoch.value);
  if (!status) return reject(StatusCode::IntegrityError, "COMMIT_RECORD_DECODE");
  const std::size_t body = reader.consumed();
  status = reader.read_u32(crc);
  if (!status || reader.remaining() != 0 ||
      crc32_iso_hdlc(ByteView{encoded.data, body}) != crc) {
    return reject(StatusCode::IntegrityError, "COMMIT_RECORD_CRC");
  }
  out.present = present != 0;
  return Status::success();
}

Status active_record_encode(const ActiveRecord& record,
                            const MutableByteView target,
                            std::size_t& out_size) noexcept {
  out_size = 0;
  ByteWriter writer(target);
  Status status = writer.write_u32(kActiveMagic);
  if (status) status = writer.write_u8(kRecordVersion);
  if (status) status = writer.write_u8(record.present ? 1U : 0U);
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u32(record.epoch.value);
  if (status) status = writer.write_u8(record.channel);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u16(0);
  if (status) {
    status = writer.write_bytes(ByteView{record.plan_hash.data(), 32});
  }
  if (!status) return status;
  const std::size_t body = writer.size();
  status = writer.write_u32(crc32_iso_hdlc(ByteView{target.data, body}));
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status active_record_decode(const ByteView encoded, ActiveRecord& out) noexcept {
  out = ActiveRecord{};
  ByteReader reader(encoded);
  std::uint32_t magic = 0, crc = 0;
  std::uint8_t version = 0, present = 0;
  std::uint16_t reserved = 0;
  Status status = reader.read_u32(magic);
  if (status) status = reader.read_u8(version);
  if (status) status = reader.read_u8(present);
  if (status) status = reader.read_u16(reserved);
  if (!status || magic != kActiveMagic || version != kRecordVersion ||
      reserved != 0) {
    return reject(StatusCode::IntegrityError, "ACTIVE_RECORD_DECODE");
  }
  if (status) status = reader.read_u32(out.epoch.value);
  if (status) status = reader.read_u8(out.channel);
  std::uint8_t pad = 0;
  std::uint16_t pad16 = 0;
  if (status) status = reader.read_u8(pad);
  if (status) status = reader.read_u16(pad16);
  if (status && (pad != 0 || pad16 != 0)) {
    return reject(StatusCode::IntegrityError, "ACTIVE_RECORD_DECODE");
  }
  if (status) {
    status = reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  }
  if (!status) return reject(StatusCode::IntegrityError, "ACTIVE_RECORD_DECODE");
  const std::size_t body = reader.consumed();
  status = reader.read_u32(crc);
  if (!status || reader.remaining() != 0 ||
      crc32_iso_hdlc(ByteView{encoded.data, body}) != crc) {
    return reject(StatusCode::IntegrityError, "ACTIVE_RECORD_CRC");
  }
  out.present = present != 0;
  return Status::success();
}

// --- recovery snapshot codec -----------------------------------------------------------

Status snapshot_encode(const RecoverySnapshot& snapshot,
                       const MutableByteView target,
                       std::size_t& out_size) noexcept {
  out_size = 0;
  if (snapshot.plan_blob_size > snapshot.plan_blob.size()) {
    return reject(StatusCode::InvalidArgument, "snapshot blob overflow");
  }
  ByteWriter writer(target);
  Status status = writer.write_u8(kRecoverySnapshotVersion);
  if (status) status = writer.write_u8(0);
  if (status) status = write_operation(writer, snapshot.operation);
  if (status) {
    status = writer.write_bytes(ByteView{snapshot.plan_hash.data(), 32});
  }
  if (status) {
    status = writer.write_u16(
        static_cast<std::uint16_t>(snapshot.plan_blob_size));
  }
  if (status) {
    status = writer.write_bytes(
        ByteView{snapshot.plan_blob.data(), snapshot.plan_blob_size});
  }
  if (!status) return status;
  out_size = writer.size();
  return Status::success();
}

Status snapshot_decode(const ByteView encoded, RecoverySnapshot& out) noexcept {
  out = RecoverySnapshot{};
  ByteReader reader(encoded);
  std::uint8_t version = 0, reserved = 0;
  std::uint16_t blob_len = 0;
  Status status = reader.read_u8(version);
  if (status) status = reader.read_u8(reserved);
  if (!status || version != kRecoverySnapshotVersion || reserved != 0) {
    return reject(StatusCode::InvalidArgument, "SNAPSHOT_DECODE");
  }
  if (status) status = read_operation(reader, out.operation);
  if (status) {
    status = reader.read_bytes(MutableByteView{out.plan_hash.data(), 32});
  }
  if (status) status = reader.read_u16(blob_len);
  if (!status || blob_len == 0 || blob_len > out.plan_blob.size()) {
    return reject(StatusCode::InvalidArgument, "SNAPSHOT_DECODE");
  }
  status = reader.read_bytes(
      MutableByteView{out.plan_blob.data(), blob_len});
  if (!status || reader.remaining() != 0) {
    return reject(StatusCode::InvalidArgument, "SNAPSHOT_DECODE");
  }
  out.plan_blob_size = blob_len;
  return Status::success();
}

// --- MigrationParticipant --------------------------------------------------------------

MigrationParticipant::MigrationParticipant(
    const MigrationParticipantConfig& config, PlanStorage& storage,
    MigrationAuthority& authority, ChannelOperationRunner& runner,
    MigrationHooks* hooks) noexcept
    : config_(config),
      storage_(storage),
      authority_(authority),
      runner_(runner),
      hooks_(hooks),
      active_channel_(config.home_channel) {}

bool MigrationParticipant::in_progress() const noexcept {
  switch (phase_) {
    case ParticipantPhase::Preparing:
    case ParticipantPhase::Committed:
    case ParticipantPhase::Switching:
    case ParticipantPhase::Verifying:
      return true;
    default:
      return false;
  }
}

MonotonicMs MigrationParticipant::to_local(
    const MonotonicMs authority_ms) const noexcept {
  return map_to_local(clock_mapping_, authority_ms);
}

MonotonicMs MigrationParticipant::switch_time_local() const noexcept {
  return to_local(pending_plan_.switch_reference_ms);
}

Status MigrationParticipant::note_assess() noexcept {
  if (phase_ != ParticipantPhase::Stable) {
    return reject(StatusCode::InvalidState, "ASSESS_OUT_OF_ORDER");
  }
  phase_ = ParticipantPhase::Assess;
  return Status::success();
}

Status MigrationParticipant::note_survey_begin() noexcept {
  if (phase_ != ParticipantPhase::Assess) {
    return reject(StatusCode::InvalidState, "SURVEY_OUT_OF_ORDER");
  }
  phase_ = ParticipantPhase::Survey;
  return Status::success();
}

Status MigrationParticipant::note_survey_end() noexcept {
  if (phase_ != ParticipantPhase::Survey) {
    return reject(StatusCode::InvalidState, "SURVEY_END_OUT_OF_ORDER");
  }
  phase_ = ParticipantPhase::Stable;
  return Status::success();
}

// --- storage helpers ---------------------------------------------------------------

Status MigrationParticipant::store_blob_verified(const Digest256& hash,
                                                 const ByteView blob) noexcept {
  // Step 1 of the §6 order: land the blob hash-addressed, then prove the
  // durable copy by readback. A mismatch is a storage fault, never a usable
  // blob.
  Status status = storage_.write_blob(hash, blob);
  if (!status) return status;
  std::array<std::uint8_t, migration_const::kPlanBlobMax> verify{};
  std::size_t verify_size = 0;
  status =
      storage_.read_blob(hash, MutableByteView{verify.data(), verify.size()},
                         verify_size);
  if (!status) return status;
  if (verify_size != blob.size ||
      std::memcmp(verify.data(), blob.data, blob.size) != 0) {
    return reject(StatusCode::StorageFailure, "PLAN_BLOB_READBACK_MISMATCH");
  }
  return Status::success();
}

Status MigrationParticipant::store_commit_record(
    const CommitRecord& record) noexcept {
  std::array<std::uint8_t, migration_const::kCommitRecordSize> buffer{};
  std::size_t size = 0;
  CommitRecord durable = record;
  durable.present = true;
  Status status = commit_record_encode(
      durable, MutableByteView{buffer.data(), buffer.size()}, size);
  if (!status) return status;
  status = storage_.write_commit_record(ByteView{buffer.data(), size});
  if (!status) return status;
  // Readback: the commit record is what re-applies after active-record loss,
  // so its durable copy must verify before COMMITTED is entered (04 §6).
  std::array<std::uint8_t, migration_const::kCommitRecordSize> check{};
  std::size_t check_size = 0;
  status = storage_.read_commit_record(
      MutableByteView{check.data(), check.size()}, check_size);
  if (!status) return status;
  if (check_size != size ||
      std::memcmp(check.data(), buffer.data(), size) != 0) {
    return reject(StatusCode::StorageFailure, "COMMIT_RECORD_READBACK_MISMATCH");
  }
  return Status::success();
}

Status MigrationParticipant::store_active_record(
    const ActiveRecord& record) noexcept {
  std::array<std::uint8_t, migration_const::kActiveRecordSize> buffer{};
  std::size_t size = 0;
  ActiveRecord durable = record;
  durable.present = true;
  Status status = active_record_encode(
      durable, MutableByteView{buffer.data(), buffer.size()}, size);
  if (!status) return status;
  return storage_.write_active_record(ByteView{buffer.data(), size});
}

// --- plan validation -------------------------------------------------------------------

Status MigrationParticipant::validate_plan(
    const MigrationPlan& plan, const PlanMeasurements& m,
    const MonotonicMs now_ms) const noexcept {
  if (plan.network != config_.network) {
    return reject(StatusCode::InvalidArgument, "PLAN_NETWORK_MISMATCH");
  }
  if (plan.authority != config_.authority) {
    // A gateway's signature on another identity earns no approval right.
    return reject(StatusCode::AuthorizationFailed, "PLAN_AUTHORITY_MISMATCH");
  }
  if (plan.old_channel == 0 || plan.old_channel > 13 ||
      plan.new_channel == 0 || plan.new_channel > 13 ||
      plan.old_channel == plan.new_channel) {
    return reject(StatusCode::InvalidArgument, "PLAN_CHANNEL_INVALID");
  }
  // Epochs are strictly monotone: a replayed or regressed plan is refused
  // and never rewinds committed/active state.
  if (plan.new_epoch.value <= committed_epoch_.value ||
      plan.new_epoch.value <= active_epoch_.value) {
    return reject(StatusCode::Conflict, "EPOCH_NOT_MONOTONIC");
  }
  if (plan.old_epoch != committed_epoch_ ||
      plan.old_channel != active_channel_) {
    return reject(StatusCode::Conflict, "PLAN_BASE_MISMATCH");
  }
  if (plan.mapping.uncertainty_ms > config_.clock_uncertainty_max_ms) {
    return reject(StatusCode::ClockUncertain, "CLOCK_UNCERTAIN");
  }
  if (plan.guard_ms <
      required_guard_ms(plan.mapping.uncertainty_ms,
                        m.measured_switch_bound_ms)) {
    return reject(StatusCode::InvalidArgument, "PLAN_GUARD_BELOW_BOUND");
  }
  // The standard 30s prepare window stands — but a plan whose required
  // management transfer cannot fit inside it is rejected, never squeezed.
  if (m.required_transfer_ms > config_.prepare_timeout_ms) {
    return reject(StatusCode::InvalidArgument, "PLAN_TRANSFER_OVER_BUDGET");
  }
  // COMMIT lead is the largest of {5s, 4*RTT_P99, delivery bound}; the
  // switch must leave room for the transfer AND that lead.
  const MonotonicMs switch_local =
      map_to_local(plan.mapping, plan.switch_reference_ms);
  const std::uint64_t need =
      static_cast<std::uint64_t>(m.required_transfer_ms) +
      required_commit_lead_ms(m.management_rtt_p99_ms,
                              m.control_delivery_bound_ms);
  if (switch_local < now_ms + need) {
    return reject(StatusCode::InvalidArgument, "COMMIT_LEAD_INSUFFICIENT");
  }
  const MonotonicMs expiry_local =
      map_to_local(plan.mapping, plan.expiry_ms);
  if (expiry_local <= switch_local + plan.guard_ms) {
    return reject(StatusCode::InvalidArgument, "PLAN_EXPIRY_BEFORE_GUARD");
  }
  if (plan.max_outage_ms == 0) {
    return reject(StatusCode::InvalidArgument, "PLAN_OUTAGE_BUDGET_MISSING");
  }
  if (plan.recovery.present) {
    const HelperSchedule& s = plan.recovery;
    if (s.visit_period_ms == 0 || s.dwell_ms == 0 ||
        s.dwell_ms > s.visit_period_ms ||
        s.window_end_ms <= s.window_begin_ms) {
      return reject(StatusCode::InvalidArgument, "RECOVERY_SCHEDULE_INVALID");
    }
  }
  return Status::success();
}

// --- prepare / commit --------------------------------------------------------------------

Status MigrationParticipant::prepare(const ByteView plan_blob,
                                     const PlanMeasurements& measurements,
                                     const MonotonicMs now_ms) noexcept {
  if (plan_blob.data == nullptr || plan_blob.size == 0 ||
      plan_blob.size > migration_const::kPlanBlobMax) {
    ++stats_.plans_rejected;
    return reject(StatusCode::InvalidArgument, "PLAN_BLOB_SIZE");
  }
  MigrationPlan plan{};
  Status status = plan_decode(plan_blob, plan);
  if (!status) {
    ++stats_.plans_rejected;
    return status;
  }
  const Digest256 hash = plan_digest(plan_blob);
  if (awaiting_blob_) {
    // Refetch path: the stored commit references exactly one blob digest.
    // Anything else is refused — a missing blob is never substituted (04 §6).
    if (hash != commit_plan_hash_ || plan.new_epoch != committed_epoch_) {
      ++stats_.plans_rejected;
      return reject(StatusCode::IntegrityError, "BLOB_NOT_COMMITTED");
    }
    if (plan.network != config_.network ||
        plan.authority != config_.authority) {
      ++stats_.plans_rejected;
      return reject(StatusCode::AuthorizationFailed, "PLAN_SCOPE_MISMATCH");
    }
    if (plan.mapping.uncertainty_ms > config_.clock_uncertainty_max_ms) {
      ++stats_.plans_rejected;
      return reject(StatusCode::ClockUncertain, "CLOCK_UNCERTAIN");
    }
    status = store_blob_verified(hash, plan_blob);
    if (!status) return status;
    pending_plan_ = plan;
    pending_hash_ = hash;
    plan_known_ = true;
    clock_mapping_ = plan.mapping;
    clock_valid_ = true;
    awaiting_blob_ = false;
    helper_index_ = static_cast<std::size_t>(-1);
    helper_visit_active_ = false;
    phase_ = ParticipantPhase::Committed;
    ++stats_.plans_prepared;
    return Status::success();
  }
  switch (phase_) {
    case ParticipantPhase::Stable:
    case ParticipantPhase::Assess:
    case ParticipantPhase::Survey:
    case ParticipantPhase::Aborted:
    case ParticipantPhase::Recovering:
    case ParticipantPhase::RecoveryRequired:
      break;
    default:
      ++stats_.plans_rejected;
      return reject(StatusCode::InvalidState, "PLAN_IN_PROGRESS");
  }
  if (now_ms < cooldown_until_ms_) {
    // The inter-plan cooldown is honored on the participant too: failures
    // never ping-pong (04 §10).
    ++stats_.plans_rejected;
    return reject(StatusCode::Busy, "PLAN_COOLDOWN");
  }
  status = validate_plan(plan, measurements, now_ms);
  if (!status) {
    ++stats_.plans_rejected;
    return status;
  }
  status = store_blob_verified(hash, plan_blob);
  if (!status) return status;
  pending_plan_ = plan;
  pending_hash_ = hash;
  plan_known_ = true;
  clock_mapping_ = plan.mapping;
  clock_valid_ = true;
  helper_index_ = static_cast<std::size_t>(-1);
  helper_visit_active_ = false;
  prepare_deadline_ms_ = now_ms + config_.prepare_timeout_ms;
  phase_ = ParticipantPhase::Preparing;
  ++stats_.plans_prepared;
  return Status::success();
}

Status MigrationParticipant::commit(const VerifiedAuthorityPlan& verified,
                                    const AuthorityOperation& operation,
                                    const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!verified.valid()) {
    // Commit evidence that did not pass real verification is never accepted
    // (D5-01): a blob alone — or a bare claim — never switches.
    ++stats_.commit_rejects;
    return reject(StatusCode::AuthenticationFailed, "UNVERIFIED_COMMIT_EVIDENCE");
  }
  if (verified.operation_hash() != operation.operation_hash ||
      verified.sequence() != operation.sequence) {
    ++stats_.commit_rejects;
    return reject(StatusCode::IntegrityError, "COMMIT_OPERATION_MISMATCH");
  }
  if (operation.network != config_.network ||
      operation.authority != config_.authority) {
    ++stats_.commit_rejects;
    return reject(StatusCode::AuthorizationFailed, "COMMIT_SCOPE_MISMATCH");
  }
  if (committed_epoch_.value != 0 &&
      verified.plan_hash() == commit_plan_hash_ &&
      verified.new_epoch() == committed_epoch_) {
    // Re-delivery of the commit already durably stored: idempotent
    // success — including while RECOVERING waiting on the blob refetch.
    return Status::success();
  }
  CommitRecord record{};
  record.operation = operation;
  record.plan_hash = verified.plan_hash();
  record.new_epoch = verified.new_epoch();
  switch (phase_) {
    case ParticipantPhase::Preparing:
      if (verified.plan_hash() != pending_hash_ ||
          verified.new_epoch() != pending_plan_.new_epoch ||
          verified.sequence() != pending_plan_.operation_sequence) {
        // The commit references a different blob/epoch/sequence than the
        // PREPARED one: refused, never silently re-bound.
        ++stats_.commit_rejects;
        return reject(StatusCode::IntegrityError, "COMMIT_BLOB_MISMATCH");
      }
      break;
    case ParticipantPhase::Committed:
      if (verified.plan_hash() == commit_plan_hash_ &&
          verified.new_epoch() == committed_epoch_) {
        return Status::success();  // idempotent re-commit of the same plan
      }
      ++stats_.commit_rejects;
      return reject(StatusCode::Conflict, "COMMIT_ALREADY_COMMITTED");
    case ParticipantPhase::Stable:
    case ParticipantPhase::Assess:
    case ParticipantPhase::Survey:
    case ParticipantPhase::Aborted:
    case ParticipantPhase::Recovering:
    case ParticipantPhase::RecoveryRequired:
      if (verified.new_epoch().value <= committed_epoch_.value) {
        ++stats_.commit_rejects;
        return reject(StatusCode::Conflict, "COMMIT_STALE");
      }
      break;
    case ParticipantPhase::Switching:
    case ParticipantPhase::Verifying:
      // A different commit arriving mid-cutover cannot be safely bound;
      // recovery snapshots carry stragglers instead.
      ++stats_.commit_rejects;
      return reject(StatusCode::InvalidState, "COMMIT_DURING_CUTOVER");
  }
  const Status stored = store_commit_record(record);
  if (!stored) return stored;
  commit_plan_hash_ = verified.plan_hash();
  committed_epoch_ = verified.new_epoch();
  ++stats_.commits;
  if (phase_ == ParticipantPhase::Preparing) {
    phase_ = ParticipantPhase::Committed;
    return Status::success();
  }
  if (plan_known_ && pending_hash_ == verified.plan_hash()) {
    // Blob already stored: follow the committed plan directly.
    phase_ = ParticipantPhase::Committed;
    return Status::success();
  }
  // Commit evidence without the blob: durable record kept, the blob is
  // refetched — never fabricated (04 §6).
  awaiting_blob_ = true;
  phase_ = ParticipantPhase::Recovering;
  ++stats_.blob_refetches;
  return Status::success();
}

Status MigrationParticipant::note_commit_evidence(
    const AuthorityOperation& operation, const Digest256& plan_hash,
    const ChannelEpoch new_epoch, const ByteView signature,
    const MonotonicMs now_ms) noexcept {
  VerifiedAuthorityPlan verified{};
  const Status checked = authority_.verify_commit(
      operation, plan_hash, new_epoch, signature, verified);
  if (!checked) {
    ++stats_.commit_rejects;
    return checked;
  }
  return commit(verified, operation, now_ms);
}

Status MigrationParticipant::note_clock(const ClockMapping& mapping,
                                        const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (mapping.uncertainty_ms > config_.clock_uncertainty_max_ms) {
    // Over-bound uncertainty never re-arms the clock (D5-03); the old
    // validity state is kept as-is.
    return reject(StatusCode::ClockUncertain, "CLOCK_UNCERTAIN");
  }
  clock_mapping_ = mapping;
  clock_valid_ = true;
  return Status::success();
}

// --- recovery ---------------------------------------------------------------------------

Status MigrationParticipant::adopt_snapshot(const ByteView snapshot,
                                            const ByteView signature,
                                            const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (phase_ == ParticipantPhase::Switching) {
    ++stats_.snapshots_rejected;
    return reject(StatusCode::InvalidState, "SNAPSHOT_DURING_CUTOVER");
  }
  Status status = authority_.verify_snapshot(snapshot, signature);
  if (!status) {
    ++stats_.snapshots_rejected;
    return status;
  }
  RecoverySnapshot snap{};
  status = snapshot_decode(snapshot, snap);
  if (!status) {
    ++stats_.snapshots_rejected;
    return status;
  }
  if (snap.operation.network != config_.network ||
      snap.operation.authority != config_.authority ||
      snap.operation.kind != AuthorityOperationKind::ChannelMigration) {
    ++stats_.snapshots_rejected;
    return reject(StatusCode::AuthorizationFailed, "SNAPSHOT_SCOPE_MISMATCH");
  }
  const Digest256 bound =
      bind_operation_payload(AuthorityOperationKind::ChannelMigration,
                             ByteView{snap.plan_hash.data(), 32});
  if (snap.operation.operation_hash != bound ||
      plan_digest(ByteView{snap.plan_blob.data(), snap.plan_blob_size}) !=
          snap.plan_hash) {
    // Snapshot content must be self-consistent: operation binds the hash,
    // the hash addresses the blob.
    ++stats_.snapshots_rejected;
    return reject(StatusCode::IntegrityError, "SNAPSHOT_BINDING_MISMATCH");
  }
  MigrationPlan plan{};
  status = plan_decode(
      ByteView{snap.plan_blob.data(), snap.plan_blob_size}, plan);
  if (!status) {
    ++stats_.snapshots_rejected;
    return status;
  }
  if (plan.network != config_.network || plan.authority != config_.authority ||
      plan.operation_sequence != snap.operation.sequence) {
    ++stats_.snapshots_rejected;
    return reject(StatusCode::AuthorizationFailed, "SNAPSHOT_PLAN_MISMATCH");
  }
  if (plan.mapping.uncertainty_ms > config_.clock_uncertainty_max_ms) {
    ++stats_.snapshots_rejected;
    return reject(StatusCode::ClockUncertain, "CLOCK_UNCERTAIN");
  }
  if (plan.new_epoch.value <= committed_epoch_.value) {
    // Stale or replayed snapshot: epochs never rewind. The newest signed
    // snapshot always wins — a node that skipped generations converges on
    // the LATEST state, not the previous one (D5-07).
    ++stats_.snapshots_rejected;
    return reject(StatusCode::Conflict, "SNAPSHOT_STALE");
  }
  status = store_blob_verified(
      snap.plan_hash,
      ByteView{snap.plan_blob.data(), snap.plan_blob_size});
  if (!status) return status;
  CommitRecord record{};
  record.operation = snap.operation;
  record.plan_hash = snap.plan_hash;
  record.new_epoch = plan.new_epoch;
  status = store_commit_record(record);
  if (!status) return status;
  pending_plan_ = plan;
  pending_hash_ = snap.plan_hash;
  plan_known_ = true;
  commit_plan_hash_ = snap.plan_hash;
  committed_epoch_ = plan.new_epoch;
  clock_mapping_ = plan.mapping;
  clock_valid_ = true;
  awaiting_blob_ = false;
  helper_index_ = static_cast<std::size_t>(-1);
  helper_visit_active_ = false;
  phase_ = ParticipantPhase::Committed;
  ++stats_.snapshots_accepted;
  return Status::success();
}

bool MigrationParticipant::helper_role() const noexcept {
  if (!plan_known_ || !pending_plan_.recovery.present) return false;
  for (std::size_t i = 0; i < pending_plan_.recovery.helper_count; ++i) {
    if (pending_plan_.recovery.helpers[i] == config_.node) return true;
  }
  return false;
}

bool MigrationParticipant::next_helper_window(
    const MonotonicMs now_ms, MonotonicMs& begin_ms,
    MonotonicMs& end_ms) const noexcept {
  if (!plan_known_ || !pending_plan_.recovery.present || !clock_valid_) {
    return false;
  }
  const HelperSchedule& s = pending_plan_.recovery;
  const MonotonicMs now_auth = map_to_authority(clock_mapping_, now_ms);
  if (now_auth >= s.window_end_ms) return false;
  std::size_t index = 0;
  if (now_auth > s.window_begin_ms && s.visit_period_ms != 0) {
    index = static_cast<std::size_t>((now_auth - s.window_begin_ms) /
                                     s.visit_period_ms);
  }
  // Bounded scan forward for the first window not already over.
  for (std::size_t attempts = 0; attempts < 128; ++attempts, ++index) {
    const MonotonicMs begin_auth =
        s.window_begin_ms + index * s.visit_period_ms;
    const MonotonicMs end_auth = begin_auth + s.dwell_ms;
    if (begin_auth >= s.window_end_ms || end_auth > s.window_end_ms) {
      return false;  // committed helper budget exhausted
    }
    if (end_auth > now_auth) {
      begin_ms = to_local(begin_auth);
      end_ms = to_local(end_auth);
      return true;
    }
  }
  return false;
}

MonotonicMs MigrationParticipant::recovery_window_end_local() const noexcept {
  if (!plan_known_ || !pending_plan_.recovery.present || !clock_valid_) {
    return 0;
  }
  return to_local(pending_plan_.recovery.window_end_ms);
}

bool MigrationParticipant::recovery_assumptions_satisfiable(
    const std::uint32_t hops, const std::uint32_t loss_windows,
    const std::uint32_t transfer_bound_ms,
    const std::uint32_t margin_ms) const noexcept {
  if (!plan_known_ || !pending_plan_.recovery.present) return false;
  const HelperSchedule& s = pending_plan_.recovery;
  const std::uint64_t bound =
      recovery_bound_ms(hops, loss_windows, s.visit_period_ms,
                        transfer_bound_ms, margin_ms);
  return bound <= (s.window_end_ms - s.window_begin_ms);
}

void MigrationParticipant::enter_recovering(
    const bool stranded_on_old) noexcept {
  if (data_held_ && hooks_ != nullptr) hooks_->hold_data(false);
  data_held_ = false;
  cutover_ = CutoverStep::None;
  recovery_retry_pending_ = stranded_on_old;
  phase_ = ParticipantPhase::Recovering;
}

void MigrationParticipant::note_recovery_violation(
    const MonotonicMs now_ms) noexcept {
  if (phase_ == ParticipantPhase::RecoveryRequired) return;
  if (data_held_ && hooks_ != nullptr) hooks_->hold_data(false);
  data_held_ = false;
  cutover_ = CutoverStep::None;
  recovery_retry_pending_ = false;
  phase_ = ParticipantPhase::RecoveryRequired;
  latch_cooldown(now_ms);
  ++stats_.recovery_required;
}

void MigrationParticipant::note_verify_failure() noexcept {
  if (phase_ != ParticipantPhase::Verifying) return;
  // The switch applied but the new channel did not verify: stranded-side
  // recovery. No unilateral rollback — only a new signed plan may move us.
  enter_recovering(false);
}

void MigrationParticipant::latch_cooldown(const MonotonicMs now_ms) noexcept {
  cooldown_until_ms_ = now_ms + config_.cooldown_ms;
}

// --- cutover ------------------------------------------------------------------------------

void MigrationParticipant::begin_cutover(const MonotonicMs now_ms) noexcept {
  // Ordered §8 sequence: DATA admission/intake hold FIRST (the reserved
  // control lane stays unmasked), then the runner performs the
  // deadline-preserving drain -> TX fence -> set_channel -> readback ->
  // peer reapply -> generation bump. The engine never touches the driver
  // directly and never assigns config_.channel around the runner.
  if (hooks_ != nullptr) hooks_->hold_data(true);
  data_held_ = true;
  RadioOperation op{};
  op.kind = RadioOperationKind::ChannelCutover;
  // The guard bounds the operation from when it actually starts, not from
  // the scheduled reference: apply-on-resume happens after the reference
  // passed and must still get its full deadline-preserving drain window.
  op.deadline_ms = now_ms + pending_plan_.guard_ms;
  op.constraints.channel = pending_plan_.new_channel;
  op.constraints.outage_permitted = true;  // the plan grants the bounded outage
  cutover_token_ = runner_.request(op, now_ms);
  cutover_ = CutoverStep::Requested;
  phase_ = ParticipantPhase::Switching;
}

void MigrationParticipant::finish_cutover_applied(
    const MonotonicMs now_ms) noexcept {
  // Order after the verified readback: durable active record -> clock/
  // observation generation update -> DATA resume (04 §8).
  ActiveRecord record{};
  record.epoch = pending_plan_.new_epoch;
  record.channel = pending_plan_.new_channel;
  record.plan_hash = pending_hash_;
  // A lost active record is safe: the stored commit re-applies idempotently
  // on resume, so the apply is never gated on this write (04 §6).
  (void)store_active_record(record);
  active_epoch_ = pending_plan_.new_epoch;
  active_channel_ = pending_plan_.new_channel;
  if (hooks_ != nullptr) {
    hooks_->note_cutover_generation(runner_.radio_generation().value);
  }
  if (hooks_ != nullptr) hooks_->hold_data(false);
  data_held_ = false;
  cutover_ = CutoverStep::None;
  verify_deadline_ms_ = now_ms + config_.verify_ms;
  phase_ = ParticipantPhase::Verifying;
  ++stats_.cutovers_applied;
}

// --- helper visits ---------------------------------------------------------------------------

void MigrationParticipant::poll_helper(const MonotonicMs now_ms) noexcept {
  if (!helper_role() || !clock_valid_) return;
  if (phase_ != ParticipantPhase::Verifying &&
      phase_ != ParticipantPhase::Stable) {
    return;
  }
  if (helper_visit_active_) {
    OperationResult result{};
    if (runner_.result(helper_token_, result) &&
        result.outcome != OperationOutcome::Pending) {
      // Visit consumed (any outcome): the schedule moves on. A helper never
      // lingers on the old channel past the committed dwell.
      helper_visit_active_ = false;
      if (hooks_ != nullptr) {
        hooks_->helper_visit(false, pending_plan_.old_channel);
      }
    }
    return;
  }
  const HelperSchedule& s = pending_plan_.recovery;
  const MonotonicMs now_auth = map_to_authority(clock_mapping_, now_ms);
  if (now_auth >= s.window_end_ms) return;  // budget over: never visit again
  std::size_t index = 0;
  if (now_auth > s.window_begin_ms) {
    index = static_cast<std::size_t>((now_auth - s.window_begin_ms) /
                                     s.visit_period_ms);
  }
  const MonotonicMs begin_auth =
      s.window_begin_ms + index * s.visit_period_ms;
  const MonotonicMs end_auth = begin_auth + s.dwell_ms;
  if (begin_auth >= s.window_end_ms || end_auth > s.window_end_ms) return;
  if (now_auth < begin_auth || index == helper_index_) return;
  // A bounded visit on the OLD channel; the runner serializes it like any
  // other radio operation. This is a migration-time outage budget, not a
  // permanent second channel (04 §9.2).
  RadioOperation op{};
  op.kind = RadioOperationKind::SurveyVisit;
  op.deadline_ms = to_local(end_auth);
  op.constraints.channel = pending_plan_.old_channel;
  op.constraints.max_duration_ms = s.dwell_ms;
  op.constraints.outage_permitted = true;
  helper_token_ = runner_.request(op, now_ms);
  helper_index_ = index;
  helper_visit_active_ = true;
  ++stats_.helper_visits;
  if (hooks_ != nullptr) {
    hooks_->helper_visit(true, pending_plan_.old_channel);
  }
}

// --- poll / resume -----------------------------------------------------------------------------

void MigrationParticipant::poll(const MonotonicMs now_ms) noexcept {
  switch (phase_) {
    case ParticipantPhase::Preparing:
      if (now_ms >= prepare_deadline_ms_) {
        // Prepare deadline with no verified commit: ABORTED keeps the
        // active configuration exactly as it was (D5-01). A verified commit
        // arriving later can still be adopted via commit().
        phase_ = ParticipantPhase::Aborted;
        latch_cooldown(now_ms);
        ++stats_.aborts;
      }
      break;
    case ParticipantPhase::Committed:
      // No timed switch without a valid clock; after a restart only a fresh
      // authenticated sample or snapshot re-arms it (D5-03).
      if (clock_valid_ && now_ms >= switch_time_local()) {
        begin_cutover(now_ms);
      }
      break;
    case ParticipantPhase::Switching: {
      OperationResult result{};
      const bool found = runner_.result(cutover_token_, result);
      if (!found) {
        // Lost operation evidence while the runner is idle: the radio state
        // is unknown — resolve INDETERMINATE-safe, never assume.
        if (!runner_.busy()) note_recovery_violation(now_ms);
        break;
      }
      switch (result.outcome) {
        case OperationOutcome::Pending:
          break;
        case OperationOutcome::Applied:
          finish_cutover_applied(now_ms);
          break;
        case OperationOutcome::Failed:
        case OperationOutcome::Rejected:
          // Verified still on the OLD channel while the mesh moved:
          // stranded-node recovery with the commit already held — ONE
          // bounded re-follow is allowed (04 §9.1), never a blind move and
          // never a retry loop.
          enter_recovering(recovery_retry_available_);
          recovery_retry_available_ = false;
          break;
        case OperationOutcome::Indeterminate:
          // Post-fence unknown: the channel state cannot be proven — this
          // is the RECOVERY_REQUIRED boundary, not a quiet failure.
          note_recovery_violation(now_ms);
          break;
      }
      break;
    }
    case ParticipantPhase::Verifying:
      if (now_ms >= verify_deadline_ms_) {
        phase_ = ParticipantPhase::Stable;
        latch_cooldown(now_ms);
      }
      break;
    case ParticipantPhase::Recovering:
      if (recovery_retry_pending_ && plan_known_ && clock_valid_ &&
          !runner_.busy() && now_ms >= switch_time_local()) {
        // Verified commit already held: re-follow once. A repeated failure
        // stays Recovering until the committed budget ends — no loop.
        recovery_retry_pending_ = false;
        begin_cutover(now_ms);
        break;
      }
      if (plan_known_ && pending_plan_.recovery.present && clock_valid_ &&
          now_ms > recovery_window_end_local()) {
        // Helper budget exhausted without recovery (04 §9.3): bounded
        // low-frequency discovery may continue, but the strong recovery
        // SLO is over.
        note_recovery_violation(now_ms);
      }
      break;
    default:
      break;
  }
  poll_helper(now_ms);
}

Status MigrationParticipant::resume(const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  // A restart loses the monotonic time mapping: the stored mapping is NEVER
  // reused. The clock stays disarmed until a fresh authenticated sample or
  // the latest signed commit state arrives (D5-03).
  clock_valid_ = false;
  awaiting_blob_ = false;
  cutover_ = CutoverStep::None;
  data_held_ = false;
  helper_visit_active_ = false;
  helper_index_ = static_cast<std::size_t>(-1);
  recovery_retry_pending_ = false;
  recovery_retry_available_ = true;

  ActiveRecord active{};
  {
    std::array<std::uint8_t, migration_const::kActiveRecordSize> raw{};
    std::size_t size = 0;
    const Status read = storage_.read_active_record(
        MutableByteView{raw.data(), raw.size()}, size);
    if (read.ok()) {
      const Status decoded =
          active_record_decode(ByteView{raw.data(), size}, active);
      if (!decoded) return decoded;  // corrupt durable state: surface, never guess
    } else if (read.code != StatusCode::NotFound) {
      return read;  // a storage fault is not "no record"
    }
  }
  CommitRecord commit{};
  {
    std::array<std::uint8_t, migration_const::kCommitRecordSize> raw{};
    std::size_t size = 0;
    const Status read = storage_.read_commit_record(
        MutableByteView{raw.data(), raw.size()}, size);
    if (read.ok()) {
      const Status decoded =
          commit_record_decode(ByteView{raw.data(), size}, commit);
      if (!decoded) return decoded;
    } else if (read.code != StatusCode::NotFound) {
      return read;
    }
  }

  if (!commit.present) {
    // No verified commit: the durable active record (if any) reports the
    // last applied channel — a sleep image is never consulted for it.
    if (active.present) {
      active_epoch_ = active.epoch;
      active_channel_ = active.channel;
    }
    phase_ = ParticipantPhase::Stable;
    return Status::success();
  }

  commit_plan_hash_ = commit.plan_hash;
  committed_epoch_ = commit.new_epoch;

  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size = 0;
  const Status blob_read = storage_.read_blob(
      commit.plan_hash, MutableByteView{blob.data(), blob.size()}, blob_size);
  MigrationPlan plan{};
  bool blob_ok = false;
  if (blob_read.ok()) {
    blob_ok = plan_decode(ByteView{blob.data(), blob_size}, plan).ok() &&
              plan_digest(ByteView{blob.data(), blob_size}) == commit.plan_hash;
  }
  if (!blob_ok) {
    // The ledger/commit record references a blob we cannot prove: refetch
    // (or quarantine), never fabricate the missing configuration (04 §6).
    awaiting_blob_ = true;
    phase_ = ParticipantPhase::Recovering;
    ++stats_.blob_refetches;
    return blob_read.ok() ? reject(StatusCode::IntegrityError, "PLAN_BLOB_CORRUPT")
                          : Status::success();
  }

  pending_plan_ = plan;
  pending_hash_ = commit.plan_hash;
  plan_known_ = true;
  clock_mapping_ = plan.mapping;  // held for later re-arm, NOT trusted yet
  if (active.present && active.epoch.value >= commit.new_epoch.value) {
    // Already applied before the restart: restore the durable record only.
    active_epoch_ = active.epoch;
    active_channel_ = active.channel;
    phase_ = ParticipantPhase::Stable;
    return Status::success();
  }
  // Committed but never applied (or active record lost): idempotent
  // re-apply — the engine re-enters Committed and, once a fresh clock
  // re-arms, follows the same switch path (apply-on-resume, 04 §6/§8).
  phase_ = ParticipantPhase::Committed;
  return Status::success();
}

}  // namespace routeloom
