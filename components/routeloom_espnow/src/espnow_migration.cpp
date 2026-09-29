#include "routeloom/espnow_migration.hpp"

#include <cstdio>
#include <cstring>

#include "esp_err.h"
#include "esp_log.h"
#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"

namespace routeloom::espnow {
namespace {

constexpr const char* kTag = "rl_migrate";

Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    return Status::error(StatusCode::NotFound, detail);
  }
  return Status::error(StatusCode::StorageFailure, detail);
}

}  // namespace

// --- NvsPlanStore ----------------------------------------------------------------

NvsPlanStore::~NvsPlanStore() { close(); }

Status NvsPlanStore::open(const char* name_space) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS namespace missing");
  }
  close();
  const esp_err_t error = nvs_open(name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_open failed");
  open_ = true;
  return Status::success();
}

void NvsPlanStore::close() noexcept {
  if (open_) nvs_close(handle_);
  handle_ = 0;
  open_ = false;
}

Status NvsPlanStore::read_key(const char* key, const MutableByteView target,
                              std::size_t& out_size) noexcept {
  out_size = 0;
  if (!open_ || key == nullptr || target.data == nullptr) {
    return Status::error(StatusCode::InvalidState, "plan store not ready");
  }
  std::size_t actual = 0;
  esp_err_t error = nvs_get_blob(handle_, key, nullptr, &actual);
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob size failed");
  if (actual > target.size) {
    // Never fabricate: an oversized record is a storage fault, and the
    // caller's buffer is left untouched.
    return Status::error(StatusCode::StorageFailure,
                         "stored record exceeds bound");
  }
  error = nvs_get_blob(handle_, key, target.data, &actual);
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob failed");
  out_size = actual;
  return Status::success();
}

Status NvsPlanStore::write_key(const char* key, const ByteView data) noexcept {
  if (!open_ || key == nullptr || data.data == nullptr || data.size == 0) {
    return Status::error(StatusCode::InvalidState, "plan store not ready");
  }
  esp_err_t error = nvs_set_blob(handle_, key, data.data, data.size);
  if (error != ESP_OK) return nvs_status(error, "nvs_set_blob failed");
  error = nvs_commit(handle_);
  return nvs_status(error, "nvs_commit failed");
}

Status NvsPlanStore::read_blob_slot(const std::uint8_t slot, Digest256& hash,
                                    std::uint32_t& seq,
                                    const MutableByteView blob,
                                    std::size_t& blob_size) noexcept {
  hash = Digest256{};
  seq = 0;
  blob_size = 0;
  char key[8]{};
  std::snprintf(key, sizeof(key), "pb%u", static_cast<unsigned>(slot));
  std::array<std::uint8_t, kBlobRecordSize> raw{};
  std::size_t size = 0;
  Status status = read_key(key, MutableByteView{raw.data(), raw.size()}, size);
  if (!status) return status;
  if (size < 42) {
    return Status::error(StatusCode::IntegrityError, "blob slot truncated");
  }
  ByteReader reader{ByteView{raw.data(), size}};
  std::uint32_t magic = 0;
  std::uint16_t length = 0;
  status = reader.read_u32(magic);
  if (status) status = reader.read_u32(seq);
  if (status) status = reader.read_bytes(MutableByteView{hash.data(), 32});
  if (status) status = reader.read_u16(length);
  if (!status || magic != kBlobMagic || length > blob.size ||
      reader.remaining() != static_cast<std::size_t>(length) + 4) {
    return Status::error(StatusCode::IntegrityError, "blob slot corrupt");
  }
  status = reader.read_bytes(MutableByteView{blob.data, length});
  std::uint32_t crc = 0;
  if (status) status = reader.read_u32(crc);
  if (!status ||
      crc32_iso_hdlc(ByteView{raw.data(), reader.consumed() - 4}) != crc) {
    return Status::error(StatusCode::IntegrityError, "blob slot corrupt");
  }
  blob_size = length;
  return Status::success();
}

Status NvsPlanStore::write_blob_slot(const std::uint8_t slot,
                                     const std::uint32_t seq,
                                     const Digest256& hash,
                                     const ByteView blob) noexcept {
  char key[8]{};
  std::snprintf(key, sizeof(key), "pb%u", static_cast<unsigned>(slot));
  std::array<std::uint8_t, kBlobRecordSize> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  Status status = writer.write_u32(kBlobMagic);
  if (status) status = writer.write_u32(seq);
  if (status) status = writer.write_bytes(ByteView{hash.data(), 32});
  if (status) {
    status = writer.write_u16(static_cast<std::uint16_t>(blob.size));
  }
  if (status) status = writer.write_bytes(blob);
  if (status) {
    status = writer.write_u32(
        crc32_iso_hdlc(ByteView{raw.data(), writer.size()}));
  }
  if (!status) return status;
  return write_key(key, ByteView{raw.data(), writer.size()});
}

Status NvsPlanStore::write_blob(const Digest256& hash,
                                const ByteView blob) noexcept {
  if (blob.data == nullptr || blob.size == 0 ||
      blob.size > migration_const::kPlanBlobMax) {
    return Status::error(StatusCode::InvalidArgument, "blob out of bounds");
  }
  // Slot selection: hash match first (in-place update), then an empty or
  // corrupt slot, then the lower-sequence slot — bounded two-slot LRU.
  std::uint32_t seqs[kBlobSlots]{};
  bool valid[kBlobSlots]{};
  int match = -1;
  int free_slot = -1;
  for (std::uint8_t i = 0; i < kBlobSlots; ++i) {
    Digest256 slot_hash{};
    std::uint32_t seq = 0;
    std::array<std::uint8_t, migration_const::kPlanBlobMax> scratch{};
    std::size_t scratch_size = 0;
    const Status status =
        read_blob_slot(i, slot_hash, seq,
                       MutableByteView{scratch.data(), scratch.size()},
                       scratch_size);
    if (!status) {
      if (status.code == StatusCode::NotFound && free_slot < 0) {
        free_slot = i;
      }
      continue;
    }
    valid[i] = true;
    seqs[i] = seq;
    if (slot_hash == hash) match = i;
  }
  std::uint8_t target = 0;
  std::uint32_t seq = 1;
  if (match >= 0) {
    target = static_cast<std::uint8_t>(match);
    seq = seqs[target] + 1;
  } else if (free_slot >= 0) {
    target = static_cast<std::uint8_t>(free_slot);
  } else {
    // Both slots hold other blobs: evict the lower sequence.
    target = seqs[0] <= seqs[1] ? 0 : 1;
    seq = (seqs[0] > seqs[1] ? seqs[0] : seqs[1]) + 1;
  }
  (void)valid;
  return write_blob_slot(target, seq, hash, blob);
}

Status NvsPlanStore::read_blob(const Digest256& hash,
                               const MutableByteView target,
                               std::size_t& out_size) noexcept {
  out_size = 0;
  for (std::uint8_t i = 0; i < kBlobSlots; ++i) {
    Digest256 slot_hash{};
    std::uint32_t seq = 0;
    const Status status =
        read_blob_slot(i, slot_hash, seq, target, out_size);
    if (status.ok() && slot_hash == hash) return Status::success();
    out_size = 0;
  }
  return Status::error(StatusCode::NotFound, "plan blob not stored");
}

Status NvsPlanStore::drop_blob(const Digest256& hash) noexcept {
  for (std::uint8_t i = 0; i < kBlobSlots; ++i) {
    Digest256 slot_hash{};
    std::uint32_t seq = 0;
    std::array<std::uint8_t, migration_const::kPlanBlobMax> scratch{};
    std::size_t scratch_size = 0;
    const Status status =
        read_blob_slot(i, slot_hash, seq,
                       MutableByteView{scratch.data(), scratch.size()},
                       scratch_size);
    if (status.ok() && slot_hash == hash) {
      char key[8]{};
      std::snprintf(key, sizeof(key), "pb%u", static_cast<unsigned>(i));
      esp_err_t error = nvs_erase_key(handle_, key);
      if (error != ESP_OK) return nvs_status(error, "nvs_erase_key failed");
      return nvs_status(nvs_commit(handle_), "nvs_commit failed");
    }
  }
  return Status::error(StatusCode::NotFound, "plan blob not stored");
}

Status NvsPlanStore::write_commit_record(const ByteView record) noexcept {
  if (record.size > migration_const::kCommitRecordSize) {
    return Status::error(StatusCode::InvalidArgument, "commit record bound");
  }
  return write_key("commit", record);
}

Status NvsPlanStore::read_commit_record(const MutableByteView target,
                                        std::size_t& out_size) noexcept {
  return read_key("commit", target, out_size);
}

Status NvsPlanStore::write_active_record(const ByteView record) noexcept {
  if (record.size > migration_const::kActiveRecordSize) {
    return Status::error(StatusCode::InvalidArgument, "active record bound");
  }
  return write_key("active", record);
}

Status NvsPlanStore::read_active_record(const MutableByteView target,
                                        std::size_t& out_size) noexcept {
  return read_key("active", target, out_size);
}

Status NvsPlanStore::boot_channel(std::uint8_t& channel) noexcept {
  channel = 0;
  std::array<std::uint8_t, migration_const::kActiveRecordSize> raw{};
  std::size_t size = 0;
  Status status =
      read_active_record(MutableByteView{raw.data(), raw.size()}, size);
  if (!status) return status;
  ActiveRecord record{};
  status = active_record_decode(ByteView{raw.data(), size}, record);
  if (!status) return status;
  if (!record.present || record.channel == 0 || record.channel > 13) {
    return Status::error(StatusCode::IntegrityError, "active record unusable");
  }
  channel = record.channel;
  return Status::success();
}

// --- EspNowMigration ----------------------------------------------------------------

EspNowMigration::EspNowMigration(const EspNowMigrationConfig& config,
                                 EspNowRuntime& runtime,
                                 PlanStorage& plan_storage,
                                 CommitSignatureVerifier& verifier,
                                 LedgerStorage* ledger_storage) noexcept
    : config_(config),
      runtime_(runtime),
      ledger_(config.authority_role && ledger_storage != nullptr
                  ? std::optional<SingleAuthority>(std::in_place,
                                                   config.agent.participant
                                                       .network,
                                                   config.agent.participant
                                                       .authority,
                                                   *ledger_storage)
                  : std::nullopt),
      authority_(MigrationAuthorityConfig{config.agent.participant.network,
                                          config.agent.participant.authority},
                 verifier,
                 ledger_.has_value() ? &*ledger_ : nullptr),
      coordinator_(config.coordinator),
      agent_(config.agent, runtime, *this, plan_storage, authority_,
             runtime.channel_operations(), &coordinator_) {}

Status EspNowMigration::start() noexcept {
  const MigrationMode mode = config_.mode;
  if (mode == MigrationMode::Disabled ||
      mode == MigrationMode::AutoGuarded) {
    return Status::error(StatusCode::Unsupported,
                         "migration mode not selectable");
  }
  if (config_.authority_role && !ledger_.has_value()) {
    return Status::error(StatusCode::InvalidState,
                         "authority role needs ledger storage");
  }
  if (ledger_.has_value()) {
    const Status status = ledger_->initialize();
    if (!status) return status;
  }
  Status status = coordinator_.set_mode(mode);
  if (!status) return status;
  // The selected mode is observable state — the host sees exactly what was
  // configured (AutoGuarded can only ever arrive via a later gated request).
  on_migration_event(mode == MigrationMode::Observe ? "MIGRATION_MODE_OBSERVE"
                                                    : "MIGRATION_MODE_MANUAL",
                     kInvalidNodeId);
  status = runtime_.attach_migration(agent_);
  if (!status) return status;
  status = agent_.resume(runtime_.now_ms());
  if (!status) {
    ESP_LOGW(kTag, "migration resume failed: %s", status.detail);
    return status;
  }
  if (authority_.experimental_provider()) {
    ESP_LOGW(kTag,
             "migration commit verifier is EXPERIMENTAL (development PSK "
             "profile) — not a production-qualification claim");
  }
  return Status::success();
}

void EspNowMigration::hold_data(const bool held) noexcept {
  // Pause mask, not a blanket drain: DATA admission/dispatch/background/
  // retry lanes pause; the reserved control lane keeps flowing so the
  // migration's own control traffic cannot deadlock (01 §3.3).
  if (held) {
    (void)runtime_.node().set_pause(PauseReason::Cutover,
                                    pause::kMigrationMask);
  } else {
    (void)runtime_.node().clear_pause(PauseReason::Cutover);
  }
}

void EspNowMigration::note_radio_generation(
    const std::uint32_t radio_generation) noexcept {
  last_radio_generation_ = radio_generation;
  ESP_LOGI(kTag, "radio generation now %lu after verified cutover",
           static_cast<unsigned long>(radio_generation));
}

void EspNowMigration::on_migration_event(const char* reason,
                                         const NodeId peer) noexcept {
  ESP_LOGW(kTag, "migration event %s peer=%llu", reason,
           static_cast<unsigned long long>(peer));
  // Bounded reason strings (<=64B) ride the existing device→host diagnostic
  // frames: operation phases, assess verdicts, gate refusals, terminal
  // outcomes — real events only, nothing fabricated.
  runtime_.note_diagnostic(reason, peer);
}

}  // namespace routeloom::espnow
