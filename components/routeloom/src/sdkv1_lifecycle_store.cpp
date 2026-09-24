#include "routeloom/sdkv1_lifecycle_store.hpp"

#include <cstring>

#include "routeloom/crc32.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

std::uint16_t get16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((p[0] << 8U) | p[1]);
}
std::uint32_t get32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}
std::uint64_t get64(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint64_t>(get32(p)) << 32U) | get32(p + 4);
}
void put16(std::uint8_t* p, std::uint16_t n) noexcept {
  p[0] = static_cast<std::uint8_t>(n >> 8U);
  p[1] = static_cast<std::uint8_t>(n);
}
void put32(std::uint8_t* p, std::uint32_t n) noexcept {
  p[0] = static_cast<std::uint8_t>(n >> 24U);
  p[1] = static_cast<std::uint8_t>(n >> 16U);
  p[2] = static_cast<std::uint8_t>(n >> 8U);
  p[3] = static_cast<std::uint8_t>(n);
}
void put64(std::uint8_t* p, std::uint64_t n) noexcept {
  put32(p, static_cast<std::uint32_t>(n >> 32U));
  put32(p + 4, static_cast<std::uint32_t>(n));
}

Status valid(const LifecycleRecord& r) noexcept {
  if (r.mode != LifecycleMode::Removing && r.mode != LifecycleMode::Holdoff &&
      r.mode != LifecycleMode::UnassignedReady && r.mode != LifecycleMode::Idle) {
    return Status::error(StatusCode::Unsupported, "rlx mode reserved");
  }
  if (r.self == 0 || r.self == kInvalidNodeId || r.site_id == 0 ||
      r.generation == 0 || r.old_network == 0 || r.new_network != 0 ||
      r.cutover_id != 0 || r.revision != 0) {
    return Status::error(StatusCode::ProtocolError, "rlx binding");
  }
  if (r.mode == LifecycleMode::Removing || r.mode == LifecycleMode::Holdoff) {
    if (r.payload.size < 4 || r.payload.size > kLifecyclePayloadMax) {
      return Status::error(StatusCode::ProtocolError, "rlx proof size");
    }
    const auto* p = r.payload.bytes.data();
    const std::size_t cert_len = get16(p), notice_len = get16(p + 2);
    if (cert_len == 0 || cert_len > kRlcw1CertMax ||
        notice_len != kRemovalNoticeObjectSize ||
        4 + cert_len + notice_len != r.payload.size) {
      return Status::error(StatusCode::ProtocolError, "rlx proof lengths");
    }
    RemovalNotice notice{};
    if (!removal_notice_decode(ByteView{p + 4 + cert_len, notice_len}, notice) ||
        notice.site_id != r.site_id || notice.node_id != r.self ||
        notice.generation != r.generation || notice.rs_epoch > r.rs_floor) {
      return Status::error(StatusCode::ProtocolError, "rlx notice binding");
    }
  } else if (r.payload.size != 0) {
    return Status::error(StatusCode::ProtocolError, "rlx watermark payload");
  }
  return Status::success();
}

Status structure(ByteView bytes) noexcept {
  if (bytes.data == nullptr || bytes.size < 88 || bytes.size > 88 + kLifecyclePayloadMax ||
      get32(bytes.data) != kLifecycleMagic || get16(bytes.data + 4) != 1 ||
      get16(bytes.data + 6) != bytes.size || get32(bytes.data + 16) == 0 ||
      bytes.data[21] != 0 || get16(bytes.data + 22) != bytes.size - 88) {
    return Status::error(StatusCode::ProtocolError, "rlx structure");
  }
  return Status::success();
}
Status semantic(ByteView bytes, void* context) noexcept {
  return lifecycle_record_decode(bytes, *static_cast<LifecycleRecord*>(context));
}
const SealedRecordFormat kFormat{kLifecycleMagic, kLifecycleSeal, kLifecycleSlotBytes,
                                  88, 88 + kLifecyclePayloadMax, true, &structure, &semantic};
}  // namespace

const SealedRecordFormat& lifecycle_record_format() noexcept { return kFormat; }

Status lifecycle_record_encode(const LifecycleRecord& r, std::uint32_t seal,
                               std::uint32_t seq, ByteBuffer<kLifecycleSlotBytes>& out) noexcept {
  out.clear();
  const Status checked = valid(r);
  if (!checked) return checked;
  if (seq == 0 || (seal != 0 && seal != kLifecycleSeal)) {
    return Status::error(StatusCode::InvalidArgument, "rlx seal/seq");
  }
  auto* p = out.bytes.data();
  const std::size_t len = 88 + r.payload.size;
  put32(p, kLifecycleMagic);
  put16(p + 4, 1);
  put16(p + 6, static_cast<std::uint16_t>(len));
  put32(p + 8, 1);
  put32(p + 12, seal);
  put32(p + 16, seq);
  p[20] = static_cast<std::uint8_t>(r.mode);
  p[21] = 0;
  put16(p + 22, static_cast<std::uint16_t>(r.payload.size));
  put64(p + 24, r.self);
  put64(p + 32, r.site_id);
  put64(p + 40, r.old_network);
  put64(p + 48, r.new_network);
  put32(p + 56, r.generation);
  put32(p + 60, r.rs_floor);
  put32(p + 64, r.gk_floor);
  put32(p + 68, r.boot_witness);
  put64(p + 72, r.cutover_id);
  put32(p + 80, r.revision);
  if (r.payload.size) std::memcpy(p + 84, r.payload.bytes.data(), r.payload.size);
  put32(p + len - 4, crc32_iso_hdlc(ByteView{p, len - 4}));
  out.size = len;
  return Status::success();
}

Status lifecycle_record_decode(ByteView bytes, LifecycleRecord& out) noexcept {
  const Status head = structure(bytes);
  if (!head) return head;
  const auto* p = bytes.data;
  if (get32(p + 8) != 1 || get32(p + 12) != kLifecycleSeal ||
      get32(p + bytes.size - 4) != crc32_iso_hdlc(ByteView{p, bytes.size - 4})) {
    return Status::error(StatusCode::IntegrityError, "rlx seal/schema/crc");
  }
  LifecycleRecord r{};
  r.mode = static_cast<LifecycleMode>(p[20]);
  r.self = get64(p + 24);
  r.site_id = get64(p + 32);
  r.old_network = get64(p + 40);
  r.new_network = get64(p + 48);
  r.generation = get32(p + 56);
  r.rs_floor = get32(p + 60);
  r.gk_floor = get32(p + 64);
  r.boot_witness = get32(p + 68);
  r.cutover_id = get64(p + 72);
  r.revision = get32(p + 80);
  r.payload.size = get16(p + 22);
  if (r.payload.size) std::memcpy(r.payload.bytes.data(), p + 84, r.payload.size);
  const Status checked = valid(r);
  if (checked) out = r;
  return checked;
}

LifecycleStore::LifecycleStore(RecordSlotStorage& storage) noexcept
    : pair_(storage, kFormat, MutableByteView{scratch_.bytes.data(), scratch_.bytes.size()},
            &record_) {}

Status LifecycleStore::initialize() noexcept {
  record_ = LifecycleRecord{};
  const Status status = pair_.initialize();
  if (!pair_.has_active()) return status;
  ByteView active{};
  const Status loaded = pair_.load_active(active);
  if (!loaded) return loaded;
  return lifecycle_record_decode(active, record_).ok() ? status
      : Status::error(StatusCode::IntegrityError, "rlx active record");
}

Status LifecycleStore::commit(const LifecycleRecord& record, bool twin) noexcept {
  if (!pair_.initialized()) return Status::error(StatusCode::InvalidState, "rlx not initialized");
  const Status checked = valid(record);
  if (!checked) return checked;
  const Status enc = lifecycle_record_encode(record, 0, 1, scratch_);
  if (!enc) return enc;
  const Status stored = twin ? pair_.commit_twin_prepared(scratch_.size)
                             : pair_.commit_prepared(scratch_.size);
  secure_clear(scratch_.bytes.data(), scratch_.bytes.size());
  if (stored) record_ = record;
  return stored;
}

Status LifecycleStore::begin_removal(const LifecycleRecord& record) noexcept {
  if (record.mode != LifecycleMode::Removing || pair_.uncertain() || pair_.quarantined() ||
      (pair_.has_active() && record_.mode != LifecycleMode::Idle)) {
    return Status::error(StatusCode::InvalidState, "rlx removal state");
  }
  return commit(record, false);
}
Status LifecycleStore::holdoff() noexcept {
  if (!pair_.has_active() || record_.mode != LifecycleMode::Removing ||
      pair_.uncertain() || pair_.quarantined()) {
    return Status::error(StatusCode::InvalidState, "rlx holdoff state");
  }
  LifecycleRecord next = record_;
  next.mode = LifecycleMode::Holdoff;
  return commit(next, false);
}
Status LifecycleStore::unassigned_ready() noexcept {
  if (!pair_.has_active() || record_.mode != LifecycleMode::Holdoff ||
      pair_.uncertain() || pair_.quarantined()) {
    return Status::error(StatusCode::InvalidState, "rlx ready state");
  }
  LifecycleRecord next = record_;
  next.mode = LifecycleMode::UnassignedReady;
  next.payload.clear();
  return commit(next, true);  // scrub proof from both slots
}
Status LifecycleStore::resume_removal(const LifecycleRecord& verified) noexcept {
  if (!pair_.has_active() || !pair_.uncertain() || unknown_sibling() ||
      (record_.mode != LifecycleMode::Removing && record_.mode != LifecycleMode::Holdoff) ||
      verified.mode != record_.mode || verified.self != record_.self ||
      verified.site_id != record_.site_id || verified.old_network != record_.old_network ||
      verified.generation != record_.generation ||
      verified.payload.size != record_.payload.size ||
      std::memcmp(verified.payload.bytes.data(), record_.payload.bytes.data(),
                  verified.payload.size) != 0) {
    return Status::error(StatusCode::InvalidState, "rlx recovery proof");
  }
  return commit(record_, true);
}

}  // namespace routeloom::sdkv1
