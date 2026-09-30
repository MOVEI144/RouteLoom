#include "routeloom/usb_session.hpp"

#include <cstring>
#include <limits>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/kdf.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::usb {
namespace {

constexpr std::uint64_t kTranscriptMagic = 0x524C553154524E32ULL;  // "RLU1TRN2"
constexpr char kHostlinkInfo[] = "RouteLoom/v2/hostlink";

ByteView label_bytes(const char* label) noexcept {
  // The trailing NUL is the label/transcript separator.
  return ByteView{reinterpret_cast<const std::uint8_t*>(label), std::strlen(label) + 1};
}

}  // namespace

Status encode_transcript(const SessionTranscript& transcript,
                         const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kTranscriptSize) {
    return Status::error(StatusCode::NoCapacity, "transcript output too small");
  }
  if (transcript.principal_len > kMaxPrincipalSize) {
    return Status::error(StatusCode::InvalidArgument, "principal too long");
  }
  ByteWriter writer(out);
  Status status = writer.write_u64(kTranscriptMagic);
  if (status) status = writer.write_u64(transcript.host_nonce);
  if (status) status = writer.write_u64(transcript.device_nonce);
  if (status) status = writer.write_u8(transcript.min_version);
  if (status) status = writer.write_u8(transcript.max_version);
  if (status) status = writer.write_u8(transcript.version);
  if (status) status = writer.write_u8(transcript.carrier);
  for (std::size_t i = 0; status && i < kBindingSize; ++i) status = writer.write_u8(0);
  if (status) status = writer.write_u64(transcript.node);
  if (status) status = writer.write_u64(transcript.boot_id);
  if (status) status = writer.write_u64(transcript.network);
  if (status) status = writer.write_u32(transcript.capability);
  if (status) status = writer.write_u8(transcript.principal_len);
  if (status) {
    status = writer.write_bytes(
        ByteView{transcript.principal.data(), transcript.principal_len});
  }
  if (!status) return status;
  // Zero-pad the principal field so every transcript is exactly
  // kTranscriptSize bytes regardless of principal length.
  while (writer.size() < kTranscriptSize) {
    status = writer.write_u8(0);
    if (!status) return status;
  }
  written = writer.size();
  return Status::success();
}

SessionProof derive_session_proof(const ByteView secret,
                                  const ByteView transcript) noexcept {
  SessionProof proof{};
  ScopeDigest hostlink_key{};
  (void)hkdf_sha256(ByteView{}, secret,
                    ByteView{reinterpret_cast<const std::uint8_t*>(kHostlinkInfo),
                             sizeof(kHostlinkInfo) - 1},
                    MutableByteView{hostlink_key.data(), hostlink_key.size()});
  const ByteView key{hostlink_key.data(), hostlink_key.size()};
  ScopeDigest value{};
  const auto derive = [&](const char* label) {
    hmac_sha256(key, label_bytes(label), transcript, ByteView{}, value);
  };
  derive("key-h2d");
  std::memcpy(proof.key_h2d.data(), value.data(), kSessionKeySize);
  derive("key-d2h");
  std::memcpy(proof.key_d2h.data(), value.data(), kSessionKeySize);
  derive("hello");
  std::memcpy(proof.hello_tag.data(), value.data(), kTagSize);
  derive("auth");
  std::memcpy(proof.auth_tag.data(), value.data(), kTagSize);
  derive("auth-ok");
  std::memcpy(proof.auth_ok_tag.data(), value.data(), kTagSize);
  derive("session-id");
  for (std::size_t i = 0; i < 8; ++i) {
    proof.session_id = (proof.session_id << 8U) | value[i];
  }
  secure_clear(value);
  secure_clear(hostlink_key);
  return proof;
}

void clear_session_proof(SessionProof& proof) noexcept {
  secure_clear(proof.key_h2d);
  secure_clear(proof.key_d2h);
  secure_clear(proof.hello_tag);
  secure_clear(proof.auth_tag);
  secure_clear(proof.auth_ok_tag);
  proof.session_id = 0;
}

void clear_session_keys(SessionKeys& keys) noexcept {
  secure_clear(keys.key_h2d);
  secure_clear(keys.key_d2h);
  keys.session_id = 0;
}

SessionTag frame_tag(const SessionKey& key, const std::uint8_t direction,
                     const std::uint64_t counter, const FrameKind kind,
                     const std::uint16_t flags, const std::uint64_t request,
                     const ByteView inner) noexcept {
  std::array<std::uint8_t, 1 + 8 + 1 + 2 + 8> header{};
  ByteWriter writer(MutableByteView{header.data(), header.size()});
  (void)writer.write_u8(direction);
  (void)writer.write_u64(counter);
  (void)writer.write_u8(static_cast<std::uint8_t>(kind));
  (void)writer.write_u16(flags);
  (void)writer.write_u64(request);
  ScopeDigest mac{};
  hmac_sha256(ByteView{key.data(), key.size()}, ByteView{header.data(), header.size()},
              inner, ByteView{}, mac);
  SessionTag tag{};
  std::memcpy(tag.data(), mac.data(), kTagSize);
  secure_clear(mac);
  return tag;
}

Status seal_body(const SessionKey& key, const std::uint8_t direction,
                 const std::uint64_t counter, const FrameKind kind,
                 const std::uint16_t flags, const std::uint64_t request,
                 const ByteView inner, const MutableByteView out,
                 std::size_t& written) noexcept {
  written = 0;
  if (counter == std::numeric_limits<std::uint64_t>::max()) {
    return Status::error(StatusCode::InvalidState, "session counter exhausted");
  }
  if (out.data == nullptr || out.size < kProtectedBodyOverhead + inner.size) {
    return Status::error(StatusCode::NoCapacity, "seal output too small");
  }
  if (inner.size > 0 && inner.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null inner body");
  }
  const SessionTag tag = frame_tag(key, direction, counter, kind, flags, request, inner);
  ByteWriter writer(out);
  Status status = writer.write_u64(counter);
  if (status) status = writer.write_bytes(ByteView{tag.data(), tag.size()});
  if (status) status = writer.write_bytes(inner);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status open_body(const SessionKey& key, const std::uint8_t direction,
                 const UsbFrame& frame, std::uint64_t& counter,
                 ByteView& inner) noexcept {
  counter = 0;
  inner = ByteView{};
  if (frame.body.size < kProtectedBodyOverhead) {
    return Status::error(StatusCode::ProtocolError, "PROTECTED_BODY_SHORT");
  }
  ByteReader reader(frame.body);
  Status status = reader.read_u64(counter);
  if (!status) return status;
  inner = ByteView{frame.body.data + kProtectedBodyOverhead,
                   frame.body.size - kProtectedBodyOverhead};
  const SessionTag expected =
      frame_tag(key, direction, counter, frame.kind, frame.flags, frame.request, inner);
  if (!constant_time_equal(ByteView{expected.data(), expected.size()},
                           ByteView{frame.body.data + 8, kTagSize})) {
    inner = ByteView{};
    return Status::error(StatusCode::AuthenticationFailed, "SESSION_TAG_MISMATCH");
  }
  return Status::success();
}

SessionTag payload_hash(const ByteView canonical_request) noexcept {
  ScopeDigest digest{};
  sha256(canonical_request, digest);
  SessionTag out{};
  std::memcpy(out.data(), digest.data(), kTagSize);
  return out;
}

IdempotencyResult IdempotencyTable::submit(
    const ByteView principal, const NetworkId network,
    const std::uint8_t operation_class, const std::uint64_t key,
    const SessionTag& hash, const std::uint64_t usb_session,
    const MonotonicMs now_ms, IdempotencyRecord*& record) noexcept {
  record = nullptr;
  if (principal.size > kMaxPrincipalSize) {
    return IdempotencyResult::Conflict;  // unreachable via bridge (bounded)
  }
  if (floor_session_ != usb_session) {
    floor_session_ = usb_session;
    has_floor_ = false;
  }
  for (std::size_t i = 0; i < kCapacity; ++i) {
    if (!used_[i]) continue;
    IdempotencyRecord& entry = records_[i];
    if (entry.usb_session != usb_session || entry.network != network ||
        entry.operation_class != operation_class ||
        entry.key != key || entry.principal_len != principal.size) {
      continue;
    }
    if (principal.size > 0 &&
        std::memcmp(entry.principal.data(), principal.data, principal.size) != 0) {
      continue;
    }
    record = &entry;
    return entry.hash == hash ? IdempotencyResult::Existing
                              : IdempotencyResult::Conflict;
  }
  if (has_floor_ && key <= floor_) return IdempotencyResult::ResultExpired;
  const std::size_t slot = reclaim_slot(usb_session);
  if (slot == kCapacity) return IdempotencyResult::NoCapacity;
  used_[slot] = true;
  IdempotencyRecord& entry = records_[slot];
  entry = IdempotencyRecord{};
  if (principal.size > 0) {
    std::memcpy(entry.principal.data(), principal.data, principal.size);
  }
  entry.principal_len = static_cast<std::uint8_t>(principal.size);
  entry.network = network;
  entry.operation_class = operation_class;
  entry.key = key;
  entry.hash = hash;
  entry.settled_ms = now_ms;
  entry.usb_session = usb_session;
  record = &entry;
  return IdempotencyResult::Accepted;
}

std::size_t IdempotencyTable::reclaim_slot(const std::uint64_t usb_session) noexcept {
  std::size_t slot = kCapacity;
  for (std::size_t i = 0; i < kCapacity; ++i) {
    if (!used_[i]) return i;
    const IdempotencyRecord& entry = records_[i];
    if (entry.settled && (entry.reported || entry.usb_session != usb_session) &&
        (slot == kCapacity || entry.settled_ms < records_[slot].settled_ms)) {
      slot = i;
    }
  }
  if (slot != kCapacity && records_[slot].usb_session == floor_session_) {
    if (!has_floor_ || records_[slot].key > floor_) floor_ = records_[slot].key;
    has_floor_ = true;
  }
  return slot;
}

bool IdempotencyTable::repeat(IdempotencyRecord*& record,
                               const std::uint64_t request) noexcept {
  if (record->request == request) return true;
  if (!record->settled || !record->reported) {
    const std::size_t slot = reclaim_slot(record->usb_session);
    if (slot == kCapacity) return false;
    records_[slot] = *record;
    used_[slot] = true;
    record = &records_[slot];
  }
  record->request = request;
  record->reported = false;
  record->replay = true;
  return true;
}

IdempotencyRecord* IdempotencyTable::find_message(
    const std::uint32_t message_session, const std::uint64_t message_sequence,
    const bool unsettled_only) noexcept {
  for (std::size_t i = 0; i < kCapacity; ++i) {
    if (used_[i] && records_[i].accepted && (!unsettled_only || !records_[i].settled) &&
        records_[i].message_session == message_session &&
        records_[i].message_sequence == message_sequence) {
      return &records_[i];
    }
  }
  return nullptr;
}

IdempotencyRecord* IdempotencyTable::next_unreported(const std::uint64_t usb_session) noexcept {
  IdempotencyRecord* oldest = nullptr;
  for (std::size_t i = 0; i < kCapacity; ++i) {
    IdempotencyRecord& entry = records_[i];
    if (!used_[i] || !entry.settled || entry.reported || entry.usb_session != usb_session) {
      continue;
    }
    if (oldest == nullptr || entry.settled_ms < oldest->settled_ms) oldest = &entry;
  }
  return oldest;
}

std::size_t IdempotencyTable::size() const noexcept {
  std::size_t count = 0;
  for (const bool used : used_) count += used ? 1U : 0U;
  return count;
}

}  // namespace routeloom::usb
