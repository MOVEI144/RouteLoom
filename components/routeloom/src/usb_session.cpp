#include "routeloom/usb_session.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"

namespace routeloom::usb {
namespace {

constexpr std::uint64_t kLaneLeft = 0x4C454654ULL;   // "LEFT"
constexpr std::uint64_t kLaneRight = 0x52474854ULL;  // "RGHT"
constexpr std::uint64_t kTranscriptMagic = 0x524C553154524E31ULL;  // "RLU1TRN1"

void absorb_be(DevMac& mac, const std::uint64_t value, const int bytes) noexcept {
  for (int i = bytes - 1; i >= 0; --i) {
    mac.absorb_u8(static_cast<std::uint8_t>(value >> (i * 8)));
  }
}

}  // namespace

void DevMac::init(const ByteView secret) noexcept {
  state_ = kDevMacSeed;
  absorb(secret);
  absorb_u64(secret.size);
}

void DevMac::absorb(const ByteView data) noexcept {
  for (std::size_t i = 0; i < data.size; ++i) {
    state_ = dev_mix(state_, data.data[i]);
  }
}

void DevMac::absorb_u8(const std::uint8_t value) noexcept {
  state_ = dev_mix(state_, value);
}

void DevMac::absorb_u16(const std::uint16_t value) noexcept {
  absorb_be(*this, value, 2);
}

void DevMac::absorb_u32(const std::uint32_t value) noexcept {
  absorb_be(*this, value, 4);
}

void DevMac::absorb_u64(const std::uint64_t value) noexcept {
  absorb_be(*this, value, 8);
}

DevTag DevMac::tag() const noexcept {
  const std::uint64_t left = dev_mix(state_, kLaneLeft);
  const std::uint64_t right = dev_mix(state_, kLaneRight);
  DevTag out{};
  for (int i = 0; i < 8; ++i) {
    out[static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>(left >> (56 - i * 8));
    out[static_cast<std::size_t>(8 + i)] =
        static_cast<std::uint8_t>(right >> (56 - i * 8));
  }
  return out;
}

DevTag dev_proof(const ByteView secret, const ByteView label,
                 const ByteView message) noexcept {
  DevMac mac;
  mac.init(secret);
  mac.absorb(label);
  mac.absorb(message);
  mac.absorb_u64(message.size);
  return mac.tag();
}

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
  if (status) status = writer.write_u8(transcript.version);
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
  const auto labeled = [&](const char* label) {
    return dev_proof(secret,
                     ByteView{reinterpret_cast<const std::uint8_t*>(label),
                              std::strlen(label)},
                     transcript);
  };
  const DevTag key = labeled("session-key");
  proof.key = key;
  proof.hello_tag = labeled("hello");
  proof.auth_tag = labeled("auth");
  proof.auth_ok_tag = labeled("auth-ok");
  const DevTag id = labeled("session-id");
  std::uint64_t session_id = 0;
  for (int i = 0; i < 8; ++i) {
    session_id = (session_id << 8U) | id[static_cast<std::size_t>(i)];
  }
  proof.session_id = session_id;
  return proof;
}

DevTag frame_tag(const SessionKey& key, const std::uint8_t direction,
                 const std::uint64_t counter, const FrameKind kind,
                 const std::uint16_t flags, const std::uint64_t request,
                 const ByteView inner) noexcept {
  DevMac mac;
  mac.init(ByteView{key.data(), key.size()});
  mac.absorb_u8(direction);
  mac.absorb_u64(counter);
  mac.absorb_u8(static_cast<std::uint8_t>(kind));
  mac.absorb_u16(flags);
  mac.absorb_u64(request);
  mac.absorb(inner);
  mac.absorb_u64(inner.size);
  return mac.tag();
}

Status seal_body(const SessionKey& key, const std::uint8_t direction,
                 const std::uint64_t counter, const FrameKind kind,
                 const std::uint16_t flags, const std::uint64_t request,
                 const ByteView inner, const MutableByteView out,
                 std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kProtectedBodyOverhead + inner.size) {
    return Status::error(StatusCode::NoCapacity, "seal output too small");
  }
  if (inner.size > 0 && inner.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null inner body");
  }
  const DevTag tag = frame_tag(key, direction, counter, kind, flags, request, inner);
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
  const ByteView tag_bytes{frame.body.data + 8, kDevTagSize};
  inner = ByteView{frame.body.data + kProtectedBodyOverhead,
                   frame.body.size - kProtectedBodyOverhead};
  const DevTag expected =
      frame_tag(key, direction, counter, frame.kind, frame.flags, frame.request, inner);
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < kDevTagSize; ++i) {
    diff |= static_cast<std::uint8_t>(expected[i] ^ tag_bytes.data[i]);
  }
  if (diff != 0) {
    return Status::error(StatusCode::AuthenticationFailed, "SESSION_TAG_MISMATCH");
  }
  return Status::success();
}

DevTag payload_hash(const ByteView canonical_request) noexcept {
  static const std::uint8_t kEmptySecret = 0;
  return dev_proof(ByteView{&kEmptySecret, 0},
                   ByteView{reinterpret_cast<const std::uint8_t*>("payload-hash"),
                            12},
                   canonical_request);
}

IdempotencyResult IdempotencyTable::submit(
    const ByteView principal, const NetworkId network,
    const std::uint8_t operation_class, const std::uint64_t key,
    const DevTag& hash, const MonotonicMs now_ms,
    IdempotencyRecord*& record) noexcept {
  record = nullptr;
  if (principal.size > kMaxPrincipalSize) {
    return IdempotencyResult::Conflict;  // unreachable via bridge (bounded)
  }
  for (std::size_t i = 0; i < kCapacity; ++i) {
    if (!used_[i]) continue;
    IdempotencyRecord& entry = records_[i];
    if (entry.network != network || entry.operation_class != operation_class ||
        entry.key != key || entry.principal_len != principal.size) {
      continue;
    }
    if (principal.size > 0 &&
        std::memcmp(entry.principal.data(), principal.data, principal.size) != 0) {
      continue;
    }
    entry.last_use_ms = now_ms;
    record = &entry;
    return entry.hash == hash ? IdempotencyResult::Existing
                              : IdempotencyResult::Conflict;
  }
  std::size_t slot = kCapacity;
  MonotonicMs oldest_use = ~MonotonicMs{0};
  for (std::size_t i = 0; i < kCapacity; ++i) {
    if (!used_[i]) {
      slot = i;
      break;
    }
    // Only retention-expired records are evictable: evicting a live record
    // would silently re-execute a resubmitted key. Reject instead — the
    // caller reports IDEMPOTENCY_FULL and the host backs off.
    if (now_ms - records_[i].last_use_ms >= kRetentionMs &&
        records_[i].last_use_ms < oldest_use) {
      oldest_use = records_[i].last_use_ms;
      slot = i;
    }
  }
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
  entry.last_use_ms = now_ms;
  record = &entry;
  return IdempotencyResult::Accepted;
}

std::size_t IdempotencyTable::size() const noexcept {
  std::size_t count = 0;
  for (const bool used : used_) count += used ? 1U : 0U;
  return count;
}

}  // namespace routeloom::usb
