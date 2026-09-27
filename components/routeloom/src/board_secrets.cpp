#include "routeloom/board_secrets.hpp"

#include <cstring>

#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/secure_clear.hpp"

namespace routeloom {
namespace {
constexpr std::uint32_t kMagic = 0x524C4B31U;  // RLK1
constexpr std::uint32_t kSeal = 0xB04D5EC1U;
// Fingerprint domain separation: the public BoardConfig binds this digest,
// which covers the record content bytes [20,123) — the seal/commit_seq the
// pair owns stay outside, so the value is deterministic across slots.
constexpr char kFingerprintDomain[] = "RouteLoom/board-secrets/v1";
constexpr std::size_t kContentBytes = 103;  // record bytes [20,123)

void put32(std::uint8_t* p, const std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 24U);
  p[1] = static_cast<std::uint8_t>(v >> 16U);
  p[2] = static_cast<std::uint8_t>(v >> 8U);
  p[3] = static_cast<std::uint8_t>(v);
}
std::uint32_t get32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}
void put16(std::uint8_t* p, const std::uint16_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 8U);
  p[1] = static_cast<std::uint8_t>(v);
}

// Canonical content layout shared by encode and the fingerprint:
// generation | flags | usb_len | reserved | psk | usb_secret.
void write_content(std::uint8_t* p, const BoardSecrets& s) noexcept {
  put32(p, s.generation);
  p[4] = (s.has_psk ? kBoardSecretsFlagPsk : 0) |
         (s.usb_len > 0 ? kBoardSecretsFlagUsb : 0);
  p[5] = s.usb_len;
  put16(p + 6, 0);
  for (std::size_t i = 0; i < s.psk.size(); ++i) p[8 + i] = s.psk[i];
  for (std::size_t i = 0; i < s.usb_secret.size(); ++i) p[40 + i] = s.usb_secret[i];
}

Status structure(const ByteView bytes) noexcept {
  if (bytes.data == nullptr || bytes.size != kBoardSecretsRecordBytes ||
      get32(bytes.data) != kMagic || bytes.data[4] != 0 || bytes.data[5] != 1 ||
      bytes.data[6] != 0 || bytes.data[7] != kBoardSecretsRecordBytes ||
      get32(bytes.data + 16) == 0) {
    return Status::error(StatusCode::IntegrityError, "secrets record header");
  }
  return Status::success();
}

Status decode(const ByteView bytes, BoardSecrets& out) noexcept {
  if (!structure(bytes) || get32(bytes.data + 8) != 1 || get32(bytes.data + 12) != kSeal ||
      get32(bytes.data + 123) != crc32_iso_hdlc(ByteView{bytes.data, 123})) {
    return Status::error(StatusCode::IntegrityError, "secrets record seal");
  }
  BoardSecrets s{};
  s.generation = get32(bytes.data + 20);
  const std::uint8_t flags = bytes.data[24];
  s.has_psk = (flags & kBoardSecretsFlagPsk) != 0;
  s.usb_len = bytes.data[25];
  const bool flag_usb = (flags & kBoardSecretsFlagUsb) != 0;
  if ((flags & ~kBoardSecretsFlagMask) != 0 || flag_usb != (s.usb_len != 0)) {
    return Status::error(StatusCode::IntegrityError, "secrets record flags");
  }
  if (bytes.data[26] != 0 || bytes.data[27] != 0) {
    return Status::error(StatusCode::IntegrityError, "secrets record reserved");
  }
  for (std::size_t i = 0; i < s.psk.size(); ++i) s.psk[i] = bytes.data[28 + i];
  for (std::size_t i = 0; i < s.usb_secret.size(); ++i) {
    s.usb_secret[i] = bytes.data[60 + i];
  }
  const Status status = board_secrets_validate(s);
  if (!status) {
    secure_clear(s.psk.data(), s.psk.size());
    secure_clear(s.usb_secret.data(), s.usb_secret.size());
    return status;
  }
  out = s;
  return Status::success();
}

Status semantic(const ByteView bytes, void* context) noexcept {
  return decode(bytes, *static_cast<BoardSecrets*>(context));
}

const sdkv1::SealedRecordFormat kFormat{kMagic, kSeal, kBoardSecretsSlotBytes,
                                        kBoardSecretsRecordBytes, kBoardSecretsRecordBytes,
                                        true, &structure, &semantic};
}  // namespace

Status board_secrets_validate(const BoardSecrets& s) noexcept {
  if (s.generation == 0 || s.usb_len > kBoardUsbSecretMax) {
    return Status::error(StatusCode::InvalidArgument, "secrets invalid");
  }
  if (!s.has_psk) {
    for (const std::uint8_t byte : s.psk) {
      if (byte != 0) {
        return Status::error(StatusCode::InvalidArgument, "secrets invalid");
      }
    }
  }
  // Absent tails stay zeroed (canonical fingerprint); present secret bytes
  // must be printable non-space ASCII — the host file rule.
  for (std::size_t i = 0; i < s.usb_secret.size(); ++i) {
    const std::uint8_t byte = s.usb_secret[i];
    if (i < s.usb_len) {
      if (byte < 0x21 || byte > 0x7E) {
        return Status::error(StatusCode::InvalidArgument, "secrets invalid");
      }
    } else if (byte != 0) {
      return Status::error(StatusCode::InvalidArgument, "secrets invalid");
    }
  }
  return Status::success();
}

bool board_secrets_equal(const BoardSecrets& a, const BoardSecrets& b) noexcept {
  return a.generation == b.generation && a.has_psk == b.has_psk &&
         a.psk == b.psk && a.usb_len == b.usb_len && a.usb_secret == b.usb_secret;
}

Status board_secrets_fingerprint(const BoardSecrets& secrets, Digest256& out) noexcept {
  std::array<std::uint8_t, sizeof(kFingerprintDomain) - 1 + kContentBytes> input{};
  std::memcpy(input.data(), kFingerprintDomain, sizeof(kFingerprintDomain) - 1);
  write_content(input.data() + sizeof(kFingerprintDomain) - 1, secrets);
  sha256(ByteView{input.data(), input.size()}, out);
  return Status::success();
}

BoardSecretsStore::BoardSecretsStore(sdkv1::RecordSlotStorage& storage) noexcept
    : pair_(storage, kFormat, scratch_.writable(), &secrets_) {}

Status BoardSecretsStore::initialize() noexcept {
  readback_ready_ = false;
  const Status status = pair_.initialize();
  secrets_ = BoardSecrets{};
  if (pair_.has_active()) {
    ByteView record{};
    Status loaded = pair_.load_active(record);
    if (loaded) loaded = decode(record, secrets_);
    if (!loaded) return loaded;
  }
  readback_ready_ = status.ok();
  return status;
}

Status BoardSecretsStore::commit(const BoardSecrets& secrets) noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "secrets store unopened");
  }
  if (!readback_ready_) {
    return Status::error(StatusCode::RecoveryRequired, "secrets readback required");
  }
  Status status = board_secrets_validate(secrets);
  if (!status) return status;
  if (pair_.has_active() && secrets.generation <= secrets_.generation) {
    return Status::error(StatusCode::Conflict, "secrets generation must increase");
  }
  auto* p = scratch_.bytes.data();
  put32(p, kMagic);
  p[4] = 0; p[5] = 1;
  p[6] = 0; p[7] = kBoardSecretsRecordBytes;
  put32(p + 8, 1);
  put32(p + 12, 0);  // SealedSlotPair commits in two writes.
  put32(p + 16, 0);  // SealedSlotPair owns the sequence.
  write_content(p + 20, secrets);
  put32(p + 123, 0);  // SealedSlotPair writes CRC after sequence and seal.
  status = pair_.commit_prepared(kBoardSecretsRecordBytes);
  if (status) secrets_ = secrets;
  else readback_ready_ = false;  // A failed acknowledgement may have committed the seal.
  return status;
}

Status BoardSecretsStore::authorize(const BoardConfig& config) const noexcept {
  const BoardSecretsNeed need = board_secrets_need(config.security, config.role);
  if (config.secrets_generation == 0) {
    if (need.psk || need.usb) {
      return Status::error(StatusCode::InvalidState, "board secrets required");
    }
    return Status::success();
  }
  if (!readback_ready_ || !pair_.initialized() || !pair_.has_active() ||
      pair_.uncertain() || pair_.quarantined()) {
    return Status::error(StatusCode::InvalidState, "board secrets unavailable");
  }
  if (secrets_.generation != config.secrets_generation) {
    return Status::error(StatusCode::Conflict, "board secrets generation mismatch");
  }
  Digest256 fingerprint{};
  const Status status = board_secrets_fingerprint(secrets_, fingerprint);
  if (!status) return status;
  if (fingerprint != config.secrets_fingerprint) {
    return Status::error(StatusCode::IntegrityError, "board secrets fingerprint mismatch");
  }
  if ((need.psk && !secrets_.has_psk) || (need.usb && secrets_.usb_len == 0)) {
    return Status::error(StatusCode::Conflict, "board secrets kind missing");
  }
  return Status::success();
}

Status resolve_field_identity(const BoardConfigStore& board,
                              const BoardSecretsStore& secrets,
                              const BoardBootIdentity& identity,
                              const BoardSecrets*& secrets_out) noexcept {
  secrets_out = nullptr;
  Status status = board.authorize_rf(identity);
  if (!status) return status;
  status = secrets.authorize(board.config());
  if (!status) return status;
  if (board.config().secrets_generation != 0) {
    secrets_out = &secrets.secrets();
  }
  return status;
}

}  // namespace routeloom
