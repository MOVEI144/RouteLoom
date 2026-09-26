#include "routeloom/sdkv1_board_setup.hpp"

#include <cstring>

#include "routeloom/crc32.hpp"
#include "routeloom/sdkv1_maintenance.hpp"  // kMaintenanceLineMax / ResponseMax
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

// Strict response builder (same contract as sdkv1_maintenance.cpp): any
// overflow fails instead of truncating.
class Response {
 public:
  Response(char* buffer, const std::size_t capacity) noexcept
      : buffer_(buffer), capacity_(capacity) {}
  bool put(const char* text) noexcept {
    const std::size_t length = std::strlen(text);
    if (!ok_ || length > capacity_ - size_) {
      ok_ = false;
      return false;
    }
    std::memcpy(buffer_ + size_, text, length);
    size_ += length;
    return true;
  }
  bool put_hex(const std::uint8_t* data, const std::size_t size) noexcept {
    static constexpr char kDigits[] = "0123456789abcdef";
    if (!ok_ || data == nullptr || size > (capacity_ - size_) / 2) {
      ok_ = false;
      return false;
    }
    for (std::size_t i = 0; i < size; ++i) {
      buffer_[size_++] = kDigits[data[i] >> 4];
      buffer_[size_++] = kDigits[data[i] & 0xF];
    }
    return true;
  }
  bool put_u64_hex(const std::uint64_t value) noexcept {
    std::uint8_t raw[8]{};
    for (int i = 7; i >= 0; --i) {
      raw[i] = static_cast<std::uint8_t>(value >> (8 * (7 - i)));
    }
    return put_hex(raw, sizeof(raw));
  }
  bool put_uint(const std::uint32_t value) noexcept {
    char text[11]{};
    std::size_t length = 0;
    std::uint32_t rest = value;
    do {
      text[length++] = static_cast<char>('0' + (rest % 10));
      rest /= 10;
    } while (rest != 0);
    for (std::size_t i = 0; i < length / 2; ++i) {
      const char swap = text[i];
      text[i] = text[length - 1 - i];
      text[length - 1 - i] = swap;
    }
    text[length] = '\0';
    return put(text);
  }
  bool finish() noexcept {
    if (!ok_ || size_ >= capacity_) {
      ok_ = false;
      return false;
    }
    buffer_[size_] = '\0';
    return true;
  }
  std::size_t size() const noexcept { return size_; }

 private:
  char* buffer_;
  std::size_t capacity_;
  std::size_t size_{0};
  bool ok_{true};
};

bool hex_decode(const ByteView text, std::uint8_t* out, const std::size_t out_max,
                std::size_t& out_len) noexcept {
  out_len = 0;
  if (text.data == nullptr || text.size == 0 || text.size % 2 != 0 ||
      text.size / 2 > out_max) {
    return false;
  }
  for (std::size_t i = 0; i < text.size; i += 2) {
    const int high = hex_value(static_cast<char>(text.data[i]));
    const int low = hex_value(static_cast<char>(text.data[i + 1]));
    if (high < 0 || low < 0) return false;
    out[out_len++] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

// One line = a verb plus up to 4 arguments separated by exactly one
// space; no leading/trailing space. (`benchsecret stage psk 7 <hex>`.)
struct Line {
  bool valid{false};
  ByteView verb{};
  ByteView args[4]{};
  int argc{0};
};

Line split_line(const ByteView line) noexcept {
  Line out{};
  if (line.data == nullptr || line.size == 0 || line.size > kBoardSetupLineMax) {
    return out;
  }
  if (line.data[line.size - 1] == ' ') return out;
  std::size_t starts[5]{};
  std::size_t lengths[5]{};
  int count = 0;
  std::size_t i = 0;
  while (i < line.size && count < 5) {
    if (line.data[i] == ' ') return out;
    const std::size_t start = i;
    while (i < line.size && line.data[i] != ' ') ++i;
    starts[count] = start;
    lengths[count] = i - start;
    ++count;
    if (i < line.size) ++i;
  }
  if (i < line.size) return out;
  out.valid = true;
  out.verb = ByteView{line.data + starts[0], lengths[0]};
  out.argc = count - 1;
  for (int a = 0; a < out.argc; ++a) {
    out.args[a] = ByteView{line.data + starts[a + 1], lengths[a + 1]};
  }
  return out;
}

bool verb_is(const ByteView verb, const char* name) noexcept {
  const std::size_t length = std::strlen(name);
  return verb.size == length && std::memcmp(verb.data, name, length) == 0;
}

bool parse_u32(const ByteView text, std::uint32_t& value) noexcept {
  value = 0;
  if (text.data == nullptr || text.size == 0 || text.size > 10) return false;
  for (std::size_t i = 0; i < text.size; ++i) {
    const std::uint8_t ch = text.data[i];
    if (ch < '0' || ch > '9') return false;
    const std::uint32_t digit = ch - '0';
    if (value > (0xFFFFFFFFU - digit) / 10U) return false;
    value = value * 10U + digit;
  }
  return true;
}

std::uint32_t get32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}
std::uint16_t get16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
}
std::uint64_t get64(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint64_t>(get32(p)) << 32U) | get32(p + 4);
}

const char* role_name(const BoardRole role) noexcept {
  return role == BoardRole::Bridge ? "bridge" : "reference";
}
const char* security_name(const BoardSecurity security) noexcept {
  return security == BoardSecurity::DevRam ? "devram" : "member";
}

// RLC1 document → the public fields of a BoardConfig (generation and the
// secrets binding are supplied at commit, never carried by the document).
Status parse_doc(const ByteView doc, BoardConfig& out) noexcept {
  if (doc.data == nullptr || doc.size != kBoardDocV1Bytes ||
      get32(doc.data) != kBoardDocMagic || doc.data[4] != 1 || doc.data[5] != 0 ||
      get16(doc.data + 6) != kBoardDocV1Bytes ||
      get32(doc.data + 38) != crc32_iso_hdlc(ByteView{doc.data, 38})) {
    return Status::error(StatusCode::InvalidArgument, "board document invalid");
  }
  for (std::size_t i = 30; i < 38; ++i) {
    if (doc.data[i] != 0) {
      return Status::error(StatusCode::InvalidArgument, "board document reserved");
    }
  }
  BoardConfig config{};
  config.node = get64(doc.data + 8);
  for (std::size_t i = 0; i < 6; ++i) config.sta_mac[i] = doc.data[16 + i];
  config.chip = doc.data[22];
  config.role = static_cast<BoardRole>(doc.data[23]);
  config.security = static_cast<BoardSecurity>(doc.data[24]);
  config.channel = doc.data[25];
  config.network = get32(doc.data + 26);
  const Status status = board_config_fields_valid(config);
  if (status) out = config;
  return status;
}

}  // namespace

BoardSetupConsole::BoardSetupConsole(BoardConfigStore& config,
                                     BoardSecretsStore& secrets,
                                     IdentityStore& identity,
                                     const BoardBootIdentity* expected) noexcept
    : config_(config),
      secrets_(secrets),
      identity_(identity),
      expected_(expected) {}

BoardSetupConsole::~BoardSetupConsole() noexcept {
  secure_clear(psk_value_);
  secure_clear(usb_value_.data(), usb_value_.size());
}

Status BoardSetupConsole::process_line(const ByteView line, char* response,
                                       const std::size_t response_capacity,
                                       std::size_t& response_size) noexcept {
  response_size = 0;
  if (response == nullptr || response_capacity < kMaintenanceResponseMax ||
      (line.size > 0 && line.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "console arguments");
  }
  Response out(response, response_capacity);
  const auto fail = [&](const char* token) {
    out.put("ERR ");
    out.put(token);
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  };

  // Fresh store state every line: lock and impairment are observed, never
  // cached. An unreadable identity store cannot prove the console is
  // unlocked, so mutating verbs fail closed.
  const Status ident_status = identity_.initialize();
  const bool ident_impaired = !ident_status.ok() || identity_.uncertain() ||
                              identity_.quarantined();
  const bool locked = !ident_impaired && identity_.has_identity() &&
                      (identity_.identity().flags & kIdentityFlagConsoleLocked) != 0;
  const Status cfg_status = config_.initialize();
  const bool cfg_impaired = !cfg_status.ok() || config_.uncertain() ||
                            config_.quarantined() || !config_.readback_ready();
  const Status sec_status = secrets_.initialize();
  const bool sec_impaired = !sec_status.ok() || secrets_.uncertain() ||
                            secrets_.quarantined() || !secrets_.readback_ready();

  const Line tokens = split_line(line);
  if (!tokens.valid) {
    return fail("invalid_argument");
  }
  const bool board_line = verb_is(tokens.verb, "benchcfg");
  const bool secret_line = verb_is(tokens.verb, "benchsecret");
  if (!board_line && !secret_line) {
    return fail("invalid_argument");
  }
  if (tokens.argc < 1) {
    return fail("invalid_argument");
  }
  const ByteView sub = tokens.args[0];
  const bool status_verb = verb_is(sub, "status");
  if (!status_verb) {
    if (ident_impaired) return fail("store_unavailable");
    if (locked) return fail("locked");
  }

  if (board_line && status_verb) {
    if (tokens.argc != 1) return fail("invalid_argument");
    out.put("OK board=");
    if (cfg_impaired) {
      out.put("impaired");
    } else {
      out.put(config_.has_config() ? "committed" : "none");
    }
    if (!cfg_impaired && config_.has_config()) {
      const BoardConfig& c = config_.config();
      out.put(" generation=");
      out.put_uint(c.generation);
      out.put(" node=");
      out.put_u64_hex(c.node);
      out.put(" role=");
      out.put(role_name(c.role));
      out.put(" security=");
      out.put(security_name(c.security));
      out.put(" secrets_generation=");
      out.put_uint(c.secrets_generation);
      out.put(" fingerprint=");
      out.put(c.secrets_generation == 0 ? "-" : "");
      if (c.secrets_generation != 0) {
        out.put_hex(c.secrets_fingerprint.data(), c.secrets_fingerprint.size());
      }
    }
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (secret_line && status_verb) {
    if (tokens.argc != 1) return fail("invalid_argument");
    out.put("OK secrets=");
    if (sec_impaired) {
      out.put("impaired");
    } else {
      out.put(secrets_.has_secrets() ? "committed" : "none");
    }
    if (!sec_impaired && secrets_.has_secrets()) {
      const BoardSecrets& s = secrets_.secrets();
      Digest256 fingerprint{};
      if (!board_secrets_fingerprint(s, fingerprint).ok()) {
        return Status::error(StatusCode::InternalError, "console response");
      }
      out.put(" generation=");
      out.put_uint(s.generation);
      out.put(" psk=");
      out.put(s.has_psk ? "1" : "0");
      out.put(" usb=");
      out.put(s.usb_len > 0 ? "1" : "0");
      out.put(" fingerprint=");
      out.put_hex(fingerprint.data(), fingerprint.size());
    }
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (board_line && verb_is(sub, "stage")) {
    if (tokens.argc != 2) return fail("invalid_argument");
    std::size_t length = 0;
    if (!hex_decode(tokens.args[1], staged_doc_.data(), staged_doc_.size(), length)) {
      staged_doc_len_ = 0;  // a torn stage leaves no half-written document
      return fail("invalid_argument");
    }
    staged_doc_len_ = length;
    out.put("OK staged bytes=");
    out.put_uint(static_cast<std::uint32_t>(length));
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (board_line && verb_is(sub, "validate")) {
    if (tokens.argc != 1) return fail("invalid_argument");
    if (staged_doc_len_ == 0) return fail("no_staged");
    BoardConfig parsed{};
    if (!parse_doc(ByteView{staged_doc_.data(), staged_doc_len_}, parsed).ok()) {
      return fail("invalid_argument");
    }
    out.put("OK valid node=");
    out.put_u64_hex(parsed.node);
    out.put(" role=");
    out.put(role_name(parsed.role));
    out.put(" security=");
    out.put(security_name(parsed.security));
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (secret_line && verb_is(sub, "stage")) {
    if (tokens.argc != 4) return fail("invalid_argument");
    const ByteView kind = tokens.args[1];
    std::uint32_t generation = 0;
    if (!parse_u32(tokens.args[2], generation) || generation == 0) {
      return fail("invalid_argument");
    }
    const bool have_staged = staged_psk_ || usb_len_ > 0;
    if (have_staged && staged_generation_ != generation) {
      return fail("generation_mismatch");
    }
    if (verb_is(kind, "psk")) {
      keys::Secret value{};
      std::size_t length = 0;
      if (!hex_decode(tokens.args[3], value.data(), value.size(), length) ||
          length != value.size()) {
        return fail("invalid_argument");
      }
      psk_value_ = value;
      secure_clear(value.data(), value.size());
      staged_psk_ = true;
      staged_generation_ = generation;
    } else if (verb_is(kind, "usb")) {
      std::array<std::uint8_t, kBoardUsbSecretMax> value{};
      std::size_t length = 0;
      if (!hex_decode(tokens.args[3], value.data(), value.size(), length) ||
          length == 0 || length > kBoardUsbSecretMax) {
        return fail("invalid_argument");
      }
      for (std::size_t i = 0; i < length; ++i) {
        if (value[i] < 0x21 || value[i] > 0x7E) {
          secure_clear(value.data(), value.size());
          return fail("invalid_argument");
        }
      }
      usb_value_ = value;
      usb_len_ = static_cast<std::uint8_t>(length);
      secure_clear(value.data(), value.size());
      staged_generation_ = generation;
    } else {
      return fail("invalid_argument");
    }
    out.put("OK staged kind=");
    out.put(verb_is(kind, "psk") ? "psk" : "usb");
    out.put(" generation=");
    out.put_uint(generation);
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (board_line && verb_is(sub, "commit")) {
    if (tokens.argc != 2) return fail("invalid_argument");
    std::uint32_t generation = 0;
    if (!parse_u32(tokens.args[1], generation) || generation == 0) {
      return fail("invalid_argument");
    }
    if (staged_doc_len_ == 0) return fail("no_staged");
    if (cfg_impaired) return fail("store_unavailable");
    BoardConfig candidate{};
    if (!parse_doc(ByteView{staged_doc_.data(), staged_doc_len_}, candidate).ok()) {
      return fail("invalid_argument");
    }
    // The document must name this image's own profile when the build
    // carries one: a record for a different chip/role/security/MAC could
    // commit here but would only ever fail the field gate — refuse it at
    // the bench instead (§4.2).
    if (expected_ != nullptr &&
        (candidate.chip != expected_->chip ||
         candidate.role != expected_->role ||
         candidate.security != expected_->security ||
         candidate.sta_mac != expected_->sta_mac)) {
      return fail("profile_mismatch");
    }
    const BoardSecretsNeed need =
        board_secrets_need(candidate.security, candidate.role);
    const bool staged_any = staged_psk_ || usb_len_ > 0;
    if (staged_any || need.psk || need.usb) {
      if (sec_impaired) return fail("store_unavailable");
    }
    if (staged_any && staged_generation_ != generation) {
      return fail("generation_mismatch");
    }
    // Secrets first: a cut between the two commits leaves a boundless
    // secrets record plus the older config — the field gate then refuses,
    // never a mismatched pair.
    if (staged_any) {
      BoardSecrets intended{};
      intended.generation = generation;
      intended.has_psk = staged_psk_;
      intended.psk = psk_value_;
      intended.usb_len = usb_len_;
      intended.usb_secret = usb_value_;
      bool written_ok = secrets_.has_secrets() &&
                        board_secrets_equal(secrets_.secrets(), intended);
      if (!written_ok) {
        const Status written = secrets_.commit(intended);
        if (written) {
          const Status reread = secrets_.initialize();
          written_ok = reread.ok() && secrets_.has_secrets() &&
                       board_secrets_equal(secrets_.secrets(), intended);
        }
        secure_clear(intended.psk.data(), intended.psk.size());
        secure_clear(intended.usb_secret.data(), intended.usb_secret.size());
        if (!written) {
          return fail(written.code == StatusCode::Conflict ? "conflict"
                                                          : "commit_failed");
        }
        if (!written_ok) {
          return fail("commit_failed");
        }
      }
      staged_psk_ = false;
      staged_generation_ = 0;
      usb_len_ = 0;
      secure_clear(psk_value_);
      secure_clear(usb_value_.data(), usb_value_.size());
    }
    candidate.generation = generation;
    // Bind the durable secrets record committed at this generation. When
    // none exists the binding is zero — only valid where nothing is needed.
    candidate.secrets_generation = 0;
    candidate.secrets_fingerprint = Digest256{};
    if (!sec_impaired && secrets_.has_secrets() &&
        secrets_.secrets().generation == generation) {
      candidate.secrets_generation = generation;
      const Status fp = board_secrets_fingerprint(secrets_.secrets(),
                                                  candidate.secrets_fingerprint);
      if (!fp) return Status::error(StatusCode::InternalError, "console response");
    }
    if ((need.psk || need.usb) && candidate.secrets_generation == 0) {
      return fail("secrets_required");
    }
    if (candidate.secrets_generation != 0) {
      const BoardSecrets& bound = secrets_.secrets();
      if ((need.psk && !bound.has_psk) || (need.usb && bound.usb_len == 0)) {
        return fail("secrets_required");
      }
    }
    if (!(config_.has_config() &&
          board_config_equal(config_.config(), candidate))) {
      const Status written = config_.commit(candidate);
      if (!written) {
        return fail(written.code == StatusCode::Conflict ? "conflict"
                                                        : "commit_failed");
      }
      const Status reread = config_.initialize();
      if (!reread.ok() || !config_.has_config() ||
          !board_config_equal(config_.config(), candidate)) {
        return fail("commit_failed");
      }
    }
    out.put("OK committed generation=");
    out.put_uint(generation);
    out.put(" node=");
    out.put_u64_hex(candidate.node);
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  return fail("invalid_argument");
}

}  // namespace routeloom::sdkv1
