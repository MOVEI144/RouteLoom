#include "routeloom/sdkv1_maintenance.hpp"

#include <cstring>

#include "routeloom/sdkv1_pop.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

constexpr std::size_t kKeygenEntropyTries = 4;
constexpr char kBundleFormat[] = "routeloom-identity-bundle-v1";

int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

// Strict response builder: any overflow fails instead of truncating (the
// caller guarantees kMaintenanceResponseMax, so overflow is unreachable).
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
  if (text.data == nullptr || text.size % 2 != 0 || text.size / 2 > out_max) return false;
  for (std::size_t i = 0; i < text.size; i += 2) {
    const int high = hex_value(static_cast<char>(text.data[i]));
    const int low = hex_value(static_cast<char>(text.data[i + 1]));
    if (high < 0 || low < 0) return false;
    out[out_len++] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

// One line = up to 3 tokens separated by exactly one space; no leading or
// trailing space. Anything else is not a line.
struct Line {
  bool valid{false};
  ByteView verb{};
  ByteView args[2]{};
  int argc{0};
};

Line split_line(const ByteView line) noexcept {
  Line out{};
  if (line.data == nullptr || line.size == 0 || line.size > kMaintenanceLineMax) {
    return out;
  }
  if (line.data[line.size - 1] == ' ') return out;
  std::size_t starts[3]{};
  std::size_t lengths[3]{};
  int count = 0;
  std::size_t i = 0;
  while (i < line.size && count < 3) {
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

bool parse_node(const ByteView text, NodeId& node) noexcept {
  node = kInvalidNodeId;
  std::uint8_t raw[8]{};
  std::size_t length = 0;
  if (!hex_decode(text, raw, sizeof(raw), length) || length != sizeof(raw)) return false;
  std::uint64_t value = 0;
  for (const std::uint8_t byte : raw) value = (value << 8U) | byte;
  if (value == 0 || value == ~std::uint64_t{0}) return false;
  node = value;
  return true;
}

// --- Identity bundle -----------------------------------------------------------
// Strict reader for exactly what the office emits (identity_bundle_json):
// fixed keys in fixed order, no unknown fields, no string escapes. The
// format marker versions the emitter and this parser together: anything
// else fails closed.

struct Bundle {
  NodeId node{kInvalidNodeId};
  std::uint8_t flags{0};
  Digest256 kid{};
  P256PublicKey pubkey{};
  std::array<IdentityAnchor, kIdentityAnchorMax> anchors{};
  std::uint8_t anchor_count{0};
  ByteBuffer<kRlcw1CertMax> devcert{};
};

class BundleParser {
 public:
  explicit BundleParser(const ByteView text) noexcept : text_(text) {}

  bool parse(Bundle& out) noexcept {
    out = Bundle{};
    if (!expect('{') || !ws()) return false;
    if (!key("format") || !string_equals(kBundleFormat)) return false;
    if (!comma()) return false;
    if (!key("node_id") || !hex_u64(out.node) || out.node == 0 ||
        out.node == ~std::uint64_t{0}) {
      return false;
    }
    if (!comma()) return false;
    std::uint64_t flags = 0;
    if (!key("flags") || !number(0xFF, flags)) return false;
    out.flags = static_cast<std::uint8_t>(flags);
    if (!comma()) return false;
    if (!key("kid_hex") || !hex_bytes(out.kid.data(), out.kid.size())) return false;
    if (!comma()) return false;
    if (!key("pubkey_hex") || !hex_bytes(out.pubkey.data(), out.pubkey.size())) return false;
    if (!comma()) return false;
    if (!key("anchors") || !expect('[') || !ws()) return false;
    for (;;) {
      if (out.anchor_count >= kIdentityAnchorMax) return false;
      if (!anchor(out.anchors[out.anchor_count])) return false;
      ++out.anchor_count;
      if (!ws()) return false;
      if (peek() == ',') {
        ++pos_;
        if (!ws()) return false;
        continue;
      }
      break;
    }
    if (out.anchor_count == 0 || !expect(']')) return false;
    if (!comma()) return false;
    std::uint8_t devcert[kRlcw1CertMax]{};
    std::size_t devcert_len = 0;
    if (!key("devcert_hex") || !hex_string(devcert, sizeof(devcert), devcert_len) ||
        devcert_len == 0) {
      return false;
    }
    std::memcpy(out.devcert.bytes.data(), devcert, devcert_len);
    out.devcert.size = devcert_len;
    if (!ws() || !expect('}')) return false;
    return ws() && pos_ == text_.size;
  }

 private:
  bool anchor(IdentityAnchor& out) noexcept {
    out = IdentityAnchor{};
    std::uint64_t id = 0;
    std::uint8_t kind = 0;
    std::uint8_t status = 0;
    if (!expect('{') || !ws()) return false;
    if (!key("anchor_id") || !hex_u64(id)) return false;
    if (!comma()) return false;
    if (!key("kind") || !enumerant(kind_map, kind)) return false;
    if (!comma()) return false;
    if (!key("status") || !enumerant(status_map, status)) return false;
    if (!comma()) return false;
    if (!key("pubkey_hex") || !hex_bytes(out.pubkey.data(), out.pubkey.size())) return false;
    if (!ws() || !expect('}')) return false;
    out.anchor_id = id;
    out.kind = static_cast<AnchorKind>(kind);
    out.status = static_cast<AnchorStatus>(status);
    return true;
  }

  struct NameValue {
    const char* name;
    std::uint8_t value;
  };
  static constexpr NameValue kind_map[] = {{"site-ca", 1}, {"assignment-verifier", 2}};
  static constexpr NameValue status_map[] = {{"active", 1}, {"disabled", 2}};

  bool enumerant(const NameValue* map, std::uint8_t& value) noexcept {
    std::uint8_t text[24]{};
    std::size_t length = 0;
    if (!quoted(text, sizeof(text), length)) return false;
    for (int i = 0; i < 2; ++i) {
      const std::size_t name_len = std::strlen(map[i].name);
      if (length == name_len && std::memcmp(text, map[i].name, length) == 0) {
        value = map[i].value;
        return true;
      }
    }
    return false;
  }

  bool comma() noexcept {
    if (!ws() || !expect(',')) return false;
    return ws();
  }

  // `"name" :` with optional whitespace around the colon.
  bool key(const char* name) noexcept {
    if (!expect('"')) return false;
    const std::size_t length = std::strlen(name);
    if (pos_ + length + 1 > text_.size ||
        std::memcmp(text_.data + pos_, name, length) != 0 ||
        text_.data[pos_ + length] != '"') {
      return false;
    }
    pos_ += length + 1;
    return ws() && expect(':') && ws();
  }

  bool string_equals(const char* expected) noexcept {
    std::uint8_t text[64]{};
    std::size_t length = 0;
    if (!quoted(text, sizeof(text), length)) return false;
    const std::size_t want = std::strlen(expected);
    return length == want && std::memcmp(text, expected, want) == 0;
  }

  bool hex_u64(std::uint64_t& value) noexcept {
    std::uint8_t raw[8]{};
    if (!hex_bytes(raw, sizeof(raw))) return false;
    value = 0;
    for (const std::uint8_t byte : raw) value = (value << 8U) | byte;
    return true;
  }

  bool hex_bytes(std::uint8_t* out, const std::size_t size) noexcept {
    std::size_t length = 0;
    return hex_string(out, size, length) && length == size;
  }

  // A quoted even-length hex string decoding to 1..max bytes.
  bool hex_string(std::uint8_t* out, const std::size_t max, std::size_t& length) noexcept {
    length = 0;
    std::uint8_t text[2 * kRlcw1CertMax]{};
    std::size_t text_len = 0;
    if (!quoted(text, sizeof(text), text_len)) return false;
    if (text_len == 0 || text_len % 2 != 0) return false;
    if (!hex_decode(ByteView{text, text_len}, out, max, length)) return false;
    return length > 0;
  }

  bool number(const std::uint64_t cap, std::uint64_t& value) noexcept {
    value = 0;
    if (pos_ >= text_.size || text_.data[pos_] < '0' || text_.data[pos_] > '9') return false;
    while (pos_ < text_.size && text_.data[pos_] >= '0' && text_.data[pos_] <= '9') {
      const std::uint64_t digit = static_cast<std::uint64_t>(text_.data[pos_] - '0');
      if (value > (cap - digit) / 10) return false;
      value = value * 10 + digit;
      ++pos_;
    }
    return true;
  }

  // A quoted string without escapes (the emitter never produces any);
  // control bytes and backslashes are rejected.
  bool quoted(std::uint8_t* out, const std::size_t max, std::size_t& length) noexcept {
    length = 0;
    if (!expect('"')) return false;
    while (pos_ < text_.size && text_.data[pos_] != '"') {
      const std::uint8_t byte = text_.data[pos_];
      if (byte < 0x20 || byte == '\\' || length >= max) return false;
      out[length++] = byte;
      ++pos_;
    }
    return expect('"');
  }

  bool ws() noexcept {
    while (pos_ < text_.size) {
      const std::uint8_t byte = text_.data[pos_];
      if (byte != ' ' && byte != '\t' && byte != '\n' && byte != '\r') break;
      ++pos_;
    }
    return true;
  }

  bool expect(const char want) noexcept {
    if (pos_ >= text_.size || text_.data[pos_] != static_cast<std::uint8_t>(want)) {
      return false;
    }
    ++pos_;
    return true;
  }

  std::uint8_t peek() const noexcept {
    return pos_ < text_.size ? text_.data[pos_] : 0;
  }

  ByteView text_{};
  std::size_t pos_{0};
};

bool identity_equal(const IdentityRecord& a, const IdentityRecord& b) noexcept {
  if (a.node_id != b.node_id || a.key_location != b.key_location || a.flags != b.flags ||
      a.kid != b.kid || a.pubkey != b.pubkey || a.key_material != b.key_material ||
      a.anchor_count != b.anchor_count || a.devcert.size != b.devcert.size) {
    return false;
  }
  for (std::uint8_t i = 0; i < a.anchor_count; ++i) {
    if (a.anchors[i].anchor_id != b.anchors[i].anchor_id ||
        a.anchors[i].kind != b.anchors[i].kind ||
        a.anchors[i].status != b.anchors[i].status ||
        a.anchors[i].pubkey != b.anchors[i].pubkey) {
      return false;
    }
  }
  return std::memcmp(a.devcert.bytes.data(), b.devcert.bytes.data(), a.devcert.size) == 0;
}

}  // namespace

MaintenanceConsole::MaintenanceConsole(IdentityStore& store,
                                       EntropySource& entropy) noexcept
    : store_(store), entropy_(entropy) {}

MaintenanceConsole::~MaintenanceConsole() noexcept {
  secure_clear(pending_scalar_);
  pending_pubkey_ = P256PublicKey{};
}

Status MaintenanceConsole::process_line(const ByteView line, char* response,
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
  // Fresh store state on every line: impairment is observed, never cached.
  // (An uncertain/quarantined store reports an error *and* its flag; an
  // unreadable one reports the fault with no flags — all three refuse.)
  const Status store_status = store_.initialize();
  if (!store_status.ok() || store_.quarantined() || store_.uncertain()) {
    return fail("store_unavailable");
  }
  if (store_.has_identity() &&
      (store_.identity().flags & kIdentityFlagConsoleLocked) != 0) {
    return fail("locked");
  }
  const Line tokens = split_line(line);
  if (!tokens.valid) {
    return fail("invalid_argument");
  }
  if (verb_is(tokens.verb, "status")) {
    if (tokens.argc != 0) {
      return fail("invalid_argument");
    }
    out.put("OK identity=");
    out.put(store_.has_identity() ? "sealed" : "none");
    out.put(" pending=");
    out.put(has_pending_ ? "1" : "0");
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (verb_is(tokens.verb, "keygen")) {
    if (tokens.argc != 2) {
      return fail("invalid_argument");
    }
    if (store_.has_identity()) {
      return fail("already_provisioned");
    }
    NodeId node = kInvalidNodeId;
    std::uint8_t challenge[kPopChallengeSize]{};
    std::size_t challenge_len = 0;
    if (!parse_node(tokens.args[0], node) ||
        !hex_decode(tokens.args[1], challenge, sizeof(challenge), challenge_len) ||
        challenge_len != sizeof(challenge)) {
      return fail("invalid_argument");
    }
    std::array<std::uint8_t, 32> scalar{};
    bool sampled = false;
    for (std::size_t attempt = 0; attempt < kKeygenEntropyTries; ++attempt) {
      if (!entropy_
               .fill(MutableByteView{scalar.data(), scalar.size()})
               .ok()) {
        secure_clear(scalar);
        return fail("entropy_not_ready");
      }
      if (p256_scalar_valid(ByteView{scalar.data(), scalar.size()})) {
        sampled = true;
        break;
      }
    }
    if (!sampled) {
      secure_clear(scalar);
      return fail("internal_error");
    }
    ByteBuffer<kPopObjectSize> pop{};
    P256PublicKey pubkey{};
    const Status signed_pop =
        pop_sign(node, CredentialKeyLocation::NvsPlaintext,
                 ByteView{challenge, sizeof(challenge)},
                 ByteView{scalar.data(), scalar.size()}, pop, pubkey);
    if (!signed_pop.ok()) {
      secure_clear(scalar);
      secure_clear(pending_scalar_);
      has_pending_ = false;
      return fail("internal_error");
    }
    secure_clear(pending_scalar_);
    has_pending_ = true;
    pending_node_ = node;
    pending_scalar_ = scalar;
    pending_pubkey_ = pubkey;
    secure_clear(scalar);
    out.put("OK pop_hex=");
    out.put_hex(pop.bytes.data(), pop.size);
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  if (verb_is(tokens.verb, "identity")) {
    if (tokens.argc != 1) {
      return fail("invalid_argument");
    }
    if (store_.has_identity()) {
      return fail("already_provisioned");
    }
    std::uint8_t bundle_text[kMaintenanceBundleMax]{};
    std::size_t bundle_len = 0;
    if (!hex_decode(tokens.args[0], bundle_text, sizeof(bundle_text), bundle_len) ||
        bundle_len == 0) {
      return fail("invalid_argument");
    }
    Bundle bundle{};
    BundleParser parser(ByteView{bundle_text, bundle_len});
    if (!parser.parse(bundle)) {
      return fail("invalid_argument");
    }
    if (!has_pending_) {
      return fail("no_pending_key");
    }
    if (bundle.node != pending_node_) {
      return fail("node_mismatch");
    }
    Digest256 pending_kid{};
    if (bundle.pubkey != pending_pubkey_ ||
        !credential_kid(ByteView{pending_pubkey_.data(), pending_pubkey_.size()},
                        pending_kid)
             .ok() ||
        pending_kid != bundle.kid) {
      return fail("key_mismatch");
    }
    IdentityRecord record{};
    record.node_id = bundle.node;
    record.key_location = CredentialKeyLocation::NvsPlaintext;
    record.flags = bundle.flags;
    record.kid = bundle.kid;
    record.pubkey = pending_pubkey_;
    record.key_material = pending_scalar_;
    record.anchors = bundle.anchors;
    record.anchor_count = bundle.anchor_count;
    record.devcert = bundle.devcert;
    if (!identity_validate(record).ok()) {
      return fail("invalid_argument");
    }
    if (!store_.commit(record).ok()) {
      return fail("seal_failed");
    }
    // Readback: re-read the store like a fresh boot and confirm the adopted
    // record is the sealed one before claiming success.
    const Status reread = store_.initialize();
    if (!reread.ok() || !store_.has_identity() ||
        !identity_equal(store_.identity(), record)) {
      return fail("seal_failed");
    }
    secure_clear(pending_scalar_);
    pending_pubkey_ = P256PublicKey{};
    pending_node_ = kInvalidNodeId;
    has_pending_ = false;
    out.put("OK sealed kid=");
    out.put_hex(bundle.kid.data(), bundle.kid.size());
    if (!out.finish()) {
      return Status::error(StatusCode::InternalError, "console response");
    }
    response_size = out.size();
    return Status::success();
  }
  return fail("invalid_argument");
}

}  // namespace routeloom::sdkv1
