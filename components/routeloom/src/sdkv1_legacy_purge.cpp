#include "routeloom/sdkv1_legacy_purge.hpp"

#include <cstring>

namespace routeloom::sdkv1 {
namespace {
constexpr std::size_t kMaxScan = 4096;
constexpr std::size_t kLineMax = 128;

bool name_is(const char* actual, const char* expected) noexcept {
  if (!actual || !expected) return false;
  for (std::size_t i = 0; i < 16; ++i) {
    if (actual[i] != expected[i]) return false;
    if (actual[i] == '\0') return true;
  }
  return false;
}

bool hex(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

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
  bool put_u32(const std::uint32_t value) noexcept {
    char digits[10];
    std::size_t count = 0;
    std::uint32_t rest = value;
    do {
      digits[count++] = static_cast<char>('0' + (rest % 10));
      rest /= 10;
    } while (rest != 0);
    if (!ok_ || count > capacity_ - size_) {
      ok_ = false;
      return false;
    }
    for (std::size_t i = 0; i < count; ++i) buffer_[size_++] = digits[count - 1 - i];
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

// One line = up to 4 tokens separated by exactly one space; no leading or
// trailing space. Anything else is not a line.
struct Line {
  bool valid{false};
  ByteView verb{};
  ByteView args[3]{};
  int argc{0};
};

Line split_line(const ByteView line) noexcept {
  Line out{};
  if (line.data == nullptr || line.size == 0 || line.size > kLineMax) return out;
  if (line.data[line.size - 1] == ' ') return out;
  std::size_t starts[4]{};
  std::size_t lengths[4]{};
  int count = 0;
  std::size_t i = 0;
  while (i < line.size && count < 4) {
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

bool token_is(const ByteView token, const char* name) noexcept {
  const std::size_t length = std::strlen(name);
  return token.size == length && std::memcmp(token.data, name, length) == 0;
}

int hex_value(const std::uint8_t c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parse_domain(const ByteView text, std::array<std::uint8_t, 16>& out) noexcept {
  out = std::array<std::uint8_t, 16>{};
  if (text.size != 32) return false;
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int hi = hex_value(text.data[2 * i]);
    const int lo = hex_value(text.data[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      out = std::array<std::uint8_t, 16>{};
      return false;
    }
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return true;
}
}  // namespace

bool is_legacy_peer_key(const LegacyKey& key) noexcept {
  const bool counter = name_is(key.name_space, "rlcounter");
  const bool replay = name_is(key.name_space, "rlreplay");
  if ((!counter && !replay) || !key.key) return false;
  if (counter ? key.key[0] != 'c' : (key.key[0] != 'f' && key.key[0] != 'r')) return false;
  for (std::size_t i = 1; i <= 8; ++i) {
    if (!hex(key.key[i])) return false;
  }
  return key.key[9] == '\0';
}

Status purge_legacy_state(LegacyPurgePort& port, const bool stopped,
                          const bool ram_only_build, LegacyPurgeResult& result) noexcept {
  (void)port;
  (void)stopped;
  (void)ram_only_build;
  (void)result;
  // The marker is invisible to older PSK images. No caller may erase
  // their replay floors until rollback is fenced outside this binary.
  return Status::error(StatusCode::RecoveryRequired, "legacy purge rollback unsafe");
}

LegacyStateConsole::LegacyStateConsole(LegacyPurgePort& port,
                                       const std::array<std::uint8_t, 16>& domain,
                                       const bool ram_only_build) noexcept
    : port_(port), domain_(domain), ram_only_(ram_only_build) {}

Status LegacyStateConsole::process_line(const ByteView line, const bool stopped, char* response,
                                        const std::size_t response_capacity,
                                        std::size_t& response_size) noexcept {
  response_size = 0;
  if (response == nullptr || response_capacity < kResponseMax) {
    return Status::error(StatusCode::InvalidArgument, "legacy console response short");
  }
  Response out(response, response_capacity);
  const Line parsed = split_line(line);
  if (!parsed.valid) {
    out.put("ERR invalid_argument");
    out.finish();
    response_size = out.size();
    return Status::success();
  }
  if (token_is(parsed.verb, "status") && parsed.argc == 0) {
    bool marker = false;
    Status status = port_.migration(marker);
    std::uint32_t legacy = 0;
    std::size_t cursor = 0;
    std::size_t scanned = 0;
    while (status.ok() && scanned < kMaxScan) {
      LegacyKey key{};
      bool found = false;
      status = port_.next(cursor, key, found);
      if (!status.ok() || !found) break;
      ++scanned;
      if (is_legacy_peer_key(key)) ++legacy;
    }
    if (!status.ok() || scanned == kMaxScan) {
      out.put("ERR store");
    } else {
      out.put("OK legacy=");
      out.put_u32(legacy);
      out.put(" marker=");
      out.put_u32(marker ? 1 : 0);
    }
    out.finish();
    response_size = out.size();
    return Status::success();
  }
  const bool purge_shape = token_is(parsed.verb, "purge") && parsed.argc == 3 &&
                           token_is(parsed.args[0], "--domain") &&
                           token_is(parsed.args[2], "--confirm");
  if (!purge_shape) {
    out.put("ERR invalid_argument");
    out.finish();
    response_size = out.size();
    return Status::success();
  }
  // Nothing below may touch the store before every gate passes.
  if (!stopped) {
    out.put("ERR busy");
  } else if (!ram_only_) {
    out.put("ERR refused");
  } else {
    std::array<std::uint8_t, 16> domain{};
    std::uint8_t diff = 0;
    if (!parse_domain(parsed.args[1], domain)) {
      out.put("ERR domain");
    } else {
      for (std::size_t i = 0; i < domain.size(); ++i) {
        diff |= static_cast<std::uint8_t>(domain[i] ^ domain_[i]);
      }
      for (auto& byte : domain) byte = 0;
      if (diff != 0) {
        out.put("ERR domain");
      } else {
        // The marker cannot stop a pre-migration PSK binary. Keep its
        // replay floors and counter leases until rollback can be fenced.
        out.put("ERR rollback_unsafe");
      }
    }
  }
  out.finish();
  response_size = out.size();
  return Status::success();
}

Status strip_legacy_state_prefix(const ByteView line, ByteView& rest) noexcept {
  rest = ByteView{};
  static constexpr char kPrefix[] = "security legacy-state";
  constexpr std::size_t kPrefixLen = sizeof(kPrefix) - 1;
  if (line.data == nullptr || line.size < kPrefixLen ||
      std::memcmp(line.data, kPrefix, kPrefixLen) != 0) {
    return Status::error(StatusCode::NotFound, "not a legacy-state line");
  }
  if (line.size == kPrefixLen) return Status::success();  // bare prefix, empty rest
  if (line.data[kPrefixLen] != ' ') {
    return Status::error(StatusCode::NotFound, "not a legacy-state line");
  }
  rest.data = line.data + kPrefixLen + 1;
  rest.size = line.size - kPrefixLen - 1;
  return Status::success();
}

}  // namespace routeloom::sdkv1
