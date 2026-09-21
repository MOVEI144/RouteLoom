#include "routeloom/discovery_scope.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"

// Portable Discovery Scope Key machinery (02-discovery-scope.md, 05 §5.2).
// See discovery_scope.hpp for the contract overview.

namespace routeloom {
namespace {

constexpr std::uint32_t kSha256RoundConstants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::uint32_t rotr(const std::uint32_t value,
                             const std::uint32_t bits) noexcept {
  return (value >> bits) | (value << (32U - bits));
}

}  // namespace

// --- Sha256 ---------------------------------------------------------------------

void Sha256::reset() noexcept {
  state_[0] = 0x6a09e667U;
  state_[1] = 0xbb67ae85U;
  state_[2] = 0x3c6ef372U;
  state_[3] = 0xa54ff53aU;
  state_[4] = 0x510e527fU;
  state_[5] = 0x9b05688cU;
  state_[6] = 0x1f83d9abU;
  state_[7] = 0x5be0cd19U;
  buffered_ = 0;
  total_bytes_ = 0;
}

void Sha256::block(const std::uint8_t* data) noexcept {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(data[i * 4]) << 24U) |
           (static_cast<std::uint32_t>(data[i * 4 + 1]) << 16U) |
           (static_cast<std::uint32_t>(data[i * 4 + 2]) << 8U) |
           static_cast<std::uint32_t>(data[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
    const std::uint32_t s1 =
        rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];
  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t t1 = h + s1 + ch + kSha256RoundConstants[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const ByteView data) noexcept {
  if (data.data == nullptr || data.size == 0) return;
  total_bytes_ += data.size;
  std::size_t offset = 0;
  if (buffered_ > 0) {
    const std::size_t take = 64 - buffered_ < data.size ? 64 - buffered_ : data.size;
    std::memcpy(buffer_.data() + buffered_, data.data + offset, take);
    buffered_ += take;
    offset += take;
    if (buffered_ == 64) {
      block(buffer_.data());
      buffered_ = 0;
    }
  }
  while (offset + 64 <= data.size) {
    block(data.data + offset);
    offset += 64;
  }
  if (offset < data.size) {
    std::memcpy(buffer_.data(), data.data + offset, data.size - offset);
    buffered_ = data.size - offset;
  }
}

void Sha256::finish(ScopeDigest& out) noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8;
  buffer_[buffered_++] = 0x80;
  if (buffered_ > 56) {
    std::memset(buffer_.data() + buffered_, 0, 64 - buffered_);
    block(buffer_.data());
    buffered_ = 0;
  }
  std::memset(buffer_.data() + buffered_, 0, 56 - buffered_);
  for (int i = 0; i < 8; ++i) {
    buffer_[56 + i] = static_cast<std::uint8_t>(bit_length >> (56 - i * 8));
  }
  block(buffer_.data());
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(state_[i] >> 24U);
    out[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16U);
    out[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8U);
    out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
  }
  reset();
}

void sha256(const ByteView input, ScopeDigest& out) noexcept {
  Sha256 hash;
  hash.update(input);
  hash.finish(out);
}

void hmac_sha256(const ByteView key, const ByteView input,
                 ScopeDigest& out) noexcept {
  hmac_sha256(key, input, ByteView{}, ByteView{}, out);
}

void hmac_sha256(const ByteView key, const ByteView part_a,
                 const ByteView part_b, const ByteView part_c,
                 ScopeDigest& out) noexcept {
  std::array<std::uint8_t, 64> pad_key{};
  if (key.size > 64) {
    ScopeDigest hashed{};
    sha256(key, hashed);
    std::memcpy(pad_key.data(), hashed.data(), hashed.size());
  } else if (key.size > 0 && key.data != nullptr) {
    std::memcpy(pad_key.data(), key.data, key.size);
  }
  std::array<std::uint8_t, 64> pad{};
  for (std::size_t i = 0; i < pad.size(); ++i) pad[i] = pad_key[i] ^ 0x36;
  ScopeDigest inner{};
  {
    Sha256 hash;
    hash.update(ByteView{pad.data(), pad.size()});
    hash.update(part_a);
    hash.update(part_b);
    hash.update(part_c);
    hash.finish(inner);
  }
  for (std::size_t i = 0; i < pad.size(); ++i) pad[i] = pad_key[i] ^ 0x5c;
  {
    Sha256 hash;
    hash.update(ByteView{pad.data(), pad.size()});
    hash.update(ByteView{inner.data(), inner.size()});
    hash.finish(out);
  }
  pad_key.fill(0);
  pad.fill(0);
  inner.fill(0);
}

bool constant_time_equal(const ByteView a, const ByteView b) noexcept {
  if (a.size != b.size || (a.size != 0 && (a.data == nullptr || b.data == nullptr))) {
    return false;
  }
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < a.size; ++i) diff |= a.data[i] ^ b.data[i];
  return diff == 0;
}

// --- Provider helpers -------------------------------------------------------------

Status scope_tag_verify(DiscoveryScopeProvider& provider, const ScopeRef scope,
                        const std::uint32_t generation, const ByteView input,
                        const ScopeTag& expected) noexcept {
  ScopeTag computed{};
  const Status status = provider.scope_tag(scope, generation, input, computed);
  if (!status) return status;
  return constant_time_equal(ByteView{computed.data(), computed.size()},
                             ByteView{expected.data(), expected.size()})
             ? Status::success()
             : Status::error(StatusCode::AuthenticationFailed,
                             "scope tag mismatch");
}

Status scope_hint(DiscoveryScopeProvider& provider, const ScopeRef scope,
                  const std::uint32_t generation,
                  const endpoint::ScopeClass scope_class, const NetworkId network,
                  std::uint32_t& out) noexcept {
  // domain_hint (with trailing NUL) || class u8 || Network u64 || generation u32.
  std::array<std::uint8_t, sizeof(endpoint::kScopeHintDomain) + 13> input{};
  ByteWriter writer(MutableByteView{input.data(), input.size()});
  Status status;
#define RL_WRITE(expr)             \
  do {                             \
    status = (expr);               \
    if (!status) return status;    \
  } while (false)
  RL_WRITE(writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>(endpoint::kScopeHintDomain),
               sizeof(endpoint::kScopeHintDomain)}));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(scope_class)));
  RL_WRITE(writer.write_u64(network));
  RL_WRITE(writer.write_u32(generation));
#undef RL_WRITE
  ScopeTag tag{};
  status = provider.scope_tag(scope, generation,
                              ByteView{input.data(), writer.size()}, tag);
  if (!status) return status;
  out = (static_cast<std::uint32_t>(tag[0]) << 24U) |
        (static_cast<std::uint32_t>(tag[1]) << 16U) |
        (static_cast<std::uint32_t>(tag[2]) << 8U) |
        static_cast<std::uint32_t>(tag[3]);
  return Status::success();
}

ScopeDigest scope_binding_digest(const bool scoped,
                                 const endpoint::ScopeClass scope_class,
                                 const std::uint32_t generation,
                                 const ScopeDigest& discover_digest,
                                 const ScopeDigest& offer_digest) noexcept {
  // SHA256(domain_binding || 71B input). Scoped: fields via the pinned codec;
  // legacy: class/generation/scheme/scoped all zero with real frame digests.
  std::array<std::uint8_t, endpoint::kScopeBindingSize> input{};
  if (scoped) {
    endpoint::ScopeBindingInput binding{};
    binding.scope_class = scope_class;
    binding.generation = generation;
    binding.scoped = 1;
    binding.discover_digest = discover_digest;
    binding.offer_digest = offer_digest;
    (void)endpoint::scope_binding_encode(binding, input);
  } else {
    std::memcpy(input.data() + 7, discover_digest.data(), discover_digest.size());
    std::memcpy(input.data() + 39, offer_digest.data(), offer_digest.size());
  }
  ScopeDigest out{};
  Sha256 hash;
  hash.update(ByteView{
      reinterpret_cast<const std::uint8_t*>(endpoint::kScopeBindingDomain),
      sizeof(endpoint::kScopeBindingDomain)});
  hash.update(ByteView{input.data(), input.size()});
  hash.finish(out);
  return out;
}

// --- ScopeKeyRing -------------------------------------------------------------------

Status ScopeKeyRing::install(const std::uint32_t generation,
                             const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (generation == 0) {
    return Status::error(StatusCode::InvalidArgument, "scope generation 0 invalid");
  }
  if (current_ != 0) {
    return Status::error(StatusCode::InvalidState, "scope key already installed");
  }
  current_ = generation;
  return Status::success();
}

Status ScopeKeyRing::rotate(const std::uint32_t next_generation,
                            const MonotonicMs now_ms) noexcept {
  if (current_ == 0) {
    return Status::error(StatusCode::InvalidState, "no current scope key");
  }
  // Strictly increasing u32: this also forbids 0 and wrap.
  if (next_generation <= current_) {
    return Status::error(StatusCode::InvalidArgument,
                         "scope generation must increase");
  }
  previous_ = current_;
  previous_until_ms_ = now_ms + kScopePreviousOverlapMaxMs;
  current_ = next_generation;
  return Status::success();
}

bool ScopeKeyRing::current(std::uint32_t& out) const noexcept {
  if (current_ == 0) return false;
  out = current_;
  return true;
}

bool ScopeKeyRing::accepted(const std::uint32_t generation,
                            const MonotonicMs now_ms) const noexcept {
  if (generation == 0) return false;
  if (generation == current_) return true;
  return generation == previous_ && now_ms < previous_until_ms_;
}

// --- ScopeDedupTable ------------------------------------------------------------------

ScopeDedupResult ScopeDedupTable::check(
    const MacAddress& source, const std::array<std::uint8_t, 16>& nonce,
    const std::uint8_t scope_class, const std::uint32_t generation,
    const std::array<std::uint8_t, 16>& content,
    const MonotonicMs now_ms) noexcept {
  // class/generation 0 marks the unauthenticated legacy lane; only
  // MAC-verified scoped frames populate nonzero records.
  const bool verified_in = scope_class != 0;
  // Exact-key lookup across ALL retained records — live AND expired. A
  // record whose first-sight window closed still answers Duplicate/Conflict
  // for an exact-key replay instead of re-admitting it as fresh work: an
  // honest retransmission always carries a fresh nonce, so a post-TTL key
  // match is a replay and must not count as new density (02 §2.5). TTL is
  // still measured from first sight only — re-receiving extends nothing.
  const Record* found = records_.find([&](const Record& record) {
    return record.source == source && record.nonce == nonce &&
           record.scope_class == scope_class && record.generation == generation;
  });
  if (found != nullptr) {
    return found->content == content ? ScopeDedupResult::Duplicate
                                     : ScopeDedupResult::Conflict;
  }

  // Victim ordering when no free slot exists: expired records are taken
  // before live ones (legacy-expired first — verified replay memory is the
  // last thing to give up), and only a MAC-verified scoped record may
  // evict the oldest LIVE legacy record. Verified records are never
  // evicted by unauthenticated traffic, and a live verified record is
  // never evicted at all — protected semantics preserved (02 §2.5).
  Record* expired_legacy = nullptr;
  Record* expired_scoped = nullptr;
  Record* live_legacy = nullptr;
  records_.for_each([&](Record& record) {
    const bool legacy = record.scope_class == 0;
    const bool expired = now_ms >= record.first_seen_ms + kScopeDedupTtlMs;
    if (expired) {
      Record*& victim = legacy ? expired_legacy : expired_scoped;
      if (victim == nullptr || record.first_seen_ms < victim->first_seen_ms) {
        victim = &record;
      }
    } else if (legacy && (live_legacy == nullptr ||
                          record.first_seen_ms < live_legacy->first_seen_ms)) {
      live_legacy = &record;
    }
  });
  Record* record = records_.allocate();
  if (record == nullptr) {
    record = expired_legacy != nullptr ? expired_legacy : expired_scoped;
    if (record == nullptr) {
      record = verified_in ? live_legacy : nullptr;
      if (record == nullptr) {
        return ScopeDedupResult::Full;
      }
    }
  }
  record->source = source;
  record->nonce = nonce;
  record->content = content;
  record->generation = generation;
  record->scope_class = scope_class;
  record->first_seen_ms = now_ms;
  return ScopeDedupResult::New;
}

}  // namespace routeloom
