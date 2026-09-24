#include "routeloom/key_schedule.hpp"

#include <cstring>

#include "routeloom/kdf.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::keys {
namespace {

// Longest info: resume-key label (23) + 0x00 + 1+1+8+8+8+4+4+32 = 90 bytes.
constexpr std::size_t kInfoCapacity = 96;

// Fixed-capacity info builder: label || 0x00 || big-endian fields. Overflow is
// a programming error in this file (every info is fixed-width); it latches
// `ok = false` and the caller refuses instead of deriving from a short info.
struct Info {
  std::array<std::uint8_t, kInfoCapacity> bytes{};
  std::size_t size{0};
  bool ok{true};

  explicit Info(const char* label) noexcept {
    put(reinterpret_cast<const std::uint8_t*>(label), std::strlen(label));
    u8(0);
  }
  void put(const std::uint8_t* data, const std::size_t count) noexcept {
    if (!ok || count > bytes.size() - size) {
      ok = false;
      return;
    }
    if (count != 0) std::memcpy(bytes.data() + size, data, count);
    size += count;
  }
  void u8(const std::uint8_t value) noexcept { put(&value, 1); }
  void be(const std::uint64_t value, const std::size_t width) noexcept {
    std::uint8_t tmp[8]{};
    for (std::size_t i = 0; i < width; ++i) {
      tmp[i] = static_cast<std::uint8_t>(value >> (8 * (width - 1 - i)));
    }
    put(tmp, width);
  }
  void u32(const std::uint32_t value) noexcept { be(value, 4); }
  void u64(const std::uint64_t value) noexcept { be(value, 8); }
  ByteView view() const noexcept { return ByteView{bytes.data(), size}; }
};

Status expand_key_iv(const ScopeDigest& prk, const Info& info, TrafficKey& out) noexcept {
  clear(out);
  if (!info.ok) return Status::error(StatusCode::InternalError, "key schedule info overflow");
  std::array<std::uint8_t, kKeyIvSize> okm{};
  const Status status = hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, info.view(),
                                           MutableByteView{okm.data(), okm.size()});
  if (status) {
    std::memcpy(out.key.data(), okm.data(), kAeadKeySize);
    std::memcpy(out.iv.data(), okm.data() + kAeadKeySize, kAeadIvSize);
  }
  secure_clear(okm);
  return status;
}

Status expand_secret(const ByteView prk, const Info& info, Secret& out) noexcept {
  if (!info.ok) {
    secure_clear(out);
    return Status::error(StatusCode::InternalError, "key schedule info overflow");
  }
  return hkdf_sha256_expand(prk, info.view(), MutableByteView{out.data(), out.size()});
}

ByteView label_view(const char* label) noexcept {
  return ByteView{reinterpret_cast<const std::uint8_t*>(label), std::strlen(label)};
}

}  // namespace

void clear(TrafficKey& key) noexcept {
  secure_clear(key.key);
  secure_clear(key.iv);
}

Status aead_nonce(const std::array<std::uint8_t, kAeadIvSize>& iv, const std::uint64_t counter,
                  AeadNonce& out) noexcept {
  out.fill(0);
  if (counter > kMaxAeadCounter) {
    return Status::error(StatusCode::CounterExhausted, "aead counter above 2^48-1");
  }
  out = iv;
  for (std::size_t i = 0; i < 6; ++i) {
    out[6 + i] = static_cast<std::uint8_t>(out[6 + i] ^ static_cast<std::uint8_t>(counter >> (8 * (5 - i))));
  }
  return Status::success();
}

// --- group -----------------------------------------------------------------

void group_prk(const NetworkId network, const Secret& gk, ScopeDigest& prk) noexcept {
  Info salt(kLabelGroupSalt);
  salt.u64(network);
  hkdf_sha256_extract(salt.view(), ByteView{gk.data(), gk.size()}, prk);
}

Status group_bcast_key(const ScopeDigest& prk, const std::uint32_t gk_epoch, const NodeId tx,
                       const std::uint32_t tx_boot, TrafficKey& out) noexcept {
  Info info(kLabelBcastLink);
  info.u32(gk_epoch);
  info.u64(tx);
  info.u32(tx_boot);
  return expand_key_iv(prk, info, out);
}

Status group_end_key(const ScopeDigest& prk, const std::uint32_t gk_epoch,
                     const std::uint64_t group_id, const NodeId origin,
                     const std::uint32_t session, TrafficKey& out) noexcept {
  Info info(kLabelGroupEnd);
  info.u32(gk_epoch);
  info.u64(group_id);
  info.u64(origin);
  info.u32(session);
  return expand_key_iv(prk, info, out);
}

Status group_dsk_key(const ScopeDigest& prk, const std::uint32_t gk_epoch, Secret& out) noexcept {
  Info info(kLabelDskMember);
  info.u32(gk_epoch);
  return expand_secret(ByteView{prk.data(), prk.size()}, info, out);
}

// --- RLRES1 ----------------------------------------------------------------

void resume_id(const Secret& rms, const Purpose purpose, ResumeId& out) noexcept {
  Info info(kLabelResumeId);
  info.u8(static_cast<std::uint8_t>(purpose));
  ScopeDigest mac{};
  hmac_sha256(ByteView{rms.data(), rms.size()}, info.view(), mac);
  std::memcpy(out.data(), mac.data(), out.size());
  secure_clear(mac);
}

Status resume_auth_key(const Secret& rms, const Purpose purpose, const NetworkId network,
                       const NodeId node_i, const NodeId node_r, Secret& out) noexcept {
  ScopeDigest prk{};
  hkdf_sha256_extract(label_view(kLabelResumeAuth), ByteView{rms.data(), rms.size()}, prk);
  Info info(kLabelResumeAuth);
  info.u8(static_cast<std::uint8_t>(purpose));
  info.u64(network);
  info.u64(node_i);
  info.u64(node_r);
  const Status status = expand_secret(ByteView{prk.data(), prk.size()}, info, out);
  secure_clear(prk);
  return status;
}

void resume_binding_routed(const Purpose purpose, const NodeId node_i, const NodeId node_r,
                           ScopeDigest& out) noexcept {
  Info info(kLabelResumeBinding);
  info.u8(static_cast<std::uint8_t>(purpose));
  info.u64(node_i);
  info.u64(node_r);
  sha256(info.view(), out);
}

void resume_binding_link(const MacAddress& mac_i, const MacAddress& mac_r,
                         const ScopeDigest& carrier_digest, ScopeDigest& out) noexcept {
  Info info(kLabelResumeBinding);
  info.u8(static_cast<std::uint8_t>(Purpose::Link));
  info.put(mac_i.data(), mac_i.size());
  info.put(mac_r.data(), mac_r.size());
  info.put(carrier_digest.data(), carrier_digest.size());
  sha256(info.view(), out);
}

void resume_prk(const ResumeNonce& nonce_i, const ResumeNonce& nonce_r, const Secret& rms,
                ScopeDigest& prk) noexcept {
  std::array<std::uint8_t, 2 * kResumeNonceSize> salt{};
  std::memcpy(salt.data(), nonce_i.data(), kResumeNonceSize);
  std::memcpy(salt.data() + kResumeNonceSize, nonce_r.data(), kResumeNonceSize);
  hkdf_sha256_extract(ByteView{salt.data(), salt.size()}, ByteView{rms.data(), rms.size()}, prk);
}

Status resume_confirm_key(const ScopeDigest& prk, const ScopeDigest& th, Secret& out) noexcept {
  Info info(kLabelResumeConfirm);
  info.put(th.data(), th.size());
  return expand_secret(ByteView{prk.data(), prk.size()}, info, out);
}

Status resume_traffic_key(const ScopeDigest& prk, const ResumeKeyContext& context,
                          const Direction direction, const ScopeDigest& th,
                          TrafficKey& out) noexcept {
  Info info(kLabelResumeKey);
  info.u8(static_cast<std::uint8_t>(context.purpose));
  info.u8(static_cast<std::uint8_t>(direction));
  info.u64(context.network);
  info.u64(context.node_i);
  info.u64(context.node_r);
  info.u32(context.cid_i);
  info.u32(context.cid_r);
  info.put(th.data(), th.size());
  return expand_key_iv(prk, info, out);
}

Status resume_mac(const ByteView key, const char* label, const ByteView a, const ByteView b,
                  const ByteView c, std::array<std::uint8_t, kResumeMacSize>& out) noexcept {
  // label || 0x00 || a is staged (a is a 32-byte binding or transcript hash);
  // b and c stream through the multi-part HMAC without a large local.
  out.fill(0);
  std::array<std::uint8_t, 64> head{};
  const std::size_t label_size = label == nullptr ? 0 : std::strlen(label);
  if (label_size == 0 || a.size > 32 || label_size + 1 + a.size > head.size() ||
      (a.size != 0 && a.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "resume mac input");
  }
  std::memcpy(head.data(), label, label_size);
  head[label_size] = 0;
  if (a.size != 0) std::memcpy(head.data() + label_size + 1, a.data, a.size);
  ScopeDigest mac{};
  hmac_sha256(key, ByteView{head.data(), label_size + 1 + a.size}, b, c, mac);
  std::memcpy(out.data(), mac.data(), out.size());
  secure_clear(mac);
  return Status::success();
}

// --- AuthorityEnvelope -----------------------------------------------------

const char* decode_error_name(const DecodeError error) noexcept {
  switch (error) {
    case DecodeError::None: return "none";
    case DecodeError::Truncated: return "truncated";
    case DecodeError::Oversized: return "oversized";
    case DecodeError::LengthMismatch: return "length_mismatch";
    case DecodeError::BadPurpose: return "bad_purpose";
    case DecodeError::UnsupportedFlags: return "unsupported_flags";
    case DecodeError::ReservedNonZero: return "reserved_nonzero";
    case DecodeError::ZeroContextId: return "zero_context_id";
    case DecodeError::TicketLength: return "ticket_length";
    case DecodeError::BadStatus: return "bad_status";
    case DecodeError::BadVersion: return "bad_version";
    case DecodeError::BadType: return "bad_type";
  }
  return "unknown";
}

namespace {
bool envelope_type_known(const std::uint8_t type) noexcept { return type >= 1 && type <= 8; }
}  // namespace

Status authority_envelope_header_encode(
    const AuthorityEnvelopeHeader& header,
    std::array<std::uint8_t, kAuthorityEnvelopeHeaderSize>& out) noexcept {
  out.fill(0);
  if (header.version != kAuthorityEnvelopeVersion ||
      !envelope_type_known(static_cast<std::uint8_t>(header.type)) || header.ctx_id == 0 ||
      header.counter > kMaxAeadCounter) {
    return Status::error(StatusCode::InvalidArgument, "authority envelope header");
  }
  out[0] = header.version;
  out[1] = static_cast<std::uint8_t>(header.type);
  for (std::size_t i = 0; i < 4; ++i) {
    out[2 + i] = static_cast<std::uint8_t>(header.ctx_id >> (8 * (3 - i)));
  }
  for (std::size_t i = 0; i < 6; ++i) {
    out[6 + i] = static_cast<std::uint8_t>(header.counter >> (8 * (5 - i)));
  }
  return Status::success();
}

DecodeError authority_envelope_decode(const ByteView envelope,
                                      AuthorityEnvelopeHeader& out) noexcept {
  out = AuthorityEnvelopeHeader{};
  if (envelope.data == nullptr || envelope.size < kAuthorityEnvelopeMin) {
    return DecodeError::Truncated;
  }
  if (envelope.size > kAuthorityEnvelopeMax) return DecodeError::Oversized;
  const std::uint8_t* p = envelope.data;
  if (p[0] != kAuthorityEnvelopeVersion) return DecodeError::BadVersion;
  if (!envelope_type_known(p[1])) return DecodeError::BadType;
  std::uint32_t ctx = 0;
  for (std::size_t i = 0; i < 4; ++i) ctx = (ctx << 8) | p[2 + i];
  if (ctx == 0) return DecodeError::ZeroContextId;
  std::uint64_t counter = 0;
  for (std::size_t i = 0; i < 6; ++i) counter = (counter << 8) | p[6 + i];
  out.version = p[0];
  out.type = static_cast<AuthorityEnvelopeType>(p[1]);
  out.ctx_id = ctx;
  out.counter = counter;
  return DecodeError::None;
}

namespace {

void hash_be(Sha256& hash, const std::uint64_t value, const std::size_t width) noexcept {
  std::uint8_t tmp[8]{};
  for (std::size_t i = 0; i < width; ++i) {
    tmp[i] = static_cast<std::uint8_t>(value >> (8 * (width - 1 - i)));
  }
  hash.update(ByteView{tmp, width});
}

void hash_label(Sha256& hash, const char* label) noexcept {
  hash.update(label_view(label));
  const std::uint8_t zero = 0;
  hash.update(ByteView{&zero, 1});
}

}  // namespace

void link_carrier_digest(const LinkCarrier& carrier, ScopeDigest& out) noexcept {
  Sha256 hash{};
  hash_label(hash, kLabelLinkCarrier);
  const std::uint8_t version = 1;
  hash.update(ByteView{&version, 1});
  hash_be(hash, carrier.network, 8);
  hash_be(hash, carrier.node_i, 8);
  hash_be(hash, carrier.node_r, 8);
  hash.update(ByteView{carrier.requester_nonce.data(), 16});
  hash.update(ByteView{carrier.responder_nonce.data(), 16});
  hash.update(ByteView{carrier.cookie.data(), 16});
  hash_be(hash, carrier.capability_i, 4);
  hash_be(hash, carrier.capability_r, 4);
  hash.update(ByteView{carrier.scope_binding.data(), carrier.scope_binding.size()});
  hash.finish(out);
}

void end_carrier_binding(const NetworkId network, const NodeId node_i, const NodeId node_r,
                         const std::uint32_t exchange_id, ScopeDigest& out) noexcept {
  Sha256 hash{};
  hash_label(hash, kLabelEndCarrier);
  hash_be(hash, network, 8);
  hash_be(hash, node_i, 8);
  hash_be(hash, node_r, 8);
  hash_be(hash, exchange_id, 4);
  hash.finish(out);
}

Status session_capability_digest(const ByteView intent44, const ByteView state_r24,
                                 const ByteView state_i24, ScopeDigest& out) noexcept {
  out.fill(0);
  if (intent44.size != 44 || state_r24.size != 24 || state_i24.size != 24 ||
      intent44.data == nullptr || state_r24.data == nullptr || state_i24.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "session profile widths");
  }
  Sha256 hash{};
  hash_label(hash, kLabelSessionProfile);
  hash.update(intent44);
  hash.update(state_r24);
  hash.update(state_i24);
  hash.finish(out);
  return Status::success();
}

Status session_contexts_digest(const ByteView context_dir1, const ByteView context_dir2,
                               const ByteView context_rms, ScopeDigest& out) noexcept {
  out.fill(0);
  constexpr std::size_t kMaxContextBytes = 256;
  const ByteView parts[3] = {context_dir1, context_dir2, context_rms};
  for (const ByteView part : parts) {
    if (part.data == nullptr || part.size == 0 || part.size > kMaxContextBytes) {
      return Status::error(StatusCode::InvalidArgument, "session contexts shape");
    }
  }
  Sha256 hash{};
  hash_label(hash, kLabelContextConfirm);
  for (const ByteView part : parts) {
    hash_be(hash, part.size, 2);
    hash.update(part);
  }
  hash.finish(out);
  return Status::success();
}

}  // namespace routeloom::keys
