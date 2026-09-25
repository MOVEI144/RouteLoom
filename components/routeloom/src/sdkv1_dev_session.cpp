#include "routeloom/sdkv1_dev_session.hpp"

#include "routeloom/discovery_scope.hpp"  // sha256, hmac_sha256
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {
constexpr char kDomain[] = "RouteLoom/v1/maintenance-domain";
// domain || 00 || profile || network_be || self_be. Sizes derive from the
// literal so a domain rename cannot overflow the staging buffers.
constexpr std::size_t kDomainLen = sizeof(kDomain) - 1;
constexpr std::size_t kDomainInput = kDomainLen + 1 + 1 + 8 + 8;
constexpr std::size_t kMemberPreimage = kDomainInput + 8 + 32;

bool id_valid(const std::uint64_t id) noexcept {
  return id != kInvalidNodeId && id != kBroadcastNodeId;
}

void domain_input(const std::uint8_t profile, const NetworkId network, const NodeId self,
                  std::array<std::uint8_t, kDomainInput>& out) noexcept {
  std::size_t pos = 0;
  for (std::size_t i = 0; kDomain[i] != '\0'; ++i) out[pos++] = static_cast<std::uint8_t>(kDomain[i]);
  out[pos++] = 0;
  out[pos++] = profile;
  for (int i = 7; i >= 0; --i) out[pos++] = static_cast<std::uint8_t>(network >> (8 * i));
  for (int i = 7; i >= 0; --i) out[pos++] = static_cast<std::uint8_t>(self >> (8 * i));
}

int hex_value(const std::uint8_t c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
}  // namespace

Status dev_find_slot(const keys::Secret& psk, const NetworkId network,
                     const keys::Purpose purpose, const NodeId self,
                     const NodeId claimed_peer, const keys::ResumeId& rid,
                     rlres1::Slot& out) noexcept {
  out = rlres1::Slot{};
  keys::Secret rms{};
  const Status derived = keys::dev_pair_rms(psk, network, self, claimed_peer, purpose, rms);
  if (!derived) {
    secure_clear(rms);
    return derived;
  }
  keys::ResumeId expect{};
  keys::resume_id(rms, purpose, expect);
  const bool match = constant_time_equal(ByteView{rid.data(), rid.size()},
                                         ByteView{expect.data(), expect.size()});
  secure_clear(expect);
  if (!match) {
    secure_clear(rms);
    return Status::error(StatusCode::NotFound, "dev resume rid mismatch");
  }
  // Dev RMS has no EDHOC birthday and no RRS1 generation: the fixed policy is
  // created_gk 1 with fresh nonces, 24 h / 2^32 rotation by the bank. The
  // install-time role comes from local config, never from this slot.
  out.purpose = purpose;
  out.peer = claimed_peer;
  out.network = network;
  out.created_gk_epoch = 1;
  out.peer_generation = 0;
  out.secret = rms;
  secure_clear(rms);
  return Status::success();
}

Status DevGroupSender::configure(const keys::Secret& psk, const NetworkId network,
                                 const NodeId origin, const std::uint32_t boot) noexcept {
  if (network == 0 || !id_valid(origin) || boot == 0) {
    return Status::error(StatusCode::InvalidArgument, "dev group epoch invalid");
  }
  if (configured_ && boot <= boot_) {
    // Same key, same counter space: restarting at 0 would reuse nonces.
    return Status::error(StatusCode::Conflict, "dev group boot not advanced");
  }
  keys::TrafficKey next{};
  const Status status = keys::dev_group_key(psk, network, origin, boot, next);
  if (!status) return status;
  clear();
  key_ = next;
  keys::clear(next);
  tx_next_ = 0;
  boot_ = boot;
  configured_ = true;
  return Status::success();
}

Status DevGroupSender::next_counter(std::uint64_t& counter) noexcept {
  counter = 0;
  if (!configured_) return Status::error(StatusCode::InvalidState, "dev group not configured");
  if (!counter_admissible(tx_next_)) {
    return Status::error(StatusCode::CounterExhausted, "dev group counter exhausted");
  }
  counter = tx_next_++;
  return Status::success();
}

Status DevGroupSender::material(keys::TrafficKey& out) const noexcept {
  keys::clear(out);
  if (!configured_) return Status::error(StatusCode::InvalidState, "dev group not configured");
  out = key_;
  return Status::success();
}

void DevGroupSender::clear() noexcept {
  keys::clear(key_);
  tx_next_ = 0;
  boot_ = 0;
  configured_ = false;
}

Status dev_maintenance_fingerprint(const keys::Secret& psk, const std::uint8_t profile,
                                   const NetworkId network, const NodeId self,
                                   MaintenanceFingerprint& out) noexcept {
  out = MaintenanceFingerprint{};
  if (network == 0 || !id_valid(self)) {
    return Status::error(StatusCode::InvalidArgument, "maintenance domain invalid");
  }
  std::array<std::uint8_t, kDomainInput> input{};
  domain_input(profile, network, self, input);
  ScopeDigest mac{};
  hmac_sha256(ByteView{psk.data(), psk.size()}, ByteView{input.data(), input.size()}, mac);
  secure_clear(input);
  for (std::size_t i = 0; i < out.size(); ++i) out[i] = mac[i];
  secure_clear(mac);
  return Status::success();
}

Status member_maintenance_fingerprint(const std::uint8_t profile, const NetworkId network,
                                      const NodeId self, const std::uint64_t site_id,
                                      const std::array<std::uint8_t, 32>& sak_kid,
                                      MaintenanceFingerprint& out) noexcept {
  out = MaintenanceFingerprint{};
  if (network == 0 || !id_valid(self)) {
    return Status::error(StatusCode::InvalidArgument, "maintenance domain invalid");
  }
  std::array<std::uint8_t, kDomainInput> input{};
  domain_input(profile, network, self, input);
  std::array<std::uint8_t, kMemberPreimage> preimage{};
  for (std::size_t i = 0; i < input.size(); ++i) preimage[i] = input[i];
  secure_clear(input);
  for (int i = 7; i >= 0; --i) {
    preimage[kDomainInput + (7 - i)] = static_cast<std::uint8_t>(site_id >> (8 * i));
  }
  for (std::size_t i = 0; i < sak_kid.size(); ++i) preimage[kDomainInput + 8 + i] = sak_kid[i];
  ScopeDigest digest{};
  sha256(ByteView{preimage.data(), preimage.size()}, digest);
  secure_clear(preimage);
  for (std::size_t i = 0; i < out.size(); ++i) out[i] = digest[i];
  secure_clear(digest);
  return Status::success();
}

Status format_fingerprint_hex(const MaintenanceFingerprint& print, char text[33]) noexcept {
  if (text == nullptr) return Status::error(StatusCode::InvalidArgument, "fingerprint text null");
  constexpr char kHex[] = "0123456789abcdef";
  for (std::size_t i = 0; i < print.size(); ++i) {
    text[2 * i] = kHex[print[i] >> 4];
    text[2 * i + 1] = kHex[print[i] & 0x0F];
  }
  text[32] = '\0';
  return Status::success();
}

Status parse_fingerprint_hex(const ByteView text, MaintenanceFingerprint& out) noexcept {
  out = MaintenanceFingerprint{};
  if (text.data == nullptr || text.size != 2 * out.size()) {
    return Status::error(StatusCode::InvalidArgument, "fingerprint hex length");
  }
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int hi = hex_value(text.data[2 * i]);
    const int lo = hex_value(text.data[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      out = MaintenanceFingerprint{};
      return Status::error(StatusCode::InvalidArgument, "fingerprint hex digit");
    }
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return Status::success();
}

}  // namespace routeloom::sdkv1
