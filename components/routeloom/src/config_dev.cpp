#include "routeloom/config_dev.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"

namespace routeloom {

namespace {

ByteView dev_domain() noexcept {
  // sizeof includes the trailing NUL, matching kConfigPermitAadSize's domain.
  return ByteView{
      reinterpret_cast<const std::uint8_t*>(kConfigDevPermitDomain),
      sizeof(kConfigDevPermitDomain)};
}

ByteView dev_recovery_domain() noexcept {
  return ByteView{
      reinterpret_cast<const std::uint8_t*>(kConfigDevRecoveryDomain),
      sizeof(kConfigDevRecoveryDomain)};
}

}  // namespace

// HMAC input = domain bytes (incl. NUL) || aad || canonical, streamed into
// the MAC — a staged copy would cost a kConfigPermitObjectMax stack frame.
Status config_dev_permit_tag(
    ByteView dev_key, ByteView aad, ByteView canonical,
    std::array<std::uint8_t, kConfigDevPermitTagSize>& out) noexcept {
  if (dev_key.size == 0 || aad.size != kConfigPermitAadSize ||
      canonical.size == 0) {
    return Status::error(StatusCode::InvalidArgument, "config dev tag input");
  }
  if (dev_domain().size + aad.size + canonical.size > kConfigPermitObjectMax) {
    return Status::error(StatusCode::NoCapacity, "config dev tag input");
  }
  ScopeDigest mac{};
  hmac_sha256(dev_key, dev_domain(), aad, canonical, mac);
  std::memcpy(out.data(), mac.data(), kConfigDevPermitTagSize);
  return Status::success();
}

// Same construction under the recovery domain: input =
// kConfigDevRecoveryDomain || NUL || recovery_aad || rcr2_canonical.
Status config_dev_recovery_tag(
    ByteView dev_key, ByteView aad, ByteView canonical,
    std::array<std::uint8_t, kConfigDevPermitTagSize>& out) noexcept {
  if (dev_key.size == 0 || aad.size != kConfigRecoveryAadSize ||
      canonical.size < endpoint::kRcr2HeaderSize ||
      canonical.size > endpoint::kRcr2MaxTotal) {
    return Status::error(StatusCode::InvalidArgument, "config dev recovery tag input");
  }
  ScopeDigest mac{};
  hmac_sha256(dev_key, dev_recovery_domain(), aad, canonical, mac);
  std::memcpy(out.data(), mac.data(), kConfigDevPermitTagSize);
  return Status::success();
}

Status DevConfigAuthorityVerifier::verify_recovery(
    const ConfigPermitContext& context, ByteView object,
    endpoint::EncodedRecoveryIntent& payload, bool& verified) noexcept {
  verified = false;
  if (dev_key_.size == 0) {
    return Status::error(StatusCode::InvalidState, "config dev key unset");
  }
  // Variable RCR2 envelope: aad(46) || header+snapshot(112..624) || tag(16),
  // within the same signed-object bound as the permit lane.
  constexpr std::size_t kDevRecoveryObjectMin =
      kConfigRecoveryAadSize + endpoint::kRcr2HeaderSize + kConfigDevPermitTagSize;
  if (object.size < kDevRecoveryObjectMin ||
      object.size > kConfigPermitObjectMax) {
    return Status::error(StatusCode::ProtocolError, "config dev recovery size");
  }
  const ByteView aad{object.data, kConfigRecoveryAadSize};
  const ByteView canonical{
      object.data + kConfigRecoveryAadSize,
      object.size - kConfigRecoveryAadSize - kConfigDevPermitTagSize};
  const ByteView tag{object.data + object.size - kConfigDevPermitTagSize,
                     kConfigDevPermitTagSize};

  // Scope binding + MAC under the recovery domains — a kind-3 permit's aad
  // and tag can never collide with this construction.
  ByteBuffer<kConfigRecoveryAadSize> expected_aad{};
  const Status aad_ok = config_recovery_aad(context.network, context.target,
                                          context.config_namespace, expected_aad);
  if (!aad_ok.ok()) return aad_ok;
  if (!constant_time_equal(aad, expected_aad.view())) {
    return Status::success();  // foreign network/target/namespace: denied
  }
  std::array<std::uint8_t, kConfigDevPermitTagSize> expected_tag{};
  const Status tag_ok =
      config_dev_recovery_tag(dev_key_, aad, canonical, expected_tag);
  if (!tag_ok.ok()) return tag_ok;
  if (!constant_time_equal(
          tag, ByteView{expected_tag.data(), expected_tag.size()})) {
    return Status::success();  // bad MAC: denied
  }
  // Authentic envelope: decode the RCR2 and apply the identity policy —
  // including the generation pin: a recovery command signed under a
  // different authority generation is not this journal's to act on.
  const Status decoded =
      endpoint::config_recovery_decode(canonical, recovery_intent_);
  if (!decoded.ok()) return decoded;
  if (recovery_intent_.network != context.network ||
      recovery_intent_.target != context.target ||
      recovery_intent_.config_namespace != context.config_namespace ||
      recovery_intent_.authority != context.authorized_issuer ||
      recovery_intent_.authority_generation != context.authority_generation) {
    return Status::success();  // not the configured authority: denied
  }
  std::memcpy(payload.bytes.data(), canonical.data, canonical.size);
  payload.size = canonical.size;
  verified = true;
  return Status::success();
}

Status DevConfigAuthorityVerifier::verify_permit(
    const ConfigPermitContext& context, ByteView permit,
    endpoint::EncodedConfigCommand& payload, bool& verified) noexcept {
  verified = false;
  if (dev_key_.size == 0) {
    return Status::error(StatusCode::InvalidState, "config dev key unset");
  }
  // Envelope must be aad || canonical || tag with a bounded canonical body.
  if (permit.size < kConfigDevPermitMin ||
      permit.size > kConfigPermitObjectMax) {
    return Status::error(StatusCode::ProtocolError, "config dev permit size");
  }
  const ByteView aad{permit.data, kConfigPermitAadSize};
  const ByteView canonical{
      permit.data + kConfigPermitAadSize,
      permit.size - kConfigPermitAadSize - kConfigDevPermitTagSize};
  const ByteView tag{permit.data + permit.size - kConfigDevPermitTagSize,
                     kConfigDevPermitTagSize};

  // Scope binding (fast reject — the tag below authenticates the aad too):
  // the permit's own aad must equal the one this context demands.
  ByteBuffer<kConfigPermitAadSize> expected_aad{};
  const Status aad_ok = config_permit_aad(context.network, context.target,
                                        context.config_namespace, expected_aad);
  if (!aad_ok.ok()) return aad_ok;
  if (!constant_time_equal(aad, expected_aad.view())) {
    return Status::success();  // foreign network/target/namespace: denied
  }
  // Authenticate the whole envelope before trusting the canonical body.
  std::array<std::uint8_t, kConfigDevPermitTagSize> expected_tag{};
  const Status tag_ok =
      config_dev_permit_tag(dev_key_, aad, canonical, expected_tag);
  if (!tag_ok.ok()) return tag_ok;
  if (!constant_time_equal(
          tag, ByteView{expected_tag.data(), expected_tag.size()})) {
    return Status::success();  // bad MAC: denied
  }
  // The envelope is authentic; decode the canonical command and apply the
  // identity policy. A decode failure under a valid MAC means a broken peer
  // (reported as an error, not denied).
  const Status decoded = endpoint::config_command_decode(canonical, command_);
  if (!decoded.ok()) return decoded;
  if (command_.network != context.network || command_.target != context.target ||
      command_.config_namespace != context.config_namespace ||
      command_.authority != context.authorized_issuer ||
      command_.authority_generation != context.authority_generation) {
    return Status::success();  // not the configured authority: denied
  }
  if (canonical.size > payload.bytes.size()) {
    return Status::error(StatusCode::NoCapacity, "config dev payload");
  }
  std::memcpy(payload.bytes.data(), canonical.data, canonical.size);
  payload.size = canonical.size;
  verified = true;
  return Status::success();
}

}  // namespace routeloom
