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

// HMAC input = domain bytes (incl. NUL) || aad || canonical.
Status build_tag_input(ByteView aad, ByteView canonical,
                       ByteBuffer<kConfigPermitObjectMax>& input) noexcept {
  ByteWriter writer(input.writable());
  Status status = writer.write_bytes(dev_domain());
  if (status.ok()) status = writer.write_bytes(aad);
  if (status.ok()) status = writer.write_bytes(canonical);
  if (!status.ok()) return status;
  input.size = writer.size();
  return Status::success();
}

}  // namespace

Status config_dev_permit_tag(
    ByteView dev_key, ByteView aad, ByteView canonical,
    std::array<std::uint8_t, kConfigDevPermitTagSize>& out) noexcept {
  if (dev_key.size == 0 || aad.size != kConfigPermitAadSize ||
      canonical.size == 0) {
    return Status::error(StatusCode::InvalidArgument, "config dev tag input");
  }
  ByteBuffer<kConfigPermitObjectMax> input{};
  const Status built = build_tag_input(aad, canonical, input);
  if (!built.ok()) return built;
  ScopeDigest mac{};
  hmac_sha256(dev_key, input.view(), mac);
  std::memcpy(out.data(), mac.data(), kConfigDevPermitTagSize);
  return Status::success();
}

Status DevConfigPermitSigner::sign(
    const endpoint::ConfigCommand& command, ByteView canonical,
    ByteBuffer<kConfigPermitObjectMax>& permit) noexcept {
  ByteBuffer<kConfigPermitAadSize> aad{};
  const Status aad_ok = config_permit_aad(command.network, command.target,
                                        command.config_namespace, aad);
  if (!aad_ok.ok()) return aad_ok;
  std::array<std::uint8_t, kConfigDevPermitTagSize> tag{};
  const Status tag_ok =
      config_dev_permit_tag(dev_key_, aad.view(), canonical, tag);
  if (!tag_ok.ok()) return tag_ok;
  ByteWriter writer(permit.writable());
  Status status = writer.write_bytes(aad.view());
  if (status.ok()) status = writer.write_bytes(canonical);
  if (status.ok()) status = writer.write_bytes(ByteView{tag.data(), tag.size()});
  if (!status.ok()) return status;
  permit.size = writer.size();
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
  endpoint::ConfigCommand command{};
  const Status decoded = endpoint::config_command_decode(canonical, command);
  if (!decoded.ok()) return decoded;
  if (command.network != context.network || command.target != context.target ||
      command.config_namespace != context.config_namespace ||
      command.authority != context.authorized_issuer ||
      command.authority_generation != context.authority_generation) {
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
