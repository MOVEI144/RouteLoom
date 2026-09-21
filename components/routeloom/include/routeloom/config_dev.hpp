#pragma once

// Development (EXPERIMENTAL) config permit profile. This is the reference
// issuer/target pair the dev profile uses while the production COSE_Sign1
// provider lands with #10 — it is NOT production cryptography and is never
// advertised as such (security_profile() stays Development).
//
// Envelope (mirrored byte-for-byte by the Rust host issuer):
//   permit = aad || canonical || tag
//   aad    = kConfigPermitAadSize bytes from config_permit_aad()
//            ("RouteLoom/config-permit/v1" || NUL || Network u64 ||
//             target u64 || namespace u16)
//   tag    = HMAC-SHA256(dev_key, input)[..16]
//   input  = "RouteLoom/config-permit-dev/v1" || NUL || aad || canonical
//
// The aad binds the permit to (network, target, namespace); the HMAC binds
// it to a provisioned dev key so a foreign mesh peer cannot mint permits.
// The verifier additionally enforces the ConfigPermitContext identity
// policy the journal supplies — transport and MAC are never authority on
// their own.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/config.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// Dev tag size appended after the canonical command.
constexpr std::size_t kConfigDevPermitTagSize = 16;
// Envelope floor: aad + at least the RCC1 header + a tag.
constexpr std::size_t kConfigDevPermitMin =
    kConfigPermitAadSize + endpoint::kRcc1HeaderSize + kConfigDevPermitTagSize;
// Domain separator for the dev HMAC (NUL-terminated like kConfigPermitDomain).
inline constexpr char kConfigDevPermitDomain[] = "RouteLoom/config-permit-dev/v1";

// Shared tag computation: out = HMAC-SHA256(dev_key,
// kConfigDevPermitDomain || NUL || aad || canonical)[..16]. Both the C++
// pair and the Rust issuer use this exact input layout.
Status config_dev_permit_tag(ByteView dev_key, ByteView aad, ByteView canonical,
                             std::array<std::uint8_t, kConfigDevPermitTagSize>& out) noexcept;

// Issuer side (dev profile). `dev_key` is caller-owned and must outlive the
// signer; an empty key reports !ready() and every sign fails honestly.
class DevConfigPermitSigner final : public ConfigPermitSigner {
 public:
  explicit DevConfigPermitSigner(ByteView dev_key) noexcept : dev_key_(dev_key) {}
  bool ready() const noexcept override { return dev_key_.size > 0; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  Status sign(const endpoint::ConfigCommand& command, ByteView canonical,
              ByteBuffer<kConfigPermitObjectMax>& permit) noexcept override;

 private:
  ByteView dev_key_{};
};

// Target side (dev profile). Verifies the envelope, the scope binding (aad
// must equal the context's own) and the MAC; decodes the canonical command
// into `payload` only after the tag verifies. `verified=false` — never an
// error — for a binding/signature mismatch; errors are reserved for
// malformed envelopes.
class DevConfigAuthorityVerifier final : public ConfigAuthorityVerifier {
 public:
  explicit DevConfigAuthorityVerifier(ByteView dev_key) noexcept : dev_key_(dev_key) {}
  bool ready() const noexcept override { return dev_key_.size > 0; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  Status verify_permit(const ConfigPermitContext& context, ByteView permit,
                       endpoint::EncodedConfigCommand& payload,
                       bool& verified) noexcept override;

 private:
  ByteView dev_key_{};
  // Decode scratch — a stack local would cost ~1.8 KiB of the Owner task's
  // 8 KiB stack on top of the reassembly/submit call chain.
  endpoint::ConfigCommand command_{};
};

}  // namespace routeloom
