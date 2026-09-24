#include "routeloom/trust_view.hpp"

#include <cstring>

#include "routeloom/discovery_scope.hpp"  // sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom {
namespace {

// The live serving policy for one key record (§4.3.1/§4.6.1): the image
// codec already constrains profile/role/scope to the only defined values
// at commit time; the status and floor checks are what make a record
// stop serving — staged, retired and revoked records are inventory, and
// any generation below min_authority_generation is denied regardless of
// status.
bool key_serves(const TrustKeyRecord& key, const std::uint32_t floor) noexcept {
  return key.status == TrustKeyStatus::Active &&
         key.profile == TrustKeyProfile::Rlcp1CoseEsp256 &&
         key.role == TrustKeyRole::ConfigIssuer &&
         key.scope == TrustKeyScope::WholeNetwork && key.generation >= floor;
}

}  // namespace

bool TrustView::usable() const noexcept {
  return store_.initialized() && store_.has_active() &&
         !store_.quarantined() && !store_.uncertain() &&
         store_.store_epoch() >= store_.epoch_floor();
}

std::uint32_t TrustView::effective_generation_floor() const noexcept {
  const std::uint32_t image_floor = store_.min_authority_generation();
  if (floor_ == nullptr) return image_floor;
  SecurityFloorState state{};
  if (!floor_->read(state)) return image_floor;
  // Higher wins: the floor reservation lands before the image commit, so
  // the floor leads across the update window and neither can lag the
  // other into admitting a retired generation.
  return state.min_authority_generation > image_floor
             ? state.min_authority_generation
             : image_floor;
}

const TrustKeyRecord* TrustView::resolve_authority_key(
    const std::uint64_t authority_id, const std::uint32_t generation) const noexcept {
  if (!usable()) return nullptr;
  const TrustKeyRecord* key = store_.find_key(authority_id, generation);
  if (key == nullptr || !key_serves(*key, effective_generation_floor())) {
    return nullptr;
  }
  return key;
}

bool TrustView::generation_permitted(
    const std::uint32_t generation, const std::uint32_t configured_pin) const noexcept {
  (void)configured_pin;  // fixed-profile pins do not apply to the trust view
  return usable() && generation >= effective_generation_floor();
}

bool TrustView::is_credential_revoked(const Digest256& kid_fingerprint) const noexcept {
  // Fail closed (§4.7): an unusable store cannot prove the credential is
  // absent from the revocation set.
  return !usable() || store_.is_credential_revoked(kid_fingerprint);
}

bool TrustView::ready() const noexcept {
  if (!usable()) return false;
  const std::uint32_t floor = effective_generation_floor();
  const TrustImage& image = store_.image();
  if (required_set_) {
    // The pinned authority resolves an active key at SOME generation
    // at/above the floor — the generation itself floats with rotation.
    for (std::uint8_t i = 0; i < image.key_count; ++i) {
      if (image.keys[i].authority_id == required_authority_ &&
          key_serves(image.keys[i], floor)) {
        return true;
      }
    }
    return false;
  }
  // Unpinned: the image must carry at least one currently-verifying key —
  // a valid image may hold none (config deliberately disabled, §4.5.1
  // rule 5), and then the COSE profile bit must not be advertised.
  for (std::uint8_t i = 0; i < image.key_count; ++i) {
    if (key_serves(image.keys[i], floor)) {
      return true;
    }
  }
  return false;
}

Status TrustView::verify_permit(
    const ConfigPermitContext& context, const ByteView permit,
    endpoint::EncodedConfigCommand& payload, bool& verified) noexcept {
  verified = false;
  // Fail closed with honest error classes, mirroring the journal's
  // impairment codes (§4.3.1/§4.7): quarantine -> IntegrityError, an
  // unproven or provably-stale image -> RecoveryRequired, a missing image
  // -> InvalidState. None is a verdict — the permit is never reached.
  if (store_.quarantined()) {
    return Status::error(StatusCode::IntegrityError, "trust store quarantined");
  }
  if (!store_.initialized() || !store_.has_active()) {
    return Status::error(StatusCode::InvalidState, "trust store unprovisioned");
  }
  if (store_.uncertain() || store_.store_epoch() < store_.epoch_floor()) {
    return Status::error(StatusCode::RecoveryRequired,
                        "trust store image unproven");
  }

  CosePermitParts parts{};
  const Status parsed = cose_permit_parse(permit, parts);
  if (!parsed.ok()) return parsed;
  // The kid is a lookup hint bound by the signature — it must name the
  // context's single authorized issuer (§4.6.2).
  if (parts.kid != context.authorized_issuer) {
    return Status::success();  // foreign authority: denied, never verified
  }

  // The RCC1 body is decoded BEFORE the signature check: its (authority,
  // authority_generation) are untrusted hints that select the key record,
  // and the signature subsequently authenticates them (03-signing's hint
  // pattern). The decode is strict and bounds-checked, so it is safe on
  // unauthenticated bytes — same cheap-parse order as trust manifests
  // (envelope -> content head -> key lookup -> signature verify).
  const Status decoded = endpoint::config_command_decode(parts.payload, command_);
  if (!decoded.ok()) return decoded;
  if (command_.authority != context.authorized_issuer) {
    return Status::success();  // hint names a foreign issuer: denied
  }
  const TrustKeyRecord* key =
      resolve_authority_key(command_.authority, command_.authority_generation);
  if (key == nullptr) {
    return Status::success();  // absent / inactive / below floor: denied
  }

  // R/S range + low-S canonicality before the expensive point multiply —
  // the identical rules CoseEsp256AuthorityVerifier applies (the compare
  // helpers and group constants are shared from config_cose.hpp; the
  // four-line check itself is deliberately duplicated rather than
  // widening that unit's API for one stanza).
  std::array<std::uint8_t, 32> r{}, s{};
  std::memcpy(r.data(), parts.signature.data, 32);
  std::memcpy(s.data(), parts.signature.data + 32, 32);
  if (cose_be32_is_zero(r) || cose_be32_is_zero(s) ||
      cose_be32_cmp(r, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1HalfOrder) > 0) {
    return Status::success();  // out-of-range / non-canonical: denied
  }

  ByteBuffer<kConfigPermitAadSize> aad{};
  const Status aad_ok = config_permit_aad(context.network, context.target,
                                        context.config_namespace, aad);
  if (!aad_ok.ok()) return aad_ok;
  ByteBuffer<kCosePermitMax + 64> to_verify{};
  const Status built = cose_sig_structure(parts.protected_bytes, aad.view(),
                                          parts.payload, to_verify);
  if (!built.ok()) return built;
  ScopeDigest digest{};
  sha256(to_verify.view(), digest);
  if (uECC_verify(key->pubkey.data(), digest.data(),
                  static_cast<unsigned>(digest.size()),
                  parts.signature.data, uECC_secp256r1()) == 0) {
    return Status::success();  // bad signature: denied
  }

  // Authentic envelope: the now-trusted command must still bind the
  // context and the resolved record — the hint could never have selected
  // a foreign key (§4.6.2). Generation equality with the resolved record
  // is inherent (find_key is an exact match) and kept explicit for the
  // audit trail.
  if (command_.network != context.network || command_.target != context.target ||
      command_.config_namespace != context.config_namespace ||
      command_.authority != context.authorized_issuer ||
      command_.authority_generation != key->generation) {
    return Status::success();  // not the authorized scope: denied
  }
  if (parts.payload.size > payload.bytes.size()) {
    return Status::error(StatusCode::NoCapacity, "trust view payload");
  }
  std::memcpy(payload.bytes.data(), parts.payload.data, parts.payload.size);
  payload.size = parts.payload.size;
  verified = true;
  return Status::success();
}

Status TrustView::verify_recovery(
    const ConfigPermitContext& context, const ByteView object,
    endpoint::EncodedRecoveryCommand& payload, bool& verified) noexcept {
  verified = false;
  // The same impairment ladder as verify_permit — an impaired trust image
  // can serve NEITHER lane: a store-quarantined node still needs the
  // trust image itself proven before any signature means anything.
  if (store_.quarantined()) {
    return Status::error(StatusCode::IntegrityError, "trust store quarantined");
  }
  if (!store_.initialized() || !store_.has_active()) {
    return Status::error(StatusCode::InvalidState, "trust store unprovisioned");
  }
  if (store_.uncertain() || store_.store_epoch() < store_.epoch_floor()) {
    return Status::error(StatusCode::RecoveryRequired,
                        "trust store image unproven");
  }

  CosePermitParts parts{};
  const Status parsed = cose_recovery_parse(object, parts);
  if (!parsed.ok()) return parsed;
  if (parts.kid != context.authorized_issuer) {
    return Status::success();  // foreign authority: denied, never verified
  }

  // The RCR1 body decodes BEFORE the signature check — same untrusted-hint
  // pattern as the permit path: its (authority, authority_generation)
  // select the key record and the signature then authenticates them.
  const Status decoded =
      endpoint::config_recovery_decode(parts.payload, recovery_command_);
  if (!decoded.ok()) return decoded;
  if (recovery_command_.authority != context.authorized_issuer) {
    return Status::success();  // hint names a foreign issuer: denied
  }
  const TrustKeyRecord* key = resolve_authority_key(
      recovery_command_.authority, recovery_command_.authority_generation);
  if (key == nullptr) {
    return Status::success();  // absent / inactive / below floor: denied
  }

  std::array<std::uint8_t, 32> r{}, s{};
  std::memcpy(r.data(), parts.signature.data, 32);
  std::memcpy(s.data(), parts.signature.data + 32, 32);
  if (cose_be32_is_zero(r) || cose_be32_is_zero(s) ||
      cose_be32_cmp(r, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1HalfOrder) > 0) {
    return Status::success();  // out-of-range / non-canonical: denied
  }

  ByteBuffer<kConfigRecoveryAadSize> aad{};
  const Status aad_ok = config_recovery_aad(context.network, context.target,
                                          context.config_namespace, aad);
  if (!aad_ok.ok()) return aad_ok;
  ByteBuffer<kCosePermitMax + 64> to_verify{};
  const Status built = cose_sig_structure(parts.protected_bytes, aad.view(),
                                          parts.payload, to_verify);
  if (!built.ok()) return built;
  ScopeDigest digest{};
  sha256(to_verify.view(), digest);
  if (uECC_verify(key->pubkey.data(), digest.data(),
                  static_cast<unsigned>(digest.size()),
                  parts.signature.data, uECC_secp256r1()) == 0) {
    return Status::success();  // bad signature: denied
  }

  // Authentic envelope: bind the context and the resolved record — the
  // recovery command must name THIS node, THIS namespace and the same
  // authority/generation the key resolved under.
  if (recovery_command_.network != context.network ||
      recovery_command_.target != context.target ||
      recovery_command_.config_namespace != context.config_namespace ||
      recovery_command_.authority != context.authorized_issuer ||
      recovery_command_.authority_generation != key->generation) {
    return Status::success();  // not the authorized scope: denied
  }
  std::memcpy(payload.bytes.data(), parts.payload.data, parts.payload.size);
  payload.size = parts.payload.size;
  verified = true;
  return Status::success();
}

}  // namespace routeloom
