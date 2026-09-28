#include "routeloom/site_signed.hpp"

#include <array>

#include "routeloom/discovery_scope.hpp"  // Sha256
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/migration_wire.hpp"

namespace routeloom {
namespace {

// An RLS1 is committed only after its SiteCert chain verified, so the
// adopted record is decoded, not re-verified, here.
Status site_sak(const sdkv1::SiteRecord& site, sdkv1::P256PublicKey& out) noexcept {
  if (site.state != sdkv1::SiteState::Member) {
    return Status::error(StatusCode::InvalidState, "no adopted site");
  }
  sdkv1::CertClaims claims{};
  const Status status = sdkv1::cert_decode(site.site_cert.view(), claims);
  if (!status) return status;
  if (claims.type != sdkv1::CertType::Site || claims.subject != site.site_id) {
    return Status::error(StatusCode::IntegrityError, "site cert does not name the site");
  }
  out = claims.pubkey;
  return Status::success();
}

}  // namespace

Status site_config_bind(const sdkv1::SiteRecord& site, const NodeId self,
                        const std::uint64_t boot_incarnation, ConfigJournalConfig& journal,
                        CoseEsp256AuthorityVerifier& verifier) noexcept {
  sdkv1::P256PublicKey sak{};
  const Status status = site_sak(site, sak);
  if (!status) return status;
  verifier.provision(site.site_id, ByteView{sak.data(), sak.size()});
  if (!verifier.ready()) {
    return Status::error(StatusCode::IntegrityError, "site authority key invalid");
  }
  journal = ConfigJournalConfig{};
  journal.network = site.network & 0xFFFFFFFFULL;
  journal.target = self;
  journal.config_namespace = endpoint::kConfigNamespaceSdk;
  journal.boot_incarnation = boot_incarnation;
  journal.authorized_issuer = site.site_id;
  journal.authority_generation = kSiteConfigAuthorityGeneration;
  return Status::success();
}

Status config_floor_ensure(SecurityFloorStorage& storage, SecurityFloorStore& floor,
                           const NetworkId network, const NodeId target) noexcept {
  if (floor.initialize()) {
    SecurityFloorState state{};
    const Status read = floor.read(state);
    if (!read) return read;
    if (state.network == network && state.target == target) return Status::success();
    return Status::error(StatusCode::Conflict, "security floor bound to another identity");
  }
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob{};
  const Status stored = storage.read(MutableByteView{blob.data(), blob.size()});
  if (stored.code != StatusCode::NotFound) {
    return Status::error(StatusCode::RecoveryRequired, "security floor unusable");
  }
  SecurityFloorState seed{};
  seed.network = network;
  seed.target = target;
  seed.namespace_count = 1;
  seed.entries[0].config_namespace = endpoint::kConfigNamespaceSdk;
  seed.entries[0].schema = 1;
  return floor.provision_seed(seed);
}

Status SiteCommitVerifier::provision(const sdkv1::SiteRecord& site) noexcept {
  ready_ = false;
  const Status status = site_sak(site, sak_);
  if (!status) return status;
  if (!sdkv1::p256_public_key_valid(sak_)) {
    return Status::error(StatusCode::IntegrityError, "site authority key invalid");
  }
  ready_ = true;
  return Status::success();
}

Status SiteCommitVerifier::check(const char* domain, const std::size_t domain_size,
                                 const ByteView input, const ByteView signature) const noexcept {
  if (!ready_) return Status::error(StatusCode::InvalidState, "site verifier not provisioned");
  if (signature.size != sdkv1::kEs256SignatureSize ||
      !sdkv1::es256_signature_canonical(signature)) {
    return Status::error(StatusCode::AuthenticationFailed, "channel evidence signature shape");
  }
  Sha256 hash{};
  hash.update(ByteView{reinterpret_cast<const std::uint8_t*>(domain), domain_size});
  hash.update(input);
  Digest256 digest{};
  hash.finish(digest);
  sdkv1::Es256Signature raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = signature.data[i];
  if (!sdkv1::default_es256_verifier().verify_digest(sak_, digest, raw)) {
    return Status::error(StatusCode::AuthenticationFailed, "channel evidence signature");
  }
  return Status::success();
}

Status SiteCommitVerifier::verify_commit(const AuthorityOperation& operation,
                                         const Digest256& plan_hash,
                                         const ChannelEpoch new_epoch,
                                         const ByteView signature) noexcept {
  std::array<std::uint8_t, kCommitSigningInputSize> input{};
  std::size_t size = 0;
  const Status status = commit_signing_input(
      operation, plan_hash, new_epoch, MutableByteView{input.data(), input.size()}, size);
  if (!status) return status;
  return check(kSiteCommitDomain, sizeof(kSiteCommitDomain), ByteView{input.data(), size},
               signature);
}

Status SiteCommitVerifier::verify_snapshot(const ByteView snapshot,
                                           const ByteView signature) noexcept {
  return check(kSiteSnapshotDomain, sizeof(kSiteSnapshotDomain), snapshot, signature);
}

}  // namespace routeloom
