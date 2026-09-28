#pragma once

// Site-Authority-rooted verification for the Owner profiles (V2-08,
// issues #17 and #5): remote-config permits and manual channel-plan
// commits verify under the SAK the adopted RLS1 SiteCert names, replacing
// the LegacyFixture dev-PSK verifiers. The host issues both with the same
// SAK (routeloom-host `--site-authority`).

#include <cstdint>

#include "routeloom/config.hpp"
#include "routeloom/config_cose.hpp"
#include "routeloom/migration.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/security_floor.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// The site is its own config authority: kid = site_id, one generation (a
// SAK is never rotated in place; a new SAK is a new site).
constexpr std::uint32_t kSiteConfigAuthorityGeneration = 1;

// Binds the SDK-namespace journal and the COSE verifier to an adopted
// Member site. network is the mesh-header low word: HostLink reports it and
// it stays fixed across site_epoch cutovers, so the journal and its floor
// keep one identity for the site's life. Call after adoption, before the
// journal is constructed.
Status site_config_bind(const sdkv1::SiteRecord& site, NodeId self,
                        std::uint64_t boot_incarnation, ConfigJournalConfig& journal,
                        CoseEsp256AuthorityVerifier& verifier) noexcept;

// Provisions the RLF1 floor at J = R = 0 for (network, target) when none is
// stored — adoption is the managed provisioning point. A floor for this
// identity is kept as is. A floor for another identity, or one that exists
// but does not decode, refuses: the removal erasure owns a site change and
// a damaged floor stays a recovery case.
Status config_floor_ensure(SecurityFloorStorage& storage, SecurityFloorStore& floor,
                           NetworkId network, NodeId target) noexcept;

// Channel-plan evidence: ES256 by the SAK over SHA-256(domain incl. NUL ||
// input), raw low-S R || S. The commit input is commit_signing_input(); the
// snapshot input is the snapshot body.
inline constexpr char kSiteCommitDomain[] = "RouteLoom/channel-commit/v1";
inline constexpr char kSiteSnapshotDomain[] = "RouteLoom/channel-snapshot/v1";

class SiteCommitVerifier final : public CommitSignatureVerifier {
 public:
  // Takes the SAK from the adopted SiteCert; ready() only after it decodes.
  Status provision(const sdkv1::SiteRecord& site) noexcept;

  bool ready() const noexcept override { return ready_; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Production;
  }
  Status verify_commit(const AuthorityOperation& operation, const Digest256& plan_hash,
                       ChannelEpoch new_epoch, ByteView signature) noexcept override;
  Status verify_snapshot(ByteView snapshot, ByteView signature) noexcept override;

 private:
  Status check(const char* domain, std::size_t domain_size, ByteView input,
               ByteView signature) const noexcept;

  sdkv1::P256PublicKey sak_{};
  bool ready_{false};
};

}  // namespace routeloom
