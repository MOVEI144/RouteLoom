#pragma once

// TrustView — the trust-store-backed config-authority permit verifier
// (issue #10; sdk-completion/04-provisioning-lifecycle.md §4.6.2, §4.7).
//
// CoseEsp256AuthorityVerifier holds ONE statically provisioned
// (authority_id, pubkey) pair. TrustView implements the same
// ConfigAuthorityVerifier interface over the identical RLCP1_COSE_ESP256
// envelope — same restricted COSE_Sign1 shape, same external AAD, same
// R/S range + low-S canonicality rules, same vendored micro-ecc P-256
// verify — but resolves the verification key at verify time from the
// committed RLT1 trust image:
//
//   - the envelope kid must name context.authorized_issuer (the context's
//     single allowed authority, unchanged);
//   - the RCC1 body's (authority, authority_generation) are UNTRUSTED
//     hints that select the key record via TrustStore::find_key — the
//     signature subsequently authenticates them, so a hint can never
//     select a foreign key;
//   - the record must be status Active (staged/retired/revoked records
//     are inventory; they verify nothing — §4.3.1, §4.6.1) at the only
//     defined profile/role/scope values;
//   - the generation must satisfy the image's min_authority_generation
//     floor — the store replaces the compile-time generation scalar as
//     the rotation policy, so an operator-bounded overlap window (two
//     generations Active at once) verifies by design. The journal's
//     configured generation pin still applies downstream at decision
//     time; this class deliberately does not re-pin
//     context.authority_generation.
//
// Fail-closed posture (§4.3.1, §4.7): the view verifies only under a
// committed image that is not quarantined, not uncertain (the lost
// sibling may have held a newer image — the store refuses commits until
// recover(), and this consumer refuses to serve possibly-stale trust as
// policy), and not provably stale (store_epoch below the epoch_floor a
// damaged committed record proved). Every impairment reports !ready()
// and verify_permit() returns an error — never a silent verdict.
//
// §4.6.2's trust_epoch intake capture and §4.6.3's decision-time recheck
// are served by store_epoch()/min_authority_generation()/
// resolve_authority_key(): the caller snapshots the epoch at intake and
// re-resolves before commit. This class keeps no cached key across
// calls, so a committed trust-manifest epoch change takes effect on the
// next verification with no re-resolution hook (§4.5.2).

#include <cstdint>

#include "routeloom/config.hpp"
#include "routeloom/config_cose.hpp"
#include "routeloom/status.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

class TrustView final : public ConfigAuthorityVerifier {
 public:
  // `store` must outlive the view; the Owner serializes calls, same as
  // the journal/ledger stores.
  explicit TrustView(const TrustStore& store) noexcept : store_(store) {}

  // ready(): the store must be usable AND a verifying key must resolve —
  // either the deployment-pinned (authority_id, generation) set via
  // require_key(), or at least one Active config-issuer record. A valid
  // image may deliberately hold zero active keys ("config disabled",
  // §4.5.1 rule 5); the COSE profile bit is then honestly not advertised.
  bool ready() const noexcept override;
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Production;
  }
  // The same wire profile bit as CoseEsp256AuthorityVerifier — the
  // envelope is identical; only the key provenance differs.
  std::uint32_t permit_profile_bit() const noexcept override { return 1u << 1; }
  // Same P-256 verify cost the intake limiter exists for (03-signing §3.3).
  bool verify_is_expensive() const noexcept override { return true; }
  Status verify_permit(const ConfigPermitContext& context, ByteView permit,
                       endpoint::EncodedConfigCommand& payload,
                       bool& verified) noexcept override;

  // §4.6.2 key-resolution primitive: the exact (authority_id, generation)
  // lookup with the active/floor policy applied — nullptr for absent,
  // staged, retired, revoked or below-floor records, and whenever the
  // store is unusable. The returned pointer borrows the committed image:
  // it is invalidated by commit_image()/recover() — re-resolve at each
  // decision point, never cache across intake boundaries.
  const TrustKeyRecord* resolve_authority_key(
      std::uint64_t authority_id, std::uint32_t generation) const noexcept;

  // §4.7.1 R2 revocation query for device-credential-bound operations
  // (context establishment, grant validation — the membership workstream
  // consumes it). Fails closed: an unusable store proves nothing about
  // the revocation set, so the predicate reports REVOKED rather than
  // admit a credential it cannot check.
  bool is_credential_revoked(const Digest256& kid_fingerprint) const noexcept;

  // Optional boot-time pin (§4.4 step 5's "the required key resolves"):
  // when set, ready() additionally requires THIS (authority_id,
  // generation) record to resolve active. Verification itself is never
  // narrowed by the pin — the store's record status and floor are the
  // whole policy.
  void require_key(std::uint64_t authority_id,
                   std::uint32_t generation) noexcept {
    required_authority_ = authority_id;
    required_generation_ = generation;
    required_set_ = true;
  }

  // State surface for intake capture (§4.6.2 trust_epoch), the
  // decision-time recheck (§4.6.3) and TrustStatus diagnostics: committed
  // epoch, generation floor and impairment flags, passed through live.
  std::uint32_t store_epoch() const noexcept { return store_.store_epoch(); }
  std::uint32_t min_authority_generation() const noexcept {
    return store_.min_authority_generation();
  }
  bool quarantined() const noexcept { return store_.quarantined(); }
  bool uncertain() const noexcept { return store_.uncertain(); }

  // The store is fit to verify under: initialized, a committed image,
  // not quarantined, not uncertain, and not provably stale — the active
  // epoch covers every epoch any committed-seal record proved this boot,
  // including CRC-failed ones (§4.3.1's recovery-floor rule).
  bool usable() const noexcept;

 private:
  const TrustStore& store_;
  std::uint64_t required_authority_{0};
  std::uint32_t required_generation_{0};
  bool required_set_{false};
  // RCC1 decode scratch (member .bss, Owner-serialized — same pattern as
  // CoseEsp256AuthorityVerifier::command_).
  endpoint::ConfigCommand command_{};
};

}  // namespace routeloom
