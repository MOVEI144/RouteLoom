#pragma once

// SDK v1 zero-touch join handshake (docs/design/sdk-v1/02-zero-touch-join.md
// §5, §6, §10; plan P3-4 PR 1). A bounded, allocation-free driver that owns
// one edhoc::Session as Initiator (method 0 / cipher suite 2) with the join
// EAD and credential plumbing of sdkv1_ead.hpp, and reduces an authenticated
// exchange to exactly one of:
//
//   AllowVerified            — a verified SiteRecord assembled only from
//                              authenticated material (m2 SiteCert, the
//                              MemberCert + SitePackage that passed the
//                              02 §10.2 matrix and the local gates, the
//                              derived DAMS), self-checked and ready for
//                              SiteStore::commit.
//   authenticated non-Allow  — PendingAssignment / AuthorityBusy /
//                              DenyNotHere / DenyBlocked, or a RemovalNotice
//                              classified by removal_notice_verify.
//   a failure class          — MalformedResult (authenticated m4 but an
//                              invalid JoinResult or Allow),
//                              AuthenticationFailed (m2 credential or
//                              responder-signature failure), Failed (m2
//                              decode/transport, m4, or a local cause).
//
// Scope: no radio, no NVS, no store, no candidate selection — the caller
// ships the composed bytes, feeds the received messages and maps the
// outcome to its candidate table (sdkv1_join_candidates.hpp). The
// IdentityRecord is borrowed and must outlive end().
//
// Authentication ordering (design P3-4 §6.1): what the EAD hook stages
// inside process_message_2/4 is unauthenticated input; values become
// trusted only when the owning session call returns success. compose_m3 is
// unreachable before process_message_2 authenticated the responder, so a
// forged SiteCert can never draw the device's DevCert out (02 §12 row 2).
// The DAMS is derived only after m4 key confirmation AND the whole Allow
// verification matrix.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery.hpp"  // EntropySource
#include "routeloom/edhoc.hpp"
#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// JoinRequest capability bits above the role positions (04 §4, P6 PR A):
// bit3 = this Joiner can apply an RRS1 during ZT recovery, bit4 = the
// join transport can relay RRS1 bytes. Assigned here; consumed by the
// P3-4 Joiner / P4 join-transport work that advertises them.
constexpr std::uint32_t kJoinCapApplyRrs = 1u << 3;
constexpr std::uint32_t kJoinCapRelayRrs = 1u << 4;

// --- Attempt configuration ---------------------------------------------------------
struct JoinHandshakeConfig {
  NodeId node{kInvalidNodeId};      // must equal identity.node_id
  // The selected candidate's observed hints, bound to the authenticated
  // SiteCert in m2 (hint collision does not pass as authentication).
  std::uint32_t org_hint{0};        // join_org_hint of the Site CA being tried
  std::uint32_t site_hint{0};       // join_site_hint of the expected site
  std::uint32_t network_low32{0};   // observed network hint
  std::uint32_t fw_version{0};
  // JoinRequest capability bits (bit0 sleepy, bit1 relay, bit2 gateway —
  // the same positions as the MemberCert role bits). The granted role's
  // relay/gateway bits must be executable: every set role bit beyond
  // endpoint needs the matching capability bit.
  std::uint32_t capability{0};
  std::uint8_t requested_role{0};   // nonzero known role bits, within capability
  NodeId last_site_id{0};           // a really held membership only, else 0
  std::uint32_t last_generation{0};
  NetworkId last_network{0};  // nonzero only for saved-membership recovery
  // bit n set -> channel n usable on this hardware (1..14). An Allow whose
  // SitePackage names an unusable channel is refused before commit.
  std::uint16_t usable_channel_mask{0xFFFE};
};

// --- Outcome -----------------------------------------------------------------------
enum class JoinAttemptOutcome : std::uint8_t {
  Pending = 0,            // attempt in flight (no classification yet)
  AllowVerified,          // verified Allow; the prepared record is ready
  PendingAssignment,      // authenticated; retry_after_s applies to this site
  AuthorityBusy,          // authenticated; retry_after_s applies to this site
  DenyNotHere,            // authenticated deny -> fixed 6 h avoidance
  DenyBlocked,            // authenticated deny -> fixed 24 h avoidance
  RemovedVerified,        // RemovalNotice verified against stored membership
  RemovedDenied,          // notice failed verification -> 24 h avoidance
  RemovedNoMembership,    // Removed but no membership evidence -> 600 s suppress
  MalformedResult,        // authenticated m4, invalid result/Allow -> 24 h
  AuthenticationFailed,   // m2 credential/signature failure -> 24 h on the key
  Failed,                 // m2 decode/transport, m4, local failure -> transient
};

// The stored-membership evidence a Removed verdict is tested against (02 §8):
// fields of the device's existing RLS1, never the presenting site's claims.
struct JoinMembershipEvidence {
  std::uint64_t site_id{0};
  NetworkId network{0};
  NodeId node{kInvalidNodeId};
  std::uint32_t generation{0};
  P256PublicKey sak{};
};

struct JoinDecideInput {
  const JoinMembershipEvidence* membership{nullptr};  // nullptr: no stored RLS1
  std::uint32_t boot_witness{0};          // current rlboot witness (Owner-prepared)
  std::uint32_t prior_rs_epoch_floor{0};  // kept iff the joined site is last_site_id
};

struct JoinDecided {
  JoinAttemptOutcome outcome{JoinAttemptOutcome::Pending};
  std::uint32_t retry_after_s{0};       // PendingAssignment/AuthorityBusy only
  std::uint32_t rs_epoch_to_fetch{0};   // Allow: the package's rs_epoch hint
  RemovalNotice removal{};              // RemovedVerified only
  std::array<std::uint8_t, kRemovalNoticeObjectSize> removal_object{};
  // AllowVerified only: the verified record, owned by the handshake, valid
  // until end(). Never populated from unverified input.
  const SiteRecord* record{nullptr};
};

struct JoinAttemptStats {
  std::uint32_t m1_composed{0};
  std::uint32_t m2_authenticated{0};
  std::uint32_t m2_failures{0};
  std::uint32_t m3_composed{0};
  std::uint32_t m4_authenticated{0};
  std::uint32_t m4_failures{0};
  std::uint32_t ead_rejects{0};
  std::uint32_t credential_rejects{0};
  std::uint32_t results_malformed{0};
  std::uint32_t allows_denied{0};
  std::uint32_t notices_denied{0};
  std::uint32_t removed_without_membership{0};
};

// --- EAD token inspection ------------------------------------------------------------
// The join acceptance matrix on libedhoc's decoded EAD items — the token-level
// equivalent of the raw-CBOR walkers join_ead_find{,_with_credential}
// (sdkv1_ead.hpp): padding (label 0) skipped, the expected message item first,
// then at most one Credential item, critical labels only, bounded value sizes,
// nothing else. `need_credential` requires the Credential item (EAD_2); with it
// false a Credential item is rejected like any other extra item (EAD_4).
// Inconsistent (pointer, count) input fails closed: more than
// edhoc::kEadItemsMax items, null item storage with a nonzero count, and
// null value storage with a nonzero size are all refused outright.
Status join_ead_items_check(const edhoc::EadItem* items, std::size_t count, JoinEad expected,
                            bool need_credential, ByteView& value,
                            ByteView& credential) noexcept;

// --- Stored-record re-verification -----------------------------------------------------
// Boot/reconcile path (02 §10.2 last row, design §7.2): re-derives every fact a
// stored RLS1 claims before it may drive membership — structure
// (site_validate), device binding (member_cert_matches), the SiteCert under an
// ACTIVE Site CA anchor of `identity`, and the MemberCert signature under the
// SiteCert's own cnf key. A malformed record is an error; a well-formed record
// that does not authenticate for this device is verified=false.
Status join_membership_verify(const SiteRecord& site, const IdentityRecord& identity,
                              bool& verified,
                              const Es256Verifier& verifier = default_es256_verifier()) noexcept;

// --- The driver ----------------------------------------------------------------------
class JoinHandshake final {
 public:
  JoinHandshake() noexcept : credentials_(*this), ead_(*this) {}
  ~JoinHandshake() { end(); }
  JoinHandshake(const JoinHandshake&) = delete;
  JoinHandshake& operator=(const JoinHandshake&) = delete;

  // Validates the identity and the config, draws a fresh nonzero C_I and
  // begins the session. RLI1 key_location: None -> Unprovisioned,
  // NvsPlaintext -> runs, external handles (2/3) -> Unsupported before
  // anything is sent; handle bytes are never used as a private scalar.
  Status begin(const JoinHandshakeConfig& config, const IdentityRecord& identity,
               EntropySource& entropy, const edhoc::AeadCcm* aead = nullptr) noexcept;

  // m1 with the JoinIntent EAD into `out` (<= kJoinMessageMax).
  Status compose_m1(MutableByteView out, std::size_t& length) noexcept;
  // m2 from the transport. Success = the responder is authenticated AND the
  // SiteOffer matches the SiteCert AND the observed candidate hints — only
  // then do offer()/site_claims()/site_cert() become meaningful. On failure
  // the outcome is AuthenticationFailed for credential/signature failures
  // and Failed for decode/transport failures.
  Status process_m2(ByteView message) noexcept;
  // m3 with JoinRequest + the DevCert Credential item.
  Status compose_m3(MutableByteView out, std::size_t& length) noexcept;
  // m4 from the transport. Success = outer verification incl. key
  // confirmation; the staged JoinResult stays unverified until decide().
  Status process_m4(ByteView message) noexcept;
  // Classifies and verifies the staged JoinResult (02 §10.2 + local gates;
  // on AllowVerified also derives the DAMS and prepares the record).
  Status decide(const JoinDecideInput& input, JoinDecided& out) noexcept;
  // Ends the session and wipes every staged/prepared copy (Session::end
  // clears keys, arena, ephemeral material; our own buffers follow).
  void end() noexcept;

  bool m1_sent() const noexcept { return stage_ != Stage::Idle && stage_ != Stage::Begun; }
  bool m2_authenticated() const noexcept { return m2_ok_; }
  const SiteOffer& offer() const noexcept { return offer_; }
  const CertClaims& site_claims() const noexcept { return site_claims_; }
  const Digest256& sak_kid() const noexcept { return sak_kid_; }
  ByteView site_cert() const noexcept { return site_cert_.view(); }
  const JoinAttemptStats& stats() const noexcept { return stats_; }
  JoinAttemptOutcome outcome() const noexcept { return outcome_; }
  const edhoc::Session& session() const noexcept { return session_; }

 private:
  enum class Stage : std::uint8_t { Idle, Begun, M1Sent, M2Done, M3Sent, M4Done };

  class Credentials final : public edhoc::CredentialProvider {
   public:
    explicit Credentials(JoinHandshake& owner) noexcept : owner_(owner) {}
    Status local(edhoc::Role role, edhoc::LocalCredential& out) noexcept override;
    Status peer(edhoc::Role role, ByteView kid, edhoc::PeerCredential& out) noexcept override;

   private:
    JoinHandshake& owner_;
  };
  class Ead final : public edhoc::EadHandler {
   public:
    explicit Ead(JoinHandshake& owner) noexcept : owner_(owner) {}
    Status compose(int message, edhoc::EadItem* items, std::size_t capacity,
                   std::size_t& count) noexcept override;
    Status process(int message, const edhoc::EadItem* items, std::size_t count) noexcept override;

   private:
    JoinHandshake& owner_;
  };

  Status config_validate(const JoinHandshakeConfig& config,
                         const IdentityRecord& identity) noexcept;
  Status decide_allow(const JoinResult& result, const JoinDecideInput& input,
                      JoinDecided& out) noexcept;
  Status decide_removed(const JoinResult& result, const JoinDecideInput& input,
                        JoinDecided& out) noexcept;
  Status build_prepared(const JoinResult& result, const CertClaims& member,
                        const JoinDecideInput& input, JoinDecided& out) noexcept;

  const IdentityRecord* identity_{nullptr};
  JoinHandshakeConfig config_{};
  edhoc::Session session_{};
  Credentials credentials_;
  Ead ead_;
  Stage stage_{Stage::Idle};
  JoinAttemptOutcome outcome_{JoinAttemptOutcome::Pending};
  bool m2_ok_{false};
  std::array<std::uint8_t, edhoc::kConnectionIdMaxSize> cid_{};
  // m2 staging (trusted only after process_m2 succeeds).
  ByteBuffer<kRlcw1CertMax> site_cert_{};
  CertClaims site_claims_{};
  SiteOffer offer_{};
  Digest256 sak_kid_{};
  std::uint16_t devcert_model_{0};
  // m4 staging (trusted only after process_m4 + decide()).
  ByteBuffer<kJoinResultMax> result_{};
  // Verified Allow output — never exposed before the matrix passed.
  SiteRecord prepared_{};
  // EAD compose values (referenced by the session during composition).
  ByteBuffer<kJoinIntentSize> intent_value_{};
  ByteBuffer<kJoinRequestSize> request_value_{};
  ByteBuffer<kLastMembershipSize> last_membership_value_{};
  JoinAttemptStats stats_{};
};

}  // namespace routeloom::sdkv1
