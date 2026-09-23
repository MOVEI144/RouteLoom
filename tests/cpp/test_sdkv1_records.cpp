// SDK v1 codec unit tests (docs/design/sdk-v1/08 P1-2/P1-3): RLCW1 issue/
// verify through the Es256Verifier hook, the 02 §10.2 field checks, SiteCert
// chain verification against RLI1 anchors, RLI1/RLS1/RRS1/RLP1 round trips
// and semantic rejections the golden vectors do not enumerate. The shared
// byte layouts themselves are pinned by routeloom_sdkv1_golden_tests.

#include <cstdio>

#include "test_sdkv1.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace sdkv1_test;

// A hook that records calls and delegates or refuses — proves the codec
// never bypasses the verifier and gates non-canonical signatures first.
class CountingVerifier final : public Es256Verifier {
 public:
  explicit CountingVerifier(const bool answer) : answer_(answer) {}
  bool verify_digest(const P256PublicKey& pubkey, const Digest256& digest,
                     const Es256Signature& signature) const noexcept override {
    ++calls;
    return answer_ && default_es256_verifier().verify_digest(pubkey, digest, signature);
  }
  mutable int calls{0};

 private:
  bool answer_;
};

void test_cert_issue_verify_and_hook() {
  const auto cert = issue(membercert_claims(), sak());
  CHECK(cert.size > 0 && cert.size <= kRlcw1CertLargest);
  CertClaims claims{};
  bool verified = false;
  CHECK_OK(cert_verify(cert.view(), sak().pub, claims, verified));
  CHECK(verified);
  CHECK(claims.assignment_generation == 3 && claims.network == kNetwork);

  CountingVerifier refuse(false);
  CHECK_OK(cert_verify(cert.view(), sak().pub, claims, verified, refuse));
  CHECK(!verified && refuse.calls == 1);

  // High-S twin: rejected before the hook runs.
  ByteBuffer<kRlcw1CertMax> high = cert;
  std::array<std::uint8_t, 32> s{};
  std::memcpy(s.data(), high.bytes.data() + high.size - 32, 32);
  std::array<std::uint8_t, 32> flipped = kSecp256r1Order;
  routeloom_test::be32_sub(flipped, s);
  std::memcpy(high.bytes.data() + high.size - 32, flipped.data(), 32);
  CountingVerifier accept(true);
  CHECK_OK(cert_verify(high.view(), sak().pub, claims, verified, accept));
  CHECK(!verified && accept.calls == 0);

  // Wrong issuer key.
  CHECK_OK(cert_verify(cert.view(), site_ca().pub, claims, verified));
  CHECK(!verified);
  // Off-curve issuer key never reaches the hook.
  P256PublicKey bad_key = sak().pub;
  bad_key[63] ^= 1;
  CountingVerifier guarded(true);
  CHECK_OK(cert_verify(cert.view(), bad_key, claims, verified, guarded));
  CHECK(!verified && guarded.calls == 0);
}

void test_cert_field_rules() {
  CertClaims c = membercert_claims();
  ByteBuffer<kRlcw1PayloadMax> payload{};
  CHECK_OK(cert_payload_encode(c, payload));
  c.site_epoch = kSiteEpoch + 1;  // network>>32 disagrees
  CHECK(!cert_payload_encode(c, payload).ok());
  c = membercert_claims();
  c.role = 0;
  CHECK(!cert_payload_encode(c, payload).ok());
  c = membercert_claims();
  c.model = 1;  // foreign field
  CHECK(!cert_payload_encode(c, payload).ok());
  c = sitecert_claims();
  c.usage = 0x02;
  CHECK(!cert_payload_encode(c, payload).ok());
  c = devcert_claims();
  c.site_epoch = 1;
  CHECK(!cert_payload_encode(c, payload).ok());
  c = devcert_claims();
  c.issuer = ~std::uint64_t{0};
  CHECK(!cert_payload_encode(c, payload).ok());
  // A payload with a trailing claim-sized byte is not canonical.
  CHECK_OK(cert_payload_encode(devcert_claims(), payload));
  payload.bytes[payload.size] = 0x00;
  CertClaims out{};
  CHECK(!cert_payload_decode(ByteView{payload.bytes.data(), payload.size + 1}, out).ok());
  CHECK_OK(cert_payload_decode(payload.view(), out));
}

void test_member_cert_matches() {
  const CertClaims site = sitecert_claims();
  const CertClaims member = membercert_claims();
  CHECK_OK(member_cert_matches(member, site, kNode, device_key().pub));
  CHECK(member_cert_matches(member, site, kNode + 1, device_key().pub).code ==
        StatusCode::AuthorizationFailed);
  CHECK(member_cert_matches(member, site, kNode, other_key().pub).code ==
        StatusCode::AuthorizationFailed);
  CertClaims other_site = site;
  other_site.subject = kSiteId + 1;
  CHECK(member_cert_matches(member, other_site, kNode, device_key().pub).code ==
        StatusCode::AuthorizationFailed);
  CertClaims other_epoch = sitecert_claims((NetworkId{kSiteEpoch + 1} << 32U) | kNetworkLow);
  CHECK(member_cert_matches(member, other_epoch, kNode, device_key().pub).code ==
        StatusCode::AuthorizationFailed);
  CHECK(!member_cert_matches(site, member, kNode, device_key().pub).ok());
}

void test_identity_site_cert_chain() {
  IdentityRecord identity = identity_record();
  const auto site_cert = issue(sitecert_claims(), site_ca());
  CertClaims claims{};
  bool verified = false;
  CHECK_OK(identity_verify_site_cert(identity, site_cert.view(), claims, verified));
  CHECK(verified && claims.subject == kSiteId);
  // Disabled anchor: denied.
  identity.anchors[0].status = AnchorStatus::Disabled;
  CHECK_OK(identity_verify_site_cert(identity, site_cert.view(), claims, verified));
  CHECK(!verified);
  // Foreign Site CA (issuer id not in the anchors): denied.
  identity = identity_record();
  CertClaims foreign = sitecert_claims();
  foreign.issuer = kSiteCaId + 1;
  const auto foreign_cert = issue(foreign, site_ca());
  CHECK_OK(identity_verify_site_cert(identity, foreign_cert.view(), claims, verified));
  CHECK(!verified);
  // Right id, wrong key: denied.
  const auto forged = issue(sitecert_claims(), other_key());
  CHECK_OK(identity_verify_site_cert(identity, forged.view(), claims, verified));
  CHECK(!verified);
  // A MemberCert is never accepted as a SiteCert.
  const auto member = issue(membercert_claims(), sak());
  CHECK_OK(identity_verify_site_cert(identity, member.view(), claims, verified));
  CHECK(!verified);
  // The AssignmentVerifier anchor is never a SiteCA.
  identity = identity_record(true);
  CertClaims via_verifier = sitecert_claims();
  via_verifier.issuer = kVerifierId;
  const auto verifier_cert = issue(via_verifier, verifier_key());
  CHECK_OK(identity_verify_site_cert(identity, verifier_cert.view(), claims, verified));
  CHECK(!verified);
}

void test_identity_roundtrip_and_rules() {
  for (const bool strict : {false, true}) {
    const IdentityRecord identity = identity_record(strict);
    ByteBuffer<kIdentitySlotBytes> record{};
    CHECK_OK(identity_record_encode(identity, kIdentitySealCommitted, record));
    IdentityRecord decoded{};
    CHECK_OK(identity_record_decode(record.view(), decoded));
    CHECK(decoded.node_id == kNode && decoded.anchor_count == identity.anchor_count);
    CHECK(decoded.devcert.size == identity.devcert.size);
    // Pending records never decode as committed identities.
    CHECK_OK(identity_record_encode(identity, kSealPending, record));
    CHECK(!identity_record_decode(record.view(), decoded).ok());
  }
  IdentityRecord r = identity_record();
  r.key_location = CredentialKeyLocation::None;  // material must then be zero
  CHECK(!identity_validate(r).ok());
  r.key_material.fill(0);
  CHECK_OK(identity_validate(r));
  r.key_location = CredentialKeyLocation::SecureElement;  // opaque handle
  r.key_material.fill(0xAB);
  CHECK_OK(identity_validate(r));
  r = identity_record();
  r.anchors[0].pubkey[5] ^= 1;  // off curve
  CHECK(!identity_validate(r).ok());
  r = identity_record();
  r.devcert = issue(devcert_claims(kNode + 1), device_ca());
  CHECK(identity_validate(r).code == StatusCode::IntegrityError);
  r = identity_record();
  r.devcert.bytes[r.devcert.size - 1] ^= 1;  // signature bits are not checked on device
  CHECK_OK(identity_validate(r));
}

void test_site_record_rules() {
  const SiteRecord site = site_record();
  CHECK_OK(site_validate(site));
  CHECK_OK(site_matches_identity(site, identity_record()));
  IdentityRecord stranger = identity_record();
  stranger.node_id = kNode + 1;
  CHECK(site_matches_identity(site, stranger).code == StatusCode::AuthorizationFailed);
  ByteBuffer<kSiteSlotBytes> record{};
  CHECK_OK(site_record_encode(site, kSiteSealCommitted, 9, record));
  CHECK(record.size == kSiteFixedSize + site.site_cert.size + site.member_cert.size + 4);
  SiteRecord decoded{};
  std::uint32_t seq = 0;
  CHECK_OK(site_record_decode(record.view(), decoded, &seq));
  CHECK(seq == 9 && decoded.gk_epoch_current == site.gk_epoch_current);

  SiteRecord r = site;
  r.gk_epoch_next = 204;  // next epoch without a key
  CHECK(!site_validate(r).ok());
  for (std::size_t i = 0; i < 32; ++i) r.gk_next[i] = static_cast<std::uint8_t>(i + 1);
  CHECK_OK(site_validate(r));
  r.gk_epoch_next = r.gk_epoch_current;  // must advance
  CHECK(!site_validate(r).ok());
  r = site;
  r.gateways[1] = r.gateways[0];
  CHECK(!site_validate(r).ok());
  r = site;
  r.channel = 15;
  CHECK(!site_validate(r).ok());
  r = site;
  r.dams.fill(0);
  CHECK(!site_validate(r).ok());
  r = site;
  r.role = static_cast<std::uint8_t>(kMemberRoleRelay);  // disagrees with the MemberCert
  CHECK(!site_validate(r).ok());
  const SiteRecord cleared{};
  CHECK_OK(site_validate(cleared));
  CHECK_OK(site_record_encode(cleared, kSiteSealCommitted, 1, record));
  CHECK(record.size == kSiteRecordMin);
}

void test_revocation_rules() {
  const RevocationSet set = revocation_set(14, 3);
  const auto object = revocation_object(set);
  CHECK(object.size > 0);
  RevocationSet out{};
  bool verified = false;
  CHECK_OK(revocation_object_verify(object.view(), sak().pub, kSiteId, kNetwork, out, verified));
  CHECK(verified && out.count == 3 && out.rs_epoch == 14);
  // The AAD binds the network the verifier expects, not a transport claim.
  const auto other_aad = revocation_object(set, sak(), kNetwork + 1);
  CHECK_OK(revocation_object_verify(other_aad.view(), sak().pub, kSiteId, kNetwork, out,
                                    verified));
  CHECK(!verified);
  CHECK_OK(revocation_object_verify(object.view(), sak().pub, kSiteId, kNetwork + 1, out,
                                    verified));
  CHECK(!verified);

  // revocation_rejects: generation below the entry's floor, site epoch below
  // the set floor.
  CHECK(revocation_rejects(set, set.entries[0].node_id, set.entries[0].min_generation - 1,
                           kSiteEpoch));
  CHECK(!revocation_rejects(set, set.entries[0].node_id, set.entries[0].min_generation,
                            kSiteEpoch));
  CHECK(!revocation_rejects(set, kNode, 1, kSiteEpoch));
  CHECK(revocation_rejects(set, kNode, 1, set.site_epoch_floor - 1));

  // Full set: 32 entries, the 616-byte object bound and the 640-byte slot.
  const RevocationSet full = revocation_set(1, 32);
  const auto full_object = revocation_object(full);
  CHECK(full_object.size == kRevocationObjectMax);
  ByteBuffer<kRevocationSlotBytes> record{};
  CHECK_OK(revocation_record_encode(full_object.view(), kRevocationSealCommitted, 1, record));
  CHECK(record.size == kRevocationSlotBytes);
  RevocationSet bad = revocation_set(1, 2);
  bad.entries[1].node_id = bad.entries[0].node_id;
  ByteBuffer<kRevocationPayloadMax> payload{};
  CHECK(!revocation_payload_encode(bad, payload).ok());
  bad = revocation_set(1, 2, kSiteEpoch + 1);
  CHECK(!revocation_payload_encode(bad, payload).ok());
}

void test_resume_slot_rules() {
  const ResumeSlot slot = resume_slot(kPeer, kResumeFlagPinned, 700);
  std::array<std::uint8_t, kResumeSlotBytes> bytes{};
  CHECK_OK(resume_slot_encode(slot, bytes));
  ResumeSlot out{};
  CHECK_OK(resume_slot_decode(ByteView{bytes.data(), bytes.size()}, out));
  CHECK(out.valid && out.peer == kPeer && out.rms == slot.rms && out.last_used_boot == 700);
  CHECK_OK(resume_slot_encode(ResumeSlot{}, bytes));
  CHECK_OK(resume_slot_decode(ByteView{bytes.data(), bytes.size()}, out));
  CHECK(!out.valid);
  ResumeSlot bad = slot;
  bad.flags = 0x80;
  CHECK(!resume_slot_encode(bad, bytes).ok());
  bad = slot;
  bad.rms.fill(0);
  CHECK(!resume_slot_encode(bad, bytes).ok());
  bad = ResumeSlot{};
  bad.last_used_boot = 1;  // empty slots carry nothing
  CHECK(!resume_slot_encode(bad, bytes).ok());
  std::array<std::uint8_t, 8> id{};
  const auto cert = issue(membercert_claims(), sak());
  resume_peer_cert_id(cert.view(), id);
  Digest256 digest{};
  sha256(cert.view(), digest);
  CHECK(std::memcmp(id.data(), digest.data(), 8) == 0);
}

}  // namespace

int main() {
  test_cert_issue_verify_and_hook();
  test_cert_field_rules();
  test_member_cert_matches();
  test_identity_site_cert_chain();
  test_identity_roundtrip_and_rules();
  test_site_record_rules();
  test_revocation_rules();
  test_resume_slot_rules();
  if (failures != 0) {
    std::fprintf(stderr, "%d sdkv1 record check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_records_tests: ok");
  return 0;
}
