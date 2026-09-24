// TrustView tests (sdk-completion/04-provisioning-lifecycle.md §4.6.2,
// §4.7): trust-store-backed config-authority verification. Covers key
// resolution by (authority_id, generation), record-status and
// generation-floor policy, the device-credential revocation query,
// fail-closed impairment posture (quarantine / uncertain / unprovisioned
// stores), live re-resolution across image commits, and a real signed
// RLCP1_COSE_ESP256 permit accepted under a store-resolved key. Permits
// are signed with the deterministic RFC-6979 low-S helper from
// test_provisioning.hpp — the same micro-ecc arithmetic the verifier runs.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/trust_view.hpp"

#include "test_provisioning.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::FaultyTrustStorage;
using routeloom_test::TestKeyPair;
using routeloom_test::cbor_put_bstr;
using routeloom_test::sign_digest_low_s;
using routeloom_test::kTrustSealCommittedWire;
using routeloom_test::test_image;
using routeloom_test::test_key_record;
using routeloom_test::test_keypair;
using routeloom_test::test_revocation;

const TestKeyPair kRoot = test_keypair(0x11);
const TestKeyPair kAuth1 = test_keypair(0x33);
const TestKeyPair kAuth2 = test_keypair(0x44);

constexpr std::uint64_t kAuthorityId = 0xA17;
constexpr NetworkId kNetwork = 7;
constexpr NodeId kTarget = 0xC3;

// A minimal valid RCC1 command (satisfies config_command_encode's
// identity/revision/field rules). `authority`/`generation` are the fields
// TrustView treats as key-selection hints.
endpoint::ConfigCommand make_command(
    const std::uint32_t generation,
    const std::uint64_t authority = kAuthorityId) {
  endpoint::ConfigCommand command{};
  command.config_namespace = endpoint::kConfigNamespaceSdk;
  command.schema = 1;
  command.network = kNetwork;
  command.target = kTarget;
  command.authority = authority;
  command.authority_generation = generation;
  command.authority_sequence = 42;
  command.operation_id.fill(0xAB);
  command.expected_revision = 4;
  command.next_revision = 5;
  command.target_boot = 9;
  command.challenge_nonce.fill(0x5C);
  command.apply_within_ms = 10000;
  command.fields[0].field_id = 1;
  command.fields[0].type = endpoint::ConfigFieldType::U8;
  command.fields[0].value_size = 1;
  command.fields[0].value[0] = 0x7F;
  command.field_count = 1;
  return command;
}

// Sign a complete RLCP1_COSE_ESP256 permit: RCC1 canonical payload, the
// byte-exact protected header {1:-9, 4:bstr8}, the expected-context AAD,
// Sig_structure -> SHA-256 -> deterministic low-S ECDSA.
// `kid` selects the protected-header authority id; 0 means "the command's
// own authority" (kid 0 is never a real authority — kInvalidNodeId).
Status make_permit(const endpoint::ConfigCommand& command,
                   const std::array<std::uint8_t, 32>& priv,
                   ByteBuffer<kCosePermitMax>& out,
                   const std::uint64_t kid = 0) {
  out.clear();
  endpoint::EncodedConfigCommand rcc1{};
  Status status = endpoint::config_command_encode(command, rcc1);
  if (!status) return status;
  ByteBuffer<13> protected_bytes{};
  ByteWriter prot(protected_bytes.writable());
  status = prot.write_u8(0xA2);  // map(2)
  if (status) status = prot.write_u8(0x01);  // label 1 (alg)
  if (status) status = prot.write_u8(0x28);  // -9 (ESP256)
  if (status) status = prot.write_u8(0x04);  // label 4 (kid)
  if (status) status = prot.write_u8(0x48);  // bstr(8)
  if (status) {
    status = prot.write_u64(kid == 0 ? command.authority : kid);
  }
  if (!status) return status;
  protected_bytes.size = prot.size();

  ByteBuffer<kConfigPermitAadSize> aad{};
  status = config_permit_aad(command.network, command.target,
                             command.config_namespace, aad);
  if (!status) return status;
  ByteBuffer<kCosePermitMax + 64> sig_structure{};
  status = cose_sig_structure(protected_bytes.view(), aad.view(),
                              rcc1.view(), sig_structure);
  if (!status) return status;
  ScopeDigest digest{};
  sha256(sig_structure.view(), digest);
  std::array<std::uint8_t, 64> signature{};
  if (!sign_digest_low_s(priv, digest, signature)) {
    return Status::error(StatusCode::InternalError, "test sign failed");
  }
  ByteWriter writer(out.writable());
  status = writer.write_u8(0xD2);  // tag 18
  if (status) status = writer.write_u8(0x84);  // array(4)
  if (status) status = cbor_put_bstr(writer, protected_bytes.view());
  if (status) status = writer.write_u8(0xA0);  // empty unprotected map
  if (status) status = cbor_put_bstr(writer, rcc1.view());
  if (status) {
    status = cbor_put_bstr(writer, ByteView{signature.data(), signature.size()});
  }
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

// An image at `epoch` with one active root anchor and the given floor;
// callers attach key/revocation tables.
TrustImage view_image(const std::uint32_t epoch, const std::uint32_t floor) {
  TrustImage image = test_image(epoch, kNetwork, kRoot, 0x100);
  image.min_authority_generation = floor;
  return image;
}

TrustImage single_key_image(const std::uint32_t epoch,
                            const std::uint32_t floor,
                            const std::uint32_t generation,
                            const std::array<std::uint8_t, 64>& pubkey,
                            const TrustKeyStatus status) {
  TrustImage image = view_image(epoch, floor);
  image.keys[0] = test_key_record(kAuthorityId, generation, pubkey, status);
  image.key_count = 1;
  return image;
}

ConfigPermitContext context(const std::uint32_t generation = 1) {
  ConfigPermitContext ctx{};
  ctx.network = kNetwork;
  ctx.target = kTarget;
  ctx.config_namespace = endpoint::kConfigNamespaceSdk;
  ctx.authorized_issuer = kAuthorityId;
  ctx.authority_generation = generation;
  return ctx;
}

// Commit `count` sequential single-key images (epochs 1..count) so both
// slots hold committed records — the quarantine/uncertain setups.
void fill_both_slots(FaultyTrustStorage& storage, const std::uint8_t count) {
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  for (std::uint8_t i = 0; i < count; ++i) {
    CHECK_OK(store.commit_image(single_key_image(
        i + 1, 1, i + 1,
        (i % 2 == 0) ? kAuth1.pub : kAuth2.pub, TrustKeyStatus::Active)));
  }
}

// --- Readiness and key resolution (§4.6.2) ----------------------------------

void test_view_ready_and_resolution() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  TrustView view(store);
  endpoint::EncodedConfigCommand payload{};
  ByteBuffer<kCosePermitMax> permit{};
  CHECK_OK(make_permit(make_command(1), kAuth1.priv, permit));
  bool verified = true;

  // Never initialized: fails closed with an error, never a verdict.
  CHECK(!view.usable() && !view.ready());
  CHECK(view.is_credential_revoked(Digest256{}));
  CHECK(view.resolve_authority_key(kAuthorityId, 1) == nullptr);
  CHECK(view.verify_permit(context(), permit.view(), payload, verified)
            .code == StatusCode::InvalidState);
  CHECK(!verified);

  // Initialized but never provisioned (pre-physical-install): same posture.
  CHECK_OK(store.initialize());
  CHECK(!view.usable() && !view.ready());
  verified = true;
  CHECK(view.verify_permit(context(), permit.view(), payload, verified)
            .code == StatusCode::InvalidState);
  CHECK(!verified);

  // A committed image with one active key and one staged key.
  TrustImage image = view_image(1, 1);
  image.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Active);
  image.keys[1] =
      test_key_record(kAuthorityId, 2, kAuth2.pub, TrustKeyStatus::Staged);
  image.key_count = 2;
  CHECK_OK(store.commit_image(image));

  CHECK(view.usable() && view.ready());
  CHECK(!view.quarantined() && !view.uncertain());
  CHECK(view.security_profile() == SecurityProfile::Production);
  CHECK(view.permit_profile_bit() == (1u << 1));  // RLCP1_COSE_ESP256 bit
  CHECK(view.verify_is_expensive());
  CHECK(view.store_epoch() == 1);
  CHECK(view.min_authority_generation() == 1);

  const TrustKeyRecord* key = view.resolve_authority_key(kAuthorityId, 1);
  CHECK(key != nullptr && key->generation == 1 && key->pubkey == kAuth1.pub);
  CHECK(view.resolve_authority_key(kAuthorityId, 2) == nullptr);  // staged
  CHECK(view.resolve_authority_key(kAuthorityId, 9) == nullptr);  // absent
  CHECK(view.resolve_authority_key(0xB0B, 1) == nullptr);         // foreign id
}

// --- Valid-signature acceptance ------------------------------------------------

void test_view_permit_valid() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit_image(single_key_image(1, 1, 1, kAuth1.pub,
                                               TrustKeyStatus::Active)));
  TrustView view(store);
  CHECK(view.ready());

  const endpoint::ConfigCommand command = make_command(1);
  ByteBuffer<kCosePermitMax> permit{};
  CHECK_OK(make_permit(command, kAuth1.priv, permit));
  endpoint::EncodedConfigCommand payload{};
  bool verified = false;
  CHECK_OK(view.verify_permit(context(), permit.view(), payload, verified));
  CHECK(verified);
  // The verified payload is byte-for-byte the canonical RCC1 signed.
  endpoint::ConfigCommand decoded{};
  CHECK_OK(endpoint::config_command_decode(payload.view(), decoded));
  CHECK(decoded.network == kNetwork && decoded.target == kTarget);
  CHECK(decoded.authority == kAuthorityId &&
        decoded.authority_generation == 1);
  CHECK(decoded.next_revision == 5 && decoded.field_count == 1);
}

// --- Status / floor / binding denials ---------------------------------------------

void test_view_permit_key_status_denied() {
  const endpoint::ConfigCommand command = make_command(1);
  ByteBuffer<kCosePermitMax> permit{};
  CHECK_OK(make_permit(command, kAuth1.priv, permit));
  const TrustKeyStatus denied_statuses[] = {
      TrustKeyStatus::Staged, TrustKeyStatus::Retired, TrustKeyStatus::Revoked};
  for (const TrustKeyStatus status : denied_statuses) {
    FaultyTrustStorage storage;
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(
        single_key_image(1, 1, 1, kAuth1.pub, status)));
    TrustView view(store);
    // No active key at all -> the COSE bit is honestly not advertised.
    CHECK(!view.ready());
    CHECK(view.resolve_authority_key(kAuthorityId, 1) == nullptr);
    endpoint::EncodedConfigCommand payload{};
    bool verified = true;
    // A well-formed permit under a non-active record is a denial, never
    // an error (§4.6.1: staged/retired/revoked verify nothing).
    CHECK_OK(view.verify_permit(context(), permit.view(), payload, verified));
    CHECK(!verified);
  }

  // Record absent for the claimed generation -> denied, but the store's
  // other active key keeps the view ready.
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit_image(single_key_image(1, 1, 9, kAuth2.pub,
                                               TrustKeyStatus::Active)));
  TrustView view(store);
  CHECK(view.ready());  // gen-9 key serves; this permit names gen 1
  endpoint::EncodedConfigCommand payload{};
  bool verified = true;
  CHECK_OK(view.verify_permit(context(), permit.view(), payload, verified));
  CHECK(!verified);
}

void test_view_generation_floor() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  TrustImage image = view_image(1, 5);  // floor raised past gen 3
  image.keys[0] =
      test_key_record(kAuthorityId, 3, kAuth1.pub, TrustKeyStatus::Active);
  image.keys[1] =
      test_key_record(kAuthorityId, 5, kAuth2.pub, TrustKeyStatus::Active);
  image.key_count = 2;
  CHECK_OK(store.commit_image(image));
  TrustView view(store);
  CHECK(view.ready());

  // An ACTIVE record below min_authority_generation verifies nothing —
  // the floor beats the status (§4.5.1 rule 5, §4.6.1 e+3).
  CHECK(view.resolve_authority_key(kAuthorityId, 3) == nullptr);
  CHECK(view.resolve_authority_key(kAuthorityId, 5) != nullptr);

  ByteBuffer<kCosePermitMax> permit3{}, permit5{};
  CHECK_OK(make_permit(make_command(3), kAuth1.priv, permit3));
  CHECK_OK(make_permit(make_command(5), kAuth2.priv, permit5));
  endpoint::EncodedConfigCommand payload{};
  bool verified = true;
  CHECK_OK(view.verify_permit(context(3), permit3.view(), payload, verified));
  CHECK(!verified);
  verified = false;
  CHECK_OK(view.verify_permit(context(5), permit5.view(), payload, verified));
  CHECK(verified);
}

void test_view_permit_binding_denied() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  TrustImage image = view_image(1, 1);
  image.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Active);
  image.keys[1] =
      test_key_record(0xB0B, 1, kAuth2.pub, TrustKeyStatus::Active);
  image.key_count = 2;
  CHECK_OK(store.commit_image(image));
  TrustView view(store);
  CHECK(view.ready());
  const endpoint::ConfigCommand command = make_command(1);
  ByteBuffer<kCosePermitMax> permit{};
  CHECK_OK(make_permit(command, kAuth1.priv, permit));
  endpoint::EncodedConfigCommand payload{};
  bool verified = true;

  // Envelope kid names a foreign authority -> denied before any lookup.
  {
    ByteBuffer<kCosePermitMax> foreign_kid{};
    CHECK_OK(make_permit(command, kAuth1.priv, foreign_kid, 0xB0B));
    CHECK_OK(view.verify_permit(context(), foreign_kid.view(), payload,
                                verified));
    CHECK(!verified);
  }
  // Payload authority is foreign even though the envelope kid names the
  // authorized issuer — the hint can never select a foreign key.
  {
    endpoint::ConfigCommand foreign = make_command(1, 0xB0B);
    ByteBuffer<kCosePermitMax> foreign_body{};
    CHECK_OK(make_permit(foreign, kAuth1.priv, foreign_body, kAuthorityId));
    CHECK_OK(view.verify_permit(context(), foreign_body.view(), payload,
                                verified));
    CHECK(!verified);
  }
  // ...and that same foreign authority DOES verify when the context
  // authorizes it — the store resolves each (authority_id, generation).
  {
    endpoint::ConfigCommand foreign = make_command(1, 0xB0B);
    ByteBuffer<kCosePermitMax> foreign_body{};
    CHECK_OK(make_permit(foreign, kAuth2.priv, foreign_body));
    ConfigPermitContext ctx = context();
    ctx.authorized_issuer = 0xB0B;
    verified = false;
    CHECK_OK(view.verify_permit(ctx, foreign_body.view(), payload, verified));
    CHECK(verified);
  }
  // Context mismatches: network / target / namespace.
  {
    ByteBuffer<kCosePermitMax> good{};
    CHECK_OK(make_permit(command, kAuth1.priv, good));
    ConfigPermitContext ctx = context();
    ctx.target = 0x999;
    verified = true;
    CHECK_OK(view.verify_permit(ctx, good.view(), payload, verified));
    CHECK(!verified);
    ctx = context();
    ctx.network = 8;
    verified = true;
    CHECK_OK(view.verify_permit(ctx, good.view(), payload, verified));
    CHECK(!verified);
    ctx = context();
    ctx.config_namespace = 0x8000;
    verified = true;
    CHECK_OK(view.verify_permit(ctx, good.view(), payload, verified));
    CHECK(!verified);
  }
  // Signature under a different private key than the record names.
  {
    ByteBuffer<kCosePermitMax> wrong_key{};
    CHECK_OK(make_permit(command, kAuth2.priv, wrong_key));
    verified = true;
    CHECK_OK(view.verify_permit(context(), wrong_key.view(), payload,
                                verified));
    CHECK(!verified);
  }
  // Tampered payload byte: the signature no longer covers it.
  {
    ByteBuffer<kCosePermitMax> tampered{};
    CHECK_OK(make_permit(command, kAuth1.priv, tampered));
    tampered.bytes[40] ^= 0x01;
    verified = true;
    CHECK_OK(view.verify_permit(context(), tampered.view(), payload,
                                verified));
    CHECK(!verified);
  }
  // Malformed envelope: an error propagates — never a silent verdict.
  {
    ByteBuffer<kCosePermitMax> malformed{};
    CHECK_OK(make_permit(command, kAuth1.priv, malformed));
    malformed.bytes[0] = 0xD3;  // wrong COSE tag
    verified = true;
    const Status s =
        view.verify_permit(context(), malformed.view(), payload, verified);
    CHECK(s.code == StatusCode::ProtocolError);
    CHECK(!verified);
  }
}

// --- Rotation: live re-resolution and the bounded overlap (§4.6.1/§4.6.2) -------

void test_view_rotation_reresolution() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit_image(single_key_image(1, 1, 1, kAuth1.pub,
                                               TrustKeyStatus::Active)));
  TrustView view(store);
  ByteBuffer<kCosePermitMax> permit1{}, permit2{};
  CHECK_OK(make_permit(make_command(1), kAuth1.priv, permit1));
  CHECK_OK(make_permit(make_command(2), kAuth2.priv, permit2));
  endpoint::EncodedConfigCommand payload{};
  bool verified = false;
  CHECK_OK(view.verify_permit(context(), permit1.view(), payload, verified));
  CHECK(verified);
  verified = true;
  CHECK_OK(view.verify_permit(context(2), permit2.view(), payload, verified));
  CHECK(!verified);  // generation 2 unknown before rotation

  // §4.6.1 e+2: gen 2 staged -> active while gen 1 stays active — the
  // bounded overlap window verifies BOTH generations. Note the context's
  // configured generation pin stays 1: the store's record status + floor
  // is the verifier-level policy (§4.6.2), the journal's configured pin
  // applies downstream at decision time.
  TrustImage overlap = view_image(2, 1);
  overlap.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Active);
  overlap.keys[1] =
      test_key_record(kAuthorityId, 2, kAuth2.pub, TrustKeyStatus::Active);
  overlap.key_count = 2;
  CHECK_OK(store.commit_image(overlap));
  CHECK(view.store_epoch() == 2);  // re-resolution is live, never cached
  verified = false;
  CHECK_OK(view.verify_permit(context(), permit1.view(), payload, verified));
  CHECK(verified);
  verified = false;
  CHECK_OK(view.verify_permit(context(1), permit2.view(), payload, verified));
  CHECK(verified);

  // §4.6.1 e+3: gen 1 retired + floor advanced — the old key dies.
  TrustImage cutover = view_image(3, 2);
  cutover.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Retired);
  cutover.keys[1] =
      test_key_record(kAuthorityId, 2, kAuth2.pub, TrustKeyStatus::Active);
  cutover.key_count = 2;
  CHECK_OK(store.commit_image(cutover));
  CHECK(view.store_epoch() == 3);
  verified = true;
  CHECK_OK(view.verify_permit(context(), permit1.view(), payload, verified));
  CHECK(!verified);  // retired AND below floor
  verified = false;
  CHECK_OK(view.verify_permit(context(2), permit2.view(), payload, verified));
  CHECK(verified);
}

// --- Device-credential revocation query (§4.7.1 R2) ------------------------------

void test_view_credential_revocation() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  TrustImage image = view_image(1, 1);
  image.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Active);
  image.key_count = 1;
  Digest256 revoked_kid{};
  revoked_kid[0] = 0xEE;
  image.revocations[0] = test_revocation(0x500, revoked_kid, 1);
  image.revocation_count = 1;
  CHECK_OK(store.commit_image(image));
  TrustView view(store);
  CHECK(view.is_credential_revoked(revoked_kid));
  Digest256 other_kid{};
  other_kid[0] = 0xEF;
  CHECK(!view.is_credential_revoked(other_kid));

  // The revocation set replaces wholesale at the next epoch (§4.5.2): an
  // image without the entry lifts it.
  TrustImage lifted = view_image(2, 1);
  lifted.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Active);
  lifted.key_count = 1;
  CHECK_OK(store.commit_image(lifted));
  CHECK(!view.is_credential_revoked(revoked_kid));
}

// --- Impairment posture: quarantine / uncertain fail closed (§4.3.1/§4.7) --------

void test_view_quarantine_fails_closed() {
  FaultyTrustStorage storage;
  fill_both_slots(storage, 2);
  // Both committed slots CRC-damaged -> SECURITY_RECOVERY_REQUIRED
  // quarantine: the verifier reports not-ready and fails closed.
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  TrustStore store(storage);
  CHECK(store.initialize().code == StatusCode::IntegrityError);
  CHECK(store.quarantined());
  TrustView view(store);
  CHECK(view.quarantined());
  CHECK(!view.usable() && !view.ready());
  CHECK(view.store_epoch() == 0);
  CHECK(view.resolve_authority_key(kAuthorityId, 1) == nullptr);
  CHECK(view.is_credential_revoked(Digest256{}));  // proves nothing: revoked

  ByteBuffer<kCosePermitMax> permit{};
  CHECK_OK(make_permit(make_command(1), kAuth1.priv, permit));
  endpoint::EncodedConfigCommand payload{};
  bool verified = true;
  const Status s = view.verify_permit(context(), permit.view(), payload,
                                      verified);
  CHECK(s.code == StatusCode::IntegrityError);
  CHECK(!verified);
}

void test_view_uncertain_fails_closed() {
  FaultyTrustStorage storage;
  {
    // A new/old split: the older committed image survives in slot 0
    // while slot 1 carries a damaged-but-committed newer record (the
    // shape an interrupted twin commit leaves behind).
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(single_key_image(1, 1, 1, kAuth1.pub,
                                                 TrustKeyStatus::Active)));
    ByteBuffer<kTrustStoreSlotBytes> record{};
    CHECK_OK(trust_image_encode(
        single_key_image(2, 1, 2, kAuth2.pub, TrustKeyStatus::Active),
        kTrustSealCommittedWire, record));
    CHECK_OK(storage.write(1, record.view()));
  }
  // The NEWER slot is damaged-but-committed: the surviving image is a
  // "known value" whose sibling may have carried a revocation or floor
  // advance — epoch_floor 2 proves the active epoch-1 image is stale.
  storage.corrupt(1, 100);
  TrustStore store(storage);
  CHECK(store.initialize().code == StatusCode::IntegrityError);
  CHECK(store.has_active() && store.uncertain() && !store.quarantined());
  CHECK(store.store_epoch() == 1 && store.epoch_floor() == 2);
  TrustView view(store);
  CHECK(view.uncertain());
  CHECK(!view.usable() && !view.ready());
  CHECK(view.is_credential_revoked(Digest256{}));

  ByteBuffer<kCosePermitMax> permit{};
  CHECK_OK(make_permit(make_command(1), kAuth1.priv, permit));
  endpoint::EncodedConfigCommand payload{};
  bool verified = true;
  const Status s = view.verify_permit(context(), permit.view(), payload,
                                      verified);
  CHECK(s.code == StatusCode::RecoveryRequired);
  CHECK(!verified);
}

// --- Deployment pin (§4.4 "the required key resolves") -----------------------------

void test_view_require_authority() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit_image(single_key_image(1, 1, 1, kAuth1.pub,
                                               TrustKeyStatus::Active)));
  TrustView view(store);
  CHECK(view.ready());  // unpinned: some active key resolves

  // The pin names an authority, never a generation: it is satisfied while
  // ANY active key of that authority resolves at/above the floor.
  TrustView pinned(store);
  pinned.require_authority(kAuthorityId);
  CHECK(pinned.ready());  // gen-1 key active
  TrustView foreign(store);
  foreign.require_authority(kAuthorityId + 1);
  CHECK(!foreign.ready());  // no key of that authority at all

  // Rotation keeps the pinned authority ready across generations: the
  // gen-2 activation below satisfies the same pin without re-pinning.
  TrustImage staged = view_image(2, 1);
  staged.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Active);
  staged.keys[1] =
      test_key_record(kAuthorityId, 2, kAuth2.pub, TrustKeyStatus::Staged);
  staged.key_count = 2;
  CHECK_OK(store.commit_image(staged));
  CHECK(pinned.ready());  // gen-1 still active
  TrustImage active = view_image(3, 1);
  active.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Retired);
  active.keys[1] =
      test_key_record(kAuthorityId, 2, kAuth2.pub, TrustKeyStatus::Active);
  active.key_count = 2;
  CHECK_OK(store.commit_image(active));
  CHECK(pinned.ready());  // served by gen-2 now, same pin
  // Retiring the last active key of the authority un-readies the view.
  TrustImage dark = view_image(4, 1);
  dark.keys[0] =
      test_key_record(kAuthorityId, 1, kAuth1.pub, TrustKeyStatus::Retired);
  dark.keys[1] =
      test_key_record(kAuthorityId, 2, kAuth2.pub, TrustKeyStatus::Retired);
  dark.key_count = 2;
  CHECK_OK(store.commit_image(dark));
  CHECK(!pinned.ready());
  CHECK(!view.ready());  // unpinned too: no active key anywhere
}

}  // namespace

int main() {
  test_view_ready_and_resolution();
  test_view_permit_valid();
  test_view_permit_key_status_denied();
  test_view_generation_floor();
  test_view_permit_binding_denied();
  test_view_rotation_reresolution();
  test_view_credential_revocation();
  test_view_quarantine_fails_closed();
  test_view_uncertain_fails_closed();
  test_view_require_authority();
  if (failures != 0) {
    std::fprintf(stderr, "%d trust-view checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom trust view tests passed");
  return 0;
}
