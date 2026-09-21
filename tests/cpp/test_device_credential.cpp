// Device credential (RLC1) tests: record codec round-trips, the
// kid/keypair/grant field-consistency checks, strict-decode rejections,
// dual-slot commit semantics (no ordinal — both slots take the identical
// record and divergent valid pairs quarantine), power-cut injection and
// the §4.8 epoch-window helper.
// sdk-completion/04-provisioning-lifecycle.md §4.3.2/§4.8.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/crc32.hpp"
#include "routeloom/device_credential.hpp"

#include "test_provisioning.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::FaultyCredentialStorage;
using routeloom_test::TestKeyPair;
using routeloom_test::test_credential;
using routeloom_test::test_grant;
using routeloom_test::test_keypair;
using routeloom_test::patch_record;
using routeloom_test::record_used_len;
using routeloom_test::kCredSealCommittedWire;
using routeloom_test::kCredSealPendingWire;

const TestKeyPair kNodeA = test_keypair(0x55);
const TestKeyPair kNodeB = test_keypair(0x66);
const TestKeyPair kNodeC = test_keypair(0x77);

constexpr std::size_t kUsedLenOffset = 6;
constexpr std::size_t kSchemaOffset = 8;
constexpr std::size_t kSealOffset = 12;
constexpr std::size_t kNodeOffset = 24;
constexpr std::size_t kGrantLenOffset = 38;
constexpr std::size_t kKidOffset = 40;
constexpr std::size_t kPubkeyOffset = 72;
constexpr std::size_t kKeyMaterialOffset = 136;

bool credentials_equal(const DeviceCredential& a, const DeviceCredential& b) {
  return a.network == b.network && a.node_id == b.node_id &&
         a.generation_base_session == b.generation_base_session &&
         a.key_location == b.key_location && a.cred_status == b.cred_status &&
         a.kid == b.kid && a.pubkey == b.pubkey &&
         a.key_material == b.key_material && a.grant.size == b.grant.size &&
         (a.grant.size == 0 ||
          std::memcmp(a.grant.bytes.data(), b.grant.bytes.data(),
                      a.grant.size) == 0);
}

// --- Codec ---------------------------------------------------------------------

void test_cose_key_and_kid() {
  ByteBuffer<80> cose_key{};
  CHECK_OK(credential_cose_key_encode(
      ByteView{kNodeA.pub.data(), kNodeA.pub.size()}, cose_key));
  // a5 01 02 03 26 20 01 21 58 20 <x:32> 22 58 20 <y:32> — 77 bytes.
  CHECK(cose_key.size == 77);
  const std::array<std::uint8_t, 10> head{{0xA5, 0x01, 0x02, 0x03, 0x26,
                                         0x20, 0x01, 0x21, 0x58, 0x20}};
  CHECK(std::memcmp(cose_key.bytes.data(), head.data(), head.size()) == 0);
  CHECK(std::memcmp(cose_key.bytes.data() + 10, kNodeA.pub.data(), 32) == 0);
  CHECK(cose_key.bytes[42] == 0x22 && cose_key.bytes[43] == 0x58 &&
        cose_key.bytes[44] == 0x20);
  CHECK(std::memcmp(cose_key.bytes.data() + 45, kNodeA.pub.data() + 32, 32) ==
        0);
  // Wrong-size input is refused (into a scratch buffer — encode clears the
  // output on failure).
  ByteBuffer<80> scratch{};
  CHECK(!credential_cose_key_encode(ByteView{kNodeA.pub.data(), 32}, scratch)
             .ok());
  // kid = SHA-256 over the canonical COSE_Key — deterministic.
  Digest256 kid{}, again{};
  CHECK_OK(credential_kid(ByteView{kNodeA.pub.data(), 64}, kid));
  ScopeDigest expected{};
  sha256(cose_key.view(), expected);
  CHECK(kid == expected);
  CHECK_OK(credential_kid(ByteView{kNodeA.pub.data(), 64}, again));
  CHECK(again == kid);
  Digest256 other{};
  CHECK_OK(credential_kid(ByteView{kNodeB.pub.data(), 64}, other));
  CHECK(other != kid);
}

void test_credential_validate() {
  DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  CHECK_OK(credential_validate(credential));

  // Identity fields.
  credential.network = 0;
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);
  credential = test_credential(7, 0xC3, kNodeA);
  credential.node_id = kInvalidNodeId;
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);
  credential.node_id = kBroadcastNodeId;
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);

  // Out-of-range enum fields.
  credential = test_credential(7, 0xC3, kNodeA);
  credential.key_location = static_cast<CredentialKeyLocation>(4);
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);
  credential = test_credential(7, 0xC3, kNodeA);
  credential.cred_status = static_cast<CredentialStatus>(9);
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);

  // kid must equal SHA-256(canonical COSE_Key(pubkey)).
  credential = test_credential(7, 0xC3, kNodeA);
  credential.kid[0] ^= 0xFF;
  CHECK(credential_validate(credential).code == StatusCode::IntegrityError);
  // Off-curve pubkey.
  credential = test_credential(7, 0xC3, kNodeA);
  credential.pubkey.fill(0x55);
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);
  // A different node's on-curve pubkey mismatches the recorded kid.
  credential = test_credential(7, 0xC3, kNodeA);
  credential.pubkey = kNodeB.pub;
  CHECK(credential_validate(credential).code == StatusCode::IntegrityError);
}

void test_credential_key_locations() {
  // key_location 0 requires all-zero key material.
  DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  credential.key_location = CredentialKeyLocation::None;
  credential.key_material.fill(0);
  CHECK_OK(credential_validate(credential));
  credential.key_material[3] = 1;
  CHECK(credential_validate(credential).code == StatusCode::InvalidArgument);

  // key_location 1: the private scalar must reproduce the public half.
  credential = test_credential(7, 0xC3, kNodeA);
  CHECK_OK(credential_validate(credential));
  credential.key_material = kNodeB.priv;  // mismatched pair = corruption
  CHECK(credential_validate(credential).code == StatusCode::IntegrityError);

  // key_location >= 2 carries an opaque handle: any bytes are locally
  // unverifiable and therefore acceptable.
  for (const CredentialKeyLocation location :
       {CredentialKeyLocation::EfuseDsBound,
        CredentialKeyLocation::SecureElement}) {
    credential = test_credential(7, 0xC3, kNodeA);
    credential.key_location = location;
    credential.key_material.fill(0x99);
    CHECK_OK(credential_validate(credential));
  }
}

void test_credential_grant_consistency() {
  // A grant whose signed payload names a different node is corruption —
  // field consistency only; the signature itself is not verified here.
  DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  CHECK_OK(credential_validate(credential));

  ByteBuffer<kCredentialGrantMax> foreign_grant{};
  Digest256 kid{};
  CHECK_OK(credential_kid(ByteView{kNodeB.pub.data(), 64}, kid));
  CHECK_OK(test_grant(7, 0xC3, kid, foreign_grant));  // names another kid
  credential.grant = foreign_grant;
  CHECK(credential_validate(credential).code == StatusCode::IntegrityError);

  ByteBuffer<kCredentialGrantMax> wrong_node{};
  CHECK_OK(test_grant(7, 0x99, credential.kid, wrong_node));
  credential.grant = wrong_node;
  CHECK(credential_validate(credential).code == StatusCode::IntegrityError);

  // The grant's network_u32 names the LOW 32 bits of the full NetworkId.
  ByteBuffer<kCredentialGrantMax> wrong_net{};
  CHECK_OK(test_grant(8, 0xC3, credential.kid, wrong_net));
  credential.grant = wrong_net;
  CHECK(credential_validate(credential).code == StatusCode::IntegrityError);
  // Upper deployment-generation bits are not part of the grant's check.
  credential = test_credential(7, 0xC3, kNodeA);
  credential.network = (std::uint64_t{5} << 32U) | 7ULL;
  ByteBuffer<kCredentialGrantMax> low32_grant{};
  CHECK_OK(test_grant(7, 0xC3, credential.kid, low32_grant));
  credential.grant = low32_grant;
  CHECK_OK(credential_validate(credential));

  // Malformed grant bytes are a parse error, not a mismatch.
  credential = test_credential(7, 0xC3, kNodeA);
  credential.grant.bytes[0] = 0xD3;  // tag 19
  CHECK(credential_validate(credential).code == StatusCode::ProtocolError);
  credential = test_credential(7, 0xC3, kNodeA);
  credential.grant.size = 4;  // truncated envelope
  CHECK(credential_validate(credential).code == StatusCode::ProtocolError);
  // No grant at all is a legal pre-registration state.
  credential = test_credential(7, 0xC3, kNodeA, /*with_grant=*/false);
  CHECK_OK(credential_validate(credential));
}

void test_record_encode_decode_roundtrip() {
  // With grant.
  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  ByteBuffer<kCredentialSlotBytes> record{};
  CHECK_OK(credential_record_encode(credential, kCredSealCommittedWire, record));
  CHECK(record.size ==
        kCredentialHeaderSize + kCredentialFixedBody + credential.grant.size + 4);
  CHECK(std::memcmp(record.bytes.data(), "RLC1", 4) == 0);
  CHECK(record.bytes[kSchemaOffset + 3] == 1);
  CHECK(record.bytes[kSealOffset] == 0xC0 && record.bytes[kSealOffset + 3] == 0xE5);
  DeviceCredential decoded{};
  CHECK_OK(credential_record_decode(record.view(), decoded));
  CHECK(credentials_equal(decoded, credential));

  // Grant-free record: minimum size.
  const DeviceCredential bare = test_credential(7, 0xC3, kNodeA, false);
  ByteBuffer<kCredentialSlotBytes> bare_record{};
  CHECK_OK(
      credential_record_encode(bare, kCredSealCommittedWire, bare_record));
  CHECK(bare_record.size == kCredentialHeaderSize + kCredentialFixedBody + 4);
  CHECK_OK(credential_record_decode(bare_record.view(), decoded));
  CHECK(credentials_equal(decoded, bare));

  // Maximum grant: record hits kCredentialRecordMax, inside the slot bound.
  DeviceCredential maxed = test_credential(7, 0xC3, kNodeA);
  maxed.key_location = CredentialKeyLocation::SecureElement;  // opaque handle
  // 40 + 128 + 256 + 4 = 428.
  ByteBuffer<kCredentialGrantMax> big_grant{};
  CHECK_OK(test_grant(7, 0xC3, maxed.kid, big_grant));
  // Pad with a longer signature field is not possible (fixed 64); instead
  // verify the bound arithmetic directly.
  CHECK(kCredentialHeaderSize + kCredentialFixedBody + kCredentialGrantMax + 4 ==
        kCredentialRecordMax);
  CHECK(kCredentialRecordMax <= kCredentialSlotBytes);
  (void)big_grant;

  // Pending seal encodes but never decodes as committed.
  ByteBuffer<kCredentialSlotBytes> pending{};
  CHECK_OK(credential_record_encode(credential, kCredSealPendingWire, pending));
  CHECK(credential_record_decode(pending.view(), decoded).code ==
        StatusCode::ProtocolError);
  // Unknown seal values are refused at encode.
  CHECK(credential_record_encode(credential, 0x77777777U, record).code ==
        StatusCode::InvalidArgument);
}

void test_record_strict_decode_rejections() {
  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  ByteBuffer<kCredentialSlotBytes> base{};
  CHECK_OK(credential_record_encode(credential, kCredSealCommittedWire, base));
  const std::size_t used = base.size;
  DeviceCredential decoded{};

  CHECK(credential_record_decode(ByteView{}, decoded).code ==
        StatusCode::ProtocolError);
  CHECK(credential_record_decode(
            ByteView{base.bytes.data(), kCredentialHeaderSize}, decoded)
            .code == StatusCode::ProtocolError);
  CHECK(credential_record_decode(
            ByteView{base.bytes.data(), kCredentialSlotBytes + 1}, decoded)
            .code == StatusCode::ProtocolError);
  CHECK(credential_record_decode(
            ByteView{base.bytes.data(), used - 2}, decoded)
            .code == StatusCode::ProtocolError);

  auto expect_decode = [&](std::array<std::uint8_t, kCredentialSlotBytes> bytes,
                           const std::size_t size, const StatusCode code,
                           const char* what) {
    const Status status =
        credential_record_decode(ByteView{bytes.data(), size}, decoded);
    if (status.code != code) {
      std::fprintf(stderr, "credential decode %s: got %d (%s), want %d\n",
                   what, static_cast<int>(status.code), status.detail,
                   static_cast<int>(code));
      ++failures;
    }
  };

  {  // bad magic
    auto m = base.bytes;
    m[1] = 'X';
    expect_decode(m, used, StatusCode::ProtocolError, "magic");
  }
  {  // bad format
    auto m = base.bytes;
    m[5] = 7;
    expect_decode(m, used, StatusCode::ProtocolError, "format");
  }
  {  // used_len below the fixed-body floor
    auto m = base.bytes;
    m[kUsedLenOffset] = 0;
    m[kUsedLenOffset + 1] = 40;
    expect_decode(m, used, StatusCode::ProtocolError, "used_len floor");
  }
  {  // pending seal
    ByteBuffer<kCredentialSlotBytes> pending{};
    CHECK_OK(credential_record_encode(credential, kCredSealPendingWire, pending));
    expect_decode(pending.bytes, pending.size, StatusCode::ProtocolError,
                  "pending seal");
  }
  {  // garbage seal
    auto m = base.bytes;
    m[kSealOffset + 2] = 0x12;
    expect_decode(m, used, StatusCode::ProtocolError, "seal value");
  }
  {  // bitrot with stale CRC
    auto m = base.bytes;
    m[kNodeOffset + 7] ^= 0x01;
    expect_decode(m, used, StatusCode::IntegrityError, "crc");
  }
  {  // schema bump, CRC repaired
    auto m = base.bytes;
    patch_record(m, kSchemaOffset + 3, 4);
    expect_decode(m, used, StatusCode::Unsupported, "schema");
  }
  {  // grant_len inconsistent with used_len (CRC repaired — structural)
    auto m = base.bytes;
    patch_record(m, kGrantLenOffset + 1,
                 static_cast<std::uint8_t>(credential.grant.size + 1));
    expect_decode(m, used, StatusCode::ProtocolError, "grant_len");
  }
  {  // kid patched, CRC repaired -> kid recompute mismatch (integrity)
    auto m = base.bytes;
    patch_record(m, kKidOffset, base.bytes[kKidOffset] ^ 0xFF);
    expect_decode(m, used, StatusCode::IntegrityError, "kid mismatch");
  }
  {  // keypair broken, CRC repaired -> private half no longer matches
    auto m = base.bytes;
    patch_record(m, kKeyMaterialOffset, base.bytes[kKeyMaterialOffset] ^ 0x01);
    expect_decode(m, used, StatusCode::IntegrityError, "keypair mismatch");
  }
  {  // off-curve pubkey, CRC repaired -> semantic rejection
    auto m = base.bytes;
    for (std::size_t i = 0; i < 64; ++i) {
      patch_record(m, kPubkeyOffset + i, 0x11);
    }
    expect_decode(m, used, StatusCode::InvalidArgument, "off-curve pubkey");
  }
}

void test_epoch_window() {
  std::uint16_t epoch = 0;
  // session must be strictly greater than the generation base.
  CHECK(credential_epoch_for_session(0, 0, epoch).code ==
        StatusCode::InvalidArgument);
  CHECK(credential_epoch_for_session(500, 500, epoch).code ==
        StatusCode::InvalidArgument);
  CHECK(credential_epoch_for_session(499, 500, epoch).code ==
        StatusCode::InvalidArgument);
  CHECK_OK(credential_epoch_for_session(501, 500, epoch));
  CHECK(epoch == 1);
  CHECK_OK(credential_epoch_for_session(502, 500, epoch));
  CHECK(epoch == 2);
  // Window top: elapsed < 0xFFF0 derives; at the threshold the helper wedges
  // with RecoveryRequired — the documented REPROVISION_REQUIRED state.
  CHECK_OK(credential_epoch_for_session(500 + kCredentialEpochWindowMax - 1,
                                        500, epoch));
  CHECK(epoch == kCredentialEpochWindowMax - 1);
  CHECK(credential_epoch_for_session(500 + kCredentialEpochWindowMax, 500,
                                     epoch)
            .code == StatusCode::RecoveryRequired);
  CHECK(credential_epoch_for_session(500 + 0xFFFFFFU, 500, epoch).code ==
        StatusCode::RecoveryRequired);
  // A generation cutover re-bases the window: the first session after the
  // new base derives epoch 1 again.
  CHECK_OK(credential_epoch_for_session(500 + 0xFFF000U + 1,
                                        500 + 0xFFF000U, epoch));
  CHECK(epoch == 1);
}

// --- Dual-slot store -----------------------------------------------------------

void test_store_fresh_and_commit() {
  FaultyCredentialStorage storage;
  DeviceCredentialStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(!store.has_active() && !store.quarantined() && !store.uncertain());

  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  CHECK_OK(store.commit_record(credential));
  CHECK(store.has_active());
  CHECK(credentials_equal(store.credential(), credential));
  // RLC1 has no ordinal: BOTH slots take the identical record — two phases
  // (pending + seal) per slot, four blob writes total.
  CHECK(storage.write_calls == 4);
  const std::size_t used = record_used_len(storage.slot_bytes(0));
  CHECK(used > 0);
  CHECK(record_used_len(storage.slot_bytes(1)) == used);
  CHECK(std::memcmp(storage.slot_bytes(0).data(), storage.slot_bytes(1).data(),
                    used) == 0);

  DeviceCredentialStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.has_active());
  CHECK(credentials_equal(reboot.credential(), credential));
}

void test_store_commit_state_gates() {
  FaultyCredentialStorage storage;
  DeviceCredentialStore store(storage);
  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  CHECK(store.commit_record(credential).code == StatusCode::InvalidState);
  CHECK(store.recover(credential).code == StatusCode::InvalidState);
  CHECK_OK(store.initialize());
  CHECK(store.recover(credential).code == StatusCode::InvalidState);
  // Invalid records never reach storage.
  DeviceCredential bad = credential;
  bad.kid[0] ^= 0xFF;
  const std::size_t before = storage.write_calls;
  CHECK(store.commit_record(bad).code == StatusCode::IntegrityError);
  CHECK(storage.write_calls == before);
}

void test_store_divergent_valid_quarantine() {
  // Two valid records with different content cannot be ordered — RLC1 has
  // no ordinal — so the pair quarantines instead of guessing which
  // credential an interrupted commit intended.
  FaultyCredentialStorage storage;
  const DeviceCredential a = test_credential(7, 0xC3, kNodeA);
  const DeviceCredential b = test_credential(7, 0xC3, kNodeB);
  ByteBuffer<kCredentialSlotBytes> rec_a{}, rec_b{};
  CHECK_OK(credential_record_encode(a, kCredSealCommittedWire, rec_a));
  CHECK_OK(credential_record_encode(b, kCredSealCommittedWire, rec_b));
  CHECK_OK(storage.write(0, rec_a.view()));
  CHECK_OK(storage.write(1, rec_b.view()));
  DeviceCredentialStore store(storage);
  CHECK(store.initialize().code == StatusCode::IntegrityError);
  CHECK(store.quarantined());
  CHECK(!store.has_active());
  CHECK(store.commit_record(a).code == StatusCode::IntegrityError);
  // Explicit operator recovery attests a complete credential to both slots.
  CHECK_OK(store.recover(b));
  CHECK(!store.quarantined());
  CHECK(credentials_equal(store.credential(), b));
  DeviceCredentialStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(credentials_equal(reboot.credential(), b));
}

void test_store_corrupt_both_quarantine() {
  FaultyCredentialStorage storage;
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(test_credential(7, 0xC3, kNodeA)));
  }
  storage.corrupt(0, 80);   // inside pubkey
  storage.corrupt(1, 80);
  DeviceCredentialStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
  CHECK(reboot.commit_record(test_credential(7, 0xC3, kNodeB)).code ==
        StatusCode::IntegrityError);
  CHECK_OK(reboot.recover(test_credential(7, 0xC3, kNodeB)));
  CHECK(reboot.credential().node_id == 0xC3);
  DeviceCredentialStore again(storage);
  CHECK_OK(again.initialize());
  CHECK(again.credential().kid == test_credential(7, 0xC3, kNodeB).kid);
}

void test_store_corrupt_sibling_uncertain() {
  FaultyCredentialStorage storage;
  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(credential));
  }
  storage.corrupt(1, 60);  // inside kid bytes: CRC fails, fields parse
  DeviceCredentialStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.has_active());
  CHECK(reboot.uncertain());
  CHECK(credentials_equal(reboot.credential(), credential));
  CHECK(reboot.commit_record(test_credential(7, 0xC3, kNodeB)).code ==
        StatusCode::RecoveryRequired);
  CHECK_OK(reboot.recover(test_credential(7, 0xC3, kNodeB)));
  CHECK(!reboot.uncertain());
}

void test_store_pending_discarded() {
  // A torn/pending sibling of a valid record is provably absent — clean
  // adopt with no uncertainty.
  FaultyCredentialStorage storage;
  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(credential));
    // Re-commit a different credential; power dies before slot 0's seal.
    storage.drop_call = storage.write_calls + 1;
    CHECK(!store.commit_record(test_credential(7, 0xC3, kNodeB)));
  }
  DeviceCredentialStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.has_active());
  CHECK(!reboot.uncertain());
  // Slot 1 still holds the OLD committed credential; slot 0 was pending and
  // is discarded — the surviving pair member rules.
  CHECK(credentials_equal(reboot.credential(), credential));
}

void test_store_divergent_after_interrupted_commit() {
  // RLC1's dual write makes this the distinctive hazard: power dies after
  // slot 0's new record sealed but before slot 1 was touched — one new
  // valid record next to one old valid record, different content, no
  // ordinal. Quarantine, not a guess.
  FaultyCredentialStorage storage;
  const DeviceCredential old_cred = test_credential(7, 0xC3, kNodeA);
  const DeviceCredential new_cred = test_credential(7, 0xC3, kNodeB);
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(old_cred));
    storage.drop_call = storage.write_calls + 2;  // slot 1's pending write
    CHECK(!store.commit_record(new_cred));
  }
  DeviceCredentialStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
  CHECK_OK(reboot.recover(new_cred));
  DeviceCredentialStore again(storage);
  CHECK_OK(again.initialize());
  CHECK(credentials_equal(again.credential(), new_cred));
}

void test_store_pending_write_boundaries() {
  // Power cut at every boundary of slot 0's pending write during a
  // re-commit: slot 1 always keeps the old committed record.
  const DeviceCredential old_cred = test_credential(7, 0xC3, kNodeA);
  const DeviceCredential new_cred = test_credential(7, 0xC3, kNodeB);
  ByteBuffer<kCredentialSlotBytes> rec{};
  CHECK_OK(credential_record_encode(new_cred, kCredSealPendingWire, rec));
  const std::size_t used = rec.size;
  for (std::size_t boundary = 0; boundary <= used; ++boundary) {
    FaultyCredentialStorage storage;
    {
      DeviceCredentialStore store(storage);
      CHECK_OK(store.initialize());
      CHECK_OK(store.commit_record(old_cred));
      storage.cut_call = storage.write_calls;  // slot 0 pending write
      storage.cut_bytes = boundary;
      CHECK(store.commit_record(new_cred).code == StatusCode::StorageFailure);
    }
    DeviceCredentialStore reboot(storage);
    const Status loaded = reboot.initialize();
    CHECK(reboot.has_active());
    CHECK(credentials_equal(reboot.credential(), old_cred));
    if (boundary <= 12 || boundary >= 16) {
      // Head fields through byte 11 are identical between the pending and
      // committed records here (same record size), so a cut <= 12 leaves the
      // old committed record byte-intact; a fully rewritten head with a zero
      // seal is discardable pending. Either way: provably absent sibling.
      CHECK_OK(loaded);
      CHECK(!reboot.uncertain());
      CHECK_OK(reboot.commit_record(new_cred));
    } else {
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.uncertain());
      CHECK(reboot.commit_record(new_cred).code ==
            StatusCode::RecoveryRequired);
    }
  }
}

void test_store_seal_write_boundaries() {
  // Cut slot 0's commit-seal write during a re-commit: a full seal landing
  // produces a NEW valid record next to the OLD valid one — divergent valid
  // pairs quarantine because they cannot be ordered.
  const DeviceCredential old_cred = test_credential(7, 0xC3, kNodeA);
  const DeviceCredential new_cred = test_credential(7, 0xC3, kNodeB);
  ByteBuffer<kCredentialSlotBytes> rec{};
  CHECK_OK(credential_record_encode(new_cred, kCredSealCommittedWire, rec));
  const std::size_t used = rec.size;
  for (std::size_t boundary = 0; boundary <= used; ++boundary) {
    FaultyCredentialStorage storage;
    {
      DeviceCredentialStore store(storage);
      CHECK_OK(store.initialize());
      CHECK_OK(store.commit_record(old_cred));
      storage.cut_call = storage.write_calls + 1;  // slot 0 seal write
      storage.cut_bytes = boundary;
      CHECK(store.commit_record(new_cred).code == StatusCode::StorageFailure);
    }
    DeviceCredentialStore reboot(storage);
    const Status loaded = reboot.initialize();
    if (boundary <= 12) {
      // Rewritten bytes identical to the pending record -> still pending.
      CHECK_OK(loaded);
      CHECK(credentials_equal(reboot.credential(), old_cred));
      CHECK(!reboot.uncertain());
    } else if (boundary < used) {
      // Partial seal or committed-head-with-stale-CRC: corrupt sibling.
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.uncertain());
      CHECK(credentials_equal(reboot.credential(), old_cred));
    } else {
      // Full new record sealed next to the old one: two valid records
      // that differ — no ordinal exists to order them -> quarantine.
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.quarantined());
      CHECK(!reboot.has_active());
      CHECK_OK(reboot.recover(new_cred));
    }
  }
}

void test_store_cut_during_second_slot() {
  // Power dies inside slot 1's writes: slot 0 holds the fully committed new
  // record and serves it (known-value uncertain when the sibling is noise).
  FaultyCredentialStorage storage;
  const DeviceCredential old_cred = test_credential(7, 0xC3, kNodeA);
  const DeviceCredential new_cred = test_credential(7, 0xC3, kNodeB);
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(old_cred));
    storage.cut_call = storage.write_calls + 3;  // slot 1 seal write
    storage.cut_bytes = 30;  // torn head -> corrupt
    CHECK(store.commit_record(new_cred).code == StatusCode::StorageFailure);
  }
  DeviceCredentialStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.uncertain());
  CHECK(credentials_equal(reboot.credential(), new_cred));
  CHECK_OK(reboot.recover(new_cred));
}

void test_store_read_errors() {
  FaultyCredentialStorage storage;
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(test_credential(7, 0xC3, kNodeA)));
  }
  storage.read_error = true;
  DeviceCredentialStore unreadable(storage);
  CHECK(unreadable.initialize().code == StatusCode::StorageFailure);
  CHECK(!unreadable.initialized() && !unreadable.quarantined());

  storage.read_error = false;
  storage.read_error_slot = 1;
  DeviceCredentialStore partial(storage);
  CHECK(partial.initialize().code == StatusCode::IntegrityError);
  CHECK(partial.uncertain());
  CHECK(partial.has_active());
}

void test_store_semantically_corrupt_record() {
  // A CRC-intact committed record whose consistency checks fail (kid no
  // longer matches the pubkey) classifies corrupt at boot — never a cue to
  // re-derive a credential.
  FaultyCredentialStorage storage;
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(test_credential(7, 0xC3, kNodeA)));
  }
  patch_record(storage.slot_bytes(0), kKidOffset,
               storage.slot_bytes(0)[kKidOffset] ^ 0xFF);
  patch_record(storage.slot_bytes(1), kKidOffset,
               storage.slot_bytes(1)[kKidOffset] ^ 0xFF);
  DeviceCredentialStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
}

void test_store_first_commit_torn() {
  const DeviceCredential credential = test_credential(7, 0xC3, kNodeA);
  ByteBuffer<kCredentialSlotBytes> rec{};
  CHECK_OK(credential_record_encode(credential, kCredSealPendingWire, rec));
  for (const std::size_t boundary : {std::size_t{0}, std::size_t{8},
                                     std::size_t{15}, std::size_t{16},
                                     std::size_t{80}, rec.size}) {
    FaultyCredentialStorage storage;
    {
      DeviceCredentialStore store(storage);
      CHECK_OK(store.initialize());
      storage.cut_call = 0;  // slot 0 pending write
      storage.cut_bytes = boundary;
      CHECK(!store.commit_record(credential));
    }
    DeviceCredentialStore reboot(storage);
    const Status loaded = reboot.initialize();
    if (boundary == 0 || boundary >= 16) {
      CHECK_OK(loaded);
      CHECK(!reboot.has_active() && !reboot.quarantined());
    } else {
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.quarantined());
    }
  }
}

void test_store_recredential_roundtrip() {
  // Re-credentialing: a second commit replaces both slots; the new record
  // survives reboots and the old credential is gone.
  FaultyCredentialStorage storage;
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(test_credential(7, 0xC3, kNodeA)));
  }
  const DeviceCredential rotated = test_credential(7, 0xC3, kNodeB);
  {
    DeviceCredentialStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_record(rotated));
    CHECK(credentials_equal(store.credential(), rotated));
  }
  DeviceCredentialStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(credentials_equal(reboot.credential(), rotated));
  // generation_base_session persists — the §4.8 window origin.
  CHECK(reboot.credential().generation_base_session == 500);
}

}  // namespace

int main() {
  test_cose_key_and_kid();
  test_credential_validate();
  test_credential_key_locations();
  test_credential_grant_consistency();
  test_record_encode_decode_roundtrip();
  test_record_strict_decode_rejections();
  test_epoch_window();
  test_store_fresh_and_commit();
  test_store_commit_state_gates();
  test_store_divergent_valid_quarantine();
  test_store_corrupt_both_quarantine();
  test_store_corrupt_sibling_uncertain();
  test_store_pending_discarded();
  test_store_divergent_after_interrupted_commit();
  test_store_pending_write_boundaries();
  test_store_seal_write_boundaries();
  test_store_cut_during_second_slot();
  test_store_read_errors();
  test_store_semantically_corrupt_record();
  test_store_first_commit_torn();
  test_store_recredential_roundtrip();
  if (failures != 0) {
    std::fprintf(stderr, "%d credential checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom device credential tests passed");
  return 0;
}
