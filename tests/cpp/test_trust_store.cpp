// Trust store (RLT1) tests: record codec round-trips and strict-decode
// rejections, the dual-slot seal/write/readback/commit state machine under
// byte-granular power-cut injection, epoch/generation floor enforcement
// (including floors proven by CRC-failed committed records), quarantine and
// the explicit recover() path. sdk-completion/04-provisioning-lifecycle.md
// §4.3.1/§4.5.1.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/crc32.hpp"
#include "routeloom/trust_store.hpp"

#include "test_provisioning.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::FaultyTrustStorage;
using routeloom_test::TestKeyPair;
using routeloom_test::test_anchor;
using routeloom_test::test_image;
using routeloom_test::test_key_record;
using routeloom_test::test_keypair;
using routeloom_test::test_revocation;
using routeloom_test::patch_record;
using routeloom_test::record_used_len;
using routeloom_test::kTrustSealCommittedWire;
using routeloom_test::kTrustSealPendingWire;

const TestKeyPair kRootA = test_keypair(0x11);
const TestKeyPair kRootB = test_keypair(0x22);
const TestKeyPair kAuth1 = test_keypair(0x33);
const TestKeyPair kAuth2 = test_keypair(0x44);

constexpr std::size_t kUsedLenOffset = 6;
constexpr std::size_t kSchemaOffset = 8;
constexpr std::size_t kSealOffset = 12;
constexpr std::size_t kEpochOffset = 16;
constexpr std::size_t kFlagsOffset = 40;
constexpr std::size_t kAnchorCountOffset = 41;
constexpr std::size_t kAnchorTable = 48;
constexpr std::size_t kAnchorStatusOffset = kAnchorTable + 72;

bool images_equal(const TrustImage& a, const TrustImage& b) {
  if (a.store_epoch != b.store_epoch ||
      a.min_authority_generation != b.min_authority_generation ||
      a.network != b.network || a.deployment_id != b.deployment_id ||
      a.flags != b.flags || a.anchor_count != b.anchor_count ||
      a.key_count != b.key_count || a.revocation_count != b.revocation_count) {
    return false;
  }
  for (std::uint8_t i = 0; i < a.anchor_count; ++i) {
    if (a.anchors[i].root_id != b.anchors[i].root_id ||
        a.anchors[i].pubkey != b.anchors[i].pubkey ||
        a.anchors[i].status != b.anchors[i].status) {
      return false;
    }
  }
  for (std::uint8_t i = 0; i < a.key_count; ++i) {
    const TrustKeyRecord& x = a.keys[i];
    const TrustKeyRecord& y = b.keys[i];
    if (x.authority_id != y.authority_id || x.generation != y.generation ||
        x.profile != y.profile || x.role != y.role || x.status != y.status ||
        x.scope != y.scope || x.pubkey != y.pubkey) {
      return false;
    }
  }
  for (std::uint8_t i = 0; i < a.revocation_count; ++i) {
    const TrustRevocation& x = a.revocations[i];
    const TrustRevocation& y = b.revocations[i];
    if (x.node_id != y.node_id || x.kid_fingerprint != y.kid_fingerprint ||
        x.revoked_at_epoch != y.revoked_at_epoch || x.kind != y.kind) {
      return false;
    }
  }
  return true;
}

TrustImage full_image(const std::uint32_t epoch, const NetworkId network) {
  TrustImage image = test_image(epoch, network, kRootA, 0x100);
  image.flags = kTrustFlagProvisioningConsoleLocked |
                kTrustFlagRequiresProductionProfile;
  image.anchors[1] = test_anchor(0x200, kRootB.pub, TrustAnchorStatus::Disabled);
  image.anchor_count = 2;
  for (std::uint8_t i = 0; i < kTrustKeyMax; ++i) {
    image.keys[i] = test_key_record(0xA17 + i, i + 1,
                                    (i % 2 == 0) ? kAuth1.pub : kAuth2.pub,
                                    i == 0 ? TrustKeyStatus::Active
                                           : TrustKeyStatus::Staged);
  }
  image.key_count = kTrustKeyMax;
  for (std::uint8_t i = 0; i < kTrustRevocationMax; ++i) {
    Digest256 kid{};
    kid[0] = static_cast<std::uint8_t>(i + 1);
    kid[31] = 0xAB;
    image.revocations[i] = test_revocation(0x500 + i, kid, epoch);
  }
  image.revocation_count = kTrustRevocationMax;
  return image;
}

// --- Codec ---------------------------------------------------------------------

void test_rlt1_encode_decode_roundtrip() {
  // Minimal image: one active anchor, no keys, no revocations.
  const TrustImage minimal = test_image(1, 7, kRootA);
  ByteBuffer<kTrustStoreSlotBytes> record{};
  CHECK_OK(trust_image_encode(minimal, kTrustSealCommittedWire, record));
  CHECK(record.size == kTrustImageHeaderSize + kTrustAnchorEntrySize + 4);
  // Header fields are byte-exact per §4.3.1.
  CHECK(std::memcmp(record.bytes.data(), "RLT1", 4) == 0);
  CHECK(record.bytes[4] == 0 && record.bytes[5] == 1);            // format
  CHECK(record.bytes[kUsedLenOffset] == 0 &&
        record.bytes[kUsedLenOffset + 1] == record.size);
  CHECK(record.bytes[kSchemaOffset + 3] == 1);                    // schema
  CHECK(record.bytes[kSealOffset] == 0x7A &&                      // seal
        record.bytes[kSealOffset + 3] == 0xE2);
  TrustImage decoded{};
  CHECK_OK(trust_image_decode(record.view(), decoded));
  CHECK(images_equal(decoded, minimal));

  // Pending seal encodes but never decodes as committed state.
  ByteBuffer<kTrustStoreSlotBytes> pending{};
  CHECK_OK(trust_image_encode(minimal, kTrustSealPendingWire, pending));
  CHECK(trust_image_decode(pending.view(), decoded).code ==
        StatusCode::ProtocolError);
}

void test_rlt1_encode_decode_max_image() {
  const TrustImage maximal = full_image(9, 0xAABBCCDD);
  CHECK(trust_image_encoded_size(maximal) == kTrustImageMax);
  CHECK(kTrustImageMax == 48 + 2 * 80 + 4 * 80 + 24 * 48 + 4);
  CHECK(kTrustImageMax <= kTrustStoreSlotBytes);
  ByteBuffer<kTrustStoreSlotBytes> record{};
  CHECK_OK(trust_image_encode(maximal, kTrustSealCommittedWire, record));
  CHECK(record.size == kTrustImageMax);
  TrustImage decoded{};
  CHECK_OK(trust_image_decode(record.view(), decoded));
  CHECK(images_equal(decoded, maximal));
}

void test_rlt1_body_codec_matches_record() {
  // The RTM1 signed content is RLT1 bytes [16, used_len-4): the body codec
  // must produce byte-for-byte that slice of the storage record.
  const TrustImage image = full_image(3, 55);
  ByteBuffer<kTrustStoreSlotBytes> record{};
  CHECK_OK(trust_image_encode(image, kTrustSealCommittedWire, record));
  ByteBuffer<kTrustImageContentMax> body{};
  CHECK_OK(trust_image_body_encode(image, body));
  CHECK(body.size == record.size - 20);
  CHECK(std::memcmp(body.bytes.data(), record.bytes.data() + 16,
                    body.size) == 0);
  TrustImage decoded{};
  CHECK_OK(trust_image_body_decode(body.view(), decoded));
  CHECK(images_equal(decoded, image));
  CHECK_OK(trust_image_validate(decoded));
}

void test_rlt1_strict_decode_rejections() {
  const TrustImage image = test_image(4, 7, kRootA);
  TrustImage decoded{};

  // Bound checks: null, undersized head, oversized view.
  CHECK(trust_image_decode(ByteView{}, decoded).code == StatusCode::ProtocolError);
  {
    ByteBuffer<kTrustStoreSlotBytes> record{};
    CHECK_OK(trust_image_encode(image, kTrustSealCommittedWire, record));
    CHECK(trust_image_decode(
              ByteView{record.bytes.data(), kTrustImageHeaderSize + 3},
              decoded)
              .code == StatusCode::ProtocolError);
    CHECK(trust_image_decode(ByteView{record.bytes.data(),
                                      kTrustStoreSlotBytes + 1},
                             decoded)
              .code == StatusCode::ProtocolError);
    // A view shorter than the declared used_len is truncated, not decoded.
    CHECK(trust_image_decode(ByteView{record.bytes.data(), record.size - 5},
                             decoded)
              .code == StatusCode::ProtocolError);
  }

  auto expect_decode = [&](std::array<std::uint8_t, kTrustStoreSlotBytes> bytes,
                           const std::size_t size, const StatusCode code,
                           const char* what) {
    const Status status =
        trust_image_decode(ByteView{bytes.data(), size}, decoded);
    if (status.code != code) {
      std::fprintf(stderr, "decode %s: got %d (%s), want %d\n", what,
                   static_cast<int>(status.code), status.detail,
                   static_cast<int>(code));
      ++failures;
    }
  };

  ByteBuffer<kTrustStoreSlotBytes> base{};
  CHECK_OK(trust_image_encode(image, kTrustSealCommittedWire, base));
  const std::size_t used = base.size;

  // Bad magic.
  {
    auto m = base.bytes;
    m[0] = 'X';
    expect_decode(m, used, StatusCode::ProtocolError, "magic");
  }
  // Bad format version.
  {
    auto m = base.bytes;
    m[5] = 2;
    expect_decode(m, used, StatusCode::ProtocolError, "format");
  }
  // used_len below the header floor.
  {
    auto m = base.bytes;
    m[kUsedLenOffset] = 0;
    m[kUsedLenOffset + 1] = 20;
    expect_decode(m, used, StatusCode::ProtocolError, "used_len floor");
  }
  // Seal neither pending nor committed.
  {
    auto m = base.bytes;
    m[kSealOffset + 3] = 0x11;
    expect_decode(m, used, StatusCode::ProtocolError, "seal value");
  }
  // Pending seal.
  {
    ByteBuffer<kTrustStoreSlotBytes> pending{};
    CHECK_OK(trust_image_encode(image, kTrustSealPendingWire, pending));
    expect_decode(pending.bytes, pending.size, StatusCode::ProtocolError,
                  "pending seal");
  }
  // Body bitrot with stale CRC -> integrity failure.
  {
    auto m = base.bytes;
    m[kEpochOffset + 3] ^= 0xFF;
    expect_decode(m, used, StatusCode::IntegrityError, "crc");
  }
  // Schema bump with a repaired CRC decodes structurally but is Unsupported.
  {
    auto m = base.bytes;
    patch_record(m, kSchemaOffset + 3, 2);
    expect_decode(m, used, StatusCode::Unsupported, "schema");
  }
  // Count beyond the table cap (CRC repaired — a structural violation).
  {
    auto m = base.bytes;
    patch_record(m, kAnchorCountOffset, kTrustAnchorMax + 1);
    expect_decode(m, used, StatusCode::ProtocolError, "anchor count");
  }
  // Reserved flags bit set (CRC repaired).
  {
    auto m = base.bytes;
    patch_record(m, kFlagsOffset, 0x08);
    expect_decode(m, used, StatusCode::ProtocolError, "flags");
  }
  // Anchor status outside the enum (CRC repaired).
  {
    auto m = base.bytes;
    patch_record(m, kAnchorStatusOffset, 9);
    expect_decode(m, used, StatusCode::ProtocolError, "anchor status");
  }
  // Declared length disagrees with the entry tables (CRC repaired at the
  // new boundary so the record is internally consistent but mis-sized).
  {
    auto m = base.bytes;
    patch_record(m, kUsedLenOffset + 1, static_cast<std::uint8_t>(used + 8));
    expect_decode(m, used + 8, StatusCode::ProtocolError, "length drift");
  }
  // CRC-valid but semantically invalid: patched anchor pubkey is off curve.
  {
    auto m = base.bytes;
    patch_record(m, kAnchorTable + 8, 0xFF);  // first pubkey byte
    // That single-bit edit can stay on-curve in principle; force a clearly
    // invalid point by zeroing the whole X coordinate.
    for (std::size_t i = 0; i < 32; ++i) {
      patch_record(m, kAnchorTable + 8 + i, 0);
    }
    expect_decode(m, used, StatusCode::InvalidArgument, "off-curve anchor");
  }
  // Body codec: any trailing byte is a strict rejection (§4.5.1 rule 2).
  {
    ByteBuffer<kTrustImageContentMax> body{};
    CHECK_OK(trust_image_body_encode(image, body));
    body.bytes[body.size] = 0x00;
    CHECK(trust_image_body_decode(
              ByteView{body.bytes.data(), body.size + 1}, decoded)
              .code == StatusCode::ProtocolError);
    CHECK(trust_image_body_decode(
              ByteView{body.bytes.data(), body.size - 1}, decoded)
              .code == StatusCode::ProtocolError);
    CHECK(trust_image_body_decode(ByteView{body.bytes.data(), 20}, decoded)
              .code == StatusCode::ProtocolError);
  }
}

void test_rlt1_encode_validation() {
  // encode() validates first — no path persists a store boot would reject.
  ByteBuffer<kTrustStoreSlotBytes> record{};
  TrustImage image = test_image(1, 7, kRootA);

  image.store_epoch = 0;
  CHECK(trust_image_encode(image, kTrustSealCommittedWire, record).code ==
        StatusCode::InvalidArgument);
  image = test_image(1, 7, kRootA);
  image.network = 0;
  CHECK(trust_image_encode(image, kTrustSealCommittedWire, record).code ==
        StatusCode::InvalidArgument);
  image = test_image(1, 7, kRootA);
  image.anchor_count = 0;
  CHECK(trust_image_encode(image, kTrustSealCommittedWire, record).code ==
        StatusCode::InvalidArgument);
  image = test_image(1, 7, kRootA);
  image.flags = 0x10;
  CHECK(trust_image_encode(image, kTrustSealCommittedWire, record).code ==
        StatusCode::InvalidArgument);
  // Unknown seal values are rejected even for valid images.
  image = test_image(1, 7, kRootA);
  CHECK(trust_image_encode(image, 0x11111111U, record).code ==
        StatusCode::InvalidArgument);
  // Over-cap counts cannot be encoded at all.
  image.revocation_count = kTrustRevocationMax + 1;
  CHECK(trust_image_encoded_size(image) == 0);
  CHECK(trust_image_encode(image, kTrustSealCommittedWire, record).code ==
        StatusCode::InvalidArgument);
  image = test_image(1, 7, kRootA);
  image.anchor_count = kTrustAnchorMax + 1;
  CHECK(trust_image_encoded_size(image) == 0);
}

void test_rlt1_semantic_validation() {
  // Every trust_image_validate clause gets a dedicated rejection.
  TrustImage image = test_image(1, 7, kRootA);
  CHECK_OK(trust_image_validate(image));

  // Off-curve anchor pubkey.
  image = test_image(1, 7, kRootA);
  image.anchors[0].pubkey.fill(0xAB);
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  // Duplicate root_id across anchors.
  image = test_image(1, 7, kRootA);
  image.anchors[1] = test_anchor(0x100, kRootB.pub);
  image.anchor_count = 2;
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  // Two anchors, all disabled -> no active anchor to sign with.
  image = test_image(1, 7, kRootA);
  image.anchors[0].status = TrustAnchorStatus::Disabled;
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  // Disabled anchor retained for inventory alongside an active one is legal.
  image = test_image(1, 7, kRootA);
  image.anchors[1] = test_anchor(0x200, kRootB.pub, TrustAnchorStatus::Disabled);
  image.anchor_count = 2;
  CHECK_OK(trust_image_validate(image));
  // Key record identity fields.
  image = test_image(1, 7, kRootA);
  image.keys[0] = test_key_record(0, 1, kAuth1.pub);
  image.key_count = 1;
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  image.keys[0].authority_id = kBroadcastNodeId;
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  image.keys[0] = test_key_record(0xA17, 0, kAuth1.pub);
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  // Duplicate (authority_id, generation).
  image.keys[0] = test_key_record(0xA17, 3, kAuth1.pub);
  image.keys[1] = test_key_record(0xA17, 3, kAuth2.pub);
  image.key_count = 2;
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  // Same authority_id under a different generation is the rotation shape.
  image.keys[1] = test_key_record(0xA17, 4, kAuth2.pub);
  CHECK_OK(trust_image_validate(image));
  // Retired/revoked key records are legal inventory.
  image.keys[1].status = TrustKeyStatus::Revoked;
  CHECK_OK(trust_image_validate(image));
  // Off-curve key pubkey.
  image.keys[1].pubkey.fill(0x01);
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  // Revocation identity fields.
  image = test_image(1, 7, kRootA);
  Digest256 kid{};
  kid[5] = 9;
  image.revocations[0] = test_revocation(kInvalidNodeId, kid, 1);
  image.revocation_count = 1;
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  image.revocations[0] = test_revocation(kBroadcastNodeId, kid, 1);
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  image.revocations[0] = test_revocation(7, Digest256{}, 1);
  CHECK(trust_image_validate(image).code == StatusCode::InvalidArgument);
  image.revocations[0] = test_revocation(7, kid, 1);
  CHECK_OK(trust_image_validate(image));
}

void test_rlt1_fingerprint() {
  const TrustImage image = test_image(2, 7, kRootA);
  ByteBuffer<kTrustStoreSlotBytes> record{};
  CHECK_OK(trust_image_encode(image, kTrustSealCommittedWire, record));
  Digest256 fingerprint{};
  CHECK_OK(trust_image_fingerprint(record.view(), fingerprint));
  Digest256 zero{};
  CHECK(fingerprint != zero);
  Digest256 again{};
  CHECK_OK(trust_image_fingerprint(record.view(), again));
  CHECK(again == fingerprint);
  // Fingerprints differ across images.
  ByteBuffer<kTrustStoreSlotBytes> other{};
  CHECK_OK(trust_image_encode(test_image(3, 7, kRootA),
                              kTrustSealCommittedWire, other));
  CHECK_OK(trust_image_fingerprint(other.view(), again));
  CHECK(again != fingerprint);
}

// --- Dual-slot store -------------------------------------------------------------

void test_store_fresh_and_commit() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(store.initialized());
  CHECK(!store.has_active());
  CHECK(!store.quarantined() && !store.uncertain());
  CHECK(store.store_epoch() == 0 && store.epoch_floor() == 0);

  // First install lands in slot 0; slot 1 stays erased.
  const TrustImage first = test_image(1, 7, kRootA);
  CHECK_OK(store.commit_image(first));
  CHECK(store.has_active());
  CHECK(store.store_epoch() == 1);
  CHECK(store.epoch_floor() == 1);
  CHECK(store.generation_floor() == 1);
  CHECK(store.network() == 7);
  CHECK(store.deployment_id() == 0xDE9UL);
  CHECK(storage.write_calls == 2);  // pending + commit seal, one slot
  CHECK(storage.slot_bytes(1)[0] == 0xFF && storage.slot_bytes(1)[1] == 0xFF);
  Digest256 zero{};
  CHECK(store.image_fingerprint() != zero);

  // Second commit alternates into slot 1.
  const TrustImage second = test_image(2, 7, kRootA);
  CHECK_OK(store.commit_image(second));
  CHECK(store.store_epoch() == 2);
  CHECK(storage.write_calls == 4);
  CHECK(record_used_len(storage.slot_bytes(1)) > 0);

  // Reboot adopts the newest committed image.
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.store_epoch() == 2);
  CHECK(reboot.epoch_floor() == 2);
  CHECK(images_equal(reboot.image(), second));
  CHECK(!reboot.uncertain());

  // Third commit returns to slot 0.
  CHECK_OK(reboot.commit_image(test_image(3, 7, kRootA)));
  CHECK(reboot.image().store_epoch == 3);
}

void test_store_epoch_and_generation_floors() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  // The first commit may pick any nonzero epoch (ordinal, starts at 1 is a
  // convention; the floor only requires strictly-greater afterwards).
  TrustImage image = test_image(7, 7, kRootA);
  image.min_authority_generation = 3;
  CHECK_OK(store.commit_image(image));
  CHECK(store.commit_image(test_image(7, 7, kRootA)).code ==
        StatusCode::Conflict);
  CHECK(store.commit_image(test_image(6, 7, kRootA)).code ==
        StatusCode::Conflict);
  // The min_authority_generation floor never regresses.
  TrustImage regressed = test_image(8, 7, kRootA);
  regressed.min_authority_generation = 2;
  CHECK(store.commit_image(regressed).code == StatusCode::AuthorizationFailed);
  // Equal floor is legal; a raise lands and binds forward.
  TrustImage next = test_image(8, 7, kRootA);
  next.min_authority_generation = 5;
  CHECK_OK(store.commit_image(next));
  CHECK(store.generation_floor() == 5);
  next = test_image(9, 7, kRootA);
  next.min_authority_generation = 4;
  CHECK(store.commit_image(next).code == StatusCode::AuthorizationFailed);
}

void test_store_commit_state_gates() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  // Not initialized.
  CHECK(store.commit_image(test_image(1, 7, kRootA)).code ==
        StatusCode::InvalidState);
  CHECK(store.recover(test_image(1, 7, kRootA)).code ==
        StatusCode::InvalidState);
  CHECK_OK(store.initialize());
  // recover() on a healthy store is not a commit path.
  CHECK(store.recover(test_image(1, 7, kRootA)).code ==
        StatusCode::InvalidState);
  // Semantically invalid images are refused before any slot is touched.
  TrustImage invalid = test_image(1, 7, kRootA);
  invalid.anchor_count = 0;
  const std::size_t before = storage.write_calls;
  CHECK(store.commit_image(invalid).code == StatusCode::InvalidArgument);
  CHECK(storage.write_calls == before);
}

void test_store_corrupt_sibling_uncertain() {
  // One valid slot serves ("known value") while a corrupt sibling marks the
  // store uncertain: commits refuse until recover(), and the corrupt slot's
  // committed fields still bound the epoch floor (§4.3.1).
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    CHECK_OK(store.commit_image(test_image(2, 7, kRootA)));  // lands in slot 1
  }
  // Offset 100 is inside the anchor pubkey: the record stays structurally
  // intact (committed_fields bound the floors) but its CRC fails.
  storage.corrupt(1, 100);
  TrustStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.has_active());
  CHECK(reboot.uncertain());
  CHECK(!reboot.quarantined());
  CHECK(reboot.store_epoch() == 1);         // slot 0's image still serves
  CHECK(reboot.epoch_floor() == 2);         // corrupt-but-committed bound it
  CHECK(reboot.commit_image(test_image(3, 7, kRootA)).code ==
        StatusCode::RecoveryRequired);
  // recover() must clear every epoch a committed record proved — including
  // the CRC-failed one — or a pre-loss image could replay.
  CHECK(reboot.recover(test_image(2, 7, kRootA)).code ==
        StatusCode::InvalidArgument);
  CHECK_OK(reboot.recover(test_image(3, 7, kRootA)));
  CHECK(!reboot.uncertain() && !reboot.quarantined());
  CHECK(reboot.store_epoch() == 3);
  // The twin pair boots clean and commits resume.
  TrustStore again(storage);
  CHECK_OK(again.initialize());
  CHECK(again.store_epoch() == 3);
  CHECK_OK(again.commit_image(test_image(4, 7, kRootA)));
}

void test_store_corrupt_both_quarantine() {
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    CHECK_OK(store.commit_image(test_image(2, 7, kRootA)));
  }
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  TrustStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
  CHECK(!reboot.has_active());
  CHECK(reboot.store_epoch() == 0);
  // Quarantine is terminal for the write path — never an implicit reset.
  CHECK(reboot.commit_image(test_image(3, 7, kRootA)).code ==
        StatusCode::IntegrityError);
  // The corrupt committed records still bound recovery: epoch 2 is proven.
  CHECK(reboot.epoch_floor() == 2);
  CHECK(reboot.recover(test_image(2, 7, kRootA)).code ==
        StatusCode::InvalidArgument);
  CHECK(reboot.recover(test_image(1, 7, kRootA)).code ==
        StatusCode::InvalidArgument);
  CHECK_OK(reboot.recover(test_image(3, 7, kRootA)));
  CHECK(!reboot.quarantined());
  CHECK(reboot.store_epoch() == 3);
  // recover() writes the twin pair: both slots hold the identical image.
  TrustStore again(storage);
  CHECK_OK(again.initialize());
  CHECK(again.store_epoch() == 3);
  CHECK(!again.uncertain());
}

void test_store_pending_slot_discarded() {
  // A pending record (seal never landed) is provably discardable: the
  // surviving committed image adopts cleanly with no uncertainty.
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    // Pending body lands; power dies before the commit-marker write.
    storage.drop_call = storage.write_calls + 1;
    CHECK(store.commit_image(test_image(2, 7, kRootA)).code ==
          StatusCode::StorageFailure);
  }
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.store_epoch() == 1);
  CHECK(!reboot.uncertain());
  CHECK_OK(reboot.commit_image(test_image(2, 7, kRootA)));  // retry lands
  CHECK(reboot.store_epoch() == 2);
}

void test_store_pending_only_is_fresh() {
  // All-empty or pending-only is pre-provisioning, not an impairment.
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    storage.cut_call = storage.write_calls;
    storage.cut_bytes = 64;  // complete head incl. pending seal, partial body
    CHECK(!store.commit_image(test_image(1, 7, kRootA)));
  }
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(!reboot.has_active() && !reboot.quarantined() && !reboot.uncertain());
  CHECK_OK(reboot.commit_image(test_image(1, 7, kRootA)));
  CHECK(reboot.store_epoch() == 1);
}

void test_store_pending_write_boundaries() {
  // Power cut at every byte boundary of the pending-record write. The
  // committed image always survives; a torn head reads as corruption and
  // marks the survivor uncertain, a landed head is discardable pending.
  const TrustImage image = test_image(2, 7, kRootA);
  const std::size_t used_len = trust_image_encoded_size(image);
  for (std::size_t boundary = 0; boundary <= used_len; ++boundary) {
    FaultyTrustStorage storage;
    {
      TrustStore store(storage);
      CHECK_OK(store.initialize());
      CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
      storage.cut_call = storage.write_calls;
      storage.cut_bytes = boundary;
      CHECK(store.commit_image(image).code == StatusCode::StorageFailure);
    }
    TrustStore reboot(storage);
    const Status loaded = reboot.initialize();
    CHECK(reboot.store_epoch() == 1);
    if (boundary >= 16 || boundary == 0) {
      // Nothing landed (erased slot) or a well-formed pending head: the
      // sibling is provably absent — clean adopt, commits still allowed.
      CHECK_OK(loaded);
      CHECK(!reboot.uncertain());
      CHECK_OK(reboot.commit_image(image));
      CHECK(reboot.store_epoch() == 2);
    } else {
      // A partial header is unverifiable noise: the slot may have held a
      // newer committed record — known-value posture, commits refused.
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.uncertain());
      CHECK(!reboot.quarantined());
      CHECK(reboot.commit_image(image).code == StatusCode::RecoveryRequired);
    }
  }
}

void test_store_seal_write_boundaries() {
  // Power cut at every byte boundary of the commit-marker write. The seal
  // field (bytes 12-15) is the commit boundary: a partial seal is noise, a
  // full seal with a stale/partial CRC is a committed-but-failed record
  // whose epoch still binds the recovery floor.
  const TrustImage image = test_image(2, 7, kRootA);
  const std::size_t used_len = trust_image_encoded_size(image);
  for (std::size_t boundary = 0; boundary <= used_len; ++boundary) {
    FaultyTrustStorage storage;
    {
      TrustStore store(storage);
      CHECK_OK(store.initialize());
      CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
      storage.cut_call = storage.write_calls + 1;  // the seal write
      storage.cut_bytes = boundary;
      CHECK(store.commit_image(image).code == StatusCode::StorageFailure);
    }
    TrustStore reboot(storage);
    const Status loaded = reboot.initialize();
    if (boundary <= 12) {
      // Only bytes identical to the pending record landed -> Pending.
      CHECK_OK(loaded);
      CHECK(reboot.store_epoch() == 1);
      CHECK(reboot.epoch_floor() == 1);
      CHECK(!reboot.uncertain());
    } else if (boundary < 16) {
      // Partial seal: neither pending nor committed -> corrupt, but the
      // committed fields could not be proven -> floor stays at 1.
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.uncertain());
      CHECK(reboot.store_epoch() == 1);
      CHECK(reboot.epoch_floor() == 1);
      CHECK_OK(reboot.recover(test_image(2, 7, kRootA)));
    } else if (boundary < used_len) {
      // Committed seal + structurally intact body + failing CRC: epoch 2
      // is proven even though the record can never serve.
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.uncertain());
      CHECK(reboot.store_epoch() == 1);
      CHECK(reboot.epoch_floor() == 2);
      CHECK(reboot.recover(image).code == StatusCode::InvalidArgument);
      CHECK_OK(reboot.recover(test_image(3, 7, kRootA)));
    } else {
      // The full commit landed despite the reported failure: both slots
      // are valid and the newer epoch wins on reboot.
      CHECK_OK(loaded);
      CHECK(reboot.store_epoch() == 2);
      CHECK(!reboot.uncertain());
    }
  }
}

void test_store_first_commit_torn() {
  // A cut inside the very first pending write: nothing landed -> fresh; a
  // discardable pending head -> fresh; unverifiable noise -> quarantine
  // (never a silent reset).
  const TrustImage image = test_image(1, 7, kRootA);
  const std::size_t used_len = trust_image_encoded_size(image);
  for (const std::size_t boundary : {std::size_t{0}, std::size_t{4},
                                    std::size_t{8}, std::size_t{15},
                                    std::size_t{16}, std::size_t{60},
                                    used_len}) {
    FaultyTrustStorage storage;
    {
      TrustStore store(storage);
      CHECK_OK(store.initialize());
      storage.cut_call = 0;
      storage.cut_bytes = boundary;
      CHECK(!store.commit_image(image));
    }
    TrustStore reboot(storage);
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

void test_store_readback_failure() {
  // A commit whose readback cannot be verified reports failure even though
  // the sealed record may have landed; the next boot adopts whatever
  // persisted.
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    storage.read_error = true;
    CHECK(store.commit_image(test_image(2, 7, kRootA)).code ==
          StatusCode::StorageFailure);
    CHECK(store.store_epoch() == 1);  // in-memory state never advanced
    storage.read_error = false;
  }
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.store_epoch() == 2);  // the sealed record was real
}

void test_store_read_errors() {
  // Both slots unreadable: a retryable storage fault, not quarantine and
  // not an implicit reset.
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    CHECK_OK(store.commit_image(test_image(2, 7, kRootA)));
  }
  storage.read_error = true;
  TrustStore unreadable(storage);
  CHECK(unreadable.initialize().code == StatusCode::StorageFailure);
  CHECK(!unreadable.initialized() && !unreadable.quarantined());
  CHECK(unreadable.commit_image(test_image(3, 7, kRootA)).code ==
        StatusCode::InvalidState);

  // One valid slot + unreadable sibling: adopt known-value, mark uncertain.
  storage.read_error = false;
  storage.read_error_slot = 1;
  TrustStore partial(storage);
  CHECK(partial.initialize().code == StatusCode::IntegrityError);
  CHECK(partial.uncertain());
  CHECK(partial.store_epoch() == 1);
  CHECK(partial.commit_image(test_image(3, 7, kRootA)).code ==
        StatusCode::RecoveryRequired);
}

void test_store_equal_epoch_slots() {
  // The recover() twin pair: two valid slots with identical bytes at the
  // same epoch adopt cleanly.
  FaultyTrustStorage storage;
  const TrustImage image = test_image(5, 7, kRootA);
  ByteBuffer<kTrustStoreSlotBytes> record{};
  CHECK_OK(trust_image_encode(image, kTrustSealCommittedWire, record));
  CHECK_OK(storage.write(0, record.view()));
  CHECK_OK(storage.write(1, record.view()));
  TrustStore twin(storage);
  CHECK_OK(twin.initialize());
  CHECK(twin.store_epoch() == 5);
  CHECK(!twin.uncertain());

  // Same epoch, different-but-valid content: cannot be ordered, quarantine.
  FaultyTrustStorage storage2;
  CHECK_OK(storage2.write(0, record.view()));
  TrustImage other = test_image(5, 7, kRootA);
  other.deployment_id = 0xBEEF;
  ByteBuffer<kTrustStoreSlotBytes> record2{};
  CHECK_OK(trust_image_encode(other, kTrustSealCommittedWire, record2));
  CHECK_OK(storage2.write(1, record2.view()));
  TrustStore divergent(storage2);
  CHECK(divergent.initialize().code == StatusCode::IntegrityError);
  CHECK(divergent.quarantined());
  CHECK_OK(divergent.recover(test_image(6, 7, kRootA)));
}

void test_store_higher_epoch_wins() {
  // Two valid slots at different epochs: the newer serves regardless of
  // which slot holds it.
  FaultyTrustStorage storage;
  ByteBuffer<kTrustStoreSlotBytes> older{}, newer{};
  CHECK_OK(trust_image_encode(test_image(4, 7, kRootA),
                              kTrustSealCommittedWire, older));
  CHECK_OK(trust_image_encode(test_image(9, 7, kRootA),
                              kTrustSealCommittedWire, newer));
  CHECK_OK(storage.write(0, newer.view()));
  CHECK_OK(storage.write(1, older.view()));
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(store.store_epoch() == 9);
  // The next commit targets the inactive (older) slot and reclaims it.
  CHECK_OK(store.commit_image(test_image(10, 7, kRootA)));
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.store_epoch() == 10);
}

void test_store_schema_mismatch() {
  // An intact committed record at a foreign schema is Unsupported — never
  // silently adopted, and still bounds the recovery floors.
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    CHECK_OK(store.commit_image(test_image(2, 7, kRootA)));
  }
  patch_record(storage.slot_bytes(0), kSchemaOffset + 3, 9);
  patch_record(storage.slot_bytes(1), kSchemaOffset + 3, 9);
  TrustStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::Unsupported);
  CHECK(reboot.quarantined());
  CHECK(reboot.epoch_floor() == 2);  // committed fields are still proven
  CHECK_OK(reboot.recover(test_image(3, 7, kRootA)));

  // One valid + one unsupported sibling: known-value uncertain.
  FaultyTrustStorage mixed;
  {
    TrustStore store(mixed);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));
    CHECK_OK(store.commit_image(test_image(2, 7, kRootA)));
  }
  patch_record(mixed.slot_bytes(0), kSchemaOffset + 3, 9);  // older image
  TrustStore store(mixed);
  CHECK(store.initialize().code == StatusCode::IntegrityError);
  CHECK(store.uncertain());
  CHECK(store.store_epoch() == 2);
}

void test_store_accessors() {
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(store.find_anchor(0x100) == nullptr);
  CHECK(store.find_key(0xA17, 1) == nullptr);
  CHECK(!store.is_credential_revoked(Digest256{}));

  TrustImage image = test_image(1, 7, kRootA, 0x100);
  image.anchors[1] = test_anchor(0x200, kRootB.pub, TrustAnchorStatus::Disabled);
  image.anchor_count = 2;
  image.keys[0] = test_key_record(0xA17, 1, kAuth1.pub, TrustKeyStatus::Active);
  image.keys[1] = test_key_record(0xA17, 2, kAuth2.pub, TrustKeyStatus::Staged);
  image.key_count = 2;
  Digest256 revoked_kid{};
  revoked_kid[0] = 0xEE;
  image.revocations[0] = test_revocation(42, revoked_kid, 1);
  image.revocation_count = 1;
  CHECK_OK(store.commit_image(image));

  const TrustAnchor* anchor = store.find_anchor(0x100);
  CHECK(anchor != nullptr && anchor->status == TrustAnchorStatus::Active);
  anchor = store.find_anchor(0x200);
  CHECK(anchor != nullptr && anchor->status == TrustAnchorStatus::Disabled);
  CHECK(store.find_anchor(0x300) == nullptr);

  // Staged records resolve — the CALLER enforces status policy.
  const TrustKeyRecord* key = store.find_key(0xA17, 2);
  CHECK(key != nullptr && key->status == TrustKeyStatus::Staged);
  CHECK(store.find_key(0xA17, 3) == nullptr);
  CHECK(store.find_key(0xA18, 1) == nullptr);

  CHECK(store.is_credential_revoked(revoked_kid));
  Digest256 other_kid{};
  other_kid[0] = 0xEF;
  CHECK(!store.is_credential_revoked(other_kid));

  // Accessors serve the adopted image across a reboot.
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.find_anchor(0x200) != nullptr);
  CHECK(reboot.is_credential_revoked(revoked_kid));
}

void test_store_slot_write_sizes() {
  // Records write only [0, used_len) — the slot tail keeps prior bytes.
  FaultyTrustStorage storage;
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit_image(test_image(1, 7, kRootA)));   // 132 B
  CHECK_OK(store.commit_image(full_image(2, 7)));            // 1684 B
  CHECK(record_used_len(storage.slot_bytes(1)) == kTrustImageMax);
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.image().revocation_count == kTrustRevocationMax);
}

}  // namespace

int main() {
  test_rlt1_encode_decode_roundtrip();
  test_rlt1_encode_decode_max_image();
  test_rlt1_body_codec_matches_record();
  test_rlt1_strict_decode_rejections();
  test_rlt1_encode_validation();
  test_rlt1_semantic_validation();
  test_rlt1_fingerprint();
  test_store_fresh_and_commit();
  test_store_epoch_and_generation_floors();
  test_store_commit_state_gates();
  test_store_corrupt_sibling_uncertain();
  test_store_corrupt_both_quarantine();
  test_store_pending_slot_discarded();
  test_store_pending_only_is_fresh();
  test_store_pending_write_boundaries();
  test_store_seal_write_boundaries();
  test_store_first_commit_torn();
  test_store_readback_failure();
  test_store_read_errors();
  test_store_equal_epoch_slots();
  test_store_higher_epoch_wins();
  test_store_schema_mismatch();
  test_store_accessors();
  test_store_slot_write_sizes();
  if (failures != 0) {
    std::fprintf(stderr, "%d trust-store checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom trust store tests passed");
  return 0;
}
