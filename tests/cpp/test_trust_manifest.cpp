// Trust manifest (RTM1) tests: envelope parse/assemble, AAD and protected-
// header codecs, the Sig_structure, and the §4.5.1 acceptance pipeline —
// real deterministic P-256 signatures (RFC 6979 via vendored micro-ecc,
// normalized to the low-S rule the verifier requires), stale/replay epochs,
// unknown/disabled anchors, wrong-network AAD binding, and commit-time
// power-cut behavior. sdk-completion/04-provisioning-lifecycle.md §4.3.3.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/trust_manifest.hpp"
#include "routeloom/trust_store.hpp"
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
using routeloom_test::test_anchor;
using routeloom_test::test_image;
using routeloom_test::test_key_record;
using routeloom_test::test_keypair;
using routeloom_test::test_revocation;

const TestKeyPair kRootA = test_keypair(0x11);
const TestKeyPair kRootB = test_keypair(0x22);
const TestKeyPair kAuth1 = test_keypair(0x33);
const TestKeyPair kIntruder = test_keypair(0xEE);

constexpr std::uint64_t kRootIdA = 0x100;
constexpr std::uint64_t kRootIdB = 0x200;
constexpr NetworkId kNetwork = 7;

// The RootSigner path: encode the RLT1 body, build the Sig_structure with
// the COMMITTED network's AAD, sign sha256(sig_structure), assemble.
void make_manifest(const TrustImage& image, const std::uint64_t root_id,
                   const std::array<std::uint8_t, 32>& priv,
                   ByteBuffer<kTrustManifestObjectMax>& out,
                   const NetworkId aad_network) {
  ByteBuffer<kTrustImageContentMax> content{};
  CHECK_OK(trust_image_body_encode(image, content));
  ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
  CHECK_OK(trust_manifest_protected(root_id, protected_bytes));
  ByteBuffer<kTrustManifestAadSize> aad{};
  CHECK_OK(trust_manifest_aad(aad_network, aad));
  ByteBuffer<kTrustManifestSigMax> sig_structure{};
  CHECK_OK(trust_manifest_sig_structure(protected_bytes.view(), aad.view(),
                                        content.view(), sig_structure));
  ScopeDigest digest{};
  sha256(sig_structure.view(), digest);
  std::array<std::uint8_t, 64> signature{};
  CHECK(sign_digest_low_s(priv, digest, signature));
  CHECK_OK(trust_manifest_assemble(content.view(), root_id,
                                   ByteView{signature.data(), signature.size()},
                                   out));
}

void make_manifest(const TrustImage& image, const std::uint64_t root_id,
                   const std::array<std::uint8_t, 32>& priv,
                   ByteBuffer<kTrustManifestObjectMax>& out) {
  make_manifest(image, root_id, priv, out, image.network);
}

// A live store with one committed epoch-1 image (root A active, one active
// config key).
void provisioned_store(FaultyTrustStorage& storage) {
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  TrustImage base = test_image(1, kNetwork, kRootA, kRootIdA);
  base.keys[0] = test_key_record(0xA17, 1, kAuth1.pub, TrustKeyStatus::Active);
  base.key_count = 1;
  CHECK_OK(store.commit_image(base));
}

class FakeFloorStore final : public SecurityFloorStorage {
 public:
  Status read(const MutableByteView target) noexcept override {
    if (target.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor read");
    }
    if (!provisioned) return Status::error(StatusCode::NotFound, "floor missing");
    std::memcpy(target.data, blob_.data(), kSecurityFloorBlobBytes);
    return Status::success();
  }
  Status write(const ByteView data) noexcept override {
    if (data.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor write");
    }
    std::memcpy(blob_.data(), data.data, data.size);
    provisioned = true;
    return Status::success();
  }
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob_{};
  bool provisioned{false};
};

// A floor for kNetwork with no trust reservation yet (E=G=0): every new
// epoch in these tests reserves above it.
void seed_floor(FakeFloorStore& storage) {
  SecurityFloorState state{};
  state.network = kNetwork;
  state.target = 0x30;
  state.namespace_count = 1;
  state.entries[0].config_namespace = 1;
  state.entries[0].schema = 1;
  SecurityFloorStore floor(storage);
  CHECK_OK(floor.provision_seed(state));
}

void test_manifest_aad_and_protected() {
  ByteBuffer<kTrustManifestAadSize> aad{};
  CHECK_OK(trust_manifest_aad(0x0102030405060708ULL, aad));
  CHECK(aad.size == kTrustManifestAadSize);
  CHECK(kTrustManifestAadSize == 36);
  const char* domain = "RouteLoom/trust-manifest/v1";
  CHECK(std::memcmp(aad.bytes.data(), domain, 27) == 0);
  CHECK(aad.bytes[27] == 0);  // NUL terminator included
  CHECK(aad.bytes[28] == 0x01 && aad.bytes[35] == 0x08);  // u64 big-endian

  ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
  CHECK_OK(trust_manifest_protected(0x0102030405060708ULL, protected_bytes));
  CHECK(protected_bytes.size == 13);
  const std::array<std::uint8_t, 5> head{{0xA2, 0x01, 0x28, 0x04, 0x48}};
  CHECK(std::memcmp(protected_bytes.bytes.data(), head.data(), 5) == 0);
  CHECK(protected_bytes.bytes[5] == 0x01 &&
        protected_bytes.bytes[12] == 0x08);
}

void test_manifest_sig_structure() {
  ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
  CHECK_OK(trust_manifest_protected(kRootIdA, protected_bytes));
  ByteBuffer<kTrustManifestAadSize> aad{};
  CHECK_OK(trust_manifest_aad(kNetwork, aad));
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  ByteBuffer<kTrustManifestSigMax> sig_structure{};
  CHECK_OK(trust_manifest_sig_structure(protected_bytes.view(), aad.view(),
                                        ByteView{payload.data(), payload.size()},
                                        sig_structure));
  // 84 6a "Signature1" 4d <protected:13> 58 24 <aad:36> 44 <payload:4>
  const std::uint8_t* b = sig_structure.bytes.data();
  CHECK(b[0] == 0x84 && b[1] == 0x6A);
  CHECK(std::memcmp(b + 2, "Signature1", 10) == 0);
  CHECK(b[12] == 0x4D);
  CHECK(std::memcmp(b + 13, protected_bytes.bytes.data(), 13) == 0);
  CHECK(b[26] == 0x58 && b[27] == 36);
  CHECK(std::memcmp(b + 28, aad.bytes.data(), 36) == 0);
  CHECK(b[64] == 0x44);
  CHECK(sig_structure.size == 65 + 4);

  // Wrong-size inputs are refused — wire-supplied context never sneaks in.
  ByteBuffer<kTrustManifestSigMax> unused{};
  const std::array<std::uint8_t, 12> short_prot{};
  CHECK(!trust_manifest_sig_structure(
            ByteView{short_prot.data(), short_prot.size()}, aad.view(),
            ByteView{payload.data(), payload.size()}, unused)
            .ok());
  CHECK(!trust_manifest_sig_structure(protected_bytes.view(),
                                      ByteView{payload.data(), payload.size()},
                                      ByteView{payload.data(), payload.size()},
                                      unused)
            .ok());
  CHECK(!trust_manifest_sig_structure(protected_bytes.view(), aad.view(),
                                      ByteView{}, unused)
            .ok());
}

void test_manifest_assemble_parse_roundtrip() {
  const TrustImage image = test_image(2, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(image, kRootIdA, kRootA.priv, object);
  CHECK(object.size <= kTrustManifestObjectMax);

  TrustManifestParts parts{};
  CHECK_OK(trust_manifest_parse(object.view(), parts));
  CHECK(parts.root_id == kRootIdA);
  CHECK(parts.protected_bytes.size == kTrustManifestProtectedSize);
  CHECK(parts.signature.size == kCoseSignatureSize);
  // The payload is byte-for-byte the RLT1 body — the shared codec truth.
  ByteBuffer<kTrustImageContentMax> content{};
  CHECK_OK(trust_image_body_encode(image, content));
  CHECK(parts.payload.size == content.size);
  CHECK(std::memcmp(parts.payload.data, content.bytes.data(), content.size) == 0);
  TrustImage decoded{};
  CHECK_OK(trust_image_body_decode(parts.payload, decoded));
  CHECK(decoded.store_epoch == 2);
}

void test_manifest_parse_malformed() {
  const TrustImage image = test_image(2, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustManifestObjectMax> base{};
  make_manifest(image, kRootIdA, kRootA.priv, base);
  TrustManifestParts parts{};

  auto expect_parse = [&](const ByteView view, const char* what) {
    const Status status = trust_manifest_parse(view, parts);
    if (status.ok()) {
      std::fprintf(stderr, "manifest parse %s: unexpectedly OK\n", what);
      ++failures;
    }
  };

  // Size floor and cap.
  expect_parse(ByteView{base.bytes.data(), 50}, "undersized");
  {
    std::array<std::uint8_t, kTrustManifestObjectMax + 1> big{};
    expect_parse(ByteView{big.data(), big.size()}, "oversized");
  }
  // Envelope mutations.
  {
    auto m = base.bytes;
    m[0] = 0xD3;
    expect_parse(ByteView{m.data(), base.size}, "tag");
  }
  {
    auto m = base.bytes;
    m[1] = 0x83;
    expect_parse(ByteView{m.data(), base.size}, "array3");
  }
  {
    auto m = base.bytes;
    m[2] = 0x58;  // non-minimal protected bstr header
    m[3] = 13;
    expect_parse(ByteView{m.data(), base.size}, "protected header form");
  }
  {
    auto m = base.bytes;
    m[3] = 0xA3;  // protected map(3)
    expect_parse(ByteView{m.data(), base.size}, "protected shape");
  }
  {
    auto m = base.bytes;
    m[2] = 0x4C;  // protected bstr(12) — wrong length
    expect_parse(ByteView{m.data(), base.size}, "protected length");
  }
  {
    auto m = base.bytes;
    m[16] = 0xA1;  // non-empty unprotected map
    expect_parse(ByteView{m.data(), base.size}, "unprotected");
  }
  {
    auto m = base.bytes;
    m[base.size - 65] = 0x3F;  // signature bstr(63)
    expect_parse(ByteView{m.data(), base.size - 1}, "signature length");
  }
  {
    auto m = base;
    m.bytes[base.size] = 0x00;
    expect_parse(ByteView{m.bytes.data(), base.size + 1}, "trailing byte");
  }
  {
    auto m = base;
    expect_parse(ByteView{m.bytes.data(), base.size - 1}, "truncated");
  }
  // Empty payload bstr is a structural violation. Hand-assemble the shape:
  // d2 84 4d <prot:13> a0 40 58 40 <sig:64>.
  {
    ByteBuffer<256> crafted{};
    ByteWriter writer(crafted.writable());
    CHECK_OK(writer.write_u8(0xD2));
    CHECK_OK(writer.write_u8(0x84));
    ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
    CHECK_OK(trust_manifest_protected(kRootIdA, protected_bytes));
    CHECK_OK(cbor_put_bstr(writer, protected_bytes.view()));
    CHECK_OK(writer.write_u8(0xA0));
    CHECK_OK(cbor_put_bstr(writer, ByteView{}));  // empty payload
    const std::array<std::uint8_t, 64> sig{};
    CHECK_OK(cbor_put_bstr(writer, ByteView{sig.data(), sig.size()}));
    crafted.size = writer.size();
    // 84 bytes — under the 86-byte object floor, rejected as undersized.
    expect_parse(crafted.view(), "empty payload");
  }
}

void test_manifest_accept_happy_path() {
  FaultyTrustStorage storage;
  provisioned_store(storage);

  TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  next.keys[0] = test_key_record(0xA17, 1, kAuth1.pub, TrustKeyStatus::Active);
  next.key_count = 1;
  next.min_authority_generation = 2;
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(next, kRootIdA, kRootA.priv, object);

  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 2);
  CHECK(store.min_authority_generation() == 2);

  // The committed image persists across reboot — manifest fully applied.
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.store_epoch() == 2);
  CHECK(reboot.generation_floor() == 2);
}

void test_manifest_accept_replay_and_stale() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  ByteBuffer<kTrustManifestObjectMax> installed{};
  make_manifest(test_image(5, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, installed);
  CHECK_OK(trust_manifest_accept(store, installed.view(), floor));

  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(test_image(4, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::Conflict);  // stale — denied before the verify
  // Completed duplicate: same epoch, byte-identical content — success
  // with no flash write.
  const std::size_t writes_before = storage.write_calls;
  make_manifest(test_image(5, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, object);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 5);
  CHECK(storage.write_calls == writes_before);
  // Same epoch with DIFFERENT content is a fork attempt, never an update.
  TrustImage fork = test_image(5, kNetwork, kRootA, kRootIdA);
  fork.min_authority_generation = 9;
  make_manifest(fork, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::Conflict);
  CHECK(store.store_epoch() == 5);
}

void test_manifest_accept_epoch_zero() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  // A structurally decodable image with epoch 0: rejected as malformed
  // before any crypto (§4.5.1 rule 2).
  TrustImage zero_epoch = test_image(0, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(zero_epoch, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::ProtocolError);
}

void test_manifest_accept_wrong_network() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(test_image(2, 8, kRootA, kRootIdA), kRootIdA, kRootA.priv,
                object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);
  CHECK(store.store_epoch() == 1);
}

void test_manifest_accept_anchor_policy() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  const TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustManifestObjectMax> object{};

  // kid names no anchor in the committed image.
  make_manifest(next, 0x999, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);

  // kid names an anchor whose record is Disabled — fails even with a
  // signature that would verify under it.
  {
    FaultyTrustStorage storage2;
    {
      TrustStore seeding(storage2);
      CHECK_OK(seeding.initialize());
      TrustImage base = test_image(1, kNetwork, kRootA, kRootIdA);
      base.anchors[1] =
          test_anchor(kRootIdB, kRootB.pub, TrustAnchorStatus::Disabled);
      base.anchor_count = 2;
      CHECK_OK(seeding.commit_image(base));
    }
    TrustStore disabled(storage2);
    CHECK_OK(disabled.initialize());
    FakeFloorStore disabled_floor_storage;
    seed_floor(disabled_floor_storage);
    SecurityFloorStore disabled_floor(disabled_floor_storage);
    CHECK_OK(disabled_floor.initialize());
    disabled.attach_floor(&disabled_floor);
    ByteBuffer<kTrustManifestObjectMax> object2{};
    make_manifest(test_image(2, kNetwork, kRootA, kRootIdA), kRootIdB,
                  kRootB.priv, object2);
    CHECK(trust_manifest_accept(disabled, object2.view(), disabled_floor).code ==
          StatusCode::AuthorizationFailed);
  }
}

void test_manifest_accept_bad_signature() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  const TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustManifestObjectMax> object{};

  // Signed by a different private key than the named anchor holds.
  make_manifest(next, kRootIdA, kIntruder.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);

  // Tampered signature byte.
  make_manifest(next, kRootIdA, kRootA.priv, object);
  object.bytes[object.size - 10] ^= 0x01;
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);

  // Signature bounds: R = 0.
  {
    ByteBuffer<kTrustImageContentMax> content{};
    CHECK_OK(trust_image_body_encode(next, content));
    std::array<std::uint8_t, 64> signature{};  // R and S both zero
    ByteBuffer<kTrustManifestObjectMax> bad{};
    CHECK_OK(trust_manifest_assemble(content.view(), kRootIdA,
                                     ByteView{signature.data(), 64}, bad));
    CHECK(trust_manifest_accept(store, bad.view(), floor).code ==
          StatusCode::AuthorizationFailed);
  }
  // S = n (out of range).
  {
    ByteBuffer<kTrustImageContentMax> content{};
    CHECK_OK(trust_image_body_encode(next, content));
    std::array<std::uint8_t, 64> signature{};
    signature[0] = 1;  // R = 1
    std::memcpy(signature.data() + 32, kSecp256r1Order.data(), 32);  // S = n
    ByteBuffer<kTrustManifestObjectMax> bad{};
    CHECK_OK(trust_manifest_assemble(content.view(), kRootIdA,
                                     ByteView{signature.data(), 64}, bad));
    CHECK(trust_manifest_accept(store, bad.view(), floor).code ==
          StatusCode::AuthorizationFailed);
  }
  // High-S form of an otherwise valid signature: malleability rejected.
  {
    make_manifest(next, kRootIdA, kRootA.priv, object);
    // Recover the signature, flip S to n - S, reassemble.
    TrustManifestParts parts{};
    CHECK_OK(trust_manifest_parse(object.view(), parts));
    std::array<std::uint8_t, 64> signature{};
    std::memcpy(signature.data(), parts.signature.data, 64);
    std::array<std::uint8_t, 32> s{};
    std::memcpy(s.data(), signature.data() + 32, 32);
    std::array<std::uint8_t, 32> flipped = kSecp256r1Order;
    routeloom_test::be32_sub(flipped, s);
    std::memcpy(signature.data() + 32, flipped.data(), 32);
    ByteBuffer<kTrustManifestObjectMax> bad{};
    CHECK_OK(trust_manifest_assemble(parts.payload, kRootIdA,
                                     ByteView{signature.data(), 64}, bad));
    CHECK(trust_manifest_accept(store, bad.view(), floor).code ==
          StatusCode::AuthorizationFailed);
  }
}

void test_manifest_accept_aad_binding() {
  // The external AAD binds the device's COMMITTED network, never transport
  // claims: a manifest whose signer built the Sig_structure over a foreign
  // AAD fails verification even though the image content matches.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  const TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(next, kRootIdA, kRootA.priv, object,
                /*aad_network=*/8);  // signed for the wrong network context
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);
}

void test_manifest_accept_store_states() {
  ByteBuffer<kTrustManifestObjectMax> object{};
  const TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  make_manifest(next, kRootIdA, kRootA.priv, object);

  // Uninitialized store (the floor object is never touched — the
  // initialized gate fires first).
  {
    FaultyTrustStorage storage;
    TrustStore store(storage);
    FakeFloorStore floor_storage;
    SecurityFloorStore floor(floor_storage);
    CHECK(trust_manifest_accept(store, object.view(), floor).code ==
          StatusCode::InvalidState);
  }
  // Fresh store (first install is physical — never a manifest).
  {
    FaultyTrustStorage storage;
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    FakeFloorStore floor_storage;
    seed_floor(floor_storage);
    SecurityFloorStore floor(floor_storage);
    CHECK_OK(floor.initialize());
    CHECK(trust_manifest_accept(store, object.view(), floor).code ==
          StatusCode::AuthorizationFailed);
  }
  // Quarantined store: no floor binding for these bytes, so the
  // store-state gate fires (same-original redelivery binds and heals —
  // covered by the resume tests).
  {
    FaultyTrustStorage storage;
    provisioned_store(storage);
    storage.corrupt(0, 100);
    storage.corrupt(1, 100);
    TrustStore store(storage);
    CHECK(store.initialize().code == StatusCode::IntegrityError);
    CHECK(store.quarantined());
    FakeFloorStore floor_storage;
    seed_floor(floor_storage);
    SecurityFloorStore floor(floor_storage);
    CHECK_OK(floor.initialize());
    CHECK(trust_manifest_accept(store, object.view(), floor).code ==
          StatusCode::IntegrityError);
    // Even malformed input reports the store state first.
    const std::array<std::uint8_t, 4> junk{{0xDE, 0xAD, 0xBE, 0xEF}};
    CHECK(trust_manifest_accept(store, ByteView{junk.data(), junk.size()},
                                floor)
              .code == StatusCode::IntegrityError);
  }
  // Uncertain store: intake refused until recover().
  {
    FaultyTrustStorage storage;
    provisioned_store(storage);
    storage.corrupt(1, 100);
    TrustStore store(storage);
    CHECK(store.initialize().code == StatusCode::IntegrityError);
    CHECK(store.uncertain());
    FakeFloorStore floor_storage;
    seed_floor(floor_storage);
    SecurityFloorStore floor(floor_storage);
    CHECK_OK(floor.initialize());
    CHECK(trust_manifest_accept(store, object.view(), floor).code ==
          StatusCode::RecoveryRequired);
  }
}

void test_manifest_accept_semantic_floor() {
  // The floor regression is caught inside commit_image (§4.5.1 rule 5),
  // after the signature verifies.
  FaultyTrustStorage storage;
  {
    TrustStore seeding(storage);
    CHECK_OK(seeding.initialize());
    TrustImage base = test_image(1, kNetwork, kRootA, kRootIdA);
    base.min_authority_generation = 5;
    CHECK_OK(seeding.commit_image(base));
  }
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  CHECK(store.generation_floor() == 5);
  TrustImage regressed = test_image(2, kNetwork, kRootA, kRootIdA);
  regressed.min_authority_generation = 3;
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(regressed, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);
  CHECK(store.store_epoch() == 1);
}

void test_manifest_accept_broken_chain_refused() {
  // An image that leaves zero active anchors can never break its own
  // signature chain — a signed manifest committing it is refused at
  // commit_image's validation (§4.5.1 rule 5).
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  TrustImage suicidal = test_image(2, kNetwork, kRootA, kRootIdA);
  suicidal.anchors[0].status = TrustAnchorStatus::Disabled;
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(suicidal, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::InvalidArgument);
  CHECK(store.store_epoch() == 1);
}

void test_manifest_accept_skip_ahead() {
  // Complete-replacement semantics: missed intermediate manifests are
  // irrelevant — epoch 5 lands directly over epoch 1.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  TrustImage jump = test_image(5, kNetwork, kRootA, kRootIdA);
  Digest256 revoked{};
  revoked[0] = 0xAB;
  jump.revocations[0] = test_revocation(42, revoked, 5);
  jump.revocation_count = 1;
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(jump, kRootIdA, kRootA.priv, object);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 5);
  CHECK(store.is_credential_revoked(revoked));
}

void test_manifest_accept_anchor_rotation() {
  // Two-image handover (§4.6.4): e2 adds root B active (signed by A);
  // e3 disables A (signed by B). Afterwards A signs nothing.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);

  TrustImage e2 = test_image(2, kNetwork, kRootA, kRootIdA);
  e2.anchors[1] = test_anchor(kRootIdB, kRootB.pub, TrustAnchorStatus::Active);
  e2.anchor_count = 2;
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(e2, kRootIdA, kRootA.priv, object);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 2);
  CHECK(store.find_anchor(kRootIdB) != nullptr);

  TrustImage e3 = e2;
  e3.store_epoch = 3;
  e3.anchors[0].status = TrustAnchorStatus::Disabled;
  make_manifest(e3, kRootIdB, kRootB.priv, object);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 3);
  CHECK(store.find_anchor(kRootIdA)->status == TrustAnchorStatus::Disabled);

  // The disabled anchor's signature no longer authorizes.
  TrustImage e4 = e3;
  e4.store_epoch = 4;
  e4.anchors[0].status = TrustAnchorStatus::Active;  // tries to re-enable
  make_manifest(e4, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);
  CHECK(store.store_epoch() == 3);
}

void test_manifest_accept_max_size() {
  // A maximum-table image signs and commits through the whole pipeline —
  // 1664 B content + envelope ≈ 1750 B, under the 2048 object cap.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);

  TrustImage maximal = test_image(2, kNetwork, kRootA, kRootIdA);
  maximal.anchors[1] =
      test_anchor(kRootIdB, kRootB.pub, TrustAnchorStatus::Disabled);
  maximal.anchor_count = 2;
  for (std::uint8_t i = 0; i < kTrustKeyMax; ++i) {
    maximal.keys[i] = test_key_record(0xA17 + i, i + 1, kAuth1.pub);
  }
  maximal.key_count = kTrustKeyMax;
  for (std::uint8_t i = 0; i < kTrustRevocationMax; ++i) {
    Digest256 kid{};
    kid[0] = static_cast<std::uint8_t>(i + 1);
    maximal.revocations[i] = test_revocation(0x600 + i, kid, 2);
  }
  maximal.revocation_count = kTrustRevocationMax;
  ByteBuffer<kTrustImageContentMax> content{};
  CHECK_OK(trust_image_body_encode(maximal, content));
  CHECK(content.size == kTrustImageContentMax);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(maximal, kRootIdA, kRootA.priv, object);
  CHECK(object.size <= kTrustManifestObjectMax);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 2);
  CHECK(store.image().revocation_count == kTrustRevocationMax);
}

void test_manifest_accept_power_cut() {
  // A power cut inside the manifest's commit leaves pending evidence the
  // boot classifier discards — the old image stays authoritative.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  ByteBuffer<kTrustManifestObjectMax> object{};
  const TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  make_manifest(next, kRootIdA, kRootA.priv, object);
  // One floor across the power cut: the reservation the failed commit
  // made is what the retry resumes.
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    store.attach_floor(&floor);
    storage.cut_call = storage.write_calls;      // pending write of the commit
    storage.cut_bytes = 20;                      // torn body, head intact
    CHECK(trust_manifest_accept(store, object.view(), floor).code ==
          StatusCode::StorageFailure);
    CHECK(store.store_epoch() == 1);  // in-memory state never advanced
  }
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  reboot.attach_floor(&floor);
  CHECK(reboot.store_epoch() == 1);
  CHECK(!reboot.uncertain());  // pending head is provably discardable
  // Retry lands cleanly through the floor-bound resume: the reservation
  // the failed commit made re-installs these exact bytes.
  CHECK_OK(trust_manifest_accept(reboot, object.view(), floor));
  CHECK(reboot.store_epoch() == 2);
}

void test_reserved_manifest_is_the_only_resume() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  TrustView view(store);
  view.attach_floor(&floor);
  CHECK(view.ready());

  ByteBuffer<kTrustManifestObjectMax> reserved_object{};
  make_manifest(test_image(2, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, reserved_object);
  SecurityFloorState before{};
  CHECK_OK(floor.read(before));
  SecurityFloorState reserved = before;
  reserved.trust_epoch_floor = 2;
  reserved.min_authority_generation = 1;
  sha256(reserved_object.view(), reserved.last_manifest_hash);
  CHECK_OK(floor.advance(before, reserved));

  // A cut after the floor reservation leaves an old, CRC-valid image.
  // It must serve neither config permits nor a different root update.
  CHECK(!view.ready());
  CHECK(view.resolve_authority_key(0xA17, 1) == nullptr);
  ByteBuffer<kTrustManifestObjectMax> replacement{};
  make_manifest(test_image(3, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, replacement);
  CHECK(!trust_manifest_accept(store, replacement.view(), floor).ok());
  SecurityFloorState after{};
  CHECK_OK(floor.read(after));
  CHECK(after.trust_epoch_floor == 2);
  CHECK(after.last_manifest_hash == reserved.last_manifest_hash);
  CHECK(store.store_epoch() == 1);

  CHECK_OK(trust_manifest_accept(store, reserved_object.view(), floor));
  CHECK(store.store_epoch() == 2);
  CHECK(view.usable());

  // Equal payload with a corrupted signature is not the reserved original.
  auto forged = reserved_object;
  forged.bytes[forged.size - 1] ^= 1;
  CHECK(!trust_manifest_accept(store, forged.view(), floor).ok());

  floor_storage.provisioned = false;
  CHECK(floor.refresh().code == StatusCode::RecoveryRequired);
  CHECK(!view.usable() && !view.ready());
  CHECK(view.resolve_authority_key(0xA17, 1) == nullptr);
}

void test_manifest_accept_total_loss_resume() {
  // Both trust slots destroyed after a committed update: the ONLY way
  // back is re-delivering the exact original the floor binds (same
  // bytes hash + E/G). No anchor survives to verify against — the floor
  // binding is the reinstall authorization — and any other bytes refuse.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  ByteBuffer<kTrustManifestObjectMax> object{};
  TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  next.keys[0] = test_key_record(0xA17, 2, kAuth1.pub, TrustKeyStatus::Active);
  next.key_count = 1;
  next.min_authority_generation = 2;
  make_manifest(next, kRootIdA, kRootA.priv, object);
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    store.attach_floor(&floor);
    CHECK_OK(trust_manifest_accept(store, object.view(), floor));
    CHECK(store.store_epoch() == 2);
  }
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  TrustStore lost(storage);
  CHECK(lost.initialize().code == StatusCode::IntegrityError);
  CHECK(lost.quarantined());
  lost.attach_floor(&floor);
  // Same original reinstalls without any surviving anchor.
  CHECK_OK(trust_manifest_accept(lost, object.view(), floor));
  CHECK(lost.store_epoch() == 2);
  CHECK(lost.find_key(0xA17, 2) != nullptr);
  CHECK(!lost.quarantined() && !lost.uncertain());
  // Both slots carry the reinstalled twins.
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.store_epoch() == 2);
  CHECK(!reboot.uncertain());
}

void test_manifest_accept_total_loss_foreign_refused() {
  // After total slot loss, bytes the floor does NOT bind are refused —
  // even well-signed ones: there is no anchor base to verify against,
  // so only the reservation authorizes.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    store.attach_floor(&floor);
    ByteBuffer<kTrustManifestObjectMax> object{};
    make_manifest(test_image(2, kNetwork, kRootA, kRootIdA), kRootIdA,
                  kRootA.priv, object);
    CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  }
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  TrustStore lost(storage);
  CHECK(lost.initialize().code == StatusCode::IntegrityError);
  lost.attach_floor(&floor);
  // A well-formed, well-signed epoch-3 manifest — but the floor binds
  // only the epoch-2 original, so this is managed re-provisioning, not
  // a resume.
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(test_image(3, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, object);
  CHECK(trust_manifest_accept(lost, object.view(), floor).code ==
        StatusCode::IntegrityError);
  CHECK(lost.quarantined());
}

void test_manifest_accept_uncertain_heal() {
  // One trust slot destroyed after a committed update: redelivering the
  // same original heals the missing twin (completed-duplicate path on an
  // uncertain store) instead of demanding a new epoch.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(test_image(2, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, object);
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    store.attach_floor(&floor);
    CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  }
  storage.corrupt(1, 100);
  TrustStore hurt(storage);
  CHECK(hurt.initialize().code == StatusCode::IntegrityError);
  CHECK(hurt.uncertain());
  hurt.attach_floor(&floor);
  CHECK_OK(trust_manifest_accept(hurt, object.view(), floor));
  CHECK(hurt.store_epoch() == 2);
  CHECK(!hurt.uncertain());
  TrustStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(!reboot.uncertain());
  CHECK(reboot.store_epoch() == 2);
}

void test_manifest_accept_top_values_refused() {
  // Epochs/generations at the u32 top value would seal the axis against
  // the next disaster recovery — refused even when well-signed.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  ByteBuffer<kTrustManifestObjectMax> object{};
  TrustImage sealed = test_image(0xFFFFFFFFU, kNetwork, kRootA, kRootIdA);
  make_manifest(sealed, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::InvalidArgument);
  TrustImage sealed_gen = test_image(2, kNetwork, kRootA, kRootIdA);
  sealed_gen.min_authority_generation = 0xFFFFFFFFU;
  make_manifest(sealed_gen, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::InvalidArgument);
  CHECK(store.store_epoch() == 1);
}

void test_manifest_accept_below_floor() {
  // The floor leads: an epoch at/below the floor's E, or a generation
  // below the floor's G, is stale — even with a valid signature under a
  // live anchor.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  // Simulate a newer reservation the store has not committed (managed
  // state, e.g. an interrupted newer update): floor E/G move first.
  SecurityFloorState reserved{};
  CHECK_OK(floor.read(reserved));
  SecurityFloorState advanced = reserved;
  advanced.trust_epoch_floor = 5;
  advanced.min_authority_generation = 4;
  CHECK_OK(floor.advance(reserved, advanced));
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(test_image(2, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::Conflict);
  TrustImage low_gen = test_image(6, kNetwork, kRootA, kRootIdA);
  low_gen.min_authority_generation = 1;
  make_manifest(low_gen, kRootIdA, kRootA.priv, object);
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::AuthorizationFailed);
  CHECK(store.store_epoch() == 1);
}

void test_manifest_accept_config_off() {
  // Zero active config keys is a legal state — config disabled deliberately
  // (§4.5.1 rule 5 constrains anchors only). The manifest commits.
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  CHECK(store.find_key(0xA17, 1) != nullptr);  // active key today
  const TrustImage config_off = test_image(2, kNetwork, kRootA, kRootIdA);
  CHECK(config_off.key_count == 0);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(config_off, kRootIdA, kRootA.priv, object);
  CHECK_OK(trust_manifest_accept(store, object.view(), floor));
  CHECK(store.store_epoch() == 2);
  CHECK(store.find_key(0xA17, 1) == nullptr);
}

void test_manifest_accept_overcap_content() {
  // Content whose declared counts exceed the table caps fails the cheap
  // structural decode before any signature work (§4.5.1 rule 2).
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  const TrustImage next = test_image(2, kNetwork, kRootA, kRootIdA);
  ByteBuffer<kTrustImageContentMax> content{};
  CHECK_OK(trust_image_body_encode(next, content));
  content.bytes[25] = kTrustAnchorMax + 1;  // anchor_count field in the body
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(next, kRootIdA, kRootA.priv, object);  // placeholder sig
  // Re-assemble with the corrupted content under the SAME signature — the
  // parse must reject it before the signature is even evaluated.
  TrustManifestParts parts{};
  CHECK_OK(trust_manifest_parse(object.view(), parts));
  CHECK_OK(trust_manifest_assemble(content.view(), kRootIdA,
                                   parts.signature, object));
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::ProtocolError);
}

void test_manifest_accept_malformed_object() {
  FaultyTrustStorage storage;
  provisioned_store(storage);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  FakeFloorStore floor_storage;
  seed_floor(floor_storage);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  store.attach_floor(&floor);
  ByteBuffer<kTrustManifestObjectMax> object{};
  make_manifest(test_image(2, kNetwork, kRootA, kRootIdA), kRootIdA,
                kRootA.priv, object);
  // Envelope corruption is a parse error, not a denial.
  object.bytes[0] = 0xD3;
  CHECK(trust_manifest_accept(store, object.view(), floor).code ==
        StatusCode::ProtocolError);
  // Oversized objects never reach the parser's semantic stage.
  std::array<std::uint8_t, kTrustManifestObjectMax + 1> huge{};
  CHECK(trust_manifest_accept(store, ByteView{huge.data(), huge.size()}, floor).code ==
        StatusCode::ProtocolError);
}

void test_manifest_assemble_validation() {
  ByteBuffer<kTrustManifestObjectMax> out{};
  const std::array<std::uint8_t, 4> content{{1, 2, 3, 4}};
  const std::array<std::uint8_t, 64> sig{};
  CHECK_OK(trust_manifest_assemble(ByteView{content.data(), content.size()},
                                   kRootIdA,
                                   ByteView{sig.data(), sig.size()}, out));
  CHECK(out.bytes[0] == 0xD2 && out.bytes[1] == 0x84);
  CHECK(!trust_manifest_assemble(ByteView{}, kRootIdA,
                                 ByteView{sig.data(), 64}, out)
            .ok());
  CHECK(!trust_manifest_assemble(ByteView{content.data(), content.size()},
                                 kRootIdA, ByteView{sig.data(), 63}, out)
            .ok());
  CHECK(!trust_manifest_assemble(ByteView{content.data(), content.size()},
                                 kRootIdA, ByteView{}, out)
            .ok());
}

}  // namespace

int main() {
  test_manifest_aad_and_protected();
  test_manifest_sig_structure();
  test_manifest_assemble_parse_roundtrip();
  test_manifest_parse_malformed();
  test_manifest_accept_happy_path();
  test_manifest_accept_replay_and_stale();
  test_manifest_accept_epoch_zero();
  test_manifest_accept_wrong_network();
  test_manifest_accept_anchor_policy();
  test_manifest_accept_bad_signature();
  test_manifest_accept_aad_binding();
  test_manifest_accept_store_states();
  test_manifest_accept_semantic_floor();
  test_manifest_accept_broken_chain_refused();
  test_manifest_accept_skip_ahead();
  test_manifest_accept_anchor_rotation();
  test_manifest_accept_max_size();
  test_manifest_accept_power_cut();
  test_reserved_manifest_is_the_only_resume();
  test_manifest_accept_total_loss_resume();
  test_manifest_accept_total_loss_foreign_refused();
  test_manifest_accept_uncertain_heal();
  test_manifest_accept_top_values_refused();
  test_manifest_accept_below_floor();
  test_manifest_accept_config_off();
  test_manifest_accept_overcap_content();
  test_manifest_accept_malformed_object();
  test_manifest_assemble_validation();
  if (failures != 0) {
    std::fprintf(stderr, "%d manifest checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom trust manifest tests passed");
  return 0;
}
