// Dev RAM session policy (G-SEC P4 §10.1/§10.2; acceptance V1-N01, V1-K10):
// the NVS-free pair resume lookup, the boot-scoped group sender, and the
// maintenance-domain fingerprints behind the legacy-state console verb.
//
// The KDFs themselves are pinned by tests/cpp/test_sdkv1_dev_keys.cpp; the
// fingerprint bytes below come from the independent Python oracle in
// /tmp/p4c-r9-fingerprint-oracle.py (hashlib/hmac only).

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/group.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_dev_session.hpp"
#include "routeloom/wire.hpp"
#include "test_sdkv1.hpp"

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
constexpr NetworkId kNet = 0x1122334455667788ULL;
constexpr NodeId kSelf = 0xAABBCCDDEEFF0011ULL;
constexpr NodeId kPeer = 0xBBCCDDEEFF0022ULL;

keys::Secret test_psk() {
  keys::Secret psk{};
  for (std::size_t i = 0; i < psk.size(); ++i) psk[i] = static_cast<std::uint8_t>(i);
  return psk;
}

// Split-tag test AEAD (proves the provider, not AES): XOR keystream with a
// tag bound to key/nonce/aad/ciphertext. Cross-key/cross-nonce confusion
// fails the tag.
struct TestAead {
  static std::uint64_t mix(const std::uint64_t state, const std::uint64_t value) noexcept {
    return (state ^ (value + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U))) *
           0xbf58476d1ce4e5b9ULL;
  }
  static std::uint64_t keystream_of(const std::uint8_t key[16], const std::uint8_t nonce[12],
                                    const ByteView aad) noexcept {
    std::uint64_t state = 0x64657667726f7570ULL;
    for (int i = 0; i < 16; ++i) state = mix(state, key[i]);
    for (int i = 0; i < 12; ++i) state = mix(state, nonce[i]);
    for (std::size_t i = 0; i < aad.size; ++i) state = mix(state, aad.data[i]);
    return state;
  }
  static void tag_of(const std::uint64_t ks, const ByteView ct,
                     std::uint8_t tag[16]) noexcept {
    for (int i = 0; i < 16; ++i)
      tag[i] = static_cast<std::uint8_t>(mix(ks ^ 0x746167ULL, static_cast<std::uint64_t>(i)) >>
                                         56U);
    for (std::size_t i = 0; i < ct.size; ++i) tag[i % 16] ^= ct.data[i];
  }
  static bool seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out_ct,
                   std::uint8_t out_tag[16]) noexcept {
    (void)ctx;
    const std::uint64_t ks = keystream_of(key, nonce, aad);
    for (std::size_t i = 0; i < plaintext.size; ++i)
      out_ct[i] = plaintext.data[i] ^ static_cast<std::uint8_t>(mix(ks, i + 1) >> 56U);
    tag_of(ks, ByteView{out_ct, plaintext.size}, out_tag);
    return true;
  }
  static bool open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out) noexcept {
    (void)ctx;
    const std::uint64_t ks = keystream_of(key, nonce, aad);
    std::uint8_t expect[16]{};
    tag_of(ks, ciphertext, expect);
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<std::uint8_t>(expect[i] ^ tag[i]);
    if (diff != 0) return false;
    for (std::size_t i = 0; i < ciphertext.size; ++i)
      out[i] = ciphertext.data[i] ^ static_cast<std::uint8_t>(mix(ks, i + 1) >> 56U);
    return true;
  }
};

SecurityContext group_ctx(const NodeId sender, const std::uint32_t boot, const NodeId group) {
  SecurityContext c{};
  c.scope = SecurityScope::Group;
  c.network = kNet;
  c.sender = sender;
  c.receiver = kBroadcastNodeId;
  c.epoch = kDevGroupEpoch;
  c.group_epoch = 0;
  c.sender_boot = boot;
  c.group_id = group;
  return c;
}
}  // namespace

int main() {
  const keys::Secret psk = test_psk();

  // --- Pair resume lookup: RAM-only, order-free, exact rid match ------------
  keys::Secret rms{};
  CHECK(keys::dev_pair_rms(psk, kNet, kSelf, 0x3344, keys::Purpose::Link, rms).ok());
  keys::ResumeId rid{};
  keys::resume_id(rms, keys::Purpose::Link, rid);
  rlres1::Slot slot{};
  CHECK(dev_find_slot(psk, kNet, keys::Purpose::Link, kSelf, 0x3344, rid, slot).ok());
  CHECK(slot.purpose == keys::Purpose::Link && slot.peer == 0x3344 && slot.network == kNet);
  CHECK(slot.created_gk_epoch == 1 && slot.peer_generation == 0);
  CHECK(slot.secret == rms);  // same PSK holder, not a device identity
  // The claimed peer is only "someone with the PSK": a wrong rid never opens.
  keys::ResumeId wrong = rid;
  wrong[0] ^= 1;
  rlres1::Slot dirty{};
  dirty.secret[0] = 0x5A;
  CHECK(dev_find_slot(psk, kNet, keys::Purpose::Link, kSelf, 0x3344, wrong, dirty).code ==
        StatusCode::NotFound);
  CHECK(dirty.secret == keys::Secret{});  // no RMS leaks on mismatch
  CHECK(dev_find_slot(psk, kNet, keys::Purpose::Link, kSelf, kSelf, rid, slot).code ==
        StatusCode::InvalidArgument);
  CHECK(dev_find_slot(psk, kNet, keys::Purpose::Link, kSelf, kInvalidNodeId, rid, slot).code ==
        StatusCode::InvalidArgument);
  CHECK(dev_find_slot(psk, 0, keys::Purpose::Link, kSelf, 0x3344, rid, slot).code ==
        StatusCode::InvalidArgument);
  keys::ResumeId end_rid{};
  keys::resume_id(rms, keys::Purpose::End, end_rid);
  CHECK(dev_find_slot(psk, kNet, keys::Purpose::Usb, kSelf, 0x3344, end_rid, slot).code ==
        StatusCode::InvalidArgument);  // never an RLRES1 purpose
  // Link and End RMS never cross: the link rid under End refuses.
  CHECK(dev_find_slot(psk, kNet, keys::Purpose::End, kSelf, 0x3344, rid, slot).code ==
        StatusCode::NotFound);

  // N01 shape: 200-peer churn through the lookup takes no store, writes no
  // c/f/r record (there is no port to write through), and stays pairwise.
  keys::Secret seen_rms[200];
  for (unsigned i = 0; i < 200; ++i) {
    const NodeId peer = 0x1000 + i;
    keys::Secret pair{};
    CHECK(keys::dev_pair_rms(psk, kNet, kSelf, peer, keys::Purpose::Link, pair).ok());
    keys::ResumeId peer_rid{};
    keys::resume_id(pair, keys::Purpose::Link, peer_rid);
    rlres1::Slot churn{};
    CHECK(dev_find_slot(psk, kNet, keys::Purpose::Link, kSelf, peer, peer_rid, churn).ok());
    CHECK(churn.secret == pair);
    seen_rms[i] = pair;
  }
  for (unsigned i = 0; i < 200; ++i) {
    for (unsigned j = i + 1; j < 200; ++j) CHECK(seen_rms[i] != seen_rms[j]);
  }

  // --- Group sender: one RAM counter under a boot-scoped key (K10) ---------
  DevGroupSender group;
  CHECK(!group.configured());
  keys::TrafficKey material{};
  CHECK(group.material(material).code == StatusCode::InvalidState);
  CHECK(group.configure(psk, kNet, kSelf, 0).code == StatusCode::InvalidArgument);
  CHECK(group.configure(psk, kNet, kInvalidNodeId, 17).code == StatusCode::InvalidArgument);
  CHECK(group.configure(psk, 0, kSelf, 17).code == StatusCode::InvalidArgument);
  CHECK(!group.configured());
  CHECK(group.configure(psk, kNet, kSelf, 17).ok());
  CHECK(group.configured() && group.boot() == 17);
  keys::TrafficKey expect{};
  CHECK(keys::dev_group_key(psk, kNet, kSelf, 17, expect).ok());
  CHECK(group.material(material).ok());
  CHECK(material.key == expect.key && material.iv == expect.iv);
  std::uint64_t counter = 0;
  CHECK(group.next_counter(counter).ok() && counter == 0);
  CHECK(group.next_counter(counter).ok() && counter == 1);
  // Same boot, rebuilt sender: the old key must never restart its counter.
  DevGroupSender rebuilt;
  CHECK(rebuilt.configure(psk, kNet, kSelf, 17).ok());
  CHECK(group.configure(psk, kNet, kSelf, 17).code == StatusCode::Conflict);
  CHECK(group.next_counter(counter).ok() && counter == 2);  // untouched
  CHECK(group.configure(psk, kNet, kSelf, 16).code == StatusCode::Conflict);  // regress
  CHECK(group.configure(psk, kNet, kSelf, 18).ok());
  CHECK(group.next_counter(counter).ok() && counter == 0);  // new boot, new key
  CHECK(group.material(material).ok());
  CHECK(material.key != expect.key);
  group.clear();
  CHECK(!group.configured());
  CHECK(group.configure(psk, kNet, kSelf, 18).code == StatusCode::Conflict);
  CHECK(group.configure(psk, kNet, kSelf, 19).ok());
  CHECK(group.next_counter(counter).ok() && counter == 0);
  CHECK(DevGroupSender::counter_admissible(DevGroupSender::kMaxUseCounter - 1));
  CHECK(!DevGroupSender::counter_admissible(DevGroupSender::kMaxUseCounter));
  CHECK(!DevGroupSender::counter_admissible(DevGroupSender::kMaxUseCounter + 1));

  // --- Maintenance-domain fingerprints (independent vectors) ---------------
  MaintenanceFingerprint dev{};
  CHECK(dev_maintenance_fingerprint(psk, 2, kNet, kSelf, dev).ok());
  CHECK(dev == (MaintenanceFingerprint{0x42, 0x7e, 0xc2, 0x0f, 0xda, 0x94, 0xe7, 0xa0,
                                        0x7e, 0x3f, 0x28, 0xe2, 0xaa, 0x00, 0x8a, 0x1d}));
  MaintenanceFingerprint moved = dev;
  CHECK(dev_maintenance_fingerprint(psk, 1, kNet, kSelf, moved).ok() && moved != dev);
  CHECK(dev_maintenance_fingerprint(psk, 2, kNet + 1, kSelf, moved).ok() && moved != dev);
  CHECK(dev_maintenance_fingerprint(psk, 2, kNet, kSelf + 1, moved).ok() && moved != dev);
  std::array<std::uint8_t, 32> sak{};
  for (std::size_t i = 0; i < sak.size(); ++i) sak[i] = static_cast<std::uint8_t>(0x80 + i);
  MaintenanceFingerprint member{};
  CHECK(member_maintenance_fingerprint(1, kNet, kSelf, 0x0102030405060708ULL, sak, member).ok());
  CHECK(member == (MaintenanceFingerprint{0x07, 0x6b, 0x62, 0x40, 0x98, 0x56, 0x12, 0x08,
                                           0xf5, 0x9b, 0x85, 0x98, 0x65, 0xe7, 0xa7, 0x1e}));
  CHECK(member_maintenance_fingerprint(1, kNet, kSelf, 0x0102030405060709ULL, sak, moved).ok() &&
        moved != member);
  sak[0] ^= 1;
  CHECK(member_maintenance_fingerprint(1, kNet, kSelf, 0x0102030405060708ULL, sak, moved).ok() &&
        moved != member);
  sak[0] ^= 1;
  const auto site_cert = sdkv1_test::issue(sdkv1_test::sitecert_claims(),
                                            sdkv1_test::site_ca());
  CertClaims site_claims{};
  CHECK(cert_decode(site_cert.view(), site_claims).ok());
  Digest256 actual_sak_kid{};
  CHECK(cert_subject_kid(site_claims, actual_sak_kid).ok());
  MaintenanceFingerprint expected_site{};
  CHECK(member_maintenance_fingerprint(1, sdkv1_test::kNetwork, sdkv1_test::kNode,
                                       sdkv1_test::kSiteId, actual_sak_kid, expected_site).ok());
  MaintenanceFingerprint from_cert{};
  CHECK(member_maintenance_fingerprint_for_site_cert(
            1, sdkv1_test::kNetwork, sdkv1_test::kNode, sdkv1_test::kSiteId,
            site_cert.view(), from_cert).ok());
  CHECK(from_cert == expected_site);
  ScopeDigest cert_hash{};
  sha256(site_cert.view(), cert_hash);
  MaintenanceFingerprint wrong_site{};
  CHECK(member_maintenance_fingerprint(1, sdkv1_test::kNetwork, sdkv1_test::kNode,
                                       sdkv1_test::kSiteId, cert_hash, wrong_site).ok());
  CHECK(from_cert != wrong_site);
  CHECK(member_maintenance_fingerprint_for_site_cert(
            1, sdkv1_test::kNetwork, sdkv1_test::kNode, sdkv1_test::kSiteId + 1,
            site_cert.view(), from_cert).code == StatusCode::InvalidArgument);
  CHECK(dev_maintenance_fingerprint(psk, 2, 0, kSelf, moved).code == StatusCode::InvalidArgument);
  CHECK(member_maintenance_fingerprint(1, 0, kSelf, 0x0102030405060708ULL, sak, moved).code ==
        StatusCode::InvalidArgument);

  char hex[33];
  CHECK(format_fingerprint_hex(dev, hex).ok());
  CHECK(std::strcmp(hex, "427ec20fda94e7a07e3f28e2aa008a1d") == 0);
  MaintenanceFingerprint parsed{};
  const char* text = "427EC20FDA94E7A07E3F28E2AA008A1D";
  CHECK(parse_fingerprint_hex(ByteView{reinterpret_cast<const std::uint8_t*>(text), 32}, parsed)
            .ok());
  CHECK(parsed == dev);  // hex case-insensitive, bytes compared exactly
  CHECK(parse_fingerprint_hex(ByteView{reinterpret_cast<const std::uint8_t*>(text), 31}, parsed)
            .code == StatusCode::InvalidArgument);
  CHECK(parse_fingerprint_hex(ByteView{reinterpret_cast<const std::uint8_t*>(text), 33}, parsed)
            .code == StatusCode::InvalidArgument);
  const char* bad_hex = "427ec20fda94e7a07e3f28e2aa008a1g";
  CHECK(parse_fingerprint_hex(ByteView{reinterpret_cast<const std::uint8_t*>(bad_hex), 32}, parsed)
            .code == StatusCode::InvalidArgument);
  CHECK(parsed == MaintenanceFingerprint{});

  // --- Dev group provider: RAM-only group TX/RX under boot-scoped keys ----
  {
    DevGroupSender sender_a, sender_b;
    CHECK(sender_a.configure(psk, kNet, kSelf, 7).ok());
    CHECK(sender_b.configure(psk, kNet, kPeer, 9).ok());
    TestAead backend_a, backend_b;
    const AeadGcm port_a{&TestAead::seal, &TestAead::open, &backend_a};
    const AeadGcm port_b{&TestAead::seal, &TestAead::open, &backend_b};
    DevGroupProvider a(sender_a, psk, kNet, port_a, kSelf);
    DevGroupProvider b(sender_b, psk, kNet, port_b, kPeer);
    const NodeId group = group_address(1);
    CHECK(a.ready() && b.ready());
    CHECK(a.context_state(SecurityScope::Group, kBroadcastNodeId) == ContextState::Ready);
    CHECK(a.context_state(SecurityScope::Link, kPeer) == ContextState::None);
    CHECK(a.accepts_group_epoch(1) && !a.accepts_group_epoch(2));
    std::uint32_t epoch = 0;
    CHECK(a.tx_epoch(SecurityScope::Group, kBroadcastNodeId, epoch).ok() && epoch == 1);
    CHECK(a.tx_epoch(SecurityScope::Link, kPeer, epoch).code == StatusCode::Unsupported);
    CHECK(a.tx_epoch(SecurityScope::Group, kPeer, epoch).code == StatusCode::Unsupported);

    // Round trip A -> B on the group.
    const SecurityContext tx = group_ctx(kSelf, 7, group);
    std::uint64_t c0 = 0;
    CHECK(a.next_counter(tx, c0).ok() && c0 == 0);
    const char* msg = "hello dev group";
    std::array<std::uint8_t, 64> ct{}, pt{};
    std::array<std::uint8_t, kAeadTagSize> tag{};
    const ByteView plain{reinterpret_cast<const std::uint8_t*>(msg), 15};
    CHECK(a.seal(tx, c0, {}, plain, MutableByteView{ct.data(), 15}, tag).ok());
    const SecurityContext rx = group_ctx(kSelf, 7, group);
    std::array<std::uint8_t, 64> ct7{};
    std::array<std::uint8_t, kAeadTagSize> tag7{};
    std::memcpy(ct7.data(), ct.data(), 15);
    tag7 = tag;
    const MutableByteView pt_view{pt.data(), 15};
    CHECK(b.open(rx, c0, {}, ByteView{ct.data(), 15}, tag, pt_view).ok());
    CHECK(std::memcmp(pt.data(), msg, 15) == 0);
    // The same frame twice is a replay (and the output wipes).
    std::memset(pt.data(), 0xA5, 15);
    CHECK(b.open(rx, c0, {}, ByteView{ct.data(), 15}, tag, pt_view).code ==
          StatusCode::ReplayRejected);
    for (int i = 0; i < 15; ++i) CHECK(pt[i] == 0);
    // A holder of another PSK derives another key: tag invalid.
    keys::Secret other = psk;
    other[0] ^= 1;
    DevGroupSender sender_c;
    CHECK(sender_c.configure(other, kNet, kPeer, 9).ok());
    TestAead backend_c;
    const AeadGcm port_c{&TestAead::seal, &TestAead::open, &backend_c};
    DevGroupProvider c(sender_c, other, kNet, port_c, kPeer);
    CHECK(c.open(rx, c0, {}, ByteView{ct.data(), 15}, tag, pt_view).code ==
          StatusCode::AuthorizationFailed);

    // Counter discipline: unissued and non-monotonic seals refuse.
    std::uint64_t c1 = 0;
    CHECK(a.next_counter(tx, c1).ok() && c1 == 1);
    CHECK(a.seal(tx, 5, {}, plain, MutableByteView{ct.data(), 15}, tag).code ==
          StatusCode::InvalidArgument);
    CHECK(a.seal(tx, c1, {}, plain, MutableByteView{ct.data(), 15}, tag).ok());
    CHECK(a.seal(tx, c0, {}, plain, MutableByteView{ct.data(), 15}, tag).code ==
          StatusCode::InvalidArgument);
    // TX binding: another sender, another epoch, another network refuse.
    CHECK(a.next_counter(group_ctx(kPeer, 7, group), c1).code ==
          StatusCode::AuthorizationFailed);
    SecurityContext bad_epoch = tx;
    bad_epoch.epoch = 2;
    CHECK(a.next_counter(bad_epoch, c1).code == StatusCode::InvalidArgument);
    SecurityContext bad_scope = tx;
    bad_scope.scope = SecurityScope::Link;
    CHECK(a.next_counter(bad_scope, c1).code == StatusCode::Unsupported);

    // Sender reboot (new boot, same PSK): the new key opens, and the old
    // boot's frames are stale even with valid tags.
    CHECK(sender_a.configure(psk, kNet, kSelf, 8).ok());
    const SecurityContext tx8 = group_ctx(kSelf, 8, group);
    std::uint64_t c8 = 0;
    CHECK(a.next_counter(tx8, c8).ok() && c8 == 0);
    CHECK(a.seal(tx8, c8, {}, plain, MutableByteView{ct.data(), 15}, tag).ok());
    CHECK(b.open(tx8, c8, {}, ByteView{ct.data(), 15}, tag, pt_view).ok());
    CHECK(std::memcmp(pt.data(), msg, 15) == 0);
    CHECK(b.open(rx, c0, {}, ByteView{ct7.data(), 15}, tag7, pt_view).code ==
          StatusCode::ReplayRejected);
  }
  // Unconfigured sender: no TX, but RX needs only the PSK.
  {
    DevGroupSender bare;
    TestAead backend;
    const AeadGcm port{&TestAead::seal, &TestAead::open, &backend};
    DevGroupProvider p(bare, psk, kNet, port, kSelf);
    CHECK(!p.ready());
    CHECK(p.context_state(SecurityScope::Group, kBroadcastNodeId) == ContextState::None);
    std::uint32_t epoch = 0;
    CHECK(p.tx_epoch(SecurityScope::Group, kBroadcastNodeId, epoch).code ==
          StatusCode::AuthRequired);
    std::uint64_t counter = 0;
    CHECK(p.next_counter(group_ctx(kSelf, 7, group_address(1)), counter).code ==
          StatusCode::AuthorizationFailed);
  }

  // --- Dev group over the wire layer ------------------------------------
  // Proves the provider against wire::seal_group/open_group: epoch
  // stamping, counter assignment, context binding and the end AAD all
  // come from the wire side here, not the test.
  {
    constexpr NetworkId kWireNet = 0x524c0001;  // Wire v1: low 32 bits only
    DevGroupSender sender_a, sender_b;
    CHECK(sender_a.configure(psk, kWireNet, kSelf, 7).ok());
    CHECK(sender_b.configure(psk, kWireNet, kPeer, 9).ok());
    TestAead backend_a, backend_b;
    const AeadGcm port_a{&TestAead::seal, &TestAead::open, &backend_a};
    const AeadGcm port_b{&TestAead::seal, &TestAead::open, &backend_b};
    DevGroupProvider a(sender_a, psk, kWireNet, port_a, kSelf);
    DevGroupProvider b(sender_b, psk, kWireNet, port_b, kPeer);
    wire::PlainFrame plain{};
    plain.header.type = FrameType::GroupData;
    plain.header.flags = wire::kFlagEndProtected;
    plain.header.delivery = DeliveryClass::Reliable;
    plain.header.hop_remaining = 8;
    plain.header.network = kWireNet;
    plain.header.origin = kSelf;
    plain.header.destination = group_address(1);
    plain.header.previous_hop = kSelf;
    plain.header.next_hop = kSelf;
    plain.header.message = MessageId{7, 1};  // session rides the sender boot
    plain.header.remaining_deadline_ms = 5000;
    plain.header.original_lifetime_ms = 5000;
    plain.header.link_epoch = 1;
    plain.header.end_epoch = 1;
    const char* text = "wire dev group";
    std::memcpy(plain.payload.data(), text, 14);
    plain.payload_size = 14;
    wire::LinkOpenedFrame sealed{};
    CHECK(wire::seal_group(plain, kSelf, a, sealed).ok());
    CHECK(sealed.header.end_epoch == kDevGroupEpoch);
    wire::PlainFrame opened{};
    CHECK(wire::open_group(sealed, b, opened).ok());
    CHECK(opened.payload_size == 14);
    CHECK(std::memcmp(opened.payload.data(), text, 14) == 0);
    // The same wire frame twice is a replay.
    wire::PlainFrame opened2{};
    CHECK(wire::open_group(sealed, b, opened2).code == StatusCode::ReplayRejected);
  }

  // --- Dev discovery scope: Required, fixed generation 1, PSK-derived ----
  {
    DevScopeProvider scope;
    CHECK(!scope.active());
    std::uint32_t generation = 0;
    CHECK(!scope.current_generation(kDevScopeRef, generation));
    CHECK(!scope.accepted_generation(kDevScopeRef, 1, 1000));
    ScopeTag tag{};
    const std::array<std::uint8_t, 8> input{{9, 8, 7}};
    CHECK(scope.scope_tag(kDevScopeRef, 1, ByteView{input.data(), input.size()}, tag).code ==
          StatusCode::AuthRequired);
    CHECK(scope.adopt(psk, 0).code == StatusCode::InvalidArgument);
    CHECK(!scope.active());
    CHECK(scope.adopt(psk, kNet).ok());
    CHECK(scope.active());
    CHECK(scope.current_generation(kDevScopeRef, generation) && generation == 1);
    CHECK(!scope.current_generation(kMemberScopeRef, generation));
    CHECK(scope.accepted_generation(kDevScopeRef, 1, 1000));
    CHECK(!scope.accepted_generation(kDevScopeRef, 2, 1000));
    CHECK(!scope.accepted_generation(kMemberScopeRef, 1, 1000));
    CHECK(scope.scope_tag(kDevScopeRef, 1, ByteView{input.data(), input.size()}, tag).ok());
    CHECK(scope_tag_verify(scope, kDevScopeRef, 1, ByteView{input.data(), input.size()}, tag));
    ScopeTag tampered = tag;
    tampered[0] ^= 1;
    CHECK(!scope_tag_verify(scope, kDevScopeRef, 1, ByteView{input.data(), input.size()},
                            tampered));
    // Another PSK never verifies; another network adopts another key.
    keys::Secret other = psk;
    other[0] ^= 1;
    DevScopeProvider foreign;
    CHECK(foreign.adopt(other, kNet).ok());
    CHECK(!scope_tag_verify(foreign, kDevScopeRef, 1, ByteView{input.data(), input.size()}, tag));
    DevScopeProvider moved;
    CHECK(moved.adopt(psk, kNet + 1).ok());
    ScopeTag moved_tag{};
    CHECK(moved.scope_tag(kDevScopeRef, 1, ByteView{input.data(), input.size()}, moved_tag).ok());
    CHECK(moved_tag != tag);
    scope.wipe();
    CHECK(!scope.active());
    CHECK(!scope.accepted_generation(kDevScopeRef, 1, 1000));
  }
  return 0;
}
