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

#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_dev_session.hpp"
#include "test_sdkv1.hpp"

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
constexpr NetworkId kNet = 0x1122334455667788ULL;
constexpr NodeId kSelf = 0xAABBCCDDEEFF0011ULL;

keys::Secret test_psk() {
  keys::Secret psk{};
  for (std::size_t i = 0; i < psk.size(); ++i) psk[i] = static_cast<std::uint8_t>(i);
  return psk;
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
  return 0;
}
