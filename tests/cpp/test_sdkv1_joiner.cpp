// SDK v1 zero-touch join FSM (plan P3-4 PR 3, sdkv1_joiner.hpp) end to end
// in the two-site simulator (join_sim_network.hpp): device D runs the real
// Joiner + ZtJoinerLink against sites A/B (real JoinProxy + JoinRelayGateway
// + scripted EDHOC Site Authority).
//
// Acceptance covered: V1-J01 (ordered durable join), V1-J04 (deny/avoid +
// second-site selection), V1-J05 (assigned-site binding under overlap),
// V1-J06 (forged site credential: no m3, no write, 24 h avoid), V1-J07
// (forged DevCert: the authority rejects, never discovered), V1-J13
// (replay of old transcripts), the V1-J12 remainder (one broken Allow
// field at a time: no write, 24 h avoid, move on), the V1-J08 FSM fault
// matrix (power cuts at every flash boundary), re-entrancy, the #109
// retransmit path, quiescence, bounds and the resource gates.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "routeloom/crc32.hpp"
#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_joiner.hpp"

#include "join_sim_network.hpp"
#include "test_sdkv1.hpp"

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,      \
                   current.c_str(), #expr);                                          \
      ++failures;                                                                    \
    }                                                                                \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;
using namespace join_sim;
using Bytes = std::vector<std::uint8_t>;

// --- Shared fixtures ------------------------------------------------------------------
constexpr NodeId kDeviceNode = 0x00A1000000001234ULL;
constexpr MacAddress kDeviceMac{{0x02, 0, 0, 0, 0x12, 0x34}};
constexpr std::uint64_t kSiteA = 0x5173000000000042ULL;
constexpr std::uint64_t kSiteB = 0x51730000000000B7ULL;
constexpr NetworkId kNetworkA = (static_cast<NetworkId>(3) << 32U) | 0x0A1B2C3DU;
constexpr NetworkId kNetworkB = (static_cast<NetworkId>(5) << 32U) | 0x0B1B2C3DU;
constexpr NodeId kGatewayA = 0x00A1000000000001ULL;
constexpr NodeId kGatewayB = 0x00A1000000000002ULL;
constexpr std::uint32_t kBootWitness = 0x00001234U;

[[maybe_unused]] const routeloom_test::TestKeyPair& site_b_ca() {
  static const auto key = routeloom_test::test_keypair(0x61);
  return key;
}
[[maybe_unused]] const routeloom_test::TestKeyPair& sak_b() {
  static const auto key = routeloom_test::test_keypair(0x62);
  return key;
}

JoinerConfig device_config() {
  JoinerConfig config{};
  config.node = kDeviceNode;
  config.mac = kDeviceMac;
  config.fw_version = 0x01040000;
  config.capability = kMemberRoleMask;
  config.requested_role = static_cast<std::uint8_t>(kMemberRoleEndpoint);
  return config;
}

IdentityRecord device_identity(std::uint32_t site_b_anchor = 0) {
  IdentityRecord record = identity_record();
  if (site_b_anchor != 0) {
    record.anchors[1] =
        IdentityAnchor{site_b_anchor, AnchorKind::SiteCa, AnchorStatus::Active, site_b_ca().pub};
    record.anchor_count = 2;
  }
  return record;
}

SitePackage site_package(std::uint8_t channel = 6) {
  SitePackage package{};
  package.site_id = kSiteA;
  package.network = kNetworkA;
  package.rs_epoch = 14;
  package.gk_epoch = 203;
  package.gk.fill(0x6B);
  package.role = static_cast<std::uint8_t>(kMemberRoleEndpoint);
  package.channel = channel;
  package.channel_epoch = 9;
  package.gateway_count = 2;
  package.gateways[0] = kGatewayA;
  package.gateways[1] = 0x00A1000000000003ULL;
  package.authority_time_s = 1700000000;
  package.time_uncertainty_ms = 150;
  package.membership_revision = 7;
  return package;
}

SimSiteParams site_a_params(std::uint8_t channel = 6, std::int16_t rssi = -50) {
  SimSiteParams params{};
  params.site_id = kSiteA;
  params.network = kNetworkA;
  params.sak = &sak();
  params.site_ca = &site_ca();
  params.site_ca_id = kSiteCaId;
  params.gateway = kGatewayA;
  params.package = site_package(channel);
  SimProxyParams proxy{};
  proxy.mac = MacAddress{{0x02, 0, 0, 0, 0x0A, 0x01}};
  proxy.node = 0x00A1000000000A01ULL;
  proxy.channel = channel;
  proxy.rssi = rssi;
  proxy.hops = 1;
  params.proxies.push_back(proxy);
  return params;
}

[[maybe_unused]] SimSiteParams site_b_params(std::uint8_t channel = 6,
                                                  std::int16_t rssi = -60) {
  SimSiteParams params = site_a_params(channel, rssi);
  params.site_id = kSiteB;
  params.network = kNetworkB;
  params.sak = &sak_b();
  params.site_ca = &site_ca();  // shared Site CA unless a test overrides
  params.site_ca_id = kSiteCaId;
  params.gateway = kGatewayB;
  params.package = site_package(channel);
  params.package.site_id = kSiteB;
  params.package.network = kNetworkB;
  params.package.gateways[0] = kGatewayB;
  params.proxies[0].mac = MacAddress{{0x02, 0, 0, 0, 0x0B, 0x01}};
  params.proxies[0].node = 0x00A1000000000B01ULL;
  return params;
}

JoinBootInput boot_input() {
  JoinBootInput boot{};
  boot.boot_witness = kBootWitness;
  boot.prepared = true;
  return boot;
}

bool blobs_equal(const ByteBuffer<kRlcw1CertMax>& blob, const Bytes& bytes) {
  if (blob.size != bytes.size()) return false;
  return std::memcmp(blob.bytes.data(), bytes.data(), bytes.size()) == 0;
}

std::uint64_t last_write_at(const LoggingStorage& storage) {
  std::uint64_t at = 0;
  for (const auto& op : storage.log_) {
    if (op.op == 'w') at = op.at;
  }
  return at;
}

std::uint64_t last_read_at(const LoggingStorage& storage) {
  std::uint64_t at = 0;
  for (const auto& op : storage.log_) {
    if (op.op == 'r') at = op.at;
  }
  return at;
}

// --- V1-J01: ordered durable join ----------------------------------------------------------
// One-hop site A allows: authority ledger commit < m4 down < device RLS1
// readback < MemberReady; the RLS1 matches field for field (DAMS included);
// no member behaviour before NVS; no ZT transmission after Ready.
void test_v1_j01_ordered_join() {
  current = "v1-j01";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready = net.pump_until(
      [&] { return net.has_terminal_action(); }, 30000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  CHECK(net.has_terminal_action());
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::MemberReady);
  CHECK(action.joined_now);
  CHECK(dev.joiner.snapshot().state == JoinState::Ready);

  const SimAuthority& authority = net.site(0).authority_;
  CHECK(authority.ledger.approved);
  const std::uint64_t approved = authority.ledger.approved_at;
  const std::uint64_t m4 = authority.ledger.m4_down_at;
  const std::uint64_t wrote = last_write_at(dev.site_storage);
  const std::uint64_t readback = last_read_at(dev.site_storage);
  const std::uint64_t ready_at = net.now();
  CHECK(approved <= m4);
  CHECK(authority.ledger.approved_seq < authority.ledger.m4_seq);
  CHECK(m4 < wrote);
  CHECK(wrote <= readback);
  CHECK(readback <= ready_at);

  CHECK(dev.site_store.has_site());
  const SiteRecord& site = dev.site_store.site();
  CHECK(site.state == SiteState::Member);
  CHECK(site.site_id == kSiteA);
  CHECK(site.network == kNetworkA);
  CHECK(site.assignment_generation == authority.ledger.generation);
  CHECK(site.role == kMemberRoleEndpoint);
  CHECK(site.gk_epoch_current == 203);
  CHECK(site.gk_current == site_package().gk);
  CHECK(site.gk_epoch_next == 0);
  CHECK(site.channel == 6);
  CHECK(site.channel_epoch == 9);
  CHECK(site.gateway_count == 2);
  CHECK(site.gateways[0] == kGatewayA);
  CHECK(site.rs_epoch_floor == 0);  // fresh join keeps no floor
  CHECK(site.boot_witness == kBootWitness);
  CHECK(blobs_equal(site.member_cert, authority.ledger.member_cert_bytes));
  CHECK(site.dams.size() == authority.ledger.dams.size());
  CHECK(std::memcmp(site.dams.data(), authority.ledger.dams.data(), site.dams.size()) == 0);
  CHECK(action.commit_seq == dev.site_store.commit_seq());
  CHECK(action.rs_epoch_to_fetch == 14);

  // No ZT transmission after Ready: the device goes quiet on the air.
  const std::uint32_t sends = dev.radio.sends;
  net.clear_terminal();
  for (int i = 0; i < 20; ++i) {
    if (!net.round()) break;
  }
  CHECK(dev.radio.sends == sends);
  CHECK(dev.joiner.quiescent());
  current.clear();
}

// All DISCOVER bodies the device broadcast, oldest first.
std::vector<ZtDiscoverBody> discovers(const JoinSimNetwork& net) {
  std::vector<ZtDiscoverBody> out;
  for (const auto& bytes : net.air_history()) {
    autonomy::Rld1Envelope env{};
    ZtDiscoverBody body{};
    if (!autonomy::rld1_decode(view(bytes), env)) continue;
    if (env.kind != FrameType::Discover) continue;
    if (!zt_discover_body_decode(ByteView{env.body.data(), env.body_size}, body)) continue;
    out.push_back(body);
  }
  return out;
}

bool flash_contains(LoggingStorage& storage, const Bytes& needle) {
  if (needle.empty()) return false;
  for (std::uint8_t slot = 0; slot < 2; ++slot) {
    const auto& bytes = storage.inner_.slot(slot);
    for (std::size_t i = 0; i + needle.size() <= bytes.size(); ++i) {
      if (std::memcmp(bytes.data() + i, needle.data(), needle.size()) == 0) return true;
    }
  }
  return false;
}

// --- V1-J04: deny/avoid, then the second site -----------------------------------------
// Strong A denies (not-here), B allows: A is avoided for 6 h without a
// single byte of its credentials landing in NVS, B is joined, and later
// DISCOVERs carry A's hint in the avoid slots.
void test_v1_j04_deny_then_second_site() {
  current = "v1-j04-select";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params(6, -40);  // stronger: attempted first
  a.policy.verdict = JoinVerdict::DenyNotHere;
  a.package.gk.fill(0xAA);
  SimSiteParams b = site_b_params(6, -60);
  b.package.gk.fill(0xBB);
  net.add_site(a);
  net.add_site(b);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteB);
  CHECK(net.site(0).authority_.exchanges == 1);  // A: exactly one attempt
  CHECK(net.site(1).authority_.ledger.approved);
  CHECK(!net.site(0).authority_.ledger.approved);

  // Nothing of A's credentials reached the flash: no GK, no member cert.
  Bytes a_gk(32, 0xAA);
  CHECK(!flash_contains(dev.site_storage, a_gk));
  CHECK(!flash_contains(dev.site_storage, net.site(0).authority_.ledger.member_cert_bytes));
  // ... while B's record is fully present.
  Bytes b_gk(32, 0xBB);
  CHECK(flash_contains(dev.site_storage, b_gk));

  // Post-deny DISCOVERs pack A's hint into the avoid slots (nonzero,
  // distinct, at most two, front-packed).
  const std::uint32_t hint_a = join_site_hint(kSiteA);
  bool saw_avoid = false;
  for (const auto& body : discovers(net)) {
    const std::uint32_t h0 = body.avoid_site_hints[0];
    const std::uint32_t h1 = body.avoid_site_hints[1];
    CHECK(h0 == 0 || h0 != h1);
    CHECK(h1 == 0 || h0 != 0);
    if (h0 == hint_a || h1 == hint_a) saw_avoid = true;
  }
  CHECK(saw_avoid);
  current.clear();
}

// The 6 h hold itself: single denying site, no second chance before the
// hold lapses, a fresh attempt right after.
void test_v1_j04_deny_hold_six_hours() {
  current = "v1-j04-hold";
  JoinerConfig config = device_config();
  config.scan_channels = {{6, 1, 11}};
  JoinSimNetwork net(config, device_identity());
  SimSiteParams a = site_a_params();
  a.policy.verdict = JoinVerdict::DenyNotHere;
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.site(0).authority_.exchanges == 1; }, 30000));
  // The hold starts when the device consumes the deny, not when m4 is sent.
  CHECK(net.pump_until([&] { return dev.joiner.snapshot().counters.denies == 1; }, 30000));
  const std::uint64_t denied_at = net.now();
  CHECK(dev.site_storage.writes() == 0);
  // Just before the hold lapses: scans run, A is never re-attempted.
  net.skip_to(denied_at + kJoinAvoidNotHereMs - 60000);
  CHECK(!net.pump_until([&] { return net.site(0).authority_.exchanges == 2; }, 5000));
  CHECK(net.site(0).authority_.exchanges == 1);
  CHECK(dev.site_storage.writes() == 0);
  // Past the hold: the next scan attempts A again with fresh crypto.
  net.skip_to(denied_at + kJoinAvoidNotHereMs + 60000);
  CHECK(net.pump_until([&] { return net.site(0).authority_.exchanges == 2; }, 120000));
  CHECK(net.site(0).authority_.exchanges == 2);
  CHECK(net.error() == StatusCode::Ok);
  current.clear();
}

// --- V1-J05: the assigned site binds under overlap ----------------------------------
// D is assigned to B only. A answers first and stronger with pending (then
// not-here); B allows. Only B ever holds a durable member for D, while A
// lists the verified D as discovered.
void test_v1_j05_assigned_site_binds() {
  current = "v1-j05";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params(6, -30);
  a.policy.verdict = JoinVerdict::PendingAssignment;
  a.policy.retry_after_s = 60;
  SimSiteParams b = site_b_params(6, -60);
  net.add_site(a);
  net.add_site(b);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 90000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteB);
  // A saw the verified device (m3) first, but holds no approval for it.
  const SimAuthority& auth_a = net.site(0).authority_;
  CHECK(auth_a.exchanges == 1);
  CHECK(auth_a.ledger.discovered.size() == 1);
  CHECK(auth_a.ledger.discovered[0] == kDeviceNode);
  CHECK(!auth_a.ledger.approved);
  CHECK(net.site(1).authority_.ledger.approved);
  current.clear();
}

// --- V1-J06: forged site credentials ----------------------------------------------------
// A bad m2 (SiteCert signature/issuer/type/kid, responder signature, or an
// inactive anchor) draws no m3 and no DevCert out, writes nothing, and
// parks the key for 24 h.
struct J06Case {
  const char* name;
  ByteBuffer<kRlcw1CertMax> cert;  // presented EAD credential (empty = own)
  bool use_cert{false};
  const std::array<std::uint8_t, 32>* sign_priv{nullptr};  // m2 signer override
};

std::vector<J06Case> j06_cases(const ByteBuffer<kRlcw1CertMax>& site_b_cert) {
  std::vector<J06Case> cases;
  CertClaims good = sitecert_claims(kNetworkA);
  good.subject = kSiteA;
  // Wrong SiteCert signature (claims name our CA, key does not).
  {
    J06Case c{};
    c.name = "bad-signature";
    c.cert = issue(good, other_key());
    c.use_cert = true;
    cases.push_back(c);
  }
  // Unknown issuer.
  {
    J06Case c{};
    c.name = "bad-issuer";
    CertClaims claims = good;
    claims.issuer = 0xDEAD000000000001ULL;
    c.cert = issue(claims, other_key());
    c.use_cert = true;
    cases.push_back(c);
  }
  // Wrong certificate type.
  {
    J06Case c{};
    c.name = "bad-type";
    CertClaims claims = devcert_claims(kDeviceNode);
    c.cert = issue(claims, device_ca());
    c.use_cert = true;
    cases.push_back(c);
  }
  // kid/cnf mismatch: B's certificate under A's kid.
  {
    J06Case c{};
    c.name = "bad-kid";
    c.cert = site_b_cert;
    c.use_cert = true;
    cases.push_back(c);
  }
  // Genuine certificate, forged responder signature.
  {
    J06Case c{};
    c.name = "bad-responder-signature";
    c.sign_priv = &other_key().priv;
    cases.push_back(c);
  }
  return cases;
}

void test_v1_j06_forged_site_credential() {
  current = "v1-j06";
  // Site B's certificate for the kid-mismatch case.
  CertClaims claims_b{};
  claims_b.type = CertType::Site;
  claims_b.issuer = kSiteCaId;
  claims_b.subject = kSiteB;
  claims_b.pubkey = sak_b().pub;
  claims_b.network_low32 = static_cast<std::uint32_t>(kNetworkB);
  claims_b.site_epoch = static_cast<std::uint32_t>(kNetworkB >> 32U);
  claims_b.usage = 1;
  claims_b.serial = 9;
  const ByteBuffer<kRlcw1CertMax> site_b_cert = issue(claims_b, site_ca());
  for (const J06Case& j06 : j06_cases(site_b_cert)) {
    JoinSimNetwork net(device_config(), device_identity());
    SimSiteParams a = site_a_params();
    if (j06.use_cert) a.policy.credential_cert = &j06.cert;
    if (j06.sign_priv != nullptr) a.policy.sign_priv = j06.sign_priv;
    net.add_site(a);
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until([&] { return net.site(0).authority_.m1_seen == 1; }, 30000));
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().counters.auth_failures == 1; }, 30000));
    const SimAuthority& authority = net.site(0).authority_;
    CHECK(authority.last_m3.empty());  // no m3, hence no DevCert EAD
    CHECK(dev.site_storage.writes() == 0);
    CHECK(dev.joiner.snapshot().counters.m1_sent == 1);
    // 24 h avoid on the observed key: no re-attempt before the hold lapses.
    const std::uint64_t failed_at = net.now();
    net.skip_to(failed_at + kJoinAvoidBlockedMs - 60000);
    CHECK(!net.pump_until([&] { return net.site(0).authority_.m1_seen == 2; }, 5000));
    CHECK(net.site(0).authority_.m1_seen == 1);
    CHECK(dev.site_storage.writes() == 0);
    net.skip_to(failed_at + kJoinAvoidBlockedMs + 60000);
    CHECK(net.pump_until([&] { return net.site(0).authority_.m1_seen == 2; }, 120000));
    CHECK(net.error() == StatusCode::Ok);
    if (failures != 0) {
      std::fprintf(stderr, "  while in J06 case %s\n", j06.name);
      break;
    }
  }
  current.clear();
}

// Re-splices a committed RLI1 slot after byte surgery: the store encoder
// refuses structurally invalid records, so these tests commit a valid one
// and patch the bytes (fixing the CRC the same way the encoder does).
void patch_identity_slot(LoggingStorage& storage, std::size_t offset,
                         const Bytes& bytes) {
  auto& slot = storage.inner_.slot(0);
  const std::size_t used =
      (static_cast<std::size_t>(slot[6]) << 8U) | static_cast<std::size_t>(slot[7]);
  CHECK(offset + bytes.size() + 4 <= used);
  std::memcpy(slot.data() + offset, bytes.data(), bytes.size());
  const std::uint32_t crc =
      crc32_iso_hdlc(ByteView{slot.data(), used - 4});
  slot[used - 4] = static_cast<std::uint8_t>((crc >> 24U) & 0xFFU);
  slot[used - 3] = static_cast<std::uint8_t>((crc >> 16U) & 0xFFU);
  slot[used - 2] = static_cast<std::uint8_t>((crc >> 8U) & 0xFFU);
  slot[used - 1] = static_cast<std::uint8_t>(crc & 0xFFU);
}

// An inactive Site CA anchor never even sends m1 (local gate, no airtime).
void test_v1_j06_inactive_anchor() {
  current = "v1-j06-anchor";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  patch_identity_slot(dev.identity_storage, 169, Bytes{2});  // anchor status
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Stopped; }, 10000));
  CHECK(dev.radio.sends == 0);
  CHECK(dev.joiner.snapshot().counters.m1_sent == 0);
  current.clear();
}

// --- V1-J07: forged DevCert ----------------------------------------------------------------
// The device's structural check passes (it holds no Device CA key), but the
// real authority rejects the m3: never discovered, reason counted, nothing
// stored. Kept apart from the locally-invalid RLI1 case below.
void test_v1_j07_forged_devcert() {
  current = "v1-j07";
  // Same subject/cnf, wrong issuer key: structurally fine, unverifiable.
  IdentityRecord identity = device_identity();
  identity.devcert = issue(devcert_claims(kDeviceNode), other_key());
  JoinSimNetwork net(device_config(), identity);
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.site(0).authority_.devcert_rejects() == 1; },
                       30000));
  const SimAuthority& authority = net.site(0).authority_;
  CHECK(authority.ledger.discovered.empty());
  CHECK(!authority.ledger.approved);
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.transient_failures >= 1; }, 30000));
  CHECK(dev.site_storage.writes() == 0);
  CHECK(!dev.site_store.has_site());
  CHECK(net.error() == StatusCode::Ok);
  current.clear();
}

// A structurally invalid RLI1 (DevCert bound to another node) never sends.
void test_v1_j07_invalid_rli1() {
  current = "v1-j07-rli1";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  // Rewrite the node id so the DevCert no longer binds to it.
  const NodeId other = 0x00A1000000009999ULL;
  Bytes node_bytes(8, 0);
  for (int i = 0; i < 8; ++i) {
    node_bytes[i] = static_cast<std::uint8_t>((other >> (56 - 8 * i)) & 0xFFU);
  }
  patch_identity_slot(dev.identity_storage, 16, node_bytes);
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Stopped; }, 10000));
  CHECK(dev.radio.sends == 0);
  CHECK(net.site(0).authority_.m1_seen == 0);
  current.clear();
}

// --- V1-J03: pending, then a late allow ----------------------------------------------------
// A waits out the KGuard timeout (pending + retry), then allows: the device
// retries with a full fresh EDHOC (no Resume phase anywhere) and joins.
void test_v1_j03_pending_then_allow() {
  current = "v1-j03";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params();
  a.policy.verdict = JoinVerdict::PendingAssignment;
  a.policy.retry_after_s = 30;
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.pendings == 1; }, 30000));
  CHECK(dev.site_storage.writes() == 0);
  CHECK(!net.has_terminal_action());
  // The late decision lands before the retry: the next attempt joins.
  AuthorityPolicy allow{};
  allow.verdict = JoinVerdict::Allow;
  net.site(0).set_policy(allow);
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 120000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteA);
  CHECK(net.site(0).up_phase_rejects == 0);  // every up rode phase 4
  CHECK(net.site(0).authority_.exchanges == 2);
  current.clear();
}

// --- V1-J13: replay resistance ------------------------------------------------------------------
// An old m2, framed for the live attempt, fails authentication: no m3, no
// write, no Ready. The following fresh attempt still joins (a fresh m2 to
// a re-sent m1 is legitimate).
void test_v1_j13_old_m2_rejected() {
  current = "v1-j13-m2";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params();
  a.policy.verdict = JoinVerdict::PendingAssignment;
  a.policy.retry_after_s = 30;
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.pendings == 1; }, 30000));
  const Bytes m2_old = net.site(0).authority_.last_m2;
  const Bytes m3_old = net.site(0).authority_.last_m3;
  CHECK(!m2_old.empty());
  CHECK(!m3_old.empty());
  // Attempt 2 opens: inject the old m2 the moment its m1 is out, ahead of
  // the genuine m2 still travelling down.
  CHECK(net.pump_until(
      [&] {
        return dev.joiner.snapshot().state == JoinState::WaitM2 &&
               dev.joiner.snapshot().counters.m1_sent == 2;
      },
      120000));
  const SimProxyParams proxy = a.proxies[0];
  CHECK(net.inject_down_chunked(proxy, m2_old, 2));
  CHECK(net.pump_until(
      [&] {
        return dev.joiner.snapshot().counters.transient_failures >= 1;
      },
      30000));
  CHECK(net.site(0).authority_.last_m3 == m3_old);  // no new m3 went out
  CHECK(dev.site_storage.writes() == 0);
  CHECK(!net.has_terminal_action());
  // The genuine m2 (now stale) cannot revive the attempt either.
  CHECK(net.pump_until(
      [&] {
        const JoinState s = dev.joiner.snapshot().state;
        return s == JoinState::Select || s == JoinState::Backoff;
      },
      30000));
  // A fresh attempt with a fresh m2 joins normally.
  AuthorityPolicy allow{};
  allow.verdict = JoinVerdict::Allow;
  net.site(0).set_policy(allow);
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 180000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  }
  current.clear();
}

// Same for an old m4: it authenticates against nothing and dies quietly.
void test_v1_j13_old_m4_rejected() {
  current = "v1-j13-m4";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params();
  a.policy.verdict = JoinVerdict::PendingAssignment;
  a.policy.retry_after_s = 30;
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.pendings == 1; }, 30000));
  const Bytes m4_old = net.site(0).authority_.last_m4;
  CHECK(!m4_old.empty());
  CHECK(net.pump_until(
      [&] {
        return dev.joiner.snapshot().state == JoinState::WaitM4 &&
               dev.joiner.snapshot().counters.m1_sent == 2;
      },
      120000));
  CHECK(net.inject_down(a.proxies[0], m4_old, 4));
  CHECK(net.pump_until(
      [&] {
        return dev.joiner.snapshot().counters.transient_failures >= 1;
      },
      30000));
  CHECK(dev.site_storage.writes() == 0);
  CHECK(!net.has_terminal_action());
  AuthorityPolicy allow{};
  allow.verdict = JoinVerdict::Allow;
  net.site(0).set_policy(allow);
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 180000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  current.clear();
}

// Foreign and stale down frames die at the gate: another proxy, another
// nonce, another network, the Resume phase, a wrong step, an oversize
// body. The live attempt is undisturbed and joins.
void test_v1_j13_foreign_frames_dropped() {
  current = "v1-j13-foreign";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  net.add_site(site_b_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  const SimProxyParams proxy_a = site_a_params().proxies[0];
  const SimProxyParams proxy_b = site_b_params().proxies[0];
  const JoinSnapshot before = dev.joiner.snapshot();
  const std::uint32_t drops = before.counters.rx_dropped;
  Bytes body(32, 0x55);
  const MacAddress stranger{{0x02, 0, 0, 0, 0xEE, 0xEE}};
  JoinNonce zero{};
  CHECK(net.inject_down_raw(proxy_a, body, FrameType::BootstrapAuth, &stranger));
  CHECK(net.inject_down_raw(proxy_a, body, FrameType::BootstrapAuth, nullptr, &zero));
  CHECK(net.inject_down_raw(proxy_a, body, FrameType::BootstrapAuth, nullptr, nullptr,
                            0xDEADBEEFU, true));
  // A live-framed Resume-phase object and a wrong-step object.
  JoinAuthObject resume{};
  resume.phase = JoinAuthPhase::Resume;
  resume.step = 2;
  resume.message = view(body);
  JoinObjectBytes encoded{};
  std::size_t written = 0;
  CHECK(join_object_encode(resume, MutableByteView{encoded.bytes.data(), encoded.bytes.size()},
                           written));
  CHECK(net.inject_down_raw(proxy_a, Bytes(encoded.bytes.begin(), encoded.bytes.begin() + written),
                            FrameType::BootstrapAuth));
  JoinAuthObject stale{};
  stale.phase = JoinAuthPhase::EdhocMessage;
  stale.step = 4;  // m4 bytes while waiting for m2
  stale.message = view(body);
  written = 0;
  CHECK(join_object_encode(stale, MutableByteView{encoded.bytes.data(), encoded.bytes.size()},
                           written));
  CHECK(net.inject_down_raw(proxy_a, Bytes(encoded.bytes.begin(), encoded.bytes.begin() + written),
                            FrameType::BootstrapAuth));
  // An oversize body that no RLD1 frame can carry, fed raw.
  Bytes huge(200, 0x11);
  JoinRxMeta meta{};
  meta.source = proxy_a.mac;
  meta.destination = kDeviceMac;
  meta.channel = dev.channel;
  meta.rssi = -50;
  CHECK(dev.joiner.on_rld1_rx(meta, view(huge), net.now()).ok());
  CHECK(net.inject_down_raw(proxy_b, body, FrameType::BootstrapAuth));
  const JoinSnapshot after = dev.joiner.snapshot();
  CHECK(after.state == before.state);
  CHECK(after.counters.rx_dropped > drops);
  CHECK(after.counters.m2_ok == before.counters.m2_ok);
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 60000));
  CHECK(net.error() == StatusCode::Ok);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  }
  current.clear();
}

// The authority side: an old m3 against a fresh session authenticates
// against nothing and approves nothing.
void test_v1_j13_old_m3_rejected_by_authority() {
  current = "v1-j13-m3";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params();
  a.policy.verdict = JoinVerdict::PendingAssignment;
  a.policy.retry_after_s = 30;
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.pendings == 1; }, 30000));
  SimAuthority& authority = net.site(0).authority_;
  const Bytes m3_old = authority.last_m3;
  CHECK(!m3_old.empty());
  CHECK(net.pump_until([&] { return authority.m1_seen == 2; }, 120000));
  const std::uint32_t exchanges = authority.exchanges;
  const std::size_t discovered = authority.ledger.discovered.size();
  // This ends exchange 2's session too (the test stops pumping here).
  const AuthorityDown answer = authority.on_up(3, view(m3_old), net.now());
  CHECK(!answer.has || answer.step == 5);  // silence or an error, never an m4
  CHECK(authority.exchanges == exchanges);
  CHECK(authority.ledger.discovered.size() == discovered);
  current.clear();
}

// Real EDHOC error bytes from a scratch responder (garbage m1 in, error
// out — the composition libedhoc does support).
Bytes make_edhoc_error() {
  CertClaims claims{};
  claims.type = CertType::Site;
  claims.issuer = kSiteCaId;
  claims.subject = kSiteA;
  claims.pubkey = sak().pub;
  claims.network_low32 = static_cast<std::uint32_t>(kNetworkA);
  claims.site_epoch = static_cast<std::uint32_t>(kNetworkA >> 32U);
  claims.usage = 1;
  claims.serial = 7;
  const ByteBuffer<kRlcw1CertMax> cert = issue(claims, site_ca());
  Digest256 kid{};
  CHECK(cert_subject_kid(claims, kid));
  SimAuthorityCreds creds(cert, kid, sak().priv, device_ca().pub);
  SimAuthorityEad ead(creds);
  SimEntropy entropy(0xE2202);
  edhoc::Session session;
  edhoc::SessionConfig config{};
  config.role = edhoc::Role::Responder;
  config.method = edhoc::Method::SignatureSignature;
  const std::array<std::uint8_t, 4> conn{{1, 2, 3, 4}};
  config.connection_id = ByteView{conn.data(), conn.size()};
  config.credentials = &creds;
  config.ead = &ead;
  config.random = &sim_random;
  config.random_ctx = &entropy;
  CHECK(session.begin(config).ok());
  const std::array<std::uint8_t, 10> garbage{{9, 9, 9, 9, 9, 9, 9, 9, 9, 9}};
  CHECK(!session.process_message_1(ByteView{garbage.data(), garbage.size()}));
  std::array<std::uint8_t, 64> buffer{};
  std::size_t length = 0;
  const std::int32_t suites[] = {2};  // the composition libedhoc supports here
  CHECK(session.compose_error(2, suites, 1, MutableByteView{buffer.data(), buffer.size()},
                              length)
            .ok());
  session.end();
  return Bytes(buffer.begin(), buffer.begin() + length);
}

// A live-framed EDHOC error fails the attempt fast (no timeout wait),
// transiently, and the next attempt joins.
void test_v1_j13_edhoc_error_transient() {
  current = "v1-j13-error";
  const Bytes error = make_edhoc_error();
  CHECK(!error.empty());
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  CHECK(net.inject_down(site_a_params().proxies[0], error, 5));
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.transient_failures == 1; },
      30000));
  CHECK(dev.joiner.snapshot().counters.timeouts == 0);  // fast, not a timeout
  CHECK(net.site(0).authority_.last_m3.empty());
  CHECK(dev.site_storage.writes() == 0);
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 120000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  current.clear();
}

// --- V1-J12 remainder: one broken Allow field at a time ----------------------------------
// Every mutation below fails closed through MalformedResult: nothing is
// written, the key is avoided for 24 h, and the device moves on. Member
// certificate fields mutate via re-issued (CA-signed, binding-broken)
// certificates; package fields mutate on the encoded bytes, since the
// encoder itself refuses to emit an invalid package.
struct J12Case {
  const char* name;
  ByteBuffer<kRlcw1CertMax> cert;  // replacement MemberCert (empty = none)
  std::function<void(Bytes&)> mutate_bytes;
};

std::size_t j12_package_at(const Bytes& encoded) {
  const std::size_t cert_len =
      (static_cast<std::size_t>(encoded[12]) << 8U) | encoded[13];
  return 14 + cert_len;
}

std::vector<J12Case> j12_cases() {
  std::vector<J12Case> cases;
  const auto member = [](CertClaims claims) {
    J12Case c{};
    c.cert = issue(claims, sak());
    return c;
  };
  CertClaims base = membercert_claims(3, kNetworkA, kDeviceNode, device_key().pub);
  base.issuer = kSiteA;
  {  // member subject
    CertClaims claims = base;
    claims.subject = kDeviceNode + 1;
    J12Case c = member(claims);
    c.name = "member-sub";
    cases.push_back(c);
  }
  {  // member cnf
    CertClaims claims = base;
    claims.pubkey = other_key().pub;
    J12Case c = member(claims);
    c.name = "member-cnf";
    cases.push_back(c);
  }
  {  // member issuer
    CertClaims claims = base;
    claims.issuer = kSiteA + 1;
    J12Case c = member(claims);
    c.name = "member-iss";
    cases.push_back(c);
  }
  {  // member network
    CertClaims claims = base;
    claims.network = kNetworkA + 1;  // structurally valid, binding broken
    J12Case c = member(claims);
    c.name = "member-network";
    cases.push_back(c);
  }
  {  // member generation 0 (bytes: the issuer refuses to sign one)
    J12Case c{};
    c.name = "member-generation-0";
    c.mutate_bytes = [](Bytes& encoded) {
      const std::size_t cert_len =
          (static_cast<std::size_t>(encoded[12]) << 8U) | encoded[13];
      const std::size_t cert_at = 14;
      // Walk to the private array's generation item, checking every
      // expected prefix byte so an encoding change fails loudly.
      static const std::array<std::uint8_t, 5> label{{0x3A, 0x00, 0x01, 0x00, 0x00}};
      std::size_t at = cert_at;
      bool found = false;
      for (; at + label.size() <= cert_at + cert_len; ++at) {
        if (std::memcmp(encoded.data() + at, label.data(), label.size()) == 0) {
          found = true;
          break;
        }
      }
      CHECK(found);
      if (!found) return;
      at += label.size();
      CHECK(at + 13 <= cert_at + cert_len);
      if (at + 13 > cert_at + cert_len) return;
      CHECK(encoded[at] == 0x86);       // 6-item private array
      CHECK(encoded[at + 1] == 0x03);   // Member type
      CHECK(encoded[at + 2] == 0x1B);   // u64 network
      CHECK(encoded[at + 11] == 0x01);  // endpoint role
      CHECK(encoded[at + 12] == 0x01);  // generation 1 (the ledger's first)
      encoded[at + 12] = 0x00;
    };
    cases.push_back(c);
  }
  const auto package = [](const char* name, std::function<void(Bytes&, std::size_t)> mutate) {
    J12Case c{};
    c.name = name;
    c.mutate_bytes = [mutate](Bytes& encoded) {
      const std::size_t at = j12_package_at(encoded);
      CHECK(at + kSitePackageSize <= encoded.size());
      mutate(encoded, at);
    };
    return c;
  };
  cases.push_back(package("package-site", [](Bytes& encoded, std::size_t at) {
    encoded[at + 4] ^= 0xFF;
  }));
  cases.push_back(package("package-network", [](Bytes& encoded, std::size_t at) {
    encoded[at + 16] = 0;
    encoded[at + 17] = 0;
    encoded[at + 18] = 0;
    encoded[at + 19] = 0;
  }));
  cases.push_back(package("package-role", [](Bytes& encoded, std::size_t at) {
    encoded[at + 61] = static_cast<std::uint8_t>(kMemberRoleRelay);
  }));
  cases.push_back(package("package-channel-0", [](Bytes& encoded, std::size_t at) {
    encoded[at + 60] = 0;
  }));
  cases.push_back(package("package-channel-15", [](Bytes& encoded, std::size_t at) {
    encoded[at + 60] = 15;
  }));
  cases.push_back(package("package-gk-zero", [](Bytes& encoded, std::size_t at) {
    for (std::size_t i = 0; i < 32; ++i) encoded[at + 28 + i] = 0;
  }));
  cases.push_back(package("package-gateway-count-0", [](Bytes& encoded, std::size_t at) {
    encoded[at + 62] = 0;
  }));
  cases.push_back(package("package-gateway-dup", [](Bytes& encoded, std::size_t at) {
    for (std::size_t i = 0; i < 8; ++i) encoded[at + 76 + i] = encoded[at + 68 + i];
  }));
  cases.push_back(J12Case{"reserved-nonzero", {},
                           [](Bytes& encoded) {
                             encoded[2] = 1;  // result head reserved
                           }});
  cases.push_back(J12Case{"length-mismatch", {},
                           [](Bytes& encoded) {
                             encoded[8] ^= 0xFF;  // body length
                             encoded[9] ^= 0xFF;
                           }});
  cases.push_back(J12Case{"truncated", {}, [](Bytes& encoded) {
                             encoded.resize(encoded.size() - 10);
                           }});
  return cases;
}

void test_v1_j12_broken_allow_matrix() {
  current = "v1-j12";
  const std::vector<J12Case> cases = j12_cases();
  for (const J12Case& j12 : cases) {
    JoinerConfig config = device_config();
    config.scan_channels = {{6, 1, 11}};
    JoinSimNetwork net(config, device_identity());
    SimSiteParams a = site_a_params();
    if (j12.cert.size != 0) {
      const ByteBuffer<kRlcw1CertMax> cert = j12.cert;  // hook-owned copy
      a.policy.mutate_result = [cert](JoinResult& result) mutable {
        result.member_cert = ByteView{cert.bytes.data(), cert.size};
      };
    }
    if (j12.mutate_bytes) a.policy.mutate_result_bytes = j12.mutate_bytes;
    net.add_site(a);
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().counters.malformed == 1; }, 30000));
    CHECK(dev.site_storage.writes() == 0);
    CHECK(!dev.site_store.has_site());
    CHECK(net.site(0).authority_.m1_seen == 1);
    const std::uint64_t failed_at = net.now();
    net.skip_to(failed_at + kJoinAvoidBlockedMs - 60000);
    CHECK(!net.pump_until([&] { return net.site(0).authority_.m1_seen == 2; }, 5000));
    net.skip_to(failed_at + kJoinAvoidBlockedMs + 60000);
    CHECK(net.pump_until([&] { return net.site(0).authority_.m1_seen == 2; }, 120000));
    CHECK(net.error() == StatusCode::Ok);
    if (failures != 0) {
      std::fprintf(stderr, "  while in J12 case %s\n", j12.name);
      break;
    }
  }
  current.clear();
}

// A granted relay role the endpoint-only hardware cannot run is refused
// before commit (and a broken A yields to a clean B).
void test_v1_j12_role_and_move_on() {
  current = "v1-j12-role";
  JoinerConfig config = device_config();
  config.capability = static_cast<std::uint32_t>(kMemberRoleEndpoint);
  JoinSimNetwork net(config, device_identity());
  SimSiteParams a = site_a_params(6, -40);
  CertClaims claims = membercert_claims(3, kNetworkA, kDeviceNode, device_key().pub);
  claims.issuer = kSiteA;
  claims.role = static_cast<std::uint8_t>(kMemberRoleRelay);
  const ByteBuffer<kRlcw1CertMax> relay_cert = issue(claims, sak());
  a.policy.mutate_result = [relay_cert](JoinResult& result) mutable {
    result.member_cert = ByteView{relay_cert.bytes.data(), relay_cert.size};
    result.site_package.role = static_cast<std::uint8_t>(kMemberRoleRelay);
  };
  SimSiteParams b = site_b_params(6, -60);
  net.add_site(a);
  net.add_site(b);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 90000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteB);
  CHECK(dev.joiner.snapshot().counters.malformed == 1);
  CHECK(net.site(0).authority_.exchanges == 1);
  current.clear();
}

// A2 fail closed: a strict identity denies the Allow with or without a
// ticket (P3-5 stays unpinned), through MalformedResult, never a record.
void test_v1_j12_strict_assignment() {
  current = "v1-j12-a2";
  for (int with_ticket = 0; with_ticket < 2; ++with_ticket) {
    JoinerConfig config = device_config();
    config.scan_channels = {{6, 1, 11}};
    JoinSimNetwork net(config, identity_record(true));
    SimSiteParams a = site_a_params();
    if (with_ticket != 0) {
      a.policy.mutate_result = [](JoinResult& result) {
        static const std::array<std::uint8_t, 8> ticket{1, 2, 3, 4, 5, 6, 7, 8};
        result.assignment_ticket = ByteView{ticket.data(), ticket.size()};
      };
    }
    net.add_site(a);
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().counters.malformed == 1; }, 30000));
    CHECK(dev.site_storage.writes() == 0);
    CHECK(!dev.site_store.has_site());
    const std::uint64_t failed_at = net.now();
    net.skip_to(failed_at + kJoinAvoidBlockedMs - 60000);
    CHECK(!net.pump_until([&] { return net.site(0).authority_.m1_seen == 2; }, 5000));
    net.skip_to(failed_at + kJoinAvoidBlockedMs + 60000);
    CHECK(net.pump_until([&] { return net.site(0).authority_.m1_seen == 2; }, 120000));
    CHECK(net.error() == StatusCode::Ok);
    if (failures != 0) break;
  }
  current.clear();
}

// --- V1-J08: power cuts at every flash boundary -------------------------------------------
// A cut during commit (or before it) followed by a restart: the device
// rejoins cleanly with the same generation (the ledger re-issues the same
// MemberCert — generations never grow spuriously), or adopts the landed
// record without another approval. Nothing half-written is ever trusted.
std::size_t j08_used_len() {
  JoinerConfig config = device_config();
  config.scan_channels = {{6, 1, 11}};
  JoinSimNetwork net(config, device_identity());
  net.add_site(site_a_params());
  CHECK(net.device().joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  const auto& slot = net.device().site_storage.inner_.slot(0);
  return (static_cast<std::size_t>(slot[6]) << 8U) | slot[7];
}

void j08_commit_cut_case(std::size_t cut_call, std::size_t cut_bytes) {
  JoinerConfig config = device_config();
  config.scan_channels = {{6, 1, 11}};
  JoinSimNetwork net(config, device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  dev.site_storage.inner_.cut_call = cut_call;
  dev.site_storage.inner_.cut_bytes = cut_bytes;
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  // Run until the commit hits the cut (no terminal action may precede it).
  CHECK(net.pump_until(
      [&] {
        return dev.joiner.snapshot().counters.store_failures >= 1 ||
               net.has_terminal_action();
      },
      30000));
  CHECK(!net.has_terminal_action());
  CHECK(dev.joiner.snapshot().counters.store_failures == 1);
  const Bytes first_cert = net.site(0).authority_.ledger.member_cert_bytes;
  CHECK(!first_cert.empty());
  // Power dies here: restart on the same flash image and rejoin.
  net.restart_device(config, 0xC07EE);
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 120000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) return;
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev2.site_store.has_site());
  CHECK(dev2.site_store.site().site_id == kSiteA);
  CHECK(dev2.site_store.site().assignment_generation == 1);
  CHECK(blobs_equal(dev2.site_store.site().member_cert, first_cert));
  CHECK(net.site(0).authority_.ledger.next_generation == 2);  // no spare gen
  CHECK(net.site(0).authority_.ledger.approved);
}

void test_v1_j08_commit_cut_matrix() {
  current = "v1-j08-commit";
  const std::size_t used = j08_used_len();
  CHECK(used > 512 && used <= kSiteSlotBytes);
  std::vector<std::size_t> edges = {0, 1, 16, 17, 64, 128, 256, 512};
  if (used >= 2) edges.push_back(used - 2);
  if (used >= 1) edges.push_back(used - 1);
  edges.push_back(used);  // bytes landed, acknowledgment lost
  for (std::size_t call = 0; call < 2; ++call) {
    for (std::size_t bytes : edges) {
      if (bytes > used) continue;
      // A fully landed sealed write adopts without another approval.
      if (call == 1 && bytes >= used) continue;  // covered below
      j08_commit_cut_case(call, bytes);
      if (failures != 0) {
        std::fprintf(stderr, "  while at cut call %zu bytes %zu\n", call, bytes);
        current.clear();
        return;
      }
    }
  }
  current.clear();
}

// The sealed bytes landed but the acknowledgment was lost: the restart
// adopts the record (no new m1, no new approval).
void test_v1_j08_sealed_landed_adopts() {
  current = "v1-j08-landed";
  const std::size_t used = j08_used_len();
  JoinerConfig config = device_config();
  config.scan_channels = {{6, 1, 11}};
  JoinSimNetwork net(config, device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  dev.site_storage.inner_.cut_call = 1;
  dev.site_storage.inner_.cut_bytes = used;
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] {
        return dev.joiner.snapshot().counters.store_failures >= 1 ||
               net.has_terminal_action();
      },
      30000));
  CHECK(!net.has_terminal_action());
  net.restart_device(config, 0x1A4DED);
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::MemberReady);
  CHECK(!action.joined_now);  // adopted, not re-issued
  CHECK(net.site(0).authority_.m1_seen == 1);
  CHECK(dev2.site_store.site().assignment_generation == 1);
  CHECK(dev2.radio.sends == 0);  // adoption touches no air
  current.clear();
}

// A cut before m4 (nothing approved durably yet... the approval exists but
// no commit was attempted): restart and join from scratch.
void test_v1_j08_cut_before_m4() {
  current = "v1-j08-prem4";
  JoinerConfig config = device_config();
  config.scan_channels = {{6, 1, 11}};
  JoinSimNetwork net(config, device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM4; }, 30000));
  CHECK(dev.site_storage.writes() == 0);
  net.restart_device(config, 0xBEF0);
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev2.site_store.site().assignment_generation == 1);
  CHECK(net.site(0).authority_.ledger.next_generation == 2);
  current.clear();
}

// The commit readback alone fails (the sealed record landed): Reconcile
// adopts it without consuming another approval — no restart involved.
void test_v1_j08_readback_failure_adopts() {
  current = "v1-j08-readback";
  JoinerConfig config = device_config();
  config.scan_channels = {{6, 1, 11}};
  JoinSimNetwork net(config, device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  dev.site_storage.fail_read_once_writes_ge = 2;  // the commit readback read
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::MemberReady);
  CHECK(action.joined_now);
  CHECK(net.site(0).authority_.exchanges == 1);  // a single approval
  CHECK(dev.site_store.site().assignment_generation == 1);
  CHECK(dev.joiner.snapshot().counters.store_failures == 1);
  current.clear();
}

// A sealed new record cannot be adopted while its sibling is corrupt:
// the sequence is known, but the pair remains uncertain until healed.
void test_v1_j08_reconcile_uncertain_pair() {
  current = "v1-j08-reconcile-uncertain";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  dev.site_storage.inner_.slot(1)[0] = 0x52;
  dev.site_storage.inner_.cut_call = 2;  // first write to the second twin fails
  dev.site_storage.inner_.cut_bytes = 0;
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.store_failures >= 1; }, 30000));
  CHECK(dev.joiner.snapshot().state == JoinState::Reconcile);
  CHECK(dev.joiner.poll(net.now()).ok());
  CHECK(dev.joiner.snapshot().state != JoinState::Ready);
  CHECK(dev.joiner.snapshot().pending_action != JoinActionKind::MemberReady);
  current.clear();
}

void test_decision_deadline_before_commit() {
  current = "decision-deadline";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Decided; }, 30000));
  CHECK(dev.site_storage.writes() == 0);
  CHECK(dev.joiner.poll(net.now() + 15000).ok());
  CHECK(dev.joiner.snapshot().state != JoinState::Commit);
  CHECK(dev.site_storage.writes() == 0);
  current.clear();
}

// Cuts during the twin write of a recovery re-issue: the device still
// lands Ready with the same generation and certificate.
void test_v1_j08_recover_cut_matrix() {
  current = "v1-j08-recover";
  const std::size_t used = j08_used_len();
  for (std::size_t call = 0; call < 4; ++call) {
    for (std::size_t bytes : {std::size_t{0}, used > 0 ? used - 1 : 0, used}) {
      JoinerConfig config = device_config();
      config.scan_channels = {{6, 1, 11}};
      JoinSimNetwork net(config, device_identity());
      net.add_site(site_a_params());
      DeviceEnds& dev = net.device();
      CHECK(dev.joiner.start(boot_input(), 0).ok());
      CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
      CHECK(dev.site_store.site().assignment_generation == 1);
      const Bytes first_cert = net.site(0).authority_.ledger.member_cert_bytes;
      // Impair the empty sibling slot (Valid + Corrupt), then restart
      // into a restricted recovery join whose twin write gets cut.
      net.clear_terminal();
      std::uint8_t empty = 0xFF;
      for (std::uint8_t slot = 0; slot < 2; ++slot) {
        const auto& bytes = dev.site_storage.inner_.slot(slot);
        // Erased flash reads all-ones; anything else holds a record.
        if (bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF && bytes[3] == 0xFF) {
          empty = slot;
        }
      }
      CHECK(empty != 0xFF);
      if (empty == 0xFF) {
        current.clear();
        return;
      }
      auto& sibling = dev.site_storage.inner_.slot(empty);
      sibling[0] = 0x52;  // corrupt the magic itself: neither empty nor valid
      sibling[8] ^= 0xFF;
      sibling[64] ^= 0xFF;
      net.restart_device(config, 0xEC0CE12);
      DeviceEnds& dev2 = net.device();
      dev2.site_storage.inner_.cut_call = call;
      dev2.site_storage.inner_.cut_bytes = bytes;
      CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
      const bool ready =
          net.pump_until([&] { return net.has_terminal_action(); }, 180000);
      CHECK(net.error() == StatusCode::Ok);
      CHECK(ready);
      if (!net.has_terminal_action()) {
        std::fprintf(stderr, "  while at recover cut call %zu bytes %zu\n", call, bytes);
        current.clear();
        return;
      }
      CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
      CHECK(dev2.site_store.site().assignment_generation == 1);
      CHECK(blobs_equal(dev2.site_store.site().member_cert, first_cert));
      CHECK(net.site(0).authority_.ledger.next_generation == 2);
      if (failures != 0) {
        std::fprintf(stderr, "  while at recover cut call %zu bytes %zu\n", call, bytes);
        current.clear();
        return;
      }
    }
  }
  current.clear();
}

// --- Re-entrancy ----------------------------------------------------------------------------------
// Calls made from port/observer/storage callbacks return Busy and change
// nothing (not even diagnostics); read-only APIs stay usable inside.
bool snapshots_equal(const JoinSnapshot& a, const JoinSnapshot& b) {
  if (a.state != b.state || a.membership != b.membership ||
      a.action_pending != b.action_pending || a.pending_action != b.pending_action ||
      a.channel != b.channel || a.channel_token != b.channel_token ||
      a.clock_uncertain != b.clock_uncertain || a.last_error != b.last_error) {
    return false;
  }
  const JoinCounters& x = a.counters;
  const JoinCounters& y = b.counters;
  return std::memcmp(&x, &y, sizeof(x)) == 0;
}

struct ReentrantObserver final : public JoinObserver {
  Joiner* joiner{nullptr};
  int events{0};
  int busy{0};
  bool quiescent_inside{true};
  bool snapshots_match{true};
  void on_event(const JoinEvent&) noexcept override {
    ++events;
    quiescent_inside = joiner->quiescent();
    const JoinSnapshot before = joiner->snapshot();
    JoinAction action{};
    if (joiner->start(JoinBootInput{}, 1).code == StatusCode::Busy) ++busy;
    if (joiner->poll(1).code == StatusCode::Busy) ++busy;
    if (joiner->stop(1).code == StatusCode::Busy) ++busy;
    if (joiner->take_action(action).code == StatusCode::Busy) ++busy;
    JoinRxMeta meta{};
    std::array<std::uint8_t, 1> byte{{0}};
    if (joiner->on_rld1_rx(meta, ByteView{byte.data(), 1}, 1).code == StatusCode::Busy) ++busy;
    if (joiner->on_channel_ready(0, Status::success(), 1).code == StatusCode::Busy) ++busy;
    snapshots_match = snapshots_match && snapshots_equal(before, joiner->snapshot());
  }
};

struct ReentrantPort final : public ZtRld1Port {
  Joiner* joiner{nullptr};
  int sends{0};
  int busy{0};
  Status send_rld1(const MacAddress&, const ByteView) noexcept override {
    ++sends;
    if (joiner != nullptr && joiner->poll(1).code == StatusCode::Busy) ++busy;
    return Status::success();
  }
};

struct ReentrantStorage final : public RecordSlotStorage {
  Joiner* joiner{nullptr};
  FaultyRecordStorage inner_{1024};
  int busy{0};
  Status read(const std::uint8_t slot, const MutableByteView target) noexcept override {
    if (joiner != nullptr && joiner->poll(1).code == StatusCode::Busy) ++busy;
    return inner_.read(slot, target);
  }
  Status write(const std::uint8_t slot, const ByteView data) noexcept override {
    if (joiner != nullptr && joiner->poll(1).code == StatusCode::Busy) ++busy;
    return inner_.write(slot, data);
  }
};

void test_reentry_refused() {
  current = "reentry";
  // A Joiner whose every dependency re-enters it; with no sites around,
  // the FSM walks BootCheck -> scan -> Backoff and rescans.
  ReentrantStorage id_storage;
  ReentrantStorage site_storage;
  IdentityStore identity(id_storage);
  SiteStore site(site_storage);
  CHECK(identity.initialize().ok());
  CHECK(identity.commit(device_identity()).ok());
  CHECK(site.initialize().ok());
  SimEntropy entropy(0xEE);
  ReentrantPort port;
  ReentrantObserver observer;
  Joiner joiner(device_config(), identity, site, entropy, port, observer);
  port.joiner = &joiner;
  observer.joiner = &joiner;
  id_storage.joiner = &joiner;
  site_storage.joiner = &joiner;
  CHECK(joiner.start(boot_input(), 1000).ok());
  MonotonicMs now = 1000;
  for (int i = 0; i < 60; ++i) {
    CHECK(joiner.poll(now).ok());
    JoinAction action{};
    if (joiner.take_action(action).ok() && action.kind == JoinActionKind::ChangeChannel) {
      CHECK(joiner.on_channel_ready(action.channel_token, Status::success(), now).ok());
    }
    now += 100;
  }
  CHECK(observer.events > 0);
  CHECK(observer.busy == observer.events * 6);
  CHECK(port.sends > 0);
  CHECK(port.busy == port.sends);
  CHECK(id_storage.busy + site_storage.busy > 0);
  CHECK(!observer.quiescent_inside);  // read-only inside callbacks: never quiet
  CHECK(observer.snapshots_match);    // re-entered calls changed nothing
  // ... and the FSM still advanced normally underneath it all.
  const JoinState state = joiner.snapshot().state;
  CHECK(state == JoinState::Backoff || state == JoinState::ScanTune ||
        state == JoinState::WaitChannel || state == JoinState::ScanWindow ||
        state == JoinState::Select);
  CHECK(joiner.stop(now).ok());
  CHECK(joiner.quiescent());
  current.clear();
}

// --- #109 retransmit path ----------------------------------------------------------------------
// m1 is one frame (59 B); m2/m3 ride chunks. Losing m3's chunk 0 once must
// retransmit and complete — the attempt, the proxy slot and the authority
// exchange all survive.
void test_109_chunk_loss_recovers() {
  current = "109-loss";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  bool armed = true;
  net.faults().drop_if = [&](RadioDir dir, const Bytes& bytes) {
    if (!armed || dir != RadioDir::Up) return false;
    autonomy::Rld1Envelope env{};
    JoinChunk chunk{};
    if (!autonomy::rld1_decode(view(bytes), env)) return false;
    if (env.kind != FrameType::BootstrapChunk) return false;
    if (!join_chunk_decode(JoinCarrier::Rld1, ByteView{env.body.data(), env.body_size},
                           chunk)) {
      return false;
    }
    if (chunk.phase == JoinAuthPhase::EdhocMessage && chunk.step == 3 && chunk.offset == 0) {
      armed = false;
      return true;
    }
    return false;
  };
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  CHECK(!armed);  // the loss actually fired
  CHECK(net.faults().dropped == 1);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  }
  CHECK(!net.site(0).authority_.last_m3.empty());
  current.clear();
}

// While m2 chunks land, the device emits receipts only — completing the
// message inside the callback never starts a new send (the #109 shape).
void test_109_no_send_inside_message_callback() {
  current = "109-callback";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  // The duplicate rides ahead of the genuine m2 still travelling down.
  CHECK(net.pump_until([&] { return !net.site(0).authority_.last_m2.empty(); }, 30000));
  CHECK(dev.joiner.snapshot().state == JoinState::WaitM2);
  const Bytes m2 = net.site(0).authority_.last_m2;
  // Feed a duplicate m2 through the raw entry: every send the device makes
  // while the callback runs must be a chunk receipt.
  const std::size_t air_before = dev.air.size();
  CHECK(net.inject_down_chunked(site_a_params().proxies[0], m2, 2));
  CHECK(dev.air.size() > air_before);  // receipts went out...
  for (std::size_t k = air_before; k < dev.air.size(); ++k) {
    autonomy::Rld1Envelope env{};
    CHECK(autonomy::rld1_decode(view(dev.air[k].bytes), env));
    CHECK(env.kind == FrameType::BootstrapReply);  // ... and nothing else
  }
  current.clear();
}

// A stale m2 arriving while m3 is still Sending dies at the phase/step
// gate: the sender slot is untouched and the exchange completes.
void test_109_stale_m2_during_m3() {
  current = "109-stale";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  // Drop the proxy's first reply (m3's Complete): m3 stays Sending while
  // a stale m2 is injected, then the retransmit completes it.
  bool armed = true;
  net.faults().drop_if = [&](RadioDir dir, const Bytes& bytes) {
    if (!armed || dir != RadioDir::Down) return false;
    autonomy::Rld1Envelope env{};
    if (!autonomy::rld1_decode(view(bytes), env)) return false;
    if (env.kind != FrameType::BootstrapReply) return false;
    armed = false;
    return true;
  };
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM4; }, 30000));
  const std::uint32_t drops = dev.joiner.snapshot().counters.rx_dropped;
  const Bytes m2 = net.site(0).authority_.last_m2;
  CHECK(!m2.empty());
  CHECK(net.inject_down_chunked(site_a_params().proxies[0], m2, 2));
  CHECK(dev.joiner.snapshot().counters.rx_dropped > drops);
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  CHECK(!armed);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  }
  current.clear();
}

// --- Quiescence ------------------------------------------------------------------------------------
void test_quiescence_points() {
  current = "quiescent";
  // stop() completes quiet.
  {
    JoinSimNetwork net(device_config(), device_identity());
    net.add_site(site_a_params());
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
    CHECK(!dev.joiner.quiescent());
    CHECK(dev.joiner.stop(net.now()).ok());
    CHECK(dev.joiner.quiescent());
    CHECK(dev.joiner.snapshot().state == JoinState::Stopped);
  }
  // A stable Backoff (nothing holds the air) is quiet with a wake time.
  {
    JoinSimNetwork net(device_config(), device_identity());
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().state == JoinState::Backoff; }, 60000));
    CHECK(dev.joiner.quiescent());
    const MonotonicMs wake = dev.joiner.next_deadline();
    CHECK(wake != kJoinNoDeadline && wake >= net.now());
  }
  // An unconsumed MemberReady is not quiet; taking it is.
  {
    JoinSimNetwork net(device_config(), device_identity());
    net.add_site(site_a_params());
    net.set_hold_terminal(true);
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] {
          return dev.joiner.snapshot().state == JoinState::Ready &&
                 dev.joiner.snapshot().action_pending;
        },
        60000));
    CHECK(!dev.joiner.quiescent());
    JoinAction action{};
    CHECK(dev.joiner.take_action(action).ok());
    CHECK(action.kind == JoinActionKind::MemberReady);
    CHECK(dev.joiner.quiescent());
  }
  // WaitChannel and SendM3 are never quiet (a tune held open by hand;
  // SendM3 persists across pump rounds).
  {
    JoinSimNetwork net(device_config(), device_identity());
    net.add_site(site_a_params());
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(dev.joiner.poll(0).ok());  // BootCheck -> ScanTune
    CHECK(dev.joiner.poll(0).ok());  // ScanTune emits the tune -> WaitChannel
    CHECK(dev.joiner.snapshot().state == JoinState::WaitChannel);
    CHECK(!dev.joiner.quiescent());
    JoinAction tune{};
    CHECK(dev.joiner.take_action(tune).ok());
    CHECK(tune.kind == JoinActionKind::ChangeChannel);
    CHECK(dev.joiner.on_channel_ready(tune.channel_token, Status::success(), 0).ok());
  }
  {
    JoinSimNetwork net(device_config(), device_identity());
    net.add_site(site_a_params());
    DeviceEnds& dev = net.device();
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().state == JoinState::SendM3; }, 30000));
    CHECK(!dev.joiner.quiescent());
  }
  {
    JoinSimNetwork net(device_config(), device_identity());
    net.add_site(site_a_params());
    DeviceEnds& dev = net.device();
    dev.site_storage.inner_.read_error = true;  // both slots unreadable
    CHECK(dev.joiner.start(boot_input(), 0).ok());
    CHECK(net.pump_until(
        [&] { return dev.joiner.snapshot().state == JoinState::Reconcile; }, 30000));
    CHECK(!dev.joiner.quiescent());
    CHECK(dev.joiner.next_deadline() != kJoinNoDeadline);
  }
  current.clear();
}

// --- Bounds -------------------------------------------------------------------------------------------
// A clock regression parks the attempt and latches; stop() opens a fresh
// clock domain (reboot semantics) and the device joins again.
void test_clock_regression_recovers() {
  current = "clock-regress";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  const MonotonicMs live = net.now();
  CHECK(live > 100);
  CHECK(dev.joiner.poll(live - 100).code == StatusCode::ClockUncertain);
  CHECK(dev.joiner.snapshot().state == JoinState::Stopped);
  CHECK(dev.joiner.snapshot().clock_uncertain);
  CHECK(dev.joiner.poll(live).code == StatusCode::ClockUncertain);  // latched
  CHECK(dev.joiner.start(boot_input(), live).code == StatusCode::ClockUncertain);
  CHECK(dev.joiner.stop(live).ok());
  CHECK(!dev.joiner.snapshot().clock_uncertain);
  CHECK(dev.joiner.start(boot_input(), live).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  current.clear();
}

void test_clock_domain_restart_clears_old_m1_rate_time() {
  current = "clock-domain-rate";
  JoinSimNetwork net(device_config(), device_identity());
  net.skip_to(1'000'000);
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), net.now()).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  CHECK(dev.joiner.poll(0).code == StatusCode::ClockUncertain);
  CHECK(dev.joiner.stop(0).ok());
  net.reset_clock_and_sites();
  net.add_site(site_a_params());
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::RefreshWindow; }, 30000));
  CHECK(dev.joiner.next_deadline() <= net.now() + kJoinMinM1IntervalMs);
  current.clear();
}

// The first entropy draw fails once (a scan DISCOVER nonce): the window
// is skipped, the scan completes, the join succeeds.
void test_entropy_shortage_degrades() {
  current = "entropy-short";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  dev.entropy.fail_at = 1;
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  CHECK(dev.entropy.calls > 1);
  current.clear();
}

// Near the u64 wraparound, timers saturate instead of wrapping: a scan
// runs, Backoff parks with a sane deadline, stop stays clean.
void test_time_overflow_smoke() {
  current = "time-overflow";
  JoinSimNetwork net(device_config(), device_identity());
  DeviceEnds& dev = net.device();
  const MonotonicMs start = ~MonotonicMs{0} - 100000;
  CHECK(dev.joiner.start(boot_input(), start).ok());
  MonotonicMs now = start;
  for (int i = 0; i < 40; ++i) {
    CHECK(dev.joiner.poll(now).ok());
    CHECK(dev.joiner.next_deadline() >= now);  // saturated, never wrapped
    JoinAction action{};
    if (dev.joiner.take_action(action).ok() &&
        action.kind == JoinActionKind::ChangeChannel) {
      CHECK(dev.joiner.on_channel_ready(action.channel_token, Status::success(), now).ok());
    }
    if (now >= ~MonotonicMs{0} - 5000) break;
    now += 5000;
  }
  CHECK(dev.joiner.stop(now).ok());
  CHECK(dev.joiner.quiescent());
  current.clear();
}

// --- Transport behaviour ---------------------------------------------------------------------------
// One failed tune skips its channel; the scan completes elsewhere and the
// join succeeds.
void test_tune_failure_skips_channel() {
  current = "tune-skip";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  net.set_fail_tunes(1);  // channel 1 never comes up
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  CHECK(net.tunes() >= 2);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  }
  current.clear();
}

// Every tune failing stalls the scan in Backoff: no m1 ever goes out, the
// FSM stays alive and keeps retrying.
void test_tune_failure_all_stalls() {
  current = "tune-stall";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  net.set_fail_tunes(1000000);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(!net.pump_until([&] { return net.site(0).authority_.m1_seen == 1; }, 30000));
  CHECK(net.site(0).authority_.m1_seen == 0);
  CHECK(dev.radio.sends == 0);  // nothing transmitted without a channel
  CHECK(net.error() == StatusCode::Ok);
  const JoinState state = dev.joiner.snapshot().state;
  CHECK(state == JoinState::Backoff || state == JoinState::ScanTune ||
        state == JoinState::WaitChannel || state == JoinState::Select);
  current.clear();
}

// Two anchors scan both org windows; the stronger site still wins.
void test_multi_anchor_scan() {
  current = "multi-anchor";
  constexpr std::uint64_t kSiteBCaId = 0xCA9D0000000000B7ULL;
  IdentityRecord identity = device_identity();
  identity.anchors[1] =
      IdentityAnchor{kSiteBCaId, AnchorKind::SiteCa, AnchorStatus::Active, site_b_ca().pub};
  identity.anchor_count = 2;
  JoinSimNetwork net(device_config(), identity);
  SimSiteParams a = site_a_params(1, -60);
  SimSiteParams b = site_b_params(11, -40);
  b.site_ca = &site_b_ca();
  b.site_ca_id = kSiteBCaId;
  net.add_site(a);
  net.add_site(b);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 90000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  const std::uint32_t org_a = join_org_hint(site_ca().pub);
  const std::uint32_t org_b = join_org_hint(site_b_ca().pub);
  CHECK(org_a != org_b);
  bool saw_a = false;
  bool saw_b = false;
  for (const auto& body : discovers(net)) {
    if (body.org_hint == org_a) saw_a = true;
    if (body.org_hint == org_b) saw_b = true;
    CHECK(body.profile_bits == kJoinProfileRljoin1);  // no RLRES1 bit
  }
  CHECK(saw_a && saw_b);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
    CHECK(dev.site_store.site().site_id == kSiteB);  // stronger wins
  }
  current.clear();
}

// An OFFER to another MAC dies at the destination gate; the identical
// frame to self is observed.
void test_offer_wrong_destination_dropped() {
  current = "offer-dest";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::ScanWindow; }, 30000));
  // The live DISCOVER nonce (still queued or already delivered).
  JoinNonce live{};
  bool have_live = false;
  const auto scan = [&](const Bytes& bytes) {
    autonomy::Rld1Envelope env{};
    if (!autonomy::rld1_decode(view(bytes), env)) return;
    if (env.kind == FrameType::Discover) {
      std::copy(env.transaction_nonce.begin(), env.transaction_nonce.end(), live.begin());
      have_live = true;
    }
  };
  for (const auto& bytes : net.air_history()) scan(bytes);
  for (const auto& frame : dev.air) scan(frame.bytes);
  CHECK(have_live);
  const SimProxyParams proxy = site_a_params().proxies[0];
  ZtOfferBody body{};
  body.flags = kZtOfferAuthorityReachable;
  body.org_hint = join_org_hint(site_ca().pub);
  body.site_hint = join_site_hint(kSiteA);
  body.authority_hops = 1;
  autonomy::Rld1Encoded frame{};
  CHECK(zt_offer_frame_encode(proxy.node, static_cast<std::uint32_t>(kNetworkA), live, body,
                              frame)
            .ok());
  const std::uint32_t drops = dev.joiner.snapshot().counters.rx_dropped;
  const std::uint32_t obs = dev.joiner.snapshot().candidates.observations;
  JoinRxMeta meta{};
  meta.source = proxy.mac;
  meta.destination = MacAddress{{0x02, 0, 0, 0, 0xEE, 0xEE}};
  meta.channel = dev.channel;
  meta.rssi = -50;
  CHECK(dev.joiner.on_rld1_rx(meta, ByteView{frame.bytes.data(), frame.size}, net.now())
            .ok());
  CHECK(dev.joiner.snapshot().counters.rx_dropped == drops + 1);
  CHECK(dev.joiner.snapshot().candidates.observations == obs);
  meta.destination = kDeviceMac;
  CHECK(dev.joiner.on_rld1_rx(meta, ByteView{frame.bytes.data(), frame.size}, net.now())
            .ok());
  CHECK(dev.joiner.snapshot().candidates.observations == obs + 1);
  current.clear();
}

// A second down message while the mailbox is full is dropped; the first
// is processed.
void test_mailbox_full_keeps_first() {
  current = "mailbox-full";
  const Bytes error = make_edhoc_error();
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  CHECK(net.inject_down(site_a_params().proxies[0], error, 5));
  CHECK(net.inject_down(site_a_params().proxies[0], error, 5));  // mailbox full
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.transient_failures == 1; },
      30000));
  CHECK(dev.joiner.snapshot().counters.timeouts == 0);
  CHECK(net.site(0).authority_.last_m3.empty());
  current.clear();
}

// A flood of unauthenticated proxy hints disturbs nothing: no verdict,
// no storage, the join completes.
void test_hint_flood_ignored() {
  current = "hint-flood";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  const SimProxyParams proxy = site_a_params().proxies[0];
  for (int i = 0; i < 12; ++i) {
    JoinAuthObject hint{};
    hint.phase = JoinAuthPhase::RelayStatus;
    hint.step = 1;  // the proxy's status shape
    hint.relay_status =
        (i % 3 == 0) ? RelayStatusCode::Busy : RelayStatusCode::AuthorityUnreachable;
    hint.retry_after_ms = static_cast<std::uint32_t>(1000 + i);
    JoinObjectBytes encoded{};
    std::size_t written = 0;
    CHECK(join_object_encode(hint, MutableByteView{encoded.bytes.data(), encoded.bytes.size()},
                             written));
    CHECK(net.inject_down_raw(proxy, Bytes(encoded.bytes.begin(), encoded.bytes.begin() + written),
                              FrameType::BootstrapAuth));
  }
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 60000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (net.has_terminal_action()) {
    CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  }
  current.clear();
}

// A proxy whose authority is unreachable is never attempted.
void test_unreachable_proxy_never_attempted() {
  current = "unreachable";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params();
  a.proxies[0].reachable = false;
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(!net.pump_until([&] { return net.site(0).authority_.m1_seen == 1; }, 30000));
  CHECK(net.site(0).authority_.m1_seen == 0);
  CHECK(dev.site_storage.writes() == 0);
  CHECK(net.error() == StatusCode::Ok);
  current.clear();
}

// --- Store behaviour -----------------------------------------------------------------------------------
// Patch a committed RLS1 slot (the encoder refuses invalid records, so
// these tests commit a valid one and splice the bytes, fixing the CRC).
void patch_site_slot(LoggingStorage& storage, std::uint8_t slot, std::size_t offset,
                     const Bytes& bytes) {
  auto& raw = storage.inner_.slot(slot);
  const std::size_t used =
      (static_cast<std::size_t>(raw[6]) << 8U) | static_cast<std::size_t>(raw[7]);
  CHECK(offset + bytes.size() + 4 <= used);
  std::memcpy(raw.data() + offset, bytes.data(), bytes.size());
  const std::uint32_t crc = crc32_iso_hdlc(ByteView{raw.data(), used - 4});
  raw[used - 4] = static_cast<std::uint8_t>((crc >> 24U) & 0xFFU);
  raw[used - 3] = static_cast<std::uint8_t>((crc >> 16U) & 0xFFU);
  raw[used - 2] = static_cast<std::uint8_t>((crc >> 8U) & 0xFFU);
  raw[used - 1] = static_cast<std::uint8_t>(crc & 0xFFU);
}

// A readback error can leave a sealed record. Reconcile must compare every
// prepared field: the certificate and DAMS can still match while GK differs.
void test_reconcile_rejects_changed_prepared_gk() {
  current = "store-reconcile-gk";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  dev.site_storage.fail_read_once_writes_ge = 2;
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().counters.store_failures >= 1; }, 30000));
  CHECK(dev.joiner.snapshot().state == JoinState::Reconcile);
  // Header 20 B, fixed fields before gk_current 32 B.
  patch_site_slot(dev.site_storage, 0, 52, Bytes{0x7A});
  CHECK(dev.joiner.poll(net.now()).ok());
  CHECK(dev.joiner.snapshot().state == JoinState::RecoveryRequired);
  CHECK(dev.joiner.snapshot().pending_action == JoinActionKind::RecoveryRequired);
  current.clear();
}

// Valid + unknown-schema: the FSM stops for external recovery, sends
// nothing, and never recovers over the unknown slot.
void test_unknown_schema_stops() {
  current = "store-schema";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  CHECK(dev.site_store.site().assignment_generation == 1);
  net.clear_terminal();
  // Rewrite the record into the sibling slot with an unknown schema.
  const auto& active = dev.site_storage.inner_.slot(0);
  auto& sibling = dev.site_storage.inner_.slot(1);
  const std::size_t used =
      (static_cast<std::size_t>(active[6]) << 8U) | static_cast<std::size_t>(active[7]);
  std::memcpy(sibling.data(), active.data(), used);
  patch_site_slot(dev.site_storage, 1, 8, Bytes{0xFF, 0xFF, 0xFF, 0xFF});  // schema
  JoinerConfig config = device_config();
  net.restart_device(config, 0xBAD);
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 60000));
  CHECK(net.error() == StatusCode::Ok);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::RecoveryRequired);
  CHECK(action.recovery_reason == JoinRecoveryReason::UnknownSchema);
  CHECK(dev2.radio.sends == 0);
  CHECK(dev2.joiner.snapshot().state == JoinState::RecoveryRequired);
  current.clear();
}

// A saturated commit_seq floor stops before any attempt (never wraps).
void test_seq_exhausted_stops() {
  current = "store-seq";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  net.clear_terminal();
  patch_site_slot(dev.site_storage, 0, kRecordSeqOffset, Bytes{0xFF, 0xFF, 0xFF, 0xFF});
  JoinerConfig config = device_config();
  net.restart_device(config, 0x5E9);
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 60000));
  CHECK(net.error() == StatusCode::Ok);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::RecoveryRequired);
  CHECK(action.recovery_reason == JoinRecoveryReason::SeqExhausted);
  CHECK(dev2.radio.sends == 0);
  current.clear();
}

// A re-issue that regresses the retained membership is refused without a
// write (the retained record stays adopted and readable).
void test_floor_regression_refused() {
  current = "store-regress";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  // Commit a generation-5 member directly, then impair its sibling.
  CHECK(dev.site_store.commit(site_record(5, 203, kNetworkA)).ok());
  auto& sibling = dev.site_storage.inner_.slot(1);
  sibling[0] = 0x52;
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 120000));
  CHECK(net.error() == StatusCode::Ok);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  // The ledger re-issues generation 1 for the known node: older than the
  // retained 5, so the recover is refused.
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::RecoveryRequired);
  CHECK(action.recovery_reason == JoinRecoveryReason::AssignmentRegressed);
  CHECK(dev.site_store.has_site());
  CHECK(dev.site_store.site().assignment_generation == 5);
  current.clear();
}

// A retained impaired membership forbids attempting any other site: with
// only B visible, no m1 leaves and the store is untouched.
void test_cross_site_recover_forbidden() {
  current = "store-xsite";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  CHECK(dev.site_store.site().assignment_generation == 1);
  net.clear_terminal();
  auto& sibling = dev.site_storage.inner_.slot(1);
  sibling[0] = 0x52;
  JoinerConfig config = device_config();
  net.restart_device(config, 0xC2055);
  net.site(0).set_proxy_muted(0, true);  // A goes dark...
  net.add_site(site_b_params());          // ...only B answers now
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  CHECK(!net.pump_until([&] { return net.site(1).authority_.m1_seen == 1; }, 120000));
  CHECK(net.site(1).authority_.m1_seen == 0);
  CHECK(net.site(0).authority_.m1_seen == 1);  // the original join only
  CHECK(dev2.site_storage.writes() == 0);
  CHECK(dev2.site_store.has_site());
  CHECK(dev2.site_store.site().site_id == kSiteA);
  CHECK(net.error() == StatusCode::Ok);
  current.clear();
}

// A healthy stored member is adopted at boot: Ready, no airtime.
void test_healthy_member_boot_adopts() {
  current = "store-adopt";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  const std::uint32_t seq = dev.site_store.commit_seq();
  net.clear_terminal();
  JoinerConfig config = device_config();
  net.restart_device(config, 0xAD09);
  DeviceEnds& dev2 = net.device();
  CHECK(dev2.joiner.start(boot_input(), net.now()).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 30000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  const JoinAction action = net.terminal_action();
  CHECK(action.kind == JoinActionKind::MemberReady);
  CHECK(!action.joined_now);
  CHECK(action.commit_seq == seq);
  CHECK(action.rs_epoch_to_fetch == 0);
  CHECK(dev2.radio.sends == 0);
  CHECK(dev2.joiner.snapshot().membership == MembershipState::Member);
  CHECK(dev2.joiner.quiescent());
  current.clear();
}

void test_member_boot_active_reread_failure() {
  current = "store-active-reread";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  net.clear_terminal();
  net.restart_device(device_config(), 0xA11CE);
  DeviceEnds& booted = net.device();
  booted.site_storage.fail_read_call = booted.site_storage.read_calls + 3;
  CHECK(booted.joiner.start(boot_input(), net.now()).ok());
  CHECK(booted.joiner.poll(net.now()).ok());
  CHECK(booted.joiner.snapshot().state == JoinState::Reconcile);
  CHECK(booted.radio.sends == 0);
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(booted.radio.sends == 0);
  current.clear();
}

void test_member_boot_unreadable_sibling() {
  current = "store-unreadable-sibling";
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site_a_params());
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  net.clear_terminal();
  net.restart_device(device_config(), 0xB007);
  DeviceEnds& booted = net.device();
  booted.site_storage.fail_read_call = booted.site_storage.read_calls + 2;
  CHECK(booted.joiner.start(boot_input(), net.now()).ok());
  CHECK(booted.joiner.poll(net.now()).ok());
  CHECK(booted.joiner.snapshot().state == JoinState::Reconcile);
  CHECK(booted.radio.sends == 0);
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(booted.radio.sends == 0);
  current.clear();
}

// --- V1-J05 variants -------------------------------------------------------------------------------------
// Pending A on channel 1, allowing B on channel 11: the scan crosses the
// channels and B binds.
void test_v1_j05_split_channels() {
  current = "v1-j05-channels";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params(1, -30);
  a.policy.verdict = JoinVerdict::PendingAssignment;
  a.policy.retry_after_s = 60;
  SimSiteParams b = site_b_params(11, -60);
  net.add_site(a);
  net.add_site(b);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 120000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteB);
  CHECK(!net.site(0).authority_.ledger.approved);
  current.clear();
}

// Same under separate orgs (separate Site CAs, two anchors).
void test_v1_j05_split_orgs() {
  current = "v1-j05-orgs";
  constexpr std::uint64_t kSiteBCaId = 0xCA9D0000000000B7ULL;
  IdentityRecord identity = device_identity();
  identity.anchors[1] =
      IdentityAnchor{kSiteBCaId, AnchorKind::SiteCa, AnchorStatus::Active, site_b_ca().pub};
  identity.anchor_count = 2;
  JoinSimNetwork net(device_config(), identity);
  SimSiteParams a = site_a_params(6, -30);
  a.policy.verdict = JoinVerdict::DenyNotHere;
  SimSiteParams b = site_b_params(6, -60);
  b.site_ca = &site_b_ca();
  b.site_ca_id = kSiteBCaId;
  net.add_site(a);
  net.add_site(b);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 120000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteB);
  CHECK(!net.site(0).authority_.ledger.approved);
  current.clear();
}

// One site, two proxies: the first dies mid-exchange and the second
// carries the join — still no wrong membership anywhere.
void test_v1_j05_proxy_changeover() {
  current = "v1-j05-proxy";
  JoinSimNetwork net(device_config(), device_identity());
  SimSiteParams a = site_a_params(6, -30);
  SimProxyParams p2{};
  p2.mac = MacAddress{{0x02, 0, 0, 0, 0x0A, 0x02}};
  p2.node = 0x00A1000000000A02ULL;
  p2.channel = 6;
  p2.rssi = -55;
  p2.hops = 2;
  a.proxies.push_back(p2);
  net.add_site(a);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  // The m1 goes to the selected proxy only; it dies after the m2 made
  // it back, so the re-attempt carries a second m1 via the survivor.
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM4; }, 30000));
  CHECK(net.site(0).authority_.m1_seen == 1);
  net.site(0).set_proxy_muted(0, true);  // the selected proxy dies here
  const bool ready =
      net.pump_until([&] { return net.has_terminal_action(); }, 120000);
  CHECK(net.error() == StatusCode::Ok);
  CHECK(ready);
  if (!net.has_terminal_action()) {
    current.clear();
    return;
  }
  CHECK(net.terminal_action().kind == JoinActionKind::MemberReady);
  CHECK(dev.site_store.site().site_id == kSiteA);
  CHECK(net.site(0).authority_.m1_seen == 2);
  CHECK(net.site(0).authority_.exchanges == 1);
  current.clear();
}

void test_refresh_proxy_is_attempted_proxy() {
  current = "refresh-proxy-binding";
  SimSiteParams site = site_a_params(6, -30);
  SimProxyParams second = site.proxies[0];
  second.mac = MacAddress{{0x02, 0, 0, 0, 0x0A, 0x02}};
  second.node = 0x00A1000000000A02ULL;
  second.rssi = -60;
  site.proxies.push_back(second);
  JoinSimNetwork net(device_config(), device_identity());
  net.add_site(site);
  DeviceEnds& dev = net.device();
  CHECK(dev.joiner.start(boot_input(), 0).ok());
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::RefreshWindow; }, 30000));
  net.site(0).set_proxy_muted(0, true);
  CHECK(net.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  MacAddress event_proxy{};
  for (const JoinEvent& event : dev.observer.events) {
    if (event.kind == JoinEventKind::AttemptStarted) event_proxy = event.proxy;
  }
  CHECK(event_proxy == second.mac);
  CHECK(dev.radio.last_unicast_destination == event_proxy);
  current.clear();
}

// --- Resource gate (design §9) -------------------------------------------------------------------------
void test_joiner_size_budget() {
  current = "size";
  std::printf("sizeof(Joiner)=%zu (budget 12288)\n", sizeof(Joiner));
  CHECK(sizeof(Joiner) <= 12288);
  current.clear();
}

// --- P4 §8.2: direct transport (a gateway joining over its own USB) -----
// The device Joiner talks (phase, step, message) to a scripted SimAuthority
// through a JoinDirectPort; no radio, no scan, no candidate table. Downs
// queue in the port and feed back after poll returns (send_direct runs
// inside poll, so feeding back inline would be re-entry).

class DirectPort final : public JoinDirectPort {
 public:
  DirectPort(SimAuthority& authority, std::uint64_t& now) : authority_(authority), now_(now) {}
  Status send_direct(JoinAuthPhase phase, std::uint8_t step, ByteView message) noexcept override {
    ups.push_back(Up{phase, step, Bytes(message.data, message.data + message.size)});
    const AuthorityDown down = authority_.on_up(step, message, now_);
    if (down.has) downs.push_back(down);
    return Status::success();
  }
  struct Up {
    JoinAuthPhase phase;
    std::uint8_t step;
    Bytes body;
  };
  std::vector<Up> ups;
  std::vector<AuthorityDown> downs;

 private:
  SimAuthority& authority_;
  std::uint64_t& now_;
};

class DirectRig {
 public:
  DirectRig(const AuthorityPolicy& policy = AuthorityPolicy{})
      : device_(device_config(), device_identity(), 0xD1EC7, faults_),
        authority_(make_authority()) {
    authority_.policy = policy;
    authority_.set_sak_signer(&sak());
  }

  DeviceEnds& device() { return device_; }
  SimAuthority& authority() { return authority_; }
  DirectPort& port() { return port_; }
  RadioFaults& faults() { return faults_; }
  std::uint64_t now() const { return now_; }

  // One pump round: poll, then feed the queued downs. Returns false when
  // a terminal action is pending (left for the test) or a call failed.
  bool round() {
    DeviceEnds& dev = device_;
    dev.now_ms = now_;
    dev.identity_storage.now_ms = now_;
    dev.site_storage.now_ms = now_;
    if (!dev.joiner.poll(now_).ok()) return false;
    for (const AuthorityDown& down : port_.downs) {
      const Status fed = dev.joiner.on_direct_message(
          JoinAuthPhase::EdhocMessage, down.step, view(down.body), now_);
      if (!fed.ok()) return false;
    }
    port_.downs.clear();
    JoinAction action{};
    if (dev.joiner.take_action(action).ok()) {
      pending_ = action;
      has_pending_ = true;
      return false;
    }
    now_ += 5;
    return true;
  }

  bool pump_until(const std::function<bool()>& done, std::uint64_t timeout_ms) {
    const std::uint64_t end = now_ + timeout_ms;
    while (now_ <= end) {
      if (!round()) return done();
      if (done()) return true;
    }
    return done();
  }

  bool has_pending() const { return has_pending_; }
  const JoinAction& pending() const { return pending_; }

 private:
  SimAuthority make_authority() {
    CertClaims claims{};
    claims.type = CertType::Site;
    claims.issuer = kSiteCaId;
    claims.subject = kSiteA;
    claims.pubkey = sak().pub;
    claims.network_low32 = static_cast<std::uint32_t>(kNetworkA);
    claims.site_epoch = static_cast<std::uint32_t>(kNetworkA >> 32U);
    claims.usage = 1;
    claims.serial = 1;
    site_cert_ = issue(claims, site_ca());
    if (!cert_subject_kid(claims, sak_kid_).ok()) std::abort();
    return SimAuthority(site_cert_, sak_kid_, sak().priv, device_ca().pub, kSiteA, kNetworkA,
                        site_package(), 0xA07);
  }

  static ByteView view(const Bytes& bytes) {
    return ByteView{bytes.data(), bytes.size()};
  }

  RadioFaults faults_{};
  DeviceEnds device_;
  ByteBuffer<kRlcw1CertMax> site_cert_{};
  Digest256 sak_kid_{};
  SimAuthority authority_;
  std::uint64_t now_{0};
  DirectPort port_{authority_, now_};
  JoinAction pending_{};
  bool has_pending_{false};
};

struct CountingPolicy final : public JoinCommitPolicy {
  bool check(const SiteRecord& prepared, MonotonicMs now) noexcept override {
    (void)prepared;
    (void)now;
    ++checks;
    return allow;
  }
  bool allow{true};
  std::uint32_t checks{0};
};

void test_direct_allow_commits() {
  current = "direct allow";
  DirectRig rig;
  DeviceEnds& dev = rig.device();
  CountingPolicy policy;
  dev.joiner.set_commit_policy(&policy);
  CHECK(dev.joiner.start_direct(boot_input(), rig.port(), 0).ok());
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Ready; }, 30000));
  CHECK(rig.has_pending());
  CHECK(rig.pending().kind == JoinActionKind::MemberReady);
  CHECK(rig.pending().joined_now);
  CHECK(rig.pending().commit_seq == dev.site_store.commit_seq());
  // Exactly one EDHOC exchange over the direct port, no radio touched.
  CHECK(rig.port().ups.size() == 2);
  CHECK(rig.port().ups[0].step == 1 && rig.port().ups[1].step == 3);
  CHECK(rig.port().ups[0].phase == JoinAuthPhase::EdhocMessage);
  CHECK(dev.air.empty());
  CHECK(dev.channel == 0);
  for (const JoinEvent& event : dev.observer.events) {
    CHECK(event.kind != JoinEventKind::StoreFailure);
  }
  // The gate was consulted exactly once, then the RLS1 landed durably.
  CHECK(policy.checks == 1);
  CHECK(dev.site_store.has_site());
  const SiteRecord& site = dev.site_store.site();
  CHECK(site.site_id == kSiteA && site.network == kNetworkA);
  CHECK(site.role == static_cast<std::uint8_t>(kMemberRoleEndpoint));
  CHECK(site.gk_epoch_current == 203);
  CHECK(dev.joiner.snapshot().state == JoinState::Ready);
  current.clear();
}

void test_direct_deny_parks_stopped() {
  current = "direct deny";
  AuthorityPolicy policy;
  policy.verdict = JoinVerdict::DenyNotHere;
  DirectRig rig(policy);
  DeviceEnds& dev = rig.device();
  CHECK(dev.joiner.start_direct(boot_input(), rig.port(), 0).ok());
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Stopped; }, 30000));
  // No table to select from: terminal, never Select/Backoff.
  CHECK(dev.joiner.snapshot().state == JoinState::Stopped);
  CHECK(dev.joiner.snapshot().counters.denies == 1);
  CHECK(!dev.site_store.has_site());
  CHECK(dev.air.empty());
  // The Owner restarts for the next attempt; the exchange runs again.
  const std::uint32_t attempts = dev.joiner.snapshot().counters.attempts;
  CHECK(dev.joiner.start_direct(boot_input(), rig.port(), rig.now()).ok());
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Stopped; }, 30000));
  CHECK(dev.joiner.snapshot().counters.attempts == attempts + 1);
  current.clear();
}

void test_direct_edges() {
  current = "direct edges";
  DirectRig rig;
  DeviceEnds& dev = rig.device();
  JoinBootInput boot = boot_input();
  // Unprepared boot and an unusable role refuse; garbage scan channels do
  // not matter (no radio is touched).
  JoinBootInput unprepared{};
  CHECK(!dev.joiner.start_direct(unprepared, rig.port(), 0).ok());
  JoinerConfig bad = device_config();
  bad.requested_role = 0;
  DeviceEnds bad_dev(bad, device_identity(), 0xD1EC7, rig.faults());
  CHECK(!bad_dev.joiner.start_direct(boot, rig.port(), 0).ok());
  JoinerConfig noscan = device_config();
  noscan.scan_channel_count = 0;
  DeviceEnds noscan_dev(noscan, device_identity(), 0xD1EC7, rig.faults());
  CHECK(noscan_dev.joiner.start_direct(boot, rig.port(), 0).ok());
  CHECK(dev.joiner.start_direct(boot, rig.port(), 0).ok());
  CHECK(!dev.joiner.start_direct(boot, rig.port(), 0).ok());  // already running
  CHECK(!dev.joiner.start(boot, 0).ok());
  // Radio RX during a direct run is an Owner bug: refused, nothing moves.
  CHECK(dev.joiner.on_rld1_rx(JoinRxMeta{}, ByteView{}, 0).code == StatusCode::InvalidState);
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM2; }, 30000));
  // An unexpected step drops counted; the staged m2 still processes.
  const std::array<std::uint8_t, 4> junk{1, 2, 3, 4};
  CHECK(dev.joiner
            .on_direct_message(JoinAuthPhase::EdhocMessage, 4,
                               ByteView{junk.data(), junk.size()}, rig.now())
            .ok());
  CHECK(dev.joiner.snapshot().counters.rx_dropped == 1);
  // A full mailbox answers Busy without overwriting: the pump already
  // staged m4, so the wedge is refused and the staged m4 still commits.
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::WaitM4; }, 30000));
  const AuthorityDown wedge{true, 5, true, Bytes{0xEE}};
  CHECK(dev.joiner
            .on_direct_message(JoinAuthPhase::EdhocMessage, wedge.step,
                               ByteView{wedge.body.data(), wedge.body.size()}, rig.now())
            .code == StatusCode::Busy);
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Ready; }, 30000));
  CHECK(rig.has_pending() && rig.pending().kind == JoinActionKind::MemberReady);
  current.clear();
}

void test_commit_policy_deny_no_write() {
  current = "commit policy deny";
  DirectRig rig;
  DeviceEnds& dev = rig.device();
  CountingPolicy policy;
  policy.allow = false;
  dev.joiner.set_commit_policy(&policy);
  CHECK(dev.joiner.start_direct(boot_input(), rig.port(), 0).ok());
  CHECK(rig.pump_until(
      [&] { return dev.joiner.snapshot().state == JoinState::Stopped; }, 30000));
  // The verified Allow was vetoed: avoided without writing anything.
  CHECK(policy.checks == 1);
  CHECK(dev.joiner.snapshot().counters.denies == 1);
  CHECK(!dev.site_store.has_site());
  for (const auto& op : dev.site_storage.log_) {
    CHECK(op.op != 'w');
  }
  current.clear();
}

}  // namespace

int main() {
  test_v1_j01_ordered_join();
  test_v1_j04_deny_then_second_site();
  test_v1_j04_deny_hold_six_hours();
  test_v1_j05_assigned_site_binds();
  test_v1_j06_forged_site_credential();
  test_v1_j06_inactive_anchor();
  test_v1_j07_forged_devcert();
  test_v1_j07_invalid_rli1();
  test_v1_j03_pending_then_allow();
  test_v1_j13_old_m2_rejected();
  test_v1_j13_old_m4_rejected();
  test_v1_j13_foreign_frames_dropped();
  test_v1_j13_old_m3_rejected_by_authority();
  test_v1_j13_edhoc_error_transient();
  test_v1_j12_broken_allow_matrix();
  test_v1_j12_role_and_move_on();
  test_v1_j12_strict_assignment();
  test_v1_j08_commit_cut_matrix();
  test_v1_j08_sealed_landed_adopts();
  test_v1_j08_cut_before_m4();
  test_v1_j08_readback_failure_adopts();
  test_v1_j08_reconcile_uncertain_pair();
  test_decision_deadline_before_commit();
  test_v1_j08_recover_cut_matrix();
  test_reentry_refused();
  test_109_chunk_loss_recovers();
  test_109_no_send_inside_message_callback();
  test_109_stale_m2_during_m3();
  test_quiescence_points();
  test_clock_regression_recovers();
  test_clock_domain_restart_clears_old_m1_rate_time();
  test_entropy_shortage_degrades();
  test_time_overflow_smoke();
  test_tune_failure_skips_channel();
  test_tune_failure_all_stalls();
  test_multi_anchor_scan();
  test_offer_wrong_destination_dropped();
  test_mailbox_full_keeps_first();
  test_hint_flood_ignored();
  test_unreachable_proxy_never_attempted();
  test_unknown_schema_stops();
  test_reconcile_rejects_changed_prepared_gk();
  test_seq_exhausted_stops();
  test_floor_regression_refused();
  test_cross_site_recover_forbidden();
  test_healthy_member_boot_adopts();
  test_member_boot_active_reread_failure();
  test_member_boot_unreadable_sibling();
  test_v1_j05_split_channels();
  test_v1_j05_split_orgs();
  test_v1_j05_proxy_changeover();
  test_refresh_proxy_is_attempted_proxy();
  test_joiner_size_budget();
  test_direct_allow_commits();
  test_direct_deny_parks_stopped();
  test_direct_edges();
  test_commit_policy_deny_no_write();
  if (failures == 0) {
    std::printf("joiner tests passed\n");
  } else {
    std::printf("joiner tests FAILED: %d\n", failures);
  }
  return failures == 0 ? 0 : 1;
}
