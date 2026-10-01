#include <cstdio>
#include "join_sim_network.hpp"

namespace {
using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;
using namespace join_sim;
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
constexpr NodeId kDeviceNode = 0x00A1000000001234ULL;
constexpr MacAddress kDeviceMac{{0x02, 0, 0, 0, 0x12, 0x34}};
constexpr std::uint64_t kSiteA = 0x5173000000000042ULL;
constexpr std::uint64_t kSiteB = 0x51730000000000B7ULL;
constexpr NetworkId kNetworkA = (static_cast<NetworkId>(3) << 32U) | 0x0A1B2C3DU;
constexpr NetworkId kNetworkB = (static_cast<NetworkId>(5) << 32U) | 0x0B1B2C3DU;
constexpr NodeId kGatewayA = 0x00A1000000000001ULL;
constexpr NodeId kGatewayB = 0x00A1000000000002ULL;
constexpr std::uint32_t kBootWitness = 0x00001234U;

const routeloom_test::TestKeyPair& sak_b() {
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

SimSiteParams site_b_params(std::uint8_t channel = 6,
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


struct Measurement { std::uint32_t attempts; std::uint64_t bytes; };
Measurement selection(bool smart, bool expected, bool expired, bool denied) {
  auto config = device_config();
  config.smart_join = smart;
  config.listen_ms = 1000;
  config.search_ms = 60000;
  JoinSimNetwork net(config, identity_record());
  auto a = site_a_params(6, -30);
  a.policy.verdict = JoinVerdict::DenyNotHere;
  auto b = site_b_params(6, -60);
  if (denied) b.policy.verdict = JoinVerdict::DenyNotHere;
  net.add_site(a);
  net.add_site(b);
  ExpectedJoinList list{};
  list.ttl_s = 300;
  list.count = expected ? 1 : 0;
  CHECK(identity_join_mark(net.device().identity_store.identity(), list.marks[0]));
  net.site(1).set_expected(list, expired ? 1 : 300000);
  net.site(0).set_expected(ExpectedJoinList{}, 300000);
  std::uint64_t bytes = 0;
  net.faults().drop_if = [&](RadioDir direction, const Bytes& frame) {
    bytes += frame.size();
    autonomy::Rld1Envelope env{};
    if (direction == RadioDir::Up && autonomy::rld1_decode(view(frame), env) &&
        env.kind == FrameType::Discover && smart) {
      CHECK(env.claimed_node != kDeviceNode);
      CHECK(env.body_size == 40);
      CHECK(std::memcmp(env.body.data() + 24, list.marks[0].data(), 16) != 0);
    }
    return false;
  };
  CHECK(net.device().joiner.start(boot_input(), 0));
  CHECK(net.pump_until([&] { return net.now() >= 995; }, 1000));
  if (smart) CHECK(net.device().radio.sends == 0);
  CHECK(net.pump_until([&] {
    return net.has_terminal_action() || net.device().joiner.snapshot().state == JoinState::Stopped;
  }, 61000));
  auto snap = net.device().joiner.snapshot();
  if (expected && !expired && !denied) {
    CHECK(net.has_terminal_action());
    CHECK(net.device().site_store.site().site_id == kSiteB);
    CHECK(snap.counters.m1_sent == (smart ? 1U : 2U));
  } else if (smart) {
    CHECK(!net.device().site_store.has_site());
    CHECK(snap.counters.m1_sent == (denied ? 1U : 0U));
    CHECK(net.now() <= 60005);
  }
  if (smart) CHECK(net.site(0).authority_.m1_seen == 0);
  return {snap.counters.m1_sent, bytes};
}

void retained_membership() {
  JoinSimNetwork net(device_config(), identity_record());
  net.add_site(site_a_params());
  CHECK(net.device().joiner.start(boot_input(), 0));
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  const auto seq = net.device().site_store.commit_seq();
  net.clear_terminal();
  auto config = device_config();
  config.smart_join = true;
  config.same_site_only = true;
  config.listen_ms = 1000;
  net.restart_device(config, 0x197);
  CHECK(net.device().joiner.start(boot_input(), net.now()));
  CHECK(net.pump_until([&] { return net.has_terminal_action(); }, 30000));
  CHECK(net.device().radio.sends == 0); // J02a: healthy boot does not request admission
  net.clear_terminal();
  net.restart_device(config, 0x198);
  net.site(0).set_proxy_muted(0, true);
  net.add_site(site_b_params());
  ExpectedJoinList expected{};
  expected.count = 1;
  expected.ttl_s = 300;
  CHECK(identity_join_mark(identity_record(), expected.marks[0]));
  net.site(1).set_expected(expected, net.now() + 300000);
  auto boot = boot_input();
  boot.mode = JoinBootMode::VerifyExistingMembership;
  const auto started = net.now();
  CHECK(net.device().joiner.start(boot, started));
  CHECK(net.pump_until([&] { return net.device().joiner.snapshot().state == JoinState::Stopped; }, 60005));
  CHECK(net.site(1).authority_.m1_seen == 0);
  CHECK(net.device().site_store.site().site_id == kSiteA);
  CHECK(net.device().site_store.commit_seq() == seq);
  CHECK(net.device().site_storage.writes() == 0);
}

void finite_and_api_only() {
  auto config = device_config();
  config.smart_join = true;
  config.boot_join = false;
  config.listen_ms = 5000;
  config.search_ms = 1000;
  JoinSimNetwork net(config, identity_record());
  CHECK(net.device().joiner.start(boot_input(), 0));
  CHECK(net.device().joiner.poll(0));
  CHECK(net.device().joiner.snapshot().state == JoinState::Stopped);
  CHECK(net.device().joiner.retry_now(0));
  CHECK(net.device().joiner.poll(0));
  CHECK(net.device().joiner.next_deadline() == 1000);
  CHECK(net.device().joiner.retry_now(0));
  CHECK(net.device().joiner.next_deadline() == 1000); // API cannot bypass listen-first
  net.skip_to(1000);
  CHECK(net.device().joiner.snapshot().state == JoinState::Stopped);
  CHECK(net.device().radio.sends == 0);
}
}

int main() {
  const auto old = selection(false, true, false, false);
  const auto smart = selection(true, true, false, false);
  CHECK(smart.attempts < old.attempts);
  CHECK(smart.bytes < old.bytes);
  std::printf("J02 legacy: m1=%u radio_bytes=%llu; smart: m1=%u radio_bytes=%llu\n",
      old.attempts, static_cast<unsigned long long>(old.bytes), smart.attempts,
      static_cast<unsigned long long>(smart.bytes));
  // J02d/e: cancel, expiry/missing, and a matching mark refused by Authority.
  selection(true, false, false, false);
  selection(true, true, true, false);
  selection(true, true, false, true);
  retained_membership();
  finite_and_api_only();
  return failures == 0 ? 0 : 1;
}
