// Dev-RAM route over the owner sim (G-SEC P4 §10.1, #95): two static
// adoptions discover (Required dev scope), complete the PSK-rooted
// RLRES1 link, and serve pairwise + group traffic with zero durable
// store writes. A wrong PSK never establishes.
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/group.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "test_sdkv1.hpp"
#include "test_sdkv1_owner_sim.hpp"

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,  \
                   current.c_str(), #expr);                                    \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;
using namespace owner_sim;

constexpr NodeId kDevNodeA = 0x00A1000000001234ULL;
constexpr NodeId kDevNodeB = 0x00A1000000005678ULL;
constexpr NodeId kDevNodeC = 0x00A1000000009ABCULL;
const MacAddress kDevMacA{{0x02, 0, 0, 0, 0x12, 0xA1}};
const MacAddress kDevMacB{{0x02, 0, 0, 0, 0x12, 0xB2}};
const MacAddress kDevMacC{{0x02, 0, 0, 0, 0x12, 0xC3}};
constexpr MonotonicMs kDevT0 = 100000;
constexpr std::uint32_t kDevBoot = 41;

keys::Secret dev_test_psk() {
  keys::Secret psk{};
  for (std::size_t i = 0; i < psk.size(); ++i) psk[i] = static_cast<std::uint8_t>(0x30 + i);
  return psk;
}

struct DevPair {
  SimNode a{kDevNodeA, kDevMacA, 0xD1A, kResume2NodeLinkQuota + kResume2NodeEndQuota};
  SimNode b{kDevNodeB, kDevMacB, 0xD1B, kResume2NodeLinkQuota + kResume2NodeEndQuota};
  SimLink link{a, b};
};

bool boot_dev_pair(DevPair& pair, MonotonicMs& now) {
  if (!pair.a.init_stores() || !pair.b.init_stores()) return false;
  if (!pair.a.boot_dev(now, dev_test_psk(), kNetwork, kDevBoot)) return false;
  if (!pair.b.boot_dev(now, dev_test_psk(), kNetwork, kDevBoot)) return false;
  for (int i = 0; i < 500; ++i) {
    now += 10;
    pair.link.pump_tick(now);
    if (pair.a.adopted_valid() && pair.b.adopted_valid() && pair.a.discovery() != nullptr &&
        pair.b.discovery() != nullptr) {
      return true;
    }
  }
  return false;
}

bool link_until_established(DevPair& pair, MonotonicMs& now, const int cap_ticks = 1500) {
  for (int i = 0; i < cap_ticks; ++i) {
    now += 10;
    pair.link.pump_tick(now);
    if (pair.a.link_session_to(kDevNodeB) && pair.b.link_session_to(kDevNodeA)) return true;
  }
  return false;
}

// One sealed link frame A -> B through the live mux providers, opened
// twice: the first open accepts, the replay refuses and wipes.
bool link_roundtrip_with_replay(DevPair& pair) {
  SecurityProvider& a = pair.a.coordinator().session_provider();
  SecurityProvider& b = pair.b.coordinator().session_provider();
  std::uint32_t epoch = 0;
  if (!a.tx_epoch(SecurityScope::Link, kDevNodeB, epoch).ok()) return false;
  SecurityContext tx{};
  tx.scope = SecurityScope::Link;
  tx.network = kNetwork;
  tx.sender = kDevNodeA;
  tx.receiver = kDevNodeB;
  tx.epoch = epoch;
  std::uint64_t counter = 0;
  if (!a.next_counter(tx, counter).ok()) return false;
  const std::uint8_t aad[] = {0xAA};
  const std::uint8_t plain[] = {1, 2, 3, 4};
  std::array<std::uint8_t, 4> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  if (!a.seal(tx, counter, ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
              MutableByteView{cipher.data(), cipher.size()}, tag).ok()) {
    return false;
  }
  SecurityContext rx = tx;
  std::array<std::uint8_t, 4> opened{};
  if (!b.open(rx, counter, ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
              tag, MutableByteView{opened.data(), opened.size()}).ok()) {
    return false;
  }
  if (opened[0] != 1 || opened[1] != 2 || opened[2] != 3 || opened[3] != 4) return false;
  // The same frame twice is a replay: refused before any window update
  // (the bank never touches the caller's buffer on refusal).
  if (b.open(rx, counter, ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
             tag, MutableByteView{opened.data(), opened.size()}).code !=
      StatusCode::ReplayRejected) {
    return false;
  }
  return true;
}

bool group_roundtrip_with_replay(DevPair& pair) {
  SecurityProvider& a = pair.a.coordinator().session_provider();
  SecurityProvider& b = pair.b.coordinator().session_provider();
  const NodeId group = group_address(1);
  std::uint32_t epoch = 0;
  if (!a.tx_epoch(SecurityScope::Group, kBroadcastNodeId, epoch).ok() || epoch != 1) {
    return false;
  }
  SecurityContext tx{};
  tx.scope = SecurityScope::Group;
  tx.network = kNetwork;
  tx.sender = kDevNodeA;
  tx.receiver = kBroadcastNodeId;
  tx.epoch = epoch;
  tx.group_epoch = 0;
  tx.sender_boot = kDevBoot;
  tx.group_id = group;
  std::uint64_t counter = 0;
  if (!a.next_counter(tx, counter).ok()) return false;
  const char* msg = "hello dev group";
  std::array<std::uint8_t, 64> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  const ByteView plain{reinterpret_cast<const std::uint8_t*>(msg), 15};
  if (!a.seal(tx, counter, {}, plain, MutableByteView{cipher.data(), 15}, tag).ok()) {
    return false;
  }
  std::array<std::uint8_t, 64> opened{};
  const MutableByteView pt_view{opened.data(), 15};
  if (!b.open(tx, counter, {}, ByteView{cipher.data(), 15}, tag, pt_view).ok()) return false;
  if (std::memcmp(opened.data(), msg, 15) != 0) return false;
  std::memset(opened.data(), 0xA5, 15);
  if (b.open(tx, counter, {}, ByteView{cipher.data(), 15}, tag, pt_view).code !=
      StatusCode::ReplayRejected) {
    return false;
  }
  for (int i = 0; i < 15; ++i) {
    if (opened[static_cast<std::size_t>(i)] != 0) return false;
  }
  return true;
}

void test_dev_link_discovers_and_binds() {
  // The full #95 pairwise path: static adopt, Required-scope discovery,
  // PSK-rooted RLRES1 both directions, elevated bindings, DATA both
  // ways, replay refused.
  current = "dev_link_discovers_and_binds";
  DevPair pair{};
  MonotonicMs now = kDevT0;
  CHECK(boot_dev_pair(pair, now));
  CHECK(pair.a.coordinator().snapshot().mode == CoordinatorMode::Dev);
  CHECK(pair.b.coordinator().snapshot().mode == CoordinatorMode::Dev);
  CHECK(pair.a.adopted().node == kDevNodeA && pair.a.adopted().boot_session == kDevBoot);
  CHECK(pair.b.adopted().node == kDevNodeB && pair.b.adopted().boot_session == kDevBoot);
  CHECK(pair.a.demand_link(kDevNodeB));
  CHECK(pair.b.demand_link(kDevNodeA));
  CHECK(link_until_established(pair, now));
  // Elevation bound the discovery neighbors on both ends.
  BindingId binding{kInvalidBindingId};
  CHECK(pair.a.discovery()->binding_of(kDevNodeB, binding));
  CHECK(pair.b.discovery()->binding_of(kDevNodeA, binding));
  CHECK(pair.a.coordinator().snapshot().link_sessions == 1);
  CHECK(pair.b.coordinator().snapshot().link_sessions == 1);
  // Dev provenance: generation 0, created_gk 1 (visible through the
  // membership evidence the hooks already vetted).
  std::uint32_t generation = 0, role = 0;
  CHECK(pair.a.coordinator().authenticated(kDevNodeB, kNetwork, generation, role));
  CHECK(generation == 0 && role != 0);
  CHECK(link_roundtrip_with_replay(pair));
  // The reverse direction seals under its own context.
  SecurityProvider& b = pair.b.coordinator().session_provider();
  std::uint32_t epoch = 0;
  CHECK(b.tx_epoch(SecurityScope::Link, kDevNodeA, epoch).ok());
}

void test_dev_group_serves_through_mux() {
  current = "dev_group_serves_through_mux";
  DevPair pair{};
  MonotonicMs now = kDevT0;
  CHECK(boot_dev_pair(pair, now));
  CHECK(group_roundtrip_with_replay(pair));
  // The mux group side accepts exactly the fixed dev epoch.
  CHECK(pair.a.coordinator().session_provider().accepts_group_epoch(1));
  CHECK(!pair.a.coordinator().session_provider().accepts_group_epoch(2));
  CHECK(!pair.a.coordinator().session_provider().group_promotion_pending());
}

void test_dev_no_store_writes() {
  // V1-N01 coordinator shape: a full link + group session writes no
  // resume slot (no c/f/r growth, #37) and reads none.
  current = "dev_no_store_writes";
  DevPair pair{};
  MonotonicMs now = kDevT0;
  CHECK(boot_dev_pair(pair, now));
  CHECK(pair.a.demand_link(kDevNodeB));
  CHECK(pair.b.demand_link(kDevNodeA));
  CHECK(link_until_established(pair, now));
  CHECK(link_roundtrip_with_replay(pair));
  CHECK(group_roundtrip_with_replay(pair));
  CHECK(pair.a.resume_writes() == 0 && pair.b.resume_writes() == 0);
  CHECK(pair.a.resume_reads() == 0 && pair.b.resume_reads() == 0);
}

void test_dev_wrong_psk_no_session() {
  // A third node on another PSK hears the same radio but the Required
  // dev scope drops its DISCOVER/OFFER before any crypto runs: no leg,
  // no session, no store traffic.
  current = "dev_wrong_psk_no_session";
  DevPair pair{};
  MonotonicMs now = kDevT0;
  CHECK(boot_dev_pair(pair, now));
  CHECK(pair.a.demand_link(kDevNodeB));
  CHECK(pair.b.demand_link(kDevNodeA));
  CHECK(link_until_established(pair, now));
  SimNode c{kDevNodeC, kDevMacC, 0xD1C, kResume2NodeLinkQuota + kResume2NodeEndQuota};
  CHECK(c.init_stores());
  keys::Secret other = dev_test_psk();
  other[0] ^= 1;
  CHECK(c.boot_dev(now, other, kNetwork, kDevBoot));
  // C adopts and discovers against A, but neither binds the other and
  // no link forms in either direction.
  SimLink link_ac{pair.a, c};
  for (int i = 0; i < 800; ++i) {
    now += 10;
    link_ac.pump_tick(now);
  }
  CHECK(c.adopted_valid() && c.discovery() != nullptr);
  CHECK(!c.link_session_to(kDevNodeA));
  CHECK(!pair.a.link_session_to(kDevNodeC));
  CHECK(pair.a.demand_link(kDevNodeC));  // still unknown: demand, no session
  BindingId binding{kInvalidBindingId};
  CHECK(!pair.a.discovery()->binding_of(kDevNodeC, binding));
  CHECK(!c.discovery()->binding_of(kDevNodeA, binding));
  // The A-B link survived the foreign chatter untouched.
  CHECK(pair.a.link_session_to(kDevNodeB));
  CHECK(c.resume_writes() == 0 && pair.a.resume_writes() == 0);
}

void test_dev_end_scope() {
  // End-to-end dev sessions ride the mesh bootstrap lane through the
  // same engine/demux legs as the member route.
  current = "dev_end_scope";
  DevPair pair{};
  MonotonicMs now = kDevT0;
  CHECK(boot_dev_pair(pair, now));
  CHECK(pair.a.demand_link(kDevNodeB));
  CHECK(pair.b.demand_link(kDevNodeA));
  CHECK(link_until_established(pair, now));
  SecurityProvider& a = pair.a.coordinator().session_provider();
  SecurityProvider& b = pair.b.coordinator().session_provider();
  std::uint32_t epoch = 0;
  CHECK(a.tx_epoch(SecurityScope::EndToEnd, kDevNodeB, epoch).code == StatusCode::AuthRequired);
  bool established = false;
  for (int i = 0; i < 1500; ++i) {
    now += 10;
    pair.link.pump_tick(now);
    if (a.tx_epoch(SecurityScope::EndToEnd, kDevNodeB, epoch).ok() &&
        b.tx_epoch(SecurityScope::EndToEnd, kDevNodeA, epoch).ok()) {
      established = true;
      break;
    }
  }
  CHECK(established);
  CHECK(pair.a.coordinator().snapshot().end_sessions == 1);
  CHECK(!pair.a.mesh_.end_profiles.empty());
  CHECK(!pair.b.mesh_.end_profiles.empty());
  for (const std::uint8_t profile : pair.a.mesh_.end_profiles) {
    CHECK(profile == kEndProfileDev);
  }
  for (const std::uint8_t profile : pair.b.mesh_.end_profiles) {
    CHECK(profile == kEndProfileDev);
  }
  std::uint32_t generation = 0, role = 0;
  CHECK(pair.a.coordinator().authenticated(kDevNodeB, kNetwork, generation, role));
  CHECK(generation == 0 && role != 0);

  // A valid end envelope from the other security profile is refused at
  // the lane gate before its untrusted message reaches the engine.
  const std::uint8_t message[] = {0x01};
  EndObject wrong{};
  wrong.phase = JoinAuthPhase::Resume;
  wrong.step = 1;
  wrong.exchange_id = 0x12345678;
  wrong.profile = kEndProfileMember;
  wrong.message = ByteView{message, sizeof(message)};
  std::array<std::uint8_t, kEndObjectMax> encoded{};
  std::size_t written = 0;
  CHECK(end_object_encode(wrong, MutableByteView{encoded.data(), encoded.size()}, written).ok());
  BootstrapMeta meta{};
  meta.origin = kDevNodeB;
  meta.destination = kDevNodeA;
  const std::uint32_t before = pair.a.coordinator().counters().demux_drops;
  CHECK(pair.a.coordinator().on_frame(meta, FrameType::BootstrapAuth,
                                      ByteView{encoded.data(), written}, now).ok());
  CoordinatorEvent poll{};
  poll.kind = CoordinatorEventKind::Poll;
  poll.now = now + 1;
  CHECK(pair.a.coordinator().step(poll).ok());
  CHECK(pair.a.coordinator().counters().demux_drops == before + 1);
}

void test_dev_ignores_stale_member_channel() {
  current = "dev_ignores_stale_member_channel";
  SimNode node{kDevNodeA, kDevMacA, 0xD1A, kResume2NodeLinkQuota + kResume2NodeEndQuota};
  CHECK(node.init_stores());
  SiteRecord old = site_record();
  old.channel = kSimChannel + 1;
  CHECK(node.site().commit(old).ok());
  CHECK(node.boot_dev(kDevT0, dev_test_psk(), kNetwork, kDevBoot));
  node.drain_actions(kDevT0);
  CHECK(node.operating_channel() == kSimChannel);
  CHECK(node.coordinator().snapshot().mode == CoordinatorMode::Dev);
}

}  // namespace

int main() {
  test_dev_link_discovers_and_binds();
  test_dev_group_serves_through_mux();
  test_dev_no_store_writes();
  test_dev_wrong_psk_no_session();
  test_dev_end_scope();
  test_dev_ignores_stale_member_channel();
  if (failures != 0) {
    std::fprintf(stderr, "FAILURES: %d\n", failures);
    return 1;
  }
  std::printf("dev route tests passed\n");
  return 0;
}
