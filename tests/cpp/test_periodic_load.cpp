// K02: latest values and reliable status through MeshNode with product timers.
#include <array>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <vector>

#include "test_sim.hpp"

using namespace routeloom;
using routeloom_test::SimWorld;

int main() {
  SimWorld w;
  w.net.record_sights = false;
  w.configure = [](NodeConfig& config) {
    config.route_gateways = {1, kInvalidNodeId};
    config.route_advertisement_period_ms = kScopedProductPeriodMs;
    config.route_lifetime_ms = kScopedProductLifetimeMs;
    config.route_refresh_ticks = kScopedDefaultRefreshTicks;
  };
  for (NodeId n = 1; n <= 31; ++n) w.add(n);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(1, 4, 1, 1);
  for (NodeId n = 5; n <= 21; ++n) w.link(2 + (n - 5) / 6, n, 1, 1);
  for (NodeId n = 22; n <= 31; ++n) w.link(n - 10, n, 1, 1);
  // K02 retains a second relay path during churn.
  w.link(2, 3, 1, 1);
  w.run(120000, 50);
  w.net.route_control_tx.clear();
  const MonotonicMs start = w.now;
  const MonotonicMs duration = std::getenv("ROUTELOOM_E2E_NIGHTLY") ? 1800000 : 300000;
  std::map<NodeId, std::size_t> last_rx;
  std::map<NodeId, MonotonicMs> last_view;
  std::map<NodeId, std::set<std::vector<std::uint8_t>>> unique;
  std::size_t status_sent = 0;
  std::size_t fault_hits = 0;
  std::size_t failures = 0;
  auto check = [&](bool ok, const char* detail) {
    if (!ok) {
      std::fprintf(stderr, "K02 failed at %llu ms: %s\n",
                   static_cast<unsigned long long>(w.now - start), detail);
      ++failures;
    }
  };
  for (MonotonicMs t = 0; t < duration; t += 50) {
    if (t == 60000) {
      w.net.disconnect(1, 3);
      ++fault_hits;
    }
    if (t == 65000) w.net.connect(1, 3);
    for (NodeId n = 22; n <= 31; ++n) {
      const MonotonicMs offset = (n - 22) * 400;
      const bool view = t % 5000 == offset;
      const bool status = t % 15000 == offset + 100 || t % 90000 == offset + 300;
      const bool content = t % 60000 == offset + 200;
      if (!view && !status && !content) continue;
      std::array<std::uint8_t, 127> payload{};
      payload[0] = view ? 1 : (content ? 3 : 2);
      payload[1] = static_cast<std::uint8_t>(n);
      for (unsigned i = 0; i < 8; ++i) payload[2 + i] = t >> (8 * i);
      SendOptions options{};
      options.delivery = view || content ? DeliveryClass::BestEffort : DeliveryClass::Reliable;
      options.lifetime_ms = 5000;
      options.coalesce_key = view ? 1 : (content ? 2 : 0);
      MessageId id{};
      const auto sent = w.at(view || content ? 1 : n)->send(
          view || content ? n : 1,
          ByteView{payload.data(), view ? 10U : (content ? 127U : 34U)}, options, w.now, id);
      check(sent.ok() || (!status && (sent.code == StatusCode::NoRoute ||
            sent.code == StatusCode::Busy || sent.code == StatusCode::NoCapacity ||
            sent.code == StatusCode::WouldBlock)), "accepted or explicit latest-value refusal");
      if (status) ++status_sent;
    }
    w.run(0, 50);
    for (NodeId n = 1; n <= 31; ++n) {
      const auto& received = w.obs(n)->messages;
      for (std::size_t i = last_rx[n]; i < received.size(); ++i) {
        const auto& payload = received[i];
        check(unique[n].insert(payload).second, "no duplicate application receive");
        if (payload[0] == 1) {
          if (last_view[n] != 0) check(w.now - last_view[n] < 20000, "view fresh");
          last_view[n] = w.now;
        }
      }
      last_rx[n] = received.size();
      if (n >= 22 && t >= 20000) check(w.now - last_view[n] < 20000, "continuous view fresh");
    }
  }
  w.run(5000, 50);
  check(fault_hits == 1, "churn fired");
  check(w.obs(1)->messages.size() * 1000 >= status_sent * 995, "reliable status >=99.5%");
  for (NodeId n = 22; n <= 31; ++n) check(w.now - last_view[n] < 20000, "final view fresh");
  const MonotonicMs elapsed = w.now - start;
  std::uint64_t total = 0;
  for (const auto& [node, tally] : w.net.route_control_tx) {
    const auto us = (tally.bytes + tally.frames * kTxFrameFixedCostBytes) * 32;
    total += us;
    (void)node;
  }
  check(total * 1000 / elapsed / w.nodes.size() <= 1000, "mean management airtime <=1000 us/s");
  check(total * 1000 / elapsed <= 100000, "network management airtime <=100000 us/s");
  std::fprintf(stderr, "K02: status=%zu/%zu, management=%llu us/s, fault_hits=%zu\n",
               w.obs(1)->messages.size(), status_sent,
               static_cast<unsigned long long>(total * 1000 / elapsed), fault_hits);
  return failures ? 1 : 0;
}
