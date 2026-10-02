#include <cstdio>
#include <cstring>
#include <vector>

#include "test_sim.hpp"

using namespace routeloom;
using namespace routeloom_test;

class Sink final : public AppliedEndpointSink {
 public:
  unsigned calls{0};
  void on_applied_request(const AppliedRequest&, AppliedReply& reply) noexcept override {
    ++calls;
    reply.outcome = endpoint::AppResultOutcome::Success;
  }
};

bool expired_emit_window_naps() {
  SimWorld world;
  world.add(1, 1, 100000, 300000);
  auto* terminal = world.add(2, 1, 100000, 300000);
  world.start_all();
  world.link(1, 2, 1, 1);
  Sink sink;
  if (!terminal->set_applied_sink(&sink)) return false;
  world.net.silent_drop = +[](const SimNetwork::Pending& pending) {
    FrameSight sight{};
    return sight_frame({pending.frame.data(), pending.frame.size()}, sight) &&
           sight.type == FrameType::AppResult;
  };
  SendOptions options{};
  options.delivery = DeliveryClass::Applied;
  options.lifetime_ms = 100;
  options.hop_limit = 1;
  MessageId id{};
  const std::uint8_t payload = 42;
  if (!world.at(1)->send_applied(2, {&payload, 1}, terminal->applied_lease(), options, 0, id))
    return false;
  world.run(20);
  if (sink.calls != 1 || terminal->applied_stats().results_emitted != 1) return false;
  if (!terminal->remove_neighbor(1, world.now)) return false;
  world.run(kAppliedLateResultMs + 200);
  if (!terminal->poll(world.now)) return false;
  // A retained result with a closed emit window has no runnable retry.
  // It must not pin next_deadline to a past timestamp until retention ends.
  if (terminal->next_deadline(world.now) <= world.now) {
    std::fprintf(stderr, "expired APPLIED emit window spins the Owner\n");
    return false;
  }
  return true;
}

int main() {
  if (!expired_emit_window_naps()) return 1;
  std::vector<std::vector<std::uint8_t>> frames[2];
  std::vector<DeliveryResult> results[2];
  std::vector<std::string> events[2];
  unsigned polls[2]{};
  for (unsigned adaptive = 0; adaptive < 2; ++adaptive) {
    SimWorld world;
    world.add(1);
    world.add(2);
    world.add(3);
    world.start_all();
    world.link(1, 2, 1, 1);
    world.link(2, 3, 1, 1);
    world.net.capture = [&](NodeId from, NodeId to, ByteView frame) {
      std::vector<std::uint8_t> bytes;
      bytes.push_back(static_cast<std::uint8_t>(from));
      bytes.push_back(static_cast<std::uint8_t>(to));
      bytes.insert(bytes.end(), frame.data, frame.data + frame.size);
      frames[adaptive].push_back(std::move(bytes));
    };
    for (MonotonicMs now = 0; now <= 5000;) {
      if (now == 125) {
        SendOptions options{};
        options.lifetime_ms = 501;
        MessageId id{};
        const std::uint8_t payload = 42;
        if (!world.at(1)->send(3, {&payload, 1}, options, now, id)) return 1;
      }
      for (auto& entry : world.nodes) {
        if (!entry.second->poll(now)) return 1;
        ++polls[adaptive];
      }
      world.net.flush(now);
      MonotonicMs due = now < 125 ? 125 : 5001;
      for (auto& entry : world.nodes) {
        const auto deadline = entry.second->next_deadline(now);
        due = std::min(due, std::max(now + 1, deadline));
        if (adaptive != 0 && deadline > now + 1) {
          const auto scans = entry.second->work_stats().expiry_slots_scanned;
          if (!entry.second->poll(now + 1) ||
              entry.second->work_stats().expiry_slots_scanned != scans) {
            std::fprintf(stderr, "active poll before deadline performed work\n");
            return 1;
          }
        }
      }
      now = adaptive != 0 ? due : now + 1;
    }
    results[adaptive] = world.obs(1)->delivery_events;
    events[adaptive] = world.obs(1)->diagnostics;
    if (world.obs(3)->messages.size() != 1) return 1;
  }
  if (frames[0] != frames[1] || events[0] != events[1] || results[0].size() != results[1].size()) {
    std::fprintf(stderr, "deadline trace mismatch: frames %zu/%zu, results %zu/%zu\n",
                 frames[0].size(), frames[1].size(), results[0].size(), results[1].size());
    return 1;
  }
  for (std::size_t i = 0; i < results[0].size(); ++i) {
    if (results[0][i].id != results[1][i].id || results[0][i].state != results[1][i].state ||
        std::strcmp(results[0][i].reason, results[1][i].reason) != 0)
      return 1;
  }
  if (polls[1] >= polls[0] / 2) return 1;
  std::printf("active mesh polls: eager=%u deadline=%u; frames=%zu, results=%zu\n", polls[0],
              polls[1], frames[0].size(), results[0].size());
}
