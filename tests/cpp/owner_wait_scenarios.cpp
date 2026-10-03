#include <algorithm>
#include <cstdio>

#include "freertos/task.h"
#include "idf_stubs.hpp"
#include "routeloom/espnow_security_owner.hpp"

int run_owner_blocked_wait_scenario(routeloom::espnow::EspNowSecurityOwner& owner,
                                   routeloom::espnow::EspNowRuntime& runtime,
                                   routeloom::MonotonicMs now) {
  using namespace routeloom;
  (void)ulTaskNotifyTake(pdTRUE, 0);
  idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
  idf_stub::enable_notify_clock();
  // Coalesced wakes for work already drained cost one extra pass, then block.
  for (unsigned i = 0; i < 32; ++i) runtime.notify_owner();
  const auto end_us = idf_stub::now_us() + 1000000;
  unsigned passes = 0;
  while (idf_stub::now_us() < end_us && passes < 2000) {
    now = static_cast<MonotonicMs>(idf_stub::now_us() / 1000);
    runtime.poll_once();
    owner.poll(now);
    // This is a virtual CPU charge, not a measurement of C6 occupancy.
    idf_stub::set_now_us(idf_stub::now_us() + 100);
    const auto wait_now = static_cast<MonotonicMs>(idf_stub::now_us() / 1000);
    const auto due = std::min(runtime.next_deadline(wait_now), owner.next_deadline(wait_now));
    runtime.wait_for_event(due > wait_now ? due - wait_now : 0);
    ++passes;
  }
  const auto stats = idf_stub::notify_wait_stats();
  const unsigned wake_limit = 2 * configTICK_RATE_HZ + 1;
  std::printf("blocked Owner: passes=%u waits=%u blocks=%u wakes=%u max_running=%llu us\n",
              passes, stats.waits, stats.blocks, stats.wakes,
              static_cast<unsigned long long>(stats.max_running_us));
  if (idf_stub::now_us() < end_us || stats.blocks == 0 || passes > wake_limit ||
      stats.waits > wake_limit || stats.wakes != 32 || stats.max_running_us > 25000) {
    std::fprintf(stderr, "blocked authority keeps Owner runnable\n");
    return 1;
  }
  return 0;
}
