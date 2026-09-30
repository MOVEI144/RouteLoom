/* The smallest RouteLoom application, in C: boot the node from the
   component Kconfig through the Device C API; consumer.cpp logs its
   capabilities from the first Owner pass. */

#include <stdbool.h>

#include "routeloom/device.h"

void consumer_log_capabilities(rl_dev_t* device);

static void on_poll(void* user, rl_dev_t* device, rl_monotonic_ms_t now_ms) {
  static bool logged;
  (void)user;
  (void)now_ms;
  if (logged) return;
  logged = true;
  consumer_log_capabilities(device);
}

void app_main(void) {
  rl_dev_observer_t observer;
  rl_dev_struct_init(&observer, sizeof observer);
  observer.on_poll = on_poll;
  (void)rl_dev_start(&observer);
}
