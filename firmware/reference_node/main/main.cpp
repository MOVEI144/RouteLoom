// firmware/reference_node: the reference RouteLoom node on the shared node
// boot (design-devflow.md §5.1). All bring-up — NVS, boot session, sdkv1
// stores, security owner, runtime, discovery/migration/config opt-ins and
// the pump loops — lives in components/routeloom_node_boot and is shared
// verbatim with firmware/bench_node. This image ships no application
// observer: the shared observer logs traffic exactly as before.

#include "routeloom/node_boot.hpp"

extern "C" void app_main(void) {
  routeloom::espnow::NodeBootHooks hooks{};
  hooks.log_tag = "RouteLoomRef";
  routeloom::espnow::run_node(hooks);
}
