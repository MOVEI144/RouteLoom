#pragma once

// Shared node boot for the firmware images (design-devflow.md §5.1):
// firmware/reference_node and firmware/bench_node run the SAME NVS /
// boot-session / sdkv1-stores / security-owner / runtime bring-up and the
// same pump loops — only the application observer and per-iteration work
// differ. Apps implement NodeBootHooks; run_node() below is the whole
// app_main body. Keeping the wiring here is what keeps the bench image an
// honest example of the public SDK path instead of a drifting copy of the
// reference main.

#include "routeloom/types.hpp"

namespace routeloom {

class NodeObserver;

namespace espnow {

class EspNowRuntime;
class EspNowSecurityOwner;
class Sdkv1Stores;

// Application surface of the shared boot. All pointers may be null — a
// null observer keeps the log-only behavior reference_node ships with.
struct NodeBootHooks {
  // Serial tag for the node's own log lines (owner_config.log_tag).
  // nullptr selects the shared default.
  const char* log_tag{nullptr};
  // Application observer bound into the runtime's MeshNode. Borrowed — must
  // be static storage (the runtime outlives run_node's frame).
  NodeObserver* observer{nullptr};
  // Called once after runtime.initialize() (and owner.attach_runtime() on
  // the owner profiles): the app attaches to the live node here. `owner`
  // is nullptr in the LegacyFixture profile; `stores` is the opened sdkv1
  // store set (identity/site/revocation/resume) every profile keeps.
  void (*attach)(EspNowRuntime& runtime, EspNowSecurityOwner* owner,
                 Sdkv1Stores* stores, void* ctx){nullptr};
  // Called once per pump iteration in every profile's main loop (owner
  // loop, deep-sleep loop, and the app pump next to the runtime task on
  // LegacyFixture). Runs in the pump thread — never blocks.
  void (*poll)(MonotonicMs now_ms, void* ctx){nullptr};
  void* ctx{nullptr};
};

// Runs the node lifecycle: NVS + boot session + sdkv1 stores + security
// owner + runtime + optional discovery/migration/config + pump. Returns
// only in the LegacyFixture profile when no poll hook needs the app_main
// thread; every failure goes through the fail-streak restart/sleep path.
void run_node(const NodeBootHooks& hooks);

}  // namespace espnow
}  // namespace routeloom
