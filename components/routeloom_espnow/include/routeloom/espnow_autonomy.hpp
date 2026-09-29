#pragma once

// ESP-NOW glue for the portable NeighborDiscovery engine (issue #3, P1b):
// a log-backed discovery observer. The security owner runs the engine with
// its own entropy, membership hooks and authenticator.

#include "routeloom/discovery.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::espnow {

// ESP_LOG-backed discovery observer: every engine reason string
// (PEER_CAPACITY, BOUND, REACHABLE, STALE, ...) lands in the app log. When
// a runtime is supplied the same reason is forwarded through the node's
// diagnostic tap, so discovery events ride the existing USB bridge
// diagnostic frames — real engine events only, never synthesized.
class EspNowDiscoveryObserver final : public DiscoveryObserver {
 public:
  EspNowDiscoveryObserver(const char* tag, EspNowRuntime* runtime) noexcept
      : tag_(tag), runtime_(runtime) {}
  void on_discovery_event(const char* reason, NodeId peer) noexcept override;

 private:
  const char* tag_;
  EspNowRuntime* runtime_;
};

}  // namespace routeloom::espnow
