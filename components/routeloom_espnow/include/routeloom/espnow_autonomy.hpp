#pragma once

// Owner-side autonomy bundle for the ESP-NOW runtime (issue #3, P1b): the
// thin non-portable glue that feeds the portable NeighborDiscovery engine —
// entropy from the hardware RNG, the development membership policy, a
// log-backed observer and the DevPskAuthenticator. All members are value or
// reference types; place the bundle in static storage, never on the heap.
//
// EXPERIMENTAL: the dev profile authenticates shared-PSK possession only.
// It cannot distinguish two holders of the same key — production device
// identity waits for the qualified G-SEC profile.

#include "routeloom/discovery.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::espnow {

// esp_random()-backed EntropySource for transaction nonces and offer-slot
// picks (02 §6). Every fill is independent hardware RNG output.
class EspNowEntropySource final : public EntropySource {
 public:
  Status fill(MutableByteView out) noexcept override;
};

// Development membership policy (06-membership-admission.md §5). Local
// membership is a provisioned flag; peer member evidence trusts the dev-PSK
// possession proof the authenticator already produced (a group secret can
// not distinguish its holders — dev semantics, never production);
// approve_join models the Authority's MembershipResult decision.
class DevMembershipHooks final : public MembershipHooks {
 public:
  DevMembershipHooks(NetworkId network, bool self_member,
                     bool auto_approve) noexcept
      : network_(network), self_member_(self_member), auto_approve_(auto_approve) {}

  bool local_member(NetworkId network) const noexcept override {
    return self_member_ && network == network_;
  }
  bool known_member(NodeId peer, NetworkId network) const noexcept override {
    return peer != kInvalidNodeId && network == network_;
  }
  bool approve_join(NodeId node, NetworkId network) noexcept override {
    return auto_approve_ && node != kInvalidNodeId && network == network_;
  }

 private:
  NetworkId network_;
  bool self_member_;
  bool auto_approve_;
};

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

struct EspNowAutonomyPolicy {
  bool self_member{true};    // provisioned-member evidence (dev)
  bool auto_approve{true};   // Authority stand-in for the join commit (dev)
  bool initiate{true};       // broadcast DISCOVER at start, else respond only
  std::uint16_t auth_domain{1};  // DevPskAuthenticator domain tag
};

// Owns the dev-profile autonomy pieces and pumps them through the runtime.
// Construct after runtime.initialize() (the discovery config needs the real
// station MAC) and call start() before the runtime pump begins.
class EspNowAutonomy final {
 public:
  EspNowAutonomy(const DiscoveryConfig& discovery,
                 const EspNowAutonomyPolicy& policy, EspNowRuntime& runtime,
                 SecurityProvider& security, const char* log_tag) noexcept
      : runtime_(runtime),
        hooks_(discovery.network, policy.self_member, policy.auto_approve),
        authenticator_(security, policy.auth_domain),
        observer_(log_tag, &runtime),
        engine_(discovery, runtime, authenticator_, hooks_, entropy_,
                observer_),
        initiate_(policy.initiate) {}

  EspNowAutonomy(const EspNowAutonomy&) = delete;
  EspNowAutonomy& operator=(const EspNowAutonomy&) = delete;

  // Attach the engine to the runtime, start membership/discovery and,
  // optionally, emit the first DISCOVER.
  Status start() noexcept {
    Status status = runtime_.attach_autonomy(engine_);
    if (!status) return status;
    status = engine_.start(runtime_.now_ms());
    if (!status) return status;
    if (initiate_) {
      return engine_.begin_discovery(runtime_.now_ms());
    }
    return Status::success();
  }

  NeighborDiscovery& engine() noexcept { return engine_; }
  const NeighborDiscovery& engine() const noexcept { return engine_; }

 private:
  EspNowRuntime& runtime_;
  EspNowEntropySource entropy_{};
  DevMembershipHooks hooks_;
  DevPskAuthenticator authenticator_;
  EspNowDiscoveryObserver observer_;
  NeighborDiscovery engine_;
  bool initiate_;
};

}  // namespace routeloom::espnow
