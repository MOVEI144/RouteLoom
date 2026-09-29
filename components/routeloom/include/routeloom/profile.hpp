#pragma once

// Compile-time resource profile: the one source of the session, route and
// feature capacities that size the Owner, the MeshNode and the USB bridge.
// ROUTELOOM_RESOURCE_PROFILE (and the optional ROUTELOOM_ROLE) are PUBLIC
// definitions on the core library — the component Kconfig on ESP-IDF, the
// CMake cache variable of the same name on host builds — so every
// translation unit sees one value. A firmware image carries exactly one
// profile; host tests default to `full`, which hosts every role.
//
// | profile       | link | end | routes | join relay gateway | USB bridge |
// |---------------|------|-----|--------|--------------------|------------|
// | endpoint      |   32 |   8 |     16 | no                 | no         |
// | relay         |   32 |   8 |    128 | no                 | no         |
// | gateway_small |   32 |  64 |    128 | yes                | yes        |
// | gateway       |   32 | 128 |    128 | yes                | yes        |
// | full          |   32 | 128 |    128 | yes                | yes        |
//
// `end` counts peers holding a live end-to-end key at once, not mesh size:
// a full end table evicts the oldest idle context and RLRES1 brings it back
// (03 §5.2). The dedup capacity rides the same selection
// (ROUTELOOM_DEDUP_CAPACITY, node.hpp): 32 for endpoint and gateway_small,
// 96 otherwise, overridable per image.

#include <cstddef>
#include <cstdint>

#define ROUTELOOM_PROFILE_ENDPOINT 1
#define ROUTELOOM_PROFILE_RELAY 2
#define ROUTELOOM_PROFILE_GATEWAY_SMALL 3
#define ROUTELOOM_PROFILE_GATEWAY 4
#define ROUTELOOM_PROFILE_FULL 5

#ifndef ROUTELOOM_RESOURCE_PROFILE
#define ROUTELOOM_RESOURCE_PROFILE ROUTELOOM_PROFILE_FULL
#endif
#if ROUTELOOM_RESOURCE_PROFILE < ROUTELOOM_PROFILE_ENDPOINT || \
    ROUTELOOM_RESOURCE_PROFILE > ROUTELOOM_PROFILE_FULL
#error "ROUTELOOM_RESOURCE_PROFILE must be 1..5 (endpoint..full)"
#endif

// Gateway profiles hold the join relay gateway and the USB bridge.
#define ROUTELOOM_PROFILE_HAS_GATEWAY \
  (ROUTELOOM_RESOURCE_PROFILE >= ROUTELOOM_PROFILE_GATEWAY_SMALL)

// Optional USB bridge state (1 = compiled in). Disabled features keep an
// Unsupported entry and never advertise their HelloAck capability bit. The
// C3 gateway leaves out the two large ones by default (node status tracking
// and the explicit gateway endpoint's ingress/send slots).
#ifndef ROUTELOOM_USB_NODE_STATUS
#define ROUTELOOM_USB_NODE_STATUS \
  (ROUTELOOM_PROFILE_HAS_GATEWAY && ROUTELOOM_RESOURCE_PROFILE != ROUTELOOM_PROFILE_GATEWAY_SMALL)
#endif
#ifndef ROUTELOOM_USB_GATEWAY_ENDPOINT
#define ROUTELOOM_USB_GATEWAY_ENDPOINT \
  (ROUTELOOM_PROFILE_HAS_GATEWAY && ROUTELOOM_RESOURCE_PROFILE != ROUTELOOM_PROFILE_GATEWAY_SMALL)
#endif
#ifndef ROUTELOOM_USB_GROUP
#define ROUTELOOM_USB_GROUP ROUTELOOM_PROFILE_HAS_GATEWAY
#endif
#ifndef ROUTELOOM_USB_OBSERVATION
#define ROUTELOOM_USB_OBSERVATION ROUTELOOM_PROFILE_HAS_GATEWAY
#endif

namespace routeloom::profile {

enum class ResourceProfile : std::uint8_t {
  Endpoint = ROUTELOOM_PROFILE_ENDPOINT,
  Relay = ROUTELOOM_PROFILE_RELAY,
  GatewaySmall = ROUTELOOM_PROFILE_GATEWAY_SMALL,
  Gateway = ROUTELOOM_PROFILE_GATEWAY,
  Full = ROUTELOOM_PROFILE_FULL,
};
constexpr ResourceProfile kResourceProfile =
    static_cast<ResourceProfile>(ROUTELOOM_RESOURCE_PROFILE);
// Nonzero wire tag of this build's profile (RTC session images).
constexpr std::uint8_t kResourceProfileId = ROUTELOOM_RESOURCE_PROFILE;

// Device role (ROUTELOOM_ROLE): ordered, a profile serves its own role and
// every smaller one.
enum class Role : std::uint8_t { Endpoint = 1, Relay = 2, Gateway = 3 };
constexpr Role kMaxRole = kResourceProfile == ResourceProfile::Endpoint ? Role::Endpoint
                          : kResourceProfile == ResourceProfile::Relay  ? Role::Relay
                                                                        : Role::Gateway;
#ifdef ROUTELOOM_ROLE
constexpr Role kRole = static_cast<Role>(ROUTELOOM_ROLE);
constexpr bool kRoleFixed = true;
#else
// Host builds pick the role per process; the non-gateway default is the
// largest member role the profile serves.
constexpr Role kRole = kMaxRole == Role::Endpoint ? Role::Endpoint : Role::Relay;
constexpr bool kRoleFixed = false;
#endif
// A role above the profile is refused before RF starts
// (RESOURCE_PROFILE_ROLE_MISMATCH).
constexpr bool role_fits(const Role role) noexcept {
  return role >= Role::Endpoint && role <= kMaxRole;
}
constexpr std::uint8_t role_mask(const Role role) noexcept {
  return static_cast<std::uint8_t>((1U << static_cast<unsigned>(role)) - 1U);
}

constexpr bool kGateway = ROUTELOOM_PROFILE_HAS_GATEWAY != 0;
// An endpoint never proxies joins: its proxy stays closed whatever the
// site grants.
constexpr bool kJoinProxy = kResourceProfile != ResourceProfile::Endpoint;

constexpr std::size_t kLinkSessions = 32;
constexpr std::size_t kEndSessions = kResourceProfile == ResourceProfile::GatewaySmall ? 64
                                     : kGateway                                        ? 128
                                                                                       : 8;
constexpr std::size_t kRouteEntries = kResourceProfile == ResourceProfile::Endpoint ? 16 : 128;
constexpr std::size_t kDedupCapacityLeaf = 32;
constexpr std::size_t kDedupCapacityRelay = 96;
constexpr std::size_t kDedupCapacityGateway = 256;
constexpr std::size_t kDedupCapacityDefault =
    kResourceProfile == ResourceProfile::Endpoint ||
            kResourceProfile == ResourceProfile::GatewaySmall
        ? kDedupCapacityLeaf
        : kDedupCapacityRelay;

// RLP2 resume purpose quotas (P4 §4.1) are NVS-only: node 12+4 for the
// endpoint and relay roles, gateway 32+128 for the gateway role on every
// gateway profile (gateway_small keeps the gateway geometry so a re-flash
// between gateway profiles keeps the store). Only gateway profiles accept
// the gateway geometry.
constexpr bool kResumeGatewayGeometry = kGateway;

// Link sessions back every discovery neighbor (discovery.hpp
// kNeighborCapacity = 32); the end table must hold at least the resume
// end quota of a node.
static_assert(kLinkSessions >= 32, "one link session per logical neighbor");
static_assert(kEndSessions >= 4, "end table below the node resume quota");
static_assert(kRole >= Role::Endpoint && kRole <= Role::Gateway, "ROUTELOOM_ROLE must be 1..3");

}  // namespace routeloom::profile
