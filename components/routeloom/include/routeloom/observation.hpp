#pragma once

// Read-only device observation (observation_v1): system health, table
// occupancy, join milestones and route detail for the USB-attached node.
//
// Design: docs/design/meshviz.md §2.3–§2.6 (PR 09a) and the D05 row of the
// dev-flow plan. This surface answers "what does THIS device know about
// itself right now" — heap, reset cause, uptime, session/dedup/queue
// occupancy, join-attempt milestones and the selected-route table. It never
// touches route selection, leases or advertisement baselines: every fill
// below runs on const tables and reports durations (ages) on the device
// monotonic clock, like node_status.hpp. Absolute device timestamps never
// leave the device; the host maps an age onto its own receive time.
//
// Unknown conventions (device → host): numeric 0/empty means "none" only
// where documented; otherwise the section documents an explicit unknown
// sentinel (ages and heap bytes saturate at UINT32_MAX, boot ids use 0,
// enums use 0). A reset, a dropped page or a session loss retires every
// claim — the host reports unknown until it re-pulls, never the last value.

#include <cstddef>
#include <cstdint>

#include "routeloom/node_status.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Sections (USB 0x70 query / 0x71 page) ----------------------------------
//
// System/Tables/Milestones/Summary are singleton bodies (count is always 1).
// Routes is a paginated id-ordered cursor walk like node_status_page; the
// per-node neighbor detail stays in node_status_v1 (0x40-0x42) and is NOT
// duplicated here — Summary carries the neighbor/route counts instead.
enum class ObservationSection : std::uint8_t {
  System = 0,      // boot identity, uptime, reset cause, heap, power, mode
  Tables = 1,      // neighbor/route/session/dedup/queue occupancy
  Milestones = 2,  // join-attempt lifecycle record for this boot
  Summary = 3,     // topology digests + counts (cheap poll / cache key)
  Routes = 4,      // selected-route detail entries (paginated)
};

// Reset-cause registry for ObservationSystem::reset_code. 0 is unknown — a
// port that cannot read the cause reports 0 rather than guessing power-on.
enum ObservationReset : std::uint8_t {
  kResetUnknown = 0,
  kResetPowerOn = 1,
  kResetSoftware = 2,
  kResetWatchdog = 3,
  kResetDeepSleepWake = 4,
  kResetPanic = 5,
  kResetBrownout = 6,
  kResetOther = 7,
};

// Power-mode registry for ObservationSystem::power_mode. Draining covers an
// in-progress sleep drain; Sleeping is reported only when the core knows it
// is not on the normal running path (otherwise Running).
enum ObservationPower : std::uint8_t {
  kPowerUnknown = 0,
  kPowerRunning = 1,
  kPowerDraining = 2,
  kPowerSleeping = 3,
};

// Coordinator-mode registry for ObservationSystem::coord_mode. Mirrors
// CoordinatorMode without including the coordinator header (the firmware
// source maps it); 0 is unknown, for builds without a coordinator.
enum ObservationCoordMode : std::uint8_t {
  kCoordModeUnknown = 0,
  kCoordModeFresh = 1,
  kCoordModeZeroTouch = 2,
  kCoordModeMember = 3,
  kCoordModeDev = 4,
  kCoordModeRemoved = 5,
  kCoordModeRecovery = 6,
};

// Security-profile registry for ObservationSystem::sec_profile. The value
// names the running provider family for lab display (MemberEdhoc vs
// DevRam); it is NOT a production certification claim.
enum ObservationProfile : std::uint8_t {
  kProfileUnknown = 0,
  kProfileMemberEdhoc = 1,
  kProfileDevRam = 2,
  kProfileLegacyFixture = 3,
};

// Membership registry for JoinMilestones::membership. Mirrors
// MembershipState (admission.hpp) shifted by one so 0 stays unknown.
enum ObservationMembership : std::uint8_t {
  kMembershipUnknown = 0,
  kMembershipUnprovisioned = 1,
  kMembershipDiscovering = 2,
  kMembershipAuthenticating = 3,
  kMembershipAuthorizedPendingCommit = 4,
  kMembershipMember = 5,
  kMembershipRevoked = 6,
};

// Joiner-state registry for JoinMilestones::joiner_state. Coarse mirror of
// JoinState (active legs collapse to one value); 0 is unknown.
enum ObservationJoiner : std::uint8_t {
  kJoinerUnknown = 0,
  kJoinerStopped = 1,
  kJoinerActive = 2,
  kJoinerReady = 3,
  kJoinerRemoved = 4,
  kJoinerRecoveryRequired = 5,
};

// JoinMilestones::flags bits.
constexpr std::uint8_t kMilestoneAdopted = 1u << 0;    // member/dev config adopted this boot
constexpr std::uint8_t kMilestoneConfirmed = 1u << 1;  // JoinConfirm ACK verified this boot

// Age sentinel: the milestone was not reached this boot (or was never
// recorded). Ages saturate here rather than wrapping.
constexpr std::uint32_t kMilestoneAgeUnknown = UINT32_MAX;
// Heap sentinel: the platform port cannot read this figure.
constexpr std::uint32_t kHeapBytesUnknown = UINT32_MAX;

// Boot identity, uptime, reset cause, heap and running mode. uptime_ms is
// the device monotonic now (the tree-wide clock starts at boot); the host
// maps it onto its own clock by subtracting it from its receive time — the
// same upper-bound idiom as heard_age_ms. boot_id echoes the USB boot
// lease: nonzero, never regressing, new every boot.
struct ObservationSystem {
  std::uint64_t boot_id{0};
  std::uint64_t uptime_ms{0};
  std::uint32_t heap_free_bytes{kHeapBytesUnknown};
  std::uint32_t heap_min_bytes{kHeapBytesUnknown};
  std::uint32_t heap_largest_bytes{kHeapBytesUnknown};
  std::uint8_t reset_code{kResetUnknown};
  std::uint8_t power_mode{kPowerUnknown};
  std::uint8_t coord_mode{kCoordModeUnknown};
  std::uint8_t sec_profile{kProfileUnknown};
};

// Live table occupancy. Counts are exact (never estimates from another
// table); *_cap is the fixed pool bound. dedup_refused saturates the three
// refusal counters, dedup_evicted the three forced-eviction counters.
struct ObservationTables {
  std::uint16_t neighbor_active{0};
  std::uint16_t neighbor_total{0};
  std::uint16_t route_reachable{0};
  std::uint16_t route_total{0};
  std::uint16_t link_sessions{0};
  std::uint16_t link_cap{0};
  std::uint16_t end_sessions{0};
  std::uint16_t end_cap{0};
  std::uint16_t dedup_resident{0};
  std::uint16_t dedup_terminal{0};
  std::uint16_t dedup_cap{0};
  std::uint8_t tx_used{0};
  std::uint8_t tx_cap{0};
  std::uint8_t group_trees{0};
  std::uint8_t group_origins{0};
  std::uint32_t dedup_refused{0};
  std::uint32_t dedup_evicted{0};
};

// Join-lifecycle record for this boot. Ages are durations against the fill
// time (kMilestoneAgeUnknown when the stage was not reached): join_started
// is the first join-attempt start, adopted the member/dev config adoption,
// confirmed the verified JoinConfirm ACK. attempts counts handshake
// attempts this boot (latched at adoption — the Joiner is destroyed once
// the member side goes live). First-STATUS and route-stable times are
// observer-side derivations (the host/mesh lab layer owns them, dev-flow
// §7.2) and are NOT fabricated here.
struct JoinMilestones {
  std::uint8_t mode{kCoordModeUnknown};
  std::uint8_t membership{kMembershipUnknown};
  std::uint8_t joiner_state{kJoinerUnknown};
  std::uint8_t flags{0};
  std::uint32_t attempts{0};
  std::uint32_t join_started_age_ms{kMilestoneAgeUnknown};
  std::uint32_t adopted_age_ms{kMilestoneAgeUnknown};
  std::uint32_t confirmed_age_ms{kMilestoneAgeUnknown};
  NodeId adopted_node{kInvalidNodeId};
};

// FNV-1a step (same primitive as the .cpp digests): the milestone change
// key hashes the 8 tuple bytes (mode, membership, joiner, flags,
// attempts big-endian u32). The zero-tuple key seeds the bridge baseline
// so a fresh zero tuple does not bump the generation.
constexpr std::uint32_t kObservationFnv1a32Offset = 2166136261U;
constexpr std::uint32_t kObservationFnv1a32Prime = 16777619U;
constexpr std::uint32_t observation_fnv1a32_step(const std::uint32_t hash,
                                                 const std::uint8_t byte) noexcept {
  return (hash ^ byte) * kObservationFnv1a32Prime;
}
constexpr std::uint32_t observation_fnv1a32_zeros(const std::uint32_t hash,
                                                 const int n) noexcept {
  return n == 0 ? hash : observation_fnv1a32_zeros(observation_fnv1a32_step(hash, 0), n - 1);
}
constexpr std::uint32_t kObservationMilestoneKeyZero =
    observation_fnv1a32_zeros(kObservationFnv1a32Offset, 8);

// Change key over the milestone tuple (mode, membership, joiner, flags,
// attempts): the bridge bumps milestone_gen whenever the key moves.
std::uint32_t observation_milestones_key(const JoinMilestones& milestones) noexcept;

// Cheap topology poll: content digests plus the counts. A digest change
// means "re-pull the routes"; equal digests mean "nothing structural
// changed" (ages/TX occupancy are NOT part of the digest).
// milestone_gen bumps whenever the milestone tuple (mode, membership,
// joiner, flags, attempts) changes — the host re-pulls Milestones then.
struct ObservationSummary {
  std::uint32_t neighbor_digest{0};
  std::uint32_t route_digest{0};
  std::uint16_t neighbor_active{0};
  std::uint16_t neighbor_total{0};
  std::uint16_t route_reachable{0};
  std::uint16_t route_total{0};
  std::uint32_t milestone_gen{0};
};

// One selected route: the USB projection of RouteSelection plus the
// remaining lease of the selected candidate. remaining_ms saturates at
// UINT32_MAX and is 0 when the route is not valid.
struct RouteDetailEntry {
  NodeId destination{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  RouteGeneration generation{0};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  bool valid{false};
  std::uint32_t remaining_ms{0};
};

// Page bound shared by the USB page codec and the bridge staging buffer.
constexpr std::size_t kObservationRoutesPageMax = 8;

// --- Platform port ----------------------------------------------------------
//
// Heap and reset cause come from the platform (ESP-IDF); the portable core
// never touches them. A null port reports every figure unknown — host
// tests and builds without the port stay honest.
class SystemHealthPort {
 public:
  virtual ~SystemHealthPort() = default;
  virtual std::uint32_t heap_free_bytes() const noexcept = 0;
  virtual std::uint32_t heap_min_bytes() const noexcept = 0;
  virtual std::uint32_t heap_largest_bytes() const noexcept = 0;
  virtual std::uint8_t reset_code() const noexcept = 0;
};

class NullSystemHealthPort final : public SystemHealthPort {
 public:
  std::uint32_t heap_free_bytes() const noexcept override { return kHeapBytesUnknown; }
  std::uint32_t heap_min_bytes() const noexcept override { return kHeapBytesUnknown; }
  std::uint32_t heap_largest_bytes() const noexcept override { return kHeapBytesUnknown; }
  std::uint8_t reset_code() const noexcept override { return kResetUnknown; }
};

// --- Bridge backing -----------------------------------------------------------
//
// The USB bridge serves observation queries from one of these. Firmware
// composes it from the MeshNode, the security owner (coordinator snapshot
// + milestones) and the platform port; host tests use a fake. All fills
// are const and read-only over the node's tables.
class ObservationSource {
 public:
  virtual ~ObservationSource() = default;
  virtual bool fill_system(MonotonicMs now_ms, ObservationSystem& out) const noexcept = 0;
  virtual bool fill_tables(MonotonicMs now_ms, ObservationTables& out) const noexcept = 0;
  virtual bool fill_milestones(MonotonicMs now_ms, JoinMilestones& out) const noexcept = 0;
  // milestone_gen for the summary: bumped by the BRIDGE (it owns the last
  // tuple), so the source fills every field except milestone_gen.
  virtual bool fill_summary(MonotonicMs now_ms, ObservationSummary& out) const noexcept = 0;
  virtual std::size_t route_detail_page(NodeId after, RouteDetailEntry* out,
                                        std::size_t capacity, MonotonicMs now_ms,
                                        bool& more) const noexcept = 0;
  virtual bool route_detail_exact(NodeId destination, MonotonicMs now_ms,
                                  RouteDetailEntry& out) const noexcept = 0;
};

// --- Portable fill helpers ------------------------------------------------------
//
// The firmware source forwards to these; each takes plain inputs so host
// tests can drive them without an owner or coordinator.
void fill_observation_system(std::uint64_t boot_id, MonotonicMs now_ms,
                             const SystemHealthPort& port, std::uint8_t power_mode,
                             std::uint8_t coord_mode, std::uint8_t sec_profile,
                             ObservationSystem& out) noexcept;

class MeshNode;  // node.hpp (observation.cpp implements against it)

// Counts scanned from the node's public read-only views. O(table) per
// call — a diagnostic-query cost, never hot-path work.
void observation_counts(const MeshNode& node, MonotonicMs now_ms,
                        std::uint16_t& neighbor_active, std::uint16_t& neighbor_total,
                        std::uint16_t& route_reachable, std::uint16_t& route_total) noexcept;

void fill_observation_tables(const MeshNode& node, MonotonicMs now_ms,
                             std::uint16_t link_sessions, std::uint16_t link_cap,
                             std::uint16_t end_sessions, std::uint16_t end_cap,
                             ObservationTables& out) noexcept;

// FNV-1a digests over the sorted (id, next_hop, generation, sequence,
// metric) selection set (routes) and the sorted active-neighbor id set
// (neighbors). Read-only; two digests let the host tell which half moved.
std::uint32_t observation_route_digest(const MeshNode& node, MonotonicMs now_ms) noexcept;
std::uint32_t observation_neighbor_digest(const MeshNode& node, MonotonicMs now_ms) noexcept;

void fill_observation_summary(const MeshNode& node, MonotonicMs now_ms,
                              std::uint32_t milestone_gen,
                              ObservationSummary& out) noexcept;

}  // namespace routeloom
