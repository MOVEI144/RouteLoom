#pragma once

// Congestion-control contract types and pinned parameters for the
// autonomous-mesh profile (docs/design/autonomous-mesh/03-congestion.md §4, §5
// and contracts.json congestion.*). The route-metric coupling is specified in
// docs/design/sdk-completion/03-congestion-routing.md: measured base + a
// bounded queue/refusal penalty feed RouteTable::update_link_cost, gated by
// the evidence rules below — congestion can only ever make a link look worse,
// never better.
//
// Invariants encoded here:
//   - Accepted RELIABLE work is never silently dropped by queue control; only
//     pre-admission rejection (BUSY) or explicit delay is produced.
//   - BUSY is a pre-acceptance signal; it never cancels HOP_ACCEPT-ed work.
//   - Attempt budgets (RF attempts, BUSY readmissions, combined physical
//     attempts, origin rounds) are per-job and never reset by peer/rate
//     changes or queue events.

#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/peer_directory.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Pinned parameters (contracts.json congestion.*) ---------------------------

// DRR class weights management/urgent/normal/bulk = 4/8/4/1.
enum class SchedClass : std::uint8_t {
  Management = 0,
  Urgent = 1,
  Normal = 2,
  Bulk = 3,
};
constexpr std::size_t kSchedClassCount = 4;
constexpr std::size_t sched_class_index(const SchedClass value) noexcept {
  return static_cast<std::size_t>(value);
}
constexpr std::uint32_t sched_class_weight(const SchedClass value) noexcept {
  switch (value) {
    case SchedClass::Management:
      return 4;
    case SchedClass::Urgent:
      return 8;
    case SchedClass::Normal:
      return 4;
    case SchedClass::Bulk:
      return 1;
  }
  return 1;
}

// Bounded flow descriptors per (verified sender scope, origin, destination).
constexpr std::size_t kFlowDescriptorsMax = 32;
// Queue watermarks (fraction of the bounded TX pool).
constexpr std::uint32_t kQueueWatermarkBackgroundPercent = 50;  // shrink probe/log work
constexpr std::uint32_t kQueueWatermarkStopPercent = 80;        // stop bulk + improvement probes
constexpr std::uint32_t kQueueTargetMs = 50;
// Route-metric queue penalty (03 §6.2, contracts congestion.*): the multiple
// of the measured base cost added per queue_penalty_step_ms of sustained
// egress delay above queue_target_ms, capped at queue_penalty_max_multiple.
constexpr std::uint32_t kQueuePenaltyStepMs = 50;
constexpr std::uint32_t kQueuePenaltyMaxMultiple = 4;
// Refusal-pressure floor (sdk-completion/03 §3.4): a saturated scheduler
// stops producing sojourn samples exactly when congestion is worst, so pool
// occupancy maps directly to penalty *steps* — never converted to ms.
// occupancy 50–59% -> 1 step ... >=80% -> 4 (the same cap as queue_ms).
constexpr std::uint32_t kRefusalStepWatermarkLowPercent = 50;
constexpr std::uint32_t kRefusalStepPerTenPercent = 10;
constexpr std::uint32_t kLinkCostRelaxSnapDivisor = 4;
// Minimum authenticated accepts before a measured exchange ratio may move a
// link cost off its nominal value (03 §6.1 — sample-poor links keep nominal).
constexpr std::uint32_t kExchangeMinAccepts = 4;
// Received BUSY retry_after is clamped into this interval.
constexpr std::uint32_t kBusyRetryAfterMinMs = 20;
constexpr std::uint32_t kBusyRetryAfterMaxMs = 1000;
// Per-peer in-flight window bounds (within the global awaiting-hop slots).
constexpr std::uint8_t kPeerWindowMin = 1;
constexpr std::uint8_t kPeerWindowInitial = 2;
constexpr std::uint8_t kPeerWindowMax = 4;
constexpr std::uint8_t kWindowGrowAccepts = 8;  // consecutive authenticated accepts -> +1
// Attempt budgets: rf_attempts_max 2 + busy_readmissions_max 4 within
// combined_physical_attempts_max 6; origin rounds stay <= 3 (existing config).
constexpr std::uint8_t kRfAttemptsMax = 2;
constexpr std::uint8_t kBusyReadmissionsMax = 4;
constexpr std::uint8_t kCombinedPhysicalAttemptsMax = 6;
// Observation / feedback freshness (03-congestion.md §3).
constexpr std::uint32_t kObservationWindowMs = 2000;
constexpr std::uint32_t kFeedbackTtlMs = 3000;
// Asymmetric slew (sdk-completion/03 §3.4): cost improvement is time-gated
// to one relax step per observation window; worsening is immediate.
constexpr std::uint32_t kLinkCostRelaxWindowMs = kObservationWindowMs;

// Fixed per-frame TX cost added to every DRR charge (radio.md §9): MAC
// header + (unpublished) long-range preamble + the MAC ACK carried by
// every frame, expressed in byte-equivalent air time. The LR preamble
// duration is not published — 96B is the middle of the ~70–105B effective
// estimate, an annotated estimate rather than a measured value.
constexpr std::size_t kTxFrameFixedCostBytes = 96;

// §14 management airtime budget — the local calibrated token bucket gating
// management-class (control-domain) emissions (03-congestion.md §8:
// calibrated local bucket first, no network reallocation). The 100000µs/s
// network envelope is split evenly across the 100 design nodes, and
// capacity holds at least one maximum frame's air time (~12000µs: a full
// frame at 250kbps plus fixed overhead — §14 "burst >= 1 max frame").
// These are SPEC-ENVELOPE values pinned in radio-defaults.json: the bucket
// is an UNCALIBRATED capability, not measured capacity or 100-node
// qualification.
constexpr std::uint32_t kControlBudgetNetworkUsPerS = 100000;
constexpr std::uint32_t kControlBudgetDesignNodes = 100;
constexpr std::uint32_t kControlBudgetRefillUsPerS =
    kControlBudgetNetworkUsPerS / kControlBudgetDesignNodes;
constexpr std::uint32_t kControlBudgetCapacityUs = 12000;
// One management emission must hold a full frame's air time in tokens.
constexpr std::uint32_t kControlBudgetFrameCostUs = kControlBudgetCapacityUs;

// Frame-length classes for observation keys (encoded size on air).
constexpr std::uint8_t frame_length_class(const std::size_t encoded_size) noexcept {
  if (encoded_size <= 96) return 0;
  if (encoded_size <= 180) return 1;
  return 2;
}

// --- Admission verdicts --------------------------------------------------------

// Result of the scheduler's pre-admission check for a job family. The BUSY
// reason sent upstream is derived from this — never fabricated after the fact.
enum class AdmitVerdict : std::uint8_t {
  Admitted = 0,
  PoolFull,       // bounded TX pool has no room for the reservation
  ScopeLimited,   // per-neighbor (sender scope) cap reached
  OriginLimited,  // per-origin cap reached (spoofed-flood resistance)
  BulkSuspended,  // >=80% watermark: bulk admission explicitly delayed/rejected
  ControlFull,    // reserved control lane is at its bound
};

// --- Observation groundwork for P3 (03-congestion.md §3) -----------------------
// Aggregate-only: EWMA + counters keyed by the contract tuple; no unbounded
// raw samples. Generations are placeholders in the portable core (0) — the
// radio Owner keys them once bindings/channel epochs exist.

enum class ObservationDirection : std::uint8_t {
  Egress = 0,  // our transmissions toward a peer
  Ingress = 1,
};

enum class ObservationProvenance : std::uint8_t {
  InjectedTest = 0,
  LocalDriver = 1,
  AuthenticatedRemoteReport = 2,
};

// V2 is deliberately separate from the legacy {rssi}-only metadata: legacy
// callers keep compiling, but do not acquire invented timestamps, validity
// or generations. The Owner captures these values in the callback and
// rechecks the identity after link authentication before passing them to
// the telemetry primitives (02-telemetry §2.3).
struct RadioRxMetadataV2 {
  std::uint64_t received_us{0};
  BindingGeneration binding_generation{};
  RadioGeneration radio_generation{};
  ChannelEpoch channel_epoch{};
  std::int8_t rssi_dbm{0};
  bool rssi_valid{false};
  std::uint8_t channel{0};
  bool channel_valid{false};
  ObservationProvenance provenance{ObservationProvenance::LocalDriver};
  // Runtime revalidation result (02 §2.2): false when the captured
  // binding/radio/channel generations no longer match the live state —
  // the frame still dispatches (it is link-authenticated), but its
  // metadata is stale evidence that must not refresh telemetry or
  // connectivity oracles.
  bool identity_current{true};
};
static_assert(sizeof(RadioRxMetadataV2) <= 32, "bounded RX metadata");

// One submitted TX attempt's completion evidence (02-telemetry §2.3). The
// Owner stamps submitted_us at driver acceptance and completed_us in the
// callback; generations are copied from the Owner's pending record so a
// stale callback can never be attributed to a newer radio/channel identity.
enum class RadioTxOutcome : std::uint8_t {
  Success = 0,   // driver reported TX_OK — MAC-level only, never hop acceptance
  Failure = 1,   // driver reported failure
  Unknown = 2,   // callback watchdog expired / fenced / indeterminate
};

struct RadioTxObservation {
  NodeId peer{kInvalidNodeId};
  BindingGeneration binding_generation{};
  RadioGeneration radio_generation{};
  ChannelEpoch channel_epoch{};
  std::uint64_t submitted_us{0};
  std::uint64_t completed_us{0};
  std::uint8_t frame_length_class{0};
  RadioTxOutcome outcome{RadioTxOutcome::Unknown};
  // Where this observation came from — only a real TX-complete callback may
  // claim LocalDriver; submitted-side bookkeeping and tests must not be
  // relabelled as driver evidence (02-telemetry §provenance).
  ObservationProvenance provenance{ObservationProvenance::InjectedTest};
  // Reserved-lane submission token echoed by the adapter so a completion
  // can attribute its measured service to the in-flight job's §14 airtime
  // domain. 0 for raw-lane, bootstrap or injected observations.
  std::uint64_t token{0};
};
static_assert(sizeof(RadioTxObservation) <= 64, "bounded TX observation");

constexpr std::size_t kObservationBucketCapacity = 8;

struct ObservationKey {
  BindingGeneration binding{};
  ObservationDirection direction{ObservationDirection::Egress};
  RadioGeneration radio{};
  ChannelEpoch channel{};
  std::uint8_t frame_length_class{0};
  // Appended so the legacy five-field aggregate initializer remains valid.
  NodeId peer{kInvalidNodeId};

  friend constexpr bool operator==(const ObservationKey& a,
                                   const ObservationKey& b) noexcept {
    return a.binding == b.binding && a.direction == b.direction &&
           a.radio == b.radio && a.channel == b.channel &&
           a.frame_length_class == b.frame_length_class && a.peer == b.peer;
  }
  friend constexpr bool operator!=(const ObservationKey& a,
                                   const ObservationKey& b) noexcept {
    return !(a == b);
  }
};

// EWMA update, alpha = 1/8. `samples` is the count including this sample;
// the first sample seeds the average directly. The delta is applied with
// sign awareness — unsigned `sample - ewma` would wrap whenever a sample
// lands below the average.
constexpr void ewma_add(std::uint32_t& ewma, const std::uint32_t sample,
                        const std::uint64_t samples) noexcept {
  if (samples <= 1) {
    ewma = sample;
  } else if (sample >= ewma) {
    ewma += (sample - ewma) / 8;
  } else {
    ewma -= (ewma - sample) / 8;
  }
}

// Bounded current/previous telemetry evidence, separate from lifetime totals.
// Source bits are internal provenance bits, not wire validity bits. A mixed
// source window cannot provide a positive metric input.
struct ObservationWindow {
  MonotonicMs first_sample_ms{0};
  MonotonicMs last_sample_ms{0};
  std::uint32_t tx_submitted{0};
  std::uint32_t hop_accepts{0};
  std::uint32_t queue_us_ewma{0};
  std::uint32_t driver_us_ewma{0};
  std::uint32_t hop_rtt_us_ewma{0};
  std::uint32_t queue_samples{0};
  std::uint32_t driver_samples{0};
  std::uint32_t hop_rtt_samples{0};
  std::uint8_t sources{0};
  bool present{false};
  bool incomplete{false};
};

// Per-key aggregate. EWMA uses alpha = 1/8; counters never decrease.
// BUSY deferrals, RF-loss retries and callback-uncertain results are kept as
// separate counters — they must never be merged into one "failure" number.
struct ObservationBucket {
  ObservationKey key{};
  std::uint32_t queue_sojourn_ms_ewma{0};    // enqueue -> handed to radio
  std::uint32_t driver_service_us_ewma{0};   // driver accept -> TX callback
  std::uint32_t sojourn_samples{0};
  std::uint32_t service_samples{0};
  std::uint64_t tx_submitted{0};
  std::uint64_t hop_accepted{0};
  // authenticated HOP_ACCEPT arrivals by physical attempt index (0..5)
  std::uint64_t accepted_at_attempt[kCombinedPhysicalAttemptsMax]{};
  std::uint64_t rf_failures{0};        // MAC failure + HOP_ACCEPT timeout
  std::uint64_t busy_deferrals{0};     // authenticated BUSY applied to our jobs
  std::uint64_t unknown_results{0};    // callback-uncertain TX results
  std::uint64_t absence_deferrals{0};  // scheduled-absence holds (P3/#5 hook)
  std::uint64_t end_receipts{0};       // deliveries completed via END_RECEIPT
  std::uint64_t completions{0};        // non-receipt completions (BestEffort TX_MAC_DONE)
  std::uint64_t expiries{0};           // deliveries expired at origin
  std::uint64_t failures{0};           // deliveries failed at origin
  std::uint64_t indeterminate{0};      // deliveries with unknown outcome
  MonotonicMs window_start_ms{0};
  MonotonicMs last_update_ms{0};

  // D1a uses tx_submitted/hop_accepted/unknown_results/busy_deferrals above
  // as lifetime totals (clamped to the wire's u32 range). rf_failures remains
  // the legacy combined counter; it cannot supply either of these two fields.
  std::uint32_t tx_mac_success{0};
  std::uint32_t tx_mac_fail{0};
  std::uint32_t sdk_retries{0};
  std::uint32_t hop_timeouts{0};
  std::uint32_t event_drops{0};
  std::uint32_t saturation_mask{0};
  std::uint64_t observer_boot{0};
  ObservationWindow current{};
  ObservationWindow previous{};
  std::uint32_t pending_completions{0};
  std::uint16_t pins{0};
  bool stale{false};

  bool positive_metric_input(MonotonicMs now_ms) const noexcept;
};

// 02-telemetry.md §2.4-§2.5: only a complete, fresh window whose samples all
// came from the local driver may raise a route metric. Injected, remote,
// mixed-source, incomplete or stale windows can never improve a link's
// apparent cost — they can still withdraw a route through failure handling.
inline bool ObservationBucket::positive_metric_input(
    const MonotonicMs now_ms) const noexcept {
  constexpr std::uint8_t kLocalDriverBit =
      static_cast<std::uint8_t>(1u << static_cast<unsigned>(
                                  ObservationProvenance::LocalDriver));
  if (!current.present || current.incomplete || stale) return false;
  if (current.sources != kLocalDriverBit) return false;
  if (current.last_sample_ms > now_ms) return false;  // clock uncertainty
  return now_ms - current.last_sample_ms <= kFeedbackTtlMs;
}

// --- Statistics ---------------------------------------------------------------

// §14 airtime domains (radio.md §9/§14): every completed TX debits its
// measured driver-service µs to exactly one domain. Ack is the reserved
// control lane — HOP_ACCEPT/BUSY replies ride inside the accepted work's
// own budget ("DATAとACKを同じ仕事の予算に含める"); Control is the gated
// management domain; Optimization is reserved for rate/probe work
// (currently unwired); Misc covers everything that bypassed the
// scheduler — discovery, Join and migration raw TXs included — which §14
// reconciliation still owes an account of.
enum class AirtimeDomain : std::uint8_t {
  Ack = 0,
  Work = 1,
  Control = 2,
  Optimization = 3,
  Misc = 4,
};

// Live scheduler/BUSY counters for tests, diagnostics and the P3 observer.
// busy_send_failed counts drops where no reply budget existed — a BUSY that
// was never transmitted is never counted as sent.
struct CongestionStats {
  std::uint64_t busy_sent{0};
  std::uint64_t busy_send_failed{0};
  std::uint64_t busy_received{0};
  std::uint64_t busy_stale{0};
  std::uint64_t busy_unmatched{0};
  std::uint64_t busy_readmitted{0};
  std::uint64_t admissions_rejected{0};
  std::uint64_t bulk_suspended{0};
  std::uint64_t flow_overflow_merged{0};
  std::uint64_t window_limited{0};  // dispatch passes skipped on a full peer window
  std::uint64_t observation_overflow{0};  // samples dropped on a full bucket pool
  // §14 airtime ledger: measured driver-service µs debited per domain at TX
  // completion. Saturating monotonic totals, never reset within a boot.
  std::uint64_t service_us_ack{0};
  std::uint64_t service_us_work{0};
  std::uint64_t service_us_control{0};
  std::uint64_t service_us_optimization{0};
  std::uint64_t service_us_misc{0};
  // Management emissions the control-budget gate could not schedule —
  // each needed a token wait beyond the route lease (§14
  // CONTROL_BUDGET_UNSATISFIABLE).
  std::uint64_t control_budget_unsatisfiable{0};
  std::size_t queued{0};
  std::size_t control_queued{0};
  std::size_t flows_active{0};

  CongestionStats& operator+=(const CongestionStats& other) noexcept {
    busy_sent += other.busy_sent;
    busy_send_failed += other.busy_send_failed;
    busy_received += other.busy_received;
    busy_stale += other.busy_stale;
    busy_unmatched += other.busy_unmatched;
    busy_readmitted += other.busy_readmitted;
    admissions_rejected += other.admissions_rejected;
    bulk_suspended += other.bulk_suspended;
    flow_overflow_merged += other.flow_overflow_merged;
    window_limited += other.window_limited;
    observation_overflow += other.observation_overflow;
    service_us_ack += other.service_us_ack;
    service_us_work += other.service_us_work;
    service_us_control += other.service_us_control;
    service_us_optimization += other.service_us_optimization;
    service_us_misc += other.service_us_misc;
    control_budget_unsatisfiable += other.control_budget_unsatisfiable;
    return *this;
  }
};

// --- P3 route-metric coupling (03-congestion.md §6) -----------------------------
// Pure cost functions so the update math is testable without a mesh. The
// abstract RouteMetric unit is preserved end to end — nothing here returns
// milliseconds or reinterprets cost as time.

// §6.1 base cost: b = clamp_positive(ceil(nominal * measured / reference)).
// `work` is eligible attempt work (every physical transmission toward the
// peer — failures included, so success-only sampling cannot flatter the
// link); `accepts` is authenticated-accept successes. The reference exchange
// cost for this profile is one attempt per accept, so the ratio is ETX-like
// and dimensionless — driver service time, which may already contain
// CCA/MAC retries, is NEVER used here (no ETX double-count). Callers pass
// accepts only once the minimum sample count is met; accepts == 0 or a
// ratio at/below ideal keeps the nominal. Results saturate to 65535 =
// infinity; a zero cost is never produced (only self-origin distance is 0).
constexpr RouteMetric measured_link_base(const RouteMetric nominal,
                                         const std::uint64_t work,
                                         const std::uint64_t accepts) noexcept {
  if (nominal == kInfiniteRouteMetric) return nominal;
  if (nominal == 0) return 1;  // never emit a 0-cost link (only self is 0)
  if (accepts == 0 || work <= accepts) return nominal;
  // Wide intermediate: nominal <= 65535 and `work` is a bounded counter, so
  // the product cannot wrap u64.
  const std::uint64_t scaled = static_cast<std::uint64_t>(nominal) * work;
  const std::uint64_t value = (scaled + accepts - 1U) / accepts;  // ceil
  if (value >= kInfiniteRouteMetric) return kInfiniteRouteMetric;
  return value == 0 ? static_cast<RouteMetric>(1)
                    : static_cast<RouteMetric>(value);
}

// §6.2 queue penalty: only the LOCAL egress-queue delay toward the peer is
// added — the peer's own queue lives inside its advertised metric and is
// never re-added (no double count).
//   steps_q = min(4, ceil(max(0, Q_ms - 50) / 50))
constexpr std::uint32_t queue_penalty_steps(const std::uint32_t queue_ms) noexcept {
  const std::uint32_t excess =
      queue_ms > kQueueTargetMs ? queue_ms - kQueueTargetMs : 0;
  const std::uint64_t steps =
      (static_cast<std::uint64_t>(excess) + kQueuePenaltyStepMs - 1U) /
      kQueuePenaltyStepMs;
  return steps > kQueuePenaltyMaxMultiple
             ? kQueuePenaltyMaxMultiple
             : static_cast<std::uint32_t>(steps);
}

// §3.4 refusal-pressure floor: a saturated pool stops producing sojourn
// samples exactly when congestion is worst. Pool occupancy is not a time
// unit, so it maps directly to penalty steps — never added as ms.
//   steps_r = occupancy >= 50% ? min(4, 1 + (occupancy - 50) / 10) : 0
constexpr std::uint32_t refusal_penalty_steps(
    const std::uint32_t occupancy_percent) noexcept {
  if (occupancy_percent < kRefusalStepWatermarkLowPercent) return 0;
  const std::uint32_t steps =
      1U + (occupancy_percent - kRefusalStepWatermarkLowPercent) /
               kRefusalStepPerTenPercent;
  return steps > kQueuePenaltyMaxMultiple ? kQueuePenaltyMaxMultiple : steps;
}

// §3.4 floor gate: occupancy crosses the watermark AND a refusal was
// observed within the observation window. Occupancy alone still produces
// sojourn samples — a merely-full pool must not inflate the metric; a
// stale refusal must not hold it inflated either.
constexpr bool refusal_floor_active(const std::uint32_t occupancy_percent,
                                    const MonotonicMs last_refusal_ms,
                                    const MonotonicMs now_ms) noexcept {
  return occupancy_percent >= kRefusalStepWatermarkLowPercent &&
         last_refusal_ms != 0 &&
         now_ms - last_refusal_ms <= kObservationWindowMs;
}

// link = base * (1 + m), saturating at wire infinity. The combined multiple
// m = max(steps_q, steps_r): pool saturation and per-peer sojourn are two
// readings of the same congestion — never added (sdk-completion/03 §3.4).
constexpr RouteMetric penalized_cost(const RouteMetric base,
                                     const std::uint32_t multiple) noexcept {
  if (base == kInfiniteRouteMetric) return base;
  if (base == 0) return 1;  // never emit a 0-cost link (only self is 0)
  const std::uint64_t total =
      static_cast<std::uint64_t>(base) * (1ULL + multiple);
  return total >= kInfiniteRouteMetric ? kInfiniteRouteMetric
                                       : static_cast<RouteMetric>(total);
}

constexpr RouteMetric queue_penalized_cost(const RouteMetric base,
                                           const std::uint32_t queue_ms) noexcept {
  return penalized_cost(base, queue_penalty_steps(queue_ms));
}

// §3.4 asymmetric slew, relax direction only (worsening is immediate and
// handled by the caller). Per observation window the cost recovers at most
// half of its excess above `target`; a residual <= ceil(base/divisor) snaps
// closed so cost always returns exactly to the honest target. Call only
// when `target < current` and the relax window elapsed.
constexpr RouteMetric relax_link_cost(const RouteMetric current,
                                      const RouteMetric target,
                                      const RouteMetric base) noexcept {
  const std::uint32_t excess =
      current > target ? static_cast<std::uint32_t>(current - target) : 0;
  const std::uint32_t snap =
      base / kLinkCostRelaxSnapDivisor > 0 ? base / kLinkCostRelaxSnapDivisor
                                           : 1U;
  if (excess <= snap) return target;
  const std::uint32_t step = excess / 2U > 0 ? excess / 2U : 1U;
  return static_cast<RouteMetric>(current - step);
}

}  // namespace routeloom
