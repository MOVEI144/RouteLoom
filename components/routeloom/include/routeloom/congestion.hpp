#pragma once

// Congestion-control contract types and pinned parameters for the
// autonomous-mesh profile (docs/design/autonomous-mesh/03-congestion.md §4, §5
// and contracts.json congestion.*). This phase implements capacity protection
// and congestion control only — route-metric coupling stays off until P3.
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

struct ObservationKey {
  BindingGeneration binding{};
  ObservationDirection direction{ObservationDirection::Egress};
  RadioGeneration radio{};
  ChannelEpoch channel{};
  std::uint8_t frame_length_class{0};

  friend constexpr bool operator==(const ObservationKey& a,
                                   const ObservationKey& b) noexcept {
    return a.binding == b.binding && a.direction == b.direction &&
           a.radio == b.radio && a.channel == b.channel &&
           a.frame_length_class == b.frame_length_class;
  }
  friend constexpr bool operator!=(const ObservationKey& a,
                                   const ObservationKey& b) noexcept {
    return !(a == b);
  }
};

// EWMA update, alpha = 1/8. `samples` is the count including this sample;
// the first sample seeds the average directly.
constexpr void ewma_add(std::uint32_t& ewma, const std::uint32_t sample,
                        const std::uint64_t samples) noexcept {
  if (samples <= 1) {
    ewma = sample;
  } else {
    ewma += (sample - ewma) / 8;
  }
}

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
};

// --- Statistics ---------------------------------------------------------------

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
    return *this;
  }
};

}  // namespace routeloom
