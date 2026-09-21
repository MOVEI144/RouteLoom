#pragma once

// Bounded real-RF observation primitives (docs/design/m1-completion/
// 02-telemetry.md). This header carries ONLY the portable pieces: per-peer
// summaries, observation-window state and the diagnostic wire codecs. The
// ESP-NOW callback plumbing is the adapter's job; nothing here assumes a
// driver, heap or RTOS.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/congestion.hpp"
#include "routeloom/peer_directory.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Per-peer summary (02 §2.4) ----------------------------------------------
//
// One bounded summary per admitted peer, keyed with the identity the samples
// were taken under. A generation mismatch is stale evidence, never a silent
// merge into a fresh window.

constexpr std::size_t kPeerSummaryCapacity = 19;  // non-broadcast peer cap

// Signed Q8.8 EWMA with alpha = 1/8. Negative RSSI is first-class: the
// (sample - ewma) delta stays signed, so a lower sample never wraps the
// average high.
constexpr void rssi_ewma_add(std::int16_t& ewma_q8_8, const std::int8_t sample,
                             const std::uint64_t samples) noexcept {
  const std::int16_t fixed = static_cast<std::int16_t>(sample) * 256;
  if (samples <= 1) {
    ewma_q8_8 = fixed;
  } else {
    ewma_q8_8 = static_cast<std::int16_t>(
        ewma_q8_8 + static_cast<std::int16_t>((fixed - ewma_q8_8) / 8));
  }
}

struct PeerTelemetrySummary {
  NodeId peer{kInvalidNodeId};
  BindingGeneration binding{};
  RadioGeneration radio{};
  ChannelEpoch channel{};
  std::uint64_t observer_boot{0};
  std::int8_t rssi_last{0};
  std::int8_t rssi_min{0};
  std::int8_t rssi_max{0};
  std::int16_t rssi_ewma_q8_8{0};
  std::uint32_t rssi_samples{0};
  MonotonicMs last_sample_ms{0};
  // Last observed receive channel of this peer's frames (diagnostic only —
  // the attribution epoch is `channel`, this is the numeric RF channel).
  std::uint8_t last_channel{0};
  bool channel_present{false};
  ObservationProvenance provenance{ObservationProvenance::LocalDriver};
  bool occupied{false};
  bool rssi_present{false};
  bool rssi_saturated{false};
  bool stale{false};
};

class PeerTelemetryTable {
 public:
  // Record one authenticated RX observation for the immediate transmitter.
  // A generation/epoch mismatch marks the entry stale and restarts its
  // window instead of folding old evidence into the new identity. Returns
  // nullptr when no free entry exists — the caller counts that as a loss,
  // not a zero-valued sample.
  PeerTelemetrySummary* note_rx(NodeId peer, const RadioRxMetadataV2& metadata,
                                ObservationProvenance provenance,
                                std::uint64_t observer_boot,
                                MonotonicMs now_ms) noexcept {
    PeerTelemetrySummary* entry = find_mutable(peer);
    if (entry != nullptr &&
        (entry->binding != metadata.binding_generation ||
         entry->radio != metadata.radio_generation ||
         entry->channel != metadata.channel_epoch ||
         entry->observer_boot != observer_boot)) {
      entry->stale = true;
      entry = nullptr;  // stale identity is not refreshed in place
    }
    if (entry == nullptr) {
      entry = find_stale_or_free(peer);
      if (entry == nullptr) return nullptr;
      *entry = PeerTelemetrySummary{};
      entry->occupied = true;
      entry->peer = peer;
      entry->binding = metadata.binding_generation;
      entry->radio = metadata.radio_generation;
      entry->channel = metadata.channel_epoch;
      entry->observer_boot = observer_boot;
    }
    entry->provenance = provenance;
    entry->last_sample_ms = now_ms;
    if (metadata.channel_valid) {
      entry->last_channel = metadata.channel;
      entry->channel_present = true;
    }
    if (!metadata.rssi_valid) return entry;
    entry->rssi_present = true;
    if (entry->rssi_samples == UINT32_MAX) {
      entry->rssi_saturated = true;
    } else {
      ++entry->rssi_samples;
    }
    const std::uint64_t n = entry->rssi_samples;
    if (n == 1 || metadata.rssi_dbm < entry->rssi_min) {
      entry->rssi_min = metadata.rssi_dbm;
    }
    if (n == 1 || metadata.rssi_dbm > entry->rssi_max) {
      entry->rssi_max = metadata.rssi_dbm;
    }
    entry->rssi_last = metadata.rssi_dbm;
    rssi_ewma_add(entry->rssi_ewma_q8_8, metadata.rssi_dbm, n);
    return entry;
  }

  const PeerTelemetrySummary* find(const NodeId peer) const noexcept {
    for (const auto& e : entries_) {
      if (e.occupied && e.peer == peer) return &e;
    }
    return nullptr;
  }

  // Identity change elsewhere (rebind, radio switch, reboot) marks the peer's
  // evidence stale. Stale entries stay readable as stale — they are not
  // deleted so loss of freshness is itself observable.
  void mark_stale(const NodeId peer) noexcept {
    if (PeerTelemetrySummary* e = find_mutable(peer)) e->stale = true;
  }

  std::size_t size() const noexcept {
    std::size_t n = 0;
    for (const auto& e : entries_) {
      if (e.occupied) ++n;
    }
    return n;
  }

 private:
  PeerTelemetrySummary* find_mutable(const NodeId peer) noexcept {
    for (auto& e : entries_) {
      if (e.occupied && e.peer == peer && !e.stale) return &e;
    }
    return nullptr;
  }
  PeerTelemetrySummary* find_stale_or_free(const NodeId peer) noexcept {
    for (auto& e : entries_) {
      if (e.occupied && e.peer == peer && e.stale) return &e;
    }
    for (auto& e : entries_) {
      if (!e.occupied) return &e;
    }
    return nullptr;
  }

  std::array<PeerTelemetrySummary, kPeerSummaryCapacity> entries_{};
};

// --- Diagnostic wire bodies (04 §4.2) ----------------------------------------
//
// FrameType::Diagnostic (48) carries a 4-byte prefix then a fixed subtype
// body. All integers big-endian; reserved/flag fields are zero and unknown
// values are rejected — a failed protected parse never falls through to a
// link-only parser.

constexpr std::uint8_t kDiagnosticBodyVersion = 1;

enum class DiagnosticSubtype : std::uint8_t {
  CapabilitiesQuery = 1,   // link-only, hop 1
  CapabilitiesReply = 2,   // link-only, hop 1
  TelemetryQuery = 3,      // link+end, Reliable
  TelemetrySnapshot = 4,   // link+end, Reliable
  TransitFailure = 5,      // link-only, hop 1 (D2)
  DiagnosticReject = 6,    // link+end, Reliable
};

constexpr std::size_t kDiagnosticPrefixSize = 4;
constexpr std::size_t kTelemetryQueryBodySize = 24;      // prefix included
constexpr std::size_t kTelemetrySnapshotBodySize = 128;  // prefix included
constexpr std::size_t kDiagnosticRejectBodySize = 24;    // prefix included
constexpr std::size_t kCapabilitiesReplyBodySize = 40;   // prefix included
constexpr std::size_t kTransitFailureBodySize = 80;      // prefix included

// TelemetryQuery validation bounds (04 §4.2).
constexpr std::uint32_t kTelemetryMaxAgeLimitMs = 3000;
constexpr std::uint8_t kTelemetryPeerSummaryClass = 255;
// One outstanding remote query may occupy the routed lane at most this long;
// the reply borrows the query's own remaining deadline and never extends it.
constexpr std::uint32_t kTelemetryQueryLifetimeMs = 5000;

struct TelemetryQuery {
  std::uint32_t request_id{0};  // nonzero
  NodeId peer{kInvalidNodeId};  // nonzero
  ObservationDirection direction{ObservationDirection::Egress};
  std::uint8_t length_class{0};  // 0..2, or 255 = peer summary only
  std::uint32_t max_age_ms{0};   // 0 = latest; 1..3000 bounds freshness
};

Status telemetry_query_encode(const TelemetryQuery& query,
                              MutableByteView out) noexcept;
Status telemetry_query_decode(ByteView body, TelemetryQuery& out) noexcept;

// Snapshot validity bits (04 §4.2). Bits 4/5 are mutually exclusive.
enum TelemetryValidity : std::uint8_t {
  kTelemetryValidRssi = 1u << 0,
  kTelemetryValidBucket = 1u << 1,
  kTelemetryValidDriverEwma = 1u << 2,
  kTelemetryValidHopRttEwma = 1u << 3,
  kTelemetrySourceLocalDriver = 1u << 4,
  kTelemetrySourceInjectedTest = 1u << 5,
  kTelemetryWindowIncomplete = 1u << 6,
  kTelemetryStale = 1u << 7,
};

// Saturation mask bits 0..10, in snapshot field order.
enum TelemetrySaturation : std::uint32_t {
  kSatRssiSamples = 1u << 0,
  kSatTxSubmitted = 1u << 1,
  kSatTxMacSuccess = 1u << 2,
  kSatTxMacFail = 1u << 3,
  kSatTxUnknown = 1u << 4,
  kSatSdkRetries = 1u << 5,
  kSatHopAccepts = 1u << 6,
  kSatHopTimeouts = 1u << 7,
  kSatBusy = 1u << 8,
  kSatEventDrops = 1u << 9,
  kSatTimeEwma = 1u << 10,
};

// Fixed 128-byte record (04 §4.2 offset table). Counter fields are
// saturating lifetime totals for the current boot/binding/bucket identity;
// a missing value encodes zero with its validity bit clear and becomes a
// host-side null, never an inferred zero measurement.
struct TelemetrySnapshot {
  std::uint32_t request_id{0};
  NodeId observer{kInvalidNodeId};
  std::uint64_t observer_boot{0};
  NodeId peer{kInvalidNodeId};
  BindingGeneration binding{};
  RadioGeneration radio{};
  ChannelEpoch channel_epoch{};
  std::uint8_t channel{0};
  ObservationDirection direction{ObservationDirection::Egress};
  std::uint8_t length_class{0};
  std::uint8_t validity{0};
  MonotonicMs sampled_at_ms{0};
  std::uint32_t window_ms{0};
  std::uint32_t sample_age_ms{0};
  std::int8_t rssi_last{0};
  std::int8_t rssi_min{0};
  std::int8_t rssi_max{0};
  std::int16_t rssi_ewma_q8_8{0};
  std::uint32_t rssi_samples{0};
  std::uint32_t tx_submitted{0};
  std::uint32_t tx_mac_success{0};
  std::uint32_t tx_mac_fail{0};
  std::uint32_t tx_unknown{0};
  std::uint32_t sdk_retries{0};
  std::uint32_t hop_accepts{0};
  std::uint32_t hop_timeouts{0};
  std::uint32_t busy{0};
  std::uint32_t queue_us_ewma{0};
  std::uint32_t driver_us_ewma{0};
  std::uint32_t hop_rtt_us_ewma{0};
  std::uint32_t event_drops{0};
  std::uint32_t saturation_mask{0};
};
static_assert(sizeof(TelemetrySnapshot) <= 176, "snapshot stays bounded");

Status telemetry_snapshot_encode(const TelemetrySnapshot& snapshot,
                                 MutableByteView out) noexcept;
Status telemetry_snapshot_decode(ByteView body, TelemetrySnapshot& out) noexcept;

enum class DiagnosticRejectReason : std::uint16_t {
  Unsupported = 1,
  Capacity = 2,
  Stale = 3,
  NoPeer = 4,
  NoBucket = 5,
  Denied = 6,
  Deadline = 7,
};

struct DiagnosticReject {
  std::uint32_t request_id{0};
  DiagnosticRejectReason reason{DiagnosticRejectReason::Unsupported};
  NodeId observer{kInvalidNodeId};
  std::uint32_t detail{0};  // zero in v1
};

Status diagnostic_reject_encode(const DiagnosticReject& reject,
                                MutableByteView out) noexcept;
Status diagnostic_reject_decode(ByteView body, DiagnosticReject& out) noexcept;

// CapabilitiesReply feature bits (04 §capabilities): what this node is wired
// to do RIGHT NOW — forward_v1 additionally requires the current effective
// relay permission, permit_profiles advertises only configured AND accepted
// profiles with ready providers, never every compiled algorithm.
enum CapabilityFeature : std::uint8_t {
  kCapForwardV1 = 1u << 0,
  kCapLocalTelemetryV1 = 1u << 1,
  kCapTransitFailureV1 = 1u << 2,
  kCapRemoteTelemetryV1 = 1u << 3,
  kCapBusyV1 = 1u << 4,
};
enum PermitProfileBit : std::uint8_t {
  kPermitProfileDevHmac = 1u << 0,
  kPermitProfileCoseEsp256 = 1u << 1,
};

// Fixed 40-byte link-only reply (subtype 2). A CapabilitiesQuery itself is
// the bare 4-byte prefix (subtype 1) — no fields.
struct CapabilitiesReply {
  NodeId observer{kInvalidNodeId};
  std::uint64_t observer_boot{0};
  std::uint8_t features{0};
  std::uint8_t permit_profiles{0};
  bool relay_effective{false};
};

Status capabilities_reply_encode(const CapabilitiesReply& reply,
                                 MutableByteView out) noexcept;
Status capabilities_reply_decode(ByteView body, CapabilitiesReply& out) noexcept;

// --- TransitFailure (subtype 5, link-only, hop-1, BestEffort) -----------------
//
// Bounded one-hop post-admission failure evidence (01-forwarding §policy,
// 04 §4.2 layout). It NEVER retracts accepted work: BUSY stays strictly
// pre-acceptance. The link authenticates only the immediate reporting
// neighbor — claimed_reporting_node is preserved verbatim as an UNVERIFIED
// claim, and the fingerprint pins the referenced frame's end-protected
// bytes so a report cannot be retargeted at a different operation.
enum class TransitFailurePhase : std::uint8_t {
  RefusedPreAcceptance = 0,  // never accepted locally (e.g. relay disabled)
  FailedPostAcceptance = 1,  // accepted work that later failed
  OutcomeUnknown = 2,        // attempt outcome cannot be proven
};
enum class TransitFailureReason : std::uint8_t {
  RelayDisabled = 1,
  HopExhausted = 2,
  NoRoute = 3,
  DuplicatePath = 4,
  MessageConflict = 5,
  RetryExhausted = 6,
  Deadline = 7,
  PeerGone = 8,
  SecurityUnavailable = 9,
  CallbackUnknown = 10,
  TimeUncertain = 11,
};

struct TransitFailure {
  // Reference to the failed frame: logical identity + type/round — a report
  // about a different round or type is a different report.
  NodeId ref_origin{kInvalidNodeId};
  std::uint32_t ref_session{0};
  std::uint64_t ref_sequence{0};
  NodeId ref_destination{kInvalidNodeId};
  std::uint8_t ref_type{0};
  std::uint8_t ref_round{0};
  TransitFailurePhase phase{TransitFailurePhase::RefusedPreAcceptance};
  TransitFailureReason reason{TransitFailureReason::RelayDisabled};
  // UNVERIFIED claim of the node that first observed the failure — the
  // receiver authenticated only its immediate neighbor.
  NodeId claimed_reporter{kInvalidNodeId};
  // Per-reporting-boot monotone, nonzero; wrap stops reports until reboot.
  std::uint32_t report_id{0};
  // SHA256("RouteLoom/transit-fingerprint/v1" || NUL || end-AAD ||
  //        protected payload incl. end tag) — excludes hop-mutable fields.
  std::array<std::uint8_t, 32> fingerprint{};
};

Status transit_failure_encode(const TransitFailure& report,
                              MutableByteView out) noexcept;
Status transit_failure_decode(ByteView body, TransitFailure& out) noexcept;

}  // namespace routeloom
