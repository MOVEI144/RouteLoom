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
#include "routeloom/node.hpp"
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

// TelemetryQuery validation bounds (04 §4.2).
constexpr std::uint32_t kTelemetryMaxAgeLimitMs = 3000;
constexpr std::uint8_t kTelemetryPeerSummaryClass = 255;

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

}  // namespace routeloom
