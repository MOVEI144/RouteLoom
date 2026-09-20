#pragma once

// Common contracts handed to the single radio Owner for the autonomous-mesh
// profile (docs/design/autonomous-mesh/01-integration.md §3, §4, §7, §8).
// Pure contract types: the Owner event loop, discovery, congestion control
// and channel migration that consume them land in later phases.
//
// Invariants encoded here:
//   - RX records are bounded, self-contained copies; the radio callback does
//     not resolve NodeId and performs only cheap parse + bounded enqueue.
//   - TX intents name a VerifiedBinding id or a limited BootstrapAddress —
//     the DATA path can never carry an arbitrary MAC.
//   - Generations, observation units and operation tokens are distinct types
//     with no silent conversions; none is a nonce counter or MessageId.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/peer_directory.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Generation types (01-integration.md §4) ---------------------------------
// All distinct, all monotonic within their own scope, none usable as a nonce
// counter or MessageId.

// Local radio configuration/callback consistency: bumped when the driver
// radio is reconfigured so stale RX/TX completions cannot be attributed to a
// newer configuration.
struct RadioGeneration {
  std::uint32_t value{0};
  friend constexpr bool operator==(RadioGeneration a, RadioGeneration b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(RadioGeneration a, RadioGeneration b) noexcept {
    return !(a == b);
  }
};

// Committed channel plan epoch. Distinct from the Wire v1 link/end epochs:
// only a verified authority plan advances it; visits alone never rewind it.
struct ChannelEpoch {
  std::uint32_t value{0};
  friend constexpr bool operator==(ChannelEpoch a, ChannelEpoch b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(ChannelEpoch a, ChannelEpoch b) noexcept {
    return !(a == b);
  }
};

// Ordering tag on authenticated load feedback (Busy/NeighborResult) so stale
// or replayed feedback is detectable. Not a packet nonce.
struct FeedbackSequence {
  std::uint32_t value{0};
  friend constexpr bool operator==(FeedbackSequence a, FeedbackSequence b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(FeedbackSequence a, FeedbackSequence b) noexcept {
    return !(a == b);
  }
};

// --- Observation units (01-integration.md §8) --------------------------------
// Distinct units; no silent conversions. Time-to-driver-callback is not
// airtime occupancy; a country's TX limit is not a per-peer capability.

struct QueueDelayMs {        // local enqueue -> handed-to-driver sojourn
  std::uint32_t value{0};
  friend constexpr bool operator==(QueueDelayMs a, QueueDelayMs b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(QueueDelayMs a, QueueDelayMs b) noexcept {
    return !(a == b);
  }
};
struct DriverServiceUs {     // driver accept -> TX callback; may include CCA/MAC retries
  std::uint32_t value{0};
  friend constexpr bool operator==(DriverServiceUs a, DriverServiceUs b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(DriverServiceUs a, DriverServiceUs b) noexcept {
    return !(a == b);
  }
};
struct EstimatedAirtimeUs {  // estimated on-air occupancy for a frame class
  std::uint32_t value{0};
  friend constexpr bool operator==(EstimatedAirtimeUs a, EstimatedAirtimeUs b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(EstimatedAirtimeUs a, EstimatedAirtimeUs b) noexcept {
    return !(a == b);
  }
};
struct TxPowerQuarterDbm {   // transmit power in 0.25 dBm units (signed)
  std::int16_t value{0};
  friend constexpr bool operator==(TxPowerQuarterDbm a, TxPowerQuarterDbm b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(TxPowerQuarterDbm a, TxPowerQuarterDbm b) noexcept {
    return !(a == b);
  }
};

// --- RX contract (01-integration.md §3.1) ------------------------------------

// Cheap callback-side classification lane. A MAC hitting the known-peer lane
// is NOT authentication evidence — the worker re-verifies everything.
enum class RxLane : std::uint8_t {
  KnownPeer = 0,  // source MAC matched the immutable peer snapshot
  Bootstrap,      // unknown/unregistered MAC: bounded discovery lane only
};

// Bounded, self-contained RX record. The callback copies into this, enqueues
// and returns; no NodeId resolution, no allocation, no unbounded queue.
struct RawRxEnvelope {
  MacAddress source{};
  MacAddress destination{};
  std::uint8_t radio_id{0};
  std::uint8_t channel{0};                       // channel observed at capture
  RadioGeneration local_radio_generation{};
  MonotonicMs received_at_ms{0};
  std::int8_t rssi_dbm{0};
  bool rssi_valid{false};                        // unmeasured RSSI stays unknown
  RxLane lane{RxLane::Bootstrap};
  std::array<std::uint8_t, kMaxEspNowBody> body{};
  std::size_t body_size{0};

  ByteView bytes() const noexcept { return ByteView{body.data(), body_size}; }
};

// --- TX contract (01-integration.md §3.2) ------------------------------------

enum class TxPurpose : std::uint8_t {
  Data = 0,
  Ack,
  BootstrapExchange,  // RLD1 or Wire bootstrap transaction traffic
  NeighborProbe,
  ControlObject,
  Survey,
  MigrationControl,
};

// Recipient of a TX intent. Exactly one arm is valid: a verified binding for
// all member traffic, or a limited bootstrap address for pre-membership
// exchange. There is intentionally no raw-MAC arm for DATA.
struct TxRecipient {
  enum class Kind : std::uint8_t { VerifiedBinding = 0, Bootstrap = 1 } kind{Kind::VerifiedBinding};
  BindingId binding{kInvalidBindingId};
  BootstrapAddress bootstrap{};

  static constexpr TxRecipient for_binding(BindingId id) noexcept {
    TxRecipient r{};
    r.kind = Kind::VerifiedBinding;
    r.binding = id;
    return r;
  }
  static constexpr TxRecipient for_bootstrap(MacAddress mac,
                                             std::uint32_t network_hint) noexcept {
    TxRecipient r{};
    r.kind = Kind::Bootstrap;
    r.bootstrap = BootstrapAddress{mac, network_hint};
    return r;
  }
};

// A unit of radio work the Owner may schedule. The Owner alone takes link
// counters in real TX order, seals and transmits; other features never call
// the driver directly. Message id/round/original deadline live in `encoded`
// and are preserved across re-evaluation after radio config changes.
struct TxIntent {
  TxRecipient recipient{};
  TxPurpose purpose{TxPurpose::Data};
  MonotonicMs deadline_ms{0};            // local monotonic deadline
  Priority priority{Priority::Normal};
  RadioGeneration radio_generation{};    // config the intent was issued under
  BindingId required_lease{kInvalidBindingId};  // peer lease that must stay held
  ByteView encoded{};                    // caller-owned encoded bytes
  bool encoded_valid{false};             // whether `encoded` is populated
};

// --- Radio operation arbiter (01-integration.md §3.3) -------------------------

// Mutually exclusive radio configuration operations; one arbiter serializes
// survey visits, committed channel switches and sleep preparation.
enum class RadioOperationKind : std::uint8_t {
  DiscoveryVisit = 0,   // bounded discovery on a non-home channel
  SurveyVisit,          // diagnostic single-radio survey visit
  ChannelCutover,       // committed plan cutover (set_channel + readback)
  SleepPrepare,         // drain/persist for sleep
};

struct RadioOperationConstraints {
  std::uint8_t channel{0};            // target/visit channel when applicable
  std::uint32_t max_duration_ms{0};   // hard bound incl. return-to-home
  bool outage_permitted{false};       // caller grants a bounded RX outage
};

struct RadioOperation {
  RadioOperationKind kind{RadioOperationKind::DiscoveryVisit};
  MonotonicMs deadline_ms{0};
  RadioOperationConstraints constraints{};
};

// Handle returned by request_radio_operation. Evidence lookups use the token;
// a token is never a delivery/MessageId.
struct OperationToken {
  std::uint64_t value{0};
  friend constexpr bool operator==(OperationToken a, OperationToken b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(OperationToken a, OperationToken b) noexcept {
    return !(a == b);
  }
};
constexpr OperationToken kInvalidOperationToken{0};

enum class OperationOutcome : std::uint8_t {
  Pending = 0,
  Applied,
  Rejected,       // refused before any side effect (policy/conflict)
  Failed,         // started, known to not have taken effect
  Indeterminate,  // side effects unknown (lost completion); never merge with success
};

struct OperationResult {
  OperationToken token{kInvalidOperationToken};
  OperationOutcome outcome{OperationOutcome::Pending};
  StatusCode reason{StatusCode::Ok};
  MonotonicMs expires_at_ms{0};  // evidence retention bound on the monotonic clock
};

}  // namespace routeloom
