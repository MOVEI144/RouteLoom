#pragma once

// Payload registry for the autonomous-mesh control payloads
// (docs/design/autonomous-mesh/01-integration.md §6). Wire v1 itself is
// frozen: these are versioned PAYLOAD layouts carried inside existing
// FrameTypes, plus the separate RLD1 1-hop bootstrap carrier.
//
// Every new payload begins with a two-byte prelude:
//   0  u8  payload version (= kPayloadVersion)
//   1  u8  subtype (per-FrameType enum below)
// followed by fixed-width big-endian fields; reserved bytes are 0. Decoders
// reject unknown versions, unknown subtypes, nonzero reserved fields and any
// length mismatch — they never guess at prefix layouts.
//
// The byte layouts here are pinned by the shared vectors in
// protocol/autonomy-golden/ (C++ and Rust must produce identical bytes).
// They fix meaning and maximum length only; they are not a substitute for
// the production crypto suite (G-SEC).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::autonomy {

constexpr std::uint8_t kPayloadVersion = 1;

// Per-frame payload budgets (contracts.json wire.*). The reassembled-object
// limits bound multi-frame objects, not a single frame payload.
constexpr std::size_t kBusyPayloadMax = 64;
constexpr std::size_t kAuthenticatedObjectMax = 2048;
constexpr std::size_t kBootstrapObjectMax = 1024;

// Maximum payload bytes a frame of this type may carry under the v1
// registry. Unlisted types have no registered autonomy payload (0).
constexpr std::size_t payload_budget(const FrameType type) noexcept {
  switch (type) {
    case FrameType::Busy:
      return kBusyPayloadMax;
    case FrameType::TimeSync:
    case FrameType::ChannelNotice:
    case FrameType::NeighborProbe:
    case FrameType::NeighborResult:
    case FrameType::ControlObject:
    case FrameType::ObjectChunk:
    case FrameType::ObjectAck:
    case FrameType::BootstrapAuth:
      return kMaxApplicationPayload;
    default:
      return 0;
  }
}

using EncodedPayload = ByteBuffer<kMaxApplicationPayload>;

// --- Busy (FrameType::Busy=20) ----------------------------------------------
// 03-congestion.md §5: pre-acceptance refusal and post-acceptance pressure
// hints. 38-byte fixed body, budget 64.
enum class BusySubtype : std::uint8_t {
  Reject = 1,        // pre-admission refusal (never cancels accepted work)
  PressureHint = 2,  // post-acceptance slow-down request upstream
};
enum class BusyReason : std::uint8_t {
  None = 0,
  QueueFull = 1,
  PeerCapacityBusy = 2,
  BudgetExhausted = 3,
  PlannedAbsence = 4,
  RateLimited = 5,
};
// Layout (38B): version u8 | subtype u8 | reason u8 | referenced type u8 |
// referenced origin u64 | session u32 | sequence u64 | round u8 |
// binding generation u32 | feedback sequence u32 | retry_after_ms u32 |
// pressure u8.
struct BusyPayload {
  BusySubtype subtype{BusySubtype::Reject};
  BusyReason reason{BusyReason::None};
  FrameType referenced_type{FrameType::Data};
  NodeId referenced_origin{kInvalidNodeId};
  std::uint32_t referenced_session{0};
  std::uint64_t referenced_sequence{0};
  std::uint8_t referenced_round{0};
  BindingGeneration binding_generation{};
  FeedbackSequence feedback_sequence{};
  std::uint32_t retry_after_ms{0};  // senders clamp to 20..1000 ms
  std::uint8_t pressure{0};         // self-declared 0..255, hint only
};
constexpr std::size_t kBusyPayloadSize = 38;
Status busy_encode(const BusyPayload& payload, EncodedPayload& out) noexcept;
Status busy_decode(ByteView encoded, BusyPayload& out) noexcept;

// --- TimeSync (FrameType::TimeSync=23) --------------------------------------
// Bounded clock-mapping sample for survey/migration coordination
// (04-channel-migration.md §8). Remote timestamps are carried as opaque
// references, never compared directly against the local clock.
enum class TimeSyncSubtype : std::uint8_t { Sample = 1 };
// Layout (26B): version u8 | subtype u8 | source u64 | sync sequence u32 |
// reference monotonic ms u64 | uncertainty ms u32.
struct TimeSyncPayload {
  TimeSyncSubtype subtype{TimeSyncSubtype::Sample};
  NodeId source{kInvalidNodeId};
  std::uint32_t sequence{0};
  MonotonicMs reference_ms{0};
  std::uint32_t uncertainty_ms{0};
};
constexpr std::size_t kTimeSyncPayloadSize = 26;
Status time_sync_encode(const TimeSyncPayload& payload, EncodedPayload& out) noexcept;
Status time_sync_decode(ByteView encoded, TimeSyncPayload& out) noexcept;

// --- ChannelNotice (FrameType::ChannelNotice=24) -----------------------------
// Short authenticated notices, e.g. a planned single-radio absence during a
// survey visit (04-channel-migration.md §3). Offsets/durations are relative
// to reception, not absolute remote times.
enum class ChannelNoticeSubtype : std::uint8_t { PlannedAbsence = 1 };
enum class AbsenceReason : std::uint8_t {
  None = 0,
  SurveyVisit = 1,
  HelperVisit = 2,
  Cutover = 3,
};
// Layout (25B): version u8 | subtype u8 | subject u64 | channel epoch u32 |
// starts_in_ms u32 | duration_ms u32 | reason u8 | protected cut id u16.
// The cut id lets remote coordinators apply cut-level absence protection
// (note_absence -> cut_absent); 0 = the absence protects no cut.
struct ChannelNoticePayload {
  ChannelNoticeSubtype subtype{ChannelNoticeSubtype::PlannedAbsence};
  NodeId subject{kInvalidNodeId};
  ChannelEpoch channel_epoch{};
  std::uint32_t starts_in_ms{0};
  std::uint32_t duration_ms{0};
  AbsenceReason reason{AbsenceReason::None};
  std::uint16_t protected_cut_id{0};
};
constexpr std::size_t kChannelNoticePayloadSize = 25;
Status channel_notice_encode(const ChannelNoticePayload& payload,
                             EncodedPayload& out) noexcept;
Status channel_notice_decode(ByteView encoded, ChannelNoticePayload& out) noexcept;

// --- NeighborProbe / NeighborResult (FrameType 40/41) ------------------------
// Post-BOUND bidirectional availability confirmation (02-discovery.md §3).
// Only usable once both ends hold membership + binding; never a pre-member
// key check.
enum class NeighborProbeSubtype : std::uint8_t { AvailabilityProbe = 1 };
// Probe layout (22B): version u8 | subtype u8 | binding generation u32 |
// probe sequence u32 | sent monotonic ms u64 | requested lease ms u32.
struct NeighborProbePayload {
  NeighborProbeSubtype subtype{NeighborProbeSubtype::AvailabilityProbe};
  BindingGeneration binding_generation{};
  std::uint32_t probe_sequence{0};
  MonotonicMs sent_ms{0};
  std::uint32_t requested_lease_ms{0};
};
constexpr std::size_t kNeighborProbePayloadSize = 22;
Status neighbor_probe_encode(const NeighborProbePayload& payload,
                             EncodedPayload& out) noexcept;
Status neighbor_probe_decode(ByteView encoded, NeighborProbePayload& out) noexcept;

enum class NeighborResultSubtype : std::uint8_t { AvailabilityResult = 1 };
enum class NeighborResultCode : std::uint8_t {
  Unknown = 0,
  Reachable = 1,
  NotListening = 2,
  Leaving = 3,
};
// Result layout (24B): version u8 | subtype u8 | binding generation u32 |
// probe sequence u32 | result u8 | pressure u8 | queue delay ms u32 |
// estimated airtime us u32 | lease granted ms u32.
struct NeighborResultPayload {
  NeighborResultSubtype subtype{NeighborResultSubtype::AvailabilityResult};
  BindingGeneration binding_generation{};
  std::uint32_t probe_sequence{0};  // echo of the probe being answered
  NeighborResultCode result{NeighborResultCode::Unknown};
  std::uint8_t pressure{0};
  std::uint32_t queue_delay_ms{0};
  std::uint32_t est_airtime_us{0};
  std::uint32_t lease_granted_ms{0};
};
constexpr std::size_t kNeighborResultPayloadSize = 24;
Status neighbor_result_encode(const NeighborResultPayload& payload,
                              EncodedPayload& out) noexcept;
Status neighbor_result_decode(ByteView encoded, NeighborResultPayload& out) noexcept;

// --- Authenticated objects (FrameType 49/50/51) ------------------------------
// Bounded authenticated object transfer: a manifest header (49), fixed
// chunks (50) and an acknowledgement (51). Reassembled objects are capped at
// kAuthenticatedObjectMax; decoder maximums are never raised without bound.
enum class ControlObjectSubtype : std::uint8_t { Manifest = 1 };
enum class ControlObjectKind : std::uint8_t {
  ChannelPlan = 1,
  RecoverySnapshot = 2,
  // Scope-gateway-config §5.1: end-protected routed config permits ride the
  // same object transfer; link-only kinds 1/2 keep their existing path.
  ConfigPermit = 3,
  // Signed recovery commands (RCR1) ride a dedicated lane of the same
  // transfer (04 §4.7, 06 §6.3): separate from kind-3 intake so an impaired
  // journal can receive recovery evidence while refusing normal permits.
  ConfigRecovery = 4,
};
using ObjectHash = std::array<std::uint8_t, 32>;
// Manifest layout (38B): version u8 | subtype u8 | kind u8 | flags u8 (=0) |
// total_len u16 | object_hash 32B.
struct ControlObjectPayload {
  ControlObjectSubtype subtype{ControlObjectSubtype::Manifest};
  ControlObjectKind kind{ControlObjectKind::ChannelPlan};
  std::uint16_t total_len{0};  // <= kAuthenticatedObjectMax
  ObjectHash object_hash{};
};
constexpr std::size_t kControlObjectPayloadSize = 38;
Status control_object_encode(const ControlObjectPayload& payload,
                             EncodedPayload& out) noexcept;
Status control_object_decode(ByteView encoded, ControlObjectPayload& out) noexcept;

enum class ObjectChunkSubtype : std::uint8_t { Chunk = 1 };
// Chunk layout (38+n): version u8 | subtype u8 | object_hash 32B |
// offset u16 | length u16 | data[length].
struct ObjectChunkPayload {
  ObjectChunkSubtype subtype{ObjectChunkSubtype::Chunk};
  ObjectHash object_hash{};
  std::uint16_t offset{0};
  std::array<std::uint8_t, kMaxApplicationPayload - 38> data{};
  std::uint16_t data_size{0};
};
constexpr std::size_t kObjectChunkHeaderSize = 38;
Status object_chunk_encode(const ObjectChunkPayload& payload,
                           EncodedPayload& out) noexcept;
Status object_chunk_decode(ByteView encoded, ObjectChunkPayload& out) noexcept;

enum class ObjectAckSubtype : std::uint8_t { Ack = 1 };
enum class ObjectAckStatus : std::uint8_t {
  Ok = 0,
  Incomplete = 1,
  Failed = 2,
};
// Ack layout (37B): version u8 | subtype u8 | object_hash 32B |
// received_len u16 | status u8.
struct ObjectAckPayload {
  ObjectAckSubtype subtype{ObjectAckSubtype::Ack};
  ObjectHash object_hash{};
  std::uint16_t received_len{0};
  ObjectAckStatus status{ObjectAckStatus::Ok};
};
constexpr std::size_t kObjectAckPayloadSize = 37;
Status object_ack_encode(const ObjectAckPayload& payload, EncodedPayload& out) noexcept;
Status object_ack_decode(ByteView encoded, ObjectAckPayload& out) noexcept;

// --- BootstrapAuth body (FrameType::BootstrapAuth=3) --------------------------
// PROVE/CONFIRM/FINISH are logical phases INSIDE type 3 — never new
// top-level frame types (06-membership-admission.md §3). Carried on RLD1
// (discovery) and on the authenticated Wire bootstrap path.
enum class AuthPhase : std::uint8_t {
  Prove = 1,
  Confirm = 2,
  Finish = 3,
};
// Layout (4+n): version u8 | phase u8 | step index u8 | reserved u8 (=0) |
// phase body n.
struct BootstrapAuthBody {
  AuthPhase phase{AuthPhase::Prove};
  std::uint8_t step_index{0};
  std::array<std::uint8_t, kMaxApplicationPayload - 4> body{};
  std::size_t body_size{0};
};
constexpr std::size_t kBootstrapAuthHeaderSize = 4;
Status bootstrap_auth_encode(const BootstrapAuthBody& payload,
                             EncodedPayload& out) noexcept;
Status bootstrap_auth_decode(ByteView encoded, BootstrapAuthBody& out) noexcept;

// --- RLD1 discovery carrier (02-discovery.md §4) ------------------------------
// A limited 1-hop bootstrap carrier — not a second FrameType numbering
// scheme. Shares semantic type ids with Wire v1 but is classified exactly
// once by its full magic+version: RLD1 input must never reach the Wire
// parser, and Wire link-open failures must never fall back to RLD1.
constexpr std::uint32_t kRld1Magic = 0x524c4431;  // "RLD1"
constexpr std::uint8_t kRld1Version = 1;
constexpr std::size_t kRld1HeaderSize = 44;
constexpr std::size_t kRld1MaxBody = 116;
constexpr std::size_t kRld1MaxTotal = 160;
static_assert(kRld1HeaderSize + kRld1MaxBody == kRld1MaxTotal,
              "RLD1 header + body budget must equal the total limit");
static_assert(kRld1MaxTotal <= kMaxEspNowBody,
              "RLD1 envelope must fit the ESP-NOW body");

// Header layout (44B): magic 4 | version u8 | kind u8 | header_len u16 |
// total_len u16 | flags u16 (=0) | network hint u32 | claimed node u64 |
// transaction nonce 16B | capability bits u32.
struct Rld1Envelope {
  FrameType kind{FrameType::Discover};  // only {1,2,3,5,6} — see rld1_kind_allowed
  std::uint16_t flags{0};               // v1: all bits reserved, must be 0
  std::uint32_t network_hint{0};        // 4-byte discovery hint, NOT the 64-bit NetworkId
  NodeId claimed_node{kInvalidNodeId};  // self-declared; verified only via transcript
  std::array<std::uint8_t, 16> transaction_nonce{};
  std::uint32_t capability_bits{0};
  std::array<std::uint8_t, kRld1MaxBody> body{};
  std::size_t body_size{0};
};

using Rld1Encoded = ByteBuffer<kRld1MaxTotal>;

// Cheap carrier probe for the single classification point: true iff the
// bytes start with the full RLD1 magic + supported version. A true probe
// followed by a decode error is a REJECT, never a fallback into Wire.
bool rld1_probe(ByteView encoded) noexcept;
Status rld1_encode(const Rld1Envelope& envelope, Rld1Encoded& out) noexcept;
Status rld1_decode(ByteView encoded, Rld1Envelope& out) noexcept;

}  // namespace routeloom::autonomy
