#pragma once

// Device-side host-operations (host_ops_v1) support: BootLease identity,
// SUBMIT/QUERY_DISPATCH/RETIRE_THROUGH/SKIP/TIME_SAMPLE inner-body codec and
// the bounded gateway DispatchWindow.
//
// Design contract (docs/design/host-security-readiness): 03-send-api.md §6
// fixes the subcommand numbers and the SUBMIT body layout; 04-capacity-
// storage.md §5 fixes the window/floor/lease rules; contracts.json
// `capacity.gateway_records_per_lane` (32) fixes the window size.
//
// Registration note: the design assumes an "existing Command kind" carrying
// these subcommands, but no such kind exists in this tree — so they ride one
// newly registered USB frame kind, FrameKind::HostOps (19), instead of
// overloading DataToMesh. Subcommand numbers 0x01-0x05 are exactly the
// design's values. Response layouts below are new (the design fixes only the
// SUBMIT request): every response is fixed-size, echoes the request's
// subcommand and the device's CURRENT boot lease, and carries a typed result
// code — no string parsing on the host state machine (TX-I2).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::usb {

// First documented USB capability bit (HelloAck capability digest): the
// device handles FrameKind::HostOps subcommands. Bits 0-1 are the legacy
// 0x3 default with no per-bit meaning assigned in this tree; the bridge
// answers HostOps frames with Unsupported unless this bit is configured.
constexpr std::uint32_t kCapHostOpsV1 = 1u << 2;

constexpr std::uint8_t kHostOpsSchema = 1;

// 03-send-api.md §6: registered once, never renumbered locally.
enum class HostOpsSub : std::uint8_t {
  Submit = 0x01,
  QueryDispatch = 0x02,
  RetireThrough = 0x03,
  Skip = 0x04,
  TimeSample = 0x05,
};

// Typed outcome carried inside every host_ops response. Malformed inner
// bodies (truncation, length mismatch, bad schema, unknown subcommand) are
// NOT reported here — those are Error frames (ProtocolError/Unsupported).
enum class HostOpsResult : std::uint8_t {
  Ok = 0,            // admitted / applied / answered
  Existing = 1,      // idempotent replay of the stored record
  Conflict = 2,      // same seq, different hash (or SUBMIT onto a SKIP)
  Retired = 3,       // seq at or below the retire floor: never re-sent
  WindowFull = 4,    // seq past floor+capacity: backpressure, retry later
  LeaseMismatch = 5,  // request lease != current boot lease (incl. reboot)
  NotRetained = 6,   // QUERY for an in-window hole / never-assigned seq
  RetireRefused = 7,  // retire would cross an unterminated position
  SkipRefused = 8,   // SKIP onto an already accepted record
  Expired = 9,       // device deadline already passed; terminal, not sent
  MeshRejected = 10,  // mesh could not take the send (no record; retry safe)
  LaneMismatch = 11,  // bound lane belongs to another dispatcher/network
  InvalidRequest = 12,  // reserved ids or unparsable canonical request
  Unsupported = 13,  // valid request, capability not enabled (APPLIED, ...)
};

constexpr std::size_t kBootLeaseSize = 16;
constexpr std::size_t kDispatcherIdSize = 16;
constexpr std::size_t kOperationIdSize = 24;  // store lineage 16B + seq 8B
constexpr std::size_t kCanonicalHashSize = 32;

// SUBMIT inner: schema:u8, sub:u8, boot_lease:16, dispatcher:16, seq:u64,
// operation_id:24, canonical_hash:32, device_deadline:u64,
// canonical_length:u16, canonical_request. Fixed part 108B (design §6,
// contracts.json wire.usb_submit_fixed_bytes), canonical 26..154B.
constexpr std::size_t kSubmitFixedSize = 108;
constexpr std::size_t kSubmitMaxSize = 262;  // 108 + 26 + 128
constexpr std::size_t kCanonicalMinSize = 26;
constexpr std::size_t kCanonicalMaxSize = 154;  // 26 + 128 payload
// QUERY_DISPATCH / RETIRE_THROUGH / SKIP share one shape: schema, sub,
// boot_lease:16, dispatcher:16, seq_or_through:u64.
constexpr std::size_t kLaneRequestSize = 42;
// TIME_SAMPLE request: schema, sub, boot_lease:16, query_nonce:u64.
constexpr std::size_t kTimeSampleRequestSize = 26;
// Responses (all fixed-size, exact-length checked):
// receipt: schema, sub, result, state, lease:16, seq:u64, hash:32,
//   msg_session:u32, msg_seq:u64, msg_valid:u8, evidence:u8.
constexpr std::size_t kReceiptSize = 74;
// query response: receipt + operation_id:24 after the hash.
constexpr std::size_t kQueryResponseSize = 98;
// retire response: schema, sub, result, lease:16, retired_through:u64.
constexpr std::size_t kRetireResponseSize = 27;
// time-sample response: schema, sub, result, lease:16, nonce:u64, time:u64.
constexpr std::size_t kTimeSampleResponseSize = 35;

// Per-boot gateway identity: NVS-monotonic boot generation bound to the
// provisioned node id, big-endian halves. The host derives the expected
// lease from HelloAck's boot+node fields — no separate discovery. A gateway
// reboot mints a new lease; anything presented under the old one is
// LeaseMismatch and the host must treat dispatched-but-unconfirmed work as
// indeterminate (04 §5). Identity only, not a secret: the protected session
// already authenticates the channel.
struct BootLease {
  std::array<std::uint8_t, kBootLeaseSize> bytes{};

  static BootLease derive(std::uint64_t boot_generation, NodeId node) noexcept;

  // Both halves must sit outside the reserved 0/MAX range (01 §3). A window
  // constructed with an invalid lease answers every request LeaseMismatch —
  // firmware must not enable business sends when boot persistence failed.
  bool valid() const noexcept;

  friend bool operator==(const BootLease& left, const BootLease& right) noexcept {
    return left.bytes == right.bytes;
  }
  friend bool operator!=(const BootLease& left, const BootLease& right) noexcept {
    return !(left == right);
  }
};

struct SubmitRequest {
  BootLease lease{};
  std::array<std::uint8_t, kDispatcherIdSize> dispatcher{};
  std::uint64_t dispatch_seq{0};
  std::array<std::uint8_t, kOperationIdSize> operation_id{};
  std::array<std::uint8_t, kCanonicalHashSize> canonical_hash{};
  std::uint64_t device_deadline{0};
  ByteView canonical{};  // borrows the decoded body (decode) or the caller's bytes (encode)
};

Status decode_submit(ByteView inner, SubmitRequest& out) noexcept;
Status encode_submit(const SubmitRequest& request, MutableByteView out,
                     std::size_t& written) noexcept;

struct LaneRequest {
  BootLease lease{};
  std::array<std::uint8_t, kDispatcherIdSize> dispatcher{};
  std::uint64_t seq{0};  // dispatch_seq (QUERY/SKIP) or retire_through (RETIRE)
};

Status decode_lane_request(ByteView inner, HostOpsSub sub, LaneRequest& out) noexcept;
Status encode_lane_request(HostOpsSub sub, const LaneRequest& request,
                           MutableByteView out, std::size_t& written) noexcept;

struct TimeSampleRequest {
  BootLease lease{};
  std::uint64_t nonce{0};
};

Status decode_time_sample_request(ByteView inner, TimeSampleRequest& out) noexcept;
Status encode_time_sample_request(const TimeSampleRequest& request,
                                  MutableByteView out, std::size_t& written) noexcept;

// Parsed canonical send request (03 §3): schema:u8=1, network:u32,
// dest_kind:u8, destination:u64, delivery:u8, priority:u8, policy:u8,
// storage:u8, ttl:u32, hop:u8, persist:u8, payload_len:u16, payload.
struct CanonicalFields {
  std::uint32_t network{0};
  std::uint8_t dest_kind{0};  // 0 node, 1 gateway
  NodeId destination{kInvalidNodeId};
  std::uint8_t delivery{0};  // 0 best-effort, 1 reliable, 2 applied
  std::uint8_t priority{0};
  std::uint8_t storage{0};
  std::uint32_t ttl_ms{0};
  std::uint8_t hop_limit{0};
  bool persist_sleep{false};
  ByteView payload{};
};

// Strict structural parse: exact 26+payload_len length, schema 1, known enum
// ranges, reserved node addresses rejected for node destinations. Delivery /
// priority / persist values that are structurally valid but not enabled in
// this phase are REPORTED, not rejected — the caller gates them to
// HostOpsResult::Unsupported (never silently downgraded).
Status parse_canonical_request(ByteView canonical, CanonicalFields& out) noexcept;

// Gateway dispatch window: the short-term per-lane record of dispatch_seq
// positions after retired_through. Single lane in this slice (04 §5 allows
// up to 4 negotiated lanes; boards without the RAM budget refuse — here any
// second dispatcher is LaneMismatch). Pure bounded state: no mesh, no clock,
// no heap. The bridge drives it (admit check → mesh send → record) and feeds
// mesh outcomes back via note_mesh_outcome.
class DispatchWindow {
 public:
  static constexpr std::size_t kCapacity = 32;  // contracts.json gateway_records_per_lane
  static constexpr std::size_t kRecordBudgetBytes = 128;  // design RAM budget per record

  // Per-position dispatch state. Terminal (04 §5) ends the gateway's own
  // new-send/resend responsibility — it says nothing about the destination
  // application's actions. Only terminal positions retire.
  enum class State : std::uint8_t {
    Empty = 0,  // no record (holes and retired positions read back as this)
    Sent = 1,   // mesh accepted, outcome pending — the only non-terminal state
    Delivered = 2,
    Failed = 3,
    Expired = 4,  // device deadline passed before any send
    Skipped = 5,  // host-certified never-submitted hole
    Indeterminate = 6,  // mesh gave up without an outcome
  };

  static constexpr bool is_terminal(const State state) noexcept {
    return state != State::Empty && state != State::Sent;
  }

  // Evidence stage (01 §5: distinct proofs, never one bool). Best-effort
  // mesh completion is MacAttemptReported — promoting it to EndSdkReceived
  // would lie about an end receipt that never existed.
  enum class Evidence : std::uint8_t {
    None = 0,
    GatewayAccepted = 1,
    MacAttemptReported = 2,
    EndSdkReceived = 3,
  };

  struct Slot {
    bool occupied{false};
    State state{State::Empty};
    std::uint8_t delivery{0};  // canonical delivery class (best-effort vs reliable)
    std::array<std::uint8_t, kCanonicalHashSize> hash{};
    std::array<std::uint8_t, kOperationIdSize> operation_id{};
    std::uint32_t msg_session{0};
    std::uint64_t msg_seq{0};
    bool msg_valid{false};
    Evidence evidence{Evidence::None};
  };

  enum class SubmitCheck : std::uint8_t {
    Admit,  // empty in-window position; caller sends, then records
    Replay,  // same seq+hash: answer Existing from the stored slot
    Conflict,  // occupied with a different hash (incl. SUBMIT onto a SKIP)
    Retired,
    WindowFull,
    LeaseMismatch,
    LaneMismatch,
    // Reserved dispatch_seq, dispatcher id, canonical_hash or operation_id
    // (all-zero / all-ones identity space, 01 §3).
    InvalidId,
  };

  enum class QueryOutcome : std::uint8_t {
    Found,
    Retired,
    NotRetained,  // in-window hole or never-assigned seq: read-only miss
    LeaseMismatch,
    LaneMismatch,
    InvalidId,
  };

  enum class RetireOutcome : std::uint8_t {
    Advanced,  // floor moved; span was fully terminal
    NoopFloor,  // through <= floor: idempotent re-RETIRE (CAP09)
    RefusedSpan,  // span crosses an empty/unterminated or untracked position
    LeaseMismatch,
    LaneMismatch,
    InvalidId,  // reserved `through` value (0 / UINT64_MAX)
  };

  enum class SkipOutcome : std::uint8_t {
    Skipped,  // hole filled with a terminal Skipped record
    ReplaySkipped,  // same hole SKIPped again: idempotent
    Occupied,  // an accepted record exists: never overwritten
    Retired,
    WindowFull,
    LeaseMismatch,
    LaneMismatch,
    InvalidId,
  };

  explicit DispatchWindow(const BootLease& lease) noexcept : lease_(lease) {}

  const BootLease& lease() const noexcept { return lease_; }
  std::uint64_t retired_through() const noexcept { return floor_; }
  bool lane_bound() const noexcept { return lane_bound_; }
  std::size_t used() const noexcept;
  const Slot* find(std::uint64_t dispatch_seq) const noexcept;

  // Stage 1 of SUBMIT: classify without mutating. The caller (bridge) then
  // parses the canonical request, enforces the device deadline and attempts
  // the mesh send before recording — a refused/failed send leaves no record
  // so a later retry is a clean Admit, never a Conflict.
  SubmitCheck check_submit(const BootLease& lease,
                           const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
                           std::uint64_t dispatch_seq,
                           const std::array<std::uint8_t, kCanonicalHashSize>& hash,
                           const std::array<std::uint8_t, kOperationIdSize>& operation_id) const noexcept;

  // Stage 2a: mesh accepted the first send — and the first actual send is
  // what binds the lane. A lone SKIP or an expired-at-admission SUBMIT only
  // writes a terminal record: those mutations leave nothing to send or
  // correlate, so letting them bind would lock the real dispatcher out of
  // its own lane for the whole boot. False only if the position is no
  // longer admittable (defensive: impossible for a single-threaded
  // check-then-record caller).
  bool record_sent(const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
                   std::uint64_t dispatch_seq,
                   const std::array<std::uint8_t, kCanonicalHashSize>& hash,
                   const std::array<std::uint8_t, kOperationIdSize>& operation_id,
                   std::uint8_t delivery, std::uint32_t msg_session,
                   std::uint64_t msg_seq) noexcept;

  // Stage 2b: device deadline already passed — terminal Expired record, no
  // mesh send. Does NOT bind the lane (only record_sent binds).
  bool record_expired(const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
                      std::uint64_t dispatch_seq,
                      const std::array<std::uint8_t, kCanonicalHashSize>& hash,
                      const std::array<std::uint8_t, kOperationIdSize>& operation_id,
                      std::uint8_t delivery) noexcept;

  // Degraded-path record for a send the mesh already accepted when the
  // primary record path refused (a post-Admit inconsistency that should be
  // unreachable for the single-threaded caller). If the position is still
  // free it becomes a terminal Indeterminate record carrying the send's
  // MessageKey: the delivery outcome still correlates, the position can
  // retire, and it can never look like a clean re-Admit — which would let
  // a retry double-send. Does NOT bind the lane.
  bool record_indeterminate(
      const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
      std::uint64_t dispatch_seq,
      const std::array<std::uint8_t, kCanonicalHashSize>& hash,
      const std::array<std::uint8_t, kOperationIdSize>& operation_id,
      std::uint8_t delivery, std::uint32_t msg_session,
      std::uint64_t msg_seq) noexcept;

  // Read-only lookup for QUERY_DISPATCH: fills `slot` on Found. Never
  // mutates, never extends anything, never re-executes.
  QueryOutcome query(const BootLease& lease,
                     const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
                     std::uint64_t dispatch_seq, Slot& slot) const noexcept;

  // Contiguous-prefix retirement only: every position in (floor_, through]
  // must be occupied AND terminal, and through must stay inside the tracked
  // window. Deletes the span, then advances the floor.
  RetireOutcome retire_through(const BootLease& lease,
                               const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
                               std::uint64_t through) noexcept;

  // Fills a hole with a terminal Skipped record. Records the hole WITHOUT
  // binding the lane: only record_sent (the first actual send) claims it,
  // so a stray SKIP cannot lock the real dispatcher out for the boot.
  SkipOutcome skip(const BootLease& lease,
                   const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
                   std::uint64_t dispatch_seq) noexcept;

  // Mesh outcome correlation (bridge on_delivery). Returns true when a slot
  // holds this MessageKey — the caller then suppresses the legacy
  // DeliveryEvent for it (host_ops outcomes are pulled via QUERY_DISPATCH).
  // Transitions Sent slots to their terminal state; terminal slots and
  // non-terminal mesh states leave the slot unchanged. Mesh session restarts
  // inside one boot are outside this slice's model (firmware reboots as a
  // unit, minting a new lease that wipes the window).
  bool note_mesh_outcome(std::uint32_t msg_session, std::uint64_t msg_seq,
                         DeliveryState mesh_state) noexcept;

 private:
  bool lease_ok(const BootLease& lease) const noexcept {
    return lease_.valid() && lease == lease_;
  }
  // Unbound lane accepts any dispatcher (nothing lane-scoped exists yet);
  // once bound, dispatcher AND network must match. The network half is
  // enforced by the bridge (canonical vs session network); the window owns
  // the dispatcher half recorded here.
  bool lane_ok(const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher) const noexcept;
  bool bind_lane(const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher) noexcept;
  Slot* position(std::uint64_t dispatch_seq) noexcept;
  const Slot* position(std::uint64_t dispatch_seq) const noexcept;

  BootLease lease_;
  std::uint64_t floor_{0};
  bool lane_bound_{false};
  std::array<std::uint8_t, kDispatcherIdSize> lane_dispatcher_{};
  std::array<Slot, kCapacity> slots_{};
};

static_assert(sizeof(DispatchWindow::Slot) <= DispatchWindow::kRecordBudgetBytes,
              "window slot exceeds the 128B design RAM budget");

// SUBMIT/SKIP answer. `hash`/`msg_*`/`evidence` come from the stored slot
// whenever one exists (Ok/Existing/Conflict/SkipRefused); administrative
// refusals (lease/lane/retired/full/invalid) echo the request seq with
// zeroed record fields.
struct DispatchReceipt {
  HostOpsSub sub{HostOpsSub::Submit};
  HostOpsResult result{HostOpsResult::Ok};
  DispatchWindow::State state{DispatchWindow::State::Empty};
  BootLease lease{};
  std::uint64_t dispatch_seq{0};
  std::array<std::uint8_t, kCanonicalHashSize> hash{};
  std::uint32_t msg_session{0};
  std::uint64_t msg_seq{0};
  bool msg_valid{false};
  DispatchWindow::Evidence evidence{DispatchWindow::Evidence::None};
};

Status encode_receipt(const DispatchReceipt& receipt, MutableByteView out,
                      std::size_t& written) noexcept;
Status decode_receipt(ByteView inner, HostOpsSub sub, DispatchReceipt& out) noexcept;

struct QueryResponse {
  HostOpsResult result{HostOpsResult::Ok};
  DispatchWindow::State state{DispatchWindow::State::Empty};
  BootLease lease{};
  std::uint64_t dispatch_seq{0};
  std::array<std::uint8_t, kCanonicalHashSize> hash{};
  std::array<std::uint8_t, kOperationIdSize> operation_id{};
  std::uint32_t msg_session{0};
  std::uint64_t msg_seq{0};
  bool msg_valid{false};
  DispatchWindow::Evidence evidence{DispatchWindow::Evidence::None};
};

Status encode_query_response(const QueryResponse& response, MutableByteView out,
                             std::size_t& written) noexcept;
Status decode_query_response(ByteView inner, QueryResponse& out) noexcept;

struct RetireResponse {
  HostOpsResult result{HostOpsResult::Ok};
  BootLease lease{};
  std::uint64_t retired_through{0};
};

Status encode_retire_response(const RetireResponse& response, MutableByteView out,
                              std::size_t& written) noexcept;
Status decode_retire_response(ByteView inner, RetireResponse& out) noexcept;

struct TimeSampleResponse {
  HostOpsResult result{HostOpsResult::Ok};
  BootLease lease{};
  std::uint64_t nonce{0};
  std::uint64_t device_time{0};  // device monotonic ms at sampling
};

Status encode_time_sample_response(const TimeSampleResponse& response,
                                   MutableByteView out, std::size_t& written) noexcept;
Status decode_time_sample_response(ByteView inner, TimeSampleResponse& out) noexcept;

}  // namespace routeloom::usb
