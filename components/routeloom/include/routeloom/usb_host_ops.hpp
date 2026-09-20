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

// scope-gateway-config P3 (docs/design/scope-gateway-config/05-wire-api.md
// §5.6): the device serves the Gateway HostOps subcommands 0x10-0x13 —
// host endpoint registration, scope-2 ReceiveLog ingress + ACK, and
// unregister. Advertised separately from host_ops_v1 so a bridge build can
// expose the dispatch window without the gateway host lane.
constexpr std::uint32_t kCapGatewayEndpointV1 = 1u << 3;

// scope-gateway-config P5 (docs/design/scope-gateway-config/05-wire-api.md
// §5.6): the device serves the Config HostOps subcommands 0x20-0x23 —
// status/challenge queries and the ConfigPermit object transfer toward a
// target. Advertised separately so a bridge build can expose the gateway
// host lane without the remote-config endpoint.
constexpr std::uint32_t kCapConfigEndpointV1 = 1u << 4;

constexpr std::uint8_t kHostOpsSchema = 1;

// 03-send-api.md §6 (0x01-0x05) and scope-gateway-config/05-wire-api.md
// §5.6 (0x10-0x13, 0x20-0x23): registered once, never renumbered locally.
enum class HostOpsSub : std::uint8_t {
  Submit = 0x01,
  QueryDispatch = 0x02,
  RetireThrough = 0x03,
  Skip = 0x04,
  TimeSample = 0x05,
  HostRegister = 0x10,      // H→G request: register/renew the host endpoint
  GatewayIngress = 0x11,    // G→H request: scope-2 payload for ReceiveLog
  GatewayIngressAck = 0x12, // H→G response: storage outcome for 0x11
  HostUnregister = 0x13,    // H→G request: drop the current registration
  ConfigQuery = 0x20,       // H→G request: status query -> async 0x22 reply
  ConfigPermit = 0x21,      // H→G request: permit transfer -> async 0x21 reply
  ConfigStatus = 0x22,      // G→H reply: ControlStatus for a 0x20 query
  ConfigChallenge = 0x23,   // H→G query / G→H reply: ControlChallenge exchange
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

// Typed result/outcome for the Gateway HostOps family (0x10-0x13 replies
// and the 0x12 ingress ACK outcome). Values are the design's fixed set —
// a u16 on the wire so the family can grow without colliding with
// HostOpsResult. STORAGE names "the host could not persist"; INDETERMINATE
// names "the host could not prove the outcome" — neither is a success.
enum class GatewayOpsResult : std::uint8_t {
  Ok = 0,
  Busy = 1,           // host capacity/rate exhausted: retryable
  Stale = 2,          // token/session from an old incarnation
  Denied = 3,         // authenticated but not authorized for this
  Unsupported = 4,    // capability not enabled on this device
  Invalid = 5,        // malformed or field-inconsistent request
  Storage = 6,        // ReceiveLog storage failed — never ACKed as stored
  Indeterminate = 7,  // outcome cannot be proven (e.g. torn exchange)
};

// Typed result for the Config HostOps family (0x21/0x22/0x23 replies), a
// u16 on the wire so the family can grow without colliding with the
// gateway/host_ops enums. Ok means the device proved the mesh step it was
// asked for — a query answer or an assembled permit object. It is NEVER a
// config verdict: the permit's own phase/reason is a separate status read.
// INDETERMINATE names "the outcome cannot be proven" — never a success and
// never a silent retry trigger.
enum class ConfigOpsResult : std::uint16_t {
  Ok = 0,             // answered / object assembled at the target
  Busy = 1,           // a config operation is already in flight
  Denied = 3,         // authenticated but not authorized (ACL/capability)
  Unsupported = 4,    // the config endpoint is not enabled on this device
  Invalid = 5,        // malformed request or field-inconsistent
  Indeterminate = 7,  // outcome cannot be proven (deadline, torn exchange)
  NoRoute = 8,        // no mesh route to the target
  Timeout = 9,        // the target did not answer inside the window
};

constexpr std::size_t kBootLeaseSize = 16;
constexpr std::size_t kDispatcherIdSize = 16;
constexpr std::size_t kOperationIdSize = 24;  // store lineage 16B + seq 8B
constexpr std::size_t kCanonicalHashSize = 32;

// SUBMIT inner: schema:u8, sub:u8, boot_lease:16, dispatcher:16, seq:u64,
// operation_id:24, canonical_hash:32, device_deadline:u64,
// canonical_length:u16, canonical_request. Fixed part 108B (design §6,
// contracts.json wire.usb_submit_fixed_bytes); canonical 26..154B for
// schema 1, 60..156B for schema 2 (gateway destination extension).
constexpr std::size_t kSubmitFixedSize = 108;
constexpr std::size_t kSubmitMaxSize = 264;  // 108 + 60 + 96
constexpr std::size_t kCanonicalMinSize = 26;
constexpr std::size_t kCanonicalMaxSize = 156;  // schema2: 60 + 96 payload
// Schema-2 gateway destination extension (05 §5.4): scope + reserved +
// token16 + gateway_boot8 + egress_gateway8 inserted before payload_len.
constexpr std::size_t kCanonicalGatewayFixedSize = 60;
constexpr std::size_t kCanonicalGatewayPayloadMax = 96;
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
// Schema 2 (scope-gateway-config/05-wire-api.md §5.4) is REQUIRED for
// dest_kind=1: the same 26B head with a 34B extension inserted before
// payload_len — scope:u8, reserved:u8, token:16, gateway_boot:u64,
// egress_gateway:u64 — so the fixed part is 60B and payload is ≤96B.
// A schema-1 canonical carrying dest_kind=1 is malformed, never silently
// reinterpreted.
struct CanonicalFields {
  std::uint8_t schema{1};
  std::uint32_t network{0};
  std::uint8_t dest_kind{0};  // 0 node, 1 gateway
  NodeId destination{kInvalidNodeId};  // schema2: the FINAL gateway node
  std::uint8_t delivery{0};  // 0 best-effort, 1 reliable, 2 applied
  std::uint8_t priority{0};
  std::uint8_t storage{0};
  std::uint32_t ttl_ms{0};
  std::uint8_t hop_limit{0};
  bool persist_sleep{false};
  ByteView payload{};
  // Schema-2 gateway extension (zero when schema==1 / dest_kind==0).
  std::uint8_t gateway_scope{0};  // 1 GATEWAY_SDK_RAM, 2 HOST_RECEIVE_RAM
  std::array<std::uint8_t, 16> gateway_token{};
  std::uint64_t gateway_boot{0};
  NodeId egress_gateway{kInvalidNodeId};
};

// Strict structural parse: exact 26+payload_len (schema 1) or
// 60+payload_len (schema 2) length, known enum ranges, reserved node
// addresses rejected for node destinations. Delivery / priority / persist
// values that are structurally valid but not enabled in this phase are
// REPORTED, not rejected — the caller gates them to
// HostOpsResult::Unsupported (never silently downgraded). Schema-2 range
// rules: reserved==0, scope in {1,2}, payload_len ≤96, token/gateway_boot/
// egress non-reserved; token↔registration and egress↔node binding are the
// caller's job (they need session state the parser does not have).
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
  // would lie about an end receipt that never existed. HostRamReceived is
  // the scope-2 gateway terminal: the verified Service Receipt for
  // HOST_RECEIVE_RAM — the registered host's ReceiveLog stored the payload
  // (distinct from a gateway-local SDK mailbox receipt).
  enum class Evidence : std::uint8_t {
    None = 0,
    GatewayAccepted = 1,
    MacAttemptReported = 2,
    EndSdkReceived = 3,
    HostRamReceived = 4,
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

  // Gateway sends (schema 2): the position is admitted for gateway
  // dispatch BEFORE the wire MessageKey exists — the endpoint resolve must
  // complete first. Records a Sent slot with msg_valid=false and binds the
  // lane (the position is committed to a send). bind_message fills the key
  // once gateway_->send issues it; QUERY honestly reports Sent without a
  // key while the resolve is in flight.
  bool record_pending(
      const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
      std::uint64_t dispatch_seq,
      const std::array<std::uint8_t, kCanonicalHashSize>& hash,
      const std::array<std::uint8_t, kOperationIdSize>& operation_id,
      std::uint8_t delivery) noexcept;

  // Fills the wire MessageKey on a record_pending slot once the gateway
  // submit is issued. Only a Sent slot with msg_valid=false may be bound —
  // any other state returns false (defensive).
  bool bind_message(std::uint64_t dispatch_seq, std::uint32_t msg_session,
                    std::uint64_t msg_seq) noexcept;

  // Terminal outcome for a gateway send, correlated by window position —
  // never by a message key that could collide with an unrelated slot.
  // `received` is the verified Service Receipt; `host_receive_ram` says
  // the receipt's scope was HOST_RECEIVE_RAM (host ReceiveLog storage),
  // which becomes the HostRamReceived evidence rather than
  // EndSdkReceived.
  bool note_gateway_outcome(std::uint64_t dispatch_seq, bool received,
                            bool host_receive_ram) noexcept;

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

// --- Gateway host endpoint subcommands (scope-gateway-config/05-wire-api.md
// §5.6, P3) -------------------------------------------------------------
//
// These four subcommands share a different inner common form than the
// 0x01-0x05 family: schema:u8=1, sub:u8, payload_len:u16, payload. Every
// request gets a same-sub reply carrying a u16 GatewayOpsResult first —
// except 0x12, which IS the reply to a device-issued 0x11 (the frame-level
// request id correlates them).
constexpr std::size_t kGatewayInnerHeadSize = 4;

// 0x10 HOST_REGISTER (H→G): network:u64, host_boot:u64, lease_ms:u32.
struct HostRegisterRequest {
  std::uint64_t network{0};
  std::uint64_t host_boot{0};
  std::uint32_t lease_ms{0};
};
constexpr std::size_t kHostRegisterRequestPayload = 20;

// 0x10 reply: result:u16, token:16, gateway_boot:u64, host_digest:32,
// lease_ms:u32. The token binds principal + host boot + USB session and is
// the value the schema-2 canonical carries as gateway_token.
struct HostRegisterResponse {
  std::uint16_t result{0};
  std::array<std::uint8_t, 16> token{};
  std::uint64_t gateway_boot{0};
  std::array<std::uint8_t, 32> host_digest{};
  std::uint32_t lease_ms{0};
};
constexpr std::size_t kHostRegisterResponsePayload = 62;

// 0x11 GATEWAY_INGRESS (G→H, device-issued): the canonical Service Submit
// prefix:32, the referenced MessageKey:20 (origin:u64, session:u32,
// sequence:u64), the request digest:32 (SHA-256 over prefix+payload), and
// the payload itself (0..96B). The host recomputes the digest before
// storing — a mismatched digest can never produce a success ACK.
struct GatewayIngress {
  std::array<std::uint8_t, 32> submit_prefix{};
  std::uint64_t ref_origin{0};
  std::uint32_t ref_session{0};
  std::uint64_t ref_sequence{0};
  std::array<std::uint8_t, 32> request_digest{};
  ByteView payload{};  // borrows the frame body (decode) or caller bytes
};
constexpr std::size_t kGatewayIngressFixedPayload = 84;   // 32+20+32, no payload
constexpr std::size_t kGatewayIngressMaxPayload = 180;    // +96 payload

// 0x12 GATEWAY_INGRESS_ACK (H→G): session token:16, ref MessageKey:20,
// request digest:32, outcome:u16 (GatewayOpsResult). The device verifies
// all bound fields before trusting the outcome — a wrong key/digest/token
// can never mark a record stored.
struct GatewayIngressAck {
  std::array<std::uint8_t, 16> token{};
  std::uint64_t ref_origin{0};
  std::uint32_t ref_session{0};
  std::uint64_t ref_sequence{0};
  std::array<std::uint8_t, 32> request_digest{};
  std::uint16_t outcome{0};
};
constexpr std::size_t kGatewayIngressAckPayload = 70;

// 0x13 HOST_UNREGISTER (H→G): token:16. Only the registration bound to the
// CURRENT session may be released — a stale token can never revoke the
// replacement session's endpoint.
struct HostUnregisterRequest {
  std::array<std::uint8_t, 16> token{};
};
constexpr std::size_t kHostUnregisterRequestPayload = 16;

// 0x13 reply: result:u16.
struct HostUnregisterResponse {
  std::uint16_t result{0};
};
constexpr std::size_t kHostUnregisterResponsePayload = 2;

Status decode_host_register(ByteView inner, HostRegisterRequest& out) noexcept;
Status encode_host_register_response(const HostRegisterResponse& response,
                                     MutableByteView out,
                                     std::size_t& written) noexcept;
Status encode_host_register(const HostRegisterRequest& request,
                            MutableByteView out, std::size_t& written) noexcept;
Status decode_host_register_response(ByteView inner,
                                     HostRegisterResponse& out) noexcept;

Status encode_gateway_ingress(const GatewayIngress& request,
                              MutableByteView out, std::size_t& written) noexcept;
Status decode_gateway_ingress(ByteView inner, GatewayIngress& out) noexcept;
Status encode_gateway_ingress_ack(const GatewayIngressAck& ack,
                                  MutableByteView out,
                                  std::size_t& written) noexcept;
Status decode_gateway_ingress_ack(ByteView inner, GatewayIngressAck& out) noexcept;

Status decode_host_unregister(ByteView inner, HostUnregisterRequest& out) noexcept;
Status encode_host_unregister_response(const HostUnregisterResponse& response,
                                       MutableByteView out,
                                       std::size_t& written) noexcept;
Status encode_host_unregister(const HostUnregisterRequest& request,
                              MutableByteView out, std::size_t& written) noexcept;
Status decode_host_unregister_response(ByteView inner,
                                       HostUnregisterResponse& out) noexcept;

// --- Config endpoint subcommands (scope-gateway-config/05-wire-api.md §5.6,
// P5) ---------------------------------------------------------------------
//
// These four share the gateway family's inner common form — schema:u8=1,
// sub:u8, payload_len:u16, payload — but the request/reply relationship is
// ASYNC over the mesh: the device forwards the query/transfer, then reports
// once under the same frame-level request id. 0x20's reply is the separate
// 0x22 ConfigStatus subcommand; 0x21 and 0x23 answer under their own sub.
// Every reply carries a u16 ConfigOpsResult first: Ok only means the mesh
// step was proven (a query answer or an assembled permit object) — never a
// config verdict.
//
// 0x20 CONFIG_QUERY (H→G): target:u64, config_namespace:u16, operation_id:16.
//   Async reply -> 0x22 CONFIG_STATUS.
struct ConfigQueryRequest {
  NodeId target{kInvalidNodeId};
  std::uint16_t config_namespace{0};
  std::array<std::uint8_t, 16> operation_id{};
};
constexpr std::size_t kConfigQueryRequestPayload = 26;

// 0x23 CONFIG_CHALLENGE (H→G query): target:u64, config_namespace:u16,
//   schema:u16, client_nonce:16. Async reply -> 0x23 CONFIG_CHALLENGE.
struct ConfigChallengeRequest {
  NodeId target{kInvalidNodeId};
  std::uint16_t config_namespace{0};
  std::uint16_t schema{0};
  std::array<std::uint8_t, 16> client_nonce{};
};
constexpr std::size_t kConfigChallengeRequestPayload = 28;

// 0x21 CONFIG_PERMIT (H→G): target:u64, permit bytes (1..kConfigPermitMax).
//   Async reply -> 0x21 CONFIG_PERMIT (result only, no body).
struct ConfigPermitRequest {
  NodeId target{kInvalidNodeId};
  ByteView permit{};  // borrows the decoded body (decode) or caller bytes
};
// The signed-permit object bound: matches the device ConfigPermit kind-3
// object ceiling (config_wire / autonomy object budget).
constexpr std::size_t kConfigPermitMax = 1024;

// Shared reply shape for 0x21/0x22/0x23: result:u16, target:u64, then an
// optional body — the raw ControlStatus (72 B) for a 0x22 reply or the raw
// ControlChallenge (92 B) for a 0x23 reply on Ok; empty on any failure and
// always for the 0x21 reply. The host decodes the body with the endpoint
// codec; the device forwards it verbatim.
struct ConfigReply {
  std::uint16_t result{0};  // ConfigOpsResult
  NodeId target{kInvalidNodeId};
  ByteView body{};  // 0 / 72 / 92 bytes depending on sub+result
};
constexpr std::size_t kConfigReplyFixedPayload = 10;   // result + target
constexpr std::size_t kConfigStatusBodySize = 72;      // endpoint::ControlStatus
constexpr std::size_t kConfigChallengeBodySize = 92;   // endpoint::ControlChallenge

Status decode_config_query(ByteView inner, ConfigQueryRequest& out) noexcept;
Status encode_config_query(const ConfigQueryRequest& request, MutableByteView out,
                           std::size_t& written) noexcept;
Status decode_config_challenge(ByteView inner, ConfigChallengeRequest& out) noexcept;
Status encode_config_challenge(const ConfigChallengeRequest& request,
                               MutableByteView out, std::size_t& written) noexcept;
Status decode_config_permit(ByteView inner, ConfigPermitRequest& out) noexcept;
Status encode_config_permit(const ConfigPermitRequest& request, MutableByteView out,
                            std::size_t& written) noexcept;
// `sub` must be one of ConfigPermit/ConfigStatus/ConfigChallenge; the body
// length the codec accepts is derived from it (0 for 0x21; 0-or-fixed for
// the query replies).
Status encode_config_reply(HostOpsSub sub, const ConfigReply& reply,
                           MutableByteView out, std::size_t& written) noexcept;
Status decode_config_reply(ByteView inner, HostOpsSub sub, ConfigReply& out) noexcept;

}  // namespace routeloom::usb
