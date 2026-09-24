#include "routeloom/usb_host_ops.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/telemetry.hpp"

namespace routeloom::usb {
namespace {

bool is_reserved_id(const std::uint64_t value) noexcept {
  return value == 0 || value == UINT64_MAX;
}

// Reserved identity space (01 §3: all IDs exclude 0 / all-ones). Applies to
// every byte-string identity on the lane — dispatcher, canonical_hash and
// operation_id — so a zeroed field can never collide with "unset".
template <std::size_t Size>
bool is_reserved_bytes(const std::array<std::uint8_t, Size>& id) noexcept {
  bool all_zero = true;
  bool all_max = true;
  for (const std::uint8_t byte : id) {
    if (byte != 0) all_zero = false;
    if (byte != 0xFF) all_max = false;
  }
  return all_zero || all_max;
}

Status write_id16(ByteWriter& writer,
                  const std::array<std::uint8_t, 16>& id) noexcept {
  return writer.write_bytes(ByteView{id.data(), id.size()});
}

Status read_id16(ByteReader& reader, std::array<std::uint8_t, 16>& id) noexcept {
  return reader.read_bytes(MutableByteView{id.data(), id.size()});
}

}  // namespace

BootLease BootLease::derive(const std::uint64_t boot_generation,
                            const NodeId node) noexcept {
  BootLease lease{};
  for (int i = 0; i < 8; ++i) {
    lease.bytes[static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>(boot_generation >> (56 - i * 8));
    lease.bytes[static_cast<std::size_t>(8 + i)] =
        static_cast<std::uint8_t>(node >> (56 - i * 8));
  }
  return lease;
}

bool BootLease::valid() const noexcept {
  std::uint64_t generation = 0;
  std::uint64_t node = 0;
  for (int i = 0; i < 8; ++i) {
    generation = (generation << 8U) | bytes[static_cast<std::size_t>(i)];
    node = (node << 8U) | bytes[static_cast<std::size_t>(8 + i)];
  }
  return !is_reserved_id(generation) && !is_reserved_id(node);
}

Status decode_submit(const ByteView inner, SubmitRequest& out) noexcept {
  out = SubmitRequest{};
  if (inner.size < kSubmitFixedSize || inner.size > kSubmitMaxSize) {
    return Status::error(StatusCode::ProtocolError, "SUBMIT_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub != static_cast<std::uint8_t>(HostOpsSub::Submit)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = read_id16(reader, out.dispatcher);
  if (status) status = reader.read_u64(out.dispatch_seq);
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.operation_id.data(), out.operation_id.size()});
  }
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.canonical_hash.data(), out.canonical_hash.size()});
  }
  if (status) status = reader.read_u64(out.device_deadline);
  std::uint16_t canonical_length = 0;
  if (status) status = reader.read_u16(canonical_length);
  if (!status) return status;
  // The length field must account for every remaining byte: no truncation,
  // no trailing garbage.
  if (canonical_length != reader.remaining() ||
      reader.consumed() != kSubmitFixedSize) {
    return Status::error(StatusCode::ProtocolError, "SUBMIT_LENGTH");
  }
  out.canonical = ByteView{inner.data + reader.consumed(), canonical_length};
  return Status::success();
}

Status encode_submit(const SubmitRequest& request, const MutableByteView out,
                     std::size_t& written) noexcept {
  written = 0;
  if (request.canonical.size > kCanonicalMaxSize) {
    return Status::error(StatusCode::InvalidArgument, "canonical too large");
  }
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(HostOpsSub::Submit));
  if (status) status = write_id16(writer, request.lease.bytes);
  if (status) status = write_id16(writer, request.dispatcher);
  if (status) status = writer.write_u64(request.dispatch_seq);
  if (status) {
    status = writer.write_bytes(
        ByteView{request.operation_id.data(), request.operation_id.size()});
  }
  if (status) {
    status = writer.write_bytes(
        ByteView{request.canonical_hash.data(), request.canonical_hash.size()});
  }
  if (status) status = writer.write_u64(request.device_deadline);
  if (status) {
    status = writer.write_u16(static_cast<std::uint16_t>(request.canonical.size));
  }
  if (status) status = writer.write_bytes(request.canonical);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_lane_request(const ByteView inner, const HostOpsSub sub,
                           LaneRequest& out) noexcept {
  out = LaneRequest{};
  if (inner.size != kLaneRequestSize) {
    return Status::error(StatusCode::ProtocolError, "LANE_REQUEST_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub_byte = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub_byte);
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = read_id16(reader, out.dispatcher);
  if (status) status = reader.read_u64(out.seq);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub_byte != static_cast<std::uint8_t>(sub)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  return Status::success();
}

Status encode_lane_request(const HostOpsSub sub, const LaneRequest& request,
                           const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(sub));
  if (status) status = write_id16(writer, request.lease.bytes);
  if (status) status = write_id16(writer, request.dispatcher);
  if (status) status = writer.write_u64(request.seq);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_time_sample_request(const ByteView inner,
                                  TimeSampleRequest& out) noexcept {
  out = TimeSampleRequest{};
  if (inner.size != kTimeSampleRequestSize) {
    return Status::error(StatusCode::ProtocolError, "TIME_SAMPLE_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub);
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = reader.read_u64(out.nonce);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub != static_cast<std::uint8_t>(HostOpsSub::TimeSample)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  return Status::success();
}

Status encode_time_sample_request(const TimeSampleRequest& request,
                                  const MutableByteView out,
                                  std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(HostOpsSub::TimeSample));
  if (status) status = write_id16(writer, request.lease.bytes);
  if (status) status = writer.write_u64(request.nonce);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status parse_canonical_request(const ByteView canonical,
                               CanonicalFields& out) noexcept {
  out = CanonicalFields{};
  if (canonical.size < kCanonicalMinSize || canonical.size > kCanonicalMaxSize) {
    return Status::error(StatusCode::InvalidArgument, "canonical length");
  }
  ByteReader reader(canonical);
  std::uint8_t schema = 0;
  std::uint8_t dest_kind = 0;
  std::uint8_t delivery = 0;
  std::uint8_t priority = 0;
  std::uint8_t policy = 0;
  std::uint8_t storage = 0;
  std::uint8_t hop = 0;
  std::uint8_t persist = 0;
  std::uint16_t payload_length = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u32(out.network);
  if (status) status = reader.read_u8(dest_kind);
  if (status) status = reader.read_u64(out.destination);
  if (status) status = reader.read_u8(delivery);
  if (status) status = reader.read_u8(priority);
  if (status) status = reader.read_u8(policy);
  if (status) status = reader.read_u8(storage);
  if (status) status = reader.read_u32(out.ttl_ms);
  if (status) status = reader.read_u8(hop);
  if (status) status = reader.read_u8(persist);
  if (!status) return status;
  if (schema != 1 && schema != 2) {
    return Status::error(StatusCode::InvalidArgument, "canonical schema");
  }
  // A gateway destination is only well-formed under schema 2 — the schema-1
  // shape has nowhere to carry the endpoint binding, so schema 1 +
  // dest_kind 1 is malformed, never reinterpreted (05 §5.4).
  if (dest_kind == 1 && schema != 2) {
    return Status::error(StatusCode::InvalidArgument, "gateway needs schema2");
  }
  if (schema == 2 && dest_kind != 1) {
    return Status::error(StatusCode::InvalidArgument, "schema2 needs gateway");
  }
  const std::size_t fixed_size =
      schema == 2 ? kCanonicalGatewayFixedSize : kCanonicalMinSize;
  if (schema == 2) {
    // 34B destination extension before payload_len: scope:u8, reserved:u8,
    // token:16, gateway_boot:u64, egress_gateway:u64.
    std::uint8_t reserved = 0;
    if (status) status = reader.read_u8(out.gateway_scope);
    if (status) status = reader.read_u8(reserved);
    if (status) {
      status = reader.read_bytes(
          MutableByteView{out.gateway_token.data(), out.gateway_token.size()});
    }
    if (status) status = reader.read_u64(out.gateway_boot);
    if (status) status = reader.read_u64(out.egress_gateway);
    if (!status) return status;
    if (reserved != 0 || (out.gateway_scope != 1 && out.gateway_scope != 2) ||
        is_reserved_bytes(out.gateway_token) ||
        is_reserved_id(out.gateway_boot) ||
        is_reserved_id(out.egress_gateway)) {
      return Status::error(StatusCode::InvalidArgument, "gateway ext range");
    }
  }
  if (status) status = reader.read_u16(payload_length);
  if (!status) return status;
  if (payload_length != reader.remaining() || reader.consumed() != fixed_size) {
    return Status::error(StatusCode::InvalidArgument, "canonical framing");
  }
  if (schema == 2 && payload_length > kCanonicalGatewayPayloadMax) {
    return Status::error(StatusCode::InvalidArgument, "gateway payload");
  }
  if (out.network == 0 || dest_kind > 1 || delivery > 2 || priority > 3 ||
      policy != 0 || storage > 1 || out.ttl_ms < 1 || out.ttl_ms > 30000 ||
      hop < 1 || hop > 10 || persist > 1) {
    return Status::error(StatusCode::InvalidArgument, "canonical range");
  }
  if (is_reserved_id(out.destination)) {
    return Status::error(StatusCode::InvalidArgument, "reserved destination");
  }
  out.schema = schema;
  out.dest_kind = dest_kind;
  out.delivery = delivery;
  out.priority = priority;
  out.storage = storage;
  out.hop_limit = hop;
  out.persist_sleep = persist != 0;
  out.payload = ByteView{canonical.data + reader.consumed(), payload_length};
  return Status::success();
}

std::size_t DispatchWindow::used() const noexcept {
  std::size_t count = 0;
  for (const Slot& slot : slots_) count += slot.occupied ? 1U : 0U;
  return count;
}

DispatchWindow::Slot* DispatchWindow::position(const std::uint64_t dispatch_seq) noexcept {
  // Unsigned offset: seq <= floor_ wraps huge and is rejected with the same
  // comparison — no underflow, no floor+capacity overflow.
  const std::uint64_t offset = dispatch_seq - floor_;
  if (offset == 0 || offset > kCapacity) return nullptr;
  return &slots_[(dispatch_seq - 1) % kCapacity];
}

const DispatchWindow::Slot* DispatchWindow::position(
    const std::uint64_t dispatch_seq) const noexcept {
  const std::uint64_t offset = dispatch_seq - floor_;
  if (offset == 0 || offset > kCapacity) return nullptr;
  return &slots_[(dispatch_seq - 1) % kCapacity];
}

const DispatchWindow::Slot* DispatchWindow::find(
    const std::uint64_t dispatch_seq) const noexcept {
  const Slot* slot = position(dispatch_seq);
  return (slot != nullptr && slot->occupied) ? slot : nullptr;
}

bool DispatchWindow::lane_ok(
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher) const noexcept {
  return !lane_bound_ || dispatcher == lane_dispatcher_;
}

bool DispatchWindow::bind_lane(
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher) noexcept {
  if (lane_bound_) return dispatcher == lane_dispatcher_;
  lane_dispatcher_ = dispatcher;
  lane_bound_ = true;
  return true;
}

DispatchWindow::SubmitCheck DispatchWindow::check_submit(
    const BootLease& lease,
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq,
    const std::array<std::uint8_t, kCanonicalHashSize>& hash,
    const std::array<std::uint8_t, kOperationIdSize>& operation_id) const noexcept {
  if (!lease_ok(lease)) return SubmitCheck::LeaseMismatch;
  if (is_reserved_id(dispatch_seq) || is_reserved_bytes(dispatcher) ||
      is_reserved_bytes(hash) || is_reserved_bytes(operation_id)) {
    return SubmitCheck::InvalidId;
  }
  if (!lane_ok(dispatcher)) return SubmitCheck::LaneMismatch;
  if (dispatch_seq <= floor_) return SubmitCheck::Retired;
  const Slot* slot = position(dispatch_seq);
  if (slot == nullptr) return SubmitCheck::WindowFull;
  if (!slot->occupied) return SubmitCheck::Admit;
  // A Skipped position is certified never-submitted and stores no hash:
  // ANY submit onto it is a Conflict — the zeroed slot hash must never
  // read back as a "replay" of a submitted hash.
  if (slot->state == State::Skipped) return SubmitCheck::Conflict;
  return slot->hash == hash ? SubmitCheck::Replay : SubmitCheck::Conflict;
}

bool DispatchWindow::record_sent(
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq,
    const std::array<std::uint8_t, kCanonicalHashSize>& hash,
    const std::array<std::uint8_t, kOperationIdSize>& operation_id,
    const std::uint8_t delivery, const std::uint32_t msg_session,
    const std::uint64_t msg_seq) noexcept {
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr || slot->occupied) return false;
  // The first actual send claims the lane for the boot (see the header:
  // SKIP/expired records deliberately do not bind).
  if (!bind_lane(dispatcher)) return false;
  *slot = Slot{};
  slot->occupied = true;
  slot->state = State::Sent;
  slot->delivery = delivery;
  slot->hash = hash;
  slot->operation_id = operation_id;
  slot->msg_session = msg_session;
  slot->msg_seq = msg_seq;
  slot->msg_valid = true;
  slot->evidence = Evidence::GatewayAccepted;
  return true;
}

bool DispatchWindow::record_expired(
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq,
    const std::array<std::uint8_t, kCanonicalHashSize>& hash,
    const std::array<std::uint8_t, kOperationIdSize>& operation_id,
    const std::uint8_t delivery) noexcept {
  (void)dispatcher;  // lane-checked by the caller; only record_sent binds
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr || slot->occupied) return false;
  *slot = Slot{};
  slot->occupied = true;
  slot->state = State::Expired;
  slot->delivery = delivery;
  slot->hash = hash;
  slot->operation_id = operation_id;
  slot->evidence = Evidence::None;
  return true;
}

bool DispatchWindow::record_indeterminate(
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq,
    const std::array<std::uint8_t, kCanonicalHashSize>& hash,
    const std::array<std::uint8_t, kOperationIdSize>& operation_id,
    const std::uint8_t delivery, const std::uint32_t msg_session,
    const std::uint64_t msg_seq) noexcept {
  (void)dispatcher;  // never binds: this is a degraded fallback record
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr || slot->occupied) return false;
  *slot = Slot{};
  slot->occupied = true;
  slot->state = State::Indeterminate;
  slot->delivery = delivery;
  slot->hash = hash;
  slot->operation_id = operation_id;
  slot->msg_session = msg_session;
  slot->msg_seq = msg_seq;
  slot->msg_valid = true;
  // The mesh DID accept the send; only the bookkeeping was degraded.
  slot->evidence = Evidence::GatewayAccepted;
  return true;
}

DispatchWindow::QueryOutcome DispatchWindow::query(
    const BootLease& lease,
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq, Slot& slot) const noexcept {
  slot = Slot{};
  if (!lease_ok(lease)) return QueryOutcome::LeaseMismatch;
  if (is_reserved_id(dispatch_seq) || is_reserved_bytes(dispatcher)) {
    return QueryOutcome::InvalidId;
  }
  if (!lane_ok(dispatcher)) return QueryOutcome::LaneMismatch;
  if (dispatch_seq <= floor_) return QueryOutcome::Retired;
  const Slot* found = position(dispatch_seq);
  if (found == nullptr || !found->occupied) return QueryOutcome::NotRetained;
  slot = *found;
  return QueryOutcome::Found;
}

DispatchWindow::RetireOutcome DispatchWindow::retire_through(
    const BootLease& lease,
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t through) noexcept {
  if (!lease_ok(lease)) return RetireOutcome::LeaseMismatch;
  // Reserved `through` values are refused like reserved seqs elsewhere:
  // 0 must not pass as a blessed floor no-op and UINT64_MAX must not pass
  // as a span refusal — both are InvalidRequest, not valid floor values.
  if (is_reserved_id(through)) return RetireOutcome::InvalidId;
  if (is_reserved_bytes(dispatcher)) {
    // Reserved dispatcher ids never bind a lane; without a lane the floor
    // cannot move, so even a no-op retire is refused rather than blessed.
    return RetireOutcome::LaneMismatch;
  }
  if (!lane_ok(dispatcher)) return RetireOutcome::LaneMismatch;
  if (through <= floor_) return RetireOutcome::NoopFloor;
  // The span must be fully verifiable: positions past floor_+capacity are
  // untracked, and untracked positions are never assumed terminal.
  if (through - floor_ > kCapacity) return RetireOutcome::RefusedSpan;
  for (std::uint64_t seq = floor_ + 1; seq <= through; ++seq) {
    const Slot* slot = position(seq);
    if (slot == nullptr || !slot->occupied || !is_terminal(slot->state)) {
      return RetireOutcome::RefusedSpan;
    }
    if (seq == UINT64_MAX) break;  // loop-guard: through is bounded above
  }
  // Ordering invariant (04 §4): a torn retire may only ever leave surplus
  // records — never a missing record under the OLD floor, which would let
  // the position re-admit and re-execute (a resurrected key). On a durable
  // store that means persisting the floor BEFORE deleting records. This
  // window is in-memory and single-threaded, so the delete loop and the
  // floor advance below are one indivisible update — and the host store
  // does the equivalent inside a single transaction — so no tear can ever
  // expose the dangerous intermediate state.
  for (std::uint64_t seq = floor_ + 1; seq <= through; ++seq) {
    Slot* slot = position(seq);
    if (slot != nullptr) *slot = Slot{};
    if (seq == UINT64_MAX) break;
  }
  floor_ = through;
  return RetireOutcome::Advanced;
}

DispatchWindow::SkipOutcome DispatchWindow::skip(
    const BootLease& lease,
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq) noexcept {
  if (!lease_ok(lease)) return SkipOutcome::LeaseMismatch;
  if (is_reserved_id(dispatch_seq) || is_reserved_bytes(dispatcher)) {
    return SkipOutcome::InvalidId;
  }
  if (!lane_ok(dispatcher)) return SkipOutcome::LaneMismatch;
  if (dispatch_seq <= floor_) return SkipOutcome::Retired;
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr) return SkipOutcome::WindowFull;
  if (slot->occupied) {
    return slot->state == State::Skipped ? SkipOutcome::ReplaySkipped
                                         : SkipOutcome::Occupied;
  }
  // The hole fills without binding the lane: only record_sent (the first
  // actual send) claims it, so a stray SKIP cannot lock the real
  // dispatcher out of the lane for the rest of the boot.
  *slot = Slot{};
  slot->occupied = true;
  slot->state = State::Skipped;
  return SkipOutcome::Skipped;
}

bool DispatchWindow::note_mesh_outcome(const std::uint32_t msg_session,
                                      const std::uint64_t msg_seq,
                                      const DeliveryState mesh_state) noexcept {
  for (Slot& slot : slots_) {
    if (!slot.occupied || !slot.msg_valid || slot.msg_session != msg_session ||
        slot.msg_seq != msg_seq) {
      continue;
    }
    if (slot.state == State::Sent) {
      switch (mesh_state) {
        case DeliveryState::Delivered:
          slot.state = State::Delivered;
          // Best-effort mesh "Delivered" is a finished MAC attempt, never an
          // end receipt (03 §5); the stored canonical class disambiguates.
          slot.evidence = slot.delivery == 0 ? Evidence::MacAttemptReported
                                             : Evidence::EndSdkReceived;
          break;
        case DeliveryState::Failed:
          slot.state = State::Failed;
          break;
        case DeliveryState::Expired:
          slot.state = State::Expired;
          break;
        case DeliveryState::Indeterminate:
        case DeliveryState::CancelledBeforeTx:
          // CAP-I2 never cancels; an unrequested cancellation is an unknown
          // outcome, honestly bucketed, still terminal for retirement.
          slot.state = State::Indeterminate;
          break;
        default:
          break;  // non-terminal mesh states: still Sent
      }
    }
    return true;
  }
  return false;
}

bool DispatchWindow::record_pending(
    const std::array<std::uint8_t, kDispatcherIdSize>& dispatcher,
    const std::uint64_t dispatch_seq,
    const std::array<std::uint8_t, kCanonicalHashSize>& hash,
    const std::array<std::uint8_t, kOperationIdSize>& operation_id,
    const std::uint8_t delivery) noexcept {
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr || slot->occupied) return false;
  // Committed to a gateway send: binds the lane exactly like record_sent —
  // the position will hold this dispatcher's record for the boot.
  if (!bind_lane(dispatcher)) return false;
  *slot = Slot{};
  slot->occupied = true;
  slot->state = State::Sent;
  slot->delivery = delivery;
  slot->hash = hash;
  slot->operation_id = operation_id;
  slot->msg_valid = false;  // wire key arrives via bind_message post-resolve
  slot->evidence = Evidence::GatewayAccepted;
  return true;
}

bool DispatchWindow::bind_message(const std::uint64_t dispatch_seq,
                                  const std::uint32_t msg_session,
                                  const std::uint64_t msg_seq) noexcept {
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr || !slot->occupied || slot->state != State::Sent ||
      slot->msg_valid) {
    return false;
  }
  slot->msg_session = msg_session;
  slot->msg_seq = msg_seq;
  slot->msg_valid = true;
  return true;
}

bool DispatchWindow::note_gateway_outcome(const std::uint64_t dispatch_seq,
                                          const bool received,
                                          const bool host_receive_ram) noexcept {
  Slot* slot = position(dispatch_seq);
  if (slot == nullptr || !slot->occupied) return false;
  if (slot->state == State::Sent) {
    if (received) {
      slot->state = State::Delivered;
      // Scope-2 terminal evidence names the host ReceiveLog store; scope-1
      // is the gateway's own SDK mailbox (EndSdkReceived). Neither is an
      // APPLIED claim.
      slot->evidence = host_receive_ram ? Evidence::HostRamReceived
                                        : Evidence::EndSdkReceived;
    } else {
      slot->state = State::Failed;
    }
  }
  return true;
}

namespace {

Status encode_result_state(ByteWriter& writer, HostOpsResult result,
                           DispatchWindow::State state) noexcept {
  Status status = writer.write_u8(static_cast<std::uint8_t>(result));
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(state));
  }
  return status;
}

Status decode_result_state(ByteReader& reader, HostOpsResult& result,
                           DispatchWindow::State& state) noexcept {
  std::uint8_t result_byte = 0;
  std::uint8_t state_byte = 0;
  Status status = reader.read_u8(result_byte);
  if (status) status = reader.read_u8(state_byte);
  if (!status) return status;
  if (result_byte > static_cast<std::uint8_t>(HostOpsResult::Unsupported) ||
      state_byte > static_cast<std::uint8_t>(DispatchWindow::State::Indeterminate)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  result = static_cast<HostOpsResult>(result_byte);
  state = static_cast<DispatchWindow::State>(state_byte);
  return Status::success();
}

Status decode_evidence(ByteReader& reader, DispatchWindow::Evidence& evidence) noexcept {
  std::uint8_t evidence_byte = 0;
  const Status status = reader.read_u8(evidence_byte);
  if (!status) return status;
  if (evidence_byte >
      static_cast<std::uint8_t>(DispatchWindow::Evidence::HostRamReceived)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  evidence = static_cast<DispatchWindow::Evidence>(evidence_byte);
  return Status::success();
}

Status decode_msg_valid(ByteReader& reader, bool& msg_valid) noexcept {
  std::uint8_t valid_byte = 0;
  const Status status = reader.read_u8(valid_byte);
  if (!status) return status;
  if (valid_byte > 1) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  msg_valid = valid_byte != 0;
  return Status::success();
}

}  // namespace

Status encode_receipt(const DispatchReceipt& receipt, const MutableByteView out,
                      std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(receipt.sub));
  if (status) status = encode_result_state(writer, receipt.result, receipt.state);
  if (status) status = write_id16(writer, receipt.lease.bytes);
  if (status) status = writer.write_u64(receipt.dispatch_seq);
  if (status) {
    status = writer.write_bytes(ByteView{receipt.hash.data(), receipt.hash.size()});
  }
  if (status) status = writer.write_u32(receipt.msg_session);
  if (status) status = writer.write_u64(receipt.msg_seq);
  if (status) status = writer.write_u8(receipt.msg_valid ? 1 : 0);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(receipt.evidence));
  }
  if (!status) return status;
  if (writer.size() != kReceiptSize) {
    return Status::error(StatusCode::InternalError, "receipt size drift");
  }
  written = writer.size();
  return Status::success();
}

Status decode_receipt(const ByteView inner, const HostOpsSub sub,
                      DispatchReceipt& out) noexcept {
  out = DispatchReceipt{};
  if (inner.size != kReceiptSize) {
    return Status::error(StatusCode::ProtocolError, "RECEIPT_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub_byte = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub_byte);
  if (status) status = decode_result_state(reader, out.result, out.state);
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = reader.read_u64(out.dispatch_seq);
  if (status) {
    status = reader.read_bytes(MutableByteView{out.hash.data(), out.hash.size()});
  }
  if (status) status = reader.read_u32(out.msg_session);
  if (status) status = reader.read_u64(out.msg_seq);
  if (status) status = decode_msg_valid(reader, out.msg_valid);
  if (status) status = decode_evidence(reader, out.evidence);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub_byte != static_cast<std::uint8_t>(sub)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  out.sub = sub;
  return Status::success();
}

Status encode_query_response(const QueryResponse& response, const MutableByteView out,
                             std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(HostOpsSub::QueryDispatch));
  }
  if (status) status = encode_result_state(writer, response.result, response.state);
  if (status) status = write_id16(writer, response.lease.bytes);
  if (status) status = writer.write_u64(response.dispatch_seq);
  if (status) {
    status = writer.write_bytes(ByteView{response.hash.data(), response.hash.size()});
  }
  if (status) {
    status = writer.write_bytes(
        ByteView{response.operation_id.data(), response.operation_id.size()});
  }
  if (status) status = writer.write_u32(response.msg_session);
  if (status) status = writer.write_u64(response.msg_seq);
  if (status) status = writer.write_u8(response.msg_valid ? 1 : 0);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(response.evidence));
  }
  if (!status) return status;
  if (writer.size() != kQueryResponseSize) {
    return Status::error(StatusCode::InternalError, "query response size drift");
  }
  written = writer.size();
  return Status::success();
}

Status decode_query_response(const ByteView inner, QueryResponse& out) noexcept {
  out = QueryResponse{};
  if (inner.size != kQueryResponseSize) {
    return Status::error(StatusCode::ProtocolError, "QUERY_RESPONSE_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub);
  if (status) status = decode_result_state(reader, out.result, out.state);
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = reader.read_u64(out.dispatch_seq);
  if (status) {
    status = reader.read_bytes(MutableByteView{out.hash.data(), out.hash.size()});
  }
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.operation_id.data(), out.operation_id.size()});
  }
  if (status) status = reader.read_u32(out.msg_session);
  if (status) status = reader.read_u64(out.msg_seq);
  if (status) status = decode_msg_valid(reader, out.msg_valid);
  if (status) status = decode_evidence(reader, out.evidence);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub != static_cast<std::uint8_t>(HostOpsSub::QueryDispatch)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  return Status::success();
}

Status encode_retire_response(const RetireResponse& response, const MutableByteView out,
                              std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(HostOpsSub::RetireThrough));
  }
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(response.result));
  if (status) status = write_id16(writer, response.lease.bytes);
  if (status) status = writer.write_u64(response.retired_through);
  if (!status) return status;
  if (writer.size() != kRetireResponseSize) {
    return Status::error(StatusCode::InternalError, "retire response size drift");
  }
  written = writer.size();
  return Status::success();
}

Status decode_retire_response(const ByteView inner, RetireResponse& out) noexcept {
  out = RetireResponse{};
  if (inner.size != kRetireResponseSize) {
    return Status::error(StatusCode::ProtocolError, "RETIRE_RESPONSE_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub = 0;
  std::uint8_t result_byte = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub);
  if (status) status = reader.read_u8(result_byte);
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = reader.read_u64(out.retired_through);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub != static_cast<std::uint8_t>(HostOpsSub::RetireThrough)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  if (result_byte > static_cast<std::uint8_t>(HostOpsResult::Unsupported)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  out.result = static_cast<HostOpsResult>(result_byte);
  return Status::success();
}

Status encode_time_sample_response(const TimeSampleResponse& response,
                                   const MutableByteView out,
                                   std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(HostOpsSub::TimeSample));
  }
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(response.result));
  if (status) status = write_id16(writer, response.lease.bytes);
  if (status) status = writer.write_u64(response.nonce);
  if (status) status = writer.write_u64(response.device_time);
  if (!status) return status;
  if (writer.size() != kTimeSampleResponseSize) {
    return Status::error(StatusCode::InternalError, "time sample size drift");
  }
  written = writer.size();
  return Status::success();
}

Status decode_time_sample_response(const ByteView inner,
                                   TimeSampleResponse& out) noexcept {
  out = TimeSampleResponse{};
  if (inner.size != kTimeSampleResponseSize) {
    return Status::error(StatusCode::ProtocolError, "TIME_SAMPLE_RESPONSE_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub = 0;
  std::uint8_t result_byte = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub);
  if (status) status = reader.read_u8(result_byte);
  if (status) status = read_id16(reader, out.lease.bytes);
  if (status) status = reader.read_u64(out.nonce);
  if (status) status = reader.read_u64(out.device_time);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub != static_cast<std::uint8_t>(HostOpsSub::TimeSample)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  if (result_byte > static_cast<std::uint8_t>(HostOpsResult::Unsupported)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  out.result = static_cast<HostOpsResult>(result_byte);
  return Status::success();
}

// --- Gateway host endpoint subcommands (05-wire-api.md §5.6) --------------
//
// Inner common form for the 0x10-0x13 family: schema:u8=1, sub:u8,
// payload_len:u16, payload. `gateway_head` writes the 4B head; the caller
// appends the fixed-layout payload. `gateway_body` validates head + exact
// payload_len and hands the payload span to the caller.
namespace {

Status write_gateway_head(ByteWriter& writer, const HostOpsSub sub,
                          const std::uint16_t payload_len) noexcept {
  Status status = writer.write_u8(kHostOpsSchema);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(sub));
  if (status) status = writer.write_u16(payload_len);
  return status;
}

// Validates schema/sub/payload_len and returns the payload span. Exact
// length only — the 0x10-0x13 family never accepts a trailing byte.
Status gateway_body(const ByteView inner, const HostOpsSub sub,
                    const std::size_t min_payload, const std::size_t max_payload,
                    ByteView& payload) noexcept {
  payload = ByteView{};
  if (inner.size < kGatewayInnerHeadSize ||
      inner.size > kGatewayInnerHeadSize + max_payload) {
    return Status::error(StatusCode::ProtocolError, "GATEWAY_OPS_LENGTH");
  }
  ByteReader reader(inner);
  std::uint8_t schema = 0;
  std::uint8_t sub_byte = 0;
  std::uint16_t payload_len = 0;
  Status status = reader.read_u8(schema);
  if (status) status = reader.read_u8(sub_byte);
  if (status) status = reader.read_u16(payload_len);
  if (!status) return status;
  if (schema != kHostOpsSchema) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_SCHEMA");
  }
  if (sub_byte != static_cast<std::uint8_t>(sub)) {
    return Status::error(StatusCode::ProtocolError, "SUBCOMMAND_MISMATCH");
  }
  if (payload_len != reader.remaining() || payload_len < min_payload ||
      payload_len > max_payload) {
    return Status::error(StatusCode::ProtocolError, "GATEWAY_OPS_LENGTH");
  }
  payload = ByteView{inner.data + reader.consumed(), payload_len};
  return Status::success();
}

bool gateway_result_valid(const std::uint16_t result) noexcept {
  return result <= static_cast<std::uint16_t>(GatewayOpsResult::Indeterminate);
}

}  // namespace

Status decode_host_register(const ByteView inner, HostRegisterRequest& out) noexcept {
  out = HostRegisterRequest{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::HostRegister, kHostRegisterRequestPayload,
                   kHostRegisterRequestPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.network);
  if (read) read = reader.read_u64(out.host_boot);
  if (read) read = reader.read_u32(out.lease_ms);
  return read;
}

Status encode_host_register(const HostRegisterRequest& request,
                            const MutableByteView out,
                            std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status =
      write_gateway_head(writer, HostOpsSub::HostRegister, kHostRegisterRequestPayload);
  if (status) status = writer.write_u64(request.network);
  if (status) status = writer.write_u64(request.host_boot);
  if (status) status = writer.write_u32(request.lease_ms);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status encode_host_register_response(const HostRegisterResponse& response,
                                     const MutableByteView out,
                                     std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::HostRegister,
                                     kHostRegisterResponsePayload);
  if (status) status = writer.write_u16(response.result);
  if (status) {
    status = writer.write_bytes(
        ByteView{response.token.data(), response.token.size()});
  }
  if (status) status = writer.write_u64(response.gateway_boot);
  if (status) {
    status = writer.write_bytes(
        ByteView{response.host_digest.data(), response.host_digest.size()});
  }
  if (status) status = writer.write_u32(response.lease_ms);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_host_register_response(const ByteView inner,
                                     HostRegisterResponse& out) noexcept {
  out = HostRegisterResponse{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::HostRegister, kHostRegisterResponsePayload,
                   kHostRegisterResponsePayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u16(out.result);
  if (read) {
    read = reader.read_bytes(MutableByteView{out.token.data(), out.token.size()});
  }
  if (read) read = reader.read_u64(out.gateway_boot);
  if (read) {
    read = reader.read_bytes(
        MutableByteView{out.host_digest.data(), out.host_digest.size()});
  }
  if (read) read = reader.read_u32(out.lease_ms);
  if (!read) return read;
  if (!gateway_result_valid(out.result)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  return Status::success();
}

Status encode_gateway_ingress(const GatewayIngress& request,
                              const MutableByteView out,
                              std::size_t& written) noexcept {
  written = 0;
  if (request.payload.size > kCanonicalGatewayPayloadMax) {
    return Status::error(StatusCode::InvalidArgument, "gateway payload");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::GatewayIngress,
      static_cast<std::uint16_t>(kGatewayIngressFixedPayload +
                                 request.payload.size));
  if (status) {
    status = writer.write_bytes(
        ByteView{request.submit_prefix.data(), request.submit_prefix.size()});
  }
  if (status) status = writer.write_u64(request.ref_origin);
  if (status) status = writer.write_u32(request.ref_session);
  if (status) status = writer.write_u64(request.ref_sequence);
  if (status) {
    status = writer.write_bytes(ByteView{request.request_digest.data(),
                                         request.request_digest.size()});
  }
  if (status) status = writer.write_bytes(request.payload);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_gateway_ingress(const ByteView inner, GatewayIngress& out) noexcept {
  out = GatewayIngress{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::GatewayIngress, kGatewayIngressFixedPayload,
                   kGatewayIngressMaxPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_bytes(
      MutableByteView{out.submit_prefix.data(), out.submit_prefix.size()});
  if (read) read = reader.read_u64(out.ref_origin);
  if (read) read = reader.read_u32(out.ref_session);
  if (read) read = reader.read_u64(out.ref_sequence);
  if (read) {
    read = reader.read_bytes(MutableByteView{out.request_digest.data(),
                                             out.request_digest.size()});
  }
  if (!read) return read;
  out.payload = ByteView{payload.data + reader.consumed(), reader.remaining()};
  return Status::success();
}

Status encode_gateway_ingress_ack(const GatewayIngressAck& ack,
                                  const MutableByteView out,
                                  std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::GatewayIngressAck,
                                     kGatewayIngressAckPayload);
  if (status) {
    status = writer.write_bytes(ByteView{ack.token.data(), ack.token.size()});
  }
  if (status) status = writer.write_u64(ack.ref_origin);
  if (status) status = writer.write_u32(ack.ref_session);
  if (status) status = writer.write_u64(ack.ref_sequence);
  if (status) {
    status = writer.write_bytes(
        ByteView{ack.request_digest.data(), ack.request_digest.size()});
  }
  if (status) status = writer.write_u16(ack.outcome);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_gateway_ingress_ack(const ByteView inner,
                                  GatewayIngressAck& out) noexcept {
  out = GatewayIngressAck{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::GatewayIngressAck, kGatewayIngressAckPayload,
                   kGatewayIngressAckPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read =
      reader.read_bytes(MutableByteView{out.token.data(), out.token.size()});
  if (read) read = reader.read_u64(out.ref_origin);
  if (read) read = reader.read_u32(out.ref_session);
  if (read) read = reader.read_u64(out.ref_sequence);
  if (read) {
    read = reader.read_bytes(MutableByteView{out.request_digest.data(),
                                             out.request_digest.size()});
  }
  if (read) read = reader.read_u16(out.outcome);
  if (!read) return read;
  if (!gateway_result_valid(out.outcome)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  return Status::success();
}

Status decode_host_unregister(const ByteView inner,
                              HostUnregisterRequest& out) noexcept {
  out = HostUnregisterRequest{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::HostUnregister,
                   kHostUnregisterRequestPayload, kHostUnregisterRequestPayload,
                   payload);
  if (!status) return status;
  ByteReader reader(payload);
  return reader.read_bytes(MutableByteView{out.token.data(), out.token.size()});
}

Status encode_host_unregister(const HostUnregisterRequest& request,
                              const MutableByteView out,
                              std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::HostUnregister,
                                     kHostUnregisterRequestPayload);
  if (status) {
    status = writer.write_bytes(
        ByteView{request.token.data(), request.token.size()});
  }
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status encode_host_unregister_response(const HostUnregisterResponse& response,
                                       const MutableByteView out,
                                       std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::HostUnregister,
                                     kHostUnregisterResponsePayload);
  if (status) status = writer.write_u16(response.result);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_host_unregister_response(const ByteView inner,
                                       HostUnregisterResponse& out) noexcept {
  out = HostUnregisterResponse{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::HostUnregister,
                   kHostUnregisterResponsePayload, kHostUnregisterResponsePayload,
                   payload);
  if (!status) return status;
  ByteReader reader(payload);
  const Status read = reader.read_u16(out.result);
  if (!read) return read;
  if (!gateway_result_valid(out.result)) {
    return Status::error(StatusCode::ProtocolError, "HOST_OPS_ENUM");
  }
  return Status::success();
}

// --- Config endpoint subcommands (0x20-0x27) --------------------------------
namespace {

bool config_result_valid(const std::uint16_t result) noexcept {
  switch (static_cast<ConfigOpsResult>(result)) {
    case ConfigOpsResult::Ok:
    case ConfigOpsResult::Busy:
    case ConfigOpsResult::Denied:
    case ConfigOpsResult::Unsupported:
    case ConfigOpsResult::Invalid:
    case ConfigOpsResult::Indeterminate:
    case ConfigOpsResult::NoRoute:
    case ConfigOpsResult::Timeout:
      return true;
  }
  return false;
}

// The body length a config reply may carry, by subcommand. The object
// replies are result-only; the query replies carry the fixed endpoint
// body on Ok and none on failure — so {0, N} is the legal set.
bool config_reply_body_valid(const HostOpsSub sub, const std::size_t body_size) noexcept {
  switch (sub) {
    case HostOpsSub::ConfigPermit:
    case HostOpsSub::ConfigRecover:
    case HostOpsSub::ConfigTrust:
      return body_size == 0;
    case HostOpsSub::ConfigStatus:
      return body_size == 0 || body_size == kConfigStatusBodySize;
    case HostOpsSub::ConfigChallenge:
      return body_size == 0 || body_size == kConfigChallengeBodySize;
    case HostOpsSub::TrustStatus:
      return body_size == 0 || body_size == kTrustStatusBodySize;
    case HostOpsSub::RecoveryInfo:
      return body_size == 0 || body_size == kRecoveryInfoBodySize;
    default:
      return false;
  }
}

}  // namespace

Status decode_config_query(const ByteView inner, ConfigQueryRequest& out) noexcept {
  out = ConfigQueryRequest{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::ConfigQuery, kConfigQueryRequestPayload,
                   kConfigQueryRequestPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (read) read = reader.read_u16(out.config_namespace);
  if (read) {
    read = reader.read_bytes(
        MutableByteView{out.operation_id.data(), out.operation_id.size()});
  }
  return read;
}

Status encode_config_query(const ConfigQueryRequest& request,
                           const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::ConfigQuery,
                                     kConfigQueryRequestPayload);
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_u16(request.config_namespace);
  if (status) {
    status = writer.write_bytes(
        ByteView{request.operation_id.data(), request.operation_id.size()});
  }
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_config_challenge(const ByteView inner,
                               ConfigChallengeRequest& out) noexcept {
  out = ConfigChallengeRequest{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::ConfigChallenge,
                   kConfigChallengeRequestPayload, kConfigChallengeRequestPayload,
                   payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (read) read = reader.read_u16(out.config_namespace);
  if (read) read = reader.read_u16(out.schema);
  if (read) {
    read = reader.read_bytes(
        MutableByteView{out.client_nonce.data(), out.client_nonce.size()});
  }
  return read;
}

Status encode_config_challenge(const ConfigChallengeRequest& request,
                               const MutableByteView out,
                               std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::ConfigChallenge,
                                     kConfigChallengeRequestPayload);
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_u16(request.config_namespace);
  if (status) status = writer.write_u16(request.schema);
  if (status) {
    status = writer.write_bytes(
        ByteView{request.client_nonce.data(), request.client_nonce.size()});
  }
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_config_permit(const ByteView inner, ConfigPermitRequest& out) noexcept {
  out = ConfigPermitRequest{};
  ByteView payload{};
  // target:u64 (8) + permit (1..kConfigPermitMax).
  const Status status =
      gateway_body(inner, HostOpsSub::ConfigPermit, 8 + 1, 8 + kConfigPermitMax,
                   payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (!read) return read;
  out.permit = ByteView{payload.data + reader.consumed(), reader.remaining()};
  return Status::success();
}

Status encode_config_permit(const ConfigPermitRequest& request,
                            const MutableByteView out,
                            std::size_t& written) noexcept {
  written = 0;
  if (request.permit.size == 0 || request.permit.size > kConfigPermitMax) {
    return Status::error(StatusCode::InvalidArgument, "config permit size");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::ConfigPermit,
      static_cast<std::uint16_t>(8 + request.permit.size));
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_bytes(request.permit);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_config_recover(const ByteView inner,
                             ConfigRecoverRequest& out) noexcept {
  out = ConfigRecoverRequest{};
  ByteView payload{};
  // Same layout as 0x21: target:u64 (8) + object (1..kConfigPermitMax).
  const Status status =
      gateway_body(inner, HostOpsSub::ConfigRecover, 8 + 1, 8 + kConfigPermitMax,
                   payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (!read) return read;
  out.object = ByteView{payload.data + reader.consumed(), reader.remaining()};
  return Status::success();
}

Status encode_config_recover(const ConfigRecoverRequest& request,
                             const MutableByteView out,
                             std::size_t& written) noexcept {
  written = 0;
  if (request.object.size == 0 || request.object.size > kConfigPermitMax) {
    return Status::error(StatusCode::InvalidArgument, "config recover size");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::ConfigRecover,
      static_cast<std::uint16_t>(8 + request.object.size));
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_bytes(request.object);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_config_trust(const ByteView inner, ConfigTrustRequest& out) noexcept {
  out = ConfigTrustRequest{};
  ByteView payload{};
  // Same layout as 0x21/0x24, at the kind-5 ceiling: target:u64 (8) +
  // object (1..kConfigTrustMax).
  const Status status =
      gateway_body(inner, HostOpsSub::ConfigTrust, 8 + 1, 8 + kConfigTrustMax,
                   payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (!read) return read;
  out.object = ByteView{payload.data + reader.consumed(), reader.remaining()};
  return Status::success();
}

Status encode_config_trust(const ConfigTrustRequest& request,
                           const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  if (request.object.size == 0 || request.object.size > kConfigTrustMax) {
    return Status::error(StatusCode::InvalidArgument, "config trust size");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::ConfigTrust,
      static_cast<std::uint16_t>(8 + request.object.size));
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_bytes(request.object);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_trust_status(const ByteView inner, TrustStatusRequest& out) noexcept {
  out = TrustStatusRequest{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::TrustStatus, kTrustStatusRequestPayload,
                   kTrustStatusRequestPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (read) read = reader.read_u64(out.network);
  if (read) {
    read = reader.read_bytes(
        MutableByteView{out.nonce.data(), out.nonce.size()});
  }
  return read;
}

Status encode_trust_status(const TrustStatusRequest& request,
                           const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::TrustStatus,
                                     kTrustStatusRequestPayload);
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_u64(request.network);
  if (status) {
    status = writer.write_bytes(
        ByteView{request.nonce.data(), request.nonce.size()});
  }
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_recovery_info(const ByteView inner, RecoveryInfoRequest& out) noexcept {
  out = RecoveryInfoRequest{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, HostOpsSub::RecoveryInfo, kRecoveryInfoRequestPayload,
                   kRecoveryInfoRequestPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.target);
  if (read) read = reader.read_u64(out.network);
  if (read) read = reader.read_u16(out.config_namespace);
  if (read) {
    read = reader.read_bytes(
        MutableByteView{out.nonce.data(), out.nonce.size()});
  }
  return read;
}

Status encode_recovery_info(const RecoveryInfoRequest& request,
                            const MutableByteView out,
                            std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::RecoveryInfo,
                                     kRecoveryInfoRequestPayload);
  if (status) status = writer.write_u64(request.target);
  if (status) status = writer.write_u64(request.network);
  if (status) status = writer.write_u16(request.config_namespace);
  if (status) {
    status = writer.write_bytes(
        ByteView{request.nonce.data(), request.nonce.size()});
  }
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status encode_config_reply(const HostOpsSub sub, const ConfigReply& reply,
                           const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  if (!config_reply_body_valid(sub, reply.body.size) ||
      !config_result_valid(reply.result)) {
    return Status::error(StatusCode::InvalidArgument, "config reply invalid");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, sub,
      static_cast<std::uint16_t>(kConfigReplyFixedPayload + reply.body.size));
  if (status) status = writer.write_u16(reply.result);
  if (status) status = writer.write_u64(reply.target);
  if (status) status = writer.write_bytes(reply.body);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_config_reply(const ByteView inner, const HostOpsSub sub,
                           ConfigReply& out) noexcept {
  out = ConfigReply{};
  ByteView payload{};
  const Status status =
      gateway_body(inner, sub, kConfigReplyFixedPayload,
                   kConfigReplyFixedPayload + kConfigChallengeBodySize, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u16(out.result);
  if (read) read = reader.read_u64(out.target);
  if (!read) return read;
  out.body = ByteView{payload.data + reader.consumed(), reader.remaining()};
  if (!config_result_valid(out.result) ||
      !config_reply_body_valid(sub, out.body.size)) {
    return Status::error(StatusCode::ProtocolError, "CONFIG_REPLY_INVALID");
  }
  return Status::success();
}

Status decode_diagnostic_request(const ByteView inner,
                                 DiagnosticRequestView& out) noexcept {
  out = DiagnosticRequestView{};
  ByteView payload{};
  // Body sizes are subtype-defined (4B prefix .. 24B TelemetryQuery); the
  // diagnostic codec itself rejects anything else — here we only bound the
  // tunnel to a single 24-byte query body.
  const Status status = gateway_body(
      inner, HostOpsSub::DiagnosticRequest,
      kDiagnosticRequestFixed + kDiagnosticPrefixSize,
      kDiagnosticRequestFixed + kTelemetryQueryBodySize, payload);
  if (!status) return status;
  ByteReader reader(payload);
  Status read = reader.read_u64(out.observer);
  if (read) {
    out.body = ByteView{payload.data + kDiagnosticRequestFixed,
                        payload.size - kDiagnosticRequestFixed};
  }
  return read;
}

Status encode_diagnostic_reply(const std::uint16_t result,
                               const NodeId observer, const ByteView body,
                               const MutableByteView out,
                               std::size_t& written) noexcept {
  written = 0;
  if (body.size > kDiagnosticReplyMaxBody) {
    return Status::error(StatusCode::InvalidArgument, "diag reply oversized");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::DiagnosticResponse,
      static_cast<std::uint16_t>(kDiagnosticReplyFixed + body.size));
  if (status) status = writer.write_u16(result);
  if (status) status = writer.write_u64(observer);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(body.size));
  if (status) status = writer.write_bytes(body);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

// --- NodeStatus family (0x40-0x42) -----------------------------------------

namespace {

bool node_event_kind_valid(const std::uint8_t kind) noexcept {
  return kind >= static_cast<std::uint8_t>(NodeEventKind::NeighborUp) &&
         kind <= static_cast<std::uint8_t>(NodeEventKind::RouteChanged);
}

Status read_entry(ByteReader& reader, NodeStatus& out) noexcept {
  out = NodeStatus{};
  std::uint8_t rssi = 0;
  std::uint16_t ewma = 0;
  Status status = reader.read_u64(out.node);
  if (status) status = reader.read_u8(out.flags);
  if (status) status = reader.read_u8(rssi);
  if (status) status = reader.read_u16(ewma);
  if (status) status = reader.read_u16(out.link_cost);
  if (status) status = reader.read_u16(out.route_metric);
  if (status) status = reader.read_u64(out.next_hop);
  if (status) status = reader.read_u32(out.heard_age_ms);
  if (!status) return status;
  out.rssi_last_dbm = static_cast<std::int8_t>(rssi);
  out.rssi_ewma_q8_8 = static_cast<std::int16_t>(ewma);
  // Structural invariants: a listable id, no reserved flag bit, and the
  // route fields agree with the reachability bit (an unreachable node has
  // no next hop; a reachable one has a real one).
  if (is_reserved_id(out.node) || (out.flags & ~kNodeStatusFlagsMask) != 0) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_ENTRY");
  }
  const bool reachable = (out.flags & kNodeStatusReachable) != 0;
  if (reachable == is_reserved_id(out.next_hop)) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_ENTRY");
  }
  if (!reachable && (out.flags & kNodeStatusDirect) != 0) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_ENTRY");
  }
  return Status::success();
}

Status write_entry(ByteWriter& writer, const NodeStatus& status) noexcept {
  Status result = writer.write_u64(status.node);
  if (result) result = writer.write_u8(status.flags);
  if (result) result = writer.write_u8(static_cast<std::uint8_t>(status.rssi_last_dbm));
  if (result) result = writer.write_u16(static_cast<std::uint16_t>(status.rssi_ewma_q8_8));
  if (result) result = writer.write_u16(status.link_cost);
  if (result) result = writer.write_u16(status.route_metric);
  if (result) result = writer.write_u64(status.reachable() ? status.next_hop : kInvalidNodeId);
  if (result) result = writer.write_u32(status.heard_age_ms);
  return result;
}

}  // namespace

Status encode_node_status_query(const NodeStatusQuery& query, const MutableByteView out,
                                std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::NodeStatusQuery,
                                     static_cast<std::uint16_t>(kNodeStatusQueryPayload));
  if (status) status = writer.write_u64(query.after);
  if (status) status = writer.write_u8(query.max_entries);
  if (status) status = writer.write_u8(query.flags);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_node_status_query(const ByteView inner, NodeStatusQuery& out) noexcept {
  out = NodeStatusQuery{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::NodeStatusQuery, kNodeStatusQueryPayload,
                               kNodeStatusQueryPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  status = reader.read_u64(out.after);
  if (status) status = reader.read_u8(out.max_entries);
  if (status) status = reader.read_u8(out.flags);
  if (!status) return status;
  // `after` may be 0 (start) but never the broadcast/all-ones id; the page
  // size is bounded by the device's fixed page buffer.
  if (out.after == UINT64_MAX || out.max_entries == 0 ||
      out.max_entries > kNodeStatusPageMax ||
      (out.flags & ~kNodeStatusQuerySubscribe) != 0) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_QUERY");
  }
  return Status::success();
}

Status encode_node_status_entry(const NodeStatus& status, const MutableByteView out) noexcept {
  if (out.size < kNodeStatusEntrySize) {
    return Status::error(StatusCode::InvalidArgument, "entry buffer");
  }
  ByteWriter writer(MutableByteView{out.data, kNodeStatusEntrySize});
  return write_entry(writer, status);
}

Status decode_node_status_entry(const ByteView entry, NodeStatus& out) noexcept {
  if (entry.size != kNodeStatusEntrySize) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_ENTRY");
  }
  ByteReader reader(entry);
  return read_entry(reader, out);
}

Status encode_node_status_page(const NodeStatusPageHeader& header,
                               const NodeStatus* const entries, const std::size_t count,
                               const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (count > kNodeStatusPageMax || header.count != count ||
      (count > 0 && entries == nullptr) ||
      (header.flags & ~(kNodeStatusPageMore | kNodeStatusPageArmed)) != 0 ||
      !config_result_valid(header.result) ||
      (header.result != static_cast<std::uint16_t>(ConfigOpsResult::Ok) && count != 0)) {
    return Status::error(StatusCode::InvalidArgument, "node status page");
  }
  for (std::size_t i = 1; i < count; ++i) {
    if (entries[i].node <= entries[i - 1].node) {
      return Status::error(StatusCode::InvalidArgument, "node status page order");
    }
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::NodeStatusPage,
      static_cast<std::uint16_t>(kNodeStatusPageFixed + count * kNodeStatusEntrySize));
  if (status) status = writer.write_u16(header.result);
  if (status) status = writer.write_u8(header.flags);
  if (status) status = writer.write_u8(header.count);
  if (status) status = writer.write_u64(header.next_after);
  if (status) status = writer.write_u32(header.event_seq);
  for (std::size_t i = 0; status && i < count; ++i) status = write_entry(writer, entries[i]);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_node_status_page(const ByteView inner, NodeStatusPageHeader& header,
                               ByteView& entries) noexcept {
  header = NodeStatusPageHeader{};
  entries = ByteView{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::NodeStatusPage, kNodeStatusPageFixed,
                               kNodeStatusPageMaxPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  status = reader.read_u16(header.result);
  if (status) status = reader.read_u8(header.flags);
  if (status) status = reader.read_u8(header.count);
  if (status) status = reader.read_u64(header.next_after);
  if (status) status = reader.read_u32(header.event_seq);
  if (!status) return status;
  if (!config_result_valid(header.result) ||
      (header.flags & ~(kNodeStatusPageMore | kNodeStatusPageArmed)) != 0 ||
      header.count > kNodeStatusPageMax ||
      reader.remaining() != header.count * kNodeStatusEntrySize ||
      (header.result != static_cast<std::uint16_t>(ConfigOpsResult::Ok) &&
       header.count != 0)) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_PAGE");
  }
  NodeId previous = kInvalidNodeId;
  for (std::size_t i = 0; i < header.count; ++i) {
    NodeStatus entry{};
    status = read_entry(reader, entry);
    if (!status) return status;
    if (i > 0 && entry.node <= previous) {
      return Status::error(StatusCode::ProtocolError, "NODE_STATUS_ORDER");
    }
    previous = entry.node;
  }
  if (header.count > 0 && header.next_after != previous) {
    return Status::error(StatusCode::ProtocolError, "NODE_STATUS_CURSOR");
  }
  entries = ByteView{payload.data + kNodeStatusPageFixed,
                     header.count * kNodeStatusEntrySize};
  return Status::success();
}

Status encode_node_event(const NodeEvent& event, const MutableByteView out,
                         std::size_t& written) noexcept {
  written = 0;
  if (event.sequence == 0 ||
      !node_event_kind_valid(static_cast<std::uint8_t>(event.kind))) {
    return Status::error(StatusCode::InvalidArgument, "node event");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::NodeEvent,
                                     static_cast<std::uint16_t>(kNodeEventPayload));
  if (status) status = writer.write_u32(event.sequence);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(event.kind));
  if (status) status = writer.write_u8(0);
  if (status) status = write_entry(writer, event.status);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_node_event(const ByteView inner, NodeEvent& out) noexcept {
  out = NodeEvent{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::NodeEvent, kNodeEventPayload,
                               kNodeEventPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  std::uint8_t kind = 0;
  std::uint8_t reserved = 0;
  status = reader.read_u32(out.sequence);
  if (status) status = reader.read_u8(kind);
  if (status) status = reader.read_u8(reserved);
  if (status) status = read_entry(reader, out.status);
  if (!status) return status;
  if (out.sequence == 0 || !node_event_kind_valid(kind) || reserved != 0) {
    return Status::error(StatusCode::ProtocolError, "NODE_EVENT");
  }
  out.kind = static_cast<NodeEventKind>(kind);
  return Status::success();
}

// --- Group family (0x50-0x52) ----------------------------------------------

namespace {

bool group_reason_valid(const char* const reason, const std::size_t size) noexcept {
  for (std::size_t i = 0; i < size; ++i) {
    const auto c = static_cast<unsigned char>(reason[i]);
    if (c < 0x20 || c > 0x7E) return false;
  }
  return true;
}

bool group_missing_id_valid(const NodeId id) noexcept {
  return !is_reserved_id(id) && !reserved_node_id(id);
}

// Structural consistency shared by the encoder and the decoder: a refusal
// names no message and counts nothing; an answer names a group message.
Status check_group_status(const GroupStatusReply& reply) noexcept {
  const bool ok = reply.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok);
  const auto state = static_cast<std::uint8_t>(reply.state);
  if (!config_result_valid(reply.result) ||
      state > static_cast<std::uint8_t>(DeliveryState::Indeterminate) ||
      reply.missing_count > kGroupReportMissingMax ||
      reply.missing_count > reply.missing_total ||
      reply.reason_len > kGroupStatusReasonMax ||
      !group_reason_valid(reply.reason.data(), reply.reason_len)) {
    return Status::error(StatusCode::ProtocolError, "GROUP_STATUS");
  }
  if (!ok && (reply.id.session != 0 || reply.id.sequence != 0 ||
              reply.state != DeliveryState::Empty || reply.rounds != 0 ||
              reply.delivered != 0 || reply.nonmember != 0 ||
              reply.missing_total != 0 || reply.unaccounted != 0)) {
    return Status::error(StatusCode::ProtocolError, "GROUP_STATUS_REFUSAL");
  }
  if (ok && !is_group_sequence(reply.id.sequence)) {
    return Status::error(StatusCode::ProtocolError, "GROUP_STATUS_ID");
  }
  for (std::size_t i = 0; i < reply.missing_count; ++i) {
    if (!group_missing_id_valid(reply.missing[i])) {
      return Status::error(StatusCode::ProtocolError, "GROUP_STATUS_MISSING");
    }
  }
  return Status::success();
}

std::uint8_t group_status_flags(const GroupStatusReply& reply) noexcept {
  return static_cast<std::uint8_t>(
      (reply.missing_total > reply.missing_count ? kGroupStatusTruncated : 0U) |
      (group_state_final(reply.state) ? kGroupStatusFinal : 0U));
}

}  // namespace

bool group_state_final(const DeliveryState state) noexcept {
  switch (state) {
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::CancelledBeforeTx:
    case DeliveryState::Indeterminate:
      return true;
    default:
      return false;
  }
}

Status encode_group_send(const GroupSendRequest& request, const MutableByteView out,
                         std::size_t& written) noexcept {
  written = 0;
  if (request.group == 0 ||
      static_cast<std::uint8_t>(request.priority) >
          static_cast<std::uint8_t>(Priority::Urgent) ||
      (request.flags & ~kGroupSendOrdered) != 0 || request.lifetime_ms == 0 ||
      request.lifetime_ms > kMaxMessageLifetimeMs || request.hop_limit == 0 ||
      request.hop_limit == UINT8_MAX || request.data.size > kGroupPayloadMax ||
      (request.data.size > 0 && request.data.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "group send");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::GroupSend,
      static_cast<std::uint16_t>(kGroupSendFixedPayload + request.data.size));
  if (status) status = writer.write_u16(request.group);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(request.priority));
  if (status) status = writer.write_u8(request.flags);
  if (status) status = writer.write_u32(request.lifetime_ms);
  if (status) status = writer.write_u8(request.hop_limit);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(request.data.size));
  if (status && request.data.size > 0) status = writer.write_bytes(request.data);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_group_send(const ByteView inner, GroupSendRequest& out) noexcept {
  out = GroupSendRequest{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::GroupSend, kGroupSendFixedPayload,
                               kGroupSendMaxPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  std::uint8_t priority = 0;
  std::uint8_t reserved = 0;
  std::uint16_t data_len = 0;
  status = reader.read_u16(out.group);
  if (status) status = reader.read_u8(priority);
  if (status) status = reader.read_u8(out.flags);
  if (status) status = reader.read_u32(out.lifetime_ms);
  if (status) status = reader.read_u8(out.hop_limit);
  if (status) status = reader.read_u8(reserved);
  if (status) status = reader.read_u16(data_len);
  if (!status) return status;
  if (out.group == 0 || priority > static_cast<std::uint8_t>(Priority::Urgent) ||
      (out.flags & ~kGroupSendOrdered) != 0 || out.lifetime_ms == 0 ||
      out.lifetime_ms > kMaxMessageLifetimeMs || out.hop_limit == 0 ||
      out.hop_limit == UINT8_MAX || reserved != 0 || data_len != reader.remaining() ||
      data_len > kGroupPayloadMax) {
    return Status::error(StatusCode::ProtocolError, "GROUP_SEND");
  }
  out.priority = static_cast<Priority>(priority);
  out.data = ByteView{payload.data + kGroupSendFixedPayload, data_len};
  return Status::success();
}

Status encode_group_query(const GroupQueryRequest& request, const MutableByteView out,
                          std::size_t& written) noexcept {
  written = 0;
  if (!is_group_sequence(request.id.sequence)) {
    return Status::error(StatusCode::InvalidArgument, "group query");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::GroupQuery,
                                     static_cast<std::uint16_t>(kGroupQueryPayload));
  if (status) status = writer.write_u32(request.id.session);
  if (status) status = writer.write_u64(request.id.sequence);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_group_query(const ByteView inner, GroupQueryRequest& out) noexcept {
  out = GroupQueryRequest{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::GroupQuery, kGroupQueryPayload,
                               kGroupQueryPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  status = reader.read_u32(out.id.session);
  if (status) status = reader.read_u64(out.id.sequence);
  if (!status) return status;
  if (!is_group_sequence(out.id.sequence)) {
    return Status::error(StatusCode::ProtocolError, "GROUP_QUERY");
  }
  return Status::success();
}

GroupStatusReply group_status_from(const std::uint16_t result,
                                   const GroupDeliveryResult& summary,
                                   const char* const reason) noexcept {
  GroupStatusReply reply{};
  reply.result = result;
  reply.group = summary.group;
  if (result == static_cast<std::uint16_t>(ConfigOpsResult::Ok)) {
    reply.id = summary.id;
    reply.state = summary.state;
    reply.rounds = summary.rounds;
    reply.delivered = summary.delivered;
    reply.nonmember = summary.nonmember;
    reply.missing_total = summary.missing_total;
    reply.unaccounted = summary.unaccounted;
    reply.missing_count = summary.missing_count <= kGroupReportMissingMax
                              ? summary.missing_count
                              : static_cast<std::uint8_t>(kGroupReportMissingMax);
    for (std::size_t i = 0; i < reply.missing_count; ++i) reply.missing[i] = summary.missing[i];
  }
  const char* const text = reason != nullptr ? reason : "";
  std::size_t length = 0;
  while (length < kGroupStatusReasonMax && text[length] != '\0') {
    const auto c = static_cast<unsigned char>(text[length]);
    reply.reason[length] = (c >= 0x20 && c <= 0x7E) ? text[length] : '?';
    ++length;
  }
  reply.reason_len = static_cast<std::uint8_t>(length);
  reply.flags = group_status_flags(reply);
  return reply;
}

Status encode_group_status(const GroupStatusReply& reply, const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  if (!check_group_status(reply)) {
    return Status::error(StatusCode::InvalidArgument, "group status");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::GroupStatus,
      static_cast<std::uint16_t>(kGroupStatusFixedPayload + reply.missing_count * 8U +
                                 reply.reason_len));
  if (status) status = writer.write_u16(reply.result);
  if (status) status = writer.write_u32(reply.id.session);
  if (status) status = writer.write_u64(reply.id.sequence);
  if (status) status = writer.write_u16(reply.group);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(reply.state));
  if (status) status = writer.write_u8(reply.rounds);
  if (status) status = writer.write_u16(reply.delivered);
  if (status) status = writer.write_u16(reply.nonmember);
  if (status) status = writer.write_u16(reply.missing_total);
  if (status) status = writer.write_u16(reply.unaccounted);
  if (status) status = writer.write_u8(group_status_flags(reply));
  if (status) status = writer.write_u8(reply.missing_count);
  if (status) status = writer.write_u8(reply.reason_len);
  if (status) status = writer.write_u8(0);
  for (std::size_t i = 0; status && i < reply.missing_count; ++i) {
    status = writer.write_u64(reply.missing[i]);
  }
  if (status && reply.reason_len > 0) {
    status = writer.write_bytes(
        ByteView{reinterpret_cast<const std::uint8_t*>(reply.reason.data()), reply.reason_len});
  }
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_group_status(const ByteView inner, GroupStatusReply& out) noexcept {
  out = GroupStatusReply{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::GroupStatus, kGroupStatusFixedPayload,
                               kGroupStatusMaxPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  std::uint8_t state = 0;
  std::uint8_t reserved = 0;
  status = reader.read_u16(out.result);
  if (status) status = reader.read_u32(out.id.session);
  if (status) status = reader.read_u64(out.id.sequence);
  if (status) status = reader.read_u16(out.group);
  if (status) status = reader.read_u8(state);
  if (status) status = reader.read_u8(out.rounds);
  if (status) status = reader.read_u16(out.delivered);
  if (status) status = reader.read_u16(out.nonmember);
  if (status) status = reader.read_u16(out.missing_total);
  if (status) status = reader.read_u16(out.unaccounted);
  if (status) status = reader.read_u8(out.flags);
  if (status) status = reader.read_u8(out.missing_count);
  if (status) status = reader.read_u8(out.reason_len);
  if (status) status = reader.read_u8(reserved);
  if (!status) return status;
  if (state > static_cast<std::uint8_t>(DeliveryState::Indeterminate) || reserved != 0 ||
      out.missing_count > kGroupReportMissingMax || out.reason_len > kGroupStatusReasonMax ||
      reader.remaining() != out.missing_count * 8U + out.reason_len) {
    return Status::error(StatusCode::ProtocolError, "GROUP_STATUS");
  }
  out.state = static_cast<DeliveryState>(state);
  for (std::size_t i = 0; status && i < out.missing_count; ++i) {
    status = reader.read_u64(out.missing[i]);
  }
  if (status && out.reason_len > 0) {
    status = reader.read_bytes(
        MutableByteView{reinterpret_cast<std::uint8_t*>(out.reason.data()), out.reason_len});
  }
  if (!status) return status;
  status = check_group_status(out);
  if (!status) return status;
  if (out.flags != group_status_flags(out)) {
    return Status::error(StatusCode::ProtocolError, "GROUP_STATUS_FLAGS");
  }
  return Status::success();
}

// --- Join relay family (join_relay_v1, 0x60-0x63) --------------------------

namespace {

bool relay_node_valid(const NodeId node) noexcept {
  return node != kInvalidNodeId && node != kBroadcastNodeId;
}

// The object must decode and point the right way at the right proxy.
Status check_relay_object(const ByteView object, const sdkv1::RelayDirection dir,
                          const NodeId proxy) noexcept {
  sdkv1::RelayObject decoded{};
  const Status status = sdkv1::relay_object_decode(object, decoded);
  if (!status) return Status::error(StatusCode::ProtocolError, "JOIN_RELAY_OBJECT");
  if (decoded.header.dir != dir || decoded.header.proxy != proxy) {
    return Status::error(StatusCode::ProtocolError, "JOIN_RELAY_OBJECT_HEADER");
  }
  return Status::success();
}

Status check_relay_up(const JoinRelayUp& up) noexcept {
  if (!relay_node_valid(up.gateway) || !relay_node_valid(up.from_proxy) ||
      up.hops > kJoinRelayHopsMax || (up.hops == 0) != (up.from_proxy == up.gateway)) {
    return Status::error(StatusCode::ProtocolError, "JOIN_RELAY_UP");
  }
  return check_relay_object(up.object, sdkv1::RelayDirection::Up, up.from_proxy);
}

bool join_relay_result_known(const std::uint16_t result) noexcept {
  switch (result) {
    case static_cast<std::uint16_t>(ConfigOpsResult::Ok):
    case static_cast<std::uint16_t>(ConfigOpsResult::Busy):
    case static_cast<std::uint16_t>(ConfigOpsResult::Denied):
    case static_cast<std::uint16_t>(ConfigOpsResult::Unsupported):
    case static_cast<std::uint16_t>(ConfigOpsResult::Invalid):
    case static_cast<std::uint16_t>(ConfigOpsResult::Indeterminate):
    case static_cast<std::uint16_t>(ConfigOpsResult::NoRoute):
      return true;
    default:
      return false;
  }
}

bool join_relay_result_fields_ok(const JoinRelayResult& result) noexcept {
  const bool ok = result.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok);
  return join_relay_result_known(result.result) && result.proxy != kBroadcastNodeId &&
         (!ok || (relay_node_valid(result.proxy) && result.relay_id != 0));
}

}  // namespace

static_assert(kJoinRelayObjectMax == sdkv1::kRelayObjectMax, "relay object bound");

Status encode_join_relay_up(const JoinRelayUp& up, const MutableByteView out,
                            std::size_t& written) noexcept {
  written = 0;
  if (!check_relay_up(up)) return Status::error(StatusCode::InvalidArgument, "join relay up");
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::JoinRelayUp,
      static_cast<std::uint16_t>(kJoinRelayUpFixed + up.object.size));
  if (status) status = writer.write_u64(up.gateway);
  if (status) status = writer.write_u64(up.from_proxy);
  if (status) status = writer.write_u8(up.hops);
  if (status) status = writer.write_bytes(up.object);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_join_relay_up(const ByteView inner, JoinRelayUp& out) noexcept {
  out = JoinRelayUp{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::JoinRelayUp, kJoinRelayUpFixed + 1,
                               kJoinRelayUpMaxPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  JoinRelayUp up{};
  status = reader.read_u64(up.gateway);
  if (status) status = reader.read_u64(up.from_proxy);
  if (status) status = reader.read_u8(up.hops);
  if (!status) return status;
  up.object = ByteView{payload.data + kJoinRelayUpFixed, payload.size - kJoinRelayUpFixed};
  status = check_relay_up(up);
  if (!status) return status;
  out = up;
  return Status::success();
}

Status encode_join_relay_down(const JoinRelayDown& down, const MutableByteView out,
                              std::size_t& written) noexcept {
  written = 0;
  if (!relay_node_valid(down.to_proxy) ||
      !check_relay_object(down.object, sdkv1::RelayDirection::Down, down.to_proxy)) {
    return Status::error(StatusCode::InvalidArgument, "join relay down");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(
      writer, HostOpsSub::JoinRelayDown,
      static_cast<std::uint16_t>(kJoinRelayDownFixed + down.object.size));
  if (status) status = writer.write_u64(down.to_proxy);
  if (status) status = writer.write_bytes(down.object);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_join_relay_down(const ByteView inner, JoinRelayDown& out) noexcept {
  out = JoinRelayDown{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::JoinRelayDown, kJoinRelayDownFixed + 1,
                               kJoinRelayDownMaxPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  JoinRelayDown down{};
  status = reader.read_u64(down.to_proxy);
  if (!status) return status;
  down.object = ByteView{payload.data + kJoinRelayDownFixed, payload.size - kJoinRelayDownFixed};
  if (!relay_node_valid(down.to_proxy)) {
    return Status::error(StatusCode::ProtocolError, "JOIN_RELAY_DOWN");
  }
  status = check_relay_object(down.object, sdkv1::RelayDirection::Down, down.to_proxy);
  if (!status) return status;
  out = down;
  return Status::success();
}

Status encode_join_relay_abort(const JoinRelayAbort& abort, const MutableByteView out,
                               std::size_t& written) noexcept {
  written = 0;
  if (!relay_node_valid(abort.proxy) || abort.relay_id == 0 ||
      !sdkv1::relay_abort_reason_known(abort.reason)) {
    return Status::error(StatusCode::InvalidArgument, "join relay abort");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::JoinRelayAbort,
                                     static_cast<std::uint16_t>(kJoinRelayAbortPayload));
  if (status) status = writer.write_u64(abort.proxy);
  if (status) status = writer.write_u32(abort.relay_id);
  if (status) status = writer.write_u8(abort.reason);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_join_relay_abort(const ByteView inner, JoinRelayAbort& out) noexcept {
  out = JoinRelayAbort{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::JoinRelayAbort, kJoinRelayAbortPayload,
                               kJoinRelayAbortPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  JoinRelayAbort abort{};
  status = reader.read_u64(abort.proxy);
  if (status) status = reader.read_u32(abort.relay_id);
  if (status) status = reader.read_u8(abort.reason);
  if (!status) return status;
  if (!relay_node_valid(abort.proxy) || abort.relay_id == 0 ||
      !sdkv1::relay_abort_reason_known(abort.reason)) {
    return Status::error(StatusCode::ProtocolError, "JOIN_RELAY_ABORT");
  }
  out = abort;
  return Status::success();
}

Status encode_join_relay_result(const JoinRelayResult& result, const MutableByteView out,
                                std::size_t& written) noexcept {
  written = 0;
  if (!join_relay_result_fields_ok(result)) {
    return Status::error(StatusCode::InvalidArgument, "join relay result");
  }
  ByteWriter writer(out);
  Status status = write_gateway_head(writer, HostOpsSub::JoinRelayResult,
                                     static_cast<std::uint16_t>(kJoinRelayResultPayload));
  if (status) status = writer.write_u16(result.result);
  if (status) status = writer.write_u64(result.proxy);
  if (status) status = writer.write_u32(result.relay_id);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status decode_join_relay_result(const ByteView inner, JoinRelayResult& out) noexcept {
  out = JoinRelayResult{};
  ByteView payload{};
  Status status = gateway_body(inner, HostOpsSub::JoinRelayResult, kJoinRelayResultPayload,
                               kJoinRelayResultPayload, payload);
  if (!status) return status;
  ByteReader reader(payload);
  JoinRelayResult result{};
  status = reader.read_u16(result.result);
  if (status) status = reader.read_u64(result.proxy);
  if (status) status = reader.read_u32(result.relay_id);
  if (!status) return status;
  if (!join_relay_result_fields_ok(result)) {
    return Status::error(StatusCode::ProtocolError, "JOIN_RELAY_RESULT");
  }
  out = result;
  return Status::success();
}

}  // namespace routeloom::usb
