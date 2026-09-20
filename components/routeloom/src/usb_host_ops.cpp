#include "routeloom/usb_host_ops.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"

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
  if (status) status = reader.read_u16(payload_length);
  if (!status) return status;
  if (schema != 1 || payload_length != reader.remaining() ||
      reader.consumed() != kCanonicalMinSize) {
    return Status::error(StatusCode::InvalidArgument, "canonical framing");
  }
  if (out.network == 0 || dest_kind > 1 || delivery > 2 || priority > 3 ||
      policy != 0 || storage > 1 || out.ttl_ms < 1 || out.ttl_ms > 30000 ||
      hop < 1 || hop > 10 || persist > 1) {
    return Status::error(StatusCode::InvalidArgument, "canonical range");
  }
  if (dest_kind == 0 && is_reserved_id(out.destination)) {
    return Status::error(StatusCode::InvalidArgument, "reserved destination");
  }
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
  if (evidence_byte > static_cast<std::uint8_t>(DispatchWindow::Evidence::EndSdkReceived)) {
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

}  // namespace routeloom::usb
