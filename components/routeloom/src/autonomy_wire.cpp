#include "routeloom/autonomy_wire.hpp"

#include "routeloom/admission.hpp"
#include "routeloom/byte_io.hpp"

namespace routeloom::autonomy {
namespace {

constexpr std::size_t kPreludeSize = 2;  // version u8 | subtype u8

Status prelude_error() noexcept {
  return Status::error(StatusCode::ProtocolError, "autonomy payload rejected");
}

// Reads the shared prelude and enforces version + exact subtype.
Status read_prelude(ByteReader& reader, const std::uint8_t subtype) noexcept {
  std::uint8_t version = 0;
  std::uint8_t found_subtype = 0;
  Status status = reader.read_u8(version);
  if (!status) return status;
  status = reader.read_u8(found_subtype);
  if (!status) return status;
  if (version != kPayloadVersion || found_subtype != subtype) {
    return prelude_error();
  }
  return Status::success();
}

Status write_prelude(ByteWriter& writer, const std::uint8_t subtype) noexcept {
  Status status = writer.write_u8(kPayloadVersion);
  if (!status) return status;
  return writer.write_u8(subtype);
}

}  // namespace

// --- Busy -------------------------------------------------------------------

Status busy_encode(const BusyPayload& payload, EncodedPayload& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.reason)));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.referenced_type)));
  RL_WRITE(writer.write_u64(payload.referenced_origin));
  RL_WRITE(writer.write_u32(payload.referenced_session));
  RL_WRITE(writer.write_u64(payload.referenced_sequence));
  RL_WRITE(writer.write_u8(payload.referenced_round));
  RL_WRITE(writer.write_u32(payload.binding_generation.value));
  RL_WRITE(writer.write_u32(payload.feedback_sequence.value));
  RL_WRITE(writer.write_u32(payload.retry_after_ms));
  RL_WRITE(writer.write_u8(payload.pressure));
#undef RL_WRITE
  if (writer.size() != kBusyPayloadSize) {
    return Status::error(StatusCode::InternalError, "busy payload size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status busy_decode(const ByteView encoded, BusyPayload& out) noexcept {
  // The subtype byte selects a variant, so the prelude is checked manually.
  if (encoded.size != kBusyPayloadSize || encoded.data[0] != kPayloadVersion) {
    return prelude_error();
  }
  const std::uint8_t subtype = encoded.data[1];
  if (subtype != static_cast<std::uint8_t>(BusySubtype::Reject) &&
      subtype != static_cast<std::uint8_t>(BusySubtype::PressureHint)) {
    return prelude_error();
  }
  ByteReader reader(ByteView{encoded.data + kPreludeSize, encoded.size - kPreludeSize});
  std::uint8_t reason = 0;
  std::uint8_t ref_type = 0;
  std::uint32_t binding = 0;
  std::uint32_t feedback = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u8(reason));
  RL_READ(reader.read_u8(ref_type));
  RL_READ(reader.read_u64(out.referenced_origin));
  RL_READ(reader.read_u32(out.referenced_session));
  RL_READ(reader.read_u64(out.referenced_sequence));
  RL_READ(reader.read_u8(out.referenced_round));
  RL_READ(reader.read_u32(binding));
  RL_READ(reader.read_u32(feedback));
  RL_READ(reader.read_u32(out.retry_after_ms));
  RL_READ(reader.read_u8(out.pressure));
#undef RL_READ
  if (reason > static_cast<std::uint8_t>(BusyReason::RateLimited) ||
      !member_frame_type(static_cast<FrameType>(ref_type))) {
    return prelude_error();
  }
  // A Reject with no reason is meaningless — it would still trigger window
  // collapse and deferral on the receiver. PressureHint never reads reason.
  if (subtype == static_cast<std::uint8_t>(BusySubtype::Reject) &&
      reason == static_cast<std::uint8_t>(BusyReason::None)) {
    return prelude_error();
  }
  out.subtype = static_cast<BusySubtype>(subtype);
  out.reason = static_cast<BusyReason>(reason);
  out.referenced_type = static_cast<FrameType>(ref_type);
  out.binding_generation = BindingGeneration{binding};
  out.feedback_sequence = FeedbackSequence{feedback};
  return Status::success();
}

// --- TimeSync -----------------------------------------------------------------

Status time_sync_encode(const TimeSyncPayload& payload, EncodedPayload& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_u64(payload.source));
  RL_WRITE(writer.write_u32(payload.sequence));
  RL_WRITE(writer.write_u64(payload.reference_ms));
  RL_WRITE(writer.write_u32(payload.uncertainty_ms));
#undef RL_WRITE
  if (writer.size() != kTimeSyncPayloadSize) {
    return Status::error(StatusCode::InternalError, "timesync payload size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status time_sync_decode(const ByteView encoded, TimeSyncPayload& out) noexcept {
  if (encoded.size != kTimeSyncPayloadSize) return prelude_error();
  ByteReader reader(encoded);
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(TimeSyncSubtype::Sample)));
  RL_READ(reader.read_u64(out.source));
  RL_READ(reader.read_u32(out.sequence));
  RL_READ(reader.read_u64(out.reference_ms));
  RL_READ(reader.read_u32(out.uncertainty_ms));
#undef RL_READ
  return Status::success();
}

// --- ChannelNotice ------------------------------------------------------------

Status channel_notice_encode(const ChannelNoticePayload& payload,
                             EncodedPayload& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_u64(payload.subject));
  RL_WRITE(writer.write_u32(payload.channel_epoch.value));
  RL_WRITE(writer.write_u32(payload.starts_in_ms));
  RL_WRITE(writer.write_u32(payload.duration_ms));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.reason)));
  RL_WRITE(writer.write_u16(payload.protected_cut_id));
#undef RL_WRITE
  if (writer.size() != kChannelNoticePayloadSize) {
    return Status::error(StatusCode::InternalError, "channel notice size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status channel_notice_decode(const ByteView encoded, ChannelNoticePayload& out) noexcept {
  if (encoded.size != kChannelNoticePayloadSize) return prelude_error();
  ByteReader reader(encoded);
  Status status;
  std::uint32_t epoch = 0;
  std::uint8_t reason = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(ChannelNoticeSubtype::PlannedAbsence)));
  RL_READ(reader.read_u64(out.subject));
  RL_READ(reader.read_u32(epoch));
  RL_READ(reader.read_u32(out.starts_in_ms));
  RL_READ(reader.read_u32(out.duration_ms));
  RL_READ(reader.read_u8(reason));
  RL_READ(reader.read_u16(out.protected_cut_id));
#undef RL_READ
  if (reason > static_cast<std::uint8_t>(AbsenceReason::Cutover)) {
    return prelude_error();
  }
  out.channel_epoch = ChannelEpoch{epoch};
  out.reason = static_cast<AbsenceReason>(reason);
  return Status::success();
}

// --- NeighborProbe / NeighborResult -------------------------------------------

Status neighbor_probe_encode(const NeighborProbePayload& payload,
                             EncodedPayload& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_u32(payload.binding_generation.value));
  RL_WRITE(writer.write_u32(payload.probe_sequence));
  RL_WRITE(writer.write_u64(payload.sent_ms));
  RL_WRITE(writer.write_u32(payload.requested_lease_ms));
#undef RL_WRITE
  if (writer.size() != kNeighborProbePayloadSize) {
    return Status::error(StatusCode::InternalError, "neighbor probe size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status neighbor_probe_decode(const ByteView encoded, NeighborProbePayload& out) noexcept {
  if (encoded.size != kNeighborProbePayloadSize) return prelude_error();
  ByteReader reader(encoded);
  Status status;
  std::uint32_t binding = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(NeighborProbeSubtype::AvailabilityProbe)));
  RL_READ(reader.read_u32(binding));
  RL_READ(reader.read_u32(out.probe_sequence));
  RL_READ(reader.read_u64(out.sent_ms));
  RL_READ(reader.read_u32(out.requested_lease_ms));
#undef RL_READ
  out.binding_generation = BindingGeneration{binding};
  return Status::success();
}

Status neighbor_result_encode(const NeighborResultPayload& payload,
                              EncodedPayload& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_u32(payload.binding_generation.value));
  RL_WRITE(writer.write_u32(payload.probe_sequence));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.result)));
  RL_WRITE(writer.write_u8(payload.pressure));
  RL_WRITE(writer.write_u32(payload.queue_delay_ms));
  RL_WRITE(writer.write_u32(payload.est_airtime_us));
  RL_WRITE(writer.write_u32(payload.lease_granted_ms));
#undef RL_WRITE
  if (writer.size() != kNeighborResultPayloadSize) {
    return Status::error(StatusCode::InternalError, "neighbor result size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status neighbor_result_decode(const ByteView encoded, NeighborResultPayload& out) noexcept {
  if (encoded.size != kNeighborResultPayloadSize) return prelude_error();
  ByteReader reader(encoded);
  Status status;
  std::uint32_t binding = 0;
  std::uint8_t result = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(NeighborResultSubtype::AvailabilityResult)));
  RL_READ(reader.read_u32(binding));
  RL_READ(reader.read_u32(out.probe_sequence));
  RL_READ(reader.read_u8(result));
  RL_READ(reader.read_u8(out.pressure));
  RL_READ(reader.read_u32(out.queue_delay_ms));
  RL_READ(reader.read_u32(out.est_airtime_us));
  RL_READ(reader.read_u32(out.lease_granted_ms));
#undef RL_READ
  if (result > static_cast<std::uint8_t>(NeighborResultCode::Leaving)) {
    return prelude_error();
  }
  out.binding_generation = BindingGeneration{binding};
  out.result = static_cast<NeighborResultCode>(result);
  return Status::success();
}

// --- Authenticated objects ------------------------------------------------------

Status control_object_encode(const ControlObjectPayload& payload,
                             EncodedPayload& out) noexcept {
  if (payload.total_len == 0 || payload.total_len > kAuthenticatedObjectMax) {
    return Status::error(StatusCode::InvalidArgument, "control object length out of range");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.kind)));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u16(payload.total_len));
  RL_WRITE(writer.write_bytes(ByteView{payload.object_hash.data(), payload.object_hash.size()}));
#undef RL_WRITE
  if (writer.size() != kControlObjectPayloadSize) {
    return Status::error(StatusCode::InternalError, "control object size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status control_object_decode(const ByteView encoded, ControlObjectPayload& out) noexcept {
  if (encoded.size != kControlObjectPayloadSize) return prelude_error();
  ByteReader reader(encoded);
  Status status;
  std::uint8_t kind = 0;
  std::uint8_t flags = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(ControlObjectSubtype::Manifest)));
  RL_READ(reader.read_u8(kind));
  RL_READ(reader.read_u8(flags));
  RL_READ(reader.read_u16(out.total_len));
  RL_READ(reader.read_bytes(MutableByteView{out.object_hash.data(), out.object_hash.size()}));
#undef RL_READ
  if (flags != 0 ||
      (kind != static_cast<std::uint8_t>(ControlObjectKind::ChannelPlan) &&
       kind != static_cast<std::uint8_t>(ControlObjectKind::RecoverySnapshot) &&
       kind != static_cast<std::uint8_t>(ControlObjectKind::ConfigPermit) &&
       kind != static_cast<std::uint8_t>(ControlObjectKind::ConfigRecovery) &&
       kind != static_cast<std::uint8_t>(ControlObjectKind::TrustManifest) &&
       kind != static_cast<std::uint8_t>(ControlObjectKind::RevocationSet) &&
       kind != static_cast<std::uint8_t>(ControlObjectKind::AuthorityEnvelope)) ||
      out.total_len == 0 || out.total_len > kAuthenticatedObjectMax) {
    return prelude_error();
  }
  out.kind = static_cast<ControlObjectKind>(kind);
  return Status::success();
}

Status object_chunk_encode(const ObjectChunkPayload& payload,
                           EncodedPayload& out) noexcept {
  if (payload.data_size > payload.data.size() ||
      static_cast<std::uint32_t>(payload.offset) + payload.data_size >
          kAuthenticatedObjectMax) {
    return Status::error(StatusCode::InvalidArgument, "object chunk out of range");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_bytes(ByteView{payload.object_hash.data(), payload.object_hash.size()}));
  RL_WRITE(writer.write_u16(payload.offset));
  RL_WRITE(writer.write_u16(payload.data_size));
  RL_WRITE(writer.write_bytes(ByteView{payload.data.data(), payload.data_size}));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status object_chunk_decode(const ByteView encoded, ObjectChunkPayload& out) noexcept {
  if (encoded.size < kObjectChunkHeaderSize ||
      encoded.size > kMaxApplicationPayload) {
    return prelude_error();
  }
  ByteReader reader(encoded);
  Status status;
  std::uint16_t offset = 0;
  std::uint16_t length = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(ObjectChunkSubtype::Chunk)));
  RL_READ(reader.read_bytes(MutableByteView{out.object_hash.data(), out.object_hash.size()}));
  RL_READ(reader.read_u16(offset));
  RL_READ(reader.read_u16(length));
#undef RL_READ
  if (reader.remaining() != length ||
      static_cast<std::uint32_t>(offset) + length > kAuthenticatedObjectMax) {
    return prelude_error();
  }
  status = reader.read_bytes(MutableByteView{out.data.data(), length});
  if (!status) return status;
  out.offset = offset;
  out.data_size = length;
  return Status::success();
}

Status object_ack_encode(const ObjectAckPayload& payload, EncodedPayload& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.subtype)));
  RL_WRITE(writer.write_bytes(ByteView{payload.object_hash.data(), payload.object_hash.size()}));
  RL_WRITE(writer.write_u16(payload.received_len));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.status)));
#undef RL_WRITE
  if (writer.size() != kObjectAckPayloadSize) {
    return Status::error(StatusCode::InternalError, "object ack size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status object_ack_decode(const ByteView encoded, ObjectAckPayload& out) noexcept {
  if (encoded.size != kObjectAckPayloadSize) return prelude_error();
  ByteReader reader(encoded);
  Status status;
  std::uint8_t result = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(read_prelude(reader, static_cast<std::uint8_t>(ObjectAckSubtype::Ack)));
  RL_READ(reader.read_bytes(MutableByteView{out.object_hash.data(), out.object_hash.size()}));
  RL_READ(reader.read_u16(out.received_len));
  RL_READ(reader.read_u8(result));
#undef RL_READ
  if (result > static_cast<std::uint8_t>(ObjectAckStatus::Failed)) {
    return prelude_error();
  }
  out.status = static_cast<ObjectAckStatus>(result);
  return Status::success();
}

// --- BootstrapAuth body -------------------------------------------------------

Status bootstrap_auth_encode(const BootstrapAuthBody& payload,
                             EncodedPayload& out) noexcept {
  if (payload.body_size > payload.body.size()) {
    return Status::error(StatusCode::InvalidArgument, "bootstrap auth body too large");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(write_prelude(writer, static_cast<std::uint8_t>(payload.phase)));
  RL_WRITE(writer.write_u8(payload.step_index));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_bytes(ByteView{payload.body.data(), payload.body_size}));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status bootstrap_auth_decode(const ByteView encoded, BootstrapAuthBody& out) noexcept {
  // The subtype byte carries the auth phase, so the prelude is checked
  // manually: version 1 followed by a known AuthPhase.
  if (encoded.size < kBootstrapAuthHeaderSize ||
      encoded.size > kMaxApplicationPayload ||
      encoded.data[0] != kPayloadVersion) {
    return prelude_error();
  }
  const std::uint8_t phase = encoded.data[1];
  if (phase < static_cast<std::uint8_t>(AuthPhase::Prove) ||
      phase > static_cast<std::uint8_t>(AuthPhase::Finish)) {
    return prelude_error();
  }
  ByteReader reader(ByteView{encoded.data + kPreludeSize, encoded.size - kPreludeSize});
  Status status;
  std::uint8_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u8(out.step_index));
  RL_READ(reader.read_u8(reserved));
#undef RL_READ
  if (reserved != 0) return prelude_error();
  out.phase = static_cast<AuthPhase>(phase);
  out.body_size = reader.remaining();
  status = reader.read_bytes(MutableByteView{out.body.data(), out.body_size});
  if (!status) return status;
  return Status::success();
}

// --- RLD1 carrier --------------------------------------------------------------

bool rld1_probe(const ByteView encoded) noexcept {
  if (encoded.size < 4) return false;
  return encoded.data[0] == 0x52 && encoded.data[1] == 0x4c &&
         encoded.data[2] == 0x44 && encoded.data[3] == 0x31;
}

Status rld1_encode(const Rld1Envelope& envelope, Rld1Encoded& out) noexcept {
  if (!rld1_kind_allowed(envelope.kind)) {
    return Status::error(StatusCode::InvalidArgument, "kind not permitted on RLD1");
  }
  if (envelope.flags != 0) {
    return Status::error(StatusCode::InvalidArgument, "RLD1 v1 flags are reserved");
  }
  if (envelope.body_size > kRld1MaxBody) {
    return Status::error(StatusCode::NoCapacity, "RLD1 body exceeds budget");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u32(kRld1Magic));
  RL_WRITE(writer.write_u8(kRld1Version));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(envelope.kind)));
  RL_WRITE(writer.write_u16(kRld1HeaderSize));
  RL_WRITE(writer.write_u16(static_cast<std::uint16_t>(kRld1HeaderSize + envelope.body_size)));
  RL_WRITE(writer.write_u16(envelope.flags));
  RL_WRITE(writer.write_u32(envelope.network_hint));
  RL_WRITE(writer.write_u64(envelope.claimed_node));
  RL_WRITE(writer.write_bytes(
      ByteView{envelope.transaction_nonce.data(), envelope.transaction_nonce.size()}));
  RL_WRITE(writer.write_u32(envelope.capability_bits));
  RL_WRITE(writer.write_bytes(ByteView{envelope.body.data(), envelope.body_size}));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status rld1_decode(const ByteView encoded, Rld1Envelope& out) noexcept {
  if (encoded.size < kRld1HeaderSize || encoded.size > kRld1MaxTotal) {
    return prelude_error();
  }
  ByteReader reader(encoded);
  Status status;
  std::uint32_t magic = 0;
  std::uint8_t version = 0;
  std::uint8_t kind = 0;
  std::uint16_t header_len = 0;
  std::uint16_t total_len = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u32(magic));
  RL_READ(reader.read_u8(version));
  RL_READ(reader.read_u8(kind));
  RL_READ(reader.read_u16(header_len));
  RL_READ(reader.read_u16(total_len));
  RL_READ(reader.read_u16(out.flags));
  RL_READ(reader.read_u32(out.network_hint));
  RL_READ(reader.read_u64(out.claimed_node));
  RL_READ(reader.read_bytes(
      MutableByteView{out.transaction_nonce.data(), out.transaction_nonce.size()}));
  RL_READ(reader.read_u32(out.capability_bits));
#undef RL_READ
  if (magic != kRld1Magic || version != kRld1Version ||
      header_len != kRld1HeaderSize || total_len != encoded.size ||
      total_len < kRld1HeaderSize || total_len > kRld1MaxTotal || out.flags != 0 ||
      !rld1_kind_allowed(static_cast<FrameType>(kind))) {
    return prelude_error();
  }
  out.kind = static_cast<FrameType>(kind);
  out.body_size = reader.remaining();
  status = reader.read_bytes(MutableByteView{out.body.data(), out.body_size});
  if (!status) return status;
  return Status::success();
}

}  // namespace routeloom::autonomy
