#include "routeloom/telemetry.hpp"

namespace routeloom {
namespace {

Status reject() noexcept {
  return Status::error(StatusCode::ProtocolError, "diagnostic body rejected");
}

Status invalid(const char* detail) noexcept {
  return Status::error(StatusCode::InvalidArgument, detail);
}

// Shared 4-byte prefix: version u8 | subtype u8 | flags u16 (zero).
Status prefix_write(ByteWriter& writer, const DiagnosticSubtype subtype) noexcept {
  Status status = writer.write_u8(kDiagnosticBodyVersion);
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(subtype));
  if (!status) return status;
  return writer.write_u16(0);
}

Status prefix_read(ByteReader& reader, const DiagnosticSubtype subtype) noexcept {
  std::uint8_t version = 0;
  std::uint8_t found_subtype = 0;
  std::uint16_t flags = 0;
  Status status = reader.read_u8(version);
  if (!status) return status;
  status = reader.read_u8(found_subtype);
  if (!status) return status;
  status = reader.read_u16(flags);
  if (!status) return status;
  if (version != kDiagnosticBodyVersion || found_subtype != static_cast<std::uint8_t>(subtype) ||
      flags != 0) {
    return reject();
  }
  return Status::success();
}

Status expect_consumed(const ByteReader& reader) noexcept {
  return reader.remaining() == 0 ? Status::success() : reject();
}

}  // namespace

// --- TelemetryQuery: prefix + request_id4/peer8/direction1/class1/res2/age4 ---

Status telemetry_query_encode(const TelemetryQuery& query,
                              MutableByteView out) noexcept {
  if (out.size < kTelemetryQueryBodySize) {
    return Status::error(StatusCode::NoCapacity, "telemetry query output");
  }
  if (query.request_id == 0 || query.peer == kInvalidNodeId ||
      (query.length_class > 2 && query.length_class != kTelemetryPeerSummaryClass) ||
      query.max_age_ms > kTelemetryMaxAgeLimitMs) {
    return invalid("telemetry query fields");
  }
  ByteWriter writer{out};
  Status status = prefix_write(writer, DiagnosticSubtype::TelemetryQuery);
  if (!status) return status;
  status = writer.write_u32(query.request_id);
  if (!status) return status;
  status = writer.write_u64(query.peer);
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(query.direction));
  if (!status) return status;
  status = writer.write_u8(query.length_class);
  if (!status) return status;
  status = writer.write_u16(0);
  if (!status) return status;
  return writer.write_u32(query.max_age_ms);
}

Status telemetry_query_decode(const ByteView body, TelemetryQuery& out) noexcept {
  if (body.size != kTelemetryQueryBodySize) return reject();
  ByteReader reader{body};
  Status status = prefix_read(reader, DiagnosticSubtype::TelemetryQuery);
  if (!status) return status;
  std::uint32_t request_id = 0;
  std::uint64_t peer = 0;
  std::uint8_t direction = 0;
  std::uint8_t length_class = 0;
  std::uint16_t reserved = 0;
  std::uint32_t max_age_ms = 0;
  status = reader.read_u32(request_id);
  if (!status) return status;
  status = reader.read_u64(peer);
  if (!status) return status;
  status = reader.read_u8(direction);
  if (!status) return status;
  status = reader.read_u8(length_class);
  if (!status) return status;
  status = reader.read_u16(reserved);
  if (!status) return status;
  status = reader.read_u32(max_age_ms);
  if (!status) return status;
  if (!expect_consumed(reader)) return reject();
  if (request_id == 0 || peer == kInvalidNodeId || peer == kBroadcastNodeId ||
      direction > 1 ||
      (length_class > 2 && length_class != kTelemetryPeerSummaryClass) ||
      reserved != 0 || max_age_ms > kTelemetryMaxAgeLimitMs) {
    return reject();
  }
  out.request_id = request_id;
  out.peer = peer;
  out.direction = static_cast<ObservationDirection>(direction);
  out.length_class = length_class;
  out.max_age_ms = max_age_ms;
  return Status::success();
}

// --- TelemetrySnapshot: the fixed 128-byte record ----------------------------

Status telemetry_snapshot_encode(const TelemetrySnapshot& s,
                                 MutableByteView out) noexcept {
  if (out.size < kTelemetrySnapshotBodySize) {
    return Status::error(StatusCode::NoCapacity, "telemetry snapshot output");
  }
  ByteWriter writer{out};
  Status status = prefix_write(writer, DiagnosticSubtype::TelemetrySnapshot);
  if (!status) return status;
  status = writer.write_u32(s.request_id);
  if (!status) return status;
  status = writer.write_u64(s.observer);
  if (!status) return status;
  status = writer.write_u64(s.observer_boot);
  if (!status) return status;
  status = writer.write_u64(s.peer);
  if (!status) return status;
  status = writer.write_u32(s.binding.value);
  if (!status) return status;
  status = writer.write_u32(s.radio.value);
  if (!status) return status;
  status = writer.write_u32(s.channel_epoch.value);
  if (!status) return status;
  status = writer.write_u8(s.channel);
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(s.direction));
  if (!status) return status;
  status = writer.write_u8(s.length_class);
  if (!status) return status;
  status = writer.write_u8(s.validity);
  if (!status) return status;
  status = writer.write_u64(s.sampled_at_ms);
  if (!status) return status;
  status = writer.write_u32(s.window_ms);
  if (!status) return status;
  status = writer.write_u32(s.sample_age_ms);
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(s.rssi_last));
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(s.rssi_min));
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(s.rssi_max));
  if (!status) return status;
  status = writer.write_u8(0);  // reserved
  if (!status) return status;
  status = writer.write_u16(static_cast<std::uint16_t>(s.rssi_ewma_q8_8));
  if (!status) return status;
  status = writer.write_u16(0);  // reserved
  if (!status) return status;
  status = writer.write_u32(s.rssi_samples);
  if (!status) return status;
  status = writer.write_u32(s.tx_submitted);
  if (!status) return status;
  status = writer.write_u32(s.tx_mac_success);
  if (!status) return status;
  status = writer.write_u32(s.tx_mac_fail);
  if (!status) return status;
  status = writer.write_u32(s.tx_unknown);
  if (!status) return status;
  status = writer.write_u32(s.sdk_retries);
  if (!status) return status;
  status = writer.write_u32(s.hop_accepts);
  if (!status) return status;
  status = writer.write_u32(s.hop_timeouts);
  if (!status) return status;
  status = writer.write_u32(s.busy);
  if (!status) return status;
  status = writer.write_u32(s.queue_us_ewma);
  if (!status) return status;
  status = writer.write_u32(s.driver_us_ewma);
  if (!status) return status;
  status = writer.write_u32(s.hop_rtt_us_ewma);
  if (!status) return status;
  status = writer.write_u32(s.event_drops);
  if (!status) return status;
  status = writer.write_u32(s.saturation_mask);
  if (!status) return status;
  return Status::success();
}

Status telemetry_snapshot_decode(const ByteView body,
                                 TelemetrySnapshot& out) noexcept {
  if (body.size != kTelemetrySnapshotBodySize) return reject();
  ByteReader reader{body};
  Status status = prefix_read(reader, DiagnosticSubtype::TelemetrySnapshot);
  if (!status) return status;
  std::uint64_t observer = 0;
  std::uint64_t peer = 0;
  std::uint8_t direction = 0;
  std::uint16_t reserved16 = 0;
  std::uint8_t reserved8 = 0;
  status = reader.read_u32(out.request_id);
  if (!status) return status;
  status = reader.read_u64(observer);
  if (!status) return status;
  status = reader.read_u64(out.observer_boot);
  if (!status) return status;
  status = reader.read_u64(peer);
  if (!status) return status;
  status = reader.read_u32(out.binding.value);
  if (!status) return status;
  status = reader.read_u32(out.radio.value);
  if (!status) return status;
  status = reader.read_u32(out.channel_epoch.value);
  if (!status) return status;
  status = reader.read_u8(out.channel);
  if (!status) return status;
  status = reader.read_u8(direction);
  if (!status) return status;
  status = reader.read_u8(out.length_class);
  if (!status) return status;
  status = reader.read_u8(out.validity);
  if (!status) return status;
  status = reader.read_u64(out.sampled_at_ms);
  if (!status) return status;
  status = reader.read_u32(out.window_ms);
  if (!status) return status;
  status = reader.read_u32(out.sample_age_ms);
  if (!status) return status;
  std::uint8_t rssi_last = 0;
  std::uint8_t rssi_min = 0;
  std::uint8_t rssi_max = 0;
  std::uint16_t ewma = 0;
  status = reader.read_u8(rssi_last);
  if (!status) return status;
  status = reader.read_u8(rssi_min);
  if (!status) return status;
  status = reader.read_u8(rssi_max);
  if (!status) return status;
  status = reader.read_u8(reserved8);
  if (!status) return status;
  status = reader.read_u16(ewma);
  if (!status) return status;
  status = reader.read_u16(reserved16);
  if (!status) return status;
  if (reserved8 != 0 || reserved16 != 0) return reject();
  status = reader.read_u32(out.rssi_samples);
  if (!status) return status;
  status = reader.read_u32(out.tx_submitted);
  if (!status) return status;
  status = reader.read_u32(out.tx_mac_success);
  if (!status) return status;
  status = reader.read_u32(out.tx_mac_fail);
  if (!status) return status;
  status = reader.read_u32(out.tx_unknown);
  if (!status) return status;
  status = reader.read_u32(out.sdk_retries);
  if (!status) return status;
  status = reader.read_u32(out.hop_accepts);
  if (!status) return status;
  status = reader.read_u32(out.hop_timeouts);
  if (!status) return status;
  status = reader.read_u32(out.busy);
  if (!status) return status;
  status = reader.read_u32(out.queue_us_ewma);
  if (!status) return status;
  status = reader.read_u32(out.driver_us_ewma);
  if (!status) return status;
  status = reader.read_u32(out.hop_rtt_us_ewma);
  if (!status) return status;
  status = reader.read_u32(out.event_drops);
  if (!status) return status;
  status = reader.read_u32(out.saturation_mask);
  if (!status) return status;
  if (!expect_consumed(reader)) return reject();
  if (observer == kInvalidNodeId || observer == kBroadcastNodeId ||
      peer == kInvalidNodeId || peer == kBroadcastNodeId || direction > 1 ||
      (out.length_class > 2 &&
       out.length_class != kTelemetryPeerSummaryClass) ||
      ((out.validity & kTelemetrySourceLocalDriver) != 0 &&
       (out.validity & kTelemetrySourceInjectedTest) != 0)) {
    return reject();
  }
  out.observer = observer;
  out.peer = peer;
  out.direction = static_cast<ObservationDirection>(direction);
  out.rssi_last = static_cast<std::int8_t>(rssi_last);
  out.rssi_min = static_cast<std::int8_t>(rssi_min);
  out.rssi_max = static_cast<std::int8_t>(rssi_max);
  out.rssi_ewma_q8_8 = static_cast<std::int16_t>(ewma);
  return Status::success();
}

// --- DiagnosticReject: prefix + request_id4/reason2/res2/observer8/detail4 ---

Status diagnostic_reject_encode(const DiagnosticReject& r,
                                MutableByteView out) noexcept {
  if (out.size < kDiagnosticRejectBodySize) {
    return Status::error(StatusCode::NoCapacity, "diagnostic reject output");
  }
  const auto reason = static_cast<std::uint16_t>(r.reason);
  if (r.request_id == 0 || reason < 1 || reason > 7 || r.observer == kInvalidNodeId) {
    return invalid("diagnostic reject fields");
  }
  ByteWriter writer{out};
  Status status = prefix_write(writer, DiagnosticSubtype::DiagnosticReject);
  if (!status) return status;
  status = writer.write_u32(r.request_id);
  if (!status) return status;
  status = writer.write_u16(reason);
  if (!status) return status;
  status = writer.write_u16(0);
  if (!status) return status;
  status = writer.write_u64(r.observer);
  if (!status) return status;
  return writer.write_u32(r.detail);
}

Status diagnostic_reject_decode(const ByteView body, DiagnosticReject& out) noexcept {
  if (body.size != kDiagnosticRejectBodySize) return reject();
  ByteReader reader{body};
  Status status = prefix_read(reader, DiagnosticSubtype::DiagnosticReject);
  if (!status) return status;
  std::uint32_t request_id = 0;
  std::uint16_t reason = 0;
  std::uint16_t reserved = 0;
  std::uint64_t observer = 0;
  std::uint32_t detail = 0;
  status = reader.read_u32(request_id);
  if (!status) return status;
  status = reader.read_u16(reason);
  if (!status) return status;
  status = reader.read_u16(reserved);
  if (!status) return status;
  status = reader.read_u64(observer);
  if (!status) return status;
  status = reader.read_u32(detail);
  if (!status) return status;
  if (!expect_consumed(reader)) return reject();
  if (request_id == 0 || reason < 1 || reason > 7 || reserved != 0 ||
      observer == kInvalidNodeId || observer == kBroadcastNodeId) {
    return reject();
  }
  out.request_id = request_id;
  out.reason = static_cast<DiagnosticRejectReason>(reason);
  out.observer = observer;
  out.detail = detail;
  return Status::success();
}

// CapabilitiesReply layout (40 B): prefix4 || features1 || permit_profiles1
// || relay_effective1 || reserved1 || observer8 || observer_boot8 || reserved16.
Status capabilities_reply_encode(const CapabilitiesReply& reply,
                                 const MutableByteView out) noexcept {
  if (out.size != kCapabilitiesReplyBodySize ||
      reply.observer == kInvalidNodeId ||
      reply.observer == kBroadcastNodeId ||
      (reply.features & ~0x1Fu) != 0 || (reply.permit_profiles & ~0x3u) != 0) {
    return reject();
  }
  ByteWriter writer{out};
  Status status = prefix_write(writer, DiagnosticSubtype::CapabilitiesReply);
  if (!status) return status;
  status = writer.write_u8(reply.features);
  if (!status) return status;
  status = writer.write_u8(reply.permit_profiles);
  if (!status) return status;
  status = writer.write_u8(reply.relay_effective ? 1 : 0);
  if (!status) return status;
  status = writer.write_u8(0);
  if (!status) return status;
  status = writer.write_u64(reply.observer);
  if (!status) return status;
  status = writer.write_u64(reply.observer_boot);
  if (!status) return status;
  for (int i = 0; i < 16; ++i) {
    status = writer.write_u8(0);
    if (!status) return status;
  }
  return Status::success();
}

Status capabilities_reply_decode(const ByteView body,
                                 CapabilitiesReply& out) noexcept {
  if (body.size != kCapabilitiesReplyBodySize) return reject();
  ByteReader reader{body};
  Status status = prefix_read(reader, DiagnosticSubtype::CapabilitiesReply);
  if (!status) return status;
  std::uint8_t features = 0, profiles = 0, relay = 0, reserved = 0;
  std::uint64_t observer = 0, boot = 0;
  status = reader.read_u8(features);
  if (!status) return status;
  status = reader.read_u8(profiles);
  if (!status) return status;
  status = reader.read_u8(relay);
  if (!status) return status;
  status = reader.read_u8(reserved);
  if (!status) return status;
  status = reader.read_u64(observer);
  if (!status) return status;
  status = reader.read_u64(boot);
  if (!status) return status;
  for (int i = 0; i < 16; ++i) {
    std::uint8_t pad = 0;
    status = reader.read_u8(pad);
    if (!status) return status;
    reserved |= pad;
  }
  if (!expect_consumed(reader)) return reject();
  if ((features & ~0x1Fu) != 0 || (profiles & ~0x3u) != 0 || relay > 1 ||
      reserved != 0 || observer == kInvalidNodeId ||
      observer == kBroadcastNodeId) {
    return reject();
  }
  out.features = features;
  out.permit_profiles = profiles;
  out.relay_effective = relay != 0;
  out.observer = observer;
  out.observer_boot = boot;
  return Status::success();
}

// TransitFailure layout (80 B): prefix4 || ref_origin8 || ref_session4 ||
// ref_sequence8 || ref_destination8 || type1|round1|phase1|reason1 ||
// claimed_reporter8 || report_id4 || fingerprint32.
Status transit_failure_encode(const TransitFailure& report,
                              const MutableByteView out) noexcept {
  if (out.size != kTransitFailureBodySize ||
      report.ref_origin == kInvalidNodeId ||
      report.ref_origin == kBroadcastNodeId ||
      report.ref_destination == kInvalidNodeId ||
      report.ref_destination == kBroadcastNodeId ||
      report.claimed_reporter == kInvalidNodeId ||
      report.claimed_reporter == kBroadcastNodeId ||
      report.ref_session == 0 || report.ref_sequence == 0 ||
      report.report_id == 0 ||
      static_cast<std::uint8_t>(report.phase) > 2 ||
      static_cast<std::uint8_t>(report.reason) < 1 ||
      static_cast<std::uint8_t>(report.reason) > 11) {
    return reject();
  }
  ByteWriter writer{out};
  Status status = prefix_write(writer, DiagnosticSubtype::TransitFailure);
  if (!status) return status;
  status = writer.write_u64(report.ref_origin);
  if (!status) return status;
  status = writer.write_u32(report.ref_session);
  if (!status) return status;
  status = writer.write_u64(report.ref_sequence);
  if (!status) return status;
  status = writer.write_u64(report.ref_destination);
  if (!status) return status;
  status = writer.write_u8(report.ref_type);
  if (!status) return status;
  status = writer.write_u8(report.ref_round);
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(report.phase));
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(report.reason));
  if (!status) return status;
  status = writer.write_u64(report.claimed_reporter);
  if (!status) return status;
  status = writer.write_u32(report.report_id);
  if (!status) return status;
  return writer.write_bytes(
      ByteView{report.fingerprint.data(), report.fingerprint.size()});
}

Status transit_failure_decode(const ByteView body,
                              TransitFailure& out) noexcept {
  if (body.size != kTransitFailureBodySize) return reject();
  ByteReader reader{body};
  Status status = prefix_read(reader, DiagnosticSubtype::TransitFailure);
  if (!status) return status;
  std::uint8_t type = 0, round = 0, phase = 0, reason = 0;
  status = reader.read_u64(out.ref_origin);
  if (!status) return status;
  status = reader.read_u32(out.ref_session);
  if (!status) return status;
  status = reader.read_u64(out.ref_sequence);
  if (!status) return status;
  status = reader.read_u64(out.ref_destination);
  if (!status) return status;
  status = reader.read_u8(type);
  if (!status) return status;
  status = reader.read_u8(round);
  if (!status) return status;
  status = reader.read_u8(phase);
  if (!status) return status;
  status = reader.read_u8(reason);
  if (!status) return status;
  status = reader.read_u64(out.claimed_reporter);
  if (!status) return status;
  status = reader.read_u32(out.report_id);
  if (!status) return status;
  status = reader.read_bytes(
      MutableByteView{out.fingerprint.data(), out.fingerprint.size()});
  if (!status) return status;
  if (!expect_consumed(reader)) return reject();
  if (out.ref_origin == kInvalidNodeId || out.ref_origin == kBroadcastNodeId ||
      out.ref_destination == kInvalidNodeId ||
      out.ref_destination == kBroadcastNodeId ||
      out.claimed_reporter == kInvalidNodeId ||
      out.claimed_reporter == kBroadcastNodeId ||
      out.ref_session == 0 || out.ref_sequence == 0 || out.report_id == 0 ||
      phase > 2 || reason < 1 || reason > 11) {
    return reject();
  }
  out.ref_type = type;
  out.ref_round = round;
  out.phase = static_cast<TransitFailurePhase>(phase);
  out.reason = static_cast<TransitFailureReason>(reason);
  return Status::success();
}

}  // namespace routeloom
