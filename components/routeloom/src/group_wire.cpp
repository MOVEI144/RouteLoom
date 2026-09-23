// Group delivery payload codecs (GROUP_DATA flags header and GROUP_REPORT),
// docs/spec/wire-protocol.md and docs/design/sdk-v1/group-delivery.md. The
// Rust mirror is host/routeloom-wire/src/group.rs; the shared golden vectors
// protocol/golden/valid/group_{data,report}.json pin both.

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/group.hpp"

namespace routeloom {

// --- Payload codecs ---------------------------------------------------------------

Status encode_group_data(const GroupDataHeader& header, const ByteView app,
                         const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (app.size > kGroupPayloadMax || (app.size > 0 && app.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "group payload too large");
  }
  if (out.data == nullptr || out.size < kGroupDataHeaderBytes + app.size) {
    return Status::error(StatusCode::NoCapacity, "group payload output too small");
  }
  const auto priority = static_cast<std::uint8_t>(header.priority);
  if (priority > static_cast<std::uint8_t>(Priority::Urgent)) {
    return Status::error(StatusCode::InvalidArgument, "group priority");
  }
  out.data[0] = static_cast<std::uint8_t>((header.ordered ? kGroupFlagOrdered : 0U) |
                                          (priority << kGroupPriorityShift));
  if (app.size > 0) std::memcpy(out.data + kGroupDataHeaderBytes, app.data, app.size);
  written = kGroupDataHeaderBytes + app.size;
  return Status::success();
}

Status decode_group_data(const ByteView input, GroupDataHeader& header,
                         ByteView& app) noexcept {
  if (input.data == nullptr || input.size < kGroupDataHeaderBytes ||
      input.size > kMaxApplicationPayload) {
    return Status::error(StatusCode::ProtocolError, "group payload length");
  }
  const std::uint8_t flags = input.data[0];
  if ((flags & ~kGroupDataFlagsKnown) != 0) {
    return Status::error(StatusCode::ProtocolError, "group payload flags");
  }
  header.ordered = (flags & kGroupFlagOrdered) != 0;
  header.priority =
      static_cast<Priority>((flags & kGroupPriorityMask) >> kGroupPriorityShift);
  app = ByteView{input.data + kGroupDataHeaderBytes, input.size - kGroupDataHeaderBytes};
  return Status::success();
}

namespace {

Status check_group_report(const GroupReportPayload& payload) noexcept {
  if (reserved_node_id(payload.key.origin) || !is_group_sequence(payload.key.id.sequence)) {
    return Status::error(StatusCode::ProtocolError, "group report message");
  }
  if ((payload.flags & ~kGroupReportFlagsKnown) != 0 ||
      payload.missing_count > kGroupReportMissingMax ||
      payload.missing_count > payload.missing_total) {
    return Status::error(StatusCode::ProtocolError, "group report flags");
  }
  const bool truncated = (payload.flags & kGroupReportTruncated) != 0;
  if (truncated != (payload.missing_total > payload.missing_count)) {
    return Status::error(StatusCode::ProtocolError, "group report truncation");
  }
  if ((payload.flags & kGroupReportNotChild) != 0 &&
      (payload.delivered != 0 || payload.nonmember != 0 || payload.missing_total != 0)) {
    return Status::error(StatusCode::ProtocolError, "group report not-child counts");
  }
  for (std::size_t i = 0; i < payload.missing_count; ++i) {
    if (reserved_node_id(payload.missing[i])) {
      return Status::error(StatusCode::ProtocolError, "group report missing id");
    }
  }
  return Status::success();
}

}  // namespace

Status encode_group_report(const GroupReportPayload& payload, const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  auto status = check_group_report(payload);
  if (!status) {
    return Status::error(StatusCode::InvalidArgument, status.detail);
  }
  ByteWriter writer(out);
#define RL_WRITE_GR(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE_GR(writer.write_u64(payload.key.origin));
  RL_WRITE_GR(writer.write_u32(payload.key.id.session));
  RL_WRITE_GR(writer.write_u64(payload.key.id.sequence));
  RL_WRITE_GR(writer.write_u8(payload.round));
  RL_WRITE_GR(writer.write_u8(payload.flags));
  RL_WRITE_GR(writer.write_u16(payload.delivered));
  RL_WRITE_GR(writer.write_u16(payload.nonmember));
  RL_WRITE_GR(writer.write_u16(payload.missing_total));
  RL_WRITE_GR(writer.write_u8(payload.missing_count));
  for (std::size_t i = 0; i < payload.missing_count; ++i) {
    RL_WRITE_GR(writer.write_u64(payload.missing[i]));
  }
#undef RL_WRITE_GR
  written = writer.size();
  return Status::success();
}

Status decode_group_report(const ByteView input, GroupReportPayload& payload) noexcept {
  if (input.size < kGroupReportFixedBytes) {
    return Status::error(StatusCode::ProtocolError, "group report length");
  }
  ByteReader reader(input);
  GroupReportPayload decoded{};
  Status status;
#define RL_READ_GR(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ_GR(reader.read_u64(decoded.key.origin));
  RL_READ_GR(reader.read_u32(decoded.key.id.session));
  RL_READ_GR(reader.read_u64(decoded.key.id.sequence));
  RL_READ_GR(reader.read_u8(decoded.round));
  RL_READ_GR(reader.read_u8(decoded.flags));
  RL_READ_GR(reader.read_u16(decoded.delivered));
  RL_READ_GR(reader.read_u16(decoded.nonmember));
  RL_READ_GR(reader.read_u16(decoded.missing_total));
  RL_READ_GR(reader.read_u8(decoded.missing_count));
  if (decoded.missing_count > kGroupReportMissingMax ||
      input.size != kGroupReportFixedBytes + 8U * decoded.missing_count) {
    return Status::error(StatusCode::ProtocolError, "group report length");
  }
  for (std::size_t i = 0; i < decoded.missing_count; ++i) {
    RL_READ_GR(reader.read_u64(decoded.missing[i]));
  }
#undef RL_READ_GR
  status = check_group_report(decoded);
  if (!status) return status;
  payload = decoded;
  return Status::success();
}

}  // namespace routeloom
