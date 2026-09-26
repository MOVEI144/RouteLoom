#include "routeloom/bench/protocol.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/status.hpp"

namespace routeloom::bench {

bool opcode_known(std::uint8_t opcode) noexcept {
  switch (static_cast<Opcode>(opcode)) {
    case Opcode::Hello:
    case Opcode::Capabilities:
    case Opcode::EchoRequest:
    case Opcode::EchoReply:
    case Opcode::CountOnly:
    case Opcode::CountGet:
    case Opcode::CountStatus:
    case Opcode::Rollcall:
    case Opcode::StatusGet:
    case Opcode::Status:
    case Opcode::PeerSendStart:
    case Opcode::PeerSendStatus:
    case Opcode::PeerSendStop:
    case Opcode::CounterReset:
    case Opcode::FaultSet:
    case Opcode::ResetRequest:
    case Opcode::ResetAck:
      return true;
  }
  return false;
}

bool opcode_is_reply(std::uint8_t opcode) noexcept {
  switch (static_cast<Opcode>(opcode)) {
    case Opcode::Capabilities:
    case Opcode::EchoReply:
    case Opcode::CountStatus:
    case Opcode::Status:
    case Opcode::PeerSendStatus:
    case Opcode::ResetAck:
      return true;
    default:
      return false;
  }
}

DecodeError decode(ByteView wire, Message& out) noexcept {
  if (wire.size < kHeaderSize) return DecodeError::Truncated;
  if (std::memcmp(wire.data, kMagic.data(), kMagic.size()) != 0) {
    return DecodeError::BadMagic;
  }
  ByteReader reader{ByteView{wire.data + kMagic.size(), wire.size - kMagic.size()}};
  std::uint8_t version = 0;
  if (!reader.read_u8(version)) return DecodeError::Truncated;
  if (version != kProtocolVersion) return DecodeError::UnsupportedVersion;
  if (!reader.read_u8(out.opcode) || !reader.read_u16(out.flags)) {
    return DecodeError::Truncated;
  }
  if (!reader.read_bytes(MutableByteView{out.run.data(), out.run.size()}) ||
      !reader.read_u32(out.sequence)) {
    return DecodeError::Truncated;
  }
  std::uint32_t crc = 0;
  if (!reader.read_u32(crc)) return DecodeError::Truncated;
  out.body = ByteView{wire.data + kHeaderSize, wire.size - kHeaderSize};
  if (crc32_iso_hdlc(out.body) != crc) return DecodeError::CrcMismatch;
  return DecodeError::Ok;
}

Status encode(std::uint8_t opcode, std::uint16_t flags, const RunUuid& run,
              std::uint32_t sequence, ByteView body, MutableByteView out,
              std::size_t& written) noexcept {
  written = 0;
  if (body.size > kMaxBody) {
    return Status::error(StatusCode::InvalidArgument, "bench body > 96 B");
  }
  if (out.size < kHeaderSize + body.size) {
    return Status::error(StatusCode::NoCapacity, "bench encode buffer");
  }
  std::memcpy(out.data, kMagic.data(), kMagic.size());
  ByteWriter writer{MutableByteView{out.data + kMagic.size(), out.size - kMagic.size()}};
  Status status = writer.write_u8(kProtocolVersion);
  if (status) status = writer.write_u8(opcode);
  if (status) status = writer.write_u16(flags);
  if (status) {
    status = writer.write_bytes(ByteView{run.data(), run.size()});
  }
  if (status) status = writer.write_u32(sequence);
  if (status) status = writer.write_u32(crc32_iso_hdlc(body));
  if (status) status = writer.write_bytes(body);
  if (!status) return status;
  written = kHeaderSize + body.size;
  return Status::success();
}

Status encode(const CapabilitiesBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u8(body.app_protocol);
  if (status) status = out.write_u8(body.app_version);
  if (status) status = out.write_u8(body.max_unicast_body);
  if (status) status = out.write_u8(body.max_group_body);
  if (status) status = out.write_u8(body.max_command_body);
  if (status) status = out.write_u8(body.run_slots);
  if (status) status = out.write_u8(body.reply_queue);
  if (status) status = out.write_u8(body.generator_max_inflight);
  if (status) status = out.write_u64(body.boot_incarnation);
  if (status) status = out.write_u32(body.firmware_digest);
  if (status) status = out.write_u32(body.config_digest);
  if (status) status = out.write_u8(body.opcode_count);
  const std::uint8_t count = body.opcode_count < body.opcodes.size()
                                 ? body.opcode_count
                                 : static_cast<std::uint8_t>(body.opcodes.size());
  for (std::uint8_t i = 0; i < count; ++i) {
    if (status) status = out.write_u8(body.opcodes[i]);
  }
  return status;
}

bool decode(ByteReader& in, CapabilitiesBody& out) noexcept {
  if (!in.read_u8(out.app_protocol) || !in.read_u8(out.app_version) ||
      !in.read_u8(out.max_unicast_body) || !in.read_u8(out.max_group_body) ||
      !in.read_u8(out.max_command_body) || !in.read_u8(out.run_slots) ||
      !in.read_u8(out.reply_queue) || !in.read_u8(out.generator_max_inflight) ||
      !in.read_u64(out.boot_incarnation) || !in.read_u32(out.firmware_digest) ||
      !in.read_u32(out.config_digest) || !in.read_u8(out.opcode_count)) {
    return false;
  }
  if (out.opcode_count > out.opcodes.size()) return false;
  for (std::uint8_t i = 0; i < out.opcode_count; ++i) {
    if (!in.read_u8(out.opcodes[i])) return false;
  }
  return in.remaining() == 0;
}

Status encode(const CountStatusBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u8(body.state);
  if (status) status = out.write_u32(body.unique_packets);
  if (status) status = out.write_u32(body.unique_bytes);
  if (status) status = out.write_u32(body.duplicates);
  if (status) status = out.write_u32(body.crc_invalid);
  if (status) status = out.write_u32(body.first_ms);
  if (status) status = out.write_u32(body.last_ms);
  if (status) status = out.write_u32(body.window_base);
  if (status) status = out.write_u64(body.window);
  return status;
}

bool decode(ByteReader& in, CountStatusBody& out) noexcept {
  if (!in.read_u8(out.state) || !in.read_u32(out.unique_packets) ||
      !in.read_u32(out.unique_bytes) || !in.read_u32(out.duplicates) ||
      !in.read_u32(out.crc_invalid) || !in.read_u32(out.first_ms) ||
      !in.read_u32(out.last_ms) || !in.read_u32(out.window_base) ||
      !in.read_u64(out.window)) {
    return false;
  }
  return in.remaining() == 0;
}

Status encode_status_head(const StatusBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u16(body.sample_seq);
  if (status) status = out.write_u64(body.boot_incarnation);
  if (status) status = out.write_u8(body.page);
  if (status) status = out.write_u8(body.page_count);
  return status;
}

Status encode(const PeerSendStartBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u64(body.expected_boot);
  if (status) status = out.write_u64(body.destination);
  if (status) status = out.write_u32(body.sequence_begin);
  if (status) status = out.write_u16(body.count);
  if (status) status = out.write_u8(body.payload_len);
  if (status) status = out.write_u32(body.seed);
  if (status) status = out.write_u32(body.interval_ms);
  if (status) status = out.write_u32(body.ttl_ms);
  if (status) status = out.write_u8(body.max_inflight);
  return status;
}

bool decode(ByteReader& in, PeerSendStartBody& out) noexcept {
  if (!in.read_u64(out.expected_boot) || !in.read_u64(out.destination) ||
      !in.read_u32(out.sequence_begin) || !in.read_u16(out.count) ||
      !in.read_u8(out.payload_len) || !in.read_u32(out.seed) ||
      !in.read_u32(out.interval_ms) || !in.read_u32(out.ttl_ms) ||
      !in.read_u8(out.max_inflight)) {
    return false;
  }
  return in.remaining() == 0;
}

Status encode(const PeerSendStatusBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u8(body.result);
  if (status) status = out.write_u8(body.state);
  if (status) status = out.write_u16(body.planned);
  if (status) status = out.write_u16(body.submitted);
  if (status) status = out.write_u16(body.admitted);
  if (status) status = out.write_u16(body.delivered);
  if (status) status = out.write_u16(body.failed);
  if (status) status = out.write_u16(body.unknown);
  if (status) status = out.write_u32(body.first_ms);
  if (status) status = out.write_u32(body.last_ms);
  return status;
}

bool decode(ByteReader& in, PeerSendStatusBody& out) noexcept {
  if (!in.read_u8(out.result) || !in.read_u8(out.state) ||
      !in.read_u16(out.planned) || !in.read_u16(out.submitted) ||
      !in.read_u16(out.admitted) || !in.read_u16(out.delivered) ||
      !in.read_u16(out.failed) || !in.read_u16(out.unknown) ||
      !in.read_u32(out.first_ms) || !in.read_u32(out.last_ms)) {
    return false;
  }
  return in.remaining() == 0;
}

Status encode(const ExpectedBootBody& body, ByteWriter& out) noexcept {
  return out.write_u64(body.expected_boot);
}

bool decode(ByteReader& in, ExpectedBootBody& out) noexcept {
  if (!in.read_u64(out.expected_boot)) return false;
  return in.remaining() == 0;
}

Status encode(const FaultSetBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u64(body.expected_boot);
  if (status) status = out.write_u8(body.fault);
  if (status) status = out.write_u32(body.duration_ms);
  if (status) status = out.write_u32(body.param);
  return status;
}

bool decode(ByteReader& in, FaultSetBody& out) noexcept {
  if (!in.read_u64(out.expected_boot) || !in.read_u8(out.fault) ||
      !in.read_u32(out.duration_ms) || !in.read_u32(out.param)) {
    return false;
  }
  return in.remaining() == 0;
}

Status encode(const ResetRequestBody& body, ByteWriter& out) noexcept {
  Status status = out.write_u64(body.expected_boot);
  if (status) status = out.write_u32(body.delay_ms);
  return status;
}

bool decode(ByteReader& in, ResetRequestBody& out) noexcept {
  if (!in.read_u64(out.expected_boot) || !in.read_u32(out.delay_ms)) {
    return false;
  }
  return in.remaining() == 0;
}

Status encode(const ResetAckBody& body, ByteWriter& out) noexcept {
  return out.write_u8(body.accepted);
}

bool decode(ByteReader& in, ResetAckBody& out) noexcept {
  if (!in.read_u8(out.accepted)) return false;
  return in.remaining() == 0;
}

Status encode_page_body(std::uint8_t page, ByteWriter& out) noexcept {
  return out.write_u8(page);
}

bool decode_page_body(ByteReader& in, std::uint8_t& page) noexcept {
  if (!in.read_u8(page)) return false;
  return in.remaining() == 0;
}

}  // namespace routeloom::bench
