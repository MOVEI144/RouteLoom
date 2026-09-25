#include "routeloom/bootstrap_transport.hpp"

#include <cstring>

namespace routeloom::sdkv1 {
namespace {

Status invalid(const char* detail) noexcept {
  return Status::error(StatusCode::InvalidArgument, detail);
}

Status malformed(const char* detail) noexcept {
  return Status::error(StatusCode::ProtocolError, detail);
}

void put_u16(std::uint8_t* p, const std::uint16_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 8U);
  p[1] = static_cast<std::uint8_t>(v);
}

void put_u32(std::uint8_t* p, const std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 24U);
  p[1] = static_cast<std::uint8_t>(v >> 16U);
  p[2] = static_cast<std::uint8_t>(v >> 8U);
  p[3] = static_cast<std::uint8_t>(v);
}

std::uint16_t get_u16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
}

std::uint32_t get_u32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) | (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}

bool end_step_ok(const JoinAuthPhase phase, const std::uint8_t step) noexcept {
  // Member EDHOC runs m1..m4 (no step-5 error object), RLRES1 R1..R3.
  return (phase == JoinAuthPhase::EdhocMessage && step >= 1 && step <= 4) ||
         (phase == JoinAuthPhase::Resume && step >= 1 && step <= 3);
}

}  // namespace

Status end_object_validate(const EndObject& object) noexcept {
  if (object.phase != JoinAuthPhase::EdhocMessage && object.phase != JoinAuthPhase::Resume) {
    return invalid("end object phase");
  }
  if (!end_step_ok(object.phase, object.step)) return invalid("end object step");
  if (object.exchange_id == 0) return invalid("end object exchange");
  if (object.profile != kEndProfileMember && object.profile != kEndProfileDev) {
    return invalid("end object profile");
  }
  if (object.message.size == 0 || object.message.size > kJoinMessageMax ||
      object.message.data == nullptr) {
    return invalid("end object message");
  }
  return Status::success();
}

std::size_t end_object_encoded_size(const EndObject& object) noexcept {
  return kEndObjectHeaderSize + object.message.size;
}

Status end_object_encode(const EndObject& object, const MutableByteView out,
                         std::size_t& written) noexcept {
  written = 0;
  const Status status = end_object_validate(object);
  if (!status) return status;
  const std::size_t size = end_object_encoded_size(object);
  if (out.data == nullptr || out.size < size) {
    return Status::error(StatusCode::NoCapacity, "end object output");
  }
  std::uint8_t* p = out.data;
  p[0] = kEndObjectVersion;
  p[1] = static_cast<std::uint8_t>(object.phase);
  p[2] = object.step;
  p[3] = 0;
  put_u32(p + 4, object.exchange_id);
  p[8] = kSessionPurposeEnd;
  p[9] = object.profile;
  put_u16(p + 10, static_cast<std::uint16_t>(object.message.size));
  std::memcpy(p + kEndObjectHeaderSize, object.message.data, object.message.size);
  written = size;
  return Status::success();
}

Status end_object_decode(const ByteView encoded, EndObject& out) noexcept {
  if (encoded.data == nullptr || encoded.size <= kEndObjectHeaderSize ||
      encoded.size > kEndObjectMax || encoded.data[0] != kEndObjectVersion ||
      encoded.data[3] != 0) {
    return malformed("end object head");
  }
  const std::uint8_t phase = encoded.data[1];
  if (phase != static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) &&
      phase != static_cast<std::uint8_t>(JoinAuthPhase::Resume)) {
    return malformed("end object phase");
  }
  EndObject object{};
  object.phase = static_cast<JoinAuthPhase>(phase);
  object.step = encoded.data[2];
  object.exchange_id = get_u32(encoded.data + 4);
  // Purpose is pinned to End (2): a link object on this lane is a
  // cross-protocol error, not a decodable alternative.
  if (encoded.data[8] != kSessionPurposeEnd) return malformed("end object purpose");
  object.profile = encoded.data[9];
  const std::uint16_t length = get_u16(encoded.data + 10);
  if (length == 0 || length > kJoinMessageMax ||
      static_cast<std::size_t>(length) + kEndObjectHeaderSize != encoded.size) {
    return malformed("end object length");
  }
  object.message = ByteView{encoded.data + kEndObjectHeaderSize, length};
  const Status status = end_object_validate(object);
  if (!status) return Status::error(StatusCode::ProtocolError, status.detail);
  out = object;
  return Status::success();
}

Status end_single_frame_decode(const FrameType type, const ByteView payload,
                               EndObject& out) noexcept {
  // Type 4 (MembershipResult) is join-relay Final/Abort only; an end object
  // there is a lane violation even when the bytes would parse.
  if (type != kEndSingleFrameType) return malformed("end object frame");
  return end_object_decode(payload, out);
}

bool BootstrapBudgets::admit_link_resume(const MonotonicMs now_ms) noexcept {
  refill(link_tokens_, kLinkResumePerSecond, kLinkResumePerSecond, link_started_, last_link_ms_,
         now_ms);
  if (link_tokens_ == 0) return false;
  --link_tokens_;
  return true;
}

bool BootstrapBudgets::admit_end_resume(const MonotonicMs now_ms) noexcept {
  refill(end_tokens_, kEndResumePerSecond, kEndResumeBurst, end_started_, last_end_ms_, now_ms);
  if (end_tokens_ == 0) return false;
  --end_tokens_;
  return true;
}

void BootstrapBudgets::refill(std::uint32_t& tokens, const std::uint32_t rate_per_s,
                              const std::uint32_t burst, bool& started, MonotonicMs& last_ms,
                              const MonotonicMs now_ms) noexcept {
  if (!started) {
    started = true;
    last_ms = now_ms;
    return;
  }
  // A backwards clock consumes nothing and grants nothing new: the caller
  // still spends from the current balance (fail-closed, no time windfall).
  if (now_ms < last_ms) return;
  // Overflow-free refill in two steps; sub-token elapsed time stays in
  // last_ms so fractional progress is never lost between admits.
  const std::uint64_t elapsed = now_ms - last_ms;
  const std::uint64_t add =
      (elapsed / 1000U) * rate_per_s + ((elapsed % 1000U) * rate_per_s) / 1000U;
  if (add == 0) return;
  if (static_cast<std::uint64_t>(tokens) + add >= burst) {
    tokens = burst;
    last_ms = now_ms;  // full: the remainder is meaningless
    return;
  }
  tokens = static_cast<std::uint32_t>(static_cast<std::uint64_t>(tokens) + add);
  last_ms += (add * 1000U) / rate_per_s;
}

}  // namespace routeloom::sdkv1
