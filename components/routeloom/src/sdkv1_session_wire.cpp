#include "routeloom/sdkv1_session_wire.hpp"

#include <cstring>

namespace routeloom::sdkv1 {
namespace {

bool all_zero_bytes(const ByteView view) noexcept {
  for (std::size_t i = 0; i < view.size; ++i) {
    if (view.data[i] != 0) return false;
  }
  return true;
}

void put_u32(std::uint8_t* at, const std::uint32_t value) noexcept {
  at[0] = static_cast<std::uint8_t>(value >> 24U);
  at[1] = static_cast<std::uint8_t>(value >> 16U);
  at[2] = static_cast<std::uint8_t>(value >> 8U);
  at[3] = static_cast<std::uint8_t>(value);
}

std::uint32_t get_u32(const std::uint8_t* at) noexcept {
  return (static_cast<std::uint32_t>(at[0]) << 24U) | (static_cast<std::uint32_t>(at[1]) << 16U) |
         (static_cast<std::uint32_t>(at[2]) << 8U) | static_cast<std::uint32_t>(at[3]);
}

// The shared 4-byte item head: ver=1, purpose 1/2, profile=1, flags=0.
// A head this strict has no room for "unknown but ignorable".
bool head_ok(const std::uint8_t* at, std::uint8_t& purpose, std::uint8_t& profile) noexcept {
  purpose = at[1];
  profile = at[2];
  return at[0] == 1 && (purpose == kSessionPurposeLink || purpose == kSessionPurposeEnd) &&
         profile == kSessionProfileMember && at[3] == 0;
}

void head_put(std::uint8_t* at, const std::uint8_t purpose) noexcept {
  at[0] = 1;
  at[1] = purpose;
  at[2] = kSessionProfileMember;
  at[3] = 0;
}

// Minimal definite-length CBOR writer (major types 0/2/3/4 only).
class CborWriter {
 public:
  explicit CborWriter(MutableByteView target) noexcept : target_(target) {}
  bool ok() const noexcept { return ok_; }
  std::size_t used() const noexcept { return used_; }

  void uint(const std::uint64_t value) noexcept { head(0, value); }
  void bstr(const ByteView bytes) noexcept {
    head(2, bytes.size);
    put(bytes);
  }
  void text(const char* value, const std::size_t size) noexcept {
    head(3, size);
    put(ByteView{reinterpret_cast<const std::uint8_t*>(value), size});
  }
  void array(const std::size_t count) noexcept { head(4, count); }

 private:
  void reserve(const std::size_t count) noexcept {
    if (!ok_ || count > target_.size - used_) ok_ = false;
  }
  void put(const ByteView bytes) noexcept {
    reserve(bytes.size);
    if (!ok_) return;
    if (bytes.size != 0) std::memcpy(target_.data + used_, bytes.data, bytes.size);
    used_ += bytes.size;
  }
  void head(const std::uint8_t major, const std::uint64_t value) noexcept {
    std::uint8_t encoded[9];
    std::size_t size = 0;
    if (value < 24) {
      encoded[0] = static_cast<std::uint8_t>((major << 5U) | value);
      size = 1;
    } else if (value <= 0xFF) {
      encoded[0] = static_cast<std::uint8_t>((major << 5U) | 24U);
      encoded[1] = static_cast<std::uint8_t>(value);
      size = 2;
    } else if (value <= 0xFFFF) {
      encoded[0] = static_cast<std::uint8_t>((major << 5U) | 25U);
      encoded[1] = static_cast<std::uint8_t>(value >> 8U);
      encoded[2] = static_cast<std::uint8_t>(value);
      size = 3;
    } else if (value <= 0xFFFFFFFFULL) {
      encoded[0] = static_cast<std::uint8_t>((major << 5U) | 26U);
      for (std::size_t i = 0; i < 4; ++i) {
        encoded[1 + i] = static_cast<std::uint8_t>(value >> (24U - 8U * i));
      }
      size = 5;
    } else {
      encoded[0] = static_cast<std::uint8_t>((major << 5U) | 27U);
      for (std::size_t i = 0; i < 8; ++i) {
        encoded[1 + i] = static_cast<std::uint8_t>(value >> (56U - 8U * i));
      }
      size = 9;
    }
    put(ByteView{encoded, size});
  }

  MutableByteView target_{nullptr, 0};
  std::size_t used_{0};
  bool ok_{true};
};

}  // namespace

Status session_intent_encode(const SessionIntent& intent,
                             std::array<std::uint8_t, kSessionIntentBytes>& out) noexcept {
  out.fill(0);
  if ((intent.purpose != kSessionPurposeLink && intent.purpose != kSessionPurposeEnd) ||
      intent.profile != kSessionProfileMember || intent.boot_i == 0 ||
      all_zero_bytes(ByteView{intent.binding.data(), intent.binding.size()})) {
    return Status::error(StatusCode::InvalidArgument, "session intent fields");
  }
  head_put(out.data(), intent.purpose);
  put_u32(out.data() + 4, intent.caps_i);
  put_u32(out.data() + 8, intent.boot_i);
  std::memcpy(out.data() + 12, intent.binding.data(), intent.binding.size());
  return Status::success();
}

Status session_intent_decode(const ByteView bytes, SessionIntent& out) noexcept {
  out = SessionIntent{};
  if (bytes.data == nullptr || bytes.size != kSessionIntentBytes) {
    return Status::error(StatusCode::ProtocolError, "session intent size");
  }
  std::uint8_t purpose = 0, profile = 0;
  if (!head_ok(bytes.data, purpose, profile)) {
    return Status::error(StatusCode::ProtocolError, "session intent version");
  }
  out.purpose = purpose;
  out.profile = profile;
  out.caps_i = get_u32(bytes.data + 4);
  out.boot_i = get_u32(bytes.data + 8);
  std::memcpy(out.binding.data(), bytes.data + 12, out.binding.size());
  if (out.boot_i == 0 ||
      all_zero_bytes(ByteView{out.binding.data(), out.binding.size()})) {
    out = SessionIntent{};
    return Status::error(StatusCode::ProtocolError, "session intent binding");
  }
  return Status::success();
}

Status session_state_encode(const SessionState& state,
                            std::array<std::uint8_t, kSessionStateBytes>& out) noexcept {
  out.fill(0);
  if ((state.purpose != kSessionPurposeLink && state.purpose != kSessionPurposeEnd) ||
      state.profile != kSessionProfileMember || state.boot == 0) {
    return Status::error(StatusCode::InvalidArgument, "session state fields");
  }
  head_put(out.data(), state.purpose);
  put_u32(out.data() + 4, state.site_epoch);
  put_u32(out.data() + 8, state.rs_epoch);
  put_u32(out.data() + 12, state.gk_epoch);
  put_u32(out.data() + 16, state.boot);
  put_u32(out.data() + 20, state.caps);
  return Status::success();
}

Status session_state_decode(const ByteView bytes, SessionState& out) noexcept {
  out = SessionState{};
  if (bytes.data == nullptr || bytes.size != kSessionStateBytes) {
    return Status::error(StatusCode::ProtocolError, "session state size");
  }
  std::uint8_t purpose = 0, profile = 0;
  if (!head_ok(bytes.data, purpose, profile)) {
    return Status::error(StatusCode::ProtocolError, "session state version");
  }
  out.purpose = purpose;
  out.profile = profile;
  out.site_epoch = get_u32(bytes.data + 4);
  out.rs_epoch = get_u32(bytes.data + 8);
  out.gk_epoch = get_u32(bytes.data + 12);
  out.boot = get_u32(bytes.data + 16);
  out.caps = get_u32(bytes.data + 20);
  if (out.boot == 0) {
    out = SessionState{};
    return Status::error(StatusCode::ProtocolError, "session state boot");
  }
  return Status::success();
}

Status context_confirm_encode(const ContextConfirm& confirm,
                              std::array<std::uint8_t, kContextConfirmBytes>& out) noexcept {
  out.fill(0);
  if ((confirm.purpose != kSessionPurposeLink && confirm.purpose != kSessionPurposeEnd) ||
      confirm.profile != kSessionProfileMember ||
      all_zero_bytes(ByteView{confirm.contexts_digest.data(), confirm.contexts_digest.size()})) {
    return Status::error(StatusCode::InvalidArgument, "context confirm fields");
  }
  head_put(out.data(), confirm.purpose);
  std::memcpy(out.data() + 4, confirm.contexts_digest.data(), confirm.contexts_digest.size());
  return Status::success();
}

Status context_confirm_decode(const ByteView bytes, ContextConfirm& out) noexcept {
  out = ContextConfirm{};
  if (bytes.data == nullptr || bytes.size != kContextConfirmBytes) {
    return Status::error(StatusCode::ProtocolError, "context confirm size");
  }
  std::uint8_t purpose = 0, profile = 0;
  if (!head_ok(bytes.data, purpose, profile)) {
    return Status::error(StatusCode::ProtocolError, "context confirm version");
  }
  out.purpose = purpose;
  out.profile = profile;
  std::memcpy(out.contexts_digest.data(), bytes.data + 4, out.contexts_digest.size());
  if (all_zero_bytes(ByteView{out.contexts_digest.data(), out.contexts_digest.size()})) {
    out = ContextConfirm{};
    return Status::error(StatusCode::ProtocolError, "context confirm digest");
  }
  return Status::success();
}

Status exporter_context_encode(const ExporterContextParams& params,
                               std::array<std::uint8_t, kExporterContextMax>& out,
                               std::size_t& used) noexcept {
  out.fill(0);
  used = 0;
  // Every field is sender-chosen or peer-verified before this call; the
  // builder still refuses the shapes that must never bind.
  if ((params.purpose != 1 && params.purpose != 2) || params.network == 0 ||
      params.node_i == kInvalidNodeId || params.node_r == kInvalidNodeId ||
      params.node_i == kBroadcastNodeId || params.node_r == kBroadcastNodeId ||
      params.node_i == params.node_r || params.role_i == 0 || params.role_r == 0 ||
      params.generation_i == 0 || params.generation_r == 0 || params.direction > 2 ||
      (params.direction == 0 && params.context_epoch != 0) ||
      (params.direction != 0 && params.context_epoch == 0)) {
    return Status::error(StatusCode::InvalidArgument, "exporter context fields");
  }
  CborWriter writer(MutableByteView{out.data(), out.size()});
  writer.array(15);
  writer.text("RouteLoom", 9);
  writer.uint(1);
  writer.uint(params.purpose);
  writer.uint(params.network);
  writer.uint(params.node_i);
  writer.uint(params.node_r);
  writer.bstr(ByteView{params.kid_i.data(), params.kid_i.size()});
  writer.bstr(ByteView{params.kid_r.data(), params.kid_r.size()});
  writer.uint(params.role_i);
  writer.uint(params.role_r);
  writer.array(2);
  writer.uint(params.generation_i);
  writer.uint(params.generation_r);
  writer.array(2);
  writer.uint(2);
  writer.uint(0);
  writer.uint(params.context_epoch);
  writer.uint(params.direction);
  writer.bstr(ByteView{params.capability_digest.data(), params.capability_digest.size()});
  if (!writer.ok()) return Status::error(StatusCode::NoCapacity, "exporter context oversized");
  used = writer.used();
  return Status::success();
}

Status edhoc_kdf_info_encode(const std::uint32_t label, const ByteView context,
                             const std::uint32_t length,
                             std::array<std::uint8_t, kEdhocKdfInfoMax>& out,
                             std::size_t& used) noexcept {
  out.fill(0);
  used = 0;
  if (context.data == nullptr || context.size == 0 || context.size > kExporterContextMax) {
    return Status::error(StatusCode::InvalidArgument, "edhoc kdf info shape");
  }
  CborWriter writer(MutableByteView{out.data(), out.size()});
  writer.uint(label);
  writer.bstr(context);
  writer.uint(length);
  if (!writer.ok()) return Status::error(StatusCode::NoCapacity, "edhoc kdf info oversized");
  used = writer.used();
  return Status::success();
}

}  // namespace routeloom::sdkv1
