#include "routeloom/usb_bridge.hpp"
#include <algorithm>
#include <cstring>
#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"

namespace routeloom::usb {
Status UsbBridge::attach_object(AppObject& object) noexcept {
  if (object_ != nullptr) return Status::error(StatusCode::AlreadyExists, "object bridge attached");
  const auto registered = object.register_buffer({object_rx_.data(), object_rx_.size()});
  if (!registered) return registered;
  object_ = &object; config_.capability |= kCapAppObjectV1;
  return Status::success();
}
void UsbBridge::object_status(std::uint64_t request, StatusCode code, MonotonicMs now_ms, std::uint32_t token) noexcept {
  std::array<std::uint8_t, 13> bytes{}; ByteWriter writer({bytes.data(), bytes.size()});
  (void)writer.write_u8(kHostOpsSchema); (void)writer.write_u8(static_cast<std::uint8_t>(HostOpsSub::ObjectStatus));
  const bool matches = token == object_token_;
  (void)writer.write_u32(token); (void)writer.write_u8(matches ? object_phase_ : 0);
  (void)writer.write_u16(static_cast<std::uint16_t>(code)); (void)writer.write_u32(matches ? object_id_ : 0);
  (void)enqueue(FrameKind::HostOps, 0, request, {bytes.data(), writer.size()}, now_ms);
}
void UsbBridge::handle_object(std::uint64_t request, ByteView inner, MonotonicMs now_ms) noexcept {
  if (object_ == nullptr || inner.size < 6) { object_status(request, StatusCode::Unsupported, now_ms); return; }
  ByteReader reader(inner); std::uint8_t schema = 0, sub = 0; std::uint32_t token = 0;
  (void)reader.read_u8(schema); (void)reader.read_u8(sub); (void)reader.read_u32(token);
  if (token == 0) { object_status(request, StatusCode::InvalidArgument, now_ms, token); return; }
  const auto command = static_cast<HostOpsSub>(sub);
  if (command == HostOpsSub::ObjectBegin) {
    NodeId destination = 0; ObjectOptions options{}; std::uint16_t total = 0;
    if (inner.size != 23 || !reader.read_u64(destination) || !reader.read_u32(options.deadline_ms) ||
        !reader.read_u16(options.app_tag) || !reader.read_u8(options.content_encoding) || !reader.read_u16(total) ||
        total == 0 || total > object_io_.size() || destination == 0 || destination == config_.mesh->node_id() ||
        options.deadline_ms == 0 || options.deadline_ms > 120000) {
      object_status(request, total > object_io_.size() ? StatusCode::TooLarge : StatusCode::InvalidArgument, now_ms, token); return;
    }
    const bool same = object_token_ == token && object_destination_ == destination && object_total_ == total &&
        object_options_.deadline_ms == options.deadline_ms && object_options_.app_tag == options.app_tag &&
        object_options_.content_encoding == options.content_encoding;
    if (object_phase_ == 1 || object_phase_ == 2) {
      object_status(request, same ? StatusCode::Ok : StatusCode::Busy, now_ms, token); return;
    }
    // A token cannot start a second mesh operation in this HostLink session.
    if (object_token_ != 0 && token <= object_token_) {
      object_status(request, token == object_token_ ? (same ? object_reason_ : StatusCode::Conflict) : StatusCode::Expired, now_ms, token);
      return;
    }
    // Upload and callback egress share one arena. Reserve its lifetime
    // before accepting BEGIN, including any already-admitted mesh RX.
    if (object_up_size_ != 0 || !object_->quiescent()) {
      object_status(request, StatusCode::Busy, now_ms, token); return;
    }
    object_token_ = token; object_id_ = 0; object_destination_ = destination;
    object_options_ = options; object_total_ = total; object_received_ = 0;
    object_deadline_ms_ = now_ms + options.deadline_ms; object_phase_ = 1; object_reason_ = StatusCode::Ok;
  } else {
    if (object_token_ != token) { object_status(request, StatusCode::NotFound, now_ms, token); return; }
    if (command == HostOpsSub::ObjectChunk) {
      std::uint16_t offset = 0, count = 0;
      if (!reader.read_u16(offset) || !reader.read_u16(count) || count == 0 || count > 512 ||
          reader.remaining() != count || offset > object_received_ || count > object_total_ ||
          offset > object_total_ - count || object_phase_ != 1) {
        object_status(request, StatusCode::InvalidArgument, now_ms, token); return;
      }
      const std::uint8_t* data = inner.data + reader.consumed();
      if (offset < object_received_) {
        if (count > object_received_ - offset || std::memcmp(object_io_.data() + offset, data, count) != 0) {
          object_phase_ = 7; object_reason_ = StatusCode::Conflict;
          std::memset(object_io_.data(), 0, object_io_.size());
          object_status(request, object_reason_, now_ms, token); return;
        }
      } else {
        std::memcpy(object_io_.data() + offset, data, count); object_received_ += count;
      }
    } else if (command == HostOpsSub::ObjectEnd) {
      if (inner.size != 6) { object_status(request, StatusCode::InvalidArgument, now_ms, token); return; }
      if (object_phase_ == 1) {
        if (object_received_ != object_total_ || now_ms >= object_deadline_ms_) {
          object_status(request, StatusCode::InvalidState, now_ms, token); return;
        }
        auto options = object_options_;
        options.deadline_ms = static_cast<std::uint32_t>(object_deadline_ms_ - now_ms);
        const auto sent = object_->send(object_destination_, {object_io_.data(), object_total_}, options, now_ms, object_id_);
        if (!sent) { object_status(request, sent.code, now_ms, token); return; }
        object_phase_ = 2;
      }
    } else if (command == HostOpsSub::ObjectCancel) {
      if (inner.size != 6) { object_status(request, StatusCode::InvalidArgument, now_ms, token); return; }
      if (object_phase_ == 2) {
        const auto cancelled = object_->cancel(object_id_);
        if (!cancelled) { object_status(request, cancelled.code, now_ms, token); return; }
      } else if (object_phase_ == 1) {
        object_phase_ = 5; std::memset(object_io_.data(), 0, object_io_.size());
      }
    } else if (command != HostOpsSub::ObjectGet || inner.size != 6) {
      object_status(request, StatusCode::InvalidArgument, now_ms, token); return;
    }
  }
  object_status(request, object_reason_, now_ms, token);
}
void UsbBridge::on_object_result(const ObjectResult& result) noexcept {
  if (object_phase_ != 2 || result.id != object_id_) return;
  object_phase_ = static_cast<std::uint8_t>(result.state) + 2; object_reason_ = result.reason;
  std::memset(object_io_.data(), 0, object_io_.size());
}
void UsbBridge::on_object(const ObjectRxInfo& info, ByteView data) noexcept {
  // The radio receive view ends with the callback. Keep one bounded USB
  // egress copy; a disconnected host must not leave this arena indefinitely.
  if (state_ != SessionState::Active || object_up_size_ != 0 || data.size > object_io_.size()) return;
  std::memcpy(object_io_.data(), data.data, data.size);
  object_up_deadline_ms_ = object_now_ms_ + 10000;
  object_up_info_ = info; object_up_size_ = static_cast<std::uint16_t>(data.size); object_up_offset_ = 0;
  ScopeDigest digest{}; sha256(data, digest);
  std::copy_n(digest.begin(), object_up_digest_.size(), object_up_digest_.begin());
}
void UsbBridge::pump_object(MonotonicMs now_ms) noexcept {
  object_now_ms_ = now_ms;
  if (object_up_size_ != 0 && now_ms >= object_up_deadline_ms_) {
    object_up_size_ = object_up_offset_ = 0;
    std::memset(object_io_.data(), 0, object_io_.size());
  }
  if (object_phase_ == 1 && now_ms >= object_deadline_ms_) {
    object_phase_ = 4; object_reason_ = StatusCode::Expired;
    std::memset(object_io_.data(), 0, object_io_.size());
  }
  if (state_ != SessionState::Active || object_up_size_ == 0) return;
  const auto count = std::min<std::uint16_t>(512, object_up_size_ - object_up_offset_);
  std::array<std::uint8_t, 560> bytes{}; ByteWriter w({bytes.data(), bytes.size()});
  (void)w.write_u8(kHostOpsSchema); (void)w.write_u8(static_cast<std::uint8_t>(HostOpsSub::ObjectIngress));
  (void)w.write_u64(object_up_info_.source); (void)w.write_u32(object_up_info_.id);
  (void)w.write_u32(object_up_info_.source_boot); (void)w.write_u32(object_up_info_.end_context);
  (void)w.write_u16(object_up_info_.app_tag); (void)w.write_u8(object_up_info_.content_encoding);
  (void)w.write_u16(object_up_size_); (void)w.write_u16(object_up_offset_); (void)w.write_u16(count);
  (void)w.write_bytes({object_up_digest_.data(), object_up_digest_.size()});
  (void)w.write_bytes({object_io_.data() + object_up_offset_, count});
  if (enqueue(FrameKind::HostOps, 0, 0, {bytes.data(), w.size()}, now_ms)) {
    object_up_offset_ += count;
    if (object_up_offset_ == object_up_size_) {
      object_up_size_ = object_up_offset_ = 0; std::memset(object_io_.data(), 0, object_io_.size());
    }
  }
}
void UsbBridge::reset_object() noexcept {
  if (object_ != nullptr && object_phase_ == 2) (void)object_->cancel(object_id_);
  object_phase_ = 0; object_token_ = object_id_ = 0;
  object_received_ = object_total_ = object_up_size_ = object_up_offset_ = 0;
  std::memset(object_io_.data(), 0, object_io_.size());
}
}  // namespace routeloom::usb
