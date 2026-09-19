#include "routeloom/usb_bridge.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"

namespace routeloom::usb {
namespace {

constexpr std::size_t kHelloBodyMin = 8 + 1 + 1 + 1;
constexpr std::size_t kHelloAckBodySize = 8 + 1 + 8 + 8 + 8 + 4 + kDevTagSize;
constexpr std::size_t kAuthOkBodySize = kDevTagSize + 8;
constexpr std::size_t kCreditGrantInnerSize = 1 + 8 + 8;

std::uint64_t read_u64(const std::uint8_t* p) noexcept {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8U) | p[i];
  return v;
}

void write_u64(std::uint8_t* p, std::uint64_t v) noexcept {
  for (int i = 7; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v & 0xFFU);
    v >>= 8U;
  }
}

void write_u32(std::uint8_t* p, std::uint32_t v) noexcept {
  for (int i = 3; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v & 0xFFU);
    v >>= 8U;
  }
}

void write_u16(std::uint8_t* p, std::uint16_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 8U);
  p[1] = static_cast<std::uint8_t>(v & 0xFFU);
}

}  // namespace

UsbBridge::UsbBridge(const Config& config, ByteStream& stream) noexcept
    : config_(config), stream_(stream), decoder_(*this) {}

void UsbBridge::on_bytes(const ByteView input, const MonotonicMs now_ms) noexcept {
  now_ms_ = now_ms;
  decoder_.push(input, now_ms);
}

void UsbBridge::poll(const MonotonicMs now_ms) noexcept {
  now_ms_ = now_ms;
  decoder_.poll(now_ms);
  // The pre-auth budget is a device-level rate limit across session attempts
  // (a new HELLO must not reset it): refill one reply per kPreAuthRefillMs.
  if (preauth_budget_ < kPreAuthBudget) {
    const std::uint64_t elapsed = now_ms - preauth_refill_ms_;
    const std::uint64_t steps = elapsed / kPreAuthRefillMs;
    if (steps > 0) {
      const std::uint64_t room = kPreAuthBudget - preauth_budget_;
      preauth_budget_ = static_cast<std::uint8_t>(
          preauth_budget_ + (steps < room ? steps : room));
      preauth_refill_ms_ += steps * kPreAuthRefillMs;
    }
  } else {
    preauth_refill_ms_ = now_ms;
  }
  if ((state_ == SessionState::Hello || state_ == SessionState::Authenticating) &&
      now_ms - state_entered_ms_ > kHandshakeTimeoutMs) {
    reset_session_state();
  }
  pump_tx(now_ms);
  if (state_ == SessionState::Draining && !tx_wire_active_ && control_q_.empty() &&
      data_q_.empty()) {
    reset_session_state();
  }
}

void UsbBridge::notify_disconnect(const MonotonicMs now_ms) noexcept {
  now_ms_ = now_ms;
  reset_session_state();
}

void UsbBridge::on_stream_error(const Status status) noexcept {
  (void)status;
  ++stats_.rx_errors;
}

void UsbBridge::on_frame(const UsbFrame& frame) noexcept {
  ++stats_.rx_frames;
  const MonotonicMs now = now_ms_;
  // A fresh HELLO is accepted from any state: a host that restarts or
  // reconnects always starts a brand-new session attempt.
  if (frame.kind == FrameKind::Hello && (frame.flags & kFlagAuth) == 0) {
    handle_hello(frame, now);
    return;
  }
  if (frame.kind == FrameKind::Hello && (frame.flags & kFlagAuth) != 0 &&
      state_ == SessionState::Hello) {
    handle_auth(frame, now);
    return;
  }
  if (state_ == SessionState::Active || state_ == SessionState::Draining) {
    handle_authenticated(frame, now);
    return;
  }
  // Unauthenticated traffic outside its state is rejected within a bounded
  // pre-auth budget; CREDIT is never treated as send permission here.
  ++stats_.rx_errors;
  if (preauth_budget_ > 0) {
    --preauth_budget_;
    send_error(UsbErrorCode::NotAuthenticated, frame.request, "NOT_AUTHENTICATED", now);
  }
}

void UsbBridge::handle_hello(const UsbFrame& frame, const MonotonicMs now_ms) noexcept {
  // body: host_nonce(8) || min_version(1) || max_version(1) || plen(1) || principal
  if (frame.session != 0 || frame.body.size < kHelloBodyMin) {
    ++stats_.rx_errors;
    if (preauth_budget_ > 0) {
      --preauth_budget_;
      send_error(UsbErrorCode::ProtocolError, frame.request, "HELLO_MALFORMED", now_ms);
    }
    return;
  }
  ByteReader reader(frame.body);
  std::uint64_t host_nonce = 0;
  std::uint8_t min_version = 0, max_version = 0, principal_len = 0;
  Status status = reader.read_u64(host_nonce);
  if (status) status = reader.read_u8(min_version);
  if (status) status = reader.read_u8(max_version);
  if (status) status = reader.read_u8(principal_len);
  if (!status || principal_len > kMaxPrincipalSize ||
      reader.remaining() != principal_len) {
    ++stats_.rx_errors;
    if (preauth_budget_ > 0) {
      --preauth_budget_;
      send_error(UsbErrorCode::ProtocolError, frame.request, "HELLO_MALFORMED", now_ms);
    }
    return;
  }
  std::array<std::uint8_t, kMaxPrincipalSize> principal{};
  if (principal_len > 0) {
    status = reader.read_bytes(
        MutableByteView{principal.data(), principal_len});
    if (!status) return;
  }

  // Valid HELLO: any previous session attempt is torn down. Grants, counters,
  // consumed values and partial TX are never carried over.
  reset_session_state();
  if (min_version > kProtocolVersion || max_version < kProtocolVersion) {
    // Same bounded pre-auth budget as the other HELLO failure paths: a flood
    // of parseable-but-unsupported HELLOs must not get free error replies.
    if (preauth_budget_ > 0) {
      --preauth_budget_;
      send_error(UsbErrorCode::Unsupported, frame.request, "VERSION_UNSUPPORTED",
                 now_ms);
    }
    return;
  }

  transcript_ = SessionTranscript{};
  transcript_.host_nonce = host_nonce;
  transcript_.device_nonce = config_.device_nonce + session_attempt_;
  ++session_attempt_;
  transcript_.version = kProtocolVersion;
  transcript_.node = config_.node;
  transcript_.boot_id = config_.boot_id;
  transcript_.network = config_.network;
  transcript_.capability = config_.capability;
  transcript_.principal_len = principal_len;
  transcript_.principal = principal;

  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t transcript_size = 0;
  status = encode_transcript(
      transcript_, MutableByteView{encoded.data(), encoded.size()}, transcript_size);
  if (!status) return;
  proof_ = derive_session_proof(
      config_.secret, ByteView{encoded.data(), transcript_size});
  proof_valid_ = true;

  // HelloAck body: device_nonce || version || node || boot || network ||
  // capability || hello_tag. The tag lets the host verify we hold the secret.
  std::array<std::uint8_t, kHelloAckBodySize> body{};
  write_u64(body.data(), transcript_.device_nonce);
  body[8] = kProtocolVersion;
  write_u64(body.data() + 9, transcript_.node);
  write_u64(body.data() + 17, transcript_.boot_id);
  write_u64(body.data() + 25, transcript_.network);
  write_u32(body.data() + 33, transcript_.capability);
  std::memcpy(body.data() + 37, proof_.hello_tag.data(), kDevTagSize);
  enqueue(FrameKind::HelloAck, 0, frame.request,
          ByteView{body.data(), body.size()}, now_ms);
  state_ = SessionState::Hello;
  state_entered_ms_ = now_ms;
}

void UsbBridge::handle_auth(const UsbFrame& frame, const MonotonicMs now_ms) noexcept {
  if (frame.session != 0 || frame.body.size != kDevTagSize || !proof_valid_) {
    ++stats_.auth_failures;
    send_error(UsbErrorCode::AuthFailed, frame.request, "AUTH_MALFORMED", now_ms);
    return;
  }
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < kDevTagSize; ++i) {
    diff |= static_cast<std::uint8_t>(frame.body.data[i] ^ proof_.auth_tag[i]);
  }
  if (diff != 0) {
    ++stats_.auth_failures;
    ++auth_attempts_;
    send_error(UsbErrorCode::AuthFailed, frame.request, "AUTH_TAG_INVALID", now_ms);
    if (auth_attempts_ >= kAuthAttemptsMax) reset_session_state();
    return;
  }
  begin_auth_session(now_ms);
}

void UsbBridge::begin_auth_session(const MonotonicMs now_ms) noexcept {
  state_ = SessionState::Authenticating;
  state_entered_ms_ = now_ms;
  rx_counter_ = 0;
  tx_counter_ = 0;
  tx_credit_.reset(proof_.session_id);
  rx_credit_.reset(proof_.session_id);
  connection_stalled_ = false;
  stall_reported_ = false;
  credit_queries_ = 0;

  // AUTH_OK (HelloAck + kFlagAuth): auth_ok_tag || session_id.
  std::array<std::uint8_t, kAuthOkBodySize> ack{};
  std::memcpy(ack.data(), proof_.auth_ok_tag.data(), kDevTagSize);
  write_u64(ack.data() + kDevTagSize, proof_.session_id);
  enqueue(FrameKind::HelloAck, kFlagAuth, 0, ByteView{ack.data(), ack.size()}, now_ms);

  // Initial grant for host→device traffic, bounded by the dedicated buffer.
  (void)rx_credit_.update(proof_.session_id, kRxGrantFrames, kRxGrantBytes);
  std::array<std::uint8_t, kCreditGrantInnerSize> grant{};
  grant[0] = kCreditGrant;
  write_u64(grant.data() + 1, rx_credit_.grant_frames());
  write_u64(grant.data() + 9, rx_credit_.grant_bytes());
  enqueue(FrameKind::Credit, 0, 0, ByteView{grant.data(), grant.size()}, now_ms);

  state_ = SessionState::Active;
  state_entered_ms_ = now_ms;
}

void UsbBridge::handle_authenticated(const UsbFrame& frame,
                                     const MonotonicMs now_ms) noexcept {
  if (frame.session != proof_.session_id) {
    ++stats_.stale_session;  // stale-session traffic is dropped, not answered
    return;
  }
  std::uint64_t counter = 0;
  ByteView inner{};
  Status status = open_body(proof_.key, kDirHostToDevice, frame, counter, inner);
  if (!status) {
    ++stats_.auth_failures;
    send_error(UsbErrorCode::AuthFailed, frame.request, "SESSION_TAG_INVALID", now_ms);
    return;
  }
  if (counter != rx_counter_) {
    ++stats_.replay_rejected;
    send_error(UsbErrorCode::ReplayRejected, frame.request, "REPLAY_REJECTED", now_ms);
    return;
  }
  ++rx_counter_;
  // Incoming CONTROL traffic is rate-limited by the reservation bucket;
  // everything else consumes the granted data credit. The check runs AFTER
  // tag/counter verification so unauthenticated bytes cannot burn tokens and
  // a dropped-but-valid frame does not desynchronize the counter stream.
  if (is_control_kind(frame.kind) &&
      !take_control_token(rx_tokens_, rx_bucket_ms_, now_ms)) {
    ++stats_.control_denied;
    return;
  }
  if (state_ == SessionState::Draining && !is_control_kind(frame.kind)) {
    send_error(UsbErrorCode::Draining, frame.request, "SESSION_DRAINING", now_ms);
    return;
  }
  if (!is_control_kind(frame.kind)) {
    const std::uint64_t decoded_len =
        kHeaderSize + frame.body.size + kCrcSize;
    status = rx_credit_.consume(decoded_len);
    if (!status) {
      ++stats_.credit_denied;
      send_error(UsbErrorCode::CreditExhausted, frame.request, "CREDIT_EXCEEDED",
                 now_ms);
      return;
    }
  }
  dispatch_inner(frame.kind, frame.flags, frame.request, inner, now_ms);
  if (!is_control_kind(frame.kind)) issue_rx_grant(false, now_ms);
}

void UsbBridge::dispatch_inner(const FrameKind kind, const std::uint16_t flags,
                               const std::uint64_t request, const ByteView inner,
                               const MonotonicMs now_ms) noexcept {
  (void)flags;
  switch (kind) {
    case FrameKind::Credit:
      handle_credit(request, inner, now_ms);
      break;
    case FrameKind::KeepAlive:
      enqueue(FrameKind::KeepAlive, 0, request, ByteView{}, now_ms);
      break;
    case FrameKind::DataToMesh:
      handle_data_to_mesh(request, inner, now_ms);
      break;
    case FrameKind::Error:
    case FrameKind::Diagnostic:
      break;  // host-reported status; accounted in stats only
    default:
      send_error(UsbErrorCode::ProtocolError, request, "KIND_UNEXPECTED", now_ms);
      break;
  }
}

void UsbBridge::handle_credit(const std::uint64_t request, const ByteView inner,
                              const MonotonicMs now_ms) noexcept {
  (void)request;
  if (inner.size == 0) {
    send_error(UsbErrorCode::ProtocolError, request, "CREDIT_MALFORMED", now_ms);
    return;
  }
  switch (inner.data[0]) {
    case kCreditGrant: {
      if (inner.size != kCreditGrantInnerSize) {
        send_error(UsbErrorCode::ProtocolError, request, "CREDIT_MALFORMED", now_ms);
        return;
      }
      const std::uint64_t frames = read_u64(inner.data + 1);
      const std::uint64_t bytes = read_u64(inner.data + 9);
      const Status status = tx_credit_.update(proof_.session_id, frames, bytes);
      if (!status) {
        ++stats_.credit_denied;
        send_error(UsbErrorCode::ProtocolError, request, status.detail, now_ms);
        return;
      }
      // Fresh permission: clear the zero-credit recovery ladder.
      credit_queries_ = 0;
      connection_stalled_ = false;
      stall_reported_ = false;
      break;
    }
    case kCreditQuery: {
      std::array<std::uint8_t, kCreditGrantInnerSize> grant{};
      grant[0] = kCreditGrant;
      write_u64(grant.data() + 1, rx_credit_.grant_frames());
      write_u64(grant.data() + 9, rx_credit_.grant_bytes());
      enqueue(FrameKind::Credit, 0, request, ByteView{grant.data(), grant.size()},
              now_ms);
      break;
    }
    case kCreditClose:
      state_ = SessionState::Draining;
      state_entered_ms_ = now_ms;
      break;
    default:
      send_error(UsbErrorCode::ProtocolError, request, "CREDIT_MALFORMED", now_ms);
      break;
  }
}

void UsbBridge::handle_data_to_mesh(const std::uint64_t request,
                                    const ByteView inner,
                                    const MonotonicMs now_ms) noexcept {
  if (inner.size < 16) {
    send_error(UsbErrorCode::ProtocolError, request, "DATA_MALFORMED", now_ms);
    return;
  }
  const std::uint64_t idempotency_key = read_u64(inner.data);
  const NodeId destination = read_u64(inner.data + 8);
  const ByteView payload{inner.data + 16, inner.size - 16};

  // Idempotency scope (principal, network, operation_class, key): the key is
  // the host-chosen identity in the inner body — stable across sessions, so
  // records may legitimately persist past a reconnect. The canonical hash
  // binds kind+body (key, destination and payload together).
  std::array<std::uint8_t, kMaxTxInner + 1> canonical{};
  canonical[0] = static_cast<std::uint8_t>(FrameKind::DataToMesh);
  if (inner.size > kMaxTxInner) {
    send_error(UsbErrorCode::PayloadTooLarge, request, "PAYLOAD_TOO_LARGE", now_ms);
    return;
  }
  std::memcpy(canonical.data() + 1, inner.data, inner.size);
  const DevTag hash =
      payload_hash(ByteView{canonical.data(), inner.size + 1});
  IdempotencyRecord* record = nullptr;
  const IdempotencyResult result = idempotency_.submit(
      ByteView{transcript_.principal.data(), transcript_.principal_len},
      transcript_.network, static_cast<std::uint8_t>(FrameKind::DataToMesh),
      idempotency_key, hash, now_ms, record);
  if (result == IdempotencyResult::Conflict) {
    send_error(UsbErrorCode::Conflict, request, "IDEMPOTENCY_CONFLICT", now_ms);
    return;
  }
  if (result == IdempotencyResult::NoCapacity || record == nullptr) {
    send_error(UsbErrorCode::NoCapacity, request, "IDEMPOTENCY_FULL", now_ms);
    return;
  }
  if (result == IdempotencyResult::Existing) {
    if (record->accepted) {
      std::array<std::uint8_t, 8 + 4 + 8 + 1 + 1 + kMaxReasonLen> body{};
      write_u64(body.data(), request);
      write_u32(body.data() + 8, record->message_session);
      write_u64(body.data() + 12, record->message_sequence);
      body[20] = static_cast<std::uint8_t>(DeliveryState::Accepted);
      const char* reason = "IDEMPOTENT_REPLAY";
      const std::size_t reason_len = std::strlen(reason);
      body[21] = static_cast<std::uint8_t>(reason_len);
      std::memcpy(body.data() + 22, reason, reason_len);
      enqueue(FrameKind::DeliveryEvent, 0, request,
              ByteView{body.data(), 22 + reason_len}, now_ms);
    } else {
      send_error(static_cast<UsbErrorCode>(record->error_code), request,
                 "IDEMPOTENT_REPLAY", now_ms);
    }
    return;
  }

  // First submission: fill the stored outcome honestly.
  if (config_.mesh == nullptr) {
    record->accepted = false;
    record->error_code = static_cast<std::uint16_t>(UsbErrorCode::Unsupported);
    send_error(UsbErrorCode::Unsupported, request, "NO_MESH", now_ms);
    return;
  }
  if (payload.size > kMaxApplicationPayload) {
    record->accepted = false;
    record->error_code = static_cast<std::uint16_t>(UsbErrorCode::PayloadTooLarge);
    send_error(UsbErrorCode::PayloadTooLarge, request, "PAYLOAD_TOO_LARGE", now_ms);
    return;
  }
  pending_request_ = request;
  MessageId id{};
  const Status status =
      config_.mesh->send(destination, payload, SendOptions{}, now_ms, id);
  pending_request_ = 0;
  if (!status) {
    record->accepted = false;
    record->error_code = static_cast<std::uint16_t>(UsbErrorCode::MeshRejected);
    send_error(UsbErrorCode::MeshRejected, request, status.detail, now_ms);
    return;
  }
  record->accepted = true;
  record->message_session = id.session;
  record->message_sequence = id.sequence;
  RequestMap* map = request_map_.allocate();
  if (map == nullptr) {
    // Bounded correlation table: reuse the oldest entry so delivery reports
    // still resolve for recent sends instead of silently degrading.
    RequestMap* oldest = nullptr;
    request_map_.for_each([&](RequestMap& value) {
      if (oldest == nullptr || value.id.sequence < oldest->id.sequence) {
        oldest = &value;
      }
    });
    if (oldest != nullptr && request_map_.release(oldest)) {
      map = request_map_.allocate();
    }
  }
  if (map != nullptr) {
    map->id = id;
    map->request = request;
  }
}

void UsbBridge::issue_rx_grant(const bool initial, const MonotonicMs now_ms) noexcept {
  if (!initial) {
    // Advance the cumulative ceiling by the released buffer amount; never
    // shrink, never refund more than the dedicated headroom.
    const std::uint64_t frames = rx_credit_.consumed_frames() + kRxGrantFrames;
    const std::uint64_t bytes = rx_credit_.consumed_bytes() + kRxGrantBytes;
    if (frames <= rx_credit_.grant_frames() && bytes <= rx_credit_.grant_bytes()) {
      return;
    }
    (void)rx_credit_.update(proof_.session_id, frames, bytes);
  }
  std::array<std::uint8_t, kCreditGrantInnerSize> grant{};
  grant[0] = kCreditGrant;
  write_u64(grant.data() + 1, rx_credit_.grant_frames());
  write_u64(grant.data() + 9, rx_credit_.grant_bytes());
  enqueue(FrameKind::Credit, 0, 0, ByteView{grant.data(), grant.size()}, now_ms);
}

void UsbBridge::send_error(const UsbErrorCode code, const std::uint64_t request,
                           const char* reason, const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, 2 + 8 + 1 + kMaxReasonLen> body{};
  write_u16(body.data(), static_cast<std::uint16_t>(code));
  write_u64(body.data() + 2, request);
  std::size_t reason_len = reason != nullptr ? std::strlen(reason) : 0;
  if (reason_len > kMaxReasonLen) reason_len = kMaxReasonLen;
  body[10] = static_cast<std::uint8_t>(reason_len);
  if (reason_len > 0) std::memcpy(body.data() + 11, reason, reason_len);
  enqueue(FrameKind::Error, 0, request, ByteView{body.data(), 11 + reason_len},
          now_ms);
}

bool UsbBridge::enqueue(const FrameKind kind, const std::uint16_t flags,
                        const std::uint64_t request, const ByteView inner,
                        const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (inner.size > kMaxTxInner) {
    ++stats_.dropped_frames;
    return false;
  }
  TxItem item{};
  item.kind = kind;
  item.flags = flags;
  item.request = request;
  item.body_size = inner.size;
  if (inner.size > 0) std::memcpy(item.body.data(), inner.data, inner.size);
  const bool queued = is_control_kind(kind) ? control_q_.push(item)
                                          : data_q_.push(item);
  if (!queued) ++stats_.dropped_frames;
  return queued;
}

void UsbBridge::pump_tx(const MonotonicMs now_ms) noexcept {
  for (int guard = 0; guard < 64; ++guard) {
    if (tx_wire_active_) {
      std::size_t written = 0;
      const Status status = stream_.write(
          ByteView{tx_wire_.data() + tx_wire_sent_, tx_wire_size_ - tx_wire_sent_},
          written);
      if (!status) {
        ++stats_.tx_write_errors;
        return;
      }
      tx_wire_sent_ += written;
      if (tx_wire_sent_ < tx_wire_size_) return;  // partial write; resume later
      tx_wire_active_ = false;
      ++stats_.tx_frames;
      continue;
    }

    bool control = true;
    TxItem* item = control_q_.front();
    if (item == nullptr) {
      item = data_q_.front();
      control = false;
    }
    if (item == nullptr) return;

    const bool protect =
        (state_ == SessionState::Active || state_ == SessionState::Draining) &&
        item->kind != FrameKind::Hello && item->kind != FrameKind::HelloAck;
    std::array<std::uint8_t, kMaxTxInner + kProtectedBodyOverhead> body{};
    std::size_t body_size = 0;
    std::uint64_t session = 0;
    if (protect) {
      session = proof_.session_id;
      const Status status =
          seal_body(proof_.key, kDirDeviceToHost, tx_counter_, item->kind,
                    item->flags, item->request,
                    ByteView{item->body.data(), item->body_size},
                    MutableByteView{body.data(), body.size()}, body_size);
      if (!status) {
        TxItem dropped{};
        if (control) control_q_.pop(dropped); else data_q_.pop(dropped);
        ++stats_.dropped_frames;
        continue;
      }
    } else {
      body_size = item->body_size;
      if (item->body_size > 0) {
        std::memcpy(body.data(), item->body.data(), item->body_size);
      }
    }
    const std::uint64_t decoded_len =
        static_cast<std::uint64_t>(kHeaderSize) + body_size + kCrcSize;
    if (control) {
      // Zero-credit CONTROL reservation: ≤4 frames × ≤256B, 10/s burst 4.
      if (decoded_len > kControlMaxDecoded) {
        TxItem dropped{};
        control_q_.pop(dropped);
        ++stats_.control_denied;
        continue;
      }

      if (!take_control_token(tx_tokens_, tx_bucket_ms_, now_ms)) return;
    } else {
      // Charge once (1 frame + full decoded protected length incl. CRC,
      // excl. COBS/delimiter) before the first byte of the write.
      const Status status = tx_credit_.consume(decoded_len);
      if (!status) {
        note_credit_stall(now_ms);
        return;
      }
    }
    std::size_t wire_size = 0;
    const Status status =
        encode_frame(item->kind, item->flags, session, item->request,
                     ByteView{body.data(), body_size},
                     MutableByteView{tx_wire_.data(), tx_wire_.size()}, wire_size);
    if (!status) {
      TxItem dropped{};
      if (control) control_q_.pop(dropped); else data_q_.pop(dropped);
      ++stats_.dropped_frames;
      continue;
    }
    TxItem sent{};
    if (control) control_q_.pop(sent); else data_q_.pop(sent);
    tx_wire_size_ = wire_size;
    tx_wire_sent_ = 0;
    tx_wire_active_ = true;
    if (protect) ++tx_counter_;
  }
}

bool UsbBridge::take_control_token(std::uint8_t& tokens, MonotonicMs& last_refill,
                                   const MonotonicMs now_ms) noexcept {
  const MonotonicMs elapsed = now_ms - last_refill;
  if (elapsed >= kControlRefillMs) {
    const std::uint64_t add = elapsed / kControlRefillMs;
    last_refill += add * kControlRefillMs;
    const std::uint64_t total = static_cast<std::uint64_t>(tokens) + add;
    tokens = total > kControlBurst ? kControlBurst : static_cast<std::uint8_t>(total);
  }
  if (tokens == 0) return false;
  --tokens;
  return true;
}

void UsbBridge::note_credit_stall(const MonotonicMs now_ms) noexcept {
  ++stats_.credit_denied;
  if (connection_stalled_) return;
  if (credit_queries_ < kCreditQueryMax) {
    if (credit_queries_ == 0 ||
        now_ms - last_credit_query_ms_ >= kCreditQueryIntervalMs) {
      static const std::uint8_t query_body = kCreditQuery;
      // Only count a query that actually made it onto the wire queue; a full
      // CONTROL queue must not burn retries toward CONNECTION_STALLED.
      if (enqueue(FrameKind::Credit, 0, 0, ByteView{&query_body, 1}, now_ms)) {
        ++credit_queries_;
        last_credit_query_ms_ = now_ms;
      }
    }
    return;
  }
  // 3 unanswered queries at ≥500ms intervals → CONNECTION_STALLED. The
  // session stays up; a fresh grant clears the stall.
  connection_stalled_ = true;
  if (!stall_reported_) {
    stall_reported_ = true;
    send_error(UsbErrorCode::ConnectionStalled, 0, "CONNECTION_STALLED", now_ms);
  }
}

void UsbBridge::reset_session_state() noexcept {
  state_ = SessionState::Disconnected;
  state_entered_ms_ = now_ms_;
  transcript_ = SessionTranscript{};
  proof_ = SessionProof{};
  proof_valid_ = false;
  rx_counter_ = 0;
  tx_counter_ = 0;
  auth_attempts_ = 0;
  // preauth_budget_ intentionally survives: it is a device-level rate limit
  // across session attempts, not per-session state.
  tx_credit_.reset(0);
  rx_credit_.reset(0);
  connection_stalled_ = false;
  stall_reported_ = false;
  credit_queries_ = 0;
  last_credit_query_ms_ = 0;
  tx_tokens_ = kControlBurst;
  rx_tokens_ = kControlBurst;
  control_q_.clear();
  data_q_.clear();
  tx_wire_active_ = false;
  tx_wire_size_ = 0;
  tx_wire_sent_ = 0;
  pending_request_ = 0;
  request_map_ = FixedPool<RequestMap, kRequestMapCapacity>{};
  decoder_.reset();
  // Idempotency records intentionally survive: their scope is the host
  // identity, not the session. Everything else volatile is cleared.
}

std::uint64_t UsbBridge::request_for(const MessageId& id) const noexcept {
  const RequestMap* found = request_map_.find(
      [&](const RequestMap& map) { return map.id == id; });
  return found != nullptr ? found->request : 0;
}

void UsbBridge::on_message(const MessageKey& key, const NodeId source,
                           const ByteView payload) noexcept {
  (void)source;
  // inner: origin(8) || msg_session(4) || msg_seq(8) || payload
  std::array<std::uint8_t, 20 + kMaxApplicationPayload> inner{};
  if (payload.size > kMaxApplicationPayload) return;
  write_u64(inner.data(), key.origin);
  write_u32(inner.data() + 8, key.id.session);
  write_u64(inner.data() + 12, key.id.sequence);
  if (payload.size > 0) {
    std::memcpy(inner.data() + 20, payload.data, payload.size);
  }
  enqueue(FrameKind::DataFromMesh, 0, 0,
          ByteView{inner.data(), 20 + payload.size}, now_ms_);
}

void UsbBridge::on_delivery(const DeliveryResult& result) noexcept {
  // inner: request(8) || msg_session(4) || msg_seq(8) || state(1) ||
  //        reason_len(1) || reason
  const std::uint64_t request =
      pending_request_ != 0 ? pending_request_ : request_for(result.id);
  std::array<std::uint8_t, 8 + 4 + 8 + 1 + 1 + kMaxReasonLen> inner{};
  write_u64(inner.data(), request);
  write_u32(inner.data() + 8, result.id.session);
  write_u64(inner.data() + 12, result.id.sequence);
  inner[20] = static_cast<std::uint8_t>(result.state);
  std::size_t reason_len = result.reason != nullptr ? std::strlen(result.reason) : 0;
  if (reason_len > kMaxReasonLen) reason_len = kMaxReasonLen;
  inner[21] = static_cast<std::uint8_t>(reason_len);
  if (reason_len > 0) {
    std::memcpy(inner.data() + 22, result.reason, reason_len);
  }
  enqueue(FrameKind::DeliveryEvent, 0, request,
          ByteView{inner.data(), 22 + reason_len}, now_ms_);
}

void UsbBridge::on_diagnostic(const char* reason, const NodeId peer,
                              const MessageId* message) noexcept {
  // inner: peer(8) || flags(1) || [msg_session(4) || msg_seq(8)] ||
  //        reason_len(1) || reason
  std::array<std::uint8_t, 8 + 1 + 12 + 1 + kMaxReasonLen> inner{};
  write_u64(inner.data(), peer);
  std::size_t size = 9;
  inner[8] = 0;
  if (message != nullptr) {
    inner[8] = kDiagFlagHasMessage;
    write_u32(inner.data() + 9, message->session);
    write_u64(inner.data() + 13, message->sequence);
    size = 21;
  }
  std::size_t reason_len = reason != nullptr ? std::strlen(reason) : 0;
  if (reason_len > kMaxReasonLen) reason_len = kMaxReasonLen;
  inner[size] = static_cast<std::uint8_t>(reason_len);
  if (reason_len > 0) std::memcpy(inner.data() + size + 1, reason, reason_len);
  enqueue(FrameKind::Diagnostic, 0, 0,
          ByteView{inner.data(), size + 1 + reason_len}, now_ms_);
}

}  // namespace routeloom::usb
