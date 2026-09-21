#include "routeloom/usb_bridge.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/telemetry.hpp"

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
    : config_(config),
      stream_(stream),
      decoder_(*this),
      window_(BootLease::derive(config.boot_id, config.node)) {}

Status UsbBridge::attach_gateway(GatewayDelivery& gateway) noexcept {
  gateway_ = &gateway;
  gateway.attach();
  gateway.set_observer(*this);
  // The role advertises HOST_RECEIVE_RAM only because this bridge IS the
  // sink: scope-2 descriptors are never issued against a sink-less role.
  GatewayRoleConfig role{};
  role.gateway_boot = config_.boot_id;
  role.capabilities = kGatewayCapHostReceive;
  role.host_sink = this;
  const Status enabled = gateway.enable_gateway(role);
  // Attaching the endpoint IS the advertisement: CAP_GATEWAY_ENDPOINT_V1 is
  // set exactly when the component exists and its role is enabled, mirroring
  // attach_config (bit 4). Builds that never attach keep the bit clear and
  // answer Unsupported.
  if (enabled.ok()) {
    config_.capability |= kCapGatewayEndpointV1;
  }
  return enabled;
}

Status UsbBridge::attach_config(ConfigGateway& gateway) noexcept {
  config_gateway_ = &gateway;
  if (config_.mesh != nullptr) {
    config_.mesh->set_config_sink(&gateway);
  }
  config_.capability |= kCapConfigEndpointV1;
  return Status::success();
}

Status UsbBridge::attach_diagnostics() noexcept {
  if (config_.mesh == nullptr) {
    return Status::error(StatusCode::InvalidState, "diagnostics needs mesh");
  }
  config_.mesh->set_diagnostic_sink(this);
  config_.capability |= kCapM1DiagnosticsV1;
  return Status::success();
}

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
  // Gateway lane: resolved endpoints become sends, outstanding ingress is
  // resent once inside its ack window, and stale slots expire.
  pump_gateway(now_ms);
  // Remote diagnostic queries expire into an honest Timeout reply — a lost
  // snapshot is reported, never left hanging or claimed answered.
  for (auto& slot : pending_diag_) {
    if (slot.active && now_ms >= slot.expires_ms) {
      const std::uint64_t usb_request = slot.usb_request;
      const NodeId observer = slot.observer;
      slot = PendingDiagnostic{};
      send_diagnostic_reply(usb_request, ConfigOpsResult::Timeout, observer,
                            ByteView{}, now_ms);
    }
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
    case FrameKind::HostOps:
      handle_host_ops(request, inner, now_ms);
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
  canonical_[0] = static_cast<std::uint8_t>(FrameKind::DataToMesh);
  if (inner.size > kMaxTxInner) {
    send_error(UsbErrorCode::PayloadTooLarge, request, "PAYLOAD_TOO_LARGE", now_ms);
    return;
  }
  std::memcpy(canonical_.data() + 1, inner.data, inner.size);
  const DevTag hash =
      payload_hash(ByteView{canonical_.data(), inner.size + 1});
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
  track_request(id, request);
}

void UsbBridge::handle_host_ops(const std::uint64_t request,
                                    const ByteView inner,
                                    const MonotonicMs now_ms) noexcept {
  // Mutual-negotiation enforcement, device side: the subcommands are served
  // only when this build is configured to speak host_ops_v1 (advertised in
  // HelloAck). The host side — send only when advertised — is TX-I2's duty.
  if ((config_.capability & kCapHostOpsV1) == 0) {
    send_error(UsbErrorCode::Unsupported, request, "HOST_OPS_UNSUPPORTED", now_ms);
    return;
  }
  if (inner.size < 2) {
    send_error(UsbErrorCode::ProtocolError, request, "HOST_OPS_MALFORMED", now_ms);
    return;
  }
  if (inner.data[0] != kHostOpsSchema) {
    send_error(UsbErrorCode::ProtocolError, request, "HOST_OPS_SCHEMA", now_ms);
    return;
  }
  switch (static_cast<HostOpsSub>(inner.data[1])) {
    case HostOpsSub::Submit:
      handle_ops_submit(request, inner, now_ms);
      break;
    case HostOpsSub::QueryDispatch:
      handle_ops_query(request, inner, now_ms);
      break;
    case HostOpsSub::RetireThrough:
      handle_ops_retire(request, inner, now_ms);
      break;
    case HostOpsSub::Skip:
      handle_ops_skip(request, inner, now_ms);
      break;
    case HostOpsSub::TimeSample:
      handle_ops_time_sample(request, inner, now_ms);
      break;
    case HostOpsSub::HostRegister:
      handle_host_register(request, inner, now_ms);
      break;
    case HostOpsSub::GatewayIngressAck:
      handle_ingress_ack(request, inner, now_ms);
      break;
    case HostOpsSub::HostUnregister:
      handle_host_unregister(request, inner, now_ms);
      break;
    case HostOpsSub::GatewayIngress:
      // 0x11 is device→host only: the host issuing one is a protocol
      // violation, never a request to answer.
      send_error(UsbErrorCode::ProtocolError, request, "INGRESS_DIRECTION",
                 now_ms);
      break;
    case HostOpsSub::ConfigQuery:
      handle_config_query(request, inner, now_ms);
      break;
    case HostOpsSub::ConfigChallenge:
      handle_config_challenge(request, inner, now_ms);
      break;
    case HostOpsSub::ConfigPermit:
      handle_config_permit(request, inner, now_ms);
      break;
    case HostOpsSub::ConfigStatus:
      // 0x22 is device→host only (the async reply to a 0x20 query): a host
      // issuing one is a protocol violation, never a request to answer.
      send_error(UsbErrorCode::ProtocolError, request, "STATUS_DIRECTION",
                 now_ms);
      break;
    case HostOpsSub::DiagnosticRequest:
      handle_diagnostic_request(request, inner, now_ms);
      break;
    case HostOpsSub::DiagnosticResponse:
      // 0x31 is device→host only — a host issuing one is a protocol
      // violation, never a request to answer.
      send_error(UsbErrorCode::ProtocolError, request, "DIAG_DIRECTION",
                 now_ms);
      break;
    default:
      send_error(UsbErrorCode::Unsupported, request, "SUBCOMMAND_UNKNOWN", now_ms);
      break;
  }
}

ConfigOpsResult UsbBridge::config_result_for(const Status& status) noexcept {
  switch (status.code) {
    case StatusCode::WouldBlock:
      return ConfigOpsResult::Busy;
    case StatusCode::NoRoute:
      return ConfigOpsResult::NoRoute;
    case StatusCode::InvalidArgument:
      return ConfigOpsResult::Invalid;
    default:
      return ConfigOpsResult::Indeterminate;
  }
}

void UsbBridge::send_config_reply(const std::uint64_t request,
                                  const std::uint8_t sub,
                                  const ConfigOpsResult result,
                                  const NodeId target, const ByteView body,
                                  const MonotonicMs now_ms) noexcept {
  ConfigReply reply{};
  reply.result = static_cast<std::uint16_t>(result);
  reply.target = target;
  reply.body = body;
  std::array<std::uint8_t,
             kGatewayInnerHeadSize + kConfigReplyFixedPayload +
                 kConfigChallengeBodySize>
      encoded{};
  std::size_t body_size = 0;
  if (encode_config_reply(static_cast<HostOpsSub>(sub), reply,
                          MutableByteView{encoded.data(), encoded.size()},
                          body_size)) {
    enqueue(FrameKind::HostOps, 0, request, ByteView{encoded.data(), body_size},
            now_ms);
  } else {
    ++stats_.dropped_frames;
  }
}

void UsbBridge::on_config_reply(const std::uint64_t request,
                                const std::uint8_t sub,
                                const ConfigOpsResult result,
                                const NodeId target, const ByteView body,
                                const MonotonicMs now_ms) noexcept {
  send_config_reply(request, sub, result, target, body, now_ms);
}

UsbBridge::PendingDiagnostic* UsbBridge::find_pending_diagnostic(
    const std::uint32_t request_id, const NodeId observer) noexcept {
  for (auto& slot : pending_diag_) {
    if (slot.active && slot.request_id == request_id &&
        slot.observer == observer) {
      return &slot;
    }
  }
  return nullptr;
}

UsbBridge::PendingDiagnostic* UsbBridge::alloc_pending_diagnostic() noexcept {
  for (auto& slot : pending_diag_) {
    if (!slot.active) return &slot;
  }
  return nullptr;
}

void UsbBridge::send_diagnostic_reply(const std::uint64_t request,
                                      const ConfigOpsResult result,
                                      const NodeId observer,
                                      const ByteView body,
                                      const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kGatewayInnerHeadSize + kDiagnosticReplyFixed +
                              kDiagnosticReplyMaxBody>
      encoded{};
  std::size_t written = 0;
  if (encode_diagnostic_reply(static_cast<std::uint16_t>(result), observer,
                              body,
                              MutableByteView{encoded.data(), encoded.size()},
                              written)) {
    enqueue(FrameKind::HostOps, 0, request, ByteView{encoded.data(), written},
            now_ms);
  } else {
    ++stats_.dropped_frames;
  }
}

void UsbBridge::handle_diagnostic_request(const std::uint64_t request,
                                          const ByteView inner,
                                          const MonotonicMs now_ms) noexcept {
  DiagnosticRequestView req{};
  if (!decode_diagnostic_request(inner, req).ok()) {
    send_error(UsbErrorCode::ProtocolError, request, "DIAG_REQ_MALFORMED",
               now_ms);
    return;
  }
  if ((config_.capability & kCapM1DiagnosticsV1) == 0 ||
      config_.mesh == nullptr) {
    send_diagnostic_reply(request, ConfigOpsResult::Unsupported, req.observer,
                          ByteView{}, now_ms);
    return;
  }
  // Body must be a version-1 diagnostic prefix with a known subtype.
  if (req.body.size < kDiagnosticPrefixSize ||
      req.body.data[0] != kDiagnosticBodyVersion || req.body.data[2] != 0 ||
      req.body.data[3] != 0) {
    send_diagnostic_reply(request, ConfigOpsResult::Invalid, req.observer,
                          ByteView{}, now_ms);
    return;
  }
  const auto subtype = static_cast<DiagnosticSubtype>(req.body.data[1]);
  const bool local = req.observer == config_.node;

  if (subtype == DiagnosticSubtype::CapabilitiesQuery) {
    // Link-only discovery is never tunnelled to a remote mesh target.
    if (!local) {
      send_diagnostic_reply(request, ConfigOpsResult::Unsupported, req.observer,
                            ByteView{}, now_ms);
      return;
    }
    std::array<std::uint8_t, kCapabilitiesReplyBodySize> out{};
    if (!capabilities_reply_encode(config_.mesh->build_capabilities_reply(),
                                   MutableByteView{out.data(), out.size()})) {
      ++stats_.dropped_frames;
      return;
    }
    send_diagnostic_reply(request, ConfigOpsResult::Ok, config_.node,
                          ByteView{out.data(), out.size()}, now_ms);
    return;
  }

  if (subtype != DiagnosticSubtype::TelemetryQuery) {
    send_diagnostic_reply(request, ConfigOpsResult::Unsupported, req.observer,
                          ByteView{}, now_ms);
    return;
  }
  TelemetryQuery query{};
  if (!telemetry_query_decode(req.body, query).ok()) {
    send_diagnostic_reply(request, ConfigOpsResult::Invalid, req.observer,
                          ByteView{}, now_ms);
    return;
  }

  if (local) {
    TelemetrySnapshot snapshot{};
    DiagnosticRejectReason reason{};
    if (config_.mesh->build_telemetry_snapshot(query, now_ms, snapshot,
                                               reason)) {
      std::array<std::uint8_t, kTelemetrySnapshotBodySize> out{};
      if (!telemetry_snapshot_encode(
              snapshot, MutableByteView{out.data(), out.size()})) {
        ++stats_.dropped_frames;
        return;
      }
      send_diagnostic_reply(request, ConfigOpsResult::Ok, config_.node,
                            ByteView{out.data(), out.size()}, now_ms);
    } else {
      // Local rejection surfaces as a verbatim DiagnosticReject body — the
      // host sees the same reason space a remote observer would.
      DiagnosticReject reject{};
      reject.request_id = query.request_id;
      reject.reason = reason;
      reject.observer = config_.node;
      std::array<std::uint8_t, kDiagnosticRejectBodySize> out{};
      if (diagnostic_reject_encode(reject,
                                   MutableByteView{out.data(), out.size()})) {
        send_diagnostic_reply(request, ConfigOpsResult::Ok, config_.node,
                              ByteView{out.data(), out.size()}, now_ms);
      } else {
        ++stats_.dropped_frames;
      }
    }
    return;
  }

  // Remote: bounded async query — slot exhaustion is an honest Busy, and
  // the request's own lifetime bounds the wait (poll() expires the slot).
  PendingDiagnostic* slot = alloc_pending_diagnostic();
  if (slot == nullptr) {
    send_diagnostic_reply(request, ConfigOpsResult::Busy, req.observer,
                          ByteView{}, now_ms);
    return;
  }
  const Status status =
      config_.mesh->send_telemetry_query(req.observer, query, now_ms);
  if (!status) {
    send_diagnostic_reply(request, config_result_for(status), req.observer,
                          ByteView{}, now_ms);
    return;
  }
  slot->active = true;
  slot->request_id = query.request_id;
  slot->usb_request = request;
  slot->observer = req.observer;
  slot->expires_ms = now_ms + kTelemetryQueryLifetimeMs;
}

void UsbBridge::on_diagnostic_body(const NodeId observer, const ByteView body,
                                   const MonotonicMs now_ms) noexcept {
  if (body.size < kDiagnosticPrefixSize ||
      body.data[0] != kDiagnosticBodyVersion) {
    ++stats_.dropped_frames;
    return;
  }
  const auto subtype = static_cast<DiagnosticSubtype>(body.data[1]);
  std::uint32_t request_id = 0;
  if (subtype == DiagnosticSubtype::TelemetrySnapshot) {
    TelemetrySnapshot snapshot{};
    if (!telemetry_snapshot_decode(body, snapshot).ok()) return;
    request_id = snapshot.request_id;
  } else if (subtype == DiagnosticSubtype::DiagnosticReject) {
    DiagnosticReject reject{};
    if (!diagnostic_reject_decode(body, reject).ok()) return;
    request_id = reject.request_id;
  } else {
    // Link-only subtypes (capabilities/transit-failure) have no pending
    // USB request — a counted drop, never a reply.
    ++stats_.dropped_frames;
    return;
  }
  PendingDiagnostic* slot = find_pending_diagnostic(request_id, observer);
  if (slot == nullptr) {
    ++stats_.dropped_frames;  // unsolicited/late body: counted, not trusted
    return;
  }
  const std::uint64_t usb_request = slot->usb_request;
  *slot = PendingDiagnostic{};
  send_diagnostic_reply(usb_request, ConfigOpsResult::Ok, observer, body,
                        now_ms);
}

void UsbBridge::handle_config_query(const std::uint64_t request,
                                    const ByteView inner,
                                    const MonotonicMs now_ms) noexcept {
  ConfigQueryRequest query{};
  if (!decode_config_query(inner, query)) {
    send_error(UsbErrorCode::ProtocolError, request, "CONFIG_QUERY_MALFORMED",
               now_ms);
    return;
  }
  if ((config_.capability & kCapConfigEndpointV1) == 0 ||
      config_gateway_ == nullptr) {
    send_config_reply(request, static_cast<std::uint8_t>(HostOpsSub::ConfigStatus),
                      ConfigOpsResult::Unsupported, query.target, ByteView{},
                      now_ms);
    return;
  }
  const Status status =
      config_gateway_->submit_status_query(request, query.target,
                                           query.config_namespace,
                                           query.operation_id, now_ms);
  if (!status) {
    send_config_reply(request, static_cast<std::uint8_t>(HostOpsSub::ConfigStatus),
                      config_result_for(status), query.target, ByteView{}, now_ms);
  }
  // Admitted: the answer lands asynchronously on on_config_reply (0x22).
}

void UsbBridge::handle_config_challenge(const std::uint64_t request,
                                        const ByteView inner,
                                        const MonotonicMs now_ms) noexcept {
  ConfigChallengeRequest challenge{};
  if (!decode_config_challenge(inner, challenge)) {
    send_error(UsbErrorCode::ProtocolError, request,
               "CONFIG_CHALLENGE_MALFORMED", now_ms);
    return;
  }
  if ((config_.capability & kCapConfigEndpointV1) == 0 ||
      config_gateway_ == nullptr) {
    send_config_reply(request,
                      static_cast<std::uint8_t>(HostOpsSub::ConfigChallenge),
                      ConfigOpsResult::Unsupported, challenge.target, ByteView{},
                      now_ms);
    return;
  }
  const Status status = config_gateway_->submit_challenge(
      request, challenge.target, challenge.config_namespace, challenge.schema,
      challenge.client_nonce, now_ms);
  if (!status) {
    send_config_reply(request,
                      static_cast<std::uint8_t>(HostOpsSub::ConfigChallenge),
                      config_result_for(status), challenge.target, ByteView{},
                      now_ms);
  }
  // Admitted: the answer lands asynchronously on on_config_reply (0x23).
}

void UsbBridge::handle_config_permit(const std::uint64_t request,
                                     const ByteView inner,
                                     const MonotonicMs now_ms) noexcept {
  ConfigPermitRequest permit{};
  if (!decode_config_permit(inner, permit)) {
    send_error(UsbErrorCode::ProtocolError, request, "CONFIG_PERMIT_MALFORMED",
               now_ms);
    return;
  }
  if ((config_.capability & kCapConfigEndpointV1) == 0 ||
      config_gateway_ == nullptr) {
    send_config_reply(request, static_cast<std::uint8_t>(HostOpsSub::ConfigPermit),
                      ConfigOpsResult::Unsupported, permit.target, ByteView{},
                      now_ms);
    return;
  }
  const Status status = config_gateway_->submit_permit(
      request, permit.target, permit.permit, now_ms);
  if (!status) {
    send_config_reply(request, static_cast<std::uint8_t>(HostOpsSub::ConfigPermit),
                      config_result_for(status), permit.target, ByteView{},
                      now_ms);
  }
  // Admitted: the ack resolves asynchronously on on_config_reply (0x21).
}

void UsbBridge::send_receipt(const DispatchReceipt& receipt,
                             const std::uint64_t request,
                             const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kReceiptSize> body{};
  std::size_t body_size = 0;
  if (!encode_receipt(receipt, MutableByteView{body.data(), body.size()},
                      body_size)) {
    ++stats_.dropped_frames;
    return;
  }
  enqueue(FrameKind::HostOps, 0, request, ByteView{body.data(), body_size},
          now_ms);
}

void UsbBridge::send_query_response(const QueryResponse& response,
                                    const std::uint64_t request,
                                    const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kQueryResponseSize> body{};
  std::size_t body_size = 0;
  if (!encode_query_response(response, MutableByteView{body.data(), body.size()},
                             body_size)) {
    ++stats_.dropped_frames;
    return;
  }
  enqueue(FrameKind::HostOps, 0, request, ByteView{body.data(), body_size},
          now_ms);
}

void UsbBridge::send_retire_response(const RetireResponse& response,
                                     const std::uint64_t request,
                                     const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kRetireResponseSize> body{};
  std::size_t body_size = 0;
  if (!encode_retire_response(response, MutableByteView{body.data(), body.size()},
                              body_size)) {
    ++stats_.dropped_frames;
    return;
  }
  enqueue(FrameKind::HostOps, 0, request, ByteView{body.data(), body_size},
          now_ms);
}

void UsbBridge::send_time_sample_response(const TimeSampleResponse& response,
                                          const std::uint64_t request,
                                          const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kTimeSampleResponseSize> body{};
  std::size_t body_size = 0;
  if (!encode_time_sample_response(response,
                                   MutableByteView{body.data(), body.size()},
                                   body_size)) {
    ++stats_.dropped_frames;
    return;
  }
  enqueue(FrameKind::HostOps, 0, request, ByteView{body.data(), body_size},
          now_ms);
}

void UsbBridge::track_request(const MessageId& id,
                              const std::uint64_t request) noexcept {
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

namespace {

// Fills a receipt's record fields from a stored slot (replay/conflict/refusal
// answers carry the authoritative slot state, not the request's claims).
void fill_receipt_from_slot(DispatchReceipt& receipt,
                            const DispatchWindow::Slot& slot) noexcept {
  receipt.state = slot.state;
  receipt.hash = slot.hash;
  receipt.msg_session = slot.msg_session;
  receipt.msg_seq = slot.msg_seq;
  receipt.msg_valid = slot.msg_valid;
  receipt.evidence = slot.evidence;
}

void fill_query_from_slot(QueryResponse& response,
                          const DispatchWindow::Slot& slot) noexcept {
  response.state = slot.state;
  response.hash = slot.hash;
  response.operation_id = slot.operation_id;
  response.msg_session = slot.msg_session;
  response.msg_seq = slot.msg_seq;
  response.msg_valid = slot.msg_valid;
  response.evidence = slot.evidence;
}

}  // namespace

void UsbBridge::send_record_refusal_receipt(
    DispatchReceipt& receipt, const SubmitRequest& submit,
    const std::uint64_t request, const MonotonicMs now_ms) noexcept {
  // A record-store refusal after a successful Admit check is explainable
  // only by the position's CURRENT state — re-run the dry classification
  // and answer with what the window actually holds rather than a
  // synthetic rejection code. The caller keeps sub/lease/seq already
  // filled on `receipt`.
  const DispatchWindow::SubmitCheck recheck = window_.check_submit(
      submit.lease, submit.dispatcher, submit.dispatch_seq,
      submit.canonical_hash, submit.operation_id);
  switch (recheck) {
    case DispatchWindow::SubmitCheck::Replay:
    case DispatchWindow::SubmitCheck::Conflict: {
      const DispatchWindow::Slot* slot = window_.find(submit.dispatch_seq);
      if (slot != nullptr) fill_receipt_from_slot(receipt, *slot);
      receipt.result = recheck == DispatchWindow::SubmitCheck::Replay
                           ? HostOpsResult::Existing
                           : HostOpsResult::Conflict;
      break;
    }
    case DispatchWindow::SubmitCheck::Retired:
      receipt.result = HostOpsResult::Retired;
      break;
    case DispatchWindow::SubmitCheck::LeaseMismatch:
      receipt.result = HostOpsResult::LeaseMismatch;
      break;
    case DispatchWindow::SubmitCheck::LaneMismatch:
      receipt.result = HostOpsResult::LaneMismatch;
      break;
    case DispatchWindow::SubmitCheck::InvalidId:
      receipt.result = HostOpsResult::InvalidRequest;
      break;
    case DispatchWindow::SubmitCheck::Admit:
    case DispatchWindow::SubmitCheck::WindowFull:
    default:
      // The position looks free but the store refused anyway (or the seq
      // slid past the window edge): answer as window pressure — never a
      // mesh outcome, since a refusal here is a bookkeeping failure.
      receipt.result = HostOpsResult::WindowFull;
      break;
  }
  send_receipt(receipt, request, now_ms);
}

void UsbBridge::handle_ops_submit(const std::uint64_t request,
                                  const ByteView inner,
                                  const MonotonicMs now_ms) noexcept {
  SubmitRequest submit{};
  if (!decode_submit(inner, submit)) {
    send_error(UsbErrorCode::ProtocolError, request, "SUBMIT_MALFORMED", now_ms);
    return;
  }
  DispatchReceipt receipt{};
  receipt.sub = HostOpsSub::Submit;
  receipt.lease = window_.lease();
  receipt.dispatch_seq = submit.dispatch_seq;
  receipt.hash = submit.canonical_hash;

  const DispatchWindow::SubmitCheck check = window_.check_submit(
      submit.lease, submit.dispatcher, submit.dispatch_seq,
      submit.canonical_hash, submit.operation_id);
  switch (check) {
    case DispatchWindow::SubmitCheck::LeaseMismatch:
      receipt.result = HostOpsResult::LeaseMismatch;
      send_receipt(receipt, request, now_ms);
      return;
    case DispatchWindow::SubmitCheck::InvalidId:
      receipt.result = HostOpsResult::InvalidRequest;
      send_receipt(receipt, request, now_ms);
      return;
    case DispatchWindow::SubmitCheck::LaneMismatch:
      receipt.result = HostOpsResult::LaneMismatch;
      send_receipt(receipt, request, now_ms);
      return;
    case DispatchWindow::SubmitCheck::Retired:
      receipt.result = HostOpsResult::Retired;
      send_receipt(receipt, request, now_ms);
      return;
    case DispatchWindow::SubmitCheck::WindowFull:
      receipt.result = HostOpsResult::WindowFull;
      send_receipt(receipt, request, now_ms);
      return;
    case DispatchWindow::SubmitCheck::Replay:
    case DispatchWindow::SubmitCheck::Conflict: {
      const DispatchWindow::Slot* slot = window_.find(submit.dispatch_seq);
      if (slot != nullptr) fill_receipt_from_slot(receipt, *slot);
      receipt.result = check == DispatchWindow::SubmitCheck::Replay
                           ? HostOpsResult::Existing
                           : HostOpsResult::Conflict;
      send_receipt(receipt, request, now_ms);
      return;
    }
    case DispatchWindow::SubmitCheck::Admit:
      break;
  }

  // Admitted position: validate the canonical request before touching the
  // mesh. Structural failures are InvalidRequest; known-but-unenabled values
  // are Unsupported — never silently downgraded.
  CanonicalFields fields{};
  if (!parse_canonical_request(submit.canonical, fields)) {
    receipt.result = HostOpsResult::InvalidRequest;
    send_receipt(receipt, request, now_ms);
    return;
  }
  // The canonical network must match the authenticated session network:
  // a dispatcher confused (or lying) about its network must not send into
  // another one.
  if (transcript_.network > 0xFFFFFFFFULL ||
      fields.network != static_cast<std::uint32_t>(transcript_.network)) {
    receipt.result = HostOpsResult::InvalidRequest;
    send_receipt(receipt, request, now_ms);
    return;
  }
  if (fields.dest_kind == 1) {
    // Schema-2 gateway destination (P3): bound to the live host
    // registration; routed to the host loopback or a remote gateway.
    handle_gateway_submit(submit, fields, receipt, request, now_ms);
    return;
  }
  if (fields.delivery == 2 || fields.priority != 1 || fields.persist_sleep) {
    receipt.result = HostOpsResult::Unsupported;
    send_receipt(receipt, request, now_ms);
    return;
  }
  if (fields.destination == config_.node) {
    receipt.result = HostOpsResult::InvalidRequest;
    send_receipt(receipt, request, now_ms);
    return;
  }

  // Device-deadline enforcement at admission (03 §4): late USB arrivals never
  // send. The terminal Expired record keeps the position accounted so a
  // retry replays the same outcome instead of wedging the retire prefix.
  if (now_ms >= submit.device_deadline) {
    if (!window_.record_expired(submit.dispatcher, submit.dispatch_seq,
                                submit.canonical_hash, submit.operation_id,
                                fields.delivery)) {
      // Defensive (check-then-record is atomic for this single-threaded
      // caller): nothing was sent, so MeshRejected would be a lie — answer
      // with the position's actual state.
      send_record_refusal_receipt(receipt, submit, request, now_ms);
      return;
    }
    receipt.result = HostOpsResult::Expired;
    receipt.state = DispatchWindow::State::Expired;
    send_receipt(receipt, request, now_ms);
    return;
  }

  if (config_.mesh == nullptr) {
    receipt.result = HostOpsResult::MeshRejected;
    send_receipt(receipt, request, now_ms);
    return;
  }
  SendOptions options{};
  options.delivery = fields.delivery == 0 ? DeliveryClass::BestEffort
                                          : DeliveryClass::Reliable;
  options.priority = Priority::Normal;
  // Mesh lifetime = min(time left to the device deadline, canonical ttl).
  // The canonical ttl is the contract's per-send budget
  // (send.ttl_max_ms = 30000): a far-future device_deadline must not pin a
  // window record and a delivery-table slot for weeks — the record retires
  // only via a contiguous terminal prefix, so an unbounded send would
  // wedge the lane.
  const std::uint64_t remaining = submit.device_deadline - now_ms;
  options.lifetime_ms = static_cast<std::uint32_t>(
      remaining < fields.ttl_ms ? remaining : fields.ttl_ms);
  options.hop_limit = fields.hop_limit;
  options.persist_across_sleep = false;
  MessageId id{};
  ops_send_active_ = true;
  const Status status =
      config_.mesh->send(fields.destination, fields.payload, options, now_ms, id);
  ops_send_active_ = false;
  if (!status) {
    // Refused or full: no record is created, so a later retry is a clean
    // Admit — never a Conflict against a half-created entry.
    receipt.result = HostOpsResult::MeshRejected;
    send_receipt(receipt, request, now_ms);
    return;
  }
  if (!window_.record_sent(submit.dispatcher, submit.dispatch_seq,
                           submit.canonical_hash, submit.operation_id,
                           fields.delivery, id.session, id.sequence)) {
    // Defensive (unreachable for this single-threaded caller): the mesh
    // send IS live, so MeshRejected would be a lie — it would orphan an
    // in-flight delivery whose outcome later surfaces as a request-0
    // DeliveryEvent. Correlate the send to this request, leave an
    // Indeterminate record if the position is still free, and answer with
    // the position's actual state.
    track_request(id, request);
    (void)window_.record_indeterminate(
        submit.dispatcher, submit.dispatch_seq, submit.canonical_hash,
        submit.operation_id, fields.delivery, id.session, id.sequence);
    send_record_refusal_receipt(receipt, submit, request, now_ms);
    return;
  }
  receipt.result = HostOpsResult::Ok;
  receipt.state = DispatchWindow::State::Sent;
  receipt.msg_session = id.session;
  receipt.msg_seq = id.sequence;
  receipt.msg_valid = true;
  receipt.evidence = DispatchWindow::Evidence::GatewayAccepted;
  send_receipt(receipt, request, now_ms);
}

void UsbBridge::handle_ops_query(const std::uint64_t request,
                                 const ByteView inner,
                                 const MonotonicMs now_ms) noexcept {
  LaneRequest query{};
  if (!decode_lane_request(inner, HostOpsSub::QueryDispatch, query)) {
    send_error(UsbErrorCode::ProtocolError, request, "QUERY_MALFORMED", now_ms);
    return;
  }
  QueryResponse response{};
  response.lease = window_.lease();
  response.dispatch_seq = query.seq;
  DispatchWindow::Slot slot{};
  const DispatchWindow::QueryOutcome outcome =
      window_.query(query.lease, query.dispatcher, query.seq, slot);
  switch (outcome) {
    case DispatchWindow::QueryOutcome::Found:
      response.result = HostOpsResult::Ok;
      fill_query_from_slot(response, slot);
      break;
    case DispatchWindow::QueryOutcome::Retired:
      response.result = HostOpsResult::Retired;
      break;
    case DispatchWindow::QueryOutcome::NotRetained:
      response.result = HostOpsResult::NotRetained;
      break;
    case DispatchWindow::QueryOutcome::LeaseMismatch:
      response.result = HostOpsResult::LeaseMismatch;
      break;
    case DispatchWindow::QueryOutcome::LaneMismatch:
      response.result = HostOpsResult::LaneMismatch;
      break;
    case DispatchWindow::QueryOutcome::InvalidId:
      response.result = HostOpsResult::InvalidRequest;
      break;
  }
  send_query_response(response, request, now_ms);
}

void UsbBridge::handle_ops_retire(const std::uint64_t request,
                                  const ByteView inner,
                                  const MonotonicMs now_ms) noexcept {
  LaneRequest retire{};
  if (!decode_lane_request(inner, HostOpsSub::RetireThrough, retire)) {
    send_error(UsbErrorCode::ProtocolError, request, "RETIRE_MALFORMED", now_ms);
    return;
  }
  RetireResponse response{};
  response.lease = window_.lease();
  const DispatchWindow::RetireOutcome outcome =
      window_.retire_through(retire.lease, retire.dispatcher, retire.seq);
  switch (outcome) {
    case DispatchWindow::RetireOutcome::Advanced:
    case DispatchWindow::RetireOutcome::NoopFloor:
      response.result = HostOpsResult::Ok;
      break;
    case DispatchWindow::RetireOutcome::RefusedSpan:
      response.result = HostOpsResult::RetireRefused;
      break;
    case DispatchWindow::RetireOutcome::LeaseMismatch:
      response.result = HostOpsResult::LeaseMismatch;
      break;
    case DispatchWindow::RetireOutcome::LaneMismatch:
      response.result = HostOpsResult::LaneMismatch;
      break;
    case DispatchWindow::RetireOutcome::InvalidId:
      response.result = HostOpsResult::InvalidRequest;
      break;
  }
  response.retired_through = window_.retired_through();
  send_retire_response(response, request, now_ms);
}

void UsbBridge::handle_ops_skip(const std::uint64_t request,
                                const ByteView inner,
                                const MonotonicMs now_ms) noexcept {
  LaneRequest skip{};
  if (!decode_lane_request(inner, HostOpsSub::Skip, skip)) {
    send_error(UsbErrorCode::ProtocolError, request, "SKIP_MALFORMED", now_ms);
    return;
  }
  DispatchReceipt receipt{};
  receipt.sub = HostOpsSub::Skip;
  receipt.lease = window_.lease();
  receipt.dispatch_seq = skip.seq;
  const DispatchWindow::SkipOutcome outcome =
      window_.skip(skip.lease, skip.dispatcher, skip.seq);
  switch (outcome) {
    case DispatchWindow::SkipOutcome::Skipped:
      receipt.result = HostOpsResult::Ok;
      receipt.state = DispatchWindow::State::Skipped;
      break;
    case DispatchWindow::SkipOutcome::ReplaySkipped:
      receipt.result = HostOpsResult::Existing;
      receipt.state = DispatchWindow::State::Skipped;
      break;
    case DispatchWindow::SkipOutcome::Occupied: {
      const DispatchWindow::Slot* slot = window_.find(skip.seq);
      if (slot != nullptr) fill_receipt_from_slot(receipt, *slot);
      receipt.result = HostOpsResult::SkipRefused;
      break;
    }
    case DispatchWindow::SkipOutcome::Retired:
      receipt.result = HostOpsResult::Retired;
      break;
    case DispatchWindow::SkipOutcome::WindowFull:
      receipt.result = HostOpsResult::WindowFull;
      break;
    case DispatchWindow::SkipOutcome::LeaseMismatch:
      receipt.result = HostOpsResult::LeaseMismatch;
      break;
    case DispatchWindow::SkipOutcome::LaneMismatch:
      receipt.result = HostOpsResult::LaneMismatch;
      break;
    case DispatchWindow::SkipOutcome::InvalidId:
      receipt.result = HostOpsResult::InvalidRequest;
      break;
  }
  send_receipt(receipt, request, now_ms);
}

void UsbBridge::handle_ops_time_sample(const std::uint64_t request,
                                       const ByteView inner,
                                       const MonotonicMs now_ms) noexcept {
  TimeSampleRequest sample{};
  if (!decode_time_sample_request(inner, sample)) {
    send_error(UsbErrorCode::ProtocolError, request, "TIME_SAMPLE_MALFORMED",
               now_ms);
    return;
  }
  // Read-only echo: the protected-session seal already binds this answer to
  // the session and direction; the CURRENT lease is always reported so the
  // host can detect a reboot from any reply. Sample ordering/acceptance on
  // the host (nonce freshness, mapping validity) is TX-I2's loop — the
  // device just answers truthfully.
  TimeSampleResponse response{};
  response.lease = window_.lease();
  response.nonce = sample.nonce;
  response.device_time = now_ms;
  response.result = (window_.lease().valid() && sample.lease == window_.lease())
                        ? HostOpsResult::Ok
                        : HostOpsResult::LeaseMismatch;
  send_time_sample_response(response, request, now_ms);
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
    std::size_t body_size = 0;
    std::uint64_t session = 0;
    if (protect) {
      session = proof_.session_id;
      const Status status =
          seal_body(proof_.key, kDirDeviceToHost, tx_counter_, item->kind,
                    item->flags, item->request,
                    ByteView{item->body.data(), item->body_size},
                    MutableByteView{tx_body_.data(), tx_body_.size()}, body_size);
      if (!status) {
        if (control) control_q_.drop(); else data_q_.drop();
        ++stats_.dropped_frames;
        continue;
      }
    } else {
      body_size = item->body_size;
      if (item->body_size > 0) {
        std::memcpy(tx_body_.data(), item->body.data(), item->body_size);
      }
    }
    const std::uint64_t decoded_len =
        static_cast<std::uint64_t>(kHeaderSize) + body_size + kCrcSize;
    if (control) {
      // Zero-credit CONTROL reservation: ≤4 frames × ≤256B, 10/s burst 4.
      if (decoded_len > kControlMaxDecoded) {
        control_q_.drop();
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
                     ByteView{tx_body_.data(), body_size},
                     MutableByteView{encode_scratch_.data(), encode_scratch_.size()},
                     MutableByteView{tx_wire_.data(), tx_wire_.size()}, wire_size);
    if (!status) {
      if (control) control_q_.drop(); else data_q_.drop();
      ++stats_.dropped_frames;
      continue;
    }
    if (control) control_q_.drop(); else data_q_.drop();
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
  // Gateway lane teardown: the registration dies with the session (a new
  // token is minted per session — old tokens can never be rebound), and
  // in-flight ingress/send slots are failed honestly instead of leaking a
  // forever-Sent window record that would wedge the retire prefix.
  clear_gateway_state();
  // Idempotency records and the dispatch window intentionally survive: their
  // scope is the host identity / boot lease, not the session. Everything
  // else volatile is cleared.
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
  // Host-ops-correlated deliveries update the dispatch window instead of
  // emitting a DeliveryEvent: their authoritative state is pulled via
  // QUERY_DISPATCH (TX-I2), and the SUBMIT request id is session-scoped while
  // window records outlive reconnects. (A duplicate callback for an already
  // retired record is the one case that still emits: the record is gone by
  // design, so the host reads it as a stale event.)
  if (ops_send_active_ ||
      window_.note_mesh_outcome(result.id.session, result.id.sequence,
                                result.state)) {
    return;
  }
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

// --- Gateway host lane (scope-gateway-config/05-wire-api.md §5.6, P3) ------

namespace {

constexpr MonotonicMs kHostRegisterLeaseMs = 15000;   // design: grant 15s
constexpr MonotonicMs kIngressResendMs = 1200;        // one retry inside 5s window
constexpr std::uint64_t kIngressAckWindowMs = 5000;   // == kGatewayHostAckMs
constexpr std::uint32_t kGatewayResolveBudgetMs = 5000;

bool reserved_id(const std::uint64_t value) noexcept {
  return value == 0 || value == UINT64_MAX;
}

}  // namespace

bool UsbBridge::host_ready(HostBinding& binding) noexcept {
  if (!registration_.active || now_ms_ >= registration_.lease_deadline_ms) {
    return false;
  }
  binding.principal_digest = registration_.principal_digest;
  binding.host_boot = registration_.host_boot;
  binding.usb_session = registration_.usb_session;
  return true;
}

Status UsbBridge::host_ingress(const MessageKey& key,
                               const RequestDigest& request_digest,
                               const ByteView submit_prefix, const ByteView payload,
                               const MonotonicMs now_ms) noexcept {
  return queue_ingress(/*loopback=*/false, key, request_digest, submit_prefix,
                       payload, /*dispatch_seq=*/0, now_ms);
}

Status UsbBridge::queue_ingress(const bool loopback, const MessageKey& key,
                                const RequestDigest& digest,
                                const ByteView submit_prefix,
                                const ByteView payload,
                                const std::uint64_t dispatch_seq,
                                const MonotonicMs now_ms) noexcept {
  if (submit_prefix.size != endpoint::kServiceSubmitHeaderSize ||
      payload.size > kCanonicalGatewayPayloadMax) {
    return Status::error(StatusCode::InvalidArgument, "ingress framing");
  }
  PendingIngress* slot = nullptr;
  for (PendingIngress& candidate : pending_ingress_) {
    if (!candidate.occupied) {
      slot = &candidate;
      break;
    }
  }
  if (slot == nullptr) {
    return Status::error(StatusCode::NoCapacity, "ingress slots full");
  }
  GatewayIngress frame{};
  std::memcpy(frame.submit_prefix.data(), submit_prefix.data,
              frame.submit_prefix.size());
  frame.ref_origin = key.origin;
  frame.ref_session = key.id.session;
  frame.ref_sequence = key.id.sequence;
  frame.request_digest = digest;
  frame.payload = payload;
  std::size_t body_size = 0;
  if (!encode_gateway_ingress(
          frame, MutableByteView{slot->body.data(), slot->body.size()},
          body_size)) {
    return Status::error(StatusCode::InternalError, "ingress encode");
  }
  slot->occupied = true;
  slot->loopback = loopback;
  slot->resent = false;
  slot->request = next_ingress_request_++;
  slot->dispatch_seq = dispatch_seq;
  slot->key = key;
  slot->digest = digest;
  slot->body_size = static_cast<std::uint16_t>(body_size);
  slot->resend_at_ms = now_ms + kIngressResendMs;
  slot->deadline_ms = now_ms + kIngressAckWindowMs;
  if (!enqueue(FrameKind::HostOps, 0, slot->request,
               ByteView{slot->body.data(), slot->body_size}, now_ms)) {
    *slot = PendingIngress{};
    return Status::error(StatusCode::NoCapacity, "ingress queue full");
  }
  return Status::success();
}

UsbBridge::PendingIngress* UsbBridge::find_ingress(
    const std::uint64_t request) noexcept {
  for (PendingIngress& slot : pending_ingress_) {
    if (slot.occupied && slot.request == request) return &slot;
  }
  return nullptr;
}

UsbBridge::PendingGatewaySend* UsbBridge::find_gateway_send(
    const std::uint64_t dispatch_seq) noexcept {
  for (PendingGatewaySend& send : pending_sends_) {
    if (send.occupied && send.dispatch_seq == dispatch_seq) return &send;
  }
  return nullptr;
}

void UsbBridge::fail_gateway_send(const std::uint64_t dispatch_seq) noexcept {
  // Sent-but-unresolved ends as Failed: adopt_slot maps it to the host's
  // INDETERMINATE — the conservative answer for an unknowable outcome.
  (void)window_.note_gateway_outcome(dispatch_seq, /*received=*/false,
                                   /*host_receive_ram=*/false);
}

void UsbBridge::free_gateway_send(PendingGatewaySend& send) noexcept {
  if (send.endpoint_held && gateway_ != nullptr) {
    gateway_->endpoint_release(send.endpoint);
  }
  send = PendingGatewaySend{};
}

void UsbBridge::clear_gateway_state() noexcept {
  registration_ = HostRegistration{};
  for (PendingIngress& slot : pending_ingress_) {
    if (slot.occupied && slot.loopback) {
      // The loopback position can never complete after session loss:
      // mark it Failed instead of leaking a forever-Sent record.
      fail_gateway_send(slot.dispatch_seq);
    }
    slot = PendingIngress{};
  }
  for (PendingGatewaySend& send : pending_sends_) {
    if (send.occupied) {
      fail_gateway_send(send.dispatch_seq);
      free_gateway_send(send);
    }
  }
}

void UsbBridge::handle_gateway_submit(const SubmitRequest& submit,
                                      const CanonicalFields& fields,
                                      DispatchReceipt& receipt,
                                      const std::uint64_t request,
                                      const MonotonicMs now_ms) noexcept {
  const auto refuse = [&](const HostOpsResult result) {
    receipt.result = result;
    send_receipt(receipt, request, now_ms);
  };
  if ((config_.capability & kCapGatewayEndpointV1) == 0 || gateway_ == nullptr ||
      !gateway_->gateway_enabled()) {
    refuse(HostOpsResult::Unsupported);
    return;
  }
  if (fields.delivery == 2 || fields.priority != 1 || fields.persist_sleep) {
    refuse(HostOpsResult::Unsupported);
    return;
  }
  // The schema-2 binding IS the authority check: token == the live
  // registration token, gateway_boot == this adapter's boot, egress ==
  // this node. Anything else is stale or foreign — never rebound (05 §5.4).
  if (!registration_.active || now_ms >= registration_.lease_deadline_ms ||
      fields.gateway_token != registration_.token ||
      fields.gateway_boot != config_.boot_id ||
      fields.egress_gateway != config_.node) {
    refuse(HostOpsResult::InvalidRequest);
    return;
  }
  // Device-deadline enforcement at admission — identical to the node path.
  if (now_ms >= submit.device_deadline) {
    if (!window_.record_expired(submit.dispatcher, submit.dispatch_seq,
                                submit.canonical_hash, submit.operation_id,
                                fields.delivery)) {
      send_record_refusal_receipt(receipt, submit, request, now_ms);
      return;
    }
    receipt.result = HostOpsResult::Expired;
    receipt.state = DispatchWindow::State::Expired;
    send_receipt(receipt, request, now_ms);
    return;
  }
  const std::uint64_t remaining = submit.device_deadline - now_ms;
  const std::uint32_t lifetime = static_cast<std::uint32_t>(
      remaining < fields.ttl_ms ? remaining : fields.ttl_ms);

  if (fields.destination == config_.node) {
    // Host loopback: the payload is delivered to THIS session's ReceiveLog.
    // Only HOST_RECEIVE_RAM is meaningful here — a scope-1 mailbox delivery
    // has no local consumer.
    if (fields.gateway_scope !=
        static_cast<std::uint8_t>(endpoint::GatewayScope::HostReceiveRam)) {
      refuse(HostOpsResult::InvalidRequest);
      return;
    }
    // Synthesize the canonical Service Submit prefix exactly as the wire
    // form carries it: ver1/sub3/scope/flags0 | token16 | boot8 | plen2 |
    // reserved2. The host recomputes the digest over prefix+payload.
    std::array<std::uint8_t, endpoint::kServiceSubmitHeaderSize> prefix{};
    {
      ByteWriter writer(MutableByteView{prefix.data(), prefix.size()});
      (void)writer.write_u8(endpoint::kServicePayloadVersion);
      (void)writer.write_u8(
          static_cast<std::uint8_t>(endpoint::ServiceSubtype::Submit));
      (void)writer.write_u8(fields.gateway_scope);
      (void)writer.write_u8(0);
      (void)writer.write_bytes(
          ByteView{registration_.token.data(), registration_.token.size()});
      (void)writer.write_u64(config_.boot_id);
      (void)writer.write_u16(static_cast<std::uint16_t>(fields.payload.size));
      (void)writer.write_u16(0);
    }
    // Canonical bytes = prefix || payload (identical to the wire submit);
    // the digest is the same value handle_submit computes for wire frames.
    std::array<std::uint8_t,
               endpoint::kServiceSubmitHeaderSize + kCanonicalGatewayPayloadMax>
        canonical{};
    std::memcpy(canonical.data(), prefix.data(), prefix.size());
    if (fields.payload.size > 0) {
      std::memcpy(canonical.data() + prefix.size(), fields.payload.data,
                  fields.payload.size);
    }
    RequestDigest digest{};
    sha256(ByteView{canonical.data(), prefix.size() + fields.payload.size},
           digest);
    const std::uint32_t synth_session =
        static_cast<std::uint32_t>(proof_.session_id);
    const MessageKey key{config_.node,
                         MessageId{synth_session, submit.dispatch_seq}};
    const Status queued =
        queue_ingress(/*loopback=*/true, key, digest,
                      ByteView{prefix.data(), prefix.size()}, fields.payload,
                      submit.dispatch_seq, now_ms);
    if (!queued) {
      refuse(HostOpsResult::MeshRejected);
      return;
    }
    if (!window_.record_sent(submit.dispatcher, submit.dispatch_seq,
                             submit.canonical_hash, submit.operation_id,
                             fields.delivery, synth_session,
                             submit.dispatch_seq)) {
      send_record_refusal_receipt(receipt, submit, request, now_ms);
      return;
    }
    receipt.result = HostOpsResult::Ok;
    receipt.state = DispatchWindow::State::Sent;
    receipt.msg_session = synth_session;
    receipt.msg_seq = submit.dispatch_seq;
    receipt.msg_valid = true;
    receipt.evidence = DispatchWindow::Evidence::GatewayAccepted;
    send_receipt(receipt, request, now_ms);
    return;
  }

  // Remote gateway: admit the position (Sent, no wire key yet), then run
  // the component's own authenticated resolve→send→result path. The SUBMIT
  // answer reports the admitted position immediately; progress and the
  // terminal receipt surface through QUERY_DISPATCH.
  PendingGatewaySend* send = find_gateway_send(submit.dispatch_seq);
  if (send != nullptr) free_gateway_send(*send);  // defensive: Admit = fresh
  send = nullptr;
  for (PendingGatewaySend& candidate : pending_sends_) {
    if (!candidate.occupied) {
      send = &candidate;
      break;
    }
  }
  if (send == nullptr) {
    refuse(HostOpsResult::MeshRejected);
    return;
  }
  if (!window_.record_pending(submit.dispatcher, submit.dispatch_seq,
                              submit.canonical_hash, submit.operation_id,
                              fields.delivery)) {
    send_record_refusal_receipt(receipt, submit, request, now_ms);
    return;
  }
  send->occupied = true;
  send->dispatch_seq = submit.dispatch_seq;
  send->destination = fields.destination;
  send->scope = fields.gateway_scope;
  send->payload_size = fields.payload.size;
  if (fields.payload.size > 0) {
    std::memcpy(send->payload.data(), fields.payload.data,
                fields.payload.size);
  }
  send->lifetime_ms = lifetime < kGatewayLifetimeMaxMs
                          ? lifetime
                          : kGatewayLifetimeMaxMs;
  send->deadline_ms = now_ms + remaining;
  send->stage = GatewaySendStage::Resolving;
  // Scope-2 remote delivery pins the SAME authenticated principal bound to
  // this registration (same-principal delivery — the only host identity
  // the canonical can prove); scope-1 carries the required zero digest.
  HostDigest expected{};
  if (fields.gateway_scope ==
      static_cast<std::uint8_t>(endpoint::GatewayScope::HostReceiveRam)) {
    expected = registration_.principal_digest;
  }
  const endpoint::GatewayScope scope =
      fields.gateway_scope ==
              static_cast<std::uint8_t>(endpoint::GatewayScope::HostReceiveRam)
          ? endpoint::GatewayScope::HostReceiveRam
          : endpoint::GatewayScope::GatewaySdkRam;
  const std::uint32_t resolve_budget =
      remaining < kGatewayResolveBudgetMs
          ? static_cast<std::uint32_t>(remaining)
          : kGatewayResolveBudgetMs;
  const Status resolved =
      gateway_->resolve(fields.destination, scope, expected, resolve_budget,
                        now_ms, send->endpoint);
  if (!resolved) {
    fail_gateway_send(send->dispatch_seq);
    *send = PendingGatewaySend{};
    const DispatchWindow::Slot* slot = window_.find(submit.dispatch_seq);
    if (slot != nullptr) fill_receipt_from_slot(receipt, *slot);
    receipt.result = HostOpsResult::Ok;
    send_receipt(receipt, request, now_ms);
    return;
  }
  send->endpoint_held = true;
  receipt.result = HostOpsResult::Ok;
  receipt.state = DispatchWindow::State::Sent;
  receipt.evidence = DispatchWindow::Evidence::GatewayAccepted;
  send_receipt(receipt, request, now_ms);
}

void UsbBridge::handle_host_register(const std::uint64_t request,
                                     const ByteView inner,
                                     const MonotonicMs now_ms) noexcept {
  HostRegisterRequest reg{};
  if (!decode_host_register(inner, reg)) {
    send_error(UsbErrorCode::ProtocolError, request, "REGISTER_MALFORMED",
               now_ms);
    return;
  }
  HostRegisterResponse response{};
  const auto answer = [&]() {
    std::array<std::uint8_t,
               kGatewayInnerHeadSize + kHostRegisterResponsePayload>
        body{};
    std::size_t body_size = 0;
    if (encode_host_register_response(
            response, MutableByteView{body.data(), body.size()}, body_size)) {
      enqueue(FrameKind::HostOps, 0, request,
              ByteView{body.data(), body_size}, now_ms);
    } else {
      ++stats_.dropped_frames;
    }
  };
  if ((config_.capability & kCapGatewayEndpointV1) == 0 || gateway_ == nullptr ||
      !gateway_->gateway_enabled()) {
    response.result = static_cast<std::uint16_t>(GatewayOpsResult::Unsupported);
    answer();
    return;
  }
  // The registration binds the AUTHENTICATED session: the network must
  // match the transcript, the host boot must be a real incarnation id and
  // the requested lease must be nonzero and sane.
  if (reg.network != transcript_.network) {
    response.result = static_cast<std::uint16_t>(GatewayOpsResult::Denied);
    answer();
    return;
  }
  if (reserved_id(reg.host_boot) || reg.lease_ms == 0 ||
      reg.lease_ms > 60000) {
    response.result = static_cast<std::uint16_t>(GatewayOpsResult::Invalid);
    answer();
    return;
  }
  if (registration_.active && registration_.host_boot == reg.host_boot &&
      registration_.usb_session == proof_.session_id) {
    // Renewal: same session + same host boot extends the CURRENT token —
    // the host cannot rotate its own binding without a new session.
    registration_.lease_deadline_ms = now_ms + kHostRegisterLeaseMs;
  } else {
    HostDigest digest{};
    sha256(ByteView{transcript_.principal.data(), transcript_.principal_len},
           digest);
    registration_.active = true;
    registration_.host_boot = reg.host_boot;
    registration_.usb_session = proof_.session_id;
    registration_.principal_digest = digest;
    registration_.lease_deadline_ms = now_ms + kHostRegisterLeaseMs;
    ++registration_.counter;
    // Token = session || counter: unique per (session, register), never
    // zero, never carried across sessions — the binding authenticates it.
    write_u64(registration_.token.data(), proof_.session_id);
    write_u64(registration_.token.data() + 8, registration_.counter);
  }
  response.token = registration_.token;
  response.gateway_boot = config_.boot_id;
  response.host_digest = registration_.principal_digest;
  response.lease_ms = kHostRegisterLeaseMs;
  response.result = static_cast<std::uint16_t>(GatewayOpsResult::Ok);
  answer();
}

void UsbBridge::handle_host_unregister(const std::uint64_t request,
                                       const ByteView inner,
                                       const MonotonicMs now_ms) noexcept {
  HostUnregisterRequest unreg{};
  if (!decode_host_unregister(inner, unreg)) {
    send_error(UsbErrorCode::ProtocolError, request, "UNREGISTER_MALFORMED",
               now_ms);
    return;
  }
  HostUnregisterResponse response{};
  const auto answer = [&]() {
    std::array<std::uint8_t,
               kGatewayInnerHeadSize + kHostUnregisterResponsePayload>
        body{};
    std::size_t body_size = 0;
    if (encode_host_unregister_response(
            response, MutableByteView{body.data(), body.size()}, body_size)) {
      enqueue(FrameKind::HostOps, 0, request,
              ByteView{body.data(), body_size}, now_ms);
    } else {
      ++stats_.dropped_frames;
    }
  };
  if ((config_.capability & kCapGatewayEndpointV1) == 0 || gateway_ == nullptr ||
      !gateway_->gateway_enabled()) {
    response.result = static_cast<std::uint16_t>(GatewayOpsResult::Unsupported);
    answer();
    return;
  }
  // Only the CURRENT session's token may release the registration — a
  // stale or foreign token can never revoke the replacement binding.
  if (!registration_.active ||
      unreg.token != registration_.token ||
      registration_.usb_session != proof_.session_id) {
    response.result = static_cast<std::uint16_t>(GatewayOpsResult::Stale);
    answer();
    return;
  }
  registration_ = HostRegistration{};
  response.result = static_cast<std::uint16_t>(GatewayOpsResult::Ok);
  answer();
}

void UsbBridge::handle_ingress_ack(const std::uint64_t request,
                                   const ByteView inner,
                                   const MonotonicMs now_ms) noexcept {
  GatewayIngressAck ack{};
  if (!decode_gateway_ingress_ack(inner, ack)) {
    send_error(UsbErrorCode::ProtocolError, request, "ACK_MALFORMED", now_ms);
    return;
  }
  PendingIngress* slot = find_ingress(request);
  if (slot == nullptr) {
    // No pending record for this request id: a stray or replayed ACK is
    // not evidence for anything — counted, never trusted.
    ++stats_.rx_errors;
    return;
  }
  const bool bound = registration_.active &&
                     ack.token == registration_.token &&
                     ack.ref_origin == slot->key.origin &&
                     ack.ref_session == slot->key.id.session &&
                     ack.ref_sequence == slot->key.id.sequence &&
                     ack.request_digest == slot->digest;
  if (!bound) {
    // A mismatched ACK is not storage evidence: the slot stays armed so
    // the real answer can still land inside the ack window.
    ++stats_.rx_errors;
    return;
  }
  const bool stored =
      ack.outcome == static_cast<std::uint16_t>(GatewayOpsResult::Ok);
  const MessageKey key = slot->key;
  const bool loopback = slot->loopback;
  const std::uint64_t dispatch_seq = slot->dispatch_seq;
  *slot = PendingIngress{};
  if (loopback) {
    (void)window_.note_gateway_outcome(dispatch_seq, stored,
                                     /*host_receive_ram=*/stored);
  } else if (gateway_ != nullptr) {
    // The component emits the Service Receipt only on real storage
    // evidence; a non-OK outcome completes as an honest non-success.
    gateway_->on_host_ingress_ack(key, stored, now_ms);
  }
}

void UsbBridge::on_gateway_resolved(const GatewayEndpoint& endpoint,
                                    const NodeId gateway,
                                    const Status result) noexcept {
  // The callback is only a hint: pump_gateway() derives each pending
  // send's true state from endpoint_state() every tick, which stays exact
  // even when two resolves to the same gateway finish in one poll.
  (void)endpoint;
  (void)gateway;
  (void)result;
}

void UsbBridge::on_gateway_result(const GatewaySendResult& result) noexcept {
  for (PendingGatewaySend& send : pending_sends_) {
    if (!send.occupied || send.stage != GatewaySendStage::Sent ||
        send.sent_id != result.id) {
      continue;
    }
    const bool received = result.state == GatewaySendState::EndpointReceived;
    const bool host_ram =
        send.scope ==
        static_cast<std::uint8_t>(endpoint::GatewayScope::HostReceiveRam);
    (void)window_.note_gateway_outcome(send.dispatch_seq, received,
                                       host_ram && received);
    free_gateway_send(send);
    return;
  }
}

void UsbBridge::pump_gateway(const MonotonicMs now_ms) noexcept {
  // Outstanding ingress: one bounded resend inside the ack window (a lost
  // 0x12 must not strand the pending record — G03); the host dedups on the
  // bound MessageKey so the retry is safe.
  for (PendingIngress& slot : pending_ingress_) {
    if (!slot.occupied) continue;
    if (now_ms >= slot.deadline_ms) {
      const bool loopback = slot.loopback;
      const std::uint64_t dispatch_seq = slot.dispatch_seq;
      slot = PendingIngress{};
      if (loopback) fail_gateway_send(dispatch_seq);
      // Wire slots: the component's own host_ack_deadline completes the
      // record as a non-success — no double ingress ever.
      continue;
    }
    if (!slot.resent && now_ms >= slot.resend_at_ms) {
      if (enqueue(FrameKind::HostOps, 0, slot.request,
                  ByteView{slot.body.data(), slot.body_size}, now_ms)) {
        slot.resent = true;
      }
    }
  }
  // Host-originated sends: resolve → send → window outcome.
  for (PendingGatewaySend& send : pending_sends_) {
    if (!send.occupied) continue;
    if (now_ms >= send.deadline_ms) {
      fail_gateway_send(send.dispatch_seq);
      free_gateway_send(send);
      continue;
    }
    if (send.stage == GatewaySendStage::Resolving && gateway_ != nullptr) {
      const EndpointState state = gateway_->endpoint_state(send.endpoint);
      if (state == EndpointState::Resolving) continue;
      if (state != EndpointState::Ready) {
        fail_gateway_send(send.dispatch_seq);
        free_gateway_send(send);
        continue;
      }
      send.stage = GatewaySendStage::Ready;
    }
    if (send.stage == GatewaySendStage::Ready && gateway_ != nullptr) {
      const std::uint64_t remaining =
          send.deadline_ms > now_ms ? send.deadline_ms - now_ms : 0;
      std::uint32_t lifetime = send.lifetime_ms;
      if (remaining < lifetime) {
        lifetime = static_cast<std::uint32_t>(remaining);
      }
      if (lifetime == 0) {
        fail_gateway_send(send.dispatch_seq);
        free_gateway_send(send);
        continue;
      }
      MessageId id{};
      const Status sent =
          gateway_->send(send.endpoint,
                         ByteView{send.payload.data(), send.payload_size},
                         lifetime, now_ms, id);
      if (!sent) {
        fail_gateway_send(send.dispatch_seq);
        free_gateway_send(send);
        continue;
      }
      send.sent_id = id;
      send.stage = GatewaySendStage::Sent;
      (void)window_.bind_message(send.dispatch_seq, id.session, id.sequence);
      // The send record holds its own endpoint reference — release ours.
      gateway_->endpoint_release(send.endpoint);
      send.endpoint_held = false;
    }
  }
}

}  // namespace routeloom::usb
