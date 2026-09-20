#pragma once

// Device-side USB bridge (G-USB, portable level). Connects a byte stream
// (UART/TTY/loopback) to a MeshNode through the v0.1 COBS+CRC32 profile, the
// EXPERIMENTAL dev-auth session (see usb_session.hpp) and session-direction
// cumulative credit. Not yet qualified on real USB hardware (HIL remains).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/fixed_containers.hpp"
#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_codec.hpp"
#include "routeloom/usb_host_ops.hpp"
#include "routeloom/usb_session.hpp"

namespace routeloom::usb {

// Hello/HelloAck flag bit marking the AUTH step of the handshake.
constexpr std::uint16_t kFlagAuth = 0x0001;

// Credit inner-body subtypes.
constexpr std::uint8_t kCreditGrant = 0;
constexpr std::uint8_t kCreditQuery = 1;
constexpr std::uint8_t kCreditClose = 2;

constexpr std::uint8_t kDiagFlagHasMessage = 0x01;

// Session state machine: DISCONNECTED → HELLO → AUTHENTICATING → ACTIVE →
// DRAINING. Reconnect always builds a new session; partial frames, grants,
// consumed values, counters and request tokens are never reused.
enum class SessionState : std::uint8_t {
  Disconnected = 0,
  Hello,
  Authenticating,
  Active,
  Draining,
};

enum class UsbErrorCode : std::uint16_t {
  ProtocolError = 1,
  AuthFailed = 2,
  ReplayRejected = 3,
  StaleSession = 4,
  CreditExhausted = 5,
  Conflict = 6,
  Unsupported = 7,
  PayloadTooLarge = 8,
  Draining = 9,
  ConnectionStalled = 10,
  NotAuthenticated = 11,
  NoCapacity = 12,
  MeshRejected = 13,
};

// Device TX byte stream. write() may consume a prefix only; the caller
// retries the remainder (partial writes are expected and charged once).
class ByteStream {
 public:
  virtual ~ByteStream() = default;
  virtual Status write(ByteView data, std::size_t& written) noexcept = 0;
};

struct BridgeStats {
  std::uint64_t rx_frames{0};
  std::uint64_t rx_errors{0};
  std::uint64_t tx_frames{0};
  std::uint64_t tx_write_errors{0};
  std::uint64_t auth_failures{0};
  std::uint64_t replay_rejected{0};
  std::uint64_t stale_session{0};
  std::uint64_t credit_denied{0};
  std::uint64_t control_denied{0};
  std::uint64_t dropped_frames{0};
};

class UsbBridge final : public UsbFrameSink, public NodeObserver {
 public:
  struct Config {
    ByteView secret{};  // dev-profile shared secret; caller-owned, must outlive the bridge
    NodeId node{kInvalidNodeId};
    NetworkId network{0};
    std::uint64_t boot_id{0};
    std::uint32_t capability{0};
    // Base device nonce; mixed with a per-attempt counter so reconnects never
    // reuse a transcript. Real firmware should seed it from boot entropy.
    std::uint64_t device_nonce{0};
    MeshNode* mesh{nullptr};  // optional; DataToMesh is rejected when null
  };

  UsbBridge(const Config& config, ByteStream& stream) noexcept;

  // Late mesh binding: the bridge is typically the node's NodeObserver, so
  // the node cannot exist before the bridge is constructed.
  void set_mesh(MeshNode* mesh) noexcept { config_.mesh = mesh; }

  // Serial RX entry point: feed raw bytes read from the wire.
  void on_bytes(ByteView input, MonotonicMs now_ms) noexcept;
  // Periodic work: partial-frame timeout, handshake timeout, TX pump,
  // zero-credit queries and drain completion.
  void poll(MonotonicMs now_ms) noexcept;
  // Cable/daemon loss or local restart: tears down to DISCONNECTED and clears
  // all volatile session state. Idempotency records intentionally survive.
  void notify_disconnect(MonotonicMs now_ms) noexcept;

  // UsbFrameSink (called from the internal StreamDecoder).
  void on_frame(const UsbFrame& frame) noexcept override;
  void on_stream_error(Status status) noexcept override;

  // NodeObserver: mesh events become host frames.
  void on_message(const MessageKey& key, NodeId source, ByteView payload) noexcept override;
  void on_delivery(const DeliveryResult& result) noexcept override;
  void on_diagnostic(const char* reason, NodeId peer,
                     const MessageId* message) noexcept override;

  SessionState state() const noexcept { return state_; }
  std::uint64_t session_id() const noexcept {
    return proof_valid_ ? proof_.session_id : 0;
  }
  const BridgeStats& stats() const noexcept { return stats_; }
  const CumulativeCredit& tx_credit() const noexcept { return tx_credit_; }
  const CumulativeCredit& rx_credit() const noexcept { return rx_credit_; }
  bool connection_stalled() const noexcept { return connection_stalled_; }

 private:
  static constexpr std::size_t kMaxTxInner = 1024;
  static constexpr std::size_t kControlQueueCapacity = 4;
  static constexpr std::size_t kDataQueueCapacity = 8;
  static constexpr std::size_t kRequestMapCapacity = 8;
  static constexpr std::uint8_t kControlBurst = 4;
  static constexpr MonotonicMs kControlRefillMs = 100;  // 10 frames/s
  static constexpr std::size_t kControlMaxDecoded = 256;
  static constexpr std::uint64_t kRxGrantFrames = 8;
  static constexpr std::uint64_t kRxGrantBytes = 16384;
  static constexpr MonotonicMs kHandshakeTimeoutMs = 5000;
  static constexpr std::uint8_t kPreAuthBudget = 8;
  static constexpr std::uint32_t kPreAuthRefillMs = 2000;
  static constexpr std::uint8_t kAuthAttemptsMax = 3;
  static constexpr MonotonicMs kCreditQueryIntervalMs = 500;
  static constexpr std::uint8_t kCreditQueryMax = 3;
  static constexpr std::size_t kMaxReasonLen = 64;

  struct TxItem {
    FrameKind kind{FrameKind::KeepAlive};
    std::uint16_t flags{0};
    std::uint64_t request{0};
    std::array<std::uint8_t, kMaxTxInner> body{};
    std::size_t body_size{0};
  };

  struct RequestMap {
    MessageId id{};
    std::uint64_t request{0};
  };

  void handle_handshake_frame(const UsbFrame& frame, MonotonicMs now_ms) noexcept;
  void handle_hello(const UsbFrame& frame, MonotonicMs now_ms) noexcept;
  void handle_auth(const UsbFrame& frame, MonotonicMs now_ms) noexcept;
  void handle_authenticated(const UsbFrame& frame, MonotonicMs now_ms) noexcept;
  void dispatch_inner(FrameKind kind, std::uint16_t flags, std::uint64_t request,
                      ByteView inner, MonotonicMs now_ms) noexcept;
  void handle_data_to_mesh(std::uint64_t request, ByteView inner,
                           MonotonicMs now_ms) noexcept;
  void handle_host_ops(std::uint64_t request, ByteView inner,
                       MonotonicMs now_ms) noexcept;
  void handle_ops_submit(std::uint64_t request, ByteView inner,
                         MonotonicMs now_ms) noexcept;
  void handle_ops_query(std::uint64_t request, ByteView inner,
                        MonotonicMs now_ms) noexcept;
  void handle_ops_retire(std::uint64_t request, ByteView inner,
                         MonotonicMs now_ms) noexcept;
  void handle_ops_skip(std::uint64_t request, ByteView inner,
                       MonotonicMs now_ms) noexcept;
  void handle_ops_time_sample(std::uint64_t request, ByteView inner,
                              MonotonicMs now_ms) noexcept;
  void send_receipt(const DispatchReceipt& receipt, std::uint64_t request,
                    MonotonicMs now_ms) noexcept;
  void send_query_response(const QueryResponse& response, std::uint64_t request,
                           MonotonicMs now_ms) noexcept;
  void send_retire_response(const RetireResponse& response, std::uint64_t request,
                            MonotonicMs now_ms) noexcept;
  void send_time_sample_response(const TimeSampleResponse& response,
                                 std::uint64_t request,
                                 MonotonicMs now_ms) noexcept;
  // Correlates a MessageId to a host request id so a later on_delivery
  // resolves instead of surfacing as a request-0 orphan.
  void track_request(const MessageId& id, std::uint64_t request) noexcept;
  // Honest answer for a record-store refusal after Admit: reports the
  // position's actual state, never a fabricated mesh outcome.
  void send_record_refusal_receipt(DispatchReceipt& receipt,
                                   const SubmitRequest& submit,
                                   std::uint64_t request,
                                   MonotonicMs now_ms) noexcept;
  void handle_credit(std::uint64_t request, ByteView inner,
                     MonotonicMs now_ms) noexcept;
  void issue_rx_grant(bool initial, MonotonicMs now_ms) noexcept;
  void send_error(UsbErrorCode code, std::uint64_t request, const char* reason,
                  MonotonicMs now_ms) noexcept;
  bool enqueue(FrameKind kind, std::uint16_t flags, std::uint64_t request,
               ByteView inner, MonotonicMs now_ms) noexcept;
  void pump_tx(MonotonicMs now_ms) noexcept;
  bool take_control_token(std::uint8_t& tokens, MonotonicMs& last_refill,
                          MonotonicMs now_ms) noexcept;
  void note_credit_stall(MonotonicMs now_ms) noexcept;
  void reset_session_state() noexcept;
  void begin_auth_session(MonotonicMs now_ms) noexcept;
  std::uint64_t request_for(const MessageId& id) const noexcept;

  Config config_{};
  ByteStream& stream_;
  StreamDecoder decoder_;

  SessionState state_{SessionState::Disconnected};
  MonotonicMs state_entered_ms_{0};
  MonotonicMs now_ms_{0};
  SessionTranscript transcript_{};
  SessionProof proof_{};
  bool proof_valid_{false};
  std::uint64_t session_attempt_{0};
  std::uint8_t auth_attempts_{0};
  std::uint8_t preauth_budget_{kPreAuthBudget};
  MonotonicMs preauth_refill_ms_{0};
  std::uint64_t rx_counter_{0};  // next expected host→device counter
  std::uint64_t tx_counter_{0};  // next device→host counter

  CumulativeCredit tx_credit_{};  // host grants for device→host sends
  CumulativeCredit rx_credit_{};  // device grants consumed by host→device frames
  bool connection_stalled_{false};
  bool stall_reported_{false};
  std::uint8_t credit_queries_{0};
  MonotonicMs last_credit_query_ms_{0};

  std::uint8_t tx_tokens_{kControlBurst};
  MonotonicMs tx_bucket_ms_{0};
  std::uint8_t rx_tokens_{kControlBurst};
  MonotonicMs rx_bucket_ms_{0};

  FixedQueue<TxItem, kControlQueueCapacity> control_q_{};
  FixedQueue<TxItem, kDataQueueCapacity> data_q_{};
  std::array<std::uint8_t, kMaxEncodedFrame> tx_wire_{};
  std::size_t tx_wire_size_{0};
  std::size_t tx_wire_sent_{0};
  bool tx_wire_active_{false};

  std::uint64_t pending_request_{0};
  // True while a host_ops SUBMIT's synchronous mesh->send runs: the Accepted/
  // Queued callbacks it fires must be suppressed (the window record is
  // created right after, and later callbacks correlate through it).
  bool ops_send_active_{false};
  FixedPool<RequestMap, kRequestMapCapacity> request_map_{};
  IdempotencyTable idempotency_{};
  // Gateway dispatch window (CAP-I2). Bound to the boot lease at
  // construction; like the idempotency records it intentionally survives
  // USB reconnects (same boot = same lane/records). A reboot rebuilds the
  // bridge with a new lease, which wipes the window by construction.
  DispatchWindow window_;
  BridgeStats stats_{};
};

}  // namespace routeloom::usb
