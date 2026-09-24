#pragma once

// Device-side USB bridge (G-USB, portable level). Connects a byte stream
// (UART/TTY/loopback) to a MeshNode through the v0.1 COBS+CRC32 profile, the
// EXPERIMENTAL dev-auth session (see usb_session.hpp) and session-direction
// cumulative credit. Not yet qualified on real USB hardware (HIL remains).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/config_wire.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/gateway.hpp"
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
  // Diagnostic replies dropped because the query's own lifetime expired
  // while the frame waited for USB credits (04 §USB: credit starvation
  // must not deliver a stale snapshot nor lose it silently).
  std::uint64_t diagnostics_expired{0};
  // node_status_v1: events handed to the TX queue, and events held back
  // because the data queue was inside its application reserve (they are
  // retried on the next monitor pass — never dropped).
  std::uint64_t node_events{0};
  std::uint64_t node_events_deferred{0};
};

class UsbBridge final : public UsbFrameSink, public NodeObserver,
                        public GatewayHostSink, public GatewayDeliveryObserver,
                        public ConfigHostSink, public DiagnosticSink,
                        public sdkv1::JoinRelayHostSink {
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

  // Late nonce binding: seeds the device nonce once boot entropy is
  // available, before the pump loop can serve a HELLO.
  void set_device_nonce(std::uint64_t nonce) noexcept {
    config_.device_nonce = nonce;
  }

  // Late gateway binding (P3): installs the component as the node's Service
  // endpoint, enables the gateway role bound to this boot id, and wires the
  // bridge in as BOTH the HOST_RECEIVE_RAM sink (0x11/0x12 ingress) and the
  // observer for host-originated gateway sends (schema-2 SUBMIT).
  // Attaching also advertises CAP_GATEWAY_ENDPOINT_V1 in HelloAck (mirroring
  // attach_config): the bit is set exactly when the endpoint exists, so a
  // build that never attaches answers Unsupported instead of advertising.
  // Returns the enable_gateway result (boot id must be nonzero).
  Status attach_gateway(GatewayDelivery& gateway) noexcept;

  // Late config binding (P5): installs the component as the node's routed
  // config endpoint (set_config_sink) and advertises CAP_CONFIG_ENDPOINT_V1
  // in HelloAck. The bridge is the component's ConfigHostSink — the async
  // 0x21/0x22/0x23 replies land on on_config_reply.
  Status attach_config(ConfigGateway& gateway) noexcept;

  // Late diagnostics binding (m1-completion D1d): installs this bridge as
  // the node's DiagnosticSink so remote TelemetrySnapshot/Reject bodies
  // correlate to pending 0x30 requests, and advertises CAP_M1_DIAGNOSTICS_V1
  // in HelloAck. Requires config_.mesh to be set; the remote-answer opt-in
  // (telemetry_remote) stays the owner's separate decision.
  Status attach_diagnostics() noexcept;

  // Late node-status binding (node_status_v1): serves HostOps 0x40 paginated
  // per-node link/route snapshots and, after a host query sets SUBSCRIBE,
  // streams 0x42 join/leave/route-change events for that session only.
  // Advertises CAP_NODE_STATUS_V1 in HelloAck. Requires config_.mesh.
  Status attach_node_status() noexcept;
  const NodeStatusMonitor& node_status_monitor() const noexcept {
    return node_monitor_;
  }

  // Late group binding (group_delivery_v1): serves HostOps 0x50 GROUP_SEND
  // and 0x52 GROUP_QUERY on the bridge's mesh node (which must be a route
  // gateway of the gateway-scoped profile for a send to be admitted) and
  // answers with 0x51 GROUP_STATUS; an admitted send gets one more FINAL
  // 0x51 under its request id when it settles. Advertises
  // CAP_GROUP_DELIVERY_V1 in HelloAck. Requires config_.mesh.
  Status attach_group() noexcept;

  // Late join-relay binding (join_relay_v2, docs/design/sdk-v1/02 §7.2/§7.4,
  // #116): serves HostOps 0x61 JOIN_RELAY_DOWN / 0x62 JOIN_RELAY_ABORT
  // through the gateway's JoinRelayGateway (answered by 0x63) and becomes
  // its host sink while a session is ACTIVE, so complete up relay objects
  // leave as 0x60 and relay ends as 0x62 (request id 0). Advertises
  // CAP_JOIN_RELAY_V2 in HelloAck. The sink follows the session: a
  // disconnect detaches it (ending the live exchanges) and the next ACTIVE
  // session re-attaches it. The owner feeds the gateway's Wire side; the
  // bridge never touches the mesh here.
  Status attach_join_relay(sdkv1::JoinRelayGateway& gateway) noexcept;

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
  // Group sends admitted through 0x50: a terminal summary becomes the FINAL
  // 0x51 under the original request id. (Group messages RECEIVED by this
  // node keep the default on_group_message -> on_message DataFromMesh path.)
  void on_group_delivery(const GroupDeliveryResult& result) noexcept override;
  void on_diagnostic(const char* reason, NodeId peer,
                     const MessageId* message) noexcept override;

  // GatewayHostSink (P3): the gateway component's readiness check and its
  // HOST_RECEIVE_RAM completion entry point. Ready only while a host
  // registration is live on THIS session; ingress queues the bounded 0x11
  // frame — storage evidence arrives as the host's 0x12.
  bool host_ready(HostBinding& binding) noexcept override;
  Status host_ingress(const MessageKey& key, const RequestDigest& request_digest,
                      ByteView submit_prefix, ByteView payload,
                      MonotonicMs now_ms) noexcept override;

  // GatewayDeliveryObserver (P3): resolve/send completions for
  // host-originated schema-2 sends to OTHER gateways. Wire-originated
  // outcomes never land here — they belong to the remote origin.
  void on_gateway_resolved(const GatewayEndpoint& endpoint, NodeId gateway,
                           Status result) noexcept override;
  void on_gateway_result(const GatewaySendResult& result) noexcept override;

  // ConfigHostSink (P5): the config component's async outcome. Encodes the
  // 0x21/0x22/0x23 reply body and queues it under the original request id —
  // the reply is framed, never an optimistic claim of application.
  void on_config_reply(std::uint64_t request, std::uint8_t sub,
                       ConfigOpsResult result, NodeId target, ByteView body,
                       MonotonicMs now_ms) noexcept override;

  // DiagnosticSink (D1d): a remote observer's end-verified Snapshot/Reject
  // resolves the pending 0x30 request matching its request_id — correlation
  // is on the diagnostic body's own id, never the transport message.
  void on_diagnostic_body(NodeId observer, ByteView body,
                          MonotonicMs now_ms) noexcept override;

  // JoinRelayHostSink (join_relay_v2): only while a session is ACTIVE —
  // otherwise the gateway tells the proxy authority_unreachable (07 §7).
  Status relay_up(NodeId proxy, std::uint8_t hops, ByteView object) noexcept override;
  Status relay_abort(NodeId proxy, sdkv1::RelayToken token,
                     sdkv1::RelayAbortReason reason) noexcept override;

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
    std::uint64_t request{0};
    // 0 = never expires; diagnostic replies carry the query's deadline so
    // credit starvation cannot retain and later deliver stale evidence.
    MonotonicMs expires_ms{0};
    std::array<std::uint8_t, kMaxTxInner> body{};
    std::size_t body_size{0};
    std::uint16_t flags{0};
    FrameKind kind{FrameKind::KeepAlive};
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
  // Schema-2 SUBMIT: the canonical carries the gateway destination
  // extension bound to the live host registration. dest==this node is the
  // host loopback (scope-2 ingress straight into the attached ReceiveLog);
  // any other destination is resolved + sent through the gateway
  // component's own origin path.
  void handle_gateway_submit(const SubmitRequest& submit,
                             const CanonicalFields& fields,
                             DispatchReceipt& receipt, std::uint64_t request,
                             MonotonicMs now_ms) noexcept;
  void handle_host_register(std::uint64_t request, ByteView inner,
                            MonotonicMs now_ms) noexcept;
  void handle_host_unregister(std::uint64_t request, ByteView inner,
                              MonotonicMs now_ms) noexcept;
  // The host's storage answer for a device-issued 0x11. Correlates by the
  // frame's request id; all bound fields (token, MessageKey, request
  // digest) must verify before the outcome is trusted.
  void handle_ingress_ack(std::uint64_t request, ByteView inner,
                          MonotonicMs now_ms) noexcept;
  // Shared ingress path for wire submits (GatewayHostSink) and the host
  // loopback: allocates a bounded pending slot, encodes the 0x11 body and
  // queues it. False = pre-acceptance refusal (slot/queue full) — the
  // caller drops its reservation, never a partial accept.
  Status queue_ingress(bool loopback, const MessageKey& key,
                       const RequestDigest& digest, ByteView submit_prefix,
                       ByteView payload, std::uint64_t dispatch_seq,
                       MonotonicMs now_ms) noexcept;
  void handle_ops_query(std::uint64_t request, ByteView inner,
                        MonotonicMs now_ms) noexcept;
  void handle_ops_retire(std::uint64_t request, ByteView inner,
                         MonotonicMs now_ms) noexcept;
  void handle_ops_skip(std::uint64_t request, ByteView inner,
                       MonotonicMs now_ms) noexcept;
  void handle_ops_time_sample(std::uint64_t request, ByteView inner,
                              MonotonicMs now_ms) noexcept;
  // Config endpoint requests (0x20/0x21/0x23): decode, gate on
  // CAP_CONFIG_ENDPOINT_V1 + an attached component, then hand to
  // ConfigGateway. Synchronous refusals answer immediately with the mapped
  // ConfigOpsResult; admitted work reports asynchronously on on_config_reply.
  void handle_config_query(std::uint64_t request, ByteView inner,
                           MonotonicMs now_ms) noexcept;
  void handle_config_challenge(std::uint64_t request, ByteView inner,
                               MonotonicMs now_ms) noexcept;
  void handle_config_permit(std::uint64_t request, ByteView inner,
                            MonotonicMs now_ms) noexcept;
  // Maps a synchronous submit_* Status to the wire result code.
  static ConfigOpsResult config_result_for(const Status& status) noexcept;
  // Encodes + queues a 0x21/0x22/0x23 reply under `request`.
  void send_config_reply(std::uint64_t request, std::uint8_t sub,
                         ConfigOpsResult result, NodeId target, ByteView body,
                         MonotonicMs now_ms) noexcept;
  // Diagnostic request (0x30): decode, gate on CAP_M1_DIAGNOSTICS_V1, then
  // answer locally (CapabilitiesQuery, local TelemetryQuery) or admit a
  // bounded remote TelemetryQuery whose reply lands on on_diagnostic_body.
  void handle_diagnostic_request(std::uint64_t request, ByteView inner,
                                 MonotonicMs now_ms) noexcept;
  // NodeStatus query (0x40): decode, gate on CAP_NODE_STATUS_V1, optionally
  // (re)arm the event monitor for this session, then answer one 0x41 page.
  void handle_node_status_query(std::uint64_t request, ByteView inner,
                                MonotonicMs now_ms) noexcept;
  // Group send/query (0x50/0x52): decode, gate on CAP_GROUP_DELIVERY_V1,
  // then answer one 0x51 with the admission outcome / current summary.
  void handle_group_send(std::uint64_t request, ByteView inner,
                         MonotonicMs now_ms) noexcept;
  void handle_group_query(std::uint64_t request, ByteView inner,
                          MonotonicMs now_ms) noexcept;
  void send_group_status(std::uint64_t request, const GroupStatusReply& reply,
                         MonotonicMs now_ms) noexcept;
  // Join relay (0x61/0x62): decode, gate on CAP_JOIN_RELAY_V2 + an attached
  // gateway, hand to JoinRelayGateway and answer one 0x63.
  void handle_join_relay_down(std::uint64_t request, ByteView inner,
                              MonotonicMs now_ms) noexcept;
  void handle_join_relay_abort(std::uint64_t request, ByteView inner,
                               MonotonicMs now_ms) noexcept;
  void send_join_relay_result(std::uint64_t request, ConfigOpsResult result, NodeId proxy,
                              sdkv1::RelayToken token, MonotonicMs now_ms) noexcept;
  // poll(): diff the mesh against the armed baseline at most every
  // kNodeMonitorIntervalMs and queue bounded 0x42 events, leaving the data
  // queue's application reserve untouched.
  void pump_node_events(MonotonicMs now_ms) noexcept;
  static constexpr MonotonicMs kNodeMonitorIntervalMs = 250;
  static constexpr std::size_t kNodeEventBurst = 4;
  static constexpr std::size_t kNodeEventQueueReserve = 4;
  // Encodes + queues a 0x31 reply under `request`.
  void send_diagnostic_reply(std::uint64_t request, ConfigOpsResult result,
                             NodeId observer, ByteView body,
                             MonotonicMs now_ms,
                             MonotonicMs expires_ms = 0) noexcept;
  // One in-flight remote telemetry query per bounded slot; correlated by
  // the diagnostic body's own request_id, never the transport MessageId.
  static constexpr std::size_t kPendingDiagnosticCapacity = 4;
  struct PendingDiagnostic {
    bool active{false};
    std::uint32_t request_id{0};
    std::uint64_t usb_request{0};
    std::uint64_t usb_session{0};   // bound at alloc — never survives reset
    NodeId observer{kInvalidNodeId};
    MonotonicMs expires_ms{0};
  };
  PendingDiagnostic* find_pending_diagnostic(std::uint32_t request_id,
                                             NodeId observer) noexcept;
  PendingDiagnostic* alloc_pending_diagnostic(NodeId observer) noexcept;
  // Bridge-minted mesh correlation id — monotone, nonzero, wraps by reset.
  // The mesh request_id is NEVER the host-supplied value: a replayed 0x30
  // request with a recycled id cannot collide with an outstanding slot
  // because slots key on ids this bridge issued (04 §USB correlation).
  std::uint32_t next_diag_request_id() noexcept;
  std::uint32_t next_diag_request_id_{1};
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
               ByteView inner, MonotonicMs now_ms,
               MonotonicMs expires_ms = 0) noexcept;
  void pump_tx(MonotonicMs now_ms) noexcept;
  bool take_control_token(std::uint8_t& tokens, MonotonicMs& last_refill,
                          MonotonicMs now_ms) noexcept;
  void note_credit_stall(MonotonicMs now_ms) noexcept;
  void reset_session_state() noexcept;
  void begin_auth_session(MonotonicMs now_ms) noexcept;
  std::uint64_t request_for(const MessageId& id) const noexcept;

  // --- Gateway host lane (P3) -------------------------------------------------
  // Current host endpoint registration (05 §5.6). The token binds the
  // authenticated principal digest + host boot + THIS USB session — it is
  // what schema-2 canonical submits present as gateway_token and what the
  // host echoes in 0x12/0x13. Cleared on every session teardown; a new
  // session can never inherit it.
  struct HostRegistration {
    bool active{false};
    std::array<std::uint8_t, 16> token{};
    HostDigest principal_digest{};
    std::uint64_t host_boot{0};
    std::uint64_t usb_session{0};
    MonotonicMs lease_deadline_ms{0};
    std::uint64_t counter{0};  // token mint sequence within the session
  };

  // One outstanding 0x11 ingress (device→host). The slot holds the encoded
  // body so a lost 0x12 can be retried once; the host dedups on the bound
  // MessageKey (G03). `loopback` marks a host-originated schema-2 send to
  // this node — its outcome updates the dispatch window directly instead
  // of a GatewayDelivery dedup record.
  struct PendingIngress {
    bool occupied{false};
    bool loopback{false};
    bool resent{false};
    std::uint64_t request{0};
    std::uint64_t dispatch_seq{0};
    MessageKey key{};
    RequestDigest digest{};
    std::uint16_t body_size{0};
    std::array<std::uint8_t, kGatewayInnerHeadSize + kGatewayIngressMaxPayload>
        body{};
    MonotonicMs resend_at_ms{0};
    MonotonicMs deadline_ms{0};
  };

  // One host-originated schema-2 send to a REMOTE gateway: admitted into
  // the dispatch window immediately (record_pending, Sent+!msg_valid), then
  // resolved → sent → result via the gateway component's origin path.
  enum class GatewaySendStage : std::uint8_t { Resolving, Ready, Sent };
  struct PendingGatewaySend {
    bool occupied{false};
    std::uint64_t dispatch_seq{0};
    NodeId destination{kInvalidNodeId};
    std::uint8_t scope{0};
    std::array<std::uint8_t, kGatewayPayloadMaxBytes> payload{};
    std::size_t payload_size{0};
    std::uint32_t lifetime_ms{0};
    MonotonicMs deadline_ms{0};
    GatewaySendStage stage{GatewaySendStage::Resolving};
    GatewayEndpoint endpoint{};
    bool endpoint_held{false};
    MessageId sent_id{};
  };

  PendingIngress* find_ingress(std::uint64_t request) noexcept;
  PendingGatewaySend* find_gateway_send(std::uint64_t dispatch_seq) noexcept;
  void free_gateway_send(PendingGatewaySend& send) noexcept;
  // poll() drives: Resolved→send, ack-window ingress resend, slot expiry.
  void pump_gateway(MonotonicMs now_ms) noexcept;
  // Marks a window position terminally failed for an in-flight gateway
  // send whose outcome became unknowable (refusal, timeout, session loss).
  void fail_gateway_send(std::uint64_t dispatch_seq) noexcept;
  void clear_gateway_state() noexcept;

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

  // TX-path staging lives in members (the bridge is a static object in
  // firmware): pump_tx runs on every emitted frame on an 8 KB main task,
  // so frame/body scratch must be .bss, never task stack. Single-threaded
  // use only — no caller may hold a view into these across a bridge call.
  static constexpr std::size_t kMaxTxBody = kMaxTxInner + kProtectedBodyOverhead;
  static constexpr std::size_t kTxScratchBytes = kHeaderSize + kMaxTxBody + kCrcSize;
  FixedQueue<TxItem, kControlQueueCapacity> control_q_{};
  FixedQueue<TxItem, kDataQueueCapacity> data_q_{};
  // The device never emits a body above kMaxTxBody, so the in-progress wire
  // frame needs the COBS bound of kTxScratchBytes, not of a 4 KB frame.
  std::array<std::uint8_t, encoded_frame_bound(kTxScratchBytes)> tx_wire_{};
  // tx_body_ is live only inside pump_tx (seal -> encode_frame). Between
  // pumps it doubles as the transient staging of two RX-side encoders that
  // finish before returning (ram-budget.md): the DataToMesh canonical hash
  // input (kind || inner) and the node-status page reply — each is copied
  // into a TxItem or hashed before any pump can run.
  std::array<std::uint8_t, kMaxTxBody> tx_body_{};
  static_assert(kMaxTxBody >= kMaxTxInner + 1, "canonical DataToMesh staging");
  std::array<std::uint8_t, kTxScratchBytes> encode_scratch_{};
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

  // --- Gateway host lane state (P3) ------------------------------------------
  GatewayDelivery* gateway_{nullptr};
  // Routed config endpoint (P5): the bridge-facing ConfigGateway, installed
  // as the mesh node's config_sink_. nullptr -> config ops Unsupported.
  ConfigGateway* config_gateway_{nullptr};
  HostRegistration registration_{};
  // Bounded pending 0x11 ingress slots — shared by wire submits and the
  // host loopback so the 8-deep pending bound is one honest pool.
  std::array<PendingIngress, kGatewayPendingMax> pending_ingress_{};
  std::array<PendingGatewaySend, kGatewayPendingMax> pending_sends_{};
  std::uint64_t next_ingress_request_{1};
  // Bounded remote diagnostic queries (D1d): full -> the 0x30 request is
  // refused with Busy, never silently queued beyond the bound.
  std::array<PendingDiagnostic, kPendingDiagnosticCapacity> pending_diag_{};
  // node_status_v1 state: the per-session event baseline (disarmed on every
  // session teardown) and the .bss page staging for 0x41 replies.
  NodeStatusMonitor node_monitor_{};
  MonotonicMs node_monitor_ms_{0};
  std::array<NodeStatus, kNodeStatusPageMax> node_page_{};
  // The encoded page reply is staged in tx_body_ (see above).
  static_assert(kMaxTxBody >= kGatewayInnerHeadSize + kNodeStatusPageMaxPayload,
                "node-status page staging");
  // group_delivery_v1: admitted 0x50 sends awaiting their FINAL 0x51. The
  // node never holds more than kGroupOriginCapacity unsettled group
  // messages, so this bound cannot refuse a correlation the node admitted.
  struct PendingGroup {
    MessageId id{};
    std::uint64_t usb_request{0};
    bool used{false};
  };
  std::array<PendingGroup, kGroupOriginCapacity> pending_group_{};
  // join_relay_v2: the attached gateway engine (owner-provided storage;
  // nullptr -> 0x61/0x62 answer Unsupported). 0x60 bodies are staged in
  // tx_body_ like the node-status page (copied into a TxItem at once).
  sdkv1::JoinRelayGateway* join_relay_{nullptr};
  static_assert(kMaxTxBody >= kGatewayInnerHeadSize + kJoinRelayUpMaxPayload,
                "join relay up staging");
  static_assert(kGatewayInnerHeadSize + kJoinRelayUpMaxPayload <= kMaxTxInner,
                "a 0x60 body fits one TxItem");
  BridgeStats stats_{};
};

}  // namespace routeloom::usb
