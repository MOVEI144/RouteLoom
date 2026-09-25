#pragma once

// Authority channel, device side (G-SEC P5): the endpoint half of
// docs/design/sdk-v1/03-key-hierarchy.md §5.3.
//
// This file covers the channel only: the AuthorityEnvelope body codecs
// (JoinConfirm / GroupKeyUpdate / GroupKeyActivate / GroupKeyPull), the
// GK-id derivation, the seal/open helpers and the `AuthorityClient`
// initiator (RLRES1 purpose=4 over DAMS, envelope replay, re-entry guard).
// Carriers enter and leave through AuthorityPort. When the Owner attaches
// GroupKeyState, verified updates are committed before their ACK is sealed;
// without that state they are answered Unsupported, never false success.
//
// Portable-core discipline: no heap, no exceptions, every API noexcept, all
// state bounded and owned by the instance. Secrets (DAMS, traffic keys,
// GroupKeyUpdate bodies) are zeroized when retired or consumed.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/aead_gcm.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

class GroupKeyState;

// --- Carrier kinds (P5 §3.2/§3.3; shared with the PR4 mesh/USB transport) ---
enum class AuthorityCarrierKind : std::uint8_t {
  R1 = 1,
  R2 = 2,
  R3 = 3,
  Envelope = 4,
  Wake = 5,
};

constexpr bool authority_carrier_kind_valid(std::uint8_t kind) noexcept {
  return kind >= 1 && kind <= 5;
}

// --- Body codec (P5 §3.1; every integer big-endian, reserved = 0) ------------
//
// Common 16-byte head: body_version:u8=1 | op:u8 | flags:u16=0 |
// assignment_generation:u32!=0 | request_id:u64!=0. `op` 1 is the request,
// `op` 2 the reply; each sender allocates request_id monotonically inside
// its own channel (a reply carries a fresh id, never an echo).
constexpr std::size_t kAuthorityBodyHeadSize = 16;
constexpr std::uint8_t kAuthorityBodyVersion = 1;

struct AuthorityBodyHead {
  std::uint8_t op{0};
  std::uint32_t generation{0};
  std::uint64_t request_id{0};
};

Status authority_head_encode(const AuthorityBodyHead& head, MutableByteView out,
                             std::size_t& written) noexcept;
Status authority_head_decode(ByteView input, AuthorityBodyHead& out) noexcept;

// Type 1 JoinConfirm, op 1 (device -> authority), 60 bytes.
struct JoinConfirmUp {
  AuthorityBodyHead head{};
  std::array<std::uint8_t, 32> cert_hash{};
  std::uint32_t boot{0};
  std::uint32_t current{0};
  std::uint32_t next{0};
};
constexpr std::size_t kJoinConfirmUpSize = 60;

// Type 1 JoinConfirm, op 2 (authority -> device), 24 bytes.
struct JoinConfirmDown {
  AuthorityBodyHead head{};
  std::uint32_t confirmed_generation{0};
  std::uint32_t authority_active{0};
};
constexpr std::size_t kJoinConfirmDownSize = 24;

enum class UpdateCause : std::uint8_t {
  Periodic = 1,
  Removal = 2,
  Manual = 3,
};
enum class UpdateResult : std::uint8_t {
  Durable = 0,
  Conflict = 1,
  StorageFailure = 2,
  Busy = 3,
  Unsupported = 4,
};
enum class StoredState : std::uint8_t {
  None = 0,
  Staged = 1,
  Active = 2,
};

// Type 2 GroupKeyUpdate, op 1 (authority -> device), 56 bytes.
struct GroupKeyUpdate {
  AuthorityBodyHead head{};
  std::uint32_t g{0};
  UpdateCause cause{UpdateCause::Periodic};
  std::uint16_t overlap_s{0};  // periodic/manual 60, removal 10 — nothing else
  keys::Secret gk{};
};
constexpr std::size_t kGroupKeyUpdateSize = 56;

// Type 2/3 ACK, op 2 (device -> authority), 56 bytes. Only result=durable is
// convergence evidence; anything else reports a failure honestly.
struct GroupKeyAck {
  AuthorityBodyHead head{};
  std::uint32_t g{0};
  std::array<std::uint8_t, 32> gk_id{};
  UpdateResult result{UpdateResult::Unsupported};
  StoredState stored_state{StoredState::None};
};
constexpr std::size_t kGroupKeyAckSize = 56;

// Type 3 GroupKeyActivate, op 1 (authority -> device), 56 bytes.
struct GroupKeyActivate {
  AuthorityBodyHead head{};
  std::uint32_t g{0};
  std::array<std::uint8_t, 32> gk_id{};
  UpdateCause cause{UpdateCause::Periodic};
  std::uint16_t overlap_s{0};
};
constexpr std::size_t kGroupKeyActivateSize = 56;

enum class PullReason : std::uint8_t {
  UnknownNewerEpoch = 1,
  BootReconnectSync = 2,
  LostAckRepair = 3,
};

// Type 4 GroupKeyPull, op 1 (device -> authority), 28 bytes. A Pull is never
// ACKed; the authority answers with Update -> Activate.
struct GroupKeyPull {
  AuthorityBodyHead head{};
  std::uint32_t current{0};
  std::uint32_t next{0};
  PullReason reason{PullReason::BootReconnectSync};
};
constexpr std::size_t kGroupKeyPullSize = 28;

Status encode_join_confirm_up(const JoinConfirmUp& msg, MutableByteView out,
                              std::size_t& written) noexcept;
Status decode_join_confirm_up(ByteView input, JoinConfirmUp& out) noexcept;
Status encode_join_confirm_down(const JoinConfirmDown& msg, MutableByteView out,
                                std::size_t& written) noexcept;
Status decode_join_confirm_down(ByteView input, JoinConfirmDown& out) noexcept;
Status encode_group_key_update(const GroupKeyUpdate& msg, MutableByteView out,
                               std::size_t& written) noexcept;
Status decode_group_key_update(ByteView input, GroupKeyUpdate& out) noexcept;
Status encode_group_key_ack(const GroupKeyAck& msg, MutableByteView out,
                            std::size_t& written) noexcept;
Status decode_group_key_ack(ByteView input, GroupKeyAck& out) noexcept;
Status encode_group_key_activate(const GroupKeyActivate& msg, MutableByteView out,
                                 std::size_t& written) noexcept;
Status decode_group_key_activate(ByteView input, GroupKeyActivate& out) noexcept;
Status encode_group_key_pull(const GroupKeyPull& msg, MutableByteView out,
                             std::size_t& written) noexcept;
Status decode_group_key_pull(ByteView input, GroupKeyPull& out) noexcept;

// GK-id = SHA256("RouteLoom/v1/gk-id" || 0x00 || network:u64 || epoch:u32 ||
// GK:32): the ACK's key-confirmation identifier, never a raw-GK export.
using GkId = std::array<std::uint8_t, 32>;
void authority_gk_id(NetworkId network, std::uint32_t epoch, const keys::Secret& gk,
                     GkId& out) noexcept;

// --- Channel crypto ----------------------------------------------------------
//
// `authority_seal` refuses counter > 2^48-1 (CounterExhausted: the key must
// be retired, never wrapped) and zero ctx ids. `authority_open` additionally
// requires the envelope's ctx to equal the receiver-chosen `want_ctx` and
// maps an AEAD failure to AuthenticationFailed without touching `plaintext`
// beyond zeroing it. Neither tracks replay: the caller commits the window
// only after a successful open.
Status authority_seal(const routeloom::AeadGcm& aead, const keys::TrafficKey& tx,
                      keys::AuthorityEnvelopeType type, std::uint32_t ctx_id,
                      std::uint64_t counter, ByteView plaintext, MutableByteView out,
                      std::size_t& written) noexcept;
Status authority_open(const routeloom::AeadGcm& aead, const keys::TrafficKey& rx, ByteView envelope,
                      std::uint32_t want_ctx, MutableByteView plaintext, std::size_t& written,
                      keys::AuthorityEnvelopeHeader& header) noexcept;

// 64-frame replay window over one direction's envelope counter. `accept`
// commits only after the caller verified the AEAD tag; it returns false for
// replays and for counters at/below the window floor without moving it.
class AuthorityReplayWindow {
 public:
  AuthorityReplayWindow() noexcept { reset(); }
  void reset() noexcept;
  bool accept(std::uint64_t counter) noexcept;
  std::uint64_t max_seen() const noexcept { return max_; }
  bool empty() const noexcept { return empty_; }

 private:
  std::uint64_t max_{0};
  std::uint64_t bitmap_{0};
  bool empty_{true};
};

// --- Port / observer ---------------------------------------------------------

// Bounded carrier sink (the PR4 mesh/USB transport implements it). Copies
// `carrier` before returning; `token` identifies this send for the later
// TxResult. False = full, nothing queued, the client retries on Tick.
class AuthorityPort {
 public:
  virtual ~AuthorityPort() = default;
  virtual bool try_send(NodeId gateway, AuthorityCarrierKind kind, ByteView carrier,
                        std::uint64_t& token) noexcept = 0;
};

// Immutable channel events. Carries no secrets: group-key bytes are passed
// only to the attached durable state. `passthrough` borrows the client's RX
// buffer and is valid during the on_event call only — the observer must copy
// what it keeps.
struct AuthorityEvent {
  enum class Kind : std::uint8_t {
    ChannelReady = 0,   // R3 accepted; JoinConfirm is being sent
    ChannelLost,        // context retired (reason names the cause)
    JoinConfirmAck,     // JoinConfirm op 2 verified
    UpdateReceived,     // GroupKeyUpdate verified (no GK bytes attached)
    ActivateReceived,   // GroupKeyActivate verified
    Passthrough,        // verified type 5..8 plaintext for the P6 sink
  };
  Kind kind{Kind::ChannelLost};
  const char* reason{"ok"};  // ChannelLost / Passthrough detail
  std::uint8_t envelope_type{0};
  std::uint32_t g{0};  // Update/Activate group epoch
  UpdateCause cause{UpdateCause::Periodic};
  std::uint16_t overlap_s{0};
  std::uint32_t confirmed_generation{0};  // JoinConfirmAck
  std::uint32_t authority_active{0};      // JoinConfirmAck
  ByteView passthrough{};                 // Passthrough body bytes
};

class AuthorityObserver {
 public:
  virtual ~AuthorityObserver() = default;
  virtual void on_event(const AuthorityEvent& event) noexcept = 0;
};

// --- Client ------------------------------------------------------------------

// What Start needs. An attached GroupKeyState validates these values against
// the committed SiteRecord; standalone fake-carrier tests supply them directly.
struct AuthorityStart {
  NetworkId network{0};
  NodeId self{kInvalidNodeId};
  std::uint64_t site_id{0};
  NodeId gateway{kInvalidNodeId};  // carrier route address
  keys::Secret dams{};             // copied in; the caller may wipe after Start
  std::uint32_t generation{0};     // assignment generation for body heads
  rlres1::Epochs epochs{};         // R1 epochs (site_epoch == network >> 32)
  std::array<std::uint8_t, 32> member_cert_hash{};
  std::uint32_t boot{0};
  std::uint32_t gk_current{0};
  std::uint32_t gk_next{0};
};

struct AuthorityRxCarrier {
  AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
  ByteView bytes{};  // valid during the advance() call only
  // When this spans the transport's writable assembly, the client may
  // authenticate and erase it in place while its TX workspace is occupied.
  MutableByteView writable{};
};

struct AuthorityTxResult {
  std::uint64_t token{0};
  bool delivered{false};
};

struct AuthorityPullRequest {
  PullReason reason{PullReason::BootReconnectSync};
};

enum class AuthorityInputKind : std::uint8_t {
  Start = 0,
  RxCarrier,
  TxResult,
  Tick,
  RequestPull,
  Suspend,
};

struct AuthorityInput {
  AuthorityInputKind kind{AuthorityInputKind::Tick};
  AuthorityStart start{};
  AuthorityRxCarrier rx{};
  AuthorityTxResult tx{};
  AuthorityPullRequest pull{};
};

// Secret-free view of the channel. Safe to log and to read from callbacks.
struct AuthoritySnapshot {
  enum class State : std::uint8_t {
    Dormant = 0,
    Connecting,
    Ready,
    Backoff,
  };
  State state{State::Dormant};
  bool started{false};
  std::uint32_t rx_ctx{0};  // ours; peers stamp it into envelopes they send
  std::uint32_t tx_ctx{0};  // the authority's; stamped into envelopes we send
  std::uint64_t tx_counter{0};
  std::uint64_t rx_max{0};
  std::uint64_t next_request_id{1};
  std::uint64_t tx_sent{0};
  std::uint64_t tx_failed{0};
  std::uint64_t rx_accepted{0};
  std::uint64_t rx_rejected{0};
  std::uint32_t backoff_s{0};  // current backoff step (0 = not backing off)
  bool pull_pending{false};
  bool join_confirmed{false};
  // True while channel work is in flight (staged TX, pending ACK,
  // handshake or backoff). Diagnostics only: the channel naps across
  // sleep and resumes on Wake, so busyness never gates sleep.
  bool busy{false};
};

class AuthorityClient final {
 public:
  // All references are caller-owned and must outlive the client. `rlres1_env`
  // supplies entropy and receive context ids (its slot directory is unused:
  // the client only initiates).
  AuthorityClient(const routeloom::AeadGcm& aead, AuthorityPort& port, AuthorityObserver& observer,
                  rlres1::Environment& rlres1_env, GroupKeyState* group = nullptr) noexcept;

  AuthorityClient(const AuthorityClient&) = delete;
  AuthorityClient& operator=(const AuthorityClient&) = delete;
  ~AuthorityClient() { wipe(); }

  // Single mutation entry. Re-entry from any callback (port, observer,
  // entropy, AEAD) returns Busy with queue/state/counters/statistics
  // untouched; snapshot/quiescent/next_deadline stay readable throughout.
  Status advance(const AuthorityInput& in, MonotonicMs now) noexcept;
  AuthoritySnapshot snapshot() const noexcept;
  // True only when Dormant with nothing pending and no outer call in flight.
  bool quiescent() const noexcept;
  // Next Tick the owner must honour, or UINT64_MAX when nothing is pending.
  MonotonicMs next_deadline() const noexcept;

 private:
  enum class TxKind : std::uint8_t { None = 0, R1, R3, Envelope };

  Status on_start(const AuthorityStart& start, MonotonicMs now) noexcept;
  Status on_rx(const AuthorityRxCarrier& rx, MonotonicMs now) noexcept;
  Status on_tx_result(const AuthorityTxResult& tx) noexcept;
  Status on_tick(MonotonicMs now) noexcept;
  Status on_pull(const AuthorityPullRequest& pull, MonotonicMs now) noexcept;
  Status on_suspend() noexcept;

  Status begin_handshake(MonotonicMs now) noexcept;
  void enter_backoff(MonotonicMs now, const char* reason) noexcept;
  void retire_channel(const char* reason, MonotonicMs now) noexcept;
  void wipe_channel_keys() noexcept;  // traffic keys/contexts only; DAMS kept
  void to_dormant() noexcept;         // full stop, DAMS wiped
  bool flush_tx() noexcept;  // try_send the staged carrier; false = still staged
  Status stage_pending_ack(MonotonicMs now) noexcept;
  UpdateResult apply_update(const GroupKeyUpdate& msg, MonotonicMs now) noexcept;
  UpdateResult apply_activate(const GroupKeyActivate& msg, MonotonicMs now) noexcept;
  StoredState stored_state(std::uint32_t g) const noexcept;
  bool site_bound() const noexcept;
  Status do_seal(keys::AuthorityEnvelopeType type, ByteView plaintext,
                 MonotonicMs now) noexcept;
  Status send_join_confirm(MonotonicMs now) noexcept;
  Status send_pull(PullReason reason, MonotonicMs now) noexcept;
  void on_envelope_ready(const AuthorityRxCarrier& rx, MonotonicMs now) noexcept;
  void wipe() noexcept;

  const routeloom::AeadGcm& aead_;
  AuthorityPort& port_;
  AuthorityObserver& observer_;
  rlres1::Environment& env_;
  GroupKeyState* group_;  // Owner-owned; never installed by a transport callback
  rlres1::Engine engine_;
  bool engine_ready_{false};
  bool in_call_{false};
  bool started_{false};
  AuthoritySnapshot::State state_{AuthoritySnapshot::State::Dormant};
  AuthorityStart local_{};
  keys::TrafficKey tx_key_{};
  keys::TrafficKey rx_key_{};
  std::uint32_t rx_ctx_{0};
  std::uint32_t tx_ctx_{0};
  AuthorityReplayWindow rx_window_{};
  std::uint64_t tx_counter_{0};
  std::uint64_t next_request_id_{1};
  // One 2048 B workspace holds a staged TX until the port copies it, or
  // one authenticated RX while no TX is staged. A port-stalled TX keeps
  // its bytes and the peer retries the refused envelope.
  std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> tx_buffer_{};
  // The fixed P5 control replies can arrive while a prior send is stalled.
  // A full-size envelope uses the common workspace once that send leaves.
  std::array<std::uint8_t, keys::kAuthorityEnvelopeHeaderSize +
                               kGroupKeyUpdateSize + kAeadTagSize> rx_control_{};
  std::size_t tx_size_{0};
  TxKind tx_kind_{TxKind::None};
  std::uint64_t tx_token_{0};  // last accepted send, for TxResult matching
  bool tx_token_live_{false};
  MonotonicMs backoff_until_{0};
  MonotonicMs hs_deadline_{0};
  std::uint32_t backoff_s_{0};
  MonotonicMs last_pull_ms_{0};
  bool pull_sent_{false};
  bool pull_pending_{false};
  PullReason pending_reason_{PullReason::BootReconnectSync};
  bool ack_pending_{false};
  keys::AuthorityEnvelopeType ack_type_{keys::AuthorityEnvelopeType::GroupKeyUpdate};
  std::uint32_t ack_g_{0};
  GkId ack_gk_id_{};
  UpdateResult ack_result_{UpdateResult::Unsupported};
  StoredState ack_state_{StoredState::None};
  MonotonicMs last_activity_{0};
  MonotonicMs last_wake_ms_{0};
  bool wake_seen_{false};
  MonotonicMs ready_since_{0};
  bool join_confirmed_{false};
  bool join_confirm_sent_{false};
  std::uint64_t tx_sent_{0};
  std::uint64_t tx_failed_{0};
  std::uint64_t rx_accepted_{0};
  std::uint64_t rx_rejected_{0};
};

}  // namespace routeloom::sdkv1
