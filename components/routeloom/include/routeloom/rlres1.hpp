#pragma once

// RLRES1 — the symmetric resume handshake of docs/design/sdk-v1/06-fast-rejoin.md
// §2 (plan P1-5): message codecs, the transcript/key schedule (key_schedule.hpp)
// and a bounded, allocation-free state machine for BOTH roles.
//
//   Initiator                                   Responder
//   IDLE --begin()--> R1 ----------------------> on_r1(): rid lookup, validity,
//                                                 mac_I, anti-replay, bounds
//   WAIT_R2 <----------------------------------- R2 (status 0 + mac_R)
//   on_r2(): mac_R, epochs -> keys, INSTALL       WAIT_R3 (context NOT active)
//            R3 -------------------------------> on_r3(): mac_I3 -> INSTALL
//   (status != 0 hint / bad R2 / timeout -> FALLBACK to full EDHOC; the
//    resume slot is never invalidated by an unauthenticated message)
//
// Every session accepts exactly one message of the expected kind; anything
// else is rejected with a specific `Reject` reason and counted. The engine
// is standalone: no MeshNode, no NVS, no radio. The P4-2 HandshakeEngine drives
// it and supplies the carrier binding, the injected clock (`now` on every
// call), entropy, context ids and the resume-slot directory through
// `Environment`. Nothing here is static; all storage lives in the instance
// (sizeof checked below against the ESP32-C3 gateway floor).
//
// Scope, honestly: RouteLoom's own protocol, not independently reviewed
// (P8-2). No forward secrecy within an RMS lifetime (06 §2).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::rlres1 {

using keys::DecodeError;
using keys::Purpose;
using keys::ResumeId;
using keys::ResumeNonce;
using keys::Secret;
using keys::TrafficKey;

constexpr std::size_t kR1BaseSize = 60;
constexpr std::size_t kTicketMax = 48;
constexpr std::size_t kR1MaxSize = kR1BaseSize + 1 + kTicketMax;  // 109
constexpr std::size_t kR2Size = 52;
constexpr std::size_t kR2HintSize = 12;
constexpr std::size_t kR3Size = 16;
constexpr std::size_t kMaxMessageSize = kR1MaxSize;
using Mac = std::array<std::uint8_t, keys::kResumeMacSize>;

enum class R2Status : std::uint8_t {
  Ok = 0,
  UnknownId = 1,
  Expired = 2,
  RevokedHint = 3,
};

struct Epochs {
  std::uint32_t site_epoch{0};
  std::uint32_t rs_epoch{0};
  std::uint32_t gk_epoch{0};
};

// --- Codecs (strict; shared reasons with the Rust mirror and golden vectors) --

struct R1 {
  Purpose purpose{Purpose::Link};
  ResumeId rid{};
  ResumeNonce nonce_i{};
  std::uint32_t cid_i{0};
  Epochs epochs{};
  std::uint8_t ticket_size{0};  // purpose PendingJoin only, 1..48
  std::array<std::uint8_t, kTicketMax> ticket{};
  Mac mac{};
};

struct R2 {
  R2Status status{R2Status::Ok};
  ResumeNonce nonce_r{};    // status Ok only
  std::uint32_t cid_r{0};   // status Ok only
  Epochs epochs{};          // status Ok only
  Mac mac{};                // status Ok only
  ResumeId hint_rid{};      // status != Ok: echo of the R1 rid (12-byte hint)
};

bool purpose_is_resumable(Purpose purpose) noexcept;
std::size_t r1_size(const R1& message) noexcept;
DecodeError decode_r1(ByteView input, R1& out) noexcept;
DecodeError decode_r2(ByteView input, R2& out) noexcept;
DecodeError decode_r3(ByteView input, Mac& out) noexcept;
// Encoders write the whole message including the MAC fields as given.
Status encode_r1(const R1& message, MutableByteView out, std::size_t& written) noexcept;
Status encode_r2(const R2& message, MutableByteView out, std::size_t& written) noexcept;

// --- State machine -----------------------------------------------------------

enum class Role : std::uint8_t { Initiator = 1, Responder = 2 };

// Why a message or request was refused. Values are stable diagnostics.
enum class Reject : std::uint8_t {
  None = 0,
  Malformed,             // codec refusal; Output::decode has the detail
  NoSession,             // no handshake expects this message (out of order, after
                         // completion, reflected R2/R3)
  Reflection,            // our own R1 (our nonce_I) came back to us
  SimultaneousOpen,      // both sides initiated; the lower NodeId's R1 wins
  DuplicateSession,      // a handshake for this (peer, purpose) is in flight
  ReplayedNonce,         // R1 nonce_I already seen (bounded replay cache)
  Timeout,               // message arrived after the session deadline
  UnknownResumptionId,   // no slot for this rid (R2 hint unknown_id)
  SlotExpired,           // created_gk_epoch + 2 <= current gk_epoch (hint expired)
  PeerRevoked,           // RRS1: peer generation revoked (hint revoked)
  WrongNetwork,          // slot bound to another network (other site / cutover)
  PeerMismatch,          // carrier-claimed sender or identity differs from the slot
  SiteEpochMismatch,     // peer's site_epoch differs from ours
  StaleGkEpoch,          // peer gk_epoch >= 2 behind, or older than the RMS
  FutureGkEpoch,         // peer gk_epoch >= 2 ahead (we must GroupKeyPull first)
  BadMac,                // mac_I / mac_R / mac_I3 did not verify
  UnauthenticatedHint,   // R2 status != 0: unauthenticated, fall back to EDHOC
  HintMismatch,          // R2 hint echoes a rid that is not ours
  PurposeNotServed,      // this node does not answer RLRES1 for this purpose
  TableFull,             // bounded session table exhausted (never evicts)
  RateLimited,           // responder admission token bucket empty
  EntropyUnavailable,
  ContextIdUnavailable,
  // The verified slot's resume budget is spent (or unprovable): R answers
  // Expired so the initiator runs a full EDHOC (P4 §6.2).
  ResumeBudgetExhausted,
  InvalidRequest,        // caller error (bad begin() arguments, local state unset)
};
constexpr std::size_t kRejectCount = static_cast<std::size_t>(Reject::InvalidRequest) + 1;
const char* reject_name(Reject reject) noexcept;

enum class Action : std::uint8_t {
  None = 0,         // nothing to send, nothing installed
  Send,             // send Output::message (R1, R2 or R2 hint)
  SendAndInstall,   // initiator: install Output::established, then send R3
  Install,          // responder: install Output::established
  Fallback,         // initiator: resume failed -> full EDHOC; slot stays valid
};

// A resume-cache entry as the directory (RLP1 / RLS1 DAMS / pending RAM) hands it
// over. `peer` is the other party: its NodeId for link/end, the site_id of
// the Site Authority (initiator side) or the device NodeId (responder side)
// for authority/pending-join.
struct Slot {
  Purpose purpose{Purpose::Link};
  NodeId peer{kInvalidNodeId};
  NetworkId network{0};
  std::uint32_t created_gk_epoch{0};  // link/end lifetime rule (05 §3.2)
  std::uint32_t peer_generation{0};   // RRS1 check
  Secret secret{};                    // RMS / DAMS / pending secret
};

// How the messages travel; decides the MAC binding and the timeout.
struct Carrier {
  enum class Kind : std::uint8_t { Routed = 0, Link = 1 };
  Kind kind{Kind::Routed};
  MacAddress mac_i{};            // Link: initiator MAC (as observed)
  MacAddress mac_r{};            // Link: responder MAC
  ScopeDigest carrier_digest{};  // Link: RLD1 transaction digest (P4-2)
  std::uint8_t hops{0};          // Routed: hops to the peer (timeout)
};

class Environment {
 public:
  // Fill `out` with fresh random bytes; false = entropy not READY.
  virtual bool random(MutableByteView out) noexcept = 0;
  // Responder: the slot whose rid (keys::resume_id) matches, if any.
  virtual bool find_slot(Purpose purpose, const ResumeId& rid, Slot& out) noexcept = 0;
  // RRS1: true when (peer, generation) is revoked / below min_generation.
  virtual bool revoked(NodeId peer, std::uint32_t generation) noexcept = 0;
  // A non-zero receive context id unique among this node's live contexts.
  virtual bool allocate_context_id(Purpose purpose, NodeId peer, std::uint32_t& cid) noexcept = 0;
  // Consume one of the 64 RMS uses of the verified (purpose, rid) slot
  // (P4 §6.2). Called synchronously inside on_r1 after the MAC, replay,
  // lifetime and revocation gates pass and before R2 is made; false (uses
  // exhausted or unprovable) makes R answer Expired so the initiator runs
  // a full EDHOC. Failed attempts are never refunded.
  virtual bool reserve_resume_use(Purpose purpose, const ResumeId& rid) noexcept = 0;

 protected:
  ~Environment() = default;
};

struct Local {
  NodeId self{kInvalidNodeId};
  NetworkId network{0};        // full 64 bits: site_epoch << 32 | network_low32
  std::uint64_t site_id{0};    // node_R for authority / pending-join
  Epochs epochs{};             // epochs.site_epoch must equal network >> 32
};

constexpr std::size_t kMaxInitiatorSessions = 4;
constexpr std::size_t kMaxResponderSessions = 4;
constexpr std::size_t kReplayCacheSize = 16;

struct Limits {
  std::uint8_t max_initiator{kMaxInitiatorSessions};
  std::uint8_t max_responder{kMaxResponderSessions};
  // Responder admission: new sessions per second and burst (06 §3/§5: 1/s for
  // neighbours, 10/s on the gateway's symmetric-key lane, 4 concurrent).
  std::uint16_t responder_rate_per_s{1};
  std::uint8_t responder_burst{kMaxResponderSessions};
  std::uint32_t base_timeout_ms{1000};    // 06 §2.2
  std::uint32_t per_hop_timeout_ms{300};  // 06 §2.2 (+hop x 0.3 s)
  std::uint8_t max_hops{16};
  // Purposes this node answers as responder: bit (1 << purpose). Devices
  // answer link/end only; authority/pending-join responders are the host.
  std::uint8_t responder_purposes{(1u << 1) | (1u << 2)};
};

struct Established {
  Purpose purpose{Purpose::Link};
  Role role{Role::Initiator};
  NodeId peer{kInvalidNodeId};
  NetworkId network{0};
  std::uint32_t rx_context_id{0};  // ours: peers put it in link_epoch/end_epoch/ctx_id
  std::uint32_t tx_context_id{0};  // the peer's
  TrafficKey tx{};
  TrafficKey rx{};
  Epochs peer_epochs{};
  bool peer_rs_behind{false};   // peer should fetch our newer RRS1 (04 §4)
  bool local_rs_behind{false};  // we should fetch the peer's newer RRS1
  std::uint8_t ticket_size{0};  // responder, pending-join: the authority's ticket
  std::array<std::uint8_t, kTicketMax> ticket{};
};

struct Output {
  Action action{Action::None};
  Reject reject{Reject::None};
  DecodeError decode{DecodeError::None};
  bool superseded_initiator{false};  // simultaneous open: our own attempt yielded
  std::size_t message_size{0};
  std::array<std::uint8_t, kMaxMessageSize> message{};
  Established established{};

  void clear() noexcept;  // zeroizes keys
};

struct BeginRequest {
  Slot slot{};
  Carrier carrier{};
  ByteView ticket{};  // PendingJoin only, 1..48 bytes
};

struct ExpiredSession {
  Role role{Role::Initiator};
  Purpose purpose{Purpose::Link};
  NodeId peer{kInvalidNodeId};
};

class Engine {
 public:
  Engine() noexcept = default;
  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;
  ~Engine() { clear_all(); }

  // Validates and installs the local view; clears every in-flight session
  // (network/site/epoch changes make them meaningless).
  Status configure(const Local& local, const Limits& limits) noexcept;
  // GK/RRS1 epoch updates without dropping sessions (site_epoch must not change).
  Status update_epochs(const Epochs& epochs) noexcept;

  void begin(const BeginRequest& request, MonotonicMs now, Environment& env,
             Output& out) noexcept;
  // `claimed_peer`: carrier-claimed sender (RLD1 header / Wire origin); 0 = unknown.
  void on_r1(ByteView message, const Carrier& carrier, NodeId claimed_peer, MonotonicMs now,
             Environment& env, Output& out) noexcept;
  // `peer`: responder identity (NodeId for link/end, site_id for authority/pending).
  void on_r2(NodeId peer, Purpose purpose, ByteView message, MonotonicMs now,
             Output& out) noexcept;
  void on_r3(NodeId peer, Purpose purpose, ByteView message, MonotonicMs now,
             Output& out) noexcept;

  // Pops one session whose deadline has passed (initiators must fall back).
  bool next_expired(MonotonicMs now, ExpiredSession& out) noexcept;
  void abort(Role role, NodeId peer, Purpose purpose) noexcept;
  void abort_peer(NodeId peer) noexcept;  // RRS1 revocation of `peer`
  void clear_all() noexcept;

  std::size_t initiator_in_flight() const noexcept;
  std::size_t responder_in_flight() const noexcept;
  std::uint32_t reject_count(Reject reject) const noexcept {
    return reject_counts_[static_cast<std::size_t>(reject)];
  }

 private:
  enum class SlotState : std::uint8_t { Free = 0, WaitR2 = 1, WaitR3 = 2 };

  struct InitiatorSession {
    SlotState state{SlotState::Free};
    Purpose purpose{Purpose::Link};
    std::uint8_t r1_size{0};
    NodeId peer{kInvalidNodeId};
    NodeId node_r{kInvalidNodeId};
    MonotonicMs deadline{0};
    std::uint32_t created_gk_epoch{0};
    Secret secret{};
    Secret auth_key{};
    ScopeDigest binding{};
    std::array<std::uint8_t, kR1MaxSize> r1{};
  };

  struct ResponderSession {
    SlotState state{SlotState::Free};
    MonotonicMs deadline{0};
    Mac expected_r3{};
    Established established{};
  };

  struct ReplayEntry {
    bool used{false};
    ResumeNonce nonce{};
  };

  void reject(Output& out, Reject reason, DecodeError decode = DecodeError::None) noexcept;
  void send_hint(Output& out, R2Status status, const ResumeId& rid, Reject reason) noexcept;
  MonotonicMs deadline_for(MonotonicMs now, std::uint8_t hops) const noexcept;
  NodeId responder_identity(Purpose purpose) const noexcept;
  Reject check_gk(Purpose purpose, std::uint32_t peer_gk, std::uint32_t created) const noexcept;
  bool take_token(MonotonicMs now) noexcept;
  bool replay_seen(const ResumeNonce& nonce) const noexcept;
  void replay_remember(const ResumeNonce& nonce) noexcept;
  InitiatorSession* find_initiator(NodeId peer, Purpose purpose) noexcept;
  ResponderSession* find_responder(NodeId peer, Purpose purpose) noexcept;
  static void wipe(InitiatorSession& session) noexcept;
  static void wipe(ResponderSession& session) noexcept;

  bool configured_{false};
  Local local_{};
  Limits limits_{};
  std::array<InitiatorSession, kMaxInitiatorSessions> initiators_{};
  std::array<ResponderSession, kMaxResponderSessions> responders_{};
  std::array<ReplayEntry, kReplayCacheSize> replay_{};
  std::size_t replay_next_{0};
  std::uint32_t tokens_milli_{0};
  MonotonicMs tokens_at_{0};
  bool tokens_primed_{false};
  std::array<std::uint32_t, kRejectCount> reject_counts_{};
};

}  // namespace routeloom::rlres1
