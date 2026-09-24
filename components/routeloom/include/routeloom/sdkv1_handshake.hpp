#pragma once

// Member handshake engine (G-SEC P4 §5-§7, link half): the single owner of
// member EDHOC and RLRES1 exchanges. Resume-first, full-EDHOC fallback,
// then install into the session bank through the narrow sink below and (for
// link) mint the discovery elevation proof. Keys and RMS move internally
// from the crypto engines to the installer/cache; results carry bytes,
// never secrets.
//
// One EDHOC exchange at a time (initiator or responder), up to 8 carrier
// records, RLRES1 I4/R4 inside. Public entries refuse Busy while a call is
// already inside (no re-entry, P4-C01) and while a result is unconsumed —
// the Owner drains take_result() before every call. No heap, no exceptions.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery.hpp"  // AuthenticatedPeerProof (link elevation)
#include "routeloom/edhoc.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_session_wire.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

enum class HandshakeRole : std::uint8_t { Initiator = 1, Responder = 2 };
enum class HandshakeReason : std::uint8_t { Initial = 0, Rekey = 1, ResumeRetry = 2 };
enum class HandshakeCancelReason : std::uint8_t {
  Timeout = 0,
  Revoked = 1,
  Shutdown = 2,
  Superseded = 3
};
enum class HandshakeEvent : std::uint8_t { Send = 1, Established = 2, Failed = 3 };

// --- MemberCookie ----------------------------------------------------------------------
// First-step DoS gate for the member profile (P4 §5.3/§7.1): a 16-byte MAC
// over (requester MAC, RLD1 txn nonce, network, time bucket) under a
// boot-random key. The discovery OFFER issues it, the handshake responder
// verifies it BEFORE allocating session state; the initiator only attaches
// it. Verification accepts the current and previous 2 s bucket.
class MemberCookie {
 public:
  static constexpr std::size_t kCookieBytes = 16;
  static constexpr MonotonicMs kBucketMs = 2000;

  MemberCookie() noexcept = default;
  MemberCookie(const MemberCookie&) = delete;
  MemberCookie& operator=(const MemberCookie&) = delete;

  using RandomFn = bool (*)(void* ctx, std::uint8_t* out, std::size_t size) noexcept;
  Status configure(RandomFn random, void* random_ctx) noexcept;
  bool configured() const noexcept { return configured_; }

  Status seal(const MacAddress& requester, const std::array<std::uint8_t, 16>& txn_nonce,
              NetworkId network, MonotonicMs now,
              std::array<std::uint8_t, kCookieBytes>& out) const noexcept;
  Status verify(const MacAddress& requester, const std::array<std::uint8_t, 16>& txn_nonce,
                NetworkId network, ByteView cookie, MonotonicMs now) const noexcept;

 private:
  void mac(const MacAddress& requester, const std::array<std::uint8_t, 16>& txn_nonce,
           NetworkId network, std::uint32_t bucket,
           std::array<std::uint8_t, kCookieBytes>& out) const noexcept;

  std::array<std::uint8_t, 32> key_{};
  bool configured_{false};
};

// --- Evidence ports -----------------------------------------------------------------------

// Local member view, read fresh at every entry and every commit (P4 §5.5).
struct HandshakeLocal {
  NodeId self{kInvalidNodeId};
  NetworkId network{0};  // full64
  std::uint64_t site_id{0};
  std::uint32_t site_epoch{0};
  std::uint32_t rs_epoch{0};
  std::uint32_t gk_epoch{0};
  std::uint32_t generation{0};
  std::uint32_t role{0};
  std::uint32_t caps{0};  // own RLD1 capability word
  std::uint32_t boot{0};  // u32 boot session
  std::array<std::uint8_t, 8> local_cert_id{};  // first8(SHA-256(local MemberCert))
};

class HandshakeMembershipView {
 public:
  virtual ~HandshakeMembershipView() = default;
  // False when local evidence is missing or unprovable (fail closed).
  virtual bool local(HandshakeLocal& out) const noexcept = 0;
  // Latest RRS1 view: true when (peer, generation) is revoked.
  virtual bool revoked(NodeId peer, std::uint32_t generation) const noexcept = 0;
};

// Member credential verification. The port verifies the chain against
// its trust stores (firmware backs it in PR4) and reports the claims it
// verified; the engine ALSO decodes the certificate itself (join_credential_check:
// type + cnf-kid match) and cross-checks every reported field. A hook
// saying "ok" is not authentication — only the cross-checked copy below
// feeds installs, Exporter contexts and proofs (P4 §5.3 m2 row).
struct PeerCertClaims {
  NodeId node{kInvalidNodeId};
  std::uint32_t generation{0};
  std::uint32_t role{0};
  std::uint32_t site_epoch{0};
};

// The engine's trusted copy: decoded from the staged certificate,
// chain-verified by the port, cross-checked field by field. The kid rule
// (P4 §5.1: SHA-256 of the cnf COSE_Key, all 32 bytes) is applied by the
// engine, never trusted from a port.
struct VerifiedPeerClaims {
  NodeId node{kInvalidNodeId};
  std::uint32_t generation{0};
  std::uint32_t role{0};
  std::uint32_t site_epoch{0};
  std::array<std::uint8_t, 8> cert_id{};  // first8(SHA-256(MemberCert))
  std::array<std::uint8_t, 64> pubkey{};  // P-256 X||Y from the cert cnf
};

struct LocalCredential {
  std::array<std::uint8_t, 256> cred{};
  std::size_t cred_size{0};
  std::array<std::uint8_t, 32> privkey{};  // scalar only; handles refuse
};

class SessionCredentialVerifier {
 public:
  virtual ~SessionCredentialVerifier() = default;
  virtual bool local_credential(LocalCredential& out) noexcept = 0;
  // Verify `cert` (a staged MemberCert by value) for `expected_node`:
  // chain, issuer/site/network/role/assignment checks. Reports the
  // claims it verified; the engine cross-checks them against its own
  // decode. Must fail closed on any issue.
  virtual bool verify_peer(ByteView cert, NodeId expected_node,
                           PeerCertClaims& out) noexcept = 0;
};

// The narrow install surface the engine needs (P4 §2.2): verified installs
// plus RX-id allocation. The bank never sees handshake internals.
class HandshakeSessionSink {
 public:
  virtual ~HandshakeSessionSink() = default;
  virtual Status install_verified(const ContextKeys& keys,
                                  const InstallAttestation& att) noexcept = 0;
  virtual Status allocate_context_id(std::uint32_t& out) noexcept = 0;
  virtual bool context_id_live(std::uint32_t id) const noexcept = 0;
};

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
class BankSessionSink final : public HandshakeSessionSink {
 public:
  explicit BankSessionSink(SessionBank<kLinkCapacity, kEndCapacity>& bank) noexcept
      : bank_(bank) {}
  Status install_verified(const ContextKeys& keys, const InstallAttestation& att) noexcept override {
    return bank_.install_verified(keys, att);
  }
  Status allocate_context_id(std::uint32_t& out) noexcept override {
    return bank_.allocate_context_id(out);
  }
  bool context_id_live(const std::uint32_t id) const noexcept override {
    return bank_.context_id_live(id);
  }

 private:
  SessionBank<kLinkCapacity, kEndCapacity>& bank_;
};

// --- Requests, inputs, results ---------------------------------------------------------------

struct HandshakeRequest {
  SecurityScope scope{SecurityScope::Link};
  NodeId peer{kInvalidNodeId};  // expected peer
  HandshakeReason reason{HandshakeReason::Initial};
  // Link: we are I; the frozen DISCOVER/OFFER exchange (P4 §5.2).
  MacAddress mac_i{};
  MacAddress mac_r{};
  keys::LinkCarrier carrier{};
};

struct HandshakeRx {
  SecurityScope scope{SecurityScope::Link};
  std::uint8_t phase{0};  // 4 EDHOC, 5 RLRES1 (join-transport object codec)
  std::uint8_t step{0};   // 1..4 / 1..3
  NodeId claimed_peer{kInvalidNodeId};  // carrier-claimed sender (0 unknown)
  // Link: observed carrier. Responder-first-message carries the frozen
  // exchange (from the Owner's discovery candidate); later steps must
  // repeat the same carrier (re-binding mid-exchange is refused).
  MacAddress src_mac{};
  MacAddress dst_mac{};
  keys::LinkCarrier carrier{};
  ByteView cookie{};  // attached cookie bytes (empty = absent)
  // End scope only: the routed envelope's exchange id (nonzero; the
  // owner/demux supplies it — P4 §7.3 — since link frames have no such
  // field). Must be 0 for link frames.
  std::uint32_t exchange_id{0};
};

struct HandshakeResult {
  HandshakeEvent event{HandshakeEvent::Failed};
  std::uint32_t token{0};  // exchange serial (correlates Send/Established)
  SecurityScope scope{SecurityScope::Link};
  NodeId peer{kInvalidNodeId};
  HandshakeRole role{HandshakeRole::Initiator};
  // Send: RLD1 object coordinates + bytes (<= 960) + cookie flag.
  std::uint8_t phase{0};
  std::uint8_t step{0};
  std::array<std::uint8_t, 960> message{};
  std::size_t message_size{0};
  bool cookie_attach{false};  // attach the carrier cookie (step 1)
  // Established: elevation proof (link) + installed ids (no keys).
  bool has_proof{false};
  AuthenticatedPeerProof proof{};
  std::uint32_t tx_context_id{0};
  std::uint32_t rx_context_id{0};
  // Failed: machine reason.
  StatusCode failure{StatusCode::Ok};
};

class HandshakeEngine final : public edhoc::EadHandler, public rlres1::Environment {
 public:
  static constexpr std::size_t kCarrierRecords = 8;
  static constexpr std::uint32_t kLinkTimeoutMs = 8000;
  static constexpr std::uint32_t kEdhocRetransmitMs = 400;
  static constexpr std::uint32_t kResumeRetransmitMs = 500;
  static constexpr std::uint8_t kMaxRetransmits = 3;
  static constexpr std::uint32_t kEccMinGapMs = 2000;  // one ECDH per 2 s
  static constexpr std::size_t kMaxMessageBytes = 1024;
  static constexpr std::uint32_t kExporterLabelKey = 32768;
  static constexpr std::uint32_t kExporterLabelIv = 32769;
  static constexpr std::uint32_t kExporterLabelRms = 32770;

  using RandomFn = bool (*)(void* ctx, std::uint8_t* out, std::size_t size) noexcept;

  HandshakeEngine(ResumeCache2& cache, HandshakeSessionSink& sink, MemberCookie& cookie,
                  HandshakeMembershipView& membership, SessionCredentialVerifier& verifier,
                  RandomFn random, void* random_ctx) noexcept;

  HandshakeEngine(const HandshakeEngine&) = delete;
  HandshakeEngine& operator=(const HandshakeEngine&) = delete;

  Status configure(MonotonicMs now) noexcept;

  // Start a resume-first exchange toward `req.peer` (single flight per
  // scope/peer; a second request is Busy until cancel/timeout).
  Status request(const HandshakeRequest& req, MonotonicMs now) noexcept;
  // One demuxed handshake message (the Owner owns framing/cookies/RSSI).
  Status on_message(const HandshakeRx& rx, ByteView message, MonotonicMs now) noexcept;
  // Timeouts, retransmits, RLRES1 expiry. Refuses Busy while a result is
  // pending (drain take_result first).
  Status poll(MonotonicMs now) noexcept;
  // Pops the pending result (NotFound when empty).
  Status take_result(HandshakeResult& out) noexcept;
  Status cancel(NodeId peer, HandshakeCancelReason reason) noexcept;
  Status cancel_all() noexcept;
  // Side-effect-free and readable any time (false while a call is inside).
  bool quiescent() const noexcept;

 private:
  // -- edhoc::EadHandler (downcalls from libedhoc, never re-entrant) --
  Status compose(int message, edhoc::EadItem* items, std::size_t capacity,
                 std::size_t& count) noexcept override;
  Status process(int message, const edhoc::EadItem* items,
                 std::size_t count) noexcept override;
  // -- rlres1::Environment --
  bool random(MutableByteView out) noexcept override;
  bool find_slot(rlres1::Purpose purpose, const rlres1::ResumeId& rid,
                 rlres1::Slot& out) noexcept override;
  bool revoked(NodeId peer, std::uint32_t generation) noexcept override;
  bool allocate_context_id(rlres1::Purpose purpose, NodeId peer,
                            std::uint32_t& cid) noexcept override;
  bool reserve_resume_use(rlres1::Purpose purpose, const rlres1::ResumeId& rid) noexcept override;

  // -- edhoc::CredentialProvider adapter (member session) --
  class MemberCredentials final : public edhoc::CredentialProvider {
   public:
    explicit MemberCredentials(HandshakeEngine& engine) noexcept : engine_(engine) {}
    Status local(edhoc::Role role, edhoc::LocalCredential& out) noexcept override;
    Status peer(edhoc::Role role, ByteView kid, edhoc::PeerCredential& out) noexcept override;

   private:
    HandshakeEngine& engine_;
  };
  friend class MemberCredentials;

  enum class RecordState : std::uint8_t {
    Free = 0,
    ResumeWaitR2,   // initiator: R1 sent
    ResumeWaitR3,   // responder: R2 sent
    ResumeR3Confirm,  // initiator: installed, R3 re-sent until quiet
    EdhocQueued,    // initiator: waiting for the single EDHOC flight / ECC
    EdhocM1Parked,  // responder: m1 stashed, waiting for flight / ECC
    EdhocWaitM2,    // initiator: m1 sent
    EdhocWaitM3,    // responder: m2 sent
    EdhocWaitM4,    // initiator: m3 sent
    EdhocM4Sent,    // responder: m4 sent, installed
  };

  struct CarrierRecord {
    bool used{false};
    SecurityScope scope{SecurityScope::Link};
    NodeId peer{kInvalidNodeId};  // expected (I) / claimed (R, unverified)
    HandshakeRole role{HandshakeRole::Initiator};
    HandshakeReason reason{HandshakeReason::Initial};
    std::uint32_t token{0};
    RecordState state{RecordState::Free};
    MacAddress mac_i{};
    MacAddress mac_r{};
    keys::LinkCarrier carrier{};
    std::uint32_t exchange_id{0};  // end purpose session nonce
    MonotonicMs deadline{0};
    MonotonicMs retransmit_at{0};
    std::uint8_t retransmits{0};
    // Retransmit/duplicate caches (small messages only; m2/m3/m4 live in
    // the single-flight big buffer).
    std::array<std::uint8_t, 256> last_tx{};
    std::size_t last_tx_size{0};
    std::uint8_t last_phase{0};
    std::uint8_t last_step{0};
    std::array<std::uint8_t, 16> r1_nonce{};  // responder duplicate Kompas
    bool r1_nonce_set{false};
  };

  struct StagedEstablished {
    bool pending{false};
    std::uint32_t token{0};
    SecurityScope scope{SecurityScope::Link};
    NodeId peer{kInvalidNodeId};
    HandshakeRole role{HandshakeRole::Initiator};
    bool has_proof{false};
    AuthenticatedPeerProof proof{};
    std::uint32_t tx_context_id{0};
    std::uint32_t rx_context_id{0};
  };

  // Single EDHOC flight state (the engine runs at most one).
  struct EdhocFlight {
    bool active{false};
    std::uint32_t owner_token{0};
    HandshakeRole role{HandshakeRole::Initiator};
    std::uint32_t cid_own{0};   // our C_x (nonzero u32)
    std::uint32_t cid_peer{0};  // read via the wrapper accessor (0 until seen)
    std::uint8_t phase{0};      // EAD compose selector (1..4 = m1..m4)
    // EDHOC kids (P4 §5.1: cnf COSE_Key hashes): ours derived at begin,
    // theirs copied from the verified presented kid. Both feed the
    // Exporter contexts.
    std::array<std::uint8_t, 32> kid_local{};
    std::array<std::uint8_t, 32> kid_peer{};
    // Peer's disclosed GK epoch (verified State): the new RMS/context
    // birthday is min(ours, theirs) (P4 §5.3).
    std::uint32_t peer_gk_epoch{0};
    // Raw EAD values (exact bytes composed/received) for the capability
    // digest; staged credentials and claims (untrusted until libedhoc
    // reports the message authenticated).
    std::array<std::uint8_t, kSessionIntentBytes> intent_bytes{};
    bool intent_set{false};
    std::array<std::uint8_t, kSessionStateBytes> state_r_bytes{};
    bool state_r_set{false};
    std::array<std::uint8_t, kSessionStateBytes> state_i_bytes{};
    bool state_i_set{false};
    std::array<std::uint8_t, kContextConfirmBytes> confirm_i_bytes{};
    bool confirm_i_set{false};
    std::array<std::uint8_t, kContextConfirmBytes> confirm_r_bytes{};
    bool confirm_r_set{false};
    std::array<std::uint8_t, 256> cred_i{};
    std::size_t cred_i_size{0};
    std::array<std::uint8_t, 256> cred_r{};
    std::size_t cred_r_size{0};
    VerifiedPeerClaims peer_claims{};
    bool peer_verified{false};
    std::array<std::uint8_t, 32> m1_hash{};
    bool m1_seen{false};
    std::array<std::uint8_t, 32> m3_hash{};
    bool m3_seen{false};
    LocalCredential local_cred{};
    bool local_cred_set{false};
  };

  class EnterGuard {
   public:
    explicit EnterGuard(bool& entered) noexcept : entered_(entered) { entered_ = true; }
    ~EnterGuard() { entered_ = false; }

   private:
    bool& entered_;
  };

  Status refresh_local() noexcept;
  // Drops every record and session without emitting (re-entry safe: used
  // under the entry guard only).
  void cancel_all_internal() noexcept;
  void end_edhoc_flight() noexcept;
  CarrierRecord* find_record(SecurityScope scope, NodeId peer, HandshakeRole role) noexcept;
  CarrierRecord* find_record_by_token(std::uint32_t token) noexcept;
  CarrierRecord* alloc_record() noexcept;
  void drop_record(CarrierRecord& record) noexcept;
  Status emit_send(CarrierRecord& record, std::uint8_t phase, std::uint8_t step, ByteView bytes,
                   bool cookie_attach) noexcept;
  Status emit_failed(CarrierRecord& record, StatusCode failure) noexcept;
  void stage_established(const StagedEstablished& established) noexcept;
  Status begin_resume(CarrierRecord& record, const ResumeSlot2& slot, MonotonicMs now) noexcept;
  Status begin_edhoc(CarrierRecord& record, MonotonicMs now) noexcept;
  // Responder m1 intake (fresh or parked): starts the flight and
  // answers m2, or parks the bytes in the shared stash when the flight
  // is busy, the ECC budget is unready, or entropy is transiently out.
  // A parked exchange is started by poll(); a credential failure drops
  // it.
  Status responder_begin_m1(CarrierRecord& record, ByteView message,
                            MonotonicMs now) noexcept;
  // Stash an intake m1 for poll(): takes buffer ownership for the
  // record. Drops the record only when the bytes cannot fit (which
  // on_message's 960 cap already excludes).
  void park_m1(CarrierRecord& record, ByteView message) noexcept;
  Status on_edhoc_message(CarrierRecord* record, const HandshakeRx& rx, ByteView message,
                          MonotonicMs now) noexcept;
  Status on_resume_message(CarrierRecord* record, const HandshakeRx& rx, ByteView message,
                           MonotonicMs now) noexcept;
  Status responder_cookie_ok(const HandshakeRx& rx) noexcept;
  Status build_binding(SecurityScope scope, const keys::LinkCarrier& carrier, const MacAddress& mac_i,
                       const MacAddress& mac_r, NodeId node_i, NodeId node_r,
                       std::uint32_t exchange_id, std::array<std::uint8_t, 32>& out) noexcept;
  Status verify_cookie_and_allocate(const HandshakeRx& rx, ByteView message, CarrierRecord*& record,
                                    MonotonicMs now) noexcept;
  Status edhoc_commit(CarrierRecord& record) noexcept;
  Status resume_commit(CarrierRecord& record, const rlres1::Established& established) noexcept;
  // Authenticated peer-state checks (purpose echo, node, site, epochs,
  // caps agreement, initiator boot/caps echo). `peer_is_initiator`
  // selects the staged State (I or R). Records the peer GK epoch.
  Status check_peer_state(CarrierRecord& record, bool peer_is_initiator) noexcept;
  // Our Confirm for compose(): capability + contexts digests.
  Status build_confirm(CarrierRecord& record, bool ours_is_initiator) noexcept;
  // The peer's staged Confirm: purpose echo + contexts digest match.
  Status check_confirm(CarrierRecord& record, bool theirs_is_initiator) noexcept;
  // The peer's negotiated CID via the wrapper accessor, under the member
  // profile rule: exactly 4 bytes, nonzero as BE u32, not our own C_x.
  Status read_peer_cid(std::uint32_t& out) noexcept;
  // Cross-protocol simultaneous open (P4 §5.5): an inbound step-1 naming
  // `peer` proceeds unless OUR initiator exchange for it wins (we are the
  // smaller NodeId — drop theirs) or yields (drop ours, answer as
  // responder). False = drop the inbound message.
  bool step1_may_proceed(SecurityScope scope, NodeId peer) noexcept;
  // Capability digest + the three Exporter contexts for this flight.
  Status build_contexts(CarrierRecord& record, ScopeDigest& capability,
                        std::array<std::uint8_t, kExporterContextMax>& dir1, std::size_t& dir1_size,
                        std::array<std::uint8_t, kExporterContextMax>& dir2, std::size_t& dir2_size,
                        std::array<std::uint8_t, kExporterContextMax>& rms,
                        std::size_t& rms_size) noexcept;
  static StatusCode map_commit_failure(const Status& status) noexcept;
  Status pre_install_checks(NodeId peer, std::uint32_t peer_generation, std::uint32_t peer_role,
                            NetworkId network) noexcept;
  Status save_resume_slot(SecurityScope scope, NodeId peer, std::uint32_t peer_generation,
                          std::uint32_t peer_role,
                          const std::array<std::uint8_t, 8>& peer_cert_id,
                          std::uint32_t created_gk_epoch,
                          const std::array<std::uint8_t, 32>& rms) noexcept;
  Status mint_proof(CarrierRecord& record, AuthenticatedPeerProof& proof) noexcept;
  bool ecc_budget_ok(MonotonicMs now) noexcept;
  void ecc_spent(MonotonicMs now) noexcept;
  Status draw_exchange_id(std::uint32_t& out) noexcept;
  bool edhoc_cid_in_flight(std::uint32_t id) const noexcept;

  ResumeCache2& cache_;
  HandshakeSessionSink& sink_;
  MemberCookie& cookie_;
  HandshakeMembershipView& membership_;
  SessionCredentialVerifier& verifier_;
  RandomFn random_;
  void* random_ctx_;
  HandshakeLocal local_{};
  bool local_set_{false};
  bool configured_{false};
  bool entered_{false};
  MonotonicMs last_tick_{0};
  MonotonicMs last_ecc_{0};
  bool ecc_primed_{false};
  std::uint32_t next_token_{1};

  edhoc::Session edhoc_;
  MemberCredentials credentials_;
  rlres1::Engine rlres1_;
  bool rlres1_configured_{false};

  std::array<CarrierRecord, kCarrierRecords> records_{};
  EdhocFlight edhoc_flight_{};
  std::array<std::uint8_t, 4> edhoc_cid_bytes_{};
  // Single-owner big-message buffer (m2/m4 responder-duplicate, m3
  // initiator-retransmit, parked responder-m1). The owner token gates
  // every reader: a clobbered buffer is skipped, never sent.
  std::array<std::uint8_t, 960> big_tx_{};
  std::size_t big_tx_size_{0};
  std::uint32_t big_tx_owner_{0};

  HandshakeResult pending_{};
  bool has_pending_{false};
  StagedEstablished staged_{};
  // Commit outputs (install ids + proof), consumed by the caller into the
  // staged Established immediately — never left behind on failure.
  std::uint32_t pending_commit_tx_{0};
  std::uint32_t pending_commit_rx_{0};
  AuthenticatedPeerProof pending_commit_proof_{};
};

}  // namespace routeloom::sdkv1
