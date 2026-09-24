#include "routeloom/discovery.hpp"

#include <algorithm>
#include <cstring>

#include "routeloom/byte_io.hpp"

// Portable neighbor-discovery core (docs/design/autonomous-mesh/02-discovery.md,
// 06-membership-admission.md). See discovery.hpp for the contract overview.

namespace routeloom {
namespace {

// --- Internal body layouts (RLD1 body space; the 44B envelope is pinned by
// autonomy_wire + shared vectors, these payloads are the P1a exchange) --------
//
// OFFER body (36B): version u8=1 | density hint u8 | reserved u16=0 |
//                   cookie 16B | responder nonce 16B.
constexpr std::size_t kOfferBodySize = 36;
// BootstrapAuth PROVE body: cookie echo 16B | prove tag 16B.
constexpr std::size_t kProveBodySize = 32;
// CONFIRM / FINISH body: tag 16B.
constexpr std::size_t kAuthTagBodySize = 16;
// RLD1 BootstrapChunk body header: version u8=1 | subtype u8=1 |
// transaction u32 | offset u16 | total u16 | data[n].
constexpr std::size_t kChunkHeaderSize = 10;
constexpr std::size_t kChunkDataMax = autonomy::kRld1MaxBody - kChunkHeaderSize;
// RLD1 BootstrapReply body: version u8=1 | subtype u8=1 | transaction u32 |
// received u16 | status u8.
constexpr std::size_t kReplyBodySize = 10;
constexpr std::uint8_t kChunkStatusOk = 0;
constexpr std::uint8_t kChunkStatusIncomplete = 1;

constexpr std::uint64_t kWindowMs = 400;  // density observation = offer window
// Empty-slot sentinel for the discover ring: 0 is a valid timestamp.
constexpr MonotonicMs kNoDiscover = ~MonotonicMs{0};

bool mac_equal(const MacAddress& a, const MacAddress& b) noexcept {
  return a == b;
}

bool nonce_equal(const std::array<std::uint8_t, 16>& a,
                 const std::array<std::uint8_t, 16>& b) noexcept {
  return a == b;
}

}  // namespace

// --- DevPskAuthenticator ------------------------------------------------------
//
// EXPERIMENTAL / GROUP_SECRET_POSSESSION. Uses the provider's AEAD tag as a
// keyed MAC over a domain-separated AAD. Nonce-based AEAD (GCM/GMAC) must
// never reuse a (key, nonce) pair across different AADs — the observed tags
// are linear in the AAD and become forgeable. Verification here is
// recompute-and-compare, so the counter must be deterministic; a plain
// AAD hash would let an attacker who controls nonce-bearing fields craft
// colliding inputs offline. Instead the counter is derived SIV-style: an
// inner seal produces a keyed, attacker-unpredictable value and the emitted
// tag seals under a counter taken from it. The inner tag is never emitted,
// so its fixed-nonce construction is unobservable; two distinct AADs can
// collide only by accident (~2^-64 per pair).

Status DevPskAuthenticator::tag_for(const SecurityContext& context, const ByteView aad,
                                    AuthTag& out) noexcept {
  AuthTag inner{};
  std::uint8_t dummy = 0;
  const Status status = provider_.seal(context, 0, aad, ByteView{&dummy, 0},
                                       MutableByteView{&dummy, 1}, inner);
  if (!status) return status;
  std::uint64_t counter = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    counter = (counter << 8U) | inner[i];
  }
  return provider_.seal(context, counter, aad, ByteView{&dummy, 0},
                        MutableByteView{&dummy, 1}, out);
}

bool DevPskAuthenticator::tag_equal(const AuthTag& a, const AuthTag& b) noexcept {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}

Status DevPskAuthenticator::cookie_seal(const CookieMaterial& material,
                                        AuthTag& out) noexcept {
  // "RLC1" | requester mac | pad | requester nonce | network | bucket |
  // responder node | requester node.
  std::array<std::uint8_t, 60> aad{};
  ByteWriter writer(MutableByteView{aad.data(), aad.size()});
  Status status;
#define RL_WRITE(expr)             \
  do {                             \
    status = (expr);               \
    if (!status) return status;    \
  } while (false)
  RL_WRITE(writer.write_u32(0x524c4331));  // "RLC1"
  RL_WRITE(writer.write_bytes(ByteView{material.requester_mac.data(), 6}));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(
      ByteView{material.requester_nonce.data(), material.requester_nonce.size()}));
  RL_WRITE(writer.write_u64(material.network));
  RL_WRITE(writer.write_u64(material.time_bucket));
  RL_WRITE(writer.write_u64(material.responder_node));
  RL_WRITE(writer.write_u64(material.requester_node));
#undef RL_WRITE
  const SecurityContext context{SecurityScope::Link, material.network,
                                material.responder_node, material.requester_node,
                                domain_tag_};
  return tag_for(context, ByteView{aad.data(), writer.size()}, out);
}

Status DevPskAuthenticator::cookie_verify(const CookieMaterial& material,
                                          const AuthTag& cookie) noexcept {
  AuthTag expected{};
  const Status status = cookie_seal(material, expected);
  if (!status) return status;
  return tag_equal(expected, cookie)
             ? Status::success()
             : Status::error(StatusCode::AuthenticationFailed, "cookie mismatch");
}

Status DevPskAuthenticator::attest(const autonomy::AuthPhase phase,
                                   const AuthTranscript& transcript,
                                   AuthTag& out) noexcept {
  // "RLA1" | phase u8 | reserved 3B | requester node | responder node |
  // requester mac | responder mac | pad | network | requester nonce |
  // responder nonce | requester capability | responder capability |
  // scope_binding 32B (02-discovery-scope §5.2).
  std::array<std::uint8_t, 120> aad{};
  ByteWriter writer(MutableByteView{aad.data(), aad.size()});
  const bool requester_side =
      phase == autonomy::AuthPhase::Prove || phase == autonomy::AuthPhase::Finish;
  const NodeId sender =
      requester_side ? transcript.requester_node : transcript.responder_node;
  const NodeId receiver =
      requester_side ? transcript.responder_node : transcript.requester_node;
  Status status;
#define RL_WRITE(expr)             \
  do {                             \
    status = (expr);               \
    if (!status) return status;    \
  } while (false)
  RL_WRITE(writer.write_u32(0x524c4131));  // "RLA1"
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(phase)));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_u64(transcript.requester_node));
  RL_WRITE(writer.write_u64(transcript.responder_node));
  RL_WRITE(writer.write_bytes(ByteView{transcript.requester_mac.data(), 6}));
  RL_WRITE(writer.write_bytes(ByteView{transcript.responder_mac.data(), 6}));
  RL_WRITE(writer.write_u32(0));
  RL_WRITE(writer.write_u64(transcript.network));
  RL_WRITE(writer.write_bytes(ByteView{transcript.requester_nonce.data(), 16}));
  RL_WRITE(writer.write_bytes(ByteView{transcript.responder_nonce.data(), 16}));
  RL_WRITE(writer.write_u32(transcript.requester_capability));
  RL_WRITE(writer.write_u32(transcript.responder_capability));
  RL_WRITE(writer.write_bytes(
      ByteView{transcript.scope_binding.data(), transcript.scope_binding.size()}));
#undef RL_WRITE
  const SecurityContext context{SecurityScope::Link, transcript.network, sender,
                                receiver, domain_tag_};
  return tag_for(context, ByteView{aad.data(), writer.size()}, out);
}

Status DevPskAuthenticator::verify(const autonomy::AuthPhase phase,
                                   const AuthTranscript& transcript,
                                   const AuthTag& tag) noexcept {
  AuthTag expected{};
  const Status status = attest(phase, transcript, expected);
  if (!status) return status;
  return tag_equal(expected, tag)
             ? Status::success()
             : Status::error(StatusCode::AuthenticationFailed, "transcript tag mismatch");
}

Status DevPskAuthenticator::issue_proof(const AuthTranscript& transcript,
                                        const NodeId self, const AuthTag& closing_tag,
                                        AuthenticatedPeerProof& out) noexcept {
  NodeId peer = kInvalidNodeId;
  MacAddress peer_mac{};
  if (self == transcript.requester_node &&
      transcript.responder_node != kInvalidNodeId) {
    peer = transcript.responder_node;
    peer_mac = transcript.responder_mac;
  } else if (self == transcript.responder_node &&
             transcript.requester_node != kInvalidNodeId) {
    peer = transcript.requester_node;
    peer_mac = transcript.requester_mac;
  } else {
    return Status::error(StatusCode::InvalidArgument, "transcript identity invalid");
  }
  out = make_proof(peer, peer_mac, transcript.network, closing_tag);
  return Status::success();
}

// --- MembershipController -------------------------------------------------------

Status MembershipController::initialize(const MembershipHooks& hooks,
                                        const NetworkId network) noexcept {
  state_ = hooks.local_member(network) ? MembershipState::Member
                                       : MembershipState::Unprovisioned;
  return Status::success();
}

Status MembershipController::begin_discovery() noexcept {
  switch (state_) {
    case MembershipState::Unprovisioned:
      state_ = MembershipState::Discovering;
      return Status::success();
    case MembershipState::Discovering:
    case MembershipState::Authenticating:
    case MembershipState::AuthorizedPendingCommit:
    case MembershipState::Member:
      // Member stays Member: local re-binding never re-joins (D3-03, 06 §5).
      return Status::success();
    case MembershipState::Revoked:
      return Status::error(StatusCode::AuthorizationFailed,
                           "revoked membership cannot self-rejoin");
  }
  return Status::error(StatusCode::InvalidState, "unknown membership state");
}

Status MembershipController::begin_authentication() noexcept {
  switch (state_) {
    case MembershipState::Unprovisioned:
    case MembershipState::Discovering:
      state_ = MembershipState::Authenticating;
      return Status::success();
    case MembershipState::Authenticating:
    case MembershipState::AuthorizedPendingCommit:
    case MembershipState::Member:
      return Status::success();
    case MembershipState::Revoked:
      return Status::error(StatusCode::AuthorizationFailed,
                           "revoked membership cannot authenticate");
  }
  return Status::error(StatusCode::InvalidState, "unknown membership state");
}

MembershipState MembershipController::complete_authentication(
    MembershipHooks& hooks, const NodeId self, const NetworkId network) noexcept {
  switch (state_) {
    case MembershipState::Authenticating:
      state_ = MembershipState::AuthorizedPendingCommit;
      [[fallthrough]];
    case MembershipState::AuthorizedPendingCommit:
      if (hooks.approve_join(self, network)) {
        state_ = MembershipState::Member;
      }
      return state_;
    default:
      return state_;
  }
}

Status MembershipController::abort_authentication() noexcept {
  if (state_ == MembershipState::Authenticating) {
    state_ = MembershipState::Discovering;
  }
  return Status::success();
}

MembershipState MembershipController::retry_commit(MembershipHooks& hooks,
                                                   const NodeId self,
                                                   const NetworkId network) noexcept {
  if (state_ == MembershipState::AuthorizedPendingCommit &&
      hooks.approve_join(self, network)) {
    state_ = MembershipState::Member;
  }
  return state_;
}

// --- NeighborDiscovery ----------------------------------------------------------

NeighborDiscovery::NeighborDiscovery(const DiscoveryConfig& config, DiscoveryPort& port,
                                     NeighborAuthenticator& authenticator,
                                     MembershipHooks& hooks, EntropySource& entropy,
                                     DiscoveryObserver& observer) noexcept
    : config_(config),
      port_(port),
      authenticator_(authenticator),
      hooks_(hooks),
      entropy_(entropy),
      observer_(observer) {
  discover_times_.fill(kNoDiscover);
}

Status NeighborDiscovery::start(const MonotonicMs now_ms) noexcept {
  if (started_) {
    return Status::error(StatusCode::InvalidState, "discovery already started");
  }
  // Broad Commissioning-scope discovery is never valid on Network 0 — this
  // check precedes the generic network!=0 rule so the specific code wins.
  if (scope_mode_scoped(config_.scope_mode) &&
      config_.scope_class == endpoint::ScopeClass::Commissioning &&
      config_.network == 0) {
    return Status::error(StatusCode::NetworkRequired,
                         "commissioning scope requires a Network");
  }
  if (config_.node == kInvalidNodeId || config_.network == 0 ||
      mac_equal(config_.mac, discovery_const::kBroadcastMac) ||
      config_.cookie_bucket_ms == 0 || config_.candidate_ttl_ms == 0 ||
      config_.awake_lease_ms == 0) {
    return Status::error(StatusCode::InvalidArgument, "discovery config invalid");
  }
  // A backwards retry range would underflow the uniform draw; a cap below
  // the draw floor would silently clamp every retry to zero wait.
  if (config_.backoff_min_ms > config_.backoff_initial_max_ms ||
      config_.backoff_max_ms < config_.backoff_min_ms) {
    return Status::error(StatusCode::InvalidArgument,
                         "discovery backoff range invalid");
  }
  if (scope_mode_scoped(config_.scope_mode)) {
    if (config_.scope_provider == nullptr ||
        config_.scope == kInvalidScopeRef) {
      return Status::error(StatusCode::InvalidArgument,
                           "scoped mode requires a scope provider and ScopeRef");
    }
    // Required is unusable when the authenticator cannot fold scope_binding
    // into the transcript — never silently advertise it (02 §5.2).
    if (config_.scope_mode == ScopeMode::Required &&
        !authenticator_.binds_scope()) {
      return Status::error(StatusCode::AuthProfileUnavailable,
                           "authenticator cannot process scope_binding");
    }
    // OptionalMigration legacy window: owner-proven deadline, capped at the
    // 24h contract maximum measured from this start (02 §2.2).
    migration_deadline_ms_ =
        config_.migration_until_ms == 0
            ? 0
            : std::min(config_.migration_until_ms,
                       now_ms + kScopeLegacyMigrationMaxMs);
  }
  membership_.initialize(hooks_, config_.network);
  started_ = true;
  return Status::success();
}

Status NeighborDiscovery::begin_discovery(const MonotonicMs now_ms) noexcept {
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "discovery not started");
  }
  const Status status = membership_.begin_discovery();
  if (!status) return status;
  // Required with an unusable scope stops discovery outright — never a
  // downgrade to OpenLegacy/Off (02-discovery-scope §2.2, §2.6).
  if (config_.scope_mode == ScopeMode::Required && !scope_tx_usable()) {
    ++scope_stats_.key_unavailable;
    return Status::error(StatusCode::AuthProfileUnavailable,
                         "required scope key unavailable");
  }
  if (outbound_.active) {
    return Status::error(StatusCode::WouldBlock, "discovery exchange in flight");
  }
  // Global handshake budget is 1: a responder-side authentication already
  // in flight counts, so an outbound request while we are mid-PROVE as the
  // responder is refused instead of silently doubling the budget.
  const bool responder_auth = candidates_.find([](const Candidate& c) {
    return c.phase == NeighborPhase::Authenticating;
  }) != nullptr;
  if (responder_auth) {
    return Status::error(StatusCode::WouldBlock,
                         "responder authentication in flight");
  }
  if (!reserve_transient()) {
    ++stats_.peer_capacity;
    reject_event("PEER_CAPACITY", kInvalidNodeId);
    return Status::error(StatusCode::PeerCapacity, "no transient peer slot");
  }
  outbound_ = Outbound{};
  outbound_.active = true;
  outbound_.transient_held = true;
  outbound_.stage = OutboundStage::AwaitingOffers;
  const Status nonce = entropy_.fill(
      MutableByteView{outbound_.our_nonce.data(), outbound_.our_nonce.size()});
  if (!nonce) {
    outbound_ = Outbound{};
    release_transient();
    return nonce;
  }
  // Cold-start spread (radio.md §13): a fresh requester exchange defers its
  // first DISCOVER by a uniform [0, cold_start_jitter_max_ms) draw so
  // simultaneous boots do not burst in lock-step. A zero draw keeps the
  // send synchronous so its failure is reported to the caller; a deferred
  // send flows through the same discover_due path as a retry.
  std::uint32_t jitter_ms = 0;
  if (config_.cold_start_jitter_max_ms > 0) {
    std::uint64_t roll = 0;
    if (!next_u64(roll)) {
      outbound_ = Outbound{};
      release_transient();
      return Status::error(StatusCode::InternalError, "entropy unavailable");
    }
    jitter_ms =
        static_cast<std::uint32_t>(roll % config_.cold_start_jitter_max_ms);
  }
  if (jitter_ms == 0) {
    outbound_.stage_deadline_ms = now_ms + config_.offer_window_ms;
    return send_discover(now_ms);
  }
  outbound_.discover_due_ms = now_ms + jitter_ms;
  outbound_.stage_deadline_ms = outbound_.discover_due_ms +
                               config_.offer_window_ms +
                               config_.auth_timeout_ms;
  return Status::success();
}

// --- RX: RLD1 carrier -----------------------------------------------------------

void NeighborDiscovery::on_rld1_rx(const DiscoveryRxMetadata& rx,
                                   const ByteView frame,
                                   const MonotonicMs now_ms) noexcept {
  if (!started_) return;
  autonomy::Rld1Envelope env{};
  // Carrier is already selected by the caller's rld1_probe; a decode failure
  // here is a REJECT — never a fallback into the Wire parser (06 §3.1).
  if (!autonomy::rld1_decode(frame, env)) {
    ++stats_.kind_rejects;
    reject_event("KIND_REJECT", kInvalidNodeId);
    return;
  }
  if (!gate(AdmissionCarrier::Rld1, AdmissionDirection::Rx, env.kind,
            /*transaction_alive=*/true, now_ms)) {
    ++stats_.kind_rejects;
    reject_event("KIND_REJECT", env.claimed_node);
    return;
  }
  // Scoped modes enforce the observed-destination rule (02-discovery-scope
  // §2.4): DISCOVER is broadcast-only, everything else must be unicast to
  // this node. Claimed addresses in the frame are never consulted.
  if (scope_mode_scoped(config_.scope_mode)) {
    const bool wants_broadcast = env.kind == FrameType::Discover;
    const MacAddress& expected =
        wants_broadcast ? discovery_const::kBroadcastMac : config_.mac;
    if (!mac_equal(rx.destination, expected)) {
      if (env.kind == FrameType::Discover || env.kind == FrameType::Offer) {
        ++scope_stats_.mac_rejected;
      } else {
        ++stats_.kind_rejects;
      }
      return;
    }
  }
  switch (env.kind) {
    case FrameType::Discover:
      handle_discover(rx, env, frame, now_ms);
      break;
    case FrameType::Offer:
      handle_offer(rx, env, frame, now_ms);
      break;
    case FrameType::BootstrapAuth:
      handle_auth(rx.source, env, now_ms);
      break;
    case FrameType::BootstrapChunk:
      handle_chunk(rx.source, env, now_ms);
      break;
    case FrameType::BootstrapReply:
      // Fragment control replies are informational only; v1 sends chunks
      // in order and does not retransmit on Incomplete beyond the exchange
      // deadline.
      break;
    default:
      ++stats_.kind_rejects;
      break;
  }
}

// Scope-filtered DISCOVER pipeline (02-discovery-scope §2.4/§2.5): cheap
// parse -> raw budget -> lane classify -> hint -> MAC verify -> dedup ->
// in-scope density -> candidate reservation. Raw accounting never
// contaminates density, candidate, transient or auth resources.
void NeighborDiscovery::handle_discover(const DiscoveryRxMetadata& rx,
                                        const autonomy::Rld1Envelope& env,
                                        const ByteView frame,
                                        const MonotonicMs now_ms) noexcept {
  ++stats_.discovers_rx;
  const bool scoped_mode = scope_mode_scoped(config_.scope_mode);
  if (scoped_mode) {
    ++scope_stats_.raw_rx;
    if (!raw_budget_.consume(now_ms)) {
      ++scope_stats_.budget_dropped;
      return;
    }
  }
  if (env.body_size == 0) {
    handle_discover_legacy(rx.source, env, frame, now_ms);
    return;
  }
  if (!scoped_mode || env.body[0] != endpoint::kScopeBodyVersion) {
    // An unknown body version is a REJECT — a malformed v2 frame is never
    // reinterpreted as a legacy exchange (02-discovery-scope §2.2).
    ++stats_.kind_rejects;
    return;
  }
  handle_discover_scoped(rx, env, frame, now_ms);
}

void NeighborDiscovery::handle_discover_legacy(
    const MacAddress& source, const autonomy::Rld1Envelope& env,
    const ByteView frame, const MonotonicMs now_ms) noexcept {
  const bool scoped_mode = scope_mode_scoped(config_.scope_mode);
  // The 4-byte hint is only an exploration filter: mismatches never reach a
  // candidate record and never imply membership either way (02 §4).
  if (env.network_hint != config_.network_hint) {
    if (scoped_mode) ++scope_stats_.hint_mismatch;
    return;
  }
  if (env.claimed_node == config_.node || env.claimed_node == kInvalidNodeId) return;
  ScopeExchangeContext exchange{};
  // The transcript binding always needs the real DISCOVER digest — in
  // Off/OpenLegacy too, or both sides compute different scope_bindings.
  sha256(frame, exchange.discover_digest);
  if (scoped_mode) {
    // OptionalMigration inside its window admits the legacy lane; Required
    // treats a tag-less frame as a silent drop — no per-source oracle.
    if (!legacy_permitted(now_ms)) {
      ++scope_stats_.mac_rejected;
      return;
    }
    std::array<std::uint8_t, 16> content{};
    std::memcpy(content.data(), exchange.discover_digest.data(), content.size());
    switch (dedup_.check(source, env.transaction_nonce, 0, 0, content, now_ms)) {
      case ScopeDedupResult::New:
        break;
      case ScopeDedupResult::Duplicate:
        ++scope_stats_.duplicate;
        return;
      case ScopeDedupResult::Conflict:
        ++scope_stats_.dedup_conflict;
        return;
      case ScopeDedupResult::Full:
        ++scope_stats_.dedup_full;
        return;
    }
  }
  // Density is measured BEFORE recording this event so a lone DISCOVER is
  // always answered (02 §6: suppression must never pin the probability to 0).
  const std::uint32_t density = recent_discovers(now_ms);
  record_discover(now_ms);
  admit_discover(source, env, exchange, density, now_ms);
}

void NeighborDiscovery::handle_discover_scoped(
    const DiscoveryRxMetadata& rx, const autonomy::Rld1Envelope& env,
    const ByteView frame, const MonotonicMs now_ms) noexcept {
  endpoint::Rld1DiscoverBodyV2 body{};
  if (!endpoint::scope_discover_body_decode(
          ByteView{env.body.data(), env.body_size}, body)) {
    ++stats_.kind_rejects;  // malformed v2 — never reinterpreted as legacy
    return;
  }
  if (env.claimed_node == config_.node || env.claimed_node == kInvalidNodeId) return;
  if (!scope_rx_usable()) {
    ++scope_stats_.key_unavailable;
    return;
  }
  std::uint32_t current = 0;
  if (!config_.scope_provider->current_generation(config_.scope, current)) {
    ++scope_stats_.key_unavailable;  // key loss stops discovery; no downgrade
    return;
  }
  if (!config_.scope_provider->accepted_generation(config_.scope, body.generation,
                                                   now_ms)) {
    ++scope_stats_.unknown_generation;
    return;
  }
  // Cheap hint candidate check against OUR configured class: the hint space
  // separates Member from Commissioning, so a frame of the other class fails
  // here without any MAC work (02 §2.4). The (class,generation,network)->hint
  // map is cached so this step never costs a scope-MAC operation.
  std::uint32_t hint = 0;
  if (!scoped_hint_for(config_.scope_class, body.generation, hint) ||
      env.network_hint != hint) {
    ++scope_stats_.hint_mismatch;
    return;
  }
  // Step 4 (scope MAC verify) is deferred to the Owner poll so a burst can
  // never exceed kScopeMacsPerPoll verifications per poll.
  PendingVerify* pending = pending_verify_.allocate();
  if (pending == nullptr) {
    ++scope_stats_.budget_dropped;
    return;
  }
  pending->offer = false;
  pending->rx = rx;
  pending->env = env;
  if (frame.size <= pending->frame.bytes.size()) {
    std::memcpy(pending->frame.bytes.data(), frame.data, frame.size);
    pending->frame.size = frame.size;
  }
  sha256(frame, pending->frame_digest);
  pending->generation = body.generation;
  pending->scope_class = body.scope_class;
  pending->expected_tag = body.tag;
}

void NeighborDiscovery::drain_scope_pending(const MonotonicMs now_ms) noexcept {
  std::size_t spent = 0;
  std::array<PendingVerify*, kScopePendingCapacity> done{};
  std::size_t done_count = 0;
  pending_verify_.for_each([&](PendingVerify& pending) {
    // Generation re-check AT VERIFY TIME: the queue-time gate admitted the
    // frame while its generation was accepted, but a previous generation's
    // overlap can close while the frame sits in the queue — queueing is not
    // evidence, the tag must still verify under an accepted generation.
    if (!config_.scope_provider->accepted_generation(config_.scope,
                                                     pending.generation,
                                                     now_ms)) {
      ++scope_stats_.unknown_generation;
      done[done_count++] = &pending;
      return;
    }
    if (spent >= kScopeMacsPerPoll) return;  // bounded MACs per Owner poll
    ++spent;
    done[done_count++] = &pending;
    Status status;
    if (pending.offer) {
      ByteBuffer<endpoint::kScopeOfferMacInputSize> input{};
      status = endpoint::scope_offer_mac_input(
          config_.network, config_.mac, pending.rx.source,
          ByteView{pending.discover_digest.data(), pending.discover_digest.size()},
          ByteView{pending.frame.bytes.data(), autonomy::kRld1HeaderSize},
          ByteView{pending.frame.bytes.data() + autonomy::kRld1HeaderSize, 44},
          input);
      if (status.ok()) {
        status = scope_tag_verify(*config_.scope_provider, config_.scope,
                                  pending.generation, input.view(),
                                  pending.expected_tag);
      }
    } else {
      ByteBuffer<endpoint::kScopeDiscoverMacInputSize> input{};
      status = endpoint::scope_discover_mac_input(
          config_.network, pending.rx.source, discovery_const::kBroadcastMac,
          ByteView{pending.frame.bytes.data(), autonomy::kRld1HeaderSize},
          ByteView{pending.frame.bytes.data() + autonomy::kRld1HeaderSize, 8},
          input);
      if (status.ok()) {
        status = scope_tag_verify(*config_.scope_provider, config_.scope,
                                  pending.generation, input.view(),
                                  pending.expected_tag);
      }
    }
    if (!status) {
      ++scope_stats_.mac_rejected;  // silent drop — no per-source oracle
      return;
    }
    if (pending.offer) {
      accept_scoped_offer(pending, now_ms);
    } else {
      admit_scoped_discover(pending, now_ms);
    }
  });
  for (std::size_t i = 0; i < done_count; ++i) {
    pending_verify_.release(done[i]);
  }
}

void NeighborDiscovery::admit_scoped_discover(PendingVerify& pending,
                                              const MonotonicMs now_ms) noexcept {
  // Dedup — only MAC-verified frames populate the table, and a re-receive
  // never extends the 8s first-sight window (02 §2.5).
  std::array<std::uint8_t, 16> content{};
  std::memcpy(content.data(), pending.frame_digest.data(), content.size());
  switch (dedup_.check(pending.rx.source, pending.env.transaction_nonce,
                       static_cast<std::uint8_t>(pending.scope_class),
                       pending.generation, content, now_ms)) {
    case ScopeDedupResult::New:
      break;
    case ScopeDedupResult::Duplicate:
      ++scope_stats_.duplicate;
      return;
    case ScopeDedupResult::Conflict:
      ++scope_stats_.dedup_conflict;
      return;
    case ScopeDedupResult::Full:
      ++scope_stats_.dedup_full;
      return;
  }
  ++scope_stats_.scope_accepted;
  const std::uint32_t density = recent_discovers(now_ms);
  record_discover(now_ms);
  ScopeExchangeContext exchange{};
  exchange.scoped = true;
  exchange.scope_class = pending.scope_class;
  exchange.generation = pending.generation;
  exchange.discover_digest = pending.frame_digest;
  admit_discover(pending.rx.source, pending.env, exchange, density, now_ms);
}

// Shared candidate/transient reservation + cookie/OFFER scheduling for both
// lanes — the scope layer only decides WHETHER this point is reached.
void NeighborDiscovery::admit_discover(
    const MacAddress& source, const autonomy::Rld1Envelope& env,
    const ScopeExchangeContext& exchange, const std::uint32_t density,
    const MonotonicMs now_ms) noexcept {
  if (scope_mode_scoped(config_.scope_mode) && !exchange.scoped) {
    ++scope_stats_.legacy_used;
  }
  // A duplicate DISCOVER for a live candidate refreshes it in place — MAC
  // churn cannot multiply candidate records (D3-04: quota is global).
  Candidate* candidate = find_candidate(source, env.transaction_nonce);
  if (candidate == nullptr) {
    candidate = candidates_.find([&](const Candidate& c) {
      return mac_equal(c.mac, source);
    });
    if (candidate != nullptr) {
      // An in-flight authentication must not be re-keyed by a fresh
      // unauthenticated DISCOVER, and a scoped candidate is never rewritten
      // by the other lane: overwriting the nonce/claim/digest would strand
      // the honest requester's PROVE and corrupt the transcript binding.
      if (candidate->phase != NeighborPhase::Candidate ||
          candidate->exchange.scoped != exchange.scoped) {
        return;
      }
      // Same radio, new attempt nonce: re-issue under the newest nonce.
      candidate->txn_nonce = env.transaction_nonce;
      candidate->claimed_node = env.claimed_node;
      candidate->expires_at_ms = now_ms + config_.candidate_ttl_ms;
      candidate->exchange = exchange;
    }
  }
  if (candidate == nullptr) {
    // Density-aware suppression (02 §6): respond with probability
    // 1/(1+recent_discovers). Never permanently zero — the divisor only grows
    // with observed density inside the offer window. An entropy failure
    // suppresses (fail-closed): a broken RNG is exactly the storm condition
    // this lottery exists for, never a reason to answer everyone.
    if (density > 0) {
      std::uint64_t draw = 0;
      if (!next_u64(draw) || (draw % (density + 1)) != 0) {
        ++stats_.suppressed_offers;
        return;
      }
    }
    candidate = candidates_.allocate();
    if (candidate == nullptr) {
      ++stats_.peer_capacity;
      if (scope_mode_scoped(config_.scope_mode)) ++scope_stats_.candidate_full;
      reject_event("PEER_CAPACITY", env.claimed_node);
      return;
    }
    if (!mint_candidate_id(next_candidate_id_, candidate->id)) {
      // Id space exhausted: drop the record rather than issuing 0 or
      // wrapping onto a live exchange (Q117-13).
      release_candidate(*candidate);
      ++stats_.candidate_id_exhausted;
      reject_event("CANDIDATE_ID_EXHAUSTED", env.claimed_node);
      return;
    }
    candidate->mac = source;
    candidate->claimed_node = env.claimed_node;
    candidate->txn_nonce = env.transaction_nonce;
    candidate->peer_capability = env.capability_bits;
    candidate->phase = NeighborPhase::Candidate;
    candidate->expires_at_ms = now_ms + config_.candidate_ttl_ms;
    candidate->exchange = exchange;
  }

  // A transient peer slot is required to answer — without one the candidate
  // is parked (bounded by TTL), never answered via DATA-broadcast escape.
  if (!candidate->transient_held) {
    if (!reserve_transient()) {
      ++stats_.peer_capacity;
      if (scope_mode_scoped(config_.scope_mode)) ++scope_stats_.candidate_full;
      reject_event("PEER_CAPACITY", env.claimed_node);
      return;  // parked; poll() retries while the TTL lasts
    }
    candidate->transient_held = true;
  }
  std::uint64_t slot = 0;
  if (entropy_.fill(MutableByteView{candidate->our_nonce.data(), 16}).ok() &&
      authenticator_
          .cookie_seal(CookieMaterial{source, candidate->txn_nonce, config_.network,
                                      now_ms / config_.cookie_bucket_ms, config_.node,
                                      candidate->claimed_node},
                       candidate->cookie)
          .ok() &&
      next_u64(slot)) {
    candidate->offer_due_ms =
        now_ms + (slot % discovery_const::kOfferSlots) *
                     discovery_const::kOfferSlotMs;
    candidate->offer_pending = true;
  } else {
    release_candidate(*candidate);
  }
}

void NeighborDiscovery::handle_offer(const DiscoveryRxMetadata& rx,
                                     const autonomy::Rld1Envelope& env,
                                     const ByteView frame,
                                     const MonotonicMs now_ms) noexcept {
  ++stats_.offers_rx;
  const bool scoped_mode = scope_mode_scoped(config_.scope_mode);
  if (scoped_mode) {
    ++scope_stats_.raw_rx;
    if (!raw_budget_.consume(now_ms)) {
      ++scope_stats_.budget_dropped;
      return;
    }
  }
  if (!outbound_.active || outbound_.stage != OutboundStage::AwaitingOffers ||
      outbound_.have_offer || now_ms > outbound_.stage_deadline_ms) {
    return;
  }
  // The OFFER echoes our transaction nonce; anything else is not ours.
  if (!nonce_equal(env.transaction_nonce, outbound_.our_nonce)) return;

  if (env.body_size >= 1 && env.body[0] == endpoint::kScopeBodyVersion) {
    if (!scoped_mode) {
      ++stats_.kind_rejects;  // v2 is never reinterpreted on a legacy node
      return;
    }
    queue_offer_verify(rx, env, frame, now_ms);
    return;
  }
  // Legacy v1 OFFER lane. In Optional it is only valid while a legacy
  // attempt is actually ours; in Required it is a tag-less drop.
  if (scoped_mode &&
      (!legacy_permitted(now_ms) || outbound_.exchange.scoped)) {
    ++scope_stats_.mac_rejected;
    return;
  }
  if (env.network_hint != config_.network_hint) {
    if (scoped_mode) ++scope_stats_.hint_mismatch;
    return;
  }
  if (env.body_size != kOfferBodySize || env.body[0] != 1 || env.body[2] != 0 ||
      env.body[3] != 0) {
    ++stats_.kind_rejects;
    return;
  }
  std::array<std::uint8_t, 16> cookie{};
  std::array<std::uint8_t, 16> responder_nonce{};
  std::memcpy(cookie.data(), env.body.data() + 4, 16);
  std::memcpy(responder_nonce.data(), env.body.data() + 20, 16);
  accept_offer(rx.source, env, cookie, responder_nonce, frame, now_ms);
}

void NeighborDiscovery::queue_offer_verify(
    const DiscoveryRxMetadata& rx, const autonomy::Rld1Envelope& env,
    const ByteView frame, const MonotonicMs now_ms) noexcept {
  endpoint::Rld1OfferBodyV2 body{};
  if (!endpoint::scope_offer_body_decode(
          ByteView{env.body.data(), env.body_size}, body)) {
    ++stats_.kind_rejects;  // malformed v2 — never reinterpreted as legacy
    return;
  }
  if (!scope_rx_usable()) {
    ++scope_stats_.key_unavailable;
    return;
  }
  std::uint32_t current = 0;
  if (!config_.scope_provider->current_generation(config_.scope, current)) {
    ++scope_stats_.key_unavailable;
    return;
  }
  if (!config_.scope_provider->accepted_generation(config_.scope, body.generation,
                                                   now_ms)) {
    ++scope_stats_.unknown_generation;
    return;
  }
  // The OFFER must answer OUR scoped DISCOVER: class/generation pin to the
  // attempt context so a foreign or replayed scoped offer cannot bind.
  if (!outbound_.exchange.scoped ||
      body.scope_class != outbound_.exchange.scope_class ||
      body.generation != outbound_.exchange.generation) {
    ++scope_stats_.mac_rejected;
    return;
  }
  std::uint32_t hint = 0;
  if (!scoped_hint_for(config_.scope_class, body.generation, hint) ||
      env.network_hint != hint) {
    ++scope_stats_.hint_mismatch;
    return;
  }
  PendingVerify* pending = pending_verify_.allocate();
  if (pending == nullptr) {
    ++scope_stats_.budget_dropped;
    return;
  }
  pending->offer = true;
  pending->rx = rx;
  pending->env = env;
  if (frame.size <= pending->frame.bytes.size()) {
    std::memcpy(pending->frame.bytes.data(), frame.data, frame.size);
    pending->frame.size = frame.size;
  }
  sha256(frame, pending->frame_digest);
  pending->discover_digest = outbound_.exchange.discover_digest;
  pending->generation = body.generation;
  pending->scope_class = body.scope_class;
  pending->expected_tag = body.tag;
  pending->offer_cookie = body.cookie;
  pending->offer_nonce = body.responder_nonce;
}

void NeighborDiscovery::accept_scoped_offer(PendingVerify& pending,
                                            const MonotonicMs now_ms) noexcept {
  // State may have moved while the frame waited in the verify queue —
  // re-check the whole cheap-parse chain on the freshest context.
  if (!outbound_.active || outbound_.stage != OutboundStage::AwaitingOffers ||
      outbound_.have_offer || now_ms > outbound_.stage_deadline_ms ||
      !nonce_equal(pending.env.transaction_nonce, outbound_.our_nonce) ||
      !outbound_.exchange.scoped ||
      pending.scope_class != outbound_.exchange.scope_class ||
      pending.generation != outbound_.exchange.generation ||
      pending.discover_digest != outbound_.exchange.discover_digest) {
    return;
  }
  ++scope_stats_.scope_accepted;
  outbound_.have_offer = true;
  outbound_.peer_mac = pending.rx.source;
  outbound_.peer_node = pending.env.claimed_node;
  outbound_.peer_capability = pending.env.capability_bits;
  outbound_.cookie_echo = pending.offer_cookie;
  outbound_.peer_nonce = pending.offer_nonce;
  outbound_.exchange.offer_digest = pending.frame_digest;
  outbound_.stage = OutboundStage::ProvePending;
  outbound_.stage_deadline_ms = now_ms + config_.auth_timeout_ms;
  membership_.begin_authentication();
}

void NeighborDiscovery::accept_offer(
    const MacAddress& source, const autonomy::Rld1Envelope& env,
    const std::array<std::uint8_t, 16>& cookie,
    const std::array<std::uint8_t, 16>& responder_nonce,
    const ByteView frame, const MonotonicMs now_ms) noexcept {
  // First valid OFFER wins; the exchange stays single (global handshakes=1).
  outbound_.have_offer = true;
  outbound_.peer_mac = source;
  outbound_.peer_node = env.claimed_node;
  outbound_.peer_capability = env.capability_bits;
  outbound_.cookie_echo = cookie;
  outbound_.peer_nonce = responder_nonce;
  sha256(frame, outbound_.exchange.offer_digest);
  outbound_.stage = OutboundStage::ProvePending;
  outbound_.stage_deadline_ms = now_ms + config_.auth_timeout_ms;
  if (scope_mode_scoped(config_.scope_mode)) ++scope_stats_.legacy_used;
  // Starting a bounded mutual exchange transitions a joining node
  // Discovering -> Authenticating; a Member stays Member (D3-11).
  membership_.begin_authentication();
}

void NeighborDiscovery::handle_auth(const MacAddress& source,
                                    const autonomy::Rld1Envelope& env,
                                    const MonotonicMs now_ms) noexcept {
  autonomy::BootstrapAuthBody auth{};
  if (!autonomy::bootstrap_auth_decode(
          ByteView{env.body.data(), env.body_size}, auth)) {
    ++stats_.kind_rejects;
    reject_event("KIND_REJECT", env.claimed_node);
    return;
  }
  switch (auth.phase) {
    case autonomy::AuthPhase::Prove:
      handle_prove(source, env, auth, now_ms);
      break;
    case autonomy::AuthPhase::Confirm:
      handle_confirm(source, env, auth, now_ms);
      break;
    case autonomy::AuthPhase::Finish:
      handle_finish(source, env, auth, now_ms);
      break;
    default:
      ++stats_.kind_rejects;
      break;
  }
}

void NeighborDiscovery::handle_prove(const MacAddress& source,
                                     const autonomy::Rld1Envelope& env,
                                     const autonomy::BootstrapAuthBody& auth,
                                     const MonotonicMs now_ms) noexcept {
  ++stats_.proves_rx;
  Candidate* candidate = find_candidate(source, env.transaction_nonce);
  if (candidate == nullptr || candidate->phase != NeighborPhase::Candidate ||
      candidate->offer_pending || auth.body_size != kProveBodySize ||
      env.claimed_node != candidate->claimed_node) {
    return;  // no live transaction expecting a PROVE for this nonce
  }

  AuthTag cookie_echo{};
  AuthTag prove_tag{};
  std::memcpy(cookie_echo.data(), auth.body.data(), 16);
  std::memcpy(prove_tag.data(), auth.body.data() + 16, 16);

  // Cookie check: bound to (MAC, nonce, network, time bucket). Accept the
  // current and previous bucket only; a foreign or replayed cookie ends the
  // transaction before any heavy verification runs.
  const std::uint64_t bucket = now_ms / config_.cookie_bucket_ms;
  CookieMaterial material{source, candidate->txn_nonce, config_.network, bucket,
                          config_.node, candidate->claimed_node};
  Status cookie = authenticator_.cookie_verify(material, cookie_echo);
  if (!cookie && bucket > 0) {
    material.time_bucket = bucket - 1;
    cookie = authenticator_.cookie_verify(material, cookie_echo);
  }
  if (!cookie || cookie_echo != candidate->cookie) {
    ++stats_.cookie_rejects;
    reject_event("COOKIE_REJECT", candidate->claimed_node);
    release_candidate(*candidate);
    relax_membership();
    return;
  }

  const AuthTranscript transcript{env.claimed_node, config_.node, source, config_.mac,
                                  config_.network, candidate->txn_nonce,
                                  candidate->our_nonce, candidate->peer_capability,
                                  config_.capability_bits,
                                  candidate->exchange.binding()};
  if (!authenticator_.verify(autonomy::AuthPhase::Prove, transcript, prove_tag)) {
    ++stats_.auth_tag_rejects;
    reject_event("AUTH_FAILED", env.claimed_node);
    release_candidate(*candidate);
    relax_membership();
    return;
  }

  // Global handshake budget = 1. A PROVE arriving while our own outbound
  // exchange is live and could still target this peer (AwaitingOffers: the
  // winner is not picked yet, or the same MAC is selected) is a simultaneous
  // open (02 §3): the verified lower NodeId stays requester, the other side
  // cancels its outbound and answers — exactly one exchange survives.
  if (outbound_.active) {
    const bool same_peer =
        outbound_.stage == OutboundStage::AwaitingOffers ||
        mac_equal(outbound_.peer_mac, source);
    if (same_peer) {
      if (env.claimed_node < config_.node) {
        // Peer is the lower NodeId: cancel our requester exchange, respond.
        outbound_ = Outbound{};
        release_transient();
      } else {
        ++stats_.simultaneous_resolved;
        return;  // our exchange wins; peer will mirror this rule
      }
    } else {
      return;  // single global handshake: defer, requester retries
    }
  }
  const bool other_auth =
      candidates_.find([](const Candidate& c) {
        return c.phase == NeighborPhase::Authenticating;
      }) != nullptr;
  if (other_auth) return;  // responder-side budget also 1

  candidate->phase = NeighborPhase::Authenticating;
  candidate->expires_at_ms = now_ms + config_.auth_timeout_ms;
  membership_.begin_authentication();
  send_confirm(*candidate, now_ms);
}

void NeighborDiscovery::handle_confirm(const MacAddress& source,
                                       const autonomy::Rld1Envelope& env,
                                       const autonomy::BootstrapAuthBody& auth,
                                       const MonotonicMs now_ms) noexcept {
  if (!outbound_.active || outbound_.stage != OutboundStage::AwaitingConfirm ||
      !mac_equal(source, outbound_.peer_mac) ||
      !nonce_equal(env.transaction_nonce, outbound_.our_nonce) ||
      env.claimed_node != outbound_.peer_node ||
      auth.body_size != kAuthTagBodySize) {
    return;  // stale/foreign CONFIRM must not resurrect a dead exchange
  }
  AuthTag confirm_tag{};
  std::memcpy(confirm_tag.data(), auth.body.data(), 16);
  const AuthTranscript transcript{config_.node, outbound_.peer_node, config_.mac,
                                  outbound_.peer_mac, config_.network,
                                  outbound_.our_nonce, outbound_.peer_nonce,
                                  config_.capability_bits,
                                  outbound_.peer_capability,
                                  outbound_.exchange.binding()};
  if (!authenticator_.verify(autonomy::AuthPhase::Confirm, transcript,
                             confirm_tag)) {
    ++stats_.auth_tag_rejects;
    fail_outbound(now_ms, "AUTH_FAILED");
    return;
  }
  if (!send_finish(now_ms).ok()) return;
  const MacAddress peer_mac = outbound_.peer_mac;
  const NodeId peer_node = outbound_.peer_node;
  const std::uint32_t peer_cap = outbound_.peer_capability;
  const auto req_nonce = outbound_.our_nonce;
  const auto resp_nonce = outbound_.peer_nonce;
  const ScopeExchangeContext exchange = outbound_.exchange;
  outbound_ = Outbound{};
  release_transient();
  complete_exchange(peer_mac, peer_node, peer_cap, req_nonce, resp_nonce,
                    confirm_tag, exchange, /*we_are_requester=*/true, now_ms);
}

void NeighborDiscovery::handle_finish(const MacAddress& source,
                                      const autonomy::Rld1Envelope& env,
                                      const autonomy::BootstrapAuthBody& auth,
                                      const MonotonicMs now_ms) noexcept {
  Candidate* candidate = find_candidate(source, env.transaction_nonce);
  if (candidate == nullptr || candidate->phase != NeighborPhase::Authenticating ||
      auth.body_size != kAuthTagBodySize ||
      env.claimed_node != candidate->claimed_node) {
    return;  // late FINISH for a cancelled transaction is ignored (06 §2.2)
  }
  AuthTag finish_tag{};
  std::memcpy(finish_tag.data(), auth.body.data(), 16);
  const AuthTranscript transcript{env.claimed_node, config_.node, source, config_.mac,
                                  config_.network, candidate->txn_nonce,
                                  candidate->our_nonce, candidate->peer_capability,
                                  config_.capability_bits,
                                  candidate->exchange.binding()};
  if (!authenticator_.verify(autonomy::AuthPhase::Finish, transcript, finish_tag)) {
    ++stats_.auth_tag_rejects;
    reject_event("AUTH_FAILED", env.claimed_node);
    release_candidate(*candidate);
    relax_membership();
    return;
  }
  const NodeId peer_node = candidate->claimed_node;
  const std::uint32_t peer_cap = candidate->peer_capability;
  const auto req_nonce = candidate->txn_nonce;
  const auto resp_nonce = candidate->our_nonce;
  const ScopeExchangeContext exchange = candidate->exchange;
  release_candidate(*candidate);
  complete_exchange(source, peer_node, peer_cap, req_nonce, resp_nonce, finish_tag,
                    exchange, /*we_are_requester=*/false, now_ms);
}

// --- RX: RLD1 fragmentation ------------------------------------------------------

void NeighborDiscovery::handle_chunk(const MacAddress& source,
                                     const autonomy::Rld1Envelope& env,
                                     const MonotonicMs now_ms) noexcept {
  if (env.body_size < kChunkHeaderSize || env.body[0] != 1 || env.body[1] != 1) {
    ++stats_.kind_rejects;
    return;
  }
  ByteReader reader(ByteView{env.body.data() + 2, env.body_size - 2});
  std::uint32_t transaction = 0;
  std::uint16_t offset = 0;
  std::uint16_t total = 0;
  if (!reader.read_u32(transaction) || !reader.read_u16(offset) ||
      !reader.read_u16(total)) {
    ++stats_.kind_rejects;
    return;
  }
  const std::size_t data_size = reader.remaining();
  // Assembly slots are granted only after the cheap cookie/transaction check:
  // a live candidate or our outbound exchange must own this nonce (06 §3.2).
  const bool known_txn =
      find_candidate(source, env.transaction_nonce) != nullptr ||
      (outbound_.active && mac_equal(outbound_.peer_mac, source) &&
       nonce_equal(outbound_.our_nonce, env.transaction_nonce));
  if (!known_txn || total == 0 ||
      total > discovery_const::kBootstrapObjectMax ||
      static_cast<std::uint32_t>(offset) + data_size > total ||
      data_size > kChunkDataMax) {
    ++stats_.kind_rejects;
    return;
  }
  RxAssembly* slot =
      assemblies_.find([&](const RxAssembly& a) {
        return a.active && mac_equal(a.mac, source) &&
               a.transaction == transaction;
      });
  if (slot == nullptr) {
    slot = assemblies_.allocate();
    if (slot == nullptr) {
      ++stats_.peer_capacity;
      reject_event("PEER_CAPACITY", kInvalidNodeId);
      return;
    }
    slot->active = true;
    slot->mac = source;
    slot->transaction = transaction;
    slot->total = total;
    slot->received = 0;
    slot->expires_at_ms = now_ms + config_.candidate_ttl_ms;
  }
  if (slot->total != total || offset != slot->received) {
    // In-order reassembly only; report progress via the control reply.
    send_chunk_reply(source, env.transaction_nonce, env.claimed_node, transaction,
                     slot->received, kChunkStatusIncomplete, now_ms);
    return;
  }
  std::memcpy(slot->data.data() + offset, env.body.data() + kChunkHeaderSize,
              data_size);
  slot->received += static_cast<std::uint16_t>(data_size);
  send_chunk_reply(source, env.transaction_nonce, env.claimed_node, transaction,
                   slot->received, kChunkStatusOk, now_ms);
  if (slot->received < slot->total) return;

  // Re-check the completed object's inner type on the freshest context:
  // RLD1 fragments may carry BootstrapAuth only (06 §3.2).
  autonomy::BootstrapAuthBody inner{};
  const bool ok = autonomy::bootstrap_auth_decode(
                      ByteView{slot->data.data(), slot->total}, inner)
                      .ok();
  assemblies_.release(slot);
  if (!ok) {
    ++stats_.kind_rejects;
    reject_event("KIND_REJECT", kInvalidNodeId);
    return;
  }
  // Completed-inner dispatch re-checks admission on the freshest context —
  // the outer chunk's CoarseAllow was not authorization for the inner frame.
  if (!gate(AdmissionCarrier::Rld1, AdmissionDirection::Rx,
            FrameType::BootstrapAuth, /*transaction_alive=*/true, now_ms)) {
    ++stats_.kind_rejects;
    return;
  }
  switch (inner.phase) {
    case autonomy::AuthPhase::Prove:
      handle_prove(source, env, inner, now_ms);
      break;
    case autonomy::AuthPhase::Confirm:
      handle_confirm(source, env, inner, now_ms);
      break;
    case autonomy::AuthPhase::Finish:
      handle_finish(source, env, inner, now_ms);
      break;
    default:
      ++stats_.kind_rejects;
      break;
  }
}

// --- RX: authenticated Wire lane --------------------------------------------------

void NeighborDiscovery::on_wire_rx(const MacAddress& source, const FrameType type,
                                   const ByteView payload,
                                   const MonotonicMs now_ms) noexcept {
  if (!started_) return;
  // Unknown MAC on the Wire carrier is rejected outright — lane membership is
  // not evidence; the record lookup below is the gate (06 §3.1).
  Neighbor* neighbor = find_neighbor(source);
  if (neighbor == nullptr || neighbor->binding == kInvalidBindingId ||
      neighbor->phase == NeighborPhase::Conflict ||
      neighbor->phase == NeighborPhase::Revoked) {
    ++stats_.kind_rejects;
    reject_event("WIRE_NEIGHBOR_REJECT", neighbor != nullptr ? neighbor->node
                                                    : kInvalidNodeId);
    reject_event("KIND_REJECT", kInvalidNodeId);
    return;
  }
  if (!gate(AdmissionCarrier::WireV1, AdmissionDirection::Rx, type,
            /*transaction_alive=*/true, now_ms)) {
    ++stats_.kind_rejects;
    reject_event("WIRE_GATE_REJECT", neighbor->node);
    return;
  }
  switch (type) {
    case FrameType::NeighborProbe:
      handle_probe(*neighbor, payload, now_ms);
      break;
    case FrameType::NeighborResult:
      handle_probe_result(*neighbor, payload, now_ms);
      break;
    default:
      // DATA and every other member type additionally require REACHABLE —
      // a BOUND or pending record never admits them (06 §4.3).
      if (neighbor->phase != NeighborPhase::Reachable ||
          !neighbor->peer_member_verified ||
          membership_.state() != MembershipState::Member) {
        ++stats_.kind_rejects;
        reject_event("DATA_REJECT", neighbor->node);
      }
      break;
  }
}

void NeighborDiscovery::handle_probe(Neighbor& neighbor, const ByteView payload,
                                     const MonotonicMs now_ms) noexcept {
  autonomy::NeighborProbePayload probe{};
  if (!autonomy::neighbor_probe_decode(payload, probe)) {
    ++stats_.kind_rejects;
    reject_event("PROBE_DECODE_REJECT", neighbor.node);
    return;
  }
  // Binding generations advance independently on each side's re-auth: a
  // peer at a NEWER epoch proves its record moved forward — adopt that
  // epoch so a re-announced peer can never wedge the exchange (02 §9).
  // A strictly-older generation is stale-epoch evidence and still rejects.
  if (probe.binding_generation.value > neighbor.generation.value) {
    neighbor.generation = probe.binding_generation;
  } else if (probe.binding_generation.value < neighbor.generation.value) {
    ++stats_.kind_rejects;
    reject_event("PROBE_GEN_MISMATCH", neighbor.node);
    return;
  }
  // An authenticated probe is liveness evidence: refresh the lease, re-arm
  // the bounded Stale re-probe budget and reply.
  neighbor.last_confirmed_ms = now_ms;
  neighbor.stale_reprobes = 0;
  neighbor.lease_expires_at_ms = now_ms + config_.awake_lease_ms;

  autonomy::NeighborResultPayload result{};
  result.binding_generation = neighbor.generation;
  result.probe_sequence = probe.probe_sequence;
  result.result = autonomy::NeighborResultCode::Reachable;
  result.lease_granted_ms = config_.awake_lease_ms;
  autonomy::EncodedPayload encoded{};
  if (autonomy::neighbor_result_encode(result, encoded).ok()) {
    const Status sent = port_.send_wire(neighbor.binding, neighbor.mac,
                                        FrameType::NeighborResult,
                                        encoded.view());
    if (!sent) {
      ++stats_.send_failures;
    }
  }
  // If we were stale/bound and have no outstanding probe of our own, start
  // one — bidirectional confirmation still requires our own Result.
  if (neighbor.probe_outstanding == 0 &&
      (neighbor.phase == NeighborPhase::Bound ||
       neighbor.phase == NeighborPhase::Stale)) {
    send_probe(neighbor, now_ms);
  }
}

void NeighborDiscovery::handle_probe_result(Neighbor& neighbor,
                                            const ByteView payload,
                                            const MonotonicMs now_ms) noexcept {
  autonomy::NeighborResultPayload result{};
  if (!autonomy::neighbor_result_decode(payload, result)) {
    ++stats_.kind_rejects;
    reject_event("RESULT_DECODE_REJECT", neighbor.node);
    return;
  }
  if (result.probe_sequence == 0 ||
      result.probe_sequence != neighbor.probe_outstanding) {
    ++stats_.kind_rejects;
    reject_event("RESULT_SEQ_MISMATCH", neighbor.node);
    return;  // late/foreign results never promote a dead exchange
  }
  // Same forward-adoption as handle_probe: the responder's newer epoch is
  // binding progress; an older one is stale evidence (02 §9).
  if (result.binding_generation.value > neighbor.generation.value) {
    neighbor.generation = result.binding_generation;
  } else if (result.binding_generation.value < neighbor.generation.value) {
    ++stats_.kind_rejects;
    reject_event("RESULT_GEN_MISMATCH", neighbor.node);
    return;
  }
  neighbor.probe_outstanding = 0;
  neighbor.stale_reprobes = 0;   // verified RX re-arms the budget
  if (result.result != autonomy::NeighborResultCode::Reachable) {
    return;  // NotListening/Leaving: keep current phase, lease still runs
  }
  // Receiving the Result to OUR probe confirms both directions (02 §3).
  const NeighborPhase before = neighbor.phase;
  if (before == NeighborPhase::Bound || before == NeighborPhase::Stale ||
      before == NeighborPhase::Reachable) {
    neighbor.phase = NeighborPhase::Reachable;
    neighbor.last_confirmed_ms = now_ms;
    const std::uint32_t granted = result.lease_granted_ms == 0
                                      ? config_.awake_lease_ms
                                      : result.lease_granted_ms;
    neighbor.lease_expires_at_ms =
        now_ms + (granted < config_.awake_lease_ms ? granted
                                                  : config_.awake_lease_ms);
    if (before != NeighborPhase::Reachable) {
      event("REACHABLE", neighbor.node);
    }
  }
}

// --- Exchange completion: membership + binding ------------------------------------

void NeighborDiscovery::complete_exchange(
    const MacAddress& peer_mac, const NodeId peer_node,
    const std::uint32_t peer_capability,
    const std::array<std::uint8_t, 16>& requester_nonce,
    const std::array<std::uint8_t, 16>& responder_nonce, const AuthTag& closing_tag,
    const ScopeExchangeContext& exchange,
    const bool we_are_requester, const MonotonicMs now_ms) noexcept {
  AuthTranscript transcript{};
  transcript.requester_node = we_are_requester ? config_.node : peer_node;
  transcript.responder_node = we_are_requester ? peer_node : config_.node;
  transcript.requester_mac = we_are_requester ? config_.mac : peer_mac;
  transcript.responder_mac = we_are_requester ? peer_mac : config_.mac;
  transcript.network = config_.network;
  transcript.requester_nonce = requester_nonce;
  transcript.responder_nonce = responder_nonce;
  transcript.requester_capability =
      we_are_requester ? config_.capability_bits : peer_capability;
  transcript.responder_capability =
      we_are_requester ? peer_capability : config_.capability_bits;
  transcript.scope_binding = exchange.binding();

  AuthenticatedPeerProof proof;
  if (!authenticator_.issue_proof(transcript, config_.node, closing_tag, proof) ||
      !proof.valid() || proof.peer() != peer_node ||
      !mac_equal(proof.mac(), peer_mac)) {
    ++stats_.auth_tag_rejects;
    reject_event("AUTH_FAILED", peer_node);
    return;
  }
  ++stats_.auths_completed;

  // Device auth is not membership: advance local membership and verify the
  // peer's member evidence before any binding exists (06 §2.2).
  membership_.complete_authentication(hooks_, config_.node, config_.network);
  const bool peer_member =
      hooks_.known_member(peer_node, config_.network);

  // MAC change / device swap (02 §8): never overwrite a live binding for the
  // same NodeId with a new address. A still-alive old binding means the two
  // radios cannot be distinguished -> CONFLICT quarantine.
  if (Neighbor* existing = find_neighbor(peer_node)) {
    if (!mac_equal(existing->mac, peer_mac)) {
      if (existing->phase != NeighborPhase::Revoked &&
          existing->phase != NeighborPhase::Conflict &&
          now_ms < existing->lease_expires_at_ms) {
        // Reuse an existing quarantine record for the same (node, MAC):
        // rotating source MACs must not be able to fill the table with
        // duplicate conflicts.
        Neighbor* conflict = neighbors_.find([&](const Neighbor& n) {
          return n.phase == NeighborPhase::Conflict && n.node == peer_node &&
                 mac_equal(n.mac, peer_mac);
        });
        if (conflict == nullptr) {
          conflict = neighbors_.allocate();
          if (conflict != nullptr) {
            conflict->node = peer_node;
            conflict->mac = peer_mac;
            conflict->phase = NeighborPhase::Conflict;
          }
        }
        if (conflict != nullptr) {
          conflict->lease_expires_at_ms = now_ms + config_.candidate_ttl_ms;
        }
        ++stats_.conflicts;
        reject_event("BINDING_CONFLICT", peer_node);
        return;
      }
      // Old binding is dead: revoke it and re-bind at a new generation so
      // stale TX/ACK/feedback can never attach to the new binding (02 §8).
      existing->phase = NeighborPhase::Revoked;
      if (existing->regular_held) {
        existing->regular_held = false;
        --regular_used_;
      }
      if (existing->pinned) {
        existing->pinned = false;
        --pins_used_;
      }
    }
  }

  if (Neighbor* same = find_neighbor(peer_mac); same != nullptr) {
    if (same->phase == NeighborPhase::Conflict ||
        same->phase == NeighborPhase::Revoked) {
      // Quarantined/revoked records are not re-authenticated implicitly —
      // only forget_peer() re-opens the address. The block is surfaced:
      // the requester sees a completed exchange, so silence here would
      // leave "authenticated but unresponsive" undiagnosable (issue #43).
      reject_event(same->phase == NeighborPhase::Revoked
                       ? "REVOKED_REBIND_BLOCKED"
                       : "CONFLICT_REBIND_BLOCKED",
                   peer_node);
      return;
    }
    if (same->node != peer_node) {
      // A different identity on an address we already bound: reject rather
      // than hand the address to a second NodeId.
      ++stats_.conflicts;
      reject_event("BINDING_CONFLICT", peer_node);
      return;
    }
    // Re-authentication of the same (node, MAC): bump the binding generation
    // and refresh the lease instead of creating a duplicate.
    if (!bump_binding_generation(same->generation)) {
      // Generation space exhausted: the old binding stays untouched rather
      // than wrapping onto a stale handle (Q117-13).
      ++stats_.binding_generation_exhausted;
      reject_event("BINDING_GENERATION_EXHAUSTED", peer_node);
      return;
    }
    same->probe_outstanding = 0;
    same->stale_reprobes = 0;
    if (membership_.state() == MembershipState::Member && peer_member) {
      same->peer_member_verified = true;
      same->phase = NeighborPhase::Bound;
      same->last_confirmed_ms = now_ms;
      same->lease_expires_at_ms = now_ms + config_.awake_lease_ms;
      send_probe(*same, now_ms);
    } else {
      same->phase = NeighborPhase::ApprovalPending;
      same->lease_expires_at_ms = now_ms + config_.candidate_ttl_ms;
      event("MEMBERSHIP_PENDING", peer_node);
    }
    return;
  }

  Neighbor* neighbor = neighbors_.allocate();
  if (neighbor == nullptr) {
    // Bounded logical table: try to retire a stale unpinned record first.
    Neighbor* victim = neighbors_.find([&](const Neighbor& n) {
      return !n.pinned && (n.phase == NeighborPhase::Stale ||
                           n.phase == NeighborPhase::Conflict ||
                           n.phase == NeighborPhase::Revoked);
    });
    if (victim != nullptr) {
      if (victim->regular_held) --regular_used_;
      neighbors_.release(victim);
      neighbor = neighbors_.allocate();
    }
    if (neighbor == nullptr) {
      ++stats_.peer_capacity;
      reject_event("PEER_CAPACITY", peer_node);
      return;
    }
  }
  neighbor->binding = kInvalidBindingId;
  neighbor->generation = BindingGeneration{1};
  neighbor->node = peer_node;
  neighbor->mac = peer_mac;
  neighbor->peer_member_verified = peer_member;
  neighbor->pinned = false;
  neighbor->regular_held = false;
  neighbor->last_confirmed_ms = now_ms;
  neighbor->probe_outstanding = 0;
  neighbor->stale_reprobes = 0;
  neighbor->next_reprobe_ms = 0;

  if (membership_.state() == MembershipState::Member && peer_member) {
    // Both memberships verified -> mint the binding and start the
    // bidirectional probe that gates REACHABLE (02 §3).
    if (!mint_binding_id(next_binding_id_, neighbor->binding)) {
      // Id space exhausted: no binding exists, so drop the record instead
      // of binding under a reused id (Q117-13).
      neighbors_.release(neighbor);
      ++stats_.binding_id_exhausted;
      reject_event("BINDING_ID_EXHAUSTED", peer_node);
      cancel_competing(peer_mac, peer_node);
      return;
    }
    neighbor->phase = NeighborPhase::Bound;
    neighbor->lease_expires_at_ms = now_ms + config_.awake_lease_ms;
    if (!reserve_regular(*neighbor)) {
      // Logical binding exists; the driver-slot shortage is reported, never
      // silently absorbed (02 §7).
      ++stats_.peer_capacity;
      reject_event("PEER_CAPACITY", peer_node);
    }
    event("BOUND", peer_node);
    send_probe(*neighbor, now_ms);
  } else {
    // Bounded hold pending local commit or peer member evidence; an absent
    // authority never auto-approves (02 §5, 06 §5).
    neighbor->phase = NeighborPhase::ApprovalPending;
    neighbor->lease_expires_at_ms = now_ms + config_.candidate_ttl_ms;
    event("MEMBERSHIP_PENDING", peer_node);
  }
  cancel_competing(peer_mac, peer_node);
}

void NeighborDiscovery::cancel_competing(const MacAddress& mac,
                                         const NodeId node) noexcept {
  // One exchange converged: expire leftover candidates/exchanges for the
  // same peer so a stale response can never attach to the new binding.
  Candidate* leftover = candidates_.find(
      [&](const Candidate& c) { return mac_equal(c.mac, mac); });
  if (leftover != nullptr) release_candidate(*leftover);
  if (outbound_.active && mac_equal(outbound_.peer_mac, mac)) {
    outbound_ = Outbound{};
    release_transient();
  }
  (void)node;
}

void NeighborDiscovery::fail_outbound(const MonotonicMs now_ms,
                                      const char* reason) noexcept {
  (void)now_ms;
  reject_event(reason, outbound_.peer_node);
  outbound_ = Outbound{};
  release_transient();
  relax_membership();
}

void NeighborDiscovery::relax_membership() noexcept {
  if (membership_.state() != MembershipState::Authenticating) return;
  if (outbound_.active &&
      outbound_.stage != OutboundStage::AwaitingOffers) {
    return;  // our own exchange is still live
  }
  const bool responder_auth = candidates_.find([](const Candidate& c) {
    return c.phase == NeighborPhase::Authenticating;
  }) != nullptr;
  if (!responder_auth) membership_.abort_authentication();
}

// --- TX helpers -------------------------------------------------------------------

bool NeighborDiscovery::gate(const AdmissionCarrier carrier,
                             const AdmissionDirection direction,
                             const FrameType type, const bool transaction_alive,
                             const MonotonicMs now_ms) noexcept {
  AdmissionContext context{};
  context.local_membership = membership_.state();
  context.direction = direction;
  context.carrier = carrier;
  context.role = local_role();
  context.transaction_alive = transaction_alive;
  context.deadline_ms = now_ms;
  context.feature_capable = true;
  context.budget_remaining = 1;
  const AdmissionDecision decision = admission_decision(context, type);
  if (decision.verdict != AdmissionVerdict::CoarseAllow) return false;
  // Bootstrap kinds beyond Discover/Offer require a live transaction — the
  // coarse screen alone is never the permit (06 §4.3).
  if (type == FrameType::BootstrapAuth || type == FrameType::BootstrapChunk ||
      type == FrameType::BootstrapReply || type == FrameType::MembershipQuery ||
      type == FrameType::MembershipResult) {
    return transaction_alive;
  }
  return true;
}

AdmissionRole NeighborDiscovery::local_role() const noexcept {
  switch (membership_.state()) {
    case MembershipState::Member:
      return AdmissionRole::EstablishedPeer;
    case MembershipState::AuthorizedPendingCommit:
    case MembershipState::Authenticating:
    case MembershipState::Discovering:
    case MembershipState::Unprovisioned:
      return AdmissionRole::JoiningNode;
    case MembershipState::Revoked:
      return AdmissionRole::JoiningNode;
  }
  return AdmissionRole::JoiningNode;
}

Status NeighborDiscovery::emit_rld1(const MacAddress& dest, const FrameType kind,
                                    const std::array<std::uint8_t, 16>& nonce,
                                    const NodeId claimed, const ByteView body,
                                    const MonotonicMs now_ms,
                                    ScopeDigest* frame_digest) noexcept {
  if (!gate(AdmissionCarrier::Rld1, AdmissionDirection::Tx, kind,
            /*transaction_alive=*/true, now_ms)) {
    ++stats_.rate_limited;
    return Status::error(StatusCode::AuthorizationFailed, "TX gated");
  }
  autonomy::Rld1Envelope env{};
  env.kind = kind;
  env.network_hint = config_.network_hint;
  env.claimed_node = claimed;
  env.transaction_nonce = nonce;
  env.capability_bits = config_.capability_bits;
  if (body.size > env.body.size()) {
    return Status::error(StatusCode::NoCapacity, "RLD1 body");
  }
  if (body.size > 0) {
    std::memcpy(env.body.data(), body.data, body.size);
  }
  env.body_size = body.size;
  autonomy::Rld1Encoded encoded{};
  Status status = autonomy::rld1_encode(env, encoded);
  if (!status) return status;
  status = port_.send_rld1(dest, encoded.view());
  if (!status) {
    ++stats_.send_failures;
  }
  if (status.ok() && frame_digest != nullptr) {
    // The auth transcript binds the exact emitted frame bytes (02 §5.2).
    sha256(encoded.view(), *frame_digest);
  }
  return status;
}

Status NeighborDiscovery::emit_auth_body(
    const MacAddress& dest, const std::array<std::uint8_t, 16>& nonce,
    const NodeId claimed, const autonomy::BootstrapAuthBody& body,
    const MonotonicMs now_ms) noexcept {
  autonomy::EncodedPayload encoded{};
  Status status = autonomy::bootstrap_auth_encode(body, encoded);
  if (!status) return status;
  if (encoded.size <= autonomy::kRld1MaxBody) {
    return emit_rld1(dest, FrameType::BootstrapAuth, nonce, claimed,
                     encoded.view(), now_ms);
  }
  // Bounded fragmentation (02 §4): RLD1 chunks carry BootstrapAuth only.
  if (encoded.size > discovery_const::kBootstrapObjectMax) {
    return Status::error(StatusCode::NoCapacity, "auth body exceeds object limit");
  }
  std::uint32_t transaction = 0;
  for (int i = 0; i < 4; ++i) {
    transaction = (transaction << 8U) | nonce[i];
  }
  const std::uint16_t total = static_cast<std::uint16_t>(encoded.size);
  std::uint16_t offset = 0;
  while (offset < total) {
    const std::size_t piece = std::min<std::size_t>(
        static_cast<std::size_t>(total - offset), kChunkDataMax);
    std::array<std::uint8_t, kChunkHeaderSize + kChunkDataMax> chunk{};
    ByteWriter writer(MutableByteView{chunk.data(), chunk.size()});
    if (!writer.write_u8(1) || !writer.write_u8(1) ||
        !writer.write_u32(transaction) || !writer.write_u16(offset) ||
        !writer.write_u16(total) ||
        !writer.write_bytes(ByteView{encoded.bytes.data() + offset, piece})) {
      return Status::error(StatusCode::InternalError, "chunk encode");
    }
    status = emit_rld1(dest, FrameType::BootstrapChunk, nonce, claimed,
                       ByteView{chunk.data(), writer.size()}, now_ms);
    if (!status) return status;
    offset += static_cast<std::uint16_t>(piece);
  }
  return Status::success();
}

Status NeighborDiscovery::send_chunk_reply(
    const MacAddress& dest, const std::array<std::uint8_t, 16>& nonce,
    const NodeId claimed, const std::uint32_t transaction,
    const std::uint16_t received, const std::uint8_t status,
    const MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kReplyBodySize> body{};
  ByteWriter writer(MutableByteView{body.data(), body.size()});
  if (!writer.write_u8(1) || !writer.write_u8(1) ||
      !writer.write_u32(transaction) || !writer.write_u16(received) ||
      !writer.write_u8(status)) {
    return Status::error(StatusCode::InternalError, "reply encode");
  }
  return emit_rld1(dest, FrameType::BootstrapReply, nonce, claimed,
                   ByteView{body.data(), writer.size()}, now_ms);
}

Status NeighborDiscovery::send_discover(const MonotonicMs now_ms) noexcept {
  const bool scoped = scoped_attempt(now_ms);
  if (!scoped && scope_mode_scoped(config_.scope_mode)) {
    if (!legacy_permitted(now_ms)) {
      // Required (or Optional outside the window) with an unusable scope:
      // stop the exchange — never silently downgrade to legacy (02 §2.2).
      ++scope_stats_.key_unavailable;
      return Status::error(StatusCode::AuthProfileUnavailable,
                           "scope unusable; discovery stopped");
    }
    // OptionalMigration: the single bounded legacy fallback attempt is
    // consumed here — a distinct attempt, never retried as legacy.
    outbound_.legacy_attempted = true;
    ++scope_stats_.legacy_used;
  }
  if (!scoped) {
    // A legacy attempt binds a distinct transcript: scoped=false and zeroed
    // class/generation with the real legacy frame digest (02 §2.4).
    outbound_.exchange = ScopeExchangeContext{};
    return emit_rld1(discovery_const::kBroadcastMac, FrameType::Discover,
                     outbound_.our_nonce, config_.node, ByteView{nullptr, 0},
                     now_ms, &outbound_.exchange.discover_digest);
  }
  return send_scoped_discover(now_ms);
}

Status NeighborDiscovery::send_scoped_discover(const MonotonicMs now_ms) noexcept {
  DiscoveryScopeProvider& provider = *config_.scope_provider;
  std::uint32_t generation = 0;
  if (!provider.current_generation(config_.scope, generation)) {
    ++scope_stats_.key_unavailable;
    return Status::error(StatusCode::AuthProfileUnavailable,
                         "scope key unavailable");
  }
  std::uint32_t hint = 0;
  Status status = scope_hint(provider, config_.scope, generation,
                             config_.scope_class, config_.network, hint);
  if (!status) return status;
  // Encode once with a zero tag so the MAC input can cover the actual
  // header44 + body prefix8; then patch the tag in and re-encode (02 §2.4).
  endpoint::Rld1DiscoverBodyV2 body{};
  body.scope_class = config_.scope_class;
  body.generation = generation;
  endpoint::EncodedScopeBody encoded_body{};
  status = endpoint::scope_discover_body_encode(body, encoded_body);
  if (!status) return status;
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Discover;
  env.network_hint = hint;
  env.claimed_node = config_.node;
  env.transaction_nonce = outbound_.our_nonce;
  env.capability_bits = config_.capability_bits;
  std::memcpy(env.body.data(), encoded_body.bytes.data(), encoded_body.size);
  env.body_size = encoded_body.size;
  autonomy::Rld1Encoded pass{};
  status = autonomy::rld1_encode(env, pass);
  if (!status) return status;
  ByteBuffer<endpoint::kScopeDiscoverMacInputSize> input{};
  status = endpoint::scope_discover_mac_input(
      config_.network, config_.mac, discovery_const::kBroadcastMac,
      ByteView{pass.bytes.data(), autonomy::kRld1HeaderSize},
      ByteView{pass.bytes.data() + autonomy::kRld1HeaderSize, 8}, input);
  if (!status) return status;
  ScopeTag tag{};
  status = provider.scope_tag(config_.scope, generation, input.view(), tag);
  if (!status) {
    ++scope_stats_.key_unavailable;
    return status;
  }
  std::memcpy(env.body.data() + 8, tag.data(), tag.size());
  autonomy::Rld1Encoded encoded{};
  status = autonomy::rld1_encode(env, encoded);
  if (!status) return status;
  if (!gate(AdmissionCarrier::Rld1, AdmissionDirection::Tx, FrameType::Discover,
            /*transaction_alive=*/true, now_ms)) {
    ++stats_.rate_limited;
    return Status::error(StatusCode::AuthorizationFailed, "TX gated");
  }
  status = port_.send_rld1(discovery_const::kBroadcastMac, encoded.view());
  if (status.ok()) {
    outbound_.exchange.scoped = true;
    outbound_.exchange.scope_class = config_.scope_class;
    outbound_.exchange.generation = generation;
    outbound_.exchange.offer_digest = ScopeDigest{};
    sha256(encoded.view(), outbound_.exchange.discover_digest);
  } else {
    ++stats_.send_failures;
  }
  return status;
}

Status NeighborDiscovery::send_offer(Candidate& candidate,
                                     const MonotonicMs now_ms) noexcept {
  if (candidate.exchange.scoped) {
    return send_scoped_offer(candidate, now_ms);
  }
  std::array<std::uint8_t, kOfferBodySize> body{};
  ByteWriter writer(MutableByteView{body.data(), body.size()});
  const std::uint32_t density = recent_discovers(now_ms);
  const std::uint8_t hint = density > 255 ? 255 : static_cast<std::uint8_t>(density);
  if (!writer.write_u8(1) || !writer.write_u8(hint) || !writer.write_u16(0) ||
      !writer.write_bytes(ByteView{candidate.cookie.data(), 16}) ||
      !writer.write_bytes(ByteView{candidate.our_nonce.data(), 16})) {
    return Status::error(StatusCode::InternalError, "offer encode");
  }
  const Status status =
      emit_rld1(candidate.mac, FrameType::Offer, candidate.txn_nonce,
                config_.node, ByteView{body.data(), writer.size()}, now_ms,
                &candidate.exchange.offer_digest);
  if (status.ok()) {
    candidate.offer_pending = false;
    ++stats_.offers_tx;
    // The OFFER commits us to a bounded mutual exchange: a non-member
    // responder becomes Authenticating so the incoming PROVE passes the
    // coarse allowlist; a Member stays Member (06 §4.2).
    membership_.begin_authentication();
  }
  return status;
}

Status NeighborDiscovery::send_scoped_offer(Candidate& candidate,
                                            const MonotonicMs now_ms) noexcept {
  DiscoveryScopeProvider& provider = *config_.scope_provider;
  const std::uint32_t generation = candidate.exchange.generation;
  const endpoint::ScopeClass scope_class = candidate.exchange.scope_class;
  if (!provider.accepted_generation(config_.scope, generation, now_ms)) {
    // The pinned generation left its acceptance window — drop the candidate
    // rather than emit a frame a conforming peer must reject.
    ++scope_stats_.key_unavailable;
    release_candidate(candidate);
    relax_membership();
    return Status::error(StatusCode::AuthProfileUnavailable,
                         "scope generation expired");
  }
  std::uint32_t hint = 0;
  Status status =
      scope_hint(provider, config_.scope, generation, scope_class,
                 config_.network, hint);
  if (!status) return status;
  endpoint::Rld1OfferBodyV2 body{};
  const std::uint32_t density = recent_discovers(now_ms);
  body.density = density > 255 ? 255 : static_cast<std::uint8_t>(density);
  body.cookie = candidate.cookie;
  body.responder_nonce = candidate.our_nonce;
  body.scope_class = scope_class;
  body.generation = generation;
  endpoint::EncodedScopeBody encoded_body{};
  status = endpoint::scope_offer_body_encode(body, encoded_body);
  if (!status) return status;
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Offer;
  env.network_hint = hint;
  env.claimed_node = config_.node;
  env.transaction_nonce = candidate.txn_nonce;
  env.capability_bits = config_.capability_bits;
  std::memcpy(env.body.data(), encoded_body.bytes.data(), encoded_body.size);
  env.body_size = encoded_body.size;
  autonomy::Rld1Encoded pass{};
  status = autonomy::rld1_encode(env, pass);
  if (!status) return status;
  // OFFER tag input binds the requester's observed MAC, our observed MAC and
  // the exact accepted DISCOVER digest (02 §2.4).
  ByteBuffer<endpoint::kScopeOfferMacInputSize> input{};
  status = endpoint::scope_offer_mac_input(
      config_.network, candidate.mac, config_.mac,
      ByteView{candidate.exchange.discover_digest.data(),
               candidate.exchange.discover_digest.size()},
      ByteView{pass.bytes.data(), autonomy::kRld1HeaderSize},
      ByteView{pass.bytes.data() + autonomy::kRld1HeaderSize, 44}, input);
  if (!status) return status;
  ScopeTag tag{};
  status = provider.scope_tag(config_.scope, generation, input.view(), tag);
  if (!status) {
    // The pinned generation can no longer authenticate this exchange —
    // drop the candidate rather than emit a frame that cannot verify.
    ++scope_stats_.key_unavailable;
    release_candidate(candidate);
    relax_membership();
    return status;
  }
  std::memcpy(env.body.data() + 44, tag.data(), tag.size());
  autonomy::Rld1Encoded encoded{};
  status = autonomy::rld1_encode(env, encoded);
  if (!status) return status;
  if (!gate(AdmissionCarrier::Rld1, AdmissionDirection::Tx, FrameType::Offer,
            /*transaction_alive=*/true, now_ms)) {
    ++stats_.rate_limited;
    return Status::error(StatusCode::AuthorizationFailed, "TX gated");
  }
  status = port_.send_rld1(candidate.mac, encoded.view());
  if (status.ok()) {
    sha256(encoded.view(), candidate.exchange.offer_digest);
    candidate.offer_pending = false;
    ++stats_.offers_tx;
    membership_.begin_authentication();
  } else {
    ++stats_.send_failures;
  }
  return status;
}

Status NeighborDiscovery::send_prove(const MonotonicMs now_ms) noexcept {
  autonomy::BootstrapAuthBody auth{};
  auth.phase = autonomy::AuthPhase::Prove;
  auth.step_index = 0;
  const AuthTranscript transcript{config_.node, outbound_.peer_node, config_.mac,
                                  outbound_.peer_mac, config_.network,
                                  outbound_.our_nonce, outbound_.peer_nonce,
                                  config_.capability_bits,
                                  outbound_.peer_capability,
                                  outbound_.exchange.binding()};
  AuthTag tag{};
  Status status = authenticator_.attest(autonomy::AuthPhase::Prove, transcript, tag);
  if (!status) return status;
  std::memcpy(auth.body.data(), outbound_.cookie_echo.data(), 16);
  std::memcpy(auth.body.data() + 16, tag.data(), 16);
  auth.body_size = kProveBodySize;
  // Transition BEFORE emitting: a synchronous transport can deliver the
  // peer's CONFIRM inside send_rld1, and it must find AwaitingConfirm.
  outbound_.stage = OutboundStage::AwaitingConfirm;
  outbound_.stage_deadline_ms = now_ms + config_.auth_timeout_ms;
  status = emit_auth_body(outbound_.peer_mac, outbound_.our_nonce, config_.node,
                          auth, now_ms);
  if (!status) {
    outbound_.stage = OutboundStage::ProvePending;
    return status;
  }
  next_handshake_ms_ = now_ms + config_.handshake_start_interval_ms;
  return status;
}

Status NeighborDiscovery::send_confirm(Candidate& candidate,
                                       const MonotonicMs now_ms) noexcept {
  autonomy::BootstrapAuthBody auth{};
  auth.phase = autonomy::AuthPhase::Confirm;
  auth.step_index = 0;
  const AuthTranscript transcript{candidate.claimed_node, config_.node,
                                  candidate.mac, config_.mac, config_.network,
                                  candidate.txn_nonce, candidate.our_nonce,
                                  candidate.peer_capability,
                                  config_.capability_bits,
                                  candidate.exchange.binding()};
  AuthTag tag{};
  Status status =
      authenticator_.attest(autonomy::AuthPhase::Confirm, transcript, tag);
  if (!status) return status;
  std::memcpy(auth.body.data(), tag.data(), 16);
  auth.body_size = kAuthTagBodySize;
  return emit_auth_body(candidate.mac, candidate.txn_nonce, config_.node, auth,
                        now_ms);
}

Status NeighborDiscovery::send_finish(const MonotonicMs now_ms) noexcept {
  autonomy::BootstrapAuthBody auth{};
  auth.phase = autonomy::AuthPhase::Finish;
  auth.step_index = 0;
  const AuthTranscript transcript{config_.node, outbound_.peer_node, config_.mac,
                                  outbound_.peer_mac, config_.network,
                                  outbound_.our_nonce, outbound_.peer_nonce,
                                  config_.capability_bits,
                                  outbound_.peer_capability,
                                  outbound_.exchange.binding()};
  AuthTag tag{};
  Status status =
      authenticator_.attest(autonomy::AuthPhase::Finish, transcript, tag);
  if (!status) return status;
  std::memcpy(auth.body.data(), tag.data(), 16);
  auth.body_size = kAuthTagBodySize;
  return emit_auth_body(outbound_.peer_mac, outbound_.our_nonce, config_.node,
                        auth, now_ms);
}

Status NeighborDiscovery::send_probe(Neighbor& neighbor,
                                     const MonotonicMs now_ms) noexcept {
  if (neighbor.binding == kInvalidBindingId) {
    return Status::error(StatusCode::InvalidState, "no binding");
  }
  autonomy::NeighborProbePayload probe{};
  probe.binding_generation = neighbor.generation;
  probe.probe_sequence = next_probe_sequence_++;
  probe.sent_ms = now_ms;
  probe.requested_lease_ms = config_.awake_lease_ms;
  autonomy::EncodedPayload encoded{};
  Status status = autonomy::neighbor_probe_encode(probe, encoded);
  if (!status) return status;
  // Record the outstanding probe BEFORE emitting: a synchronous transport can
  // deliver the peer's Result inside send_wire, and it must match.
  neighbor.probe_outstanding = probe.probe_sequence;
  neighbor.probe_deadline_ms = now_ms + config_.probe_timeout_ms;
  status = port_.send_wire(neighbor.binding, neighbor.mac,
                           FrameType::NeighborProbe, encoded.view());
  if (status.ok()) {
    ++stats_.probes_tx;
  } else {
    neighbor.probe_outstanding = 0;
    ++stats_.send_failures;
  }
  return status;
}

// --- poll -------------------------------------------------------------------------

void NeighborDiscovery::poll(const MonotonicMs now_ms) noexcept {
  if (!started_) return;

  // Scope-MAC verification is budgeted to kScopeMacsPerPoll per Owner poll
  // so a wrong-scope burst can never starve DATA/ACK work (02 §2.5).
  drain_scope_pending(now_ms);

  // Due OFFERs and parked candidates retrying for a transient slot.
  std::array<Candidate*, discovery_const::kCandidateCapacity> due{};
  std::size_t due_count = 0;
  candidates_.for_each([&](Candidate& c) {
    if (now_ms >= c.expires_at_ms || (c.offer_pending && now_ms >= c.offer_due_ms) ||
        (c.phase == NeighborPhase::Candidate && !c.transient_held &&
         !c.offer_pending)) {
      due[due_count++] = &c;
    }
  });
  for (std::size_t i = 0; i < due_count; ++i) {
    Candidate& c = *due[i];
    if (now_ms >= c.expires_at_ms) {
      release_candidate(c);
      continue;
    }
    if (!c.transient_held) {
      if (!reserve_transient()) continue;  // still parked
      c.transient_held = true;
      std::uint64_t slot = 0;
      if (!entropy_.fill(MutableByteView{c.our_nonce.data(), 16}).ok() ||
          !authenticator_
               .cookie_seal(CookieMaterial{c.mac, c.txn_nonce, config_.network,
                                           now_ms / config_.cookie_bucket_ms,
                                           config_.node, c.claimed_node},
                                c.cookie)
               .ok() ||
          !next_u64(slot)) {
        release_candidate(c);
        continue;
      }
      c.offer_due_ms =
          now_ms + (slot % discovery_const::kOfferSlots) *
                       discovery_const::kOfferSlotMs;
      c.offer_pending = true;
    }
    if (c.offer_pending && now_ms >= c.offer_due_ms) {
      send_offer(c, now_ms);
    }
  }
  relax_membership();

  // Outbound exchange driver.
  if (outbound_.active) {
    if (outbound_.stage == OutboundStage::ProvePending &&
        outbound_.have_offer && now_ms >= next_handshake_ms_) {
      send_prove(now_ms);
    }
    if (outbound_.stage != OutboundStage::Idle &&
        now_ms > outbound_.stage_deadline_ms) {
      // Exchange attempt failed: fresh attempt nonce, and the next retry
      // waits a uniform [backoff_min_ms, backoff_initial_max_ms] draw that
      // doubles toward backoff_max_ms (radio.md §7/§13).
      ++outbound_.attempts;
      if (outbound_.attempts >= config_.max_attempts) {
        fail_outbound(now_ms, "DISCOVERY_FAILED");
      } else if (outbound_.retry_backoff_ms == 0 &&
                 !draw_retry_backoff(outbound_.retry_backoff_ms)) {
        fail_outbound(now_ms, "DISCOVERY_FAILED");
      } else {
        const std::uint32_t backoff = outbound_.retry_backoff_ms;
        const std::uint64_t next_wait =
            static_cast<std::uint64_t>(backoff) * 2;
        outbound_.retry_backoff_ms =
            next_wait > config_.backoff_max_ms
                ? config_.backoff_max_ms
                : static_cast<std::uint32_t>(next_wait);
        outbound_.have_offer = false;
        outbound_.stage = OutboundStage::AwaitingOffers;
        // Deadline covers the backoff wait PLUS the new offer window, so the
        // retry has room to run before the next timeout check.
        outbound_.discover_due_ms = now_ms + backoff;
        outbound_.stage_deadline_ms =
            outbound_.discover_due_ms + config_.offer_window_ms +
            config_.auth_timeout_ms;
      }
    }
    if (outbound_.stage == OutboundStage::AwaitingOffers &&
        !outbound_.have_offer && outbound_.discover_due_ms != 0 &&
        now_ms >= outbound_.discover_due_ms) {
      // Retry round: fresh nonce per attempt (02 §6).
      if (entropy_.fill(
              MutableByteView{outbound_.our_nonce.data(), 16})
              .ok()) {
        outbound_.discover_due_ms = 0;
        outbound_.stage_deadline_ms = now_ms + config_.offer_window_ms;
        send_discover(now_ms);
      } else {
        fail_outbound(now_ms, "DISCOVERY_FAILED");
      }
    }
  }

  // Neighbor lease lifecycle: expiry demotes to Stale (the record survives —
  // binding/security state is never silently deleted, 02 §9).
  std::array<Neighbor*, discovery_const::kNeighborCapacity> pending{};
  std::size_t pending_count = 0;
  neighbors_.for_each([&](Neighbor& n) { pending[pending_count++] = &n; });
  for (std::size_t i = 0; i < pending_count; ++i) {
    Neighbor& n = *pending[i];
    switch (n.phase) {
      case NeighborPhase::ApprovalPending:
        if (now_ms >= n.lease_expires_at_ms) {
          if (n.regular_held) --regular_used_;
          neighbors_.release(&n);
          break;
        }
        // Re-check on the freshest context before promotion (06 §2.2).
        if (membership_.state() == MembershipState::Member &&
            hooks_.known_member(n.node, config_.network)) {
          n.peer_member_verified = true;
          if (!mint_binding_id(next_binding_id_, n.binding)) {
            // Id space exhausted: stay ApprovalPending until the lease
            // lapses rather than binding under a reused id (Q117-13).
            ++stats_.binding_id_exhausted;
            reject_event("BINDING_ID_EXHAUSTED", n.node);
            break;
          }
          n.phase = NeighborPhase::Bound;
          n.lease_expires_at_ms = now_ms + config_.awake_lease_ms;
          n.last_confirmed_ms = now_ms;
          if (!reserve_regular(n)) {
            ++stats_.peer_capacity;
            reject_event("PEER_CAPACITY", n.node);
          }
          event("BOUND", n.node);
          send_probe(n, now_ms);
        }
        break;
      case NeighborPhase::Suspended:
        if (now_ms >= n.suspended_until_ms) {
          n.phase = NeighborPhase::Stale;
          n.stale_reprobes = 0;
          n.next_reprobe_ms = now_ms;
          ++stats_.stale_expirations;
          event("STALE", n.node);
        }
        break;
      case NeighborPhase::Conflict:
        // The quarantine is a bounded hold, not a permanent tombstone: once
        // its lease lapses the record is released so a genuine device swap
        // can re-bind, and the slot cannot be pinned forever by replayed
        // conflicts.
        if (now_ms >= n.lease_expires_at_ms) {
          neighbors_.release(&n);
        }
        break;
      case NeighborPhase::Bound:
      case NeighborPhase::Reachable:
        if (n.probe_outstanding != 0 && now_ms > n.probe_deadline_ms) {
          n.probe_outstanding = 0;
        }
        if (now_ms >= n.lease_expires_at_ms) {
          n.phase = NeighborPhase::Stale;
          n.stale_reprobes = 0;
          n.next_reprobe_ms = now_ms;
          ++stats_.stale_expirations;
          event("STALE", n.node);
          break;
        }
        // A BOUND peer retries its probe until a Result confirms both
        // directions; REACHABLE refreshes at the idle target (02 §9).
        if (n.probe_outstanding == 0 &&
            (n.phase == NeighborPhase::Bound ||
             now_ms - n.last_confirmed_ms >= config_.idle_refresh_ms)) {
          send_probe(n, now_ms);
        }
        break;
      case NeighborPhase::Stale:
        // "Stale keeps resolving" (02 §9): a lapsed lease must not sever the
        // re-join lane — channel migration can strand a whole neighbor set
        // on the old channel with no way back (issue #40). A bounded
        // unicast re-probe at stale_reprobe_ms cadence re-confirms a peer
        // that is merely quiet; after stale_reprobe_attempts emitted probes
        // the record parks dormant until fresh RX evidence re-arms it, so a
        // permanently partitioned peer can never become a background storm
        // (02 §6). A refused emission (transport busy) keeps the budget and
        // defers to the next cadence tick instead of spinning per-poll.
        if (n.probe_outstanding != 0 && now_ms > n.probe_deadline_ms) {
          n.probe_outstanding = 0;
        }
        if (n.probe_outstanding == 0 &&
            n.stale_reprobes < config_.stale_reprobe_attempts &&
            now_ms >= n.next_reprobe_ms) {
          if (send_probe(n, now_ms).ok()) {
            ++n.stale_reprobes;
          }
          n.next_reprobe_ms = now_ms + config_.stale_reprobe_ms;
        }
        break;
      default:
        break;
    }
  }

  // Stranded-node re-discovery (issue #40, 04 §9.2): when every usable edge
  // is gone but resolvable Stale records survive, only a fresh RLD1
  // exchange re-opens the lane — a migration helper dwells on the old
  // channel on a plan clock this node cannot observe, so it re-announces
  // on a bounded backoff until an edge returns. The unicast re-probe above
  // gets the first probe_timeout window before broadcasts start; the
  // schedule then doubles backoff_base -> backoff_max and holds there.
  // begin_discovery already refuses safely while an exchange or responder
  // authentication is in flight.
  {
    bool any_bound = false;
    bool any_stale = false;
    neighbors_.for_each([&](const Neighbor& n) {
      any_bound = any_bound || n.phase == NeighborPhase::Bound ||
                  n.phase == NeighborPhase::Reachable;
      any_stale = any_stale || n.phase == NeighborPhase::Stale;
    });
    if (any_bound || !any_stale ||
        membership_.state() == MembershipState::Revoked) {
      next_rediscovery_ms_ = 0;
      rediscovery_backoff_ms_ = 0;
    } else if (rediscovery_backoff_ms_ == 0) {
      // Newly stranded: arm after one probe window, then ramp from a uniform
      // [backoff_min_ms, backoff_initial_max_ms] draw to backoff_max_ms
      // (radio.md §7/§13). Entropy failure falls back to the floor — the
      // wait stays bounded either way.
      if (!draw_retry_backoff(rediscovery_backoff_ms_)) {
        rediscovery_backoff_ms_ = config_.backoff_min_ms;
      }
      next_rediscovery_ms_ = now_ms + config_.probe_timeout_ms;
    } else if (!outbound_.active && now_ms >= next_rediscovery_ms_) {
      if (begin_discovery(now_ms).ok()) {
        event("REDISCOVERY", kInvalidNodeId);
      }
      const std::uint64_t step =
          static_cast<std::uint64_t>(rediscovery_backoff_ms_) * 2;
      rediscovery_backoff_ms_ = step > config_.backoff_max_ms
                                    ? config_.backoff_max_ms
                                    : static_cast<std::uint32_t>(step);
      next_rediscovery_ms_ = now_ms + rediscovery_backoff_ms_;
    }
  }

  // Retry a pending local commit (e.g. a dev approval hook that became
  // available); the bounded ApprovalPending records above then promote.
  membership_.retry_commit(hooks_, config_.node, config_.network);

  // Expire reassembly slots.
  std::array<RxAssembly*, discovery_const::kReassemblySlots> expired{};
  std::size_t expired_count = 0;
  assemblies_.for_each(
      [&](RxAssembly& a) { expired[expired_count++] = &a; });
  for (std::size_t i = 0; i < expired_count; ++i) {
    if (now_ms >= expired[i]->expires_at_ms) assemblies_.release(expired[i]);
  }
}

// --- Inspection / owner controls -----------------------------------------------------

bool NeighborDiscovery::phase_of(const MacAddress& mac,
                                 NeighborPhase& out) const noexcept {
  const Neighbor* neighbor = find_neighbor(mac);
  if (neighbor != nullptr) {
    out = neighbor->phase;
    return true;
  }
  const Candidate* candidate = candidates_.find(
      [&](const Candidate& c) { return mac_equal(c.mac, mac); });
  if (candidate != nullptr) {
    out = candidate->phase;
    return true;
  }
  return false;
}

bool NeighborDiscovery::phase_of(const NodeId peer, NeighborPhase& out) const noexcept {
  const Neighbor* neighbor = find_neighbor(peer);
  if (neighbor != nullptr) {
    out = neighbor->phase;
    return true;
  }
  const Candidate* candidate = candidates_.find(
      [&](const Candidate& c) { return c.claimed_node == peer; });
  if (candidate != nullptr) {
    out = candidate->phase;
    return true;
  }
  return false;
}

bool NeighborDiscovery::data_permitted(const MacAddress& mac) const noexcept {
  const Neighbor* neighbor = find_neighbor(mac);
  return neighbor != nullptr && neighbor->phase == NeighborPhase::Reachable &&
         neighbor->peer_member_verified &&
         membership_.state() == MembershipState::Member;
}

bool NeighborDiscovery::data_permitted(const NodeId peer) const noexcept {
  const Neighbor* neighbor = find_neighbor(peer);
  return neighbor != nullptr && neighbor->phase == NeighborPhase::Reachable &&
         neighbor->peer_member_verified &&
         membership_.state() == MembershipState::Member;
}

// Phases where the verified MAC↔NodeId mapping may still resolve. Conflict
// records are quarantined (the mapping is disputed) and Revoked bindings
// are dead — neither may attribute traffic or sends. Stale keeps resolving
// precisely so re-confirmation probes can find the peer; Suspended is a
// planned absence, not a broken binding.
bool resolvable_phase(const NeighborPhase phase) noexcept {
  return phase != NeighborPhase::Conflict && phase != NeighborPhase::Revoked;
}

bool NeighborDiscovery::binding_of(const NodeId peer, BindingId& out) const noexcept {
  const Neighbor* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || neighbor->binding == kInvalidBindingId ||
      !resolvable_phase(neighbor->phase)) {
    return false;
  }
  out = neighbor->binding;
  return true;
}

bool NeighborDiscovery::binding_generation_of(
    const NodeId peer, BindingGeneration& out) const noexcept {
  const Neighbor* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || neighbor->binding == kInvalidBindingId ||
      !resolvable_phase(neighbor->phase)) {
    return false;
  }
  out = neighbor->generation;
  return true;
}

bool NeighborDiscovery::node_of(const MacAddress& mac, NodeId& out) const noexcept {
  const Neighbor* neighbor = find_neighbor(mac);
  if (neighbor == nullptr || neighbor->node == kInvalidNodeId ||
      !resolvable_phase(neighbor->phase)) {
    return false;
  }
  out = neighbor->node;
  return true;
}

Status NeighborDiscovery::revoke_peer(const NodeId peer) noexcept {
  Neighbor* neighbor = find_neighbor(peer);
  if (neighbor == nullptr) {
    return Status::error(StatusCode::NotFound, "peer not bound");
  }
  neighbor->phase = NeighborPhase::Revoked;
  neighbor->probe_outstanding = 0;
  if (neighbor->regular_held) {
    neighbor->regular_held = false;
    --regular_used_;
  }
  if (neighbor->pinned) {
    neighbor->pinned = false;
    --pins_used_;
  }
  event("REVOKED", peer);
  return Status::success();
}

Status NeighborDiscovery::reauth_revoked(const NodeId peer,
                                            const MonotonicMs now_ms) noexcept {
  constexpr MonotonicMs kReauthCooldownMs = 60000;
  bool revoked = false;
  bool cooling = false;
  neighbors_.for_each([&](const Neighbor& n) {
    if (n.node != peer || n.phase != NeighborPhase::Revoked) return;
    revoked = true;
    // Underflow-safe: an attempt is recent only when now is at/past it
    // and inside the minute.
    if (now_ms >= n.last_reauth_attempt_ms &&
        now_ms - n.last_reauth_attempt_ms < kReauthCooldownMs) {
      cooling = true;
    }
  });
  if (!revoked) return Status::error(StatusCode::NotFound, "peer not revoked");
  if (cooling) return Status::error(StatusCode::Busy, "reauth cooldown");
  neighbors_.for_each([&](Neighbor& n) {
    if (n.node == peer && n.phase == NeighborPhase::Revoked) n.last_reauth_attempt_ms = now_ms;
  });
  event("REAUTH_ADMITTED", peer);
  return Status::success();
}

Status NeighborDiscovery::forget_peer(const NodeId peer) noexcept {
  const auto dead = [&](const Neighbor& n) {
    return n.node == peer && (n.phase == NeighborPhase::Revoked ||
                              n.phase == NeighborPhase::Conflict);
  };
  if (find_neighbor(peer) == nullptr) {
    return Status::error(StatusCode::NotFound, "peer not bound");
  }
  std::size_t forgotten = 0;
  // A node may hold several dead records (a revoked old MAC plus conflict
  // quarantines); each release happens outside the pool scan.
  while (Neighbor* record = neighbors_.find(dead)) {
    // Revocation already returned regular/pin accounting; a Conflict
    // quarantine never held any.
    if (record->regular_held) --regular_used_;
    if (record->pinned) --pins_used_;
    (void)neighbors_.release(record);
    ++forgotten;
  }
  if (forgotten == 0) {
    return Status::error(StatusCode::InvalidState, "peer binding is live");
  }
  event("FORGOTTEN", peer);
  return Status::success();
}

Status NeighborDiscovery::suspend_peer(const NodeId peer,
                                       const MonotonicMs until_ms) noexcept {
  Neighbor* neighbor = find_neighbor(peer);
  if (neighbor == nullptr) {
    return Status::error(StatusCode::NotFound, "peer not bound");
  }
  if (neighbor->phase == NeighborPhase::Bound ||
      neighbor->phase == NeighborPhase::Reachable) {
    neighbor->phase = NeighborPhase::Suspended;
    neighbor->suspended_until_ms = until_ms;
  }
  return Status::success();
}

Status NeighborDiscovery::pin_peer(const NodeId peer) noexcept {
  Neighbor* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || neighbor->binding == kInvalidBindingId) {
    return Status::error(StatusCode::NotFound, "peer not bound");
  }
  if (neighbor->pinned) return Status::success();
  if (pins_used_ >= discovery_const::kRegularPinsMax) {
    ++stats_.peer_capacity;
    reject_event("PEER_CAPACITY", peer);
    return Status::error(StatusCode::PeerCapacity, "regular pin budget");
  }
  neighbor->pinned = true;
  ++pins_used_;
  return Status::success();
}

void NeighborDiscovery::reevaluate(const MonotonicMs now_ms) noexcept {
  // Fresh context re-check only — poll() performs the actual promotion so a
  // late caller can never resurrect a cancelled transaction inline.
  poll(now_ms);
}

// --- internals -------------------------------------------------------------------

// Scope RX lanes are usable only while the provider can verify tags AND the
// authenticator can fold the resulting scope_binding into the transcript —
// otherwise an accepted scoped exchange could never be proven (02 §5.2).
bool NeighborDiscovery::scope_rx_usable() const noexcept {
  return config_.scope_provider != nullptr &&
         config_.scope != kInvalidScopeRef &&
         authenticator_.binds_scope();
}

bool NeighborDiscovery::scope_tx_usable() noexcept {
  if (!scope_rx_usable()) return false;
  std::uint32_t generation = 0;
  return config_.scope_provider->current_generation(config_.scope, generation);
}

// Whether the next outbound DISCOVER attempt is a scoped v2 frame.
bool NeighborDiscovery::scoped_attempt(const MonotonicMs now_ms) noexcept {
  if (!scope_mode_scoped(config_.scope_mode) || !scope_tx_usable()) {
    return false;
  }
  if (config_.scope_mode == ScopeMode::Required) return true;
  // OptionalMigration: scoped first and after the single legacy fallback;
  // the fallback occupies exactly one retry (02 §2.2).
  return outbound_.attempts == 0 || outbound_.legacy_attempted ||
         !legacy_permitted(now_ms);
}

bool NeighborDiscovery::legacy_permitted(const MonotonicMs now_ms) const noexcept {
  switch (config_.scope_mode) {
    case ScopeMode::Off:
    case ScopeMode::OpenLegacy:
      return true;
    case ScopeMode::OptionalMigration:
      // Owner-proven deadline (0 = unprovable -> Required-like), capped at
      // the 24h contract maximum measured from start (02 §2.2).
      return migration_deadline_ms_ != 0 && now_ms < migration_deadline_ms_;
    case ScopeMode::Required:
      return false;
  }
  return false;
}

// (class,generation,network)->hint cache: keeps step-3 hint checks MAC-free
// after the first computation per key (02 §2.4).
bool NeighborDiscovery::scoped_hint_for(const endpoint::ScopeClass scope_class,
                                        const std::uint32_t generation,
                                        std::uint32_t& out) noexcept {
  for (const HintEntry& entry : hint_cache_) {
    if (entry.valid && entry.scope_class == scope_class &&
        entry.generation == generation) {
      out = entry.hint;
      return true;
    }
  }
  if (config_.scope_provider == nullptr) return false;
  std::uint32_t hint = 0;
  if (!scope_hint(*config_.scope_provider, config_.scope, generation,
                  scope_class, config_.network, hint)) {
    return false;
  }
  HintEntry& slot = hint_cache_[hint_cursor_ % hint_cache_.size()];
  ++hint_cursor_;
  slot.valid = true;
  slot.scope_class = scope_class;
  slot.generation = generation;
  slot.hint = hint;
  out = hint;
  return true;
}

void NeighborDiscovery::record_discover(const MonotonicMs now_ms) noexcept {
  discover_times_[discover_cursor_ % discover_times_.size()] = now_ms;
  ++discover_cursor_;
}

NeighborDiscovery::Candidate* NeighborDiscovery::find_candidate(
    const MacAddress& mac, const std::array<std::uint8_t, 16>& nonce) noexcept {
  return candidates_.find([&](const Candidate& c) {
    return mac_equal(c.mac, mac) && nonce_equal(c.txn_nonce, nonce);
  });
}

NeighborDiscovery::Neighbor* NeighborDiscovery::find_neighbor(
    const MacAddress& mac) noexcept {
  return neighbors_.find(
      [&](const Neighbor& n) { return mac_equal(n.mac, mac); });
}

NeighborDiscovery::Neighbor* NeighborDiscovery::find_neighbor(
    const NodeId node) noexcept {
  return neighbors_.find([&](const Neighbor& n) { return n.node == node; });
}

const NeighborDiscovery::Neighbor* NeighborDiscovery::find_neighbor(
    const MacAddress& mac) const noexcept {
  return neighbors_.find(
      [&](const Neighbor& n) { return mac_equal(n.mac, mac); });
}

const NeighborDiscovery::Neighbor* NeighborDiscovery::find_neighbor(
    const NodeId node) const noexcept {
  return neighbors_.find([&](const Neighbor& n) { return n.node == node; });
}

bool NeighborDiscovery::reserve_transient() noexcept {
  if (transient_used_ >= discovery_const::kTransientPeerSlots) return false;
  ++transient_used_;
  return true;
}

void NeighborDiscovery::release_transient() noexcept {
  if (transient_used_ > 0) --transient_used_;
}

bool NeighborDiscovery::reserve_regular(Neighbor& neighbor) noexcept {
  if (neighbor.regular_held) return true;
  if (regular_used_ >= discovery_const::kRegularPeerSlots) return false;
  neighbor.regular_held = true;
  ++regular_used_;
  return true;
}

void NeighborDiscovery::release_candidate(Candidate& candidate) noexcept {
  if (candidate.transient_held) release_transient();
  candidates_.release(&candidate);
}

bool NeighborDiscovery::next_u64(std::uint64_t& out) noexcept {
  out = 0;
  // A failed draw reports failure — callers fail CLOSED (suppress the
  // offer/lottery) rather than collapsing every draw onto value 0, which
  // would silently disable density suppression and slot spreading exactly
  // when a broken RNG is most likely (mass simultaneous boot).
  return entropy_.fill(MutableByteView{reinterpret_cast<std::uint8_t*>(&out), 8})
      .ok();
}

bool NeighborDiscovery::draw_retry_backoff(std::uint32_t& out_ms) noexcept {
  std::uint64_t roll = 0;
  if (!next_u64(roll)) {
    out_ms = 0;
    return false;
  }
  const std::uint64_t span =
      static_cast<std::uint64_t>(config_.backoff_initial_max_ms) -
      config_.backoff_min_ms + 1;
  out_ms = config_.backoff_min_ms +
           static_cast<std::uint32_t>(roll % span);
  // The cap is a hard ceiling on the wait, not just the doubling limit:
  // a cap below the initial draw range must still bound the first retry.
  if (out_ms > config_.backoff_max_ms) out_ms = config_.backoff_max_ms;
  return true;
}

std::uint32_t NeighborDiscovery::recent_discovers(
    const MonotonicMs now_ms) const noexcept {
  std::uint32_t count = 0;
  for (const MonotonicMs t : discover_times_) {
    if (t != kNoDiscover && now_ms >= t && now_ms - t <= kWindowMs) ++count;
  }
  return count;
}

}  // namespace routeloom
