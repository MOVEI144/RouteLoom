// SDK v1 zero-touch join FSM (sdkv1_joiner.hpp; design P3-4; plan P3-4
// PR 3). See the header for the Owner contract and the re-entrancy rules.

#include "routeloom/sdkv1_joiner.hpp"

#include <cstring>
#include <limits>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {

namespace {

constexpr std::uint64_t kAttemptOverallMs = 15000;  // m1..m4 exchange bound (§4.1)
constexpr std::uint64_t kReconcileWaitMs = 5000;    // storage re-read spacing
constexpr std::uint8_t kReconcileMaxRetries = 3;    // consecutive read failures
constexpr std::uint32_t kDecisionMinMs = 500;       // m2 decision timeout clamp
constexpr std::uint32_t kDecisionMaxMs = 5000;
constexpr std::uint32_t kHintRetryMaxMs = 600000;  // unauthenticated hint cap

ZtJoinerConfig make_link_config(const JoinerConfig& config) noexcept {
  ZtJoinerConfig link{};
  link.node = config.node;
  link.mac = config.mac;
  return link;
}

// Scope guard for the re-entrancy contract (§3.1): while set, every
// mutating entry returns Busy and changes nothing.
class InCall {
 public:
  explicit InCall(bool& flag) noexcept : flag_(flag) { flag_ = true; }
  ~InCall() { flag_ = false; }

 private:
  bool& flag_;
};

bool channels_valid(const JoinerConfig& config) noexcept {
  if (config.scan_channel_count == 0 || config.scan_channel_count > kJoinScanChannelMax) {
    return false;
  }
  for (std::uint8_t i = 0; i < config.scan_channel_count; ++i) {
    const std::uint8_t ch = config.scan_channels[i];
    if (ch == 0 || ch > 14) return false;
    for (std::uint8_t j = 0; j < i; ++j) {
      if (config.scan_channels[j] == ch) return false;
    }
  }
  return true;
}

bool role_valid(const JoinerConfig& config) noexcept {
  if (config.requested_role == 0 || (config.requested_role & ~kMemberRoleMask) != 0) return false;
  // Every requested relay/gateway bit needs the matching capability bit.
  const std::uint32_t need =
      static_cast<std::uint32_t>(config.requested_role) & ~kMemberRoleEndpoint;
  return (need & ~config.capability) == 0;
}

}  // namespace

// --- Lifetime -------------------------------------------------------------------------------

Joiner::Joiner(const JoinerConfig& config, IdentityStore& identity, SiteStore& site,
               EntropySource& entropy, ZtRld1Port& port, JoinObserver& observer,
               const edhoc::AeadCcm* aead) noexcept
    : config_(config),
      identity_(identity),
      site_(site),
      entropy_(entropy),
      observer_(observer),
      aead_(aead),
      link_observer_(*this),
      link_(make_link_config(config), port, entropy_, link_observer_) {}

Joiner::~Joiner() {
  teardown_attempt();
  wipe_expectation();
  secure_clear(retained_fingerprint_);
  secure_clear(msg_);
}

MonotonicMs Joiner::sat_add(const MonotonicMs a, const std::uint64_t delta) noexcept {
  return delta > ~MonotonicMs{0} - a ? ~MonotonicMs{0} : a + delta;
}

void Joiner::sat_inc(std::uint32_t& counter) noexcept {
  if (counter < std::numeric_limits<std::uint32_t>::max()) ++counter;
}

bool Joiner::step_expected(const JoinState state, const JoinAuthPhase phase,
                           const std::uint8_t step) noexcept {
  if (state != JoinState::WaitM2 && state != JoinState::WaitM4) return false;
  if (phase == JoinAuthPhase::RelayStatus) return true;  // hints ride any wait
  if (phase != JoinAuthPhase::EdhocMessage) return false;  // no Resume in P3-4
  return state == JoinState::WaitM2 ? (step == 2 || step == 5) : (step == 4 || step == 5);
}

bool Joiner::clock_ok(const MonotonicMs now) noexcept {
  if (clock_uncertain_) return false;
  if (now >= last_now_) {
    last_now_ = now;
    return true;
  }
  // Regression: a new clock domain. Park the attempt, keep every hold (the
  // tables never see this `now`), and latch until stop() reopens.
  if (attempt_.active) {
    candidates_.apply_outcome(attempt_, JoinAttemptOutcome::Pending, 0, last_now_, entropy_);
    attempt_ = JoinAttempt{};
    attempt_record_ = nullptr;
  }
  teardown_attempt();
  clear_mailbox();
  hint_valid_ = false;
  link_failed_ = false;
  channel_waiting_ = false;
  clock_uncertain_ = true;
  last_error_ = StatusCode::ClockUncertain;
  set_state(JoinState::Stopped);
  return false;
}

// --- Small helpers --------------------------------------------------------------------------

void Joiner::set_projection(const MembershipState next) noexcept {
  if (projection_ == next) return;
  projection_ = next;
  link_.set_membership(next);
}

void Joiner::set_state(const JoinState next) noexcept {
  if (state_ == next) return;
  event_.from = state_;
  event_.to = next;
  state_ = next;
  switch (next) {
    case JoinState::BootCheck:
      set_projection(MembershipState::Unprovisioned);
      break;
    case JoinState::ScanTune:
    case JoinState::WaitChannel:
    case JoinState::ScanWindow:
    case JoinState::Select:
    case JoinState::RefreshWindow:
    case JoinState::Backoff:
      set_projection(MembershipState::Discovering);
      break;
    case JoinState::SendM1:
    case JoinState::WaitM2:
    case JoinState::SendM3:
    case JoinState::WaitM4:
    case JoinState::Decided:
      set_projection(MembershipState::Authenticating);
      break;
    case JoinState::Commit:
      set_projection(MembershipState::AuthorizedPendingCommit);
      break;
    case JoinState::Reconcile:
      set_projection(reconcile_authorized_ ? MembershipState::AuthorizedPendingCommit
                                           : MembershipState::Discovering);
      break;
    case JoinState::Ready:
      set_projection(MembershipState::Member);
      break;
    case JoinState::Removed:
      set_projection(MembershipState::Revoked);
      break;
    case JoinState::Stopped:
    case JoinState::RecoveryRequired:
      break;  // keep the last projection; no traffic flows either way
  }
  emit(JoinEventKind::StateChanged);
}

void Joiner::emit(const JoinEventKind kind) noexcept {
  event_.kind = kind;
  event_.counters = counters_;
  observer_.on_event(event_);
}

bool Joiner::emit_action(const JoinAction& action) noexcept {
  if (action_pending_) return false;
  action_ = action;
  action_pending_ = true;
  return true;
}

void Joiner::clear_mailbox() noexcept {
  mailbox_valid_ = false;
  msg_len_ = 0;
  mailbox_phase_ = JoinAuthPhase::EdhocMessage;
  mailbox_step_ = 0;
}

void Joiner::teardown_attempt() noexcept {
  link_.close();
  handshake_.end();
  secure_clear(msg_);
  clear_mailbox();
  hint_valid_ = false;
  link_failed_ = false;
  decided_valid_ = false;
  decided_ = JoinDecided{};
  attempt_record_ = nullptr;
  attempt_ = JoinAttempt{};
  attempt_key_ = JoinCandidateKey{};
  attempt_proxy_ = MacAddress{};
  attempt_hops_ = kZtHopsUnknown;
  refresh_offer_ = ZtOfferView{};
  refresh_offer_valid_ = false;
  refresh_rssi_ = 0;
  t2_deadline_ = 0;
  t4_deadline_ = 0;
  overall_deadline_ = 0;
}

void Joiner::wipe_expectation() noexcept {
  secure_clear(commit_expect_.fingerprint);
  commit_expect_ = CommitExpectation{};
}

bool Joiner::matches_expectation(const SiteRecord& site) noexcept {
  if (!commit_expect_.valid) return false;
  Digest256 actual{};
  if (!site_.fingerprint(site, actual)) return false;
  return actual == commit_expect_.fingerprint;
}

bool Joiner::recovery_match(const JoinCandidateKey& key) const noexcept {
  if (key.site_hint != recovery_key_.site_hint ||
      key.network_low32 != recovery_key_.network_low32) {
    return false;
  }
  // An unknown org (0) matches any anchor's window; the m2 site binding is
  // the real check against hint collisions.
  return recovery_key_.org_hint == 0 || key.org_hint == recovery_key_.org_hint;
}

// --- Link observer: table, mailbox and flags only -----------------------------------
// Runs inside link_.on_rld1_rx()/link_.poll(), i.e. inside our own guarded
// entry: it must never call back into the Joiner or the link.

void Joiner::LinkObserver::on_offer(const ZtOfferView& offer) noexcept {
  JoinState state = owner_.state_;
  if (state != JoinState::ScanWindow && state != JoinState::RefreshWindow) return;
  JoinCandidateKey key{};
  key.org_hint = offer.body.org_hint;
  key.site_hint = offer.body.site_hint;
  key.network_low32 = offer.network_low32;
  JoinProxyObservation proxy{};
  proxy.mac = offer.proxy_mac;
  proxy.node = offer.proxy;
  proxy.channel = owner_.channel_;
  proxy.rssi = owner_.last_rx_.rssi;
  proxy.authority_hops = offer.body.authority_hops;
  proxy.authority_reachable = (offer.body.flags & kZtOfferAuthorityReachable) != 0;
  proxy.proxy_busy = (offer.body.flags & kZtOfferProxyBusy) != 0;
  const JoinObserve observed =
      owner_.candidates_.observe(key, proxy, owner_.last_now_);
  if (observed == JoinObserve::Rejected) Joiner::sat_inc(owner_.counters_.rx_dropped);
  if (state != JoinState::RefreshWindow || owner_.refresh_phase_ != RefreshPhase::Collect ||
      !(key == owner_.attempt_key_)) {
    return;
  }
  // The refresh window keeps the single best OFFER for the selected site.
  const ZtOfferView& best = owner_.refresh_offer_;
  bool take = !owner_.refresh_offer_valid_;
  if (!take) {
    const bool reachable = proxy.authority_reachable && !proxy.proxy_busy;
    const bool best_reachable = (best.body.flags & kZtOfferAuthorityReachable) != 0 &&
                                (best.body.flags & kZtOfferProxyBusy) == 0;
    if (reachable != best_reachable) {
      take = reachable;
    } else if (proxy.authority_hops != best.body.authority_hops) {
      take = proxy.authority_hops < best.body.authority_hops;
    } else {
      take = proxy.rssi > owner_.refresh_rssi_;
    }
  }
  if (take) {
    owner_.refresh_offer_ = offer;
    owner_.refresh_rssi_ = proxy.rssi;
    owner_.refresh_offer_valid_ = true;
  }
}

void Joiner::LinkObserver::on_message(const JoinAuthPhase phase, const std::uint8_t step,
                                     const ByteView message) noexcept {
  if (!Joiner::step_expected(owner_.state_, phase, step)) return;
  if (owner_.mailbox_valid_) return;  // never overwrite a staged message
  if (message.size > owner_.msg_.size()) {
    Joiner::sat_inc(owner_.counters_.rx_dropped);
    return;
  }
  std::memcpy(owner_.msg_.data(), message.data, message.size);
  owner_.msg_len_ = message.size;
  owner_.mailbox_phase_ = phase;
  owner_.mailbox_step_ = step;
  owner_.mailbox_valid_ = true;
}

void Joiner::LinkObserver::on_relay_status(const RelayStatusCode status,
                                          const std::uint32_t retry_after_ms) noexcept {
  if (owner_.state_ != JoinState::WaitM2 && owner_.state_ != JoinState::WaitM4) return;
  owner_.hint_valid_ = true;
  owner_.hint_status_ = status;
  owner_.hint_retry_ms_ =
      retry_after_ms > kHintRetryMaxMs ? kHintRetryMaxMs : retry_after_ms;
}

void Joiner::LinkObserver::on_link_failure(const char* reason) noexcept {
  (void)reason;
  if (owner_.state_ != JoinState::WaitM2 && owner_.state_ != JoinState::WaitM4) return;
  owner_.link_failed_ = true;
}

// --- Public API -------------------------------------------------------------------------------

Status Joiner::start(const JoinBootInput& boot, const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "joiner re-entry");
  InCall guard(in_call_);
  if (state_ != JoinState::Stopped) {
    return Status::error(StatusCode::InvalidState, "joiner already started");
  }
  if (!boot.prepared) return Status::error(StatusCode::InvalidArgument, "joiner boot unprepared");
  if (boot.mode != JoinBootMode::Normal &&
      boot.mode != JoinBootMode::VerifyExistingMembership) {
    return Status::error(StatusCode::InvalidArgument, "joiner boot mode");
  }
  if ((boot.removal_watermark_site_id == 0) !=
          (boot.removal_watermark_generation == 0) ||
      boot.removal_watermark_site_id == std::numeric_limits<std::uint64_t>::max()) {
    return Status::error(StatusCode::InvalidArgument, "joiner removal watermark");
  }
  if (!channels_valid(config_) || !role_valid(config_)) {
    return Status::error(StatusCode::InvalidArgument, "joiner config");
  }
  if (!clock_ok(now)) return Status::error(StatusCode::ClockUncertain, "joiner clock");
  // A new run drops every pending output; the radio stays where it is and
  // the candidate holds survive a soft restart.
  teardown_attempt();
  clear_mailbox();
  wipe_expectation();
  action_ = JoinAction{};
  action_pending_ = false;
  channel_waiting_ = false;
  tune_is_refresh_ = false;
  recovery_only_ = false;
  verify_existing_ = boot.mode == JoinBootMode::VerifyExistingMembership;
  recovery_key_ = JoinCandidateKey{};
  recovery_site_id_ = 0;
  evidence_valid_ = false;
  retained_floor_ = 0;
  secure_clear(retained_fingerprint_);
  retained_fingerprint_valid_ = false;
  reconcile_retries_ = 0;
  reconcile_deadline_ = 0;
  backoff_deadline_ = 0;
  decided_valid_ = false;
  boot_witness_ = boot.boot_witness;
  removal_watermark_site_id_ = boot.removal_watermark_site_id;
  removal_watermark_generation_ = boot.removal_watermark_generation;
  last_error_ = StatusCode::Ok;
  set_state(JoinState::BootCheck);
  return Status::success();
}

Status Joiner::stop(const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "joiner re-entry");
  InCall guard(in_call_);
  if (clock_uncertain_ || now < last_now_) {
    // A new clock domain is a reboot: the candidate table (whose own latch
    // tripped or would trip on the old times) is rebuilt empty and time
    // restarts. Holds do not survive a domain change, as after a reboot.
    teardown_attempt();
    clear_mailbox();
    wipe_expectation();
    action_ = JoinAction{};
    action_pending_ = false;
    channel_waiting_ = false;
    candidates_.~JoinCandidates();
    new (&candidates_) JoinCandidates();
    last_now_ = 0;
    clock_uncertain_ = false;
    last_m1_ms_ = 0;
    boot_witness_ = 0;
    retained_floor_ = 0;
    secure_clear(retained_fingerprint_);
    retained_fingerprint_valid_ = false;
    recovery_only_ = false;
    evidence_valid_ = false;
    last_error_ = StatusCode::Ok;
    set_state(JoinState::Stopped);
    return Status::success();
  }
  last_now_ = now;
  // Quietly unbind the selected record: stopping is not an outcome.
  if (attempt_.active) {
    candidates_.apply_outcome(attempt_, JoinAttemptOutcome::Pending, 0, now, entropy_);
  }
  teardown_attempt();
  clear_mailbox();
  wipe_expectation();
  action_ = JoinAction{};
  action_pending_ = false;
  if (channel_token_ < std::numeric_limits<std::uint32_t>::max()) ++channel_token_;
  channel_waiting_ = false;
  tune_is_refresh_ = false;
  recovery_only_ = false;
  evidence_valid_ = false;
  retained_floor_ = 0;
  secure_clear(retained_fingerprint_);
  retained_fingerprint_valid_ = false;
  reconcile_retries_ = 0;
  set_state(JoinState::Stopped);
  return Status::success();
}

Status Joiner::poll(const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "joiner re-entry");
  InCall guard(in_call_);
  if (!clock_ok(now)) return Status::error(StatusCode::ClockUncertain, "joiner clock");
  link_.poll(now);  // chunk retransmits and assembly expiry; callbacks only set flags
  return drive(now);
}

Status Joiner::on_rld1_rx(const JoinRxMeta& meta, const ByteView frame,
                          const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "joiner re-entry");
  InCall guard(in_call_);
  if (!clock_ok(now)) return Status::error(StatusCode::ClockUncertain, "joiner clock");
  last_rx_ = meta;
  // The adapter gate (§5.3): the link re-checks the enrolment-level rules,
  // but destination, channel and phase/step gating live here so a stale or
  // foreign frame never reaches the slot or the observer.
  if (channel_ == 0 || meta.channel != channel_) {
    sat_inc(counters_.rx_dropped);
    return Status::success();
  }
  if (!(meta.destination == config_.mac)) {
    sat_inc(counters_.rx_dropped);
    return Status::success();
  }
  autonomy::Rld1Envelope env{};
  if (!autonomy::rld1_decode(frame, env) || !zt_rld1_frame(env)) {
    sat_inc(counters_.rx_dropped);
    return Status::success();
  }
  const ByteView body{env.body.data(), env.body_size};
  switch (env.kind) {
    case FrameType::Offer:
      if (state_ != JoinState::ScanWindow && state_ != JoinState::RefreshWindow) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      break;
    case FrameType::BootstrapAuth: {
      if (state_ != JoinState::WaitM2 && state_ != JoinState::WaitM4) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      JoinAuthObject object{};
      if (!join_object_decode(body, object) ||
          !step_expected(state_, object.phase, object.step)) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      break;
    }
    case FrameType::BootstrapChunk: {
      if (state_ != JoinState::WaitM2 && state_ != JoinState::WaitM4) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      JoinChunk chunk{};
      if (!join_chunk_decode(JoinCarrier::Rld1, body, chunk) ||
          !step_expected(state_, chunk.phase, chunk.step) ||
          chunk.id != join_rld1_object_id(link_.nonce())) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      break;
    }
    case FrameType::BootstrapReply: {
      if (state_ != JoinState::WaitM2 && state_ != JoinState::WaitM4) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      JoinReply reply{};
      if (!join_reply_decode(JoinCarrier::Rld1, body, reply)) {
        sat_inc(counters_.rx_dropped);
        return Status::success();
      }
      break;
    }
    default:
      sat_inc(counters_.rx_dropped);
      return Status::success();
  }
  link_.on_rld1_rx(meta.source, meta.destination, frame, now);
  return Status::success();
}

Status Joiner::on_channel_ready(const std::uint32_t token, const Status result,
                                const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "joiner re-entry");
  InCall guard(in_call_);
  if (!clock_ok(now)) return Status::error(StatusCode::ClockUncertain, "joiner clock");
  if (!channel_waiting_ || token != channel_token_ || state_ != JoinState::WaitChannel) {
    sat_inc(counters_.stale_events);  // a late completion from an older tune
    return Status::success();
  }
  channel_waiting_ = false;
  if (!result) {
    tune_failed(now);
    return Status::success();
  }
  channel_ = channel_target_;
  if (tune_is_refresh_) {
    refresh_phase_ = RefreshPhase::RateWait;
    set_state(JoinState::RefreshWindow);
    return Status::success();
  }
  open_scan_window(now);
  return Status::success();
}

Status Joiner::take_action(JoinAction& out) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "joiner re-entry");
  InCall guard(in_call_);
  if (!action_pending_) return Status::error(StatusCode::NotFound, "joiner no action");
  out = action_;
  action_ = JoinAction{};
  action_pending_ = false;
  return Status::success();
}

JoinSnapshot Joiner::snapshot() const noexcept {
  JoinSnapshot snapshot{};
  snapshot.state = state_;
  snapshot.membership = projection_;
  snapshot.action_pending = action_pending_;
  snapshot.pending_action = action_.kind;
  snapshot.channel = channel_;
  snapshot.channel_token = channel_token_;
  snapshot.clock_uncertain = clock_uncertain_;
  snapshot.last_error = last_error_;
  snapshot.counters = counters_;
  snapshot.candidates = candidates_.stats();
  snapshot.handshake = handshake_.stats();
  return snapshot;
}

MonotonicMs Joiner::next_deadline() const noexcept {
  if (action_pending_) return last_now_;  // the Owner must take it first
  switch (state_) {
    case JoinState::Stopped:
    case JoinState::Ready:
    case JoinState::Removed:
    case JoinState::RecoveryRequired:
      return kJoinNoDeadline;
    case JoinState::BootCheck:
    case JoinState::Select:
    case JoinState::SendM1:
    case JoinState::SendM3:
    case JoinState::Decided:
    case JoinState::Commit:
      return last_now_;
    case JoinState::ScanTune:
      return last_now_;
    case JoinState::WaitChannel:
      return channel_deadline_;
    case JoinState::ScanWindow:
      return window_deadline_;
    case JoinState::RefreshWindow:
      if (refresh_phase_ == RefreshPhase::RateWait) {
        const MonotonicMs rate =
            last_m1_ms_ == 0 ? last_now_ : sat_add(last_m1_ms_, kJoinMinM1IntervalMs);
        return rate < last_now_ ? last_now_ : rate;
      }
      return window_deadline_;
    case JoinState::WaitM2:
      if (mailbox_valid_ || link_failed_) return last_now_;
      return t2_deadline_ < overall_deadline_ ? t2_deadline_ : overall_deadline_;
    case JoinState::WaitM4:
      if (mailbox_valid_ || link_failed_) return last_now_;
      return t4_deadline_ < overall_deadline_ ? t4_deadline_ : overall_deadline_;
    case JoinState::Reconcile:
      return reconcile_deadline_;
    case JoinState::Backoff:
      return backoff_deadline_;
  }
  return kJoinNoDeadline;
}

bool Joiner::quiescent() const noexcept {
  if (in_call_) return false;
  if (action_pending_ || mailbox_valid_ || hint_valid_ || link_failed_) return false;
  if (link_.slot().mode() != JoinObjectSlot::Mode::Idle || link_.connected()) return false;
  switch (state_) {
    case JoinState::Stopped:
    case JoinState::Backoff:
    case JoinState::Ready:
    case JoinState::Removed:
    case JoinState::RecoveryRequired:
      return true;
    default:
      return false;
  }
}

// --- Driver -------------------------------------------------------------------------------------

Status Joiner::drive(const MonotonicMs now) noexcept {
  switch (state_) {
    case JoinState::Stopped:
    case JoinState::Ready:
    case JoinState::Removed:
    case JoinState::RecoveryRequired:
      return Status::success();
    case JoinState::BootCheck:
      return enter_boot_check(now);
    case JoinState::ScanTune:
      return drive_scan_tune(now);
    case JoinState::WaitChannel:
      return drive_wait_channel(now);
    case JoinState::ScanWindow:
      return drive_scan_window(now);
    case JoinState::Select:
      return drive_select(now);
    case JoinState::RefreshWindow:
      return drive_refresh(now);
    case JoinState::SendM1:
      return drive_send_m1(now);
    case JoinState::WaitM2:
      return drive_wait_m2(now);
    case JoinState::SendM3:
      return drive_send_m3(now);
    case JoinState::WaitM4:
      return drive_wait_m4(now);
    case JoinState::Decided:
      return drive_decided(now);
    case JoinState::Commit:
      return drive_commit(now);
    case JoinState::Reconcile:
      return drive_reconcile(now);
    case JoinState::Backoff:
      return drive_backoff(now);
  }
  return Status::success();
}

bool Joiner::verify_adopted(const SiteRecord& site, const IdentityRecord& identity) noexcept {
  if (!site_validate(site)) return false;
  if (!site_matches_identity(site, identity)) return false;
  bool verified = false;
  if (!join_membership_verify(site, identity, verified) || !verified) return false;
  return true;
}

bool Joiner::below_removal_watermark(const SiteRecord& site) const noexcept {
  return removal_watermark_site_id_ != 0 &&
         site.site_id == removal_watermark_site_id_ &&
         site.assignment_generation <= removal_watermark_generation_;
}

bool Joiner::retain_membership(const SiteRecord& site, const IdentityRecord& identity) noexcept {
  if (!site_.fingerprint(site, retained_fingerprint_)) return false;
  retained_fingerprint_valid_ = true;
  evidence_.site_id = site.site_id;
  evidence_.network = site.network;
  evidence_.node = identity.node_id;
  evidence_.generation = site.assignment_generation;
  CertClaims claims{};
  evidence_valid_ =
      cert_decode(site.site_cert.view(), claims) && claims.type == CertType::Site;
  if (evidence_valid_) evidence_.sak = claims.pubkey;
  retained_floor_ = site.rs_epoch_floor;
  // The preferred DISCOVER hint rides the anchor that issued the stored
  // SiteCert; selection preference needs the site id alone.
  std::uint32_t org = 0;
  for (std::uint8_t i = 0; i < identity.anchor_count; ++i) {
    const IdentityAnchor& anchor = identity.anchors[i];
    if (anchor.kind == AnchorKind::SiteCa && anchor.status == AnchorStatus::Active &&
        anchor.anchor_id == claims.issuer) {
      org = join_org_hint(anchor.pubkey);
      break;
    }
  }
  candidates_.set_preferred(site.site_id, org, join_site_hint(site.site_id));
  if (recovery_only_) {
    recovery_key_.org_hint = org;
    recovery_key_.site_hint = join_site_hint(site.site_id);
    recovery_key_.network_low32 = static_cast<std::uint32_t>(site.network & 0xFFFFFFFFULL);
  }
  return true;
}

void Joiner::start_scan() noexcept {
  candidates_.scan_begin();
  set_state(JoinState::ScanTune);
}

void Joiner::reconcile_enter(const bool authorized, const MonotonicMs now) noexcept {
  reconcile_authorized_ = authorized;
  reconcile_retries_ = 0;
  reconcile_deadline_ = now;
  set_state(JoinState::Reconcile);
}

void Joiner::recovery_required(const JoinRecoveryReason reason) noexcept {
  JoinAction action{};
  action.kind = JoinActionKind::RecoveryRequired;
  action.recovery_reason = reason;
  if (!emit_action(action)) return;  // slot busy: stall and retry next poll
  last_error_ = StatusCode::RecoveryRequired;
  set_state(JoinState::RecoveryRequired);
}

void Joiner::finish_attempt(const JoinAttemptOutcome outcome, const std::uint32_t retry_after_s,
                            const MonotonicMs now) noexcept {
  switch (outcome) {
    case JoinAttemptOutcome::AllowVerified:
      sat_inc(counters_.allows);
      break;
    case JoinAttemptOutcome::PendingAssignment:
      sat_inc(counters_.pendings);
      break;
    case JoinAttemptOutcome::AuthorityBusy:
      sat_inc(counters_.busies);
      break;
    case JoinAttemptOutcome::DenyNotHere:
    case JoinAttemptOutcome::DenyBlocked:
      sat_inc(counters_.denies);
      break;
    case JoinAttemptOutcome::RemovedVerified:
    case JoinAttemptOutcome::RemovedDenied:
    case JoinAttemptOutcome::RemovedNoMembership:
      sat_inc(counters_.removals);
      break;
    case JoinAttemptOutcome::MalformedResult:
      sat_inc(counters_.malformed);
      break;
    case JoinAttemptOutcome::AuthenticationFailed:
      sat_inc(counters_.auth_failures);
      break;
    case JoinAttemptOutcome::Failed:
      sat_inc(counters_.transient_failures);
      break;
    case JoinAttemptOutcome::Pending:
      break;
  }
  const bool authenticated = outcome != JoinAttemptOutcome::Pending &&
                             outcome != JoinAttemptOutcome::Failed &&
                             outcome != JoinAttemptOutcome::AuthenticationFailed;
  event_.key = attempt_key_;
  event_.outcome = outcome;
  event_.authenticated = authenticated;
  if (attempt_.active) {
    candidates_.apply_outcome(attempt_, outcome, retry_after_s, now, entropy_);
    // The unauthenticated proxy hint only steers path selection after a
    // failure — never a verdict, never storage (§8).
    if (outcome == JoinAttemptOutcome::Failed && hint_valid_ &&
        hint_status_ != RelayStatusCode::Queued && attempt_record_ != nullptr) {
      candidates_.suppress_proxy(*attempt_record_, attempt_proxy_, hint_retry_ms_, now);
    }
  }
  teardown_attempt();
  emit(JoinEventKind::AttemptFinished);
  set_state(JoinState::Select);
}

Status Joiner::enter_boot_check(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  const Status id_status = identity_.initialize();
  if (!id_status || !identity_.has_identity() || identity_.quarantined() ||
      identity_.uncertain()) {
    // No usable RLI1: never send m1. The Owner stops/starts to retry.
    last_error_ = !id_status ? id_status.code : StatusCode::IntegrityError;
    event_.store_error = last_error_;
    sat_inc(counters_.store_failures);
    emit(JoinEventKind::StoreFailure);
    set_state(JoinState::Stopped);
    return Status::success();
  }
  const IdentityRecord& identity = identity_.identity();
  const Status id_valid = identity_validate(identity);
  if (!id_valid || identity.node_id != config_.node ||
      identity.key_location == CredentialKeyLocation::None) {
    last_error_ = !id_valid ? id_valid.code : StatusCode::InvalidArgument;
    set_state(JoinState::Stopped);
    return Status::success();
  }
  if (identity.key_location != CredentialKeyLocation::NvsPlaintext) {
    // External key handles need a backend the session does not have: stop
    // before anything is sent, never treat handle bytes as a scalar.
    last_error_ = StatusCode::Unsupported;
    set_state(JoinState::Stopped);
    return Status::success();
  }
  set_projection(MembershipState::Discovering);
  // Scan cursor: configured channels x active Site CA org hints.
  JoinScanConfig scan{};
  for (std::uint8_t i = 0; i < config_.scan_channel_count; ++i) {
    scan.channels[i] = config_.scan_channels[i];
  }
  scan.channel_count = config_.scan_channel_count;
  for (std::uint8_t i = 0; i < identity.anchor_count && scan.org_hint_count < kJoinAnchorMax;
       ++i) {
    const IdentityAnchor& anchor = identity.anchors[i];
    if (anchor.kind != AnchorKind::SiteCa || anchor.status != AnchorStatus::Active) continue;
    const std::uint32_t hint = join_org_hint(anchor.pubkey);
    if (hint == 0) continue;
    bool dup = false;
    for (std::uint8_t j = 0; j < scan.org_hint_count; ++j) dup = dup || scan.org_hints[j] == hint;
    if (!dup) scan.org_hints[scan.org_hint_count++] = hint;
  }
  if (scan.org_hint_count == 0 || !candidates_.configure_scan(scan)) {
    last_error_ = StatusCode::InvalidState;
    set_state(JoinState::Stopped);
    return Status::success();
  }
  const Status site_status = site_.initialize();
  (void)site_status;
  const SiteStoreHealth health = site_.health();
  if (!health.initialized) {
    // Both slots unreadable: retry in Reconcile, never read as empty.
    event_.store_error = StatusCode::StorageFailure;
    sat_inc(counters_.store_failures);
    emit(JoinEventKind::StoreFailure);
    reconcile_enter(false, now);
    return Status::success();
  }
  if (health.unsupported_mask != 0) {
    recovery_required(JoinRecoveryReason::UnknownSchema);
    return Status::success();
  }
  if (health.seq_floor == std::numeric_limits<std::uint32_t>::max()) {
    recovery_required(JoinRecoveryReason::SeqExhausted);
    return Status::success();
  }
  if (health.read_error_mask != 0 || health.active_load_failed) {
    reconcile_enter(false, now);
    return Status::success();
  }
  if (health.has_site) {
    const SiteRecord& site = site_.site();
    if (!verify_adopted(site, identity)) {
      // Decodes but is not ours: needs an external clear, never a silent
      // overwrite and never an m1 (commit and recover are both unusable).
      recovery_required(JoinRecoveryReason::MembershipInvalid);
      return Status::success();
    }
    if (site.boot_witness > boot_witness_) {
      recovery_required(JoinRecoveryReason::BootWitnessMismatch);
      return Status::success();
    }
    if (below_removal_watermark(site)) {
      recovery_required(JoinRecoveryReason::AssignmentRegressed);
      return Status::success();
    }
    if (health.quarantined || health.uncertain) {
      // Known-impaired: only this site may be re-issued, via full EDHOC.
      recovery_only_ = true;
      recovery_site_id_ = site.site_id;
      if (!retain_membership(site, identity)) {
        recovery_required(JoinRecoveryReason::MembershipInvalid);
        return Status::success();
      }
      start_scan();
      return Status::success();
    }
    // Recovery queries keep the old record and its floors until an authenticated
    // verdict; they cannot adopt another site's offer or become Member here.
    if (verify_existing_) {
      recovery_only_ = true;
      recovery_site_id_ = site.site_id;
      if (!retain_membership(site, identity)) {
        recovery_required(JoinRecoveryReason::MembershipInvalid);
        return Status::success();
      }
      start_scan();
      return Status::success();
    }
    // A healthy stored member: adopt it without touching the air.
    if (!retain_membership(site, identity)) {
      recovery_required(JoinRecoveryReason::MembershipInvalid);
      return Status::success();
    }
    JoinAction action{};
    action.kind = JoinActionKind::MemberReady;
    action.commit_seq = site_.commit_seq();
    action.joined_now = false;
    action.rs_epoch_to_fetch = 0;
    if (!emit_action(action)) return Status::success();
    set_state(JoinState::Ready);
    return Status::success();
  }
  if (health.read_error_mask != 0 || health.uncertain) {
    reconcile_enter(false, now);  // re-read before classifying further
    return Status::success();
  }
  start_scan();  // fresh, or a clean quarantine healing via full EDHOC
  return Status::success();
}

// Opens scan windows until one DISCOVER goes out or the cursor exhausts.
// A failed DISCOVER (entropy/radio) skips its window; the scan still walks
// every remaining window before selecting.
bool Joiner::open_scan_window(const MonotonicMs now) noexcept {
  for (;;) {
    const JoinScanStep step = candidates_.scan_step();
    if (!step.valid) {
      set_state(JoinState::Select);
      return false;
    }
    ZtDiscoverBody body{};
    body.profile_bits = kJoinProfileRljoin1 |
                        (recovery_only_ && evidence_valid_ ? kJoinProfileMembershipRecovery : 0u);
    body.org_hint = step.org_hint;
    body.preferred_site_hint = candidates_.preferred_hint(step.org_hint);
    candidates_.avoid_hints(step.org_hint, now, body.avoid_site_hints);
    if (link_.discover(body, now)) {
      window_deadline_ = sat_add(now, kJoinScanWindowMs);
      set_state(JoinState::ScanWindow);
      return true;
    }
    if (!candidates_.scan_advance()) {
      set_state(JoinState::Select);
      return false;
    }
  }
}

Status Joiner::drive_scan_tune(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  if (channel_token_ == std::numeric_limits<std::uint32_t>::max()) {
    recovery_required(JoinRecoveryReason::TokenExhausted);
    return Status::success();
  }
  const JoinScanStep step = candidates_.scan_step();
  if (!step.valid) {
    set_state(JoinState::Select);
    return Status::success();
  }
  ++channel_token_;
  channel_target_ = step.channel;
  channel_waiting_ = true;
  tune_is_refresh_ = false;
  channel_deadline_ = sat_add(now, kJoinChannelTuneMs);
  JoinAction action{};
  action.kind = JoinActionKind::ChangeChannel;
  action.channel_token = channel_token_;
  action.channel = step.channel;
  action.phy = JoinPhy::Lr250;
  if (!emit_action(action)) return Status::success();
  set_state(JoinState::WaitChannel);
  return Status::success();
}

void Joiner::tune_failed(const MonotonicMs now) noexcept {
  if (tune_is_refresh_) {
    // The selected proxy's channel never came up: a path failure on this
    // record, like a refresh window with no answer.
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return;
  }
  // Skip every remaining window on the dead channel, then tune on or select.
  const std::uint8_t dead = channel_target_;
  for (;;) {
    const JoinScanStep step = candidates_.scan_step();
    if (!step.valid || step.channel != dead) break;
    if (!candidates_.scan_advance()) break;
  }
  if (candidates_.scan_step().valid) {
    set_state(JoinState::ScanTune);
  } else {
    set_state(JoinState::Select);
  }
}

Status Joiner::drive_wait_channel(const MonotonicMs now) noexcept {
  if (now < channel_deadline_) return Status::success();
  channel_waiting_ = false;  // a late completion turns stale from here on
  tune_failed(now);
  return Status::success();
}

Status Joiner::drive_scan_window(const MonotonicMs now) noexcept {
  if (now < window_deadline_) return Status::success();
  if (!candidates_.scan_advance()) {
    set_state(JoinState::Select);
    return Status::success();
  }
  const JoinScanStep step = candidates_.scan_step();
  if (!step.valid) {
    set_state(JoinState::Select);
    return Status::success();
  }
  if (step.channel != channel_) {
    set_state(JoinState::ScanTune);
    return Status::success();
  }
  open_scan_window(now);
  return Status::success();
}

Status Joiner::drive_select(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  // At most one pass over the table per poll: a recovery join skips every
  // winner that is not the known site (parking it under a short hold so a
  // stronger foreign site cannot wedge the selection), then either binds
  // the known site or backs off to rescan.
  for (std::size_t pass = 0; pass <= kJoinCandidateMax; ++pass) {
    // Selection and attempt start are one atomic table operation: each
    // begun attempt the recovery join skips is ended (Failed parks the
    // foreign record under a short hold) before the next begin.
    JoinAttempt attempt{};
    JoinSelect selected{};
    const Status begun = candidates_.select_and_begin(now, attempt, selected);
    if (!begun.ok() || selected.candidate == nullptr) {
      candidates_.note_scan_cycle_failed();
      // The deadline is set even when entropy fails (the floor holds then).
      (void)candidates_.next_scan_deadline(now, entropy_, backoff_deadline_);
      set_state(JoinState::Backoff);
      return Status::success();
    }
    if (recovery_only_ && !recovery_match(selected.candidate->key)) {
      candidates_.apply_outcome(attempt, JoinAttemptOutcome::Failed, 0, now, entropy_);
      continue;
    }
    if (recovery_only_ && selected.candidate->site_id_authenticated &&
        selected.candidate->site_id != recovery_site_id_) {
      candidates_.apply_outcome(attempt, JoinAttemptOutcome::Failed, 0, now, entropy_);
      continue;
    }
    attempt_ = attempt;
    attempt_record_ = const_cast<JoinCandidate*>(selected.candidate);
    attempt_key_ = selected.candidate->key;
    attempt_proxy_ = selected.proxy.mac;
    attempt_hops_ = selected.proxy.authority_hops;
    begin_refresh();
    return Status::success();
  }
  (void)candidates_.next_scan_deadline(now, entropy_, backoff_deadline_);
  set_state(JoinState::Backoff);
  return Status::success();
}

void Joiner::begin_refresh() noexcept {
  // The proxy's channel is known; the tune (when needed) runs through the
  // single WaitChannel state, the rate wait inside RefreshWindow.
  const JoinCandidate* record = attempt_record_;
  std::uint8_t target = channel_;
  if (record != nullptr) {
    for (const auto& proxy : record->proxies) {
      if (proxy.present && proxy.mac == attempt_proxy_) {
        target = proxy.channel;
        break;
      }
    }
  }
  if (target == 0) target = channel_;
  if (target == channel_ || channel_ == 0) {
    if (channel_ == 0) channel_ = target;  // untuned only before the first scan
    refresh_phase_ = RefreshPhase::RateWait;
    set_state(JoinState::RefreshWindow);
    return;
  }
  if (channel_token_ == std::numeric_limits<std::uint32_t>::max()) {
    recovery_required(JoinRecoveryReason::TokenExhausted);
    return;
  }
  ++channel_token_;
  channel_target_ = target;
  channel_waiting_ = true;
  tune_is_refresh_ = true;
  channel_deadline_ = sat_add(last_now_, kJoinChannelTuneMs);
  JoinAction action{};
  action.kind = JoinActionKind::ChangeChannel;
  action.channel_token = channel_token_;
  action.channel = target;
  action.phy = JoinPhy::Lr250;
  if (!emit_action(action)) return;  // slot busy: Select retries next poll
  set_state(JoinState::WaitChannel);
}

Status Joiner::drive_refresh(const MonotonicMs now) noexcept {
  if (refresh_phase_ == RefreshPhase::RateWait) {
    // The 2 s device-wide m1 spacing waits here, before the refresh
    // DISCOVER, so the OFFER cookie stays younger than the window.
    if (last_m1_ms_ != 0 && now < sat_add(last_m1_ms_, kJoinMinM1IntervalMs)) {
      return Status::success();
    }
    ZtDiscoverBody body{};
    body.profile_bits = kJoinProfileRljoin1 |
                        (recovery_only_ && evidence_valid_ ? kJoinProfileMembershipRecovery : 0u);
    body.org_hint = attempt_key_.org_hint;
    body.preferred_site_hint = candidates_.preferred_hint(attempt_key_.org_hint);
    candidates_.avoid_hints(attempt_key_.org_hint, now, body.avoid_site_hints);
    if (!link_.discover(body, now)) {
      finish_attempt(JoinAttemptOutcome::Failed, 0, now);
      return Status::success();
    }
    window_deadline_ = sat_add(now, kJoinScanWindowMs);
    refresh_offer_valid_ = false;
    refresh_phase_ = RefreshPhase::Collect;
    return Status::success();
  }
  if (now < window_deadline_) return Status::success();
  if (!refresh_offer_valid_) {
    // The selected proxy never answered: a path failure; the alternate
    // proxy (if any) wins the next selection.
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (!candidates_.use_refresh_proxy(attempt_, refresh_offer_.proxy_mac)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  attempt_.proxy = refresh_offer_.proxy_mac;
  attempt_proxy_ = refresh_offer_.proxy_mac;
  attempt_hops_ = refresh_offer_.body.authority_hops;
  if (!link_.connect(refresh_offer_)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  JoinHandshakeConfig hs{};
  hs.node = config_.node;
  hs.org_hint = attempt_key_.org_hint;
  hs.site_hint = attempt_key_.site_hint;
  hs.network_low32 = attempt_key_.network_low32;
  hs.fw_version = config_.fw_version;
  hs.capability = config_.capability;
  hs.requested_role = config_.requested_role;
  hs.last_site_id = evidence_valid_ ? evidence_.site_id : 0;
  hs.last_generation = evidence_valid_ ? evidence_.generation : 0;
  hs.last_network = evidence_valid_ && recovery_only_ ? evidence_.network : 0;
  hs.usable_channel_mask = config_.usable_channel_mask;
  if (!handshake_.begin(hs, identity_.identity(), entropy_, aead_)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  sat_inc(counters_.attempts);
  event_.key = attempt_key_;
  event_.proxy = attempt_proxy_;
  emit(JoinEventKind::AttemptStarted);
  set_state(JoinState::SendM1);
  return Status::success();
}

Status Joiner::drive_send_m1(const MonotonicMs now) noexcept {
  if (last_m1_ms_ != 0 && now < sat_add(last_m1_ms_, kJoinMinM1IntervalMs)) {
    return Status::success();  // defensive: the refresh wait owns the spacing
  }
  std::size_t length = 0;
  if (!handshake_.compose_m1(MutableByteView{msg_.data(), msg_.size()}, length)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (!link_.send(JoinAuthPhase::EdhocMessage, 1, ByteView{msg_.data(), length}, now)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  clear_mailbox();
  last_m1_ms_ = now;
  t2_deadline_ = sat_add(now, join_m2_deadline_ms(attempt_hops_));
  overall_deadline_ = sat_add(now, kAttemptOverallMs);
  sat_inc(counters_.m1_sent);
  set_state(JoinState::WaitM2);
  return Status::success();
}

Status Joiner::drive_wait_m2(const MonotonicMs now) noexcept {
  if (now >= t2_deadline_ || now >= overall_deadline_) {
    sat_inc(counters_.timeouts);
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (link_failed_) {
    sat_inc(counters_.link_failures);
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (!mailbox_valid_) return Status::success();
  if (mailbox_phase_ != JoinAuthPhase::EdhocMessage || mailbox_step_ == 5) {
    clear_mailbox();  // an EDHOC error answers the attempt: transient, counted
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (mailbox_step_ != 2) {
    sat_inc(counters_.rx_dropped);
    clear_mailbox();
    return Status::success();
  }
  const ByteView message{msg_.data(), msg_len_};
  clear_mailbox();
  if (!handshake_.process_m2(message)) {
    // AuthenticationFailed (bad SiteCert/responder signature -> 24 h on
    // the key, no m3) or Failed (decode/transport -> transient).
    finish_attempt(handshake_.outcome(), 0, now);
    return Status::success();
  }
  sat_inc(counters_.m2_ok);
  JoinCandidate* bound = nullptr;
  if (!candidates_.bind_authenticated(attempt_, handshake_.offer().site_id, now, bound) ||
      bound == nullptr) {
    // Held elsewhere or no room for the split: park this record briefly
    // and let another candidate go first.
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (recovery_only_ && handshake_.offer().site_id != recovery_site_id_) {
    // A hint collision resolved against us: this record is not the known
    // site, so no m3 goes out here.
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  attempt_record_ = bound;
  set_state(JoinState::SendM3);  // m3 composes on the next poll, never here
  return Status::success();
}

Status Joiner::drive_send_m3(const MonotonicMs now) noexcept {
  if (now >= overall_deadline_) {
    sat_inc(counters_.timeouts);
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  std::size_t length = 0;
  if (!handshake_.compose_m3(MutableByteView{msg_.data(), msg_.size()}, length)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (!link_.send(JoinAuthPhase::EdhocMessage, 3, ByteView{msg_.data(), length}, now)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  clear_mailbox();
  std::uint32_t decision = handshake_.offer().decision_timeout_ms;
  if (decision < kDecisionMinMs) decision = kDecisionMinMs;
  if (decision > kDecisionMaxMs) decision = kDecisionMaxMs;
  t4_deadline_ = sat_add(now, join_m4_deadline_ms(attempt_hops_, decision));
  if (t4_deadline_ < overall_deadline_) overall_deadline_ = t4_deadline_;
  set_state(JoinState::WaitM4);
  return Status::success();
}

Status Joiner::drive_wait_m4(const MonotonicMs now) noexcept {
  if (now >= t4_deadline_ || now >= overall_deadline_) {
    sat_inc(counters_.timeouts);
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (link_failed_) {
    sat_inc(counters_.link_failures);
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (!mailbox_valid_) return Status::success();
  if (mailbox_phase_ != JoinAuthPhase::EdhocMessage || mailbox_step_ == 5) {
    clear_mailbox();
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (mailbox_step_ != 4) {
    sat_inc(counters_.rx_dropped);
    clear_mailbox();
    return Status::success();
  }
  const ByteView message{msg_.data(), msg_len_};
  clear_mailbox();
  if (!handshake_.process_m4(message)) {
    finish_attempt(handshake_.outcome(), 0, now);
    return Status::success();
  }
  sat_inc(counters_.m4_ok);
  set_state(JoinState::Decided);  // verification runs on the next poll
  return Status::success();
}

Status Joiner::drive_decided(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  if (now >= overall_deadline_) {
    sat_inc(counters_.timeouts);
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  JoinDecideInput input{};
  input.membership = evidence_valid_ ? &evidence_ : nullptr;
  input.boot_witness = boot_witness_;
  input.prior_rs_epoch_floor = evidence_valid_ ? retained_floor_ : 0;
  JoinDecided decided{};
  if (!handshake_.decide(input, decided)) {
    finish_attempt(JoinAttemptOutcome::Failed, 0, now);
    return Status::success();
  }
  if (decided.outcome == JoinAttemptOutcome::AllowVerified && decided.record != nullptr &&
      below_removal_watermark(*decided.record)) {
    teardown_attempt();
    recovery_required(JoinRecoveryReason::AssignmentRegressed);
    return Status::success();
  }
  decided_ = decided;
  decided_valid_ = true;
  switch (decided.outcome) {
    case JoinAttemptOutcome::AllowVerified:
      set_state(JoinState::Commit);  // the flash commit runs on the next poll
      return Status::success();
    case JoinAttemptOutcome::PendingAssignment:
    case JoinAttemptOutcome::AuthorityBusy:
      finish_attempt(decided.outcome, decided.retry_after_s, now);
      return Status::success();
    case JoinAttemptOutcome::DenyNotHere:
    case JoinAttemptOutcome::DenyBlocked:
    case JoinAttemptOutcome::MalformedResult:
    case JoinAttemptOutcome::RemovedDenied:
    case JoinAttemptOutcome::RemovedNoMembership:
      finish_attempt(decided.outcome, 0, now);
      return Status::success();
    case JoinAttemptOutcome::RemovedVerified: {
      JoinAction action{};
      action.kind = JoinActionKind::RemovalRequired;
      action.removal = decided.removal;
      action.removal_object = decided.removal_object;
      action.removal_site_id = decided.removal.site_id;
      action.removal_generation = decided.removal.generation;
      if (!emit_action(action)) return Status::success();  // retry next poll
      event_.key = attempt_key_;
      event_.outcome = decided.outcome;
      event_.authenticated = true;
      sat_inc(counters_.removals);
      if (attempt_.active) {
        candidates_.apply_outcome(attempt_, decided.outcome, 0, now, entropy_);
      }
      teardown_attempt();
      emit(JoinEventKind::AttemptFinished);
      set_state(JoinState::Removed);
      return Status::success();
    }
    case JoinAttemptOutcome::Failed:
    case JoinAttemptOutcome::AuthenticationFailed:
    case JoinAttemptOutcome::Pending:
      finish_attempt(JoinAttemptOutcome::Failed, 0, now);
      return Status::success();
  }
  finish_attempt(JoinAttemptOutcome::Failed, 0, now);
  return Status::success();
}

Status Joiner::drive_commit(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  link_.close();  // the m4 Complete reply already went out during assembly
  if (!decided_valid_ || decided_.record == nullptr || attempt_record_ == nullptr) {
    teardown_attempt();
    reconcile_enter(true, now);  // nothing was written; classify the store
    return Status::success();
  }
  const SiteRecord& prepared = *decided_.record;
  if (below_removal_watermark(prepared)) {
    teardown_attempt();
    recovery_required(JoinRecoveryReason::AssignmentRegressed);
    return Status::success();
  }
  Digest256 prepared_fingerprint{};
  if (!site_.fingerprint(prepared, prepared_fingerprint)) {
    finish_attempt(JoinAttemptOutcome::MalformedResult, 0, now);
    return Status::success();
  }
  Status stored;
  const SiteStoreHealth health = site_.health();
  if (health.quarantined || health.uncertain) {
    // An impaired store refuses commit(): the verified Allow is the
    // explicit way out — except over unknown schemas or read errors.
    if (health.unsupported_mask != 0 || health.read_error_mask != 0) {
      if (attempt_.active) {
        candidates_.apply_outcome(attempt_, JoinAttemptOutcome::AllowVerified, 0, now, entropy_);
      }
      teardown_attempt();
      reconcile_enter(true, now);
      return Status::success();
    }
    if (site_.has_site()) {
      // Monotonicity against the retained value first: a re-issue must
      // keep the site and never regress epochs, generation or floors.
      const SiteRecord& current = site_.site();
      const std::uint32_t old_epoch = static_cast<std::uint32_t>(current.network >> 32U);
      const std::uint32_t new_epoch = static_cast<std::uint32_t>(prepared.network >> 32U);
      const bool regressed =
          prepared.site_id != current.site_id || new_epoch < old_epoch ||
          (new_epoch == old_epoch && prepared.network != current.network) ||
          prepared.assignment_generation < current.assignment_generation ||
          prepared.gk_epoch_current < current.gk_epoch_current ||
          prepared.rs_epoch_floor < current.rs_epoch_floor ||
          prepared.boot_witness < current.boot_witness;
      if (regressed) {
        teardown_attempt();
        wipe_expectation();
        recovery_required(JoinRecoveryReason::AssignmentRegressed);
        return Status::success();
      }
    }
    stored = site_.recover(prepared);
  } else {
    stored = site_.commit(prepared);
  }
  // The prepared pointer dies with the session: keep the minimal compare
  // set for the re-read below and for Reconcile.
  commit_expect_.valid = true;
  commit_expect_.rs_epoch_to_fetch = decided_.rs_epoch_to_fetch;
  commit_expect_.fingerprint = prepared_fingerprint;
  candidates_.apply_outcome(attempt_, JoinAttemptOutcome::AllowVerified, 0, now, entropy_);
  teardown_attempt();
  if (!stored) {
    // A commit error is NOT "flash unchanged": the sealed record may have
    // landed. Never assume; re-read in Reconcile.
    event_.store_error = stored.code;
    sat_inc(counters_.store_failures);
    emit(JoinEventKind::StoreFailure);
    reconcile_enter(true, now);
    return Status::success();
  }
  (void)site_.initialize();
  const SiteStoreHealth after = site_.health();
  if (after.has_site && after.unsupported_mask == 0 && after.read_error_mask == 0 &&
      !after.active_load_failed && !after.quarantined && !after.uncertain &&
      !below_removal_watermark(site_.site()) && matches_expectation(site_.site()) &&
      verify_adopted(site_.site(), identity_.identity())) {
    // The complete verified record was read back from a healthy pair.
    JoinAction action{};
    action.kind = JoinActionKind::MemberReady;
    action.commit_seq = site_.commit_seq();
    action.joined_now = true;
    action.rs_epoch_to_fetch = commit_expect_.rs_epoch_to_fetch;
    if (!emit_action(action)) return Status::success();
    wipe_expectation();
    recovery_only_ = false;
    set_state(JoinState::Ready);
    return Status::success();
  }
  reconcile_enter(true, now);
  return Status::success();
}

Status Joiner::drive_reconcile(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  if (now < reconcile_deadline_) return Status::success();
  (void)site_.initialize();
  const SiteStoreHealth health = site_.health();
  if (!health.initialized || health.read_error_mask != 0 || health.active_load_failed ||
      (health.uncertain && !health.has_site)) {
    // Unreadable or undecodable: bounded re-reads, then external recovery.
    ++reconcile_retries_;
    event_.store_error = StatusCode::StorageFailure;
    sat_inc(counters_.store_failures);
    emit(JoinEventKind::StoreFailure);
    if (reconcile_retries_ >= kReconcileMaxRetries) {
      recovery_required(JoinRecoveryReason::StorageFailure);
      return Status::success();
    }
    reconcile_deadline_ = sat_add(now, kReconcileWaitMs);
    return Status::success();
  }
  reconcile_retries_ = 0;  // the streak counts consecutive failures only
  if (health.unsupported_mask != 0) {
    recovery_required(JoinRecoveryReason::UnknownSchema);
    return Status::success();
  }
  if (health.seq_floor == std::numeric_limits<std::uint32_t>::max()) {
    recovery_required(JoinRecoveryReason::SeqExhausted);
    return Status::success();
  }
  const IdentityRecord& identity = identity_.identity();
  if (health.has_site) {
    const SiteRecord& site = site_.site();
    if (!verify_adopted(site, identity)) {
      recovery_required(JoinRecoveryReason::MembershipInvalid);
      return Status::success();
    }
    if (site.boot_witness > boot_witness_) {
      recovery_required(JoinRecoveryReason::BootWitnessMismatch);
      return Status::success();
    }
    if (below_removal_watermark(site)) {
      recovery_required(JoinRecoveryReason::AssignmentRegressed);
      return Status::success();
    }
    if (commit_expect_.valid && !health.quarantined && !health.uncertain &&
        matches_expectation(site)) {
      // Our write landed (the error was the readback or later): adopt it
      // without consuming another approval or writing again.
      JoinAction action{};
      action.kind = JoinActionKind::MemberReady;
      action.commit_seq = site_.commit_seq();
      action.joined_now = true;
      action.rs_epoch_to_fetch = commit_expect_.rs_epoch_to_fetch;
      if (!emit_action(action)) return Status::success();
      wipe_expectation();
      recovery_only_ = false;
      set_state(JoinState::Ready);
      return Status::success();
    }
    if (!health.quarantined && !health.uncertain) {
      // A healthy old member survived: keep it, never guess DAMS equality.
      Digest256 actual{};
      if (commit_expect_.valid &&
          (!retained_fingerprint_valid_ || !site_.fingerprint(site, actual) ||
           actual != retained_fingerprint_)) {
        recovery_required(JoinRecoveryReason::MembershipInvalid);
        return Status::success();
      }
      wipe_expectation();
      if (!retain_membership(site, identity)) {
        recovery_required(JoinRecoveryReason::MembershipInvalid);
        return Status::success();
      }
      JoinAction action{};
      action.kind = JoinActionKind::MemberReady;
      action.commit_seq = site_.commit_seq();
      action.joined_now = false;
      action.rs_epoch_to_fetch = 0;
      if (!emit_action(action)) return Status::success();
      set_state(JoinState::Ready);
      return Status::success();
    }
    // Known-impaired with a verifying value: re-issue this site only.
    wipe_expectation();
    recovery_only_ = true;
    recovery_site_id_ = site.site_id;
    if (!retain_membership(site, identity)) {
      recovery_required(JoinRecoveryReason::MembershipInvalid);
      return Status::success();
    }
    start_scan();
    return Status::success();
  }
  // Provably empty: forget the uncommitted secrets and try over. A clean
  // quarantine heals through a fresh full EDHOC; anything else paces out.
  wipe_expectation();
  if (health.quarantined) {
    start_scan();
    return Status::success();
  }
  (void)candidates_.next_scan_deadline(now, entropy_, backoff_deadline_);
  set_state(JoinState::Backoff);
  return Status::success();
}

Status Joiner::drive_backoff(const MonotonicMs now) noexcept {
  if (action_pending_) return Status::success();
  // No eligibility peek exists: selection and attempt start are atomic, so
  // Backoff always honors its deadline (a jittered ~1-2 s at k=0, cut by
  // the nearest pending eligibility) before the rescan.
  if (now < backoff_deadline_) return Status::success();
  start_scan();
  return Status::success();
}

}  // namespace routeloom::sdkv1
