// SDK v1 zero-touch join candidate table (02 §5, §10; design P3-4 §5, §9).
// See sdkv1_join_candidates.hpp for the component contract.

#include "routeloom/sdkv1_join_candidates.hpp"

#include <cstring>

namespace routeloom::sdkv1 {
namespace {

Status invalid(const char* detail) { return Status::error(StatusCode::InvalidArgument, detail); }
Status err(const StatusCode code, const char* detail) { return Status::error(code, detail); }

bool id_valid(const std::uint64_t id) noexcept { return id != 0 && id != ~std::uint64_t{0}; }

bool unicast_mac(const MacAddress& mac) noexcept {
  bool zero = true;
  for (const std::uint8_t b : mac) zero = zero && b == 0;
  return !zero && (mac[0] & 0x01U) == 0;
}

bool avoid_policy(const JoinCandidatePolicy p) noexcept {
  return p == JoinCandidatePolicy::AvoidNotHere || p == JoinCandidatePolicy::AvoidBlocked;
}

// Proxy rank: hops asc (255 unknown last), RSSI desc, MAC lex asc. One
// definition serves stored proxies and fresh observations alike, so a later
// rank change cannot land in one copy and miss the other.
template <typename A, typename B>
bool proxy_better(const A& a, const B& b) noexcept {
  if (a.authority_hops != b.authority_hops) return a.authority_hops < b.authority_hops;
  if (a.rssi != b.rssi) return a.rssi > b.rssi;
  for (std::size_t i = 0; i < a.mac.size(); ++i) {
    if (a.mac[i] != b.mac[i]) return a.mac[i] < b.mac[i];
  }
  return false;
}

// A saturated deadline (UINT64_MAX, the kJoinNoDeadline sentinel) never
// arrives: sat_add can only produce it on overflow, so a hold that computed
// it stays in force instead of releasing at the clock's maximum.
bool hold_active(const MonotonicMs eligible_at, const MonotonicMs now) noexcept {
  return eligible_at == kJoinNoDeadline || eligible_at > now;
}

std::uint32_t get_u32(const std::uint8_t* p) noexcept {
  std::uint32_t v = 0;
  std::memcpy(&v, p, sizeof(v));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v = __builtin_bswap32(v);
#endif
  return v;
}

void fill_proxy(JoinCandidateProxy& p, const JoinProxyObservation& o,
                const MonotonicMs now_ms) noexcept {
  p = JoinCandidateProxy{};
  p.present = true;
  p.mac = o.mac;
  p.node = o.node;
  p.channel = o.channel;
  p.rssi = o.rssi;
  p.authority_hops = o.authority_hops;
  p.authority_reachable = o.authority_reachable;
  p.proxy_busy = o.proxy_busy;
  p.last_seen_ms = now_ms;
}

// Failed-path memory: the zero MAC marks an empty slot (observations require
// a nonzero unicast MAC, so zero never collides with a real path).
bool failed_contains(const JoinCandidate& r, const MacAddress& mac) noexcept {
  for (const auto& f : r.failed_proxies) {
    if (f == mac) return true;
  }
  return false;
}

// Remembers one more failed path, dropping the oldest past two — proxy churn
// may show more paths than slots, and the survivors must be the recent ones.
void failed_add(JoinCandidate& r, const MacAddress& mac) noexcept {
  if (failed_contains(r, mac)) return;
  for (auto& f : r.failed_proxies) {
    if (f == MacAddress{}) {
      f = mac;
      return;
    }
  }
  r.failed_proxies[0] = r.failed_proxies[1];
  r.failed_proxies[1] = mac;
}

}  // namespace

// --- Clock ---------------------------------------------------------------------------

bool JoinCandidates::clock_ok(const MonotonicMs now_ms) noexcept {
  // Sticky: a regressed clock is a new clock domain, which design §4.1 treats
  // as a restart. Only a new instance resumes; catching up must not release
  // holds or restart crypto on this table.
  if (clock_uncertain_) return false;
  if (now_ms < last_now_ms_) {
    clock_uncertain_ = true;
    ++stats_.clock_regressions;
    return false;
  }
  last_now_ms_ = now_ms;
  return true;
}

MonotonicMs JoinCandidates::sat_add(const MonotonicMs a,
                                    const std::uint64_t delta_ms) noexcept {
  return delta_ms > ~MonotonicMs{0} - a ? ~MonotonicMs{0} : a + delta_ms;
}

Status JoinCandidates::transient_delay(const std::uint8_t k, EntropySource& entropy,
                                       std::uint64_t& delay_ms) noexcept {
  const std::uint8_t kk = k > kJoinTransientMaxK ? kJoinTransientMaxK : k;
  const std::uint64_t base =
      std::min<std::uint64_t>(kJoinBackoffMaxMs, std::uint64_t{kJoinTransientBaseMs} << kk);
  const std::uint64_t hi = std::min<std::uint64_t>(kJoinBackoffMaxMs, base + base / 4);
  const std::uint64_t spread = hi - base;
  if (spread == 0) {
    delay_ms = base;
    return Status::success();
  }
  std::uint8_t buf[4]{};
  const Status st = entropy.fill(MutableByteView{buf, sizeof(buf)});
  if (!st) {
    ++stats_.entropy_failures;
    delay_ms = base;  // floor only; an entropy failure never lengthens a hold
    return st;
  }
  delay_ms = base + get_u32(buf) % (spread + 1);
  return Status::success();
}

// --- Scan cursor ----------------------------------------------------------------------

Status JoinCandidates::configure_scan(const JoinScanConfig& config) noexcept {
  if (config.channel_count == 0 || config.channel_count > kJoinScanChannelMax ||
      config.org_hint_count == 0 || config.org_hint_count > kJoinAnchorMax) {
    return invalid("join scan bounds");
  }
  JoinScanConfig clean{};
  for (std::uint8_t i = 0; i < config.channel_count; ++i) {
    const std::uint8_t ch = config.channels[i];
    if (ch == 0 || ch > 14) return invalid("join scan channel");
    for (std::uint8_t j = 0; j < i; ++j) {
      if (clean.channels[j] == ch) return invalid("join scan channel dup");
    }
    clean.channels[clean.channel_count++] = ch;
  }
  // Anchor hints are deduplicated, not rejected (design §4.1).
  for (std::uint8_t i = 0; i < config.org_hint_count; ++i) {
    const std::uint32_t h = config.org_hints[i];
    if (h == 0) return invalid("join scan org hint");
    bool dup = false;
    for (std::uint8_t j = 0; j < clean.org_hint_count; ++j) {
      dup = dup || clean.org_hints[j] == h;
    }
    if (!dup) clean.org_hints[clean.org_hint_count++] = h;
  }
  scan_ = clean;
  scan_active_ = false;
  scan_channel_i_ = 0;
  scan_org_i_ = 0;
  return Status::success();
}

JoinScanStep JoinCandidates::scan_begin() noexcept {
  scan_active_ = scan_.channel_count > 0 && scan_.org_hint_count > 0;
  scan_channel_i_ = 0;
  scan_org_i_ = 0;
  return scan_step();
}

bool JoinCandidates::scan_advance() noexcept {
  if (!scan_active_) return false;
  if (++scan_org_i_ < scan_.org_hint_count) return true;
  scan_org_i_ = 0;
  if (++scan_channel_i_ < scan_.channel_count) return true;
  scan_active_ = false;
  return false;
}

JoinScanStep JoinCandidates::scan_step() const noexcept {
  if (!scan_active_) return JoinScanStep{};
  return JoinScanStep{scan_.channels[scan_channel_i_], scan_.org_hints[scan_org_i_], true};
}

// --- Records --------------------------------------------------------------------------

bool JoinCandidates::proxy_fresh(const JoinCandidateProxy& p, const MonotonicMs now) noexcept {
  return p.present && now - p.last_seen_ms <= kJoinOfferFreshMs;
}

bool JoinCandidates::proxy_usable(const JoinCandidateProxy& p, const MonotonicMs now) noexcept {
  return proxy_fresh(p, now) && p.authority_reachable && !p.proxy_busy &&
         !hold_active(p.suppressed_until_ms, now);
}

const JoinCandidateProxy* JoinCandidates::best_proxy(const JoinCandidate& record,
                                                     const MonotonicMs now) noexcept {
  // A failed path stays usable once its hold expires, so rank failed paths
  // separately: an untried proxy wins even when weaker, and a failed path is
  // reused only when it is the only usable one (§5.1 rule 5).
  const JoinCandidateProxy* best = nullptr;
  const JoinCandidateProxy* failed = nullptr;
  for (const auto& p : record.proxies) {
    if (!proxy_usable(p, now)) continue;
    const JoinCandidateProxy*& slot = failed_contains(record, p.mac) ? failed : best;
    if (slot == nullptr || proxy_better(p, *slot)) slot = &p;
  }
  return best != nullptr ? best : failed;
}

bool JoinCandidates::key_less(const JoinCandidateKey& a, const JoinCandidateKey& b) noexcept {
  if (a.org_hint != b.org_hint) return a.org_hint < b.org_hint;
  if (a.site_hint != b.site_hint) return a.site_hint < b.site_hint;
  return a.network_low32 < b.network_low32;
}

bool JoinCandidates::mac_less(const MacAddress& a, const MacAddress& b) noexcept {
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return false;
}

// Selection order within one rule-5 pass (design §5.1 rule 4): preferred,
// untried, hops asc, RSSI desc, oldest attempt, key/MAC lexicographic.
bool JoinCandidates::better(const JoinCandidate& a, const JoinCandidateProxy& ap,
                            const JoinCandidate& b, const JoinCandidateProxy& bp) noexcept {
  if (a.preferred != b.preferred) return a.preferred;
  const bool au = a.policy == JoinCandidatePolicy::Untried;
  const bool bu = b.policy == JoinCandidatePolicy::Untried;
  if (au != bu) return au;
  if (ap.authority_hops != bp.authority_hops) return ap.authority_hops < bp.authority_hops;
  if (ap.rssi != bp.rssi) return ap.rssi > bp.rssi;
  if (a.last_attempt_ms != b.last_attempt_ms) return a.last_attempt_ms < b.last_attempt_ms;
  if (key_less(a.key, b.key)) return true;
  if (key_less(b.key, a.key)) return false;
  return mac_less(ap.mac, bp.mac);
}

// Strongest-hold merge: records resolving to the same authenticated site_id
// share the later eligible_at, so a colliding OFFER key cannot bypass a
// pending/busy/avoid hold (design §5.1 rule 2, §5.2).
MonotonicMs JoinCandidates::effective_eligible_at(const JoinCandidate& record) const noexcept {
  MonotonicMs eff = record.eligible_at_ms;
  if (!record.site_id_authenticated) return eff;
  for (const auto& o : records_) {
    if (o.occupied && o.site_id_authenticated && o.site_id == record.site_id &&
        o.eligible_at_ms > eff) {
      eff = o.eligible_at_ms;
    }
  }
  return eff;
}

// A handle names the live attempt only while the table holds an attempt of
// the same generation for the same key: the generation rejects handles from
// earlier cycles (attempts may share a timestamp), the key rejects handles
// mixed up across tables. The site is NOT compared — bind moves the live
// attempt to the proven site while the caller's copy still names the old one.
bool JoinCandidates::attempt_live(const JoinAttempt& attempt) const noexcept {
  return attempt.active && attempt_.active && attempt.seq == attempt_.seq &&
         attempt.key == attempt_.key;
}

// The attempt pins exactly one record: before m2 the key's unbound record,
// once a site is proven (pre-bound or via bind) that site's record. A split
// sibling sharing the key is NOT pinned — it stays evictable throughout.
bool JoinCandidates::attempt_pinned(const JoinCandidate& record) const noexcept {
  if (!attempt_.active || !record.occupied || !(record.key == attempt_.key)) return false;
  if (attempt_.site_id == 0) return !record.site_id_authenticated;
  return record.site_id_authenticated && record.site_id == attempt_.site_id;
}

// Empty slot first, else the stalest record whose hold expired; never the
// attempt's record nor one under an unexpired hold. An expired hold already
// kept its site out for the full term, so any expired policy is replaceable —
// pinning it forever would wedge the table (§5.1 rule 3).
JoinCandidate* JoinCandidates::acquire(const MonotonicMs now_ms, bool& evicted) noexcept {
  evicted = false;
  JoinCandidate* victim = nullptr;
  for (auto& r : records_) {
    if (!r.occupied) return &r;
    if (attempt_pinned(r) || hold_active(r.eligible_at_ms, now_ms)) continue;
    if (victim == nullptr || r.last_seen_ms < victim->last_seen_ms) victim = &r;
  }
  if (victim != nullptr) {
    *victim = JoinCandidate{};
    evicted = true;
  }
  return victim;
}

// Keep at most the best 2 proxies. A fresh-but-worse observation replaces
// stale evidence before quality-ranked replacement is considered — a stale
// route cannot be used anyway (§5.1 freshness, rule 5).
void JoinCandidates::upsert_proxy(JoinCandidate& record, const JoinProxyObservation& o,
                                  const MonotonicMs now_ms) noexcept {
  JoinCandidateProxy* stale = nullptr;
  JoinCandidateProxy* worst = nullptr;
  for (auto& p : record.proxies) {
    if (!p.present) {
      fill_proxy(p, o, now_ms);
      return;
    }
    if (p.mac == o.mac) {
      p.node = o.node;
      p.channel = o.channel;
      p.rssi = o.rssi;
      p.authority_hops = o.authority_hops;
      p.authority_reachable = o.authority_reachable;
      p.proxy_busy = o.proxy_busy;
      p.last_seen_ms = now_ms;
      return;
    }
    // Among stale slots the oldest loses; equally old, the worse quality
    // loses — keep the better stale route plus the fresh observation.
    if (!proxy_fresh(p, now_ms) &&
        (stale == nullptr || p.last_seen_ms < stale->last_seen_ms ||
         (p.last_seen_ms == stale->last_seen_ms && proxy_better(*stale, p)))) {
      stale = &p;
    }
    if (worst == nullptr || proxy_better(*worst, p)) worst = &p;
  }
  JoinCandidateProxy* slot = nullptr;
  if (stale != nullptr) {
    slot = stale;
  } else if (worst != nullptr && proxy_better(o, *worst)) {
    slot = worst;
  }
  if (slot == nullptr) return;
  // A different MAC is a different path: the old proxy's suppression does
  // not transfer.
  fill_proxy(*slot, o, now_ms);
}

JoinObserve JoinCandidates::observe(const JoinCandidateKey& key,
                                    const JoinProxyObservation& proxy,
                                    const MonotonicMs now_ms) noexcept {
  ++stats_.observations;
  if (!clock_ok(now_ms) || key.org_hint == 0 || key.site_hint == 0 ||
      key.network_low32 == 0 || !id_valid(proxy.node) || proxy.channel == 0 ||
      proxy.channel > 14 || !unicast_mac(proxy.mac)) {
    ++stats_.rejected;
    return JoinObserve::Rejected;
  }
  // Observation is key-level: refresh every record carrying this key
  // (colliding authenticated records share the physical OFFER).
  bool updated = false;
  for (auto& r : records_) {
    if (r.occupied && r.key == key) {
      upsert_proxy(r, proxy, now_ms);
      r.last_seen_ms = now_ms;
      updated = true;
    }
  }
  if (updated) return JoinObserve::Updated;
  bool evicted = false;
  JoinCandidate* r = acquire(now_ms, evicted);
  if (r == nullptr) {
    ++stats_.dropped_no_capacity;
    return JoinObserve::NoCapacity;
  }
  r->occupied = true;
  r->key = key;
  r->last_seen_ms = now_ms;
  upsert_proxy(*r, proxy, now_ms);
  if (evicted) {
    ++stats_.evicted;
    return JoinObserve::Evicted;
  }
  ++stats_.inserted;
  return JoinObserve::Inserted;
}

// --- Selection + authentication binding -------------------------------------------------

Status JoinCandidates::select_and_begin(const MonotonicMs now_ms, JoinAttempt& attempt,
                                        JoinSelect& sel) noexcept {
  attempt = JoinAttempt{};
  sel = JoinSelect{};
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  if (attempt_.active) return err(StatusCode::InvalidState, "join attempt in flight");
  JoinCandidate* best_c = nullptr;
  const JoinCandidateProxy* best_p = nullptr;
  // Two passes (§5.1 rule 5 outranks rule 4, even preferred): records with
  // an untried usable route first — best_proxy prefers untried, so a failed
  // pick means every usable route failed — and only when none exists do the
  // all-failed records compete, reusing their best failed path.
  for (int pass = 0; pass < 2 && best_c == nullptr; ++pass) {
    for (auto& r : records_) {
      if (!r.occupied || hold_active(effective_eligible_at(r), now_ms)) continue;
      const JoinCandidateProxy* p = best_proxy(r, now_ms);
      if (p == nullptr) continue;
      if (pass == 0 && failed_contains(r, p->mac)) continue;
      if (best_c == nullptr || better(r, *p, *best_c, *best_p)) {
        best_c = &r;
        best_p = p;
      }
    }
  }
  if (best_c == nullptr) {
    ++stats_.selections_empty;
    return err(StatusCode::NotFound, "join no candidate");
  }
  best_c->last_attempt_ms = now_ms;
  attempt_.active = true;
  attempt_.seq = ++attempt_seq_;  // the 2^64 wrap is unreachable in practice
  attempt_.key = best_c->key;
  attempt_.proxy = best_p->mac;
  attempt_.site_id = best_c->site_id_authenticated ? best_c->site_id : 0;
  attempt = attempt_;
  sel.candidate = best_c;
  sel.proxy = *best_p;
  ++stats_.selections;
  return Status::success();
}

Status JoinCandidates::use_refresh_proxy(const JoinAttempt& attempt,
                                         const MacAddress& proxy) noexcept {
  if (!attempt_live(attempt)) return err(StatusCode::InvalidState, "join no live attempt");
  if (!unicast_mac(proxy)) return invalid("join refresh proxy MAC");
  attempt_.proxy = proxy;
  return Status::success();
}

Status JoinCandidates::bind_authenticated(const JoinAttempt& attempt,
                                          const std::uint64_t site_id,
                                          const MonotonicMs now_ms,
                                          JoinCandidate*& record) noexcept {
  record = nullptr;
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  if (!attempt_live(attempt)) return err(StatusCode::InvalidState, "join no live attempt");
  if (site_id == 0) return invalid("join bind site id");
  // Holds are site-wide: while ANY record proven as this site still holds it
  // — avoid, pending, busy or transient, whatever the key — the attempt
  // aborts and no m3 goes out. Same-site records share one effective
  // deadline, so the first match decides (§5.1 rule 2, §5.2).
  for (const auto& r : records_) {
    if (r.occupied && r.site_id_authenticated && r.site_id == site_id &&
        hold_active(effective_eligible_at(r), now_ms)) {
      attempt_ = JoinAttempt{};
      return err(StatusCode::InvalidState, "join site held");
    }
  }
  JoinCandidate* pinned = nullptr;
  for (auto& r : records_) {
    if (attempt_pinned(r)) {
      pinned = &r;
      break;
    }
  }
  if (pinned == nullptr) {
    // The attempt pins its record against eviction, so a live attempt always
    // has its key. Fail closed and release the attempt.
    attempt_ = JoinAttempt{};
    return err(StatusCode::InvalidState, "join bind key lost");
  }
  if (attempt_.site_id == 0 || attempt_.site_id == site_id) {
    // First bind on the attempt's own unbound record (an unbound attempt owns
    // its key alone: same-key records only ever split into all-bound pairs),
    // or a re-proof of the attempt's site. Either way no scan, no split.
    pinned->site_id = site_id;
    pinned->site_id_authenticated = true;
    pinned->preferred = site_id == preferred_site_id_;
    attempt_.site_id = site_id;
    record = pinned;
    return Status::success();
  }
  for (auto& r : records_) {
    if (r.occupied && r.key == attempt_.key && r.site_id_authenticated &&
        r.site_id == site_id) {
      // The key already proved this site on a split sibling: the attempt
      // simply starts naming it. No per-record state moves.
      attempt_.site_id = site_id;
      record = &r;
      return Status::success();
    }
  }
  // Hint collision resolved by authentication: the newly proven site needs a
  // second record sharing the key (§5.2). The branch source is the attempt's
  // own record — already pinned, so it can never be its own victim — and a
  // full table aborts the attempt rather than conflating two sites.
  bool evicted = false;
  JoinCandidate* target = acquire(now_ms, evicted);
  if (target == nullptr) {
    ++stats_.auth_split_failed;
    ++stats_.dropped_no_capacity;
    attempt_ = JoinAttempt{};
    return err(StatusCode::NoCapacity, "join split capacity");
  }
  *target = *pinned;  // same observed proxy evidence under one key
  target->site_id = site_id;
  target->site_id_authenticated = true;
  target->policy = JoinCandidatePolicy::Untried;
  target->eligible_at_ms = 0;
  target->failures = 0;
  for (auto& f : target->failed_proxies) f = MacAddress{};
  target->preferred = site_id == preferred_site_id_;
  attempt_.site_id = site_id;
  ++stats_.auth_splits;
  if (evicted) ++stats_.evicted;
  record = target;
  return Status::success();
}

// --- Attempt outcome ----------------------------------------------------------------------

Status JoinCandidates::apply_outcome(const JoinAttempt& attempt,
                                     const JoinAttemptOutcome outcome,
                                     const std::uint32_t retry_after_s,
                                     const MonotonicMs now_ms,
                                     EntropySource& entropy) noexcept {
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  if (!attempt_live(attempt)) return err(StatusCode::InvalidState, "join no live attempt");
  JoinCandidate* record = nullptr;
  for (auto& r : records_) {
    if (attempt_pinned(r)) {
      record = &r;
      break;
    }
  }
  if (record == nullptr) {
    attempt_ = JoinAttempt{};
    return err(StatusCode::InvalidState, "join attempt record lost");
  }
  // The attempt ends on every path below, including Pending (the neutral end
  // that changes no policy). The attempted path is kept aside first: the
  // failure belongs to the Attempt's MAC, never to a slot index.
  const MacAddress attempted_proxy = attempt_.proxy;
  attempt_ = JoinAttempt{};
  Status st = Status::success();
  bool clear_streak = true;
  switch (outcome) {
    case JoinAttemptOutcome::AllowVerified:
      record->policy = JoinCandidatePolicy::Untried;
      record->eligible_at_ms = now_ms;
      scan_failures_ = 0;
      break;
    case JoinAttemptOutcome::PendingAssignment:
      record->policy = JoinCandidatePolicy::Pending;
      record->eligible_at_ms = sat_add(now_ms, std::uint64_t{retry_after_s} * 1000);
      break;
    case JoinAttemptOutcome::AuthorityBusy:
      record->policy = JoinCandidatePolicy::Busy;
      record->eligible_at_ms = sat_add(now_ms, std::uint64_t{retry_after_s} * 1000);
      break;
    case JoinAttemptOutcome::DenyNotHere:
      record->policy = JoinCandidatePolicy::AvoidNotHere;
      record->eligible_at_ms = sat_add(now_ms, kJoinAvoidNotHereMs);
      break;
    case JoinAttemptOutcome::DenyBlocked:
    case JoinAttemptOutcome::MalformedResult:
    case JoinAttemptOutcome::AuthenticationFailed:
    case JoinAttemptOutcome::RemovedDenied:
      record->policy = JoinCandidatePolicy::AvoidBlocked;
      record->eligible_at_ms = sat_add(now_ms, kJoinAvoidBlockedMs);
      break;
    case JoinAttemptOutcome::RemovedVerified:
      *record = JoinCandidate{};
      return Status::success();
    case JoinAttemptOutcome::RemovedNoMembership:
      // Authenticated: the 600 s suppression stays, but the transient streak
      // and the failed-path memory reset with it — the next failure backs
      // off from k=0 again.
      record->policy = JoinCandidatePolicy::Transient;
      record->eligible_at_ms = sat_add(now_ms, kJoinSuppressNoMemberMs);
      break;
    case JoinAttemptOutcome::Failed: {
      const std::uint8_t k =
          record->failures < kJoinTransientMaxK ? record->failures : kJoinTransientMaxK;
      std::uint64_t delay_ms = kJoinTransientBaseMs;
      st = transient_delay(k, entropy, delay_ms);
      record->policy = JoinCandidatePolicy::Transient;
      record->eligible_at_ms = sat_add(now_ms, delay_ms);
      if (record->failures < 0xFF) ++record->failures;
      // Proxy slots may have been reused by OFFERs mid-attempt: remember and
      // suppress the MAC the exchange actually used, whatever the slots hold.
      failed_add(*record, attempted_proxy);
      for (auto& p : record->proxies) {
        if (p.present && p.mac == attempted_proxy) p.suppressed_until_ms = record->eligible_at_ms;
      }
      clear_streak = false;
      break;
    }
    case JoinAttemptOutcome::Pending:
    default:
      return Status::success();
  }
  if (clear_streak) {
    record->failures = 0;
    for (auto& f : record->failed_proxies) f = MacAddress{};  // reset path memory
  }
  return st;
}

void JoinCandidates::suppress_proxy(JoinCandidate& record, const MacAddress& proxy_mac,
                                    const std::uint32_t suppress_ms,
                                    const MonotonicMs now_ms) noexcept {
  if (!clock_ok(now_ms)) return;
  for (auto& p : record.proxies) {
    if (p.present && p.mac == proxy_mac) {
      const MonotonicMs until =
          sat_add(now_ms, std::min<std::uint64_t>(suppress_ms, kJoinBackoffMaxMs));
      if (until > p.suppressed_until_ms) p.suppressed_until_ms = until;
      ++stats_.proxy_suppressions;
    }
  }
}

// --- Scheduling ---------------------------------------------------------------------------

MonotonicMs JoinCandidates::next_eligible_ms(const MonotonicMs now_ms) noexcept {
  if (!clock_ok(now_ms)) return kJoinNoDeadline;
  MonotonicMs earliest = kJoinNoDeadline;
  for (const auto& r : records_) {
    if (!r.occupied) continue;
    const MonotonicMs eff = effective_eligible_at(r);
    if (eff > now_ms && eff < earliest) earliest = eff;
    if (hold_active(eff, now_ms)) continue;
    for (const auto& p : r.proxies) {
      if (proxy_fresh(p, now_ms) && p.authority_reachable && !p.proxy_busy &&
          p.suppressed_until_ms > now_ms && p.suppressed_until_ms < earliest) {
        earliest = p.suppressed_until_ms;
      }
    }
  }
  return earliest;
}

Status JoinCandidates::next_scan_deadline(const MonotonicMs now_ms, EntropySource& entropy,
                                          MonotonicMs& deadline) noexcept {
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  std::uint64_t delay_ms = kJoinTransientBaseMs;
  const Status st = transient_delay(scan_failures_, entropy, delay_ms);
  MonotonicMs d = sat_add(now_ms, delay_ms);
  const MonotonicMs earliest = next_eligible_ms(now_ms);
  if (earliest < d) d = earliest;
  const MonotonicMs cap = sat_add(now_ms, kJoinBackoffMaxMs);
  if (cap < d) d = cap;
  deadline = d;
  return st;
}

void JoinCandidates::note_scan_cycle_failed() noexcept {
  if (scan_failures_ < 0xFF) ++scan_failures_;
}

// --- DISCOVER avoid hints -----------------------------------------------------------------

std::size_t JoinCandidates::avoid_hints(const std::uint32_t org_hint, const MonotonicMs now_ms,
                                        std::array<std::uint32_t, kZtAvoidHints>& out) noexcept {
  out = {0, 0};
  if (!clock_ok(now_ms) || org_hint == 0) return 0;
  struct Entry {
    std::uint32_t hint{0};
    MonotonicMs until{0};
  };
  std::array<Entry, kJoinCandidateMax> entries{};
  std::size_t n = 0;
  for (const auto& r : records_) {
    if (!r.occupied || !avoid_policy(r.policy) || !hold_active(r.eligible_at_ms, now_ms) ||
        r.key.org_hint != org_hint || r.key.site_hint == 0) {
      continue;
    }
    const std::uint32_t h = r.key.site_hint;
    if (h == preferred_site_hint_ && org_hint == preferred_org_hint_) continue;
    bool ambiguous = false;
    for (const auto& o : records_) {
      if (&o == &r || !o.occupied || o.key.org_hint != org_hint || o.key.site_hint != h) {
        continue;
      }
      if (o.key == r.key) {
        // Same observation key: ambiguous only when authentication proved
        // two DIFFERENT sites behind it (a split) — sending the hint would
        // suppress the other, possibly eligible, site as well.
        if (r.site_id_authenticated && o.site_id_authenticated && o.site_id != r.site_id) {
          ambiguous = true;
        }
      } else {
        // A different key in the SAME org carrying the same hint makes the
        // value unresolvable inside that org's DISCOVER namespace.
        ambiguous = true;
      }
    }
    if (ambiguous) continue;
    bool dup = false;
    for (std::size_t i = 0; i < n; ++i) dup = dup || entries[i].hint == h;
    if (dup) continue;
    entries[n++] = Entry{h, r.eligible_at_ms};
  }
  // Latest expiry first, then hint order (insertion sort over <=8 entries).
  for (std::size_t i = 1; i < n; ++i) {
    const Entry e = entries[i];
    std::size_t j = i;
    while (j > 0 && (entries[j - 1].until < e.until ||
                     (entries[j - 1].until == e.until && entries[j - 1].hint > e.hint))) {
      entries[j] = entries[j - 1];
      --j;
    }
    entries[j] = e;
  }
  const std::size_t count = n < kZtAvoidHints ? n : kZtAvoidHints;
  for (std::size_t i = 0; i < count; ++i) out[i] = entries[i].hint;
  return count;
}

// --- Preferred / accessors ------------------------------------------------------------------

void JoinCandidates::set_preferred(const std::uint64_t site_id, const std::uint32_t org_hint,
                                   const std::uint32_t site_hint) noexcept {
  preferred_site_id_ = site_id;
  preferred_org_hint_ = org_hint;
  preferred_site_hint_ = site_hint;
  for (auto& r : records_) {
    if (r.occupied && r.site_id_authenticated) r.preferred = r.site_id == site_id;
  }
}

std::uint32_t JoinCandidates::preferred_hint(const std::uint32_t org_hint) const noexcept {
  return org_hint == preferred_org_hint_ ? preferred_site_hint_ : 0;
}

const JoinCandidate* JoinCandidates::find(const JoinCandidateKey& key) const noexcept {
  for (const auto& r : records_) {
    if (r.occupied && r.key == key) return &r;
  }
  return nullptr;
}

JoinCandidate* JoinCandidates::find(const JoinCandidateKey& key) noexcept {
  for (auto& r : records_) {
    if (r.occupied && r.key == key) return &r;
  }
  return nullptr;
}

std::size_t JoinCandidates::size() const noexcept {
  std::size_t n = 0;
  for (const auto& r : records_) n += r.occupied ? 1 : 0;
  return n;
}

}  // namespace routeloom::sdkv1
