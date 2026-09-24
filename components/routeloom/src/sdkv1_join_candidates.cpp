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

// Proxy quality: hops asc (255 unknown last), RSSI desc, MAC lex asc.
bool proxy_better(const JoinCandidateProxy& a, const JoinCandidateProxy& b) noexcept {
  if (a.authority_hops != b.authority_hops) return a.authority_hops < b.authority_hops;
  if (a.rssi != b.rssi) return a.rssi > b.rssi;
  for (std::size_t i = 0; i < a.mac.size(); ++i) {
    if (a.mac[i] != b.mac[i]) return a.mac[i] < b.mac[i];
  }
  return false;
}

bool obs_better(const JoinProxyObservation& a, const JoinCandidateProxy& b) noexcept {
  if (a.authority_hops != b.authority_hops) return a.authority_hops < b.authority_hops;
  if (a.rssi != b.rssi) return a.rssi > b.rssi;
  for (std::size_t i = 0; i < a.mac.size(); ++i) {
    if (a.mac[i] != b.mac[i]) return a.mac[i] < b.mac[i];
  }
  return false;
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

}  // namespace

// --- Clock ---------------------------------------------------------------------------

bool JoinCandidates::clock_ok(const MonotonicMs now_ms) noexcept {
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
         p.suppressed_until_ms <= now;
}

const JoinCandidateProxy* JoinCandidates::best_proxy(const JoinCandidate& record,
                                                     const MonotonicMs now) noexcept {
  const JoinCandidateProxy* best = nullptr;
  for (const auto& p : record.proxies) {
    if (!proxy_usable(p, now)) continue;
    if (best == nullptr || proxy_better(p, *best)) best = &p;
  }
  return best;
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

// Selection order (design §5.1 rule 4): preferred, untried, hops asc,
// RSSI desc, oldest attempt, key/MAC lexicographic.
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

JoinCandidate* JoinCandidates::find_mutable(const JoinCandidateKey& key,
                                            const std::uint64_t site_id,
                                            const bool authenticated) noexcept {
  for (auto& r : records_) {
    if (r.occupied && r.key == key && r.site_id_authenticated == authenticated &&
        (!authenticated || r.site_id == site_id)) {
      return &r;
    }
  }
  return nullptr;
}

// Empty slot first, else the stalest unprotected untried/transient record;
// never evict a record mid-attempt or under an unexpired hold (§5.1 rule 3).
JoinCandidate* JoinCandidates::acquire(const MonotonicMs now_ms, bool& evicted) noexcept {
  evicted = false;
  JoinCandidate* victim = nullptr;
  for (auto& r : records_) {
    if (!r.occupied) return &r;
    const bool evictable =
        !r.selected && r.eligible_at_ms <= now_ms &&
        (r.policy == JoinCandidatePolicy::Untried || r.policy == JoinCandidatePolicy::Transient);
    if (evictable && (victim == nullptr || r.last_seen_ms < victim->last_seen_ms)) victim = &r;
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
  } else if (worst != nullptr && obs_better(o, *worst)) {
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

// --- Authentication binding -------------------------------------------------------------

Status JoinCandidates::bind_authenticated(const JoinCandidateKey& key,
                                          const std::uint64_t site_id,
                                          const MonotonicMs now_ms,
                                          JoinCandidate*& record) noexcept {
  record = nullptr;
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  if (site_id == 0) return invalid("join bind site id");
  JoinCandidate* unbound = nullptr;
  JoinCandidate* colliding = nullptr;
  for (auto& r : records_) {
    if (!r.occupied || !(r.key == key)) continue;
    if (r.site_id_authenticated) {
      if (r.site_id == site_id) {
        record = &r;
        return Status::success();
      }
      if (colliding == nullptr) colliding = &r;
    } else if (unbound == nullptr) {
      unbound = &r;
    }
  }
  JoinCandidate* target = unbound;
  if (target == nullptr && colliding != nullptr) {
    // Hint collision resolved by authentication: the key stays on the old
    // record; the newly proven site_id needs a second record (§5.2). Full
    // table -> the attempt aborts rather than conflating two sites.
    bool evicted = false;
    target = acquire(now_ms, evicted);
    if (target == nullptr) {
      ++stats_.auth_split_failed;
      ++stats_.dropped_no_capacity;
      return err(StatusCode::NoCapacity, "join split capacity");
    }
    *target = *colliding;  // same observed evidence under one key
    target->site_id = 0;
    target->site_id_authenticated = false;
    target->policy = JoinCandidatePolicy::Untried;
    target->eligible_at_ms = 0;
    target->last_attempt_ms = 0;
    target->failures = 0;
    target->preferred = false;
    target->selected = false;
    target->attempted_proxy = -1;
    ++stats_.auth_splits;
    if (evicted) ++stats_.evicted;
  } else if (target == nullptr) {
    // Never observed: keep the binding anyway (defensive; observe() should
    // have inserted the key before an attempt was made on it).
    bool evicted = false;
    target = acquire(now_ms, evicted);
    if (target == nullptr) {
      ++stats_.dropped_no_capacity;
      return err(StatusCode::NoCapacity, "join bind capacity");
    }
    target->occupied = true;
    target->key = key;
    target->last_seen_ms = now_ms;
    if (evicted) ++stats_.evicted;
  }
  target->site_id = site_id;
  target->site_id_authenticated = true;
  target->preferred = site_id == preferred_site_id_;
  record = target;
  return Status::success();
}

// --- Attempt bookkeeping -----------------------------------------------------------------

void JoinCandidates::mark_attempt(JoinCandidate& record, const std::uint8_t proxy_index,
                                  const MonotonicMs now_ms) noexcept {
  if (!clock_ok(now_ms) || !record.occupied) return;
  record.selected = true;
  record.last_attempt_ms = now_ms;
  record.attempted_proxy = proxy_index < kJoinCandidateProxyMax ? proxy_index : -1;
}

void JoinCandidates::suppress_proxy(JoinCandidate& record, const MacAddress& proxy_mac,
                                    const std::uint32_t suppress_ms,
                                    const MonotonicMs now_ms) noexcept {
  if (!clock_ok(now_ms)) return;
  for (auto& p : record.proxies) {
    if (p.present && p.mac == proxy_mac) {
      p.suppressed_until_ms = sat_add(now_ms, std::min<std::uint64_t>(suppress_ms, kJoinBackoffMaxMs));
      ++stats_.proxy_suppressions;
    }
  }
}

Status JoinCandidates::apply_outcome(JoinCandidate& record, const JoinAttemptOutcome outcome,
                                     const std::uint32_t retry_after_s,
                                     const MonotonicMs now_ms, EntropySource& entropy) noexcept {
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  if (!record.occupied) return err(StatusCode::InvalidState, "join outcome on empty record");
  record.selected = false;
  Status st = Status::success();
  bool clear_streak = true;
  switch (outcome) {
    case JoinAttemptOutcome::AllowVerified:
      record.policy = JoinCandidatePolicy::Untried;
      record.eligible_at_ms = now_ms;
      scan_failures_ = 0;
      break;
    case JoinAttemptOutcome::PendingAssignment:
      record.policy = JoinCandidatePolicy::Pending;
      record.eligible_at_ms = sat_add(now_ms, std::uint64_t{retry_after_s} * 1000);
      break;
    case JoinAttemptOutcome::AuthorityBusy:
      record.policy = JoinCandidatePolicy::Busy;
      record.eligible_at_ms = sat_add(now_ms, std::uint64_t{retry_after_s} * 1000);
      break;
    case JoinAttemptOutcome::DenyNotHere:
      record.policy = JoinCandidatePolicy::AvoidNotHere;
      record.eligible_at_ms = sat_add(now_ms, kJoinAvoidNotHereMs);
      break;
    case JoinAttemptOutcome::DenyBlocked:
    case JoinAttemptOutcome::MalformedResult:
    case JoinAttemptOutcome::AuthenticationFailed:
    case JoinAttemptOutcome::RemovedDenied:
      record.policy = JoinCandidatePolicy::AvoidBlocked;
      record.eligible_at_ms = sat_add(now_ms, kJoinAvoidBlockedMs);
      break;
    case JoinAttemptOutcome::RemovedVerified:
      record = JoinCandidate{};
      return Status::success();
    case JoinAttemptOutcome::RemovedNoMembership:
      record.policy = JoinCandidatePolicy::Transient;
      record.eligible_at_ms = sat_add(now_ms, kJoinSuppressNoMemberMs);
      clear_streak = false;  // suppression, not a path failure
      break;
    case JoinAttemptOutcome::Failed: {
      const std::uint8_t k =
          record.failures < kJoinTransientMaxK ? record.failures : kJoinTransientMaxK;
      std::uint64_t delay_ms = kJoinTransientBaseMs;
      st = transient_delay(k, entropy, delay_ms);
      record.policy = JoinCandidatePolicy::Transient;
      record.eligible_at_ms = sat_add(now_ms, delay_ms);
      if (record.failures < 0xFF) ++record.failures;
      if (record.attempted_proxy >= 0 &&
          record.attempted_proxy < static_cast<std::int8_t>(kJoinCandidateProxyMax)) {
        record.proxies[record.attempted_proxy].suppressed_until_ms = record.eligible_at_ms;
      }
      clear_streak = false;
      break;
    }
    case JoinAttemptOutcome::Pending:
    default:
      record.attempted_proxy = -1;
      return Status::success();
  }
  if (clear_streak) record.failures = 0;
  record.attempted_proxy = -1;
  return st;
}

// --- Selection --------------------------------------------------------------------------

Status JoinCandidates::select(const MonotonicMs now_ms, JoinSelect& out) noexcept {
  out = JoinSelect{};
  if (!clock_ok(now_ms)) return err(StatusCode::TimeUncertain, "join clock regression");
  const JoinCandidate* best_c = nullptr;
  const JoinCandidateProxy* best_p = nullptr;
  for (const auto& r : records_) {
    if (!r.occupied || effective_eligible_at(r) > now_ms) continue;
    const JoinCandidateProxy* p = best_proxy(r, now_ms);
    if (p == nullptr) continue;
    if (best_c == nullptr || better(r, *p, *best_c, *best_p)) {
      best_c = &r;
      best_p = p;
    }
  }
  out.candidate = best_c;
  out.proxy = best_p;
  if (best_c != nullptr) {
    ++stats_.selections;
  } else {
    ++stats_.selections_empty;
  }
  return Status::success();
}

MonotonicMs JoinCandidates::next_eligible_ms(const MonotonicMs now_ms) noexcept {
  if (!clock_ok(now_ms)) return kJoinNoDeadline;
  MonotonicMs earliest = kJoinNoDeadline;
  for (const auto& r : records_) {
    if (!r.occupied) continue;
    const MonotonicMs eff = effective_eligible_at(r);
    if (eff > now_ms && eff < earliest) earliest = eff;
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
    if (!r.occupied || !avoid_policy(r.policy) || r.eligible_at_ms <= now_ms ||
        r.key.org_hint != org_hint || r.key.site_hint == 0) {
      continue;
    }
    const std::uint32_t h = r.key.site_hint;
    if (h == preferred_site_hint_ && org_hint == preferred_org_hint_) continue;
    bool ambiguous = false;
    for (const auto& o : records_) {
      // The same key (e.g. an authenticated split) is the same observation;
      // a different key in the SAME org carrying the same hint makes the
      // value unresolvable inside that org's DISCOVER namespace.
      if (o.occupied && !(o.key == r.key) && o.key.org_hint == org_hint &&
          o.key.site_hint == h) {
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

std::size_t JoinCandidates::size() const noexcept {
  std::size_t n = 0;
  for (const auto& r : records_) n += r.occupied ? 1 : 0;
  return n;
}

}  // namespace routeloom::sdkv1
