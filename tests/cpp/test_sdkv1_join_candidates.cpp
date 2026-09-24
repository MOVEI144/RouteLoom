// SDK v1 zero-touch join candidate table (plan P3-4 PR 2,
// sdkv1_join_candidates.hpp). Table-driven coverage of the 8-record
// observation/avoid views: bounded insertion and protected records, the
// hint-collision split by authenticated site_id, the atomic select-and-begin,
// site-wide holds, MAC-keyed failed-path memory, the selection order, policy
// timers (6 h / 24 h / retry_after / transient backoff), DISCOVER avoid
// hints, the multi-anchor scan cursor, clock regression and the
// entropy-failure floor. The J04/J05 selection halves: a strong OFFER that
// denies is never retried early while a weaker assigned site is selected.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "routeloom/sdkv1_join_candidates.hpp"

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,      \
                   current.c_str(), #expr);                                          \
      ++failures;                                                                    \
    }                                                                                \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;

// --- Deterministic entropy -------------------------------------------------------------
class TestEntropy final : public routeloom::EntropySource {
 public:
  explicit TestEntropy(const std::uint64_t seed) : state_(seed | 1) {}
  Status fill(const MutableByteView out) noexcept override {
    if (fail_next) {
      fail_next = false;
      return Status::error(StatusCode::InternalError, "injected entropy failure");
    }
    for (std::size_t i = 0; i < out.size; ++i) {
      state_ ^= state_ << 13U;
      state_ ^= state_ >> 7U;
      state_ ^= state_ << 17U;
      out.data[i] = static_cast<std::uint8_t>(state_ >> 32U);
    }
    return Status::success();
  }
  bool fail_next{false};

 private:
  std::uint64_t state_;
};

TestEntropy entropy(0xC0FFEE);
TestEntropy entropy2(0xBADC0DE);

JoinCandidateKey key(const std::uint32_t org, const std::uint32_t site,
                     const std::uint32_t net) {
  JoinCandidateKey k{};
  k.org_hint = org;
  k.site_hint = site;
  k.network_low32 = net;
  return k;
}

MacAddress mac(const std::uint8_t last) {
  MacAddress m{0x02, 0x00, 0x00, 0x00, 0x00, last};
  return m;
}

JoinProxyObservation obs(const std::uint8_t mac_last, const std::uint64_t node,
                         const std::uint8_t channel, const std::int16_t rssi,
                         const std::uint8_t hops, const bool reachable = true,
                         const bool busy = false) {
  JoinProxyObservation o{};
  o.mac = mac(mac_last);
  o.node = node;
  o.channel = channel;
  o.rssi = rssi;
  o.authority_hops = hops;
  o.authority_reachable = reachable;
  o.proxy_busy = busy;
  return o;
}

JoinObserve offer(JoinCandidates& t, const std::uint32_t org, const std::uint32_t site,
                  const std::uint32_t net, const std::uint8_t mac_last,
                  const std::int16_t rssi, const std::uint8_t hops,
                  const MonotonicMs now) {
  return t.observe(key(org, site, net),
                   obs(mac_last, 0x1000 + mac_last, 1, rssi, hops), now);
}

struct Begun {
  JoinAttempt attempt{};
  JoinSelect sel{};
};

// Selects and begins; the attempt must end (apply_outcome) before the next.
Begun begin(JoinCandidates& t, const MonotonicMs now) {
  Begun b{};
  const Status st = t.select_and_begin(now, b.attempt, b.sel);
  CHECK(st.ok());
  CHECK(b.attempt.active);
  CHECK(b.sel.candidate != nullptr && b.sel.proxy.present);
  return b;
}

Status finish(JoinCandidates& t, const JoinAttempt& a, const JoinAttemptOutcome outcome,
              const std::uint32_t retry_after_s, const MonotonicMs now, TestEntropy& e) {
  const Status st = t.apply_outcome(a, outcome, retry_after_s, now, e);
  CHECK(st.ok());
  CHECK(!t.attempt().active);
  return st;
}

void cancel(JoinCandidates& t, const JoinAttempt& a, const MonotonicMs now) {
  finish(t, a, JoinAttemptOutcome::Pending, 0, now, entropy);
}

// Peeks at the winner without leaving an attempt behind. Note the begin
// stamps last_attempt_ms, so consecutive peeks can differ from one pure
// selection — each peek below asserts only its own winner.
JoinSelect peek(JoinCandidates& t, const MonotonicMs now) {
  JoinAttempt a{};
  JoinSelect s{};
  const Status st = t.select_and_begin(now, a, s);
  if (!st.ok()) {
    CHECK(st.code == StatusCode::NotFound);
    return JoinSelect{};
  }
  cancel(t, a, now);
  return s;
}

JoinCandidate* record_of(JoinCandidates& t, const JoinCandidateKey& k) {
  return t.find(k);
}

bool failed_has(const JoinCandidate& r, const MacAddress& m) {
  for (const auto& f : r.failed_proxies) {
    if (f == m) return true;
  }
  return false;
}

bool failed_empty(const JoinCandidate& r) {
  for (const auto& f : r.failed_proxies) {
    if (!(f == MacAddress{})) return false;
  }
  return true;
}

// --- Cases -----------------------------------------------------------------------------

void observe_insert_select() {
  JoinCandidates t;
  CHECK(t.size() == 0);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  CHECK(t.size() == 1);
  const JoinSelect s = peek(t, 1000);
  CHECK(s.candidate != nullptr && s.candidate->key == key(7, 42, 0xA5));
  CHECK(s.proxy.present && s.proxy.mac == mac(1));
  // Second OFFER refreshes evidence; policy untouched.
  CHECK(offer(t, 7, 42, 0xA5, 2, -40, 0, 2000) == JoinObserve::Updated);
  const JoinSelect s2 = peek(t, 2000);
  CHECK(s2.proxy.present && s2.proxy.mac == mac(2));  // hops 0 beats hops 1
}

void offer_never_releases_policy() {
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  const Begun b = begin(t, 1100);
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyNotHere, 0, 1100, entropy).ok());
  CHECK(!t.attempt().active);
  const JoinCandidate* r = record_of(t, key(7, 42, 0xA5));
  CHECK(r != nullptr && r->policy == JoinCandidatePolicy::AvoidNotHere);
  // A new OFFER refreshes evidence only — the 6 h hold stays (design §5.1
  // rule 2: OFFERs never reset unexpired policies, and never a cooldown).
  CHECK(offer(t, 7, 42, 0xA5, 1, -30, 0, 2000) == JoinObserve::Updated);
  CHECK(peek(t, 2000).candidate == nullptr);
  CHECK(r->policy == JoinCandidatePolicy::AvoidNotHere);
}

void j04_deny_then_other_site() {
  // V1-J04 selection half: strong A denies -> B tried; A stays avoided for
  // the full 6 h, hints on the wire, then A is eligible again.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -30, 0, 1000) == JoinObserve::Inserted);  // A strong
  CHECK(offer(t, 7, 43, 0xA5, 2, -70, 2, 1000) == JoinObserve::Inserted);  // B weaker
  const Begun a = begin(t, 1100);
  CHECK(a.sel.candidate->key.site_hint == 42);
  CHECK(t.apply_outcome(a.attempt, JoinAttemptOutcome::DenyNotHere, 0, 1200, entropy).ok());
  const Begun b = begin(t, 1200);
  CHECK(b.sel.candidate != nullptr && b.sel.candidate->key.site_hint == 43);
  // B tries too — denied harder (24 h); nothing eligible meanwhile.
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1300, entropy).ok());
  CHECK(peek(t, 1400).candidate == nullptr);
  // A is in the avoid hints for this org.
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, 1400, hints) == 2);
  // 6 h - 1 ms: still not eligible even with a fresh route.
  const MonotonicMs almost = 1200 + kJoinAvoidNotHereMs - 1;
  CHECK(offer(t, 7, 42, 0xA5, 1, -20, 0, almost - 10) == JoinObserve::Updated);
  CHECK(peek(t, almost).candidate == nullptr);
  // 6 h elapsed with a fresh route: A is eligible again (B still blocked).
  const MonotonicMs after = 1200 + kJoinAvoidNotHereMs;
  CHECK(offer(t, 7, 42, 0xA5, 1, -20, 0, after) == JoinObserve::Updated);
  const JoinSelect s2 = peek(t, after);
  CHECK(s2.candidate != nullptr && s2.candidate->key.site_hint == 42);
}

void j05_pending_retry_after() {
  // V1-J05 selection half: pending site is retried exactly at retry_after,
  // never earlier; an avoided site never competes meanwhile.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -30, 0, 1000) == JoinObserve::Inserted);  // A
  CHECK(offer(t, 7, 43, 0xA5, 2, -40, 1, 1000) == JoinObserve::Inserted);  // B assigned
  const Begun a = begin(t, 1100);
  CHECK(a.sel.candidate->key.site_hint == 42);
  CHECK(t.apply_outcome(a.attempt, JoinAttemptOutcome::DenyNotHere, 0, 1200, entropy).ok());
  const Begun b = begin(t, 1300);
  CHECK(b.sel.candidate->key.site_hint == 43);
  CHECK(
      t.apply_outcome(b.attempt, JoinAttemptOutcome::PendingAssignment, 30, 1300, entropy).ok());
  const JoinCandidate* r = record_of(t, key(7, 43, 0xA5));
  CHECK(r->policy == JoinCandidatePolicy::Pending);
  CHECK(r->eligible_at_ms == 1300 + 30000);
  CHECK(peek(t, 1400).candidate == nullptr);
  CHECK(peek(t, 31299).candidate == nullptr);                // 1 ms early
  const JoinSelect s = peek(t, 31300);                       // exactly retry_after
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 43);
}

void ordering() {
  JoinCandidates t;
  // Untried beats transient-eligible; among untried, hops asc decides.
  CHECK(offer(t, 7, 10, 0xA5, 1, -50, 2, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 11, 0xA5, 2, -50, 1, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 12, 0xA5, 3, -50, 3, 1000) == JoinObserve::Inserted);
  JoinSelect s = peek(t, 1000);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 11);  // hops 1
  // Transient-failed but expired record loses to a never-tried one.
  const Begun b11 = begin(t, 1100);
  CHECK(b11.sel.candidate->key.site_hint == 11);
  CHECK(t.apply_outcome(b11.attempt, JoinAttemptOutcome::Failed, 0, 1200, entropy).ok());
  const JoinCandidate* r11 = record_of(t, key(7, 11, 0xA5));
  const MonotonicMs after = r11->eligible_at_ms + 10;
  CHECK(offer(t, 7, 10, 0xA5, 1, -50, 2, after - 5) == JoinObserve::Updated);
  s = peek(t, after);
  // r10 (untried, hops2) vs r12 (untried, hops3) vs r11 (transient, hops1):
  // untried first, then hops -> r10.
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 10);
  // Same quality: oldest last_attempt wins (0 = never tried).
  JoinCandidates t2;
  CHECK(offer(t2, 7, 20, 0xA5, 1, -40, 2, 1000) == JoinObserve::Inserted);
  CHECK(offer(t2, 7, 21, 0xA5, 2, -40, 2, 1000) == JoinObserve::Inserted);
  s = peek(t2, 1000);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 20);  // key order
  // The peek stamped r20=1000, so the older r21 (0) wins the real attempt.
  const Begun b21 = begin(t2, 1500);
  CHECK(b21.sel.candidate->key.site_hint == 21);
  CHECK(t2.apply_outcome(b21.attempt, JoinAttemptOutcome::AllowVerified, 0, 1500, entropy).ok());
  s = peek(t2, 1600);
  // Equal hops/RSSI: r21 attempted at 1500, r20 at 1000 -> older wins.
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 20);
  // Preferred membership outranks everything.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 30, 0xA5, 1, -30, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t3, 7, 31, 0xA5, 2, -60, 4, 1000) == JoinObserve::Inserted);
  JoinCandidate* r30 = record_of(t3, key(7, 30, 0xA5));
  t3.suppress_proxy(*r30, mac(1), 600000, 1000);  // let the weaker site bind first
  const Begun b31 = begin(t3, 1100);
  CHECK(b31.sel.candidate->key.site_hint == 31);
  JoinCandidate* r31 = nullptr;
  CHECK(t3.bind_authenticated(b31.attempt, 0xAAAA, 1100, r31).ok());
  t3.set_preferred(0xAAAA, 7, 31);
  CHECK(r31->preferred);
  cancel(t3, b31.attempt, 1100);
  // Past the suppression with fresh evidence on both: preferred wins over
  // the better (hops 0) route.
  CHECK(offer(t3, 7, 30, 0xA5, 1, -30, 0, 601001) == JoinObserve::Updated);
  CHECK(offer(t3, 7, 31, 0xA5, 2, -60, 4, 601001) == JoinObserve::Updated);
  s = peek(t3, 601001);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 31);
}

void freshness_and_flags() {
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  // Evidence older than 60 s is stale: not eligible.
  CHECK(peek(t, 1000 + kJoinOfferFreshMs).candidate != nullptr);
  CHECK(peek(t, 1000 + kJoinOfferFreshMs + 1).candidate == nullptr);
  // Flags gate: unreachable or busy proxies never satisfy eligibility.
  JoinCandidates t2;
  CHECK(t2.observe(key(7, 1, 0xA5), obs(1, 0x1001, 1, -30, 0, false, false), 1000) ==
        JoinObserve::Inserted);
  CHECK(peek(t2, 1000).candidate == nullptr);
  CHECK(t2.observe(key(7, 1, 0xA5), obs(1, 0x1001, 1, -30, 0, true, true), 2000) ==
        JoinObserve::Updated);
  CHECK(peek(t2, 2000).candidate == nullptr);
  // Second usable proxy keeps the site eligible.
  CHECK(t2.observe(key(7, 1, 0xA5), obs(2, 0x1002, 1, -40, 1, true, false), 3000) ==
        JoinObserve::Updated);
  const JoinSelect s = peek(t2, 3000);
  CHECK(s.proxy.present && s.proxy.mac == mac(2));
}

void proxy_best_two() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 5, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 4, true), 1000) == JoinObserve::Updated);
  // A better third observation evicts the worse stored proxy.
  CHECK(t.observe(k, obs(3, 0x1003, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  const JoinCandidate* r = t.find(k);
  int present = 0;
  bool have1 = false, have2 = false, have3 = false;
  for (const auto& p : r->proxies) {
    present += p.present ? 1 : 0;
    have1 = have1 || (p.present && p.mac == mac(1));
    have2 = have2 || (p.present && p.mac == mac(2));
    have3 = have3 || (p.present && p.mac == mac(3));
  }
  CHECK(present == 2 && !have1 && have2 && have3);  // worst (hops 5) dropped
  // A worse fourth observation is dropped while evidence is fresh.
  CHECK(t.observe(k, obs(4, 0x1004, 1, -50, 9, true), 2000) == JoinObserve::Updated);
  r = t.find(k);
  have3 = false;
  for (const auto& p : r->proxies) have3 = have3 || (p.present && p.mac == mac(3));
  CHECK(have3);
  // Once stored evidence is stale, a fresh observation displaces the worse
  // of the two stale entries — a live route is never dropped for a dead one.
  const MonotonicMs later = 2000 + kJoinOfferFreshMs + 10;
  CHECK(t.observe(k, obs(4, 0x1004, 1, -50, 9, true), later) == JoinObserve::Updated);
  r = t.find(k);
  have2 = have3 = false;
  bool have4 = false;
  for (const auto& p : r->proxies) {
    have2 = have2 || (p.present && p.mac == mac(2));
    have3 = have3 || (p.present && p.mac == mac(3));
    have4 = have4 || (p.present && p.mac == mac(4));
  }
  CHECK(have4 && have3 && !have2);  // worse stale proxy (hops 4) displaced
}

void suppress_and_fail() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  // RelayStatus busy on the best proxy: the other is picked next (§5.1 r5).
  JoinCandidate* r = record_of(t, k);
  t.suppress_proxy(*r, mac(1), 5000, 1000);  // mac1 held until 6000
  JoinSelect s = peek(t, 1000);
  CHECK(s.proxy.present && s.proxy.mac == mac(2));
  // Both suppressed -> site not eligible until the hold passes.
  t.suppress_proxy(*r, mac(2), 4000, 1000);  // mac2 held until 5000
  CHECK(peek(t, 1000).candidate == nullptr);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 5001) == JoinObserve::Updated);
  s = peek(t, 5001);
  CHECK(s.candidate != nullptr && s.proxy.mac == mac(2));  // mac1 still held
  s = peek(t, 6001);
  CHECK(s.candidate != nullptr && s.proxy.mac == mac(1));  // 5 s hold over
  // Transient failure: policy Transient, backoff in [1000,1250], the
  // attempted proxy suppressed to the same instant.
  const Begun b1 = begin(t, 6100);
  CHECK(b1.sel.proxy.mac == mac(1));
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, 6100, entropy).ok());
  r = record_of(t, k);
  CHECK(r->policy == JoinCandidatePolicy::Transient);
  CHECK(r->eligible_at_ms >= 7100 && r->eligible_at_ms <= 7350);
  CHECK(r->failures == 1);
  CHECK(failed_has(*r, mac(1)));
  CHECK(r->proxies[0].suppressed_until_ms == r->eligible_at_ms);
  // The next attempt takes the untried alternate; its failure widens the
  // bound: base 2000 -> [2000,2500].
  const Begun b2 = begin(t, r->eligible_at_ms);
  CHECK(b2.sel.proxy.mac == mac(2));
  const MonotonicMs was = r->eligible_at_ms;
  CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::Failed, 0, was, entropy).ok());
  CHECK(r->failures == 2);
  CHECK(r->eligible_at_ms >= was + 2000 && r->eligible_at_ms <= was + 2500);
  CHECK(failed_has(*r, mac(2)));
  // k saturates at 10 -> base pinned at the 600 s cap, delay flat. Floored
  // entropy keeps the chained times exact; each hold is awaited because a
  // new attempt needs an eligible record.
  JoinCandidates t3;
  TestEntropy sat(0xBADC0DE);
  const JoinCandidateKey k3 = key(7, 1, 0xA5);
  CHECK(t3.observe(k3, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  MonotonicMs now = 2000;
  MonotonicMs t11 = 0, d11 = 0, d12 = 0;
  for (int i = 1; i <= 12; ++i) {
    CHECK(t3.observe(k3, obs(1, 0x1001, 1, -50, 0, true), now) == JoinObserve::Updated);
    JoinAttempt a{};
    JoinSelect sl{};
    CHECK(t3.select_and_begin(now, a, sl).ok());
    sat.fail_next = true;
    const Status fst = t3.apply_outcome(a, JoinAttemptOutcome::Failed, 0, now, sat);
    if (i <= 10) {
      CHECK(!fst.ok());  // the entropy failure surfaces...
    } else {
      CHECK(fst.ok());  // ... unless the spread is already zero at the cap
    }
    CHECK(!t3.attempt().active);  // ... but the outcome still lands either way
    const JoinCandidate* r3 = t3.find(k3);
    if (i == 11) {
      t11 = now;
      d11 = r3->eligible_at_ms;
    }
    if (i == 12) d12 = r3->eligible_at_ms;
    now = r3->eligible_at_ms;
  }
  const JoinCandidate* r3 = t3.find(k3);
  CHECK(r3->policy == JoinCandidatePolicy::Transient);
  CHECK(r3->failures == 12);
  // Floored chain: t11 = 2000 + (1000+...+512000), then the 600 s cap twice.
  CHECK(t11 == 1025000 && d11 == 1625000 && d12 == 2225000);
  CHECK(t3.stats().entropy_failures == 10);
}

void authenticated_outcomes() {
  // AuthorityBusy: wire retry_after taken as-is (never folded into 600 s).
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1100);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::AuthorityBusy, 3600, 1100, entropy)
              .ok());
    const JoinCandidate* r = record_of(t, key(7, 42, 0xA5));
    CHECK(r->policy == JoinCandidatePolicy::Busy);
    CHECK(r->eligible_at_ms == 1100 + 3600000);
  }
  // DenyBlocked -> 24 h.
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1200);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1200, entropy).ok());
    const JoinCandidate* r = record_of(t, key(7, 42, 0xA5));
    CHECK(r->policy == JoinCandidatePolicy::AvoidBlocked);
    CHECK(r->eligible_at_ms == 1200 + kJoinAvoidBlockedMs);
  }
  // MalformedResult -> 24 h on the authenticated record.
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1300);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::MalformedResult, 0, 1300, entropy).ok());
    const JoinCandidate* r = record_of(t, key(7, 42, 0xA5));
    CHECK(r->eligible_at_ms == 1300 + kJoinAvoidBlockedMs);
  }
  // AuthenticationFailed -> 24 h on the observed key.
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1400);
    CHECK(
        t.apply_outcome(b.attempt, JoinAttemptOutcome::AuthenticationFailed, 0, 1400, entropy)
            .ok());
    const JoinCandidate* r = record_of(t, key(7, 42, 0xA5));
    CHECK(r->eligible_at_ms == 1400 + kJoinAvoidBlockedMs);
  }
  // Removed without membership evidence -> 600 s suppression, streak reset.
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1100);
    CHECK(
        t.apply_outcome(b.attempt, JoinAttemptOutcome::RemovedNoMembership, 0, 1100, entropy)
            .ok());
    const JoinCandidate* r = record_of(t, key(7, 1, 0xA5));
    CHECK(r->policy == JoinCandidatePolicy::Transient);
    CHECK(r->eligible_at_ms == 1100 + kJoinSuppressNoMemberMs);
    CHECK(r->failures == 0);
    CHECK(failed_empty(*r));
  }
  // Verified removal evicts the record entirely.
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1200);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::RemovedVerified, 0, 1200, entropy).ok());
    CHECK(t.find(key(7, 1, 0xA5)) == nullptr);
    CHECK(t.size() == 0);
  }
  // Allow clears the streak and the scan cycle counter.
  {
    JoinCandidates t;
    CHECK(offer(t, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
    const Begun b = begin(t, 1100);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::Failed, 0, 1100, entropy).ok());
    const JoinCandidate* r = record_of(t, key(7, 1, 0xA5));
    CHECK(r->failures == 1);
    for (int i = 0; i < 12; ++i) t.note_scan_cycle_failed();
    MonotonicMs d = 0;
    // Saturated cycle backoff loses to the record's near transient retry.
    CHECK(t.next_scan_deadline(2000, entropy2, d).ok());
    CHECK(d == r->eligible_at_ms);
    const Begun b2 = begin(t, r->eligible_at_ms);
    const MonotonicMs at = r->eligible_at_ms;
    CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::AllowVerified, 0, at, entropy).ok());
    CHECK(r->policy == JoinCandidatePolicy::Untried && r->failures == 0);
    CHECK(failed_empty(*r));
    CHECK(t.next_scan_deadline(at, entropy2, d).ok());
    CHECK(d <= at + 1250);  // cycle counter reset by success
    CHECK(peek(t, at).candidate != nullptr);
  }
}

void capacity_and_protection() {
  JoinCandidates t;
  // Fill all 8 with protected records: 4 avoided, 2 pending, 1 busy, 1
  // in-flight attempt. Winners come in key order: identical quality, all
  // last_attempt 0, then the next key once the winner holds.
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000) ==
          JoinObserve::Inserted);
  }
  for (std::uint32_t i = 1; i <= 4; ++i) {
    const Begun b = begin(t, 1100);
    CHECK(b.sel.candidate->key.site_hint == i);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  }
  for (std::uint32_t i = 5; i <= 6; ++i) {
    const Begun b = begin(t, 1100);
    CHECK(b.sel.candidate->key.site_hint == i);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::PendingAssignment, 60, 1100, entropy)
              .ok());
  }
  {
    const Begun b = begin(t, 1100);
    CHECK(b.sel.candidate->key.site_hint == 7);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::AuthorityBusy, 60, 1100, entropy).ok());
  }
  const Begun held = begin(t, 1100);
  CHECK(held.sel.candidate->key.site_hint == 8);
  // All protected (7 held + 1 pinned by the live attempt): the 9th site is
  // dropped, counted, and nothing is evicted.
  CHECK(offer(t, 7, 9, 0xA5, 9, -20, 0, 1200) == JoinObserve::NoCapacity);
  CHECK(t.size() == 8);
  CHECK(t.stats().dropped_no_capacity == 1);
  cancel(t, held.attempt, 1200);
  // Now a table of untried/transient records: the stalest is replaced. Site
  // 3 wins first (hops 0) and takes the transient failure; site 1 keeps the
  // stalest observation.
  JoinCandidates t2;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    const std::uint8_t hops = i == 3 ? 0 : 1;
    CHECK(offer(t2, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, hops, 1000 + i) ==
          JoinObserve::Inserted);
  }
  const Begun b3 = begin(t2, 2000);
  CHECK(b3.sel.candidate->key.site_hint == 3);
  CHECK(t2.apply_outcome(b3.attempt, JoinAttemptOutcome::Failed, 0, 2000, entropy).ok());
  const MonotonicMs evictable_deadline = record_of(t2, key(7, 3, 0xA5))->eligible_at_ms;
  // Site 1 has the stalest observation (t=1001); site 3 is transient but its
  // hold expired -> both evictable; the stalest last_seen is replaced.
  CHECK(offer(t2, 7, 9, 0xA5, 9, -20, 0, evictable_deadline + 10) == JoinObserve::Evicted);
  CHECK(t2.find(key(7, 1, 0xA5)) == nullptr);
  CHECK(t2.find(key(7, 9, 0xA5)) != nullptr);
  CHECK(t2.stats().evicted == 1);
}

void hint_collision_split() {
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b = begin(t, 1100);
  JoinCandidate* r = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0x1111, 1100, r).ok() && r != nullptr);
  CHECK(r->site_id_authenticated && r->site_id == 0x1111);
  // Same site again: same record, no split.
  JoinCandidate* r2 = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0x1111, 1200, r2).ok());
  CHECK(r2 == r && t.size() == 1);
  // Colliding hint resolves to a DIFFERENT site: split into a second record
  // that inherits the key-level observation but none of the policy.
  JoinCandidate* r3 = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0x2222, 1200, r3).ok() && r3 != nullptr);
  CHECK(r3 != r && r3->site_id == 0x2222 && r3->site_id_authenticated);
  CHECK(r3->policy == JoinCandidatePolicy::Untried);
  CHECK(r3->proxies[0].present);  // evidence is key-level, copied on split
  CHECK(t.size() == 2 && t.stats().auth_splits == 1);
  CHECK(t.attempt().site_id == 0x2222);  // the attempt follows the proof
  cancel(t, b.attempt, 1200);
  // Hold the first sibling: the winner is whichever untried record the order
  // names — the split record stays eligible either way (a hold on one
  // site_id does not punish the other).
  const Begun bw = begin(t, 1300);
  CHECK(t.apply_outcome(bw.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1300, entropy).ok());
  const JoinSelect s = peek(t, 1400);
  CHECK(s.candidate != nullptr && s.candidate != bw.sel.candidate);
  // OFFER updates BOTH records sharing the key.
  CHECK(offer(t, 7, 42, 0xA5, 5, -30, 0, 1500) == JoinObserve::Updated);
  CHECK(r->last_seen_ms == 1500 && r3->last_seen_ms == 1500);
}

void policy_merge_same_site() {
  // Two different keys resolve to the same authenticated site_id: the
  // stronger hold merges — a colliding key cannot bypass a 24 h avoid.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 8, 42, 0xB5, 2, -60, 0, 1000) == JoinObserve::Inserted);
  const Begun b2 = begin(t, 1100);  // hops 0 wins first
  CHECK(b2.sel.candidate->key == key(8, 42, 0xB5));
  JoinCandidate* b = nullptr;
  CHECK(t.bind_authenticated(b2.attempt, 0x7777, 1100, b).ok());
  cancel(t, b2.attempt, 1100);
  t.suppress_proxy(*b, mac(2), 600000, 1100);  // let the other key bind next
  const Begun b1 = begin(t, 1100);
  CHECK(b1.sel.candidate->key == key(7, 42, 0xA5));
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(b1.attempt, 0x7777, 1100, a).ok());
  cancel(t, b1.attempt, 1100);
  CHECK(a != b && t.size() == 2);
  const Begun bh = begin(t, 1200);
  CHECK(bh.sel.candidate->key == key(7, 42, 0xA5));
  CHECK(t.apply_outcome(bh.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1200, entropy).ok());
  CHECK(peek(t, 1300).candidate == nullptr);  // B merged to A's 24 h hold
  // Once the hold expires, either key can carry the site again.
  const MonotonicMs after = 1200 + kJoinAvoidBlockedMs;
  CHECK(offer(t, 8, 42, 0xB5, 2, -60, 0, after - 5) == JoinObserve::Updated);
  const JoinSelect s = peek(t, after);
  CHECK(s.candidate == b);  // untried beats A's expired avoid
}

void split_full_table_aborts_attempt() {
  // A hint collision must split — which needs a slot the fully-protected
  // table cannot give. The bind is refused and the attempt aborts instead of
  // conflating two sites.
  JoinCandidates t;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000) ==
          JoinObserve::Inserted);
  }
  const Begun skip = begin(t, 1050);  // stamp K1 so the holds land on K2..K8
  CHECK(skip.sel.candidate->key.site_hint == 1);
  cancel(t, skip.attempt, 1050);
  for (std::uint32_t i = 2; i <= 8; ++i) {
    const Begun b = begin(t, 1100);
    CHECK(b.sel.candidate->key.site_hint == i);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  }
  const Begun b1 = begin(t, 1150);  // K1 alone is eligible
  CHECK(b1.sel.candidate->key.site_hint == 1);
  JoinCandidate* first = nullptr;
  CHECK(t.bind_authenticated(b1.attempt, 0x8888, 1150, first).ok());
  JoinCandidate* r = nullptr;
  const Status st = t.bind_authenticated(b1.attempt, 0x9999, 1200, r);
  CHECK(!st.ok() && st.code == StatusCode::NoCapacity);
  CHECK(r == nullptr && t.stats().auth_split_failed == 1);
  CHECK(!t.attempt().active);  // the attempt aborted, wedging nothing
  CHECK(first->site_id_authenticated && first->site_id == 0x8888);
  // And the table is usable again: K1 is still the eligible candidate.
  const JoinSelect s = peek(t, 1200);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 1);
}

void avoid_hint_rules() {
  JoinCandidates t;
  CHECK(offer(t, 7, 11, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 22, 0xA5, 2, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 33, 0xA5, 3, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 8, 11, 0xB5, 4, -50, 0, 1000) == JoinObserve::Inserted);  // other org
  const Begun b11 = begin(t, 1100);
  CHECK(b11.sel.candidate->key == key(7, 11, 0xA5));
  CHECK(t.apply_outcome(b11.attempt, JoinAttemptOutcome::DenyNotHere, 0, 1100, entropy).ok());
  const Begun b22 = begin(t, 1100);
  CHECK(b22.sel.candidate->key == key(7, 22, 0xA5));
  CHECK(t.apply_outcome(b22.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  const Begun b33 = begin(t, 1100);
  CHECK(t.apply_outcome(b33.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  const Begun b81 = begin(t, 1100);
  CHECK(t.apply_outcome(b81.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  // Org 7: B and C share the latest expiry; hint order breaks the tie; A
  // (earlier expiry) doesn't fit — still avoided, just not on the wire.
  CHECK(t.avoid_hints(7, 1200, hints) == 2);
  CHECK(hints[0] == 22 && hints[1] == 33);
  // Org 8 sees only its own avoid.
  CHECK(t.avoid_hints(8, 1200, hints) == 1 && hints[0] == 11);
  // Unknown org: nothing.
  CHECK(t.avoid_hints(9, 1200, hints) == 0);
  // Expired avoids leave the wire set.
  const MonotonicMs much_later = 1200 + kJoinAvoidBlockedMs + 1;
  CHECK(t.avoid_hints(7, much_later, hints) == 0);
  // Preferred site hint is never advertised as avoided.
  JoinCandidates t2;
  CHECK(offer(t2, 7, 55, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun bp = begin(t2, 1050);
  JoinCandidate* bound = nullptr;
  CHECK(t2.bind_authenticated(bp.attempt, 0xAAAA, 1050, bound).ok());
  t2.set_preferred(0xAAAA, 7, 55);
  CHECK(bound->preferred);
  CHECK(t2.apply_outcome(bp.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  CHECK(t2.avoid_hints(7, 1200, hints) == 0);
  CHECK(t2.preferred_hint(7) == 55 && t2.preferred_hint(8) == 0);
  // Ambiguous hint: two DIFFERENT keys carrying site_hint 77 — excluded.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 77, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t3, 7, 77, 0xC3, 2, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun ba = begin(t3, 1100);
  CHECK(ba.sel.candidate->key == key(7, 77, 0xA5));  // lower network first
  CHECK(t3.apply_outcome(ba.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  CHECK(t3.avoid_hints(7, 1200, hints) == 0);  // collision -> no hint on wire
}

void next_scan_deadline_rules() {
  JoinCandidates t;
  MonotonicMs d = 0;
  // Empty table: pure jittered backoff, capped at 600 s.
  CHECK(t.next_scan_deadline(1000, entropy, d).ok());
  CHECK(d >= 2000 && d <= 2250);
  // Failed cycles grow k; after 12 failures delay pins at the 600 s cap.
  for (int i = 0; i < 12; ++i) t.note_scan_cycle_failed();
  CHECK(t.next_scan_deadline(1000, entropy, d).ok());
  CHECK(d == 601000);
  // A pending eligibility cuts the wait: retry at +30 s wins over backoff.
  JoinCandidates t2;
  CHECK(offer(t2, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b2 = begin(t2, 1100);
  CHECK(t2.apply_outcome(b2.attempt, JoinAttemptOutcome::PendingAssignment, 30, 1100, entropy2)
            .ok());
  CHECK(t2.next_scan_deadline(1200, entropy2, d).ok());
  // min(backoff, eligibility): the ~1 s backoff wakes first and the pending
  // site is retried when its own deadline arrives on a later ask.
  CHECK(d >= 2200 && d <= 2450 && d < 31100);
  // A 3600 s pending still yields a scan every <=600 s for unknown sites.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b3 = begin(t3, 1100);
  CHECK(t3.apply_outcome(b3.attempt, JoinAttemptOutcome::PendingAssignment, 3600, 1100, entropy2)
            .ok());
  CHECK(t3.next_scan_deadline(1200, entropy2, d).ok());
  CHECK(d <= 601200 && d >= 2200);  // in [backoff, 600 s] — never the 3600 s
  // Long avoids likewise: 24 h holds never postpone rediscovery past 600 s.
  JoinCandidates t4;
  CHECK(offer(t4, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b4 = begin(t4, 1100);
  CHECK(t4.apply_outcome(b4.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy2).ok());
  CHECK(t4.next_scan_deadline(1200, entropy2, d).ok());
  CHECK(d <= 601200);
  CHECK(t4.next_eligible_ms(1200) == 1100 + kJoinAvoidBlockedMs);
  // Entropy failure: floor delay, error status, stat counted — the attempt
  // schedule still moves on the lower bound (never lengthened).
  entropy2.fail_next = true;
  const Status st = t4.next_scan_deadline(1300, entropy2, d);
  CHECK(!st.ok());
  CHECK(d == 2300);  // k=0 floor: 1 s
  CHECK(t4.stats().entropy_failures == 1);
}

void clock_regression() {
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 10000) == JoinObserve::Inserted);
  // Any entry with a non-monotonic stamp is refused and counted.
  CHECK(offer(t, 7, 43, 0xA5, 2, -50, 0, 9999) == JoinObserve::Rejected);
  JoinAttempt a{};
  JoinSelect s{};
  CHECK(!t.select_and_begin(9999, a, s).ok());
  CHECK(!a.active && s.candidate == nullptr);
  MonotonicMs d = 0;
  CHECK(!t.next_scan_deadline(9999, entropy, d).ok());
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, 9999, hints) == 0);
  CHECK(t.clock_uncertain());
  CHECK(t.stats().clock_regressions == 1);
  // Uncertainty sticks until a new instance: even after time catches up,
  // every time-dependent operation is still refused (design §4.1: a new
  // clock domain is a restart).
  CHECK(offer(t, 7, 43, 0xA5, 2, -50, 0, 10000) == JoinObserve::Rejected);
  CHECK(!t.select_and_begin(10000, a, s).ok() && s.candidate == nullptr);
  CHECK(!t.next_scan_deadline(10000, entropy, d).ok());
  CHECK(t.avoid_hints(7, 10000, hints) == 0);
  CHECK(t.next_eligible_ms(10000) == kJoinNoDeadline);
  JoinCandidate* rb = nullptr;
  JoinAttempt none{};
  CHECK(!t.bind_authenticated(none, 0x1, 10000, rb).ok() && rb == nullptr);
  CHECK(!t.apply_outcome(none, JoinAttemptOutcome::Failed, 0, 10000, entropy).ok());
  // The clock is checked before the handle: even a live-looking attempt
  // reports TimeUncertain, and the table is untouched.
  JoinAttempt fake{};
  fake.active = true;
  fake.seq = 1;
  fake.key = key(7, 42, 0xA5);
  CHECK(t.apply_outcome(fake, JoinAttemptOutcome::Failed, 0, 10000, entropy).code ==
        StatusCode::TimeUncertain);
  CHECK(t.clock_uncertain());
  CHECK(t.stats().clock_regressions == 1);
  // A new instance starts clean at the same stamps.
  JoinCandidates fresh;
  CHECK(offer(fresh, 7, 43, 0xA5, 2, -50, 0, 10000) == JoinObserve::Inserted);
  CHECK(peek(fresh, 10000).candidate != nullptr);
}

void scan_cursor() {
  JoinCandidates t;
  // Invalid configs rejected.
  JoinScanConfig bad{};
  CHECK(!t.configure_scan(bad).ok());
  bad.channel_count = 2;
  bad.channels = {6, 6};
  bad.org_hint_count = 1;
  bad.org_hints = {7};
  CHECK(!t.configure_scan(bad).ok());  // duplicate channel
  bad.channels = {0, 6};
  CHECK(!t.configure_scan(bad).ok());  // channel 0
  bad.channels = {15, 6};
  CHECK(!t.configure_scan(bad).ok());  // channel 15
  bad.channels = {1, 6};
  bad.org_hint_count = 4;
  bad.org_hints = {7, 8, 9};
  CHECK(!t.configure_scan(bad).ok());  // >3 hints
  // Duplicate anchor hints are merged, not rejected (§4.1).
  JoinScanConfig cfg{};
  cfg.channel_count = 2;
  cfg.channels = {1, 6};
  cfg.org_hint_count = 3;
  cfg.org_hints = {7, 7, 8};
  CHECK(t.configure_scan(cfg).ok());
  // Channel outer, hint inner: (1,7) (1,8) (6,7) (6,8) — dedup 3->2 hints.
  const JoinScanStep expected[4] = {{1, 7, true}, {1, 8, true}, {6, 7, true}, {6, 8, true}};
  JoinScanStep s = t.scan_begin();
  std::size_t i = 0;
  while (s.valid) {
    CHECK(i < 4);
    CHECK(s.channel == expected[i].channel && s.org_hint == expected[i].org_hint);
    ++i;
    t.scan_advance();
    s = t.scan_step();
  }
  CHECK(i == 4);
  CHECK(!t.scan_advance());
}

void deadline_helpers() {
  CHECK(join_m2_deadline_ms(0) == 2000);
  CHECK(join_m2_deadline_ms(10) == 5000);
  CHECK(join_m2_deadline_ms(14) == 6000);              // capped
  CHECK(join_m2_deadline_ms(kZtHopsUnknown) == 6000);  // unknown takes the cap
  CHECK(join_m4_deadline_ms(0, 500) == 2500);
  CHECK(join_m4_deadline_ms(0, 9000) == 10000);  // capped
  CHECK(join_m4_deadline_ms(kZtHopsUnknown, 5000) == 10000);
}

void bounds() {
  static_assert(sizeof(JoinCandidate) <= kJoinCandidateRecordMax, "record bound");
  CHECK(sizeof(JoinCandidate) <= kJoinCandidateRecordMax);
  // The whole table stays inside the §9 budget (8 x 160 B records + config).
  CHECK(sizeof(JoinCandidates) <= 8 * kJoinCandidateRecordMax + 256);
}

void split_excludes_branch_source() {
  // A full table whose branch source is the stalest record: the split must
  // take any slot BUT the source — success with an unoccupied record and a
  // table that shrank 8->7 loses the authenticated site.
  JoinCandidates t;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000 + i) ==
          JoinObserve::Inserted);
  }
  const Begun b = begin(t, 1100);
  CHECK(b.sel.candidate->key.site_hint == 1);
  JoinCandidate* source = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xAAAA, 1100, source).ok());
  CHECK(source != nullptr);
  JoinCandidate* split = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xBBBB, 1200, split).ok());
  CHECK(split != nullptr);
  if (split != nullptr) {
    CHECK(split->occupied);
    CHECK(split->site_id == 0xBBBB && split->site_id_authenticated);
    CHECK(split->policy == JoinCandidatePolicy::Untried);
    CHECK(split->proxies[0].present);  // key-level evidence copied, not lost
  }
  CHECK(t.size() == 8);  // a victim was replaced — the table never shrinks
  CHECK(t.stats().evicted == 1);
  // The victim is the stalest record that is NOT the pinned source.
  CHECK(t.find(key(7, 2, 0xA5)) == nullptr);
  const JoinCandidate* kept = t.find(key(7, 1, 0xA5));
  CHECK(kept != nullptr);
  if (kept != nullptr) {
    CHECK(kept->site_id_authenticated && kept->site_id == 0xAAAA);
    CHECK(kept != split);
  }
  cancel(t, b.attempt, 1200);
}

void split_attempt_names_new_site() {
  // The in-flight attempt follows the proof: after a split the attempt names
  // the newly proven site, the outcome lands on its record, and the source
  // keeps no attempt state at all (there is none to strand on records) and
  // stays evictable.
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b = begin(t, 1200);
  JoinCandidate* source = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xAAAA, 1200, source).ok());
  CHECK(source != nullptr);
  if (source == nullptr) return;
  JoinCandidate* split = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xBBBB, 1300, split).ok());
  CHECK(split != nullptr);
  CHECK(t.attempt().active && t.attempt().site_id == 0xBBBB);
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::Failed, 0, 1300, entropy).ok());
  CHECK(split->failures == 1 && split->eligible_at_ms > 1300);
  CHECK(source->failures == 0 && source->eligible_at_ms == 0);
  CHECK(source->policy == JoinCandidatePolicy::Untried);
  // The source is evictable: fill the table, then the 9th key replaces the
  // stalest record — the source observed at t=1000.
  for (std::uint32_t i = 1; i <= 6; ++i) {
    CHECK(offer(t, 7, 100 + i, 0xA5, static_cast<std::uint8_t>(10 + i), -60, 1,
                2000 + i) == JoinObserve::Inserted);
  }
  CHECK(t.size() == 8);
  CHECK(offer(t, 7, 200, 0xA5, 20, -20, 0, 3000) == JoinObserve::Evicted);
  CHECK(!source->occupied || !(source->key == k));  // source slot reused
}

void avoid_hint_split_collision() {
  // A is avoid-blocked for 24 h; the same hint splits to an eligible B.
  // The hint is unresolvable — it must stay off DISCOVER, while B itself
  // remains selectable.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b = begin(t, 1100);
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xAAAA, 1100, a).ok());
  CHECK(a != nullptr);
  if (a == nullptr) return;
  JoinCandidate* sib = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xBBBB, 1100, sib).ok());
  CHECK(sib != nullptr);
  cancel(t, b.attempt, 1100);
  // Both siblings are identical, so the first record wins the tie; denying
  // it must leave the split sibling eligible with the hint suppressed.
  const Begun bw = begin(t, 1200);
  CHECK(bw.sel.candidate == a);
  CHECK(t.apply_outcome(bw.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1200, entropy).ok());
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, 1400, hints) == 0);  // hint 42 suppressed, not sent
  // B is a different authenticated site: eligible despite A's hold.
  const JoinSelect s = peek(t, 1400);
  CHECK(s.candidate == sib);
}

void expired_policy_evictable() {
  // Eight DenyBlocked records: the 9th site is dropped while every hold is
  // unexpired, then replaces the stalest record exactly at expiry and after.
  JoinCandidates t;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000 + i) ==
          JoinObserve::Inserted);
  }
  for (std::uint32_t i = 1; i <= 8; ++i) {
    const Begun b = begin(t, 1100);
    CHECK(b.sel.candidate->key.site_hint == i);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  }
  const MonotonicMs expiry = 1100 + kJoinAvoidBlockedMs;
  CHECK(offer(t, 7, 9, 0xA5, 9, -20, 0, expiry - 1) == JoinObserve::NoCapacity);
  CHECK(t.size() == 8);
  CHECK(offer(t, 7, 9, 0xA5, 9, -20, 0, expiry) == JoinObserve::Evicted);
  CHECK(t.size() == 8);
  CHECK(t.find(key(7, 1, 0xA5)) == nullptr);  // stalest observation replaced
  CHECK(t.find(key(7, 9, 0xA5)) != nullptr);
  CHECK(offer(t, 7, 10, 0xA5, 10, -20, 0, expiry + 1000) == JoinObserve::Evicted);
  CHECK(t.find(key(7, 10, 0xA5)) != nullptr);
  // Expired pending/busy holds release their records the same way.
  JoinCandidates t2;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t2, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000 + i) ==
          JoinObserve::Inserted);
  }
  for (std::uint32_t i = 1; i <= 8; ++i) {
    const Begun b = begin(t2, 1100);
    CHECK(t2.apply_outcome(b.attempt, JoinAttemptOutcome::PendingAssignment, 60, 1100, entropy)
              .ok());
  }
  CHECK(offer(t2, 7, 9, 0xA5, 9, -20, 0, 1100 + 60000) == JoinObserve::Evicted);
}

void saturated_hold_never_expires() {
  // A 24 h hold set at MAX-1000 saturates its deadline to UINT64_MAX; the
  // saturated hold must never read as "arrived" — not for selection,
  // replacement, or the avoid wire set.
  const MonotonicMs kMax = ~MonotonicMs{0};
  const MonotonicMs t0 = kMax - 1000;
  JoinCandidates t;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, t0) ==
          JoinObserve::Inserted);
    const Begun b = begin(t, t0);
    CHECK(b.sel.candidate->key.site_hint == i);
    CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::DenyBlocked, 0, t0, entropy).ok());
    CHECK(record_of(t, key(7, i, 0xA5))->eligible_at_ms == kMax);
  }
  CHECK(peek(t, kMax).candidate == nullptr);  // still held, not selectable
  CHECK(offer(t, 7, 9, 0xA5, 9, -20, 0, kMax) == JoinObserve::NoCapacity);
  CHECK(t.size() == 8);
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, kMax, hints) == 2);  // saturated avoids stay on wire
}

void rebind_outcome_lands_on_proven_site() {
  // After a split, the same key carries two authenticated sites. An attempt
  // whose m2 proves the sibling belongs to that sibling: the bind hands back
  // its record and the outcome lands there, leaving the other pristine.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b0 = begin(t, 1100);
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xAAAA, 1100, a).ok() && a != nullptr);
  JoinCandidate* sib = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xBBBB, 1200, sib).ok() && sib != nullptr);
  if (a == nullptr || sib == nullptr) return;
  cancel(t, b0.attempt, 1200);
  const Begun b1 = begin(t, 1300);
  JoinCandidate* r = nullptr;
  CHECK(t.bind_authenticated(b1.attempt, 0xBBBB, 1400, r).ok());
  CHECK(r == sib);
  CHECK(t.attempt().site_id == 0xBBBB);
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, 1400, entropy).ok());
  CHECK(sib->failures == 1 && sib->eligible_at_ms > 1400);
  CHECK(a->failures == 0 && a->eligible_at_ms == 0);
  CHECK(a->policy == JoinCandidatePolicy::Untried);
}

void rebind_to_held_site_aborts() {
  // Same split, but B is avoid-blocked for 24 h. Re-proving B must not hand
  // back a held record for m3: the bind is refused and the attempt aborts,
  // leaving A evictable.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun b0 = begin(t, 1100);
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xAAAA, 1100, a).ok() && a != nullptr);
  JoinCandidate* sib = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xBBBB, 1200, sib).ok() && sib != nullptr);
  if (a == nullptr || sib == nullptr) return;
  cancel(t, b0.attempt, 1200);
  // The tie goes to the first record; cancelling there stamps it, so the
  // sibling (older attempt) wins next and takes the hold.
  const Begun b1 = begin(t, 1200);
  CHECK(b1.sel.candidate == a);
  cancel(t, b1.attempt, 1200);
  const Begun b2 = begin(t, 1300);
  CHECK(b2.sel.candidate == sib);
  CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1300, entropy).ok());
  CHECK(sib->policy == JoinCandidatePolicy::AvoidBlocked);
  const Begun b3 = begin(t, 1400);
  CHECK(b3.sel.candidate == a);
  JoinCandidate* r = sib;
  const Status st = t.bind_authenticated(b3.attempt, 0xBBBB, 1500, r);
  CHECK(!st.ok() && st.code == StatusCode::InvalidState);
  CHECK(r == nullptr);
  CHECK(!t.attempt().active);
  CHECK(sib->policy == JoinCandidatePolicy::AvoidBlocked);
  // A is evictable: with B protected and six fresh records, the 9th key
  // replaces the stalest record — A, observed at t=1000.
  for (std::uint32_t i = 1; i <= 6; ++i) {
    CHECK(offer(t, 7, 100 + i, 0xA5, static_cast<std::uint8_t>(10 + i), -60, 1,
                2000 + i) == JoinObserve::Inserted);
  }
  CHECK(t.size() == 8);
  CHECK(offer(t, 7, 200, 0xA5, 20, -20, 0, 3000) == JoinObserve::Evicted);
  CHECK(a->key == key(7, 200, 0xA5));  // A's slot reused, not wedged
}

void failed_proxy_yields_to_alternate() {
  // Two routes, the better one fails: its record and proxy holds expire
  // together, so rank alone would reselect the same failed path. The next
  // selection prefers the usable alternate instead.
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  const Begun b1 = begin(t, 1000);
  CHECK(b1.sel.proxy.present && b1.sel.proxy.mac == mac(1));
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, 1000, entropy).ok());
  const JoinCandidate* r = record_of(t, k);
  const MonotonicMs d = r->eligible_at_ms;
  CHECK(r->proxies[0].suppressed_until_ms == d);  // both holds expire together
  const Begun b2 = begin(t, d);
  CHECK(b2.sel.candidate != nullptr && b2.sel.proxy.present &&
        b2.sel.proxy.mac == mac(2));
  // Failing the alternate too leaves no untried route: with no other site
  // the best failed path is retried.
  CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::Failed, 0, d, entropy).ok());
  const JoinSelect s = peek(t, r->eligible_at_ms);
  CHECK(s.candidate != nullptr && s.proxy.present && s.proxy.mac == mac(1));
}

void failed_proxy_tracked_by_mac() {
  // The failed path is tracked by proxy MAC, not by array slot: an OFFER
  // that replaces the other slot between failure and reselection must not
  // resurrect the failed route, even though it still ranks best.
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  const Begun b = begin(t, 1000);
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::Failed, 0, 1000, entropy).ok());
  const JoinCandidate* r = record_of(t, k);
  const MonotonicMs d = r->eligible_at_ms;
  // mac3 (hops 0, weaker RSSI) displaces mac2's slot; mac1 still ranks best.
  CHECK(t.observe(k, obs(3, 0x1003, 1, -60, 0, true), 1100) == JoinObserve::Updated);
  CHECK(r->proxies[0].mac == mac(1) && r->proxies[1].mac == mac(3));
  // Re-observing the failed proxy refreshes evidence, not preference.
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1200) == JoinObserve::Updated);
  const JoinSelect s = peek(t, d);
  CHECK(s.candidate != nullptr && s.proxy.present && s.proxy.mac == mac(3));
}

void select_and_begin_atomicity() {
  // Selection and attempt start are one table operation: the begin either
  // starts the winning attempt or rejects — there is no separate mark that
  // could act on a stale selection, and no second attempt while one flies.
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 1, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -40, 0, true), 1000) == JoinObserve::Updated);
  const Begun b = begin(t, 1000);
  CHECK(b.sel.proxy.present && b.sel.proxy.mac == mac(2));  // hops 0 wins
  CHECK(b.attempt.active && b.attempt.seq != 0);
  CHECK(b.attempt.key == k && b.attempt.proxy == mac(2) && b.attempt.site_id == 0);
  CHECK(b.sel.candidate->last_attempt_ms == 1000);
  // A second begin while the attempt flies is rejected; the live attempt is
  // untouched.
  JoinAttempt dup{};
  JoinSelect dsel{};
  CHECK(t.select_and_begin(1000, dup, dsel).code == StatusCode::InvalidState);
  CHECK(!dup.active && dsel.candidate == nullptr);
  CHECK(t.attempt().active && t.attempt().seq == b.attempt.seq);
  CHECK(t.attempt().proxy == mac(2));
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::Failed, 0, 1000, entropy).ok());
  const MonotonicMs d = record_of(t, k)->eligible_at_ms;
  // Stale, empty and foreign handles are rejected; nothing moves.
  const Begun b2 = begin(t, d);
  CHECK(b2.sel.proxy.mac == mac(1));  // mac2 failed: the alternate wins
  JoinCandidate* rb = nullptr;
  CHECK(t.bind_authenticated(b.attempt, 0xAAAA, d, rb).code == StatusCode::InvalidState);
  CHECK(rb == nullptr);
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::Failed, 0, d, entropy).code ==
        StatusCode::InvalidState);
  JoinAttempt empty{};
  CHECK(t.apply_outcome(empty, JoinAttemptOutcome::Failed, 0, d, entropy).code ==
        StatusCode::InvalidState);
  JoinAttempt wrong_key = b2.attempt;
  wrong_key.key = key(7, 99, 0xA5);
  CHECK(t.apply_outcome(wrong_key, JoinAttemptOutcome::Failed, 0, d, entropy).code ==
        StatusCode::InvalidState);
  JoinCandidates u;
  CHECK(offer(u, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  const Begun bu = begin(u, 1000);  // seq 1 there, seq 2 here
  CHECK(t.apply_outcome(bu.attempt, JoinAttemptOutcome::Failed, 0, d, entropy).code ==
        StatusCode::InvalidState);
  CHECK(t.attempt().active && t.attempt().seq == b2.attempt.seq);
  cancel(t, b2.attempt, d);
  cancel(u, bu.attempt, 1000);
  // A regressed clock refuses the attempt start as well.
  const JoinSelect s2 = peek(t, d);
  CHECK(s2.candidate != nullptr);
  JoinAttempt late{};
  JoinSelect lsel{};
  CHECK(t.select_and_begin(900, late, lsel).code == StatusCode::TimeUncertain);
  CHECK(!late.active && !t.attempt().active);
}

// --- Round-4 structural regressions ------------------------------------------------------
// The attempt is one table-owned value: the m2 bind and every outcome work
// off its key, proxy MAC and generation, so splits, slot reuse and rebinds
// cannot strand or misattribute the in-flight state.

void r4_bind_held_site_cross_key_refused() {
  // A is 24 h-avoided on one key; proving A through a different key's m2
  // must not bypass the hold: the bind is refused, the attempt aborts, and
  // no record comes back to send m3 with.
  JoinCandidates t;
  TestEntropy e(0x401);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 8, 42, 0xB5, 2, -60, 1, 1000) == JoinObserve::Inserted);
  const Begun b1 = begin(t, 1100);
  CHECK(b1.sel.candidate->key == key(7, 42, 0xA5));
  JoinCandidate* ra = nullptr;
  CHECK(t.bind_authenticated(b1.attempt, 0x7777, 1100, ra).ok());
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::DenyBlocked, 0, 1200, e).ok());
  const Begun b2 = begin(t, 1300);  // K1 held, K2 unbound and eligible
  CHECK(b2.sel.candidate->key == key(8, 42, 0xB5));
  JoinCandidate* rb = nullptr;
  const Status st = t.bind_authenticated(b2.attempt, 0x7777, 1400, rb);
  CHECK(!st.ok() && st.code == StatusCode::InvalidState);
  CHECK(rb == nullptr);
  CHECK(!t.attempt().active);
  const JoinCandidate* k2 = record_of(t, key(8, 42, 0xB5));
  CHECK(!k2->site_id_authenticated && k2->site_id == 0);  // refused before binding
  CHECK(ra->policy == JoinCandidatePolicy::AvoidBlocked);  // the hold stands
  const Begun b3 = begin(t, 1400);  // nothing wedged: K2 still carries attempts
  CHECK(b3.sel.candidate->key == key(8, 42, 0xB5));
  cancel(t, b3.attempt, 1400);
}

void r4_three_site_split_attempt_follows_proof() {
  // Three sites behind one hint: the attempt rides on B when m2 proves C.
  // The split hands back C's record, the outcome lands there, and A and B
  // keep no attempt state and stay evictable.
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -40, 1, true), 1000) == JoinObserve::Inserted);
  const Begun b0 = begin(t, 1100);
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xAAAA, 1100, a).ok() && a != nullptr);
  JoinCandidate* sib = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xBBBB, 1200, sib).ok() && sib != nullptr);
  if (a == nullptr || sib == nullptr) return;
  cancel(t, b0.attempt, 1200);
  const Begun b1 = begin(t, 1300);  // tie goes to the first record...
  CHECK(b1.sel.candidate == a);
  cancel(t, b1.attempt, 1300);  // ... so stamping it lets B win next.
  const Begun b2 = begin(t, 1400);
  CHECK(b2.sel.candidate == sib);  // B is the site under attempt now
  JoinCandidate* c = nullptr;
  CHECK(t.bind_authenticated(b2.attempt, 0xCCCC, 1400, c).ok() && c != nullptr);
  CHECK(t.size() == 3 && t.stats().auth_splits == 2);
  CHECK(c != a && c != sib && c->site_id == 0xCCCC);
  CHECK(t.attempt().active && t.attempt().site_id == 0xCCCC);
  CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::Failed, 0, 1400, entropy).ok());
  CHECK(c->failures == 1 && c->eligible_at_ms > 1400);
  CHECK(a->failures == 0 && a->eligible_at_ms == 0);
  CHECK(sib->failures == 0 && sib->eligible_at_ms == 0);
  CHECK(a->policy == JoinCandidatePolicy::Untried);
  CHECK(sib->policy == JoinCandidatePolicy::Untried);
  // Neither A nor B is pinned: filling the table lets the 9th key reuse the
  // stalest slot.
  for (std::uint32_t i = 1; i <= 5; ++i) {
    CHECK(offer(t, 7, 100 + i, 0xA5, static_cast<std::uint8_t>(10 + i), -60, 1,
                2000 + i) == JoinObserve::Inserted);
  }
  CHECK(t.size() == 8);
  CHECK(offer(t, 7, 200, 0xA5, 20, -20, 0, 3000) == JoinObserve::Evicted);
  CHECK(!a->occupied || !(a->key == k));  // A's slot reused
}

void r4_all_failed_prefers_other_site() {
  // Preferred site A fails on both its proxies in turn; the eligible other
  // site B wins next (§5.1 rule 5) instead of A snapping back to its first
  // failed proxy.
  JoinCandidates t;
  TestEntropy e(0x403);
  const JoinCandidateKey ka = key(7, 42, 0xA5);
  const JoinCandidateKey kb = key(7, 43, 0xA5);
  CHECK(t.observe(ka, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(ka, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  CHECK(t.observe(kb, obs(3, 0x1003, 1, -60, 2, true), 1000) == JoinObserve::Inserted);
  const Begun b0 = begin(t, 1000);
  CHECK(b0.sel.candidate->key == ka && b0.sel.proxy.mac == mac(1));
  JoinCandidate* ra = nullptr;
  CHECK(t.bind_authenticated(b0.attempt, 0xAAAA, 1000, ra).ok());
  cancel(t, b0.attempt, 1000);
  t.set_preferred(0xAAAA, 7, 42);
  CHECK(ra->preferred);
  const Begun b1 = begin(t, 1100);
  CHECK(b1.sel.candidate->key == ka && b1.sel.proxy.mac == mac(1));
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, 1100, e).ok());
  const MonotonicMs d1 = ra->eligible_at_ms;
  // Preferred with an untried route still stays home for the second proxy.
  const Begun b2 = begin(t, d1);
  CHECK(b2.sel.candidate->key == ka && b2.sel.proxy.mac == mac(2));
  CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::Failed, 0, d1, e).ok());
  const MonotonicMs d2 = ra->eligible_at_ms;
  // Every route of A failed: the eligible B wins despite A preferred.
  const Begun b3 = begin(t, d2);
  CHECK(b3.sel.candidate->key == kb && b3.sel.proxy.mac == mac(3));
  cancel(t, b3.attempt, d2);
}

void r4_failure_records_attempt_mac() {
  // The failure belongs to the proxy MAC the attempt started with — not to
  // whatever MAC an OFFER moved into a slot mid-attempt. Churn between
  // begin and outcome must not misattribute the failed path.
  JoinCandidates t;
  TestEntropy e(0x404);
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  const Begun b = begin(t, 1000);
  CHECK(b.sel.proxy.mac == mac(1));
  CHECK(b.attempt.proxy == mac(1));
  CHECK(t.observe(k, obs(3, 0x1003, 1, -40, 0, true), 1100) == JoinObserve::Updated);
  const JoinCandidate* r = record_of(t, k);
  CHECK(r->proxies[0].mac == mac(1) && r->proxies[1].mac == mac(3));
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1200) == JoinObserve::Updated);
  CHECK(t.apply_outcome(b.attempt, JoinAttemptOutcome::Failed, 0, 1200, e).ok());
  CHECK(failed_has(*r, mac(1)));
  CHECK(!failed_has(*r, mac(3)));
  for (const auto& p : r->proxies) {
    if (p.mac == mac(1)) CHECK(p.suppressed_until_ms == r->eligible_at_ms);
    if (p.mac == mac(3)) CHECK(p.suppressed_until_ms == 0);
  }
  const Begun b2 = begin(t, r->eligible_at_ms);
  CHECK(b2.sel.proxy.mac == mac(3));  // the untried alternate, not mac1 again
  cancel(t, b2.attempt, r->eligible_at_ms);
}

void r4_no_stale_mark_double_begin_rejected() {
  // There is no mark step that could act on a stale selection: the only way
  // to start is a fresh atomic begin, a second begin flies into InvalidState,
  // and slot churn between begin and outcome cannot redirect the attempt.
  JoinCandidates t;
  TestEntropy e(0x405);
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  const Begun b1 = begin(t, 1000);
  CHECK(b1.sel.proxy.mac == mac(1));
  JoinAttempt dup{};
  JoinSelect dsel{};
  CHECK(t.select_and_begin(1001, dup, dsel).code == StatusCode::InvalidState);
  CHECK(!dup.active);
  CHECK(t.attempt().seq == b1.attempt.seq && t.attempt().proxy == mac(1));
  CHECK(t.observe(k, obs(3, 0x1003, 1, -40, 0, true), 1002) == JoinObserve::Updated);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1003) == JoinObserve::Updated);
  CHECK(t.attempt().proxy == mac(1));  // churn cannot redirect the attempt
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, 1003, e).ok());
  const JoinCandidate* r = record_of(t, k);
  const Begun b2 = begin(t, r->eligible_at_ms);
  CHECK(b2.sel.proxy.mac == mac(3));  // mac1 failed: best untried wins
  JoinCandidate* rb = nullptr;
  CHECK(t.bind_authenticated(b1.attempt, 0xAAAA, r->eligible_at_ms, rb).code ==
        StatusCode::InvalidState);
  CHECK(rb == nullptr);
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, r->eligible_at_ms, e)
            .code == StatusCode::InvalidState);
  CHECK(t.attempt().active && t.attempt().seq == b2.attempt.seq);
  cancel(t, b2.attempt, r->eligible_at_ms);
}

void r4_removed_no_membership_clears_streak() {
  // An authenticated Removed without membership evidence keeps its 600 s
  // suppression but resets the transient streak and the failed-path memory:
  // the next failure backs off from k=0 and the best route is tried again.
  JoinCandidates t;
  TestEntropy e(0x406);
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), 1000) == JoinObserve::Updated);
  const Begun b1 = begin(t, 1000);
  CHECK(t.apply_outcome(b1.attempt, JoinAttemptOutcome::Failed, 0, 1000, e).ok());
  const JoinCandidate* r = record_of(t, k);
  CHECK(r->failures == 1);
  CHECK(failed_has(*r, mac(1)));
  const Begun b2 = begin(t, r->eligible_at_ms);
  CHECK(b2.sel.proxy.mac == mac(2));
  const MonotonicMs at = r->eligible_at_ms;
  CHECK(t.apply_outcome(b2.attempt, JoinAttemptOutcome::RemovedNoMembership, 0, at, e).ok());
  CHECK(r->eligible_at_ms - at == kJoinSuppressNoMemberMs);  // the hold stays
  CHECK(r->failures == 0);                                   // the streak resets
  CHECK(failed_empty(*r));                                   // so does path memory
  const MonotonicMs d2 = r->eligible_at_ms;
  // The 600 s suppression outlasts the 60 s evidence: re-observe first.
  CHECK(t.observe(k, obs(1, 0x1001, 1, -50, 0, true), d2) == JoinObserve::Updated);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1, true), d2) == JoinObserve::Updated);
  const Begun b3 = begin(t, d2);
  CHECK(b3.sel.proxy.mac == mac(1));  // best route again, not the alternate
  CHECK(t.apply_outcome(b3.attempt, JoinAttemptOutcome::Failed, 0, d2, e).ok());
  const std::uint64_t delay = r->eligible_at_ms - d2;
  CHECK(delay >= 1000 && delay <= 1250);  // k=0 base, not the k=1 doubling
}

void selected_proxy_snapshot_survives_offer_churn() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -40, 0), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 6, -50, 1), 1000) == JoinObserve::Updated);
  const Begun b = begin(t, 1000);
  CHECK(b.sel.proxy.present && b.sel.proxy.mac == mac(1));
  CHECK(b.sel.proxy.channel == 1);
  CHECK(t.observe(k, obs(1, 0x1001, 11, -80, 3), 1001) == JoinObserve::Updated);
  CHECK(t.observe(k, obs(3, 0x1003, 6, -30, 0), 1002) == JoinObserve::Updated);
  CHECK(b.attempt.proxy == mac(1));
  CHECK(b.sel.proxy.present && b.sel.proxy.mac == mac(1));
  CHECK(b.sel.proxy.channel == 1);
  cancel(t, b.attempt, 1002);
}

void split_starts_with_site_local_path_memory() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -40, 0), 1000) == JoinObserve::Inserted);
  CHECK(t.observe(k, obs(2, 0x1002, 1, -50, 1), 1000) == JoinObserve::Updated);
  const Begun first = begin(t, 1000);
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(first.attempt, 0xAAAA, 1000, a).ok());
  CHECK(t.apply_outcome(first.attempt, JoinAttemptOutcome::Failed, 0, 1000, entropy).ok());
  CHECK(a != nullptr && failed_has(*a, mac(1)));
  if (a == nullptr) return;
  const Begun second = begin(t, a->eligible_at_ms);
  CHECK(second.sel.proxy.present && second.sel.proxy.mac == mac(2));
  JoinCandidate* c = nullptr;
  CHECK(t.bind_authenticated(second.attempt, 0xCCCC, a->eligible_at_ms, c).ok());
  CHECK(c != nullptr && c != a);
  if (c != nullptr) {
    CHECK(!failed_has(*c, mac(1)));
    CHECK(!failed_has(*c, mac(2)));
  }
  cancel(t, second.attempt, a->eligible_at_ms);
}

void proxy_suppression_deadline_drives_scan() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(t.observe(k, obs(1, 0x1001, 1, -40, 0), 1000) == JoinObserve::Inserted);
  JoinCandidate* r = t.find(k);
  CHECK(r != nullptr);
  if (r == nullptr) return;
  t.suppress_proxy(*r, mac(1), 5000, 1000);
  t.suppress_proxy(*r, mac(1), 10, 2000);
  CHECK(r->proxies[0].suppressed_until_ms == 6000);
  for (int i = 0; i < 12; ++i) t.note_scan_cycle_failed();
  CHECK(t.next_eligible_ms(2000) == 6000);
  MonotonicMs deadline = 0;
  CHECK(t.next_scan_deadline(2000, entropy, deadline).ok());
  CHECK(deadline == 6000);
}

}  // namespace

int main() {
  struct Case {
    const char* name;
    void (*fn)();
  };
  const Case cases[] = {
      {"observe_insert_select", observe_insert_select},
      {"offer_never_releases_policy", offer_never_releases_policy},
      {"j04_deny_then_other_site", j04_deny_then_other_site},
      {"j05_pending_retry_after", j05_pending_retry_after},
      {"ordering", ordering},
      {"freshness_and_flags", freshness_and_flags},
      {"proxy_best_two", proxy_best_two},
      {"suppress_and_fail", suppress_and_fail},
      {"authenticated_outcomes", authenticated_outcomes},
      {"capacity_and_protection", capacity_and_protection},
      {"hint_collision_split", hint_collision_split},
      {"policy_merge_same_site", policy_merge_same_site},
      {"split_full_table_aborts_attempt", split_full_table_aborts_attempt},
      {"avoid_hint_rules", avoid_hint_rules},
      {"next_scan_deadline_rules", next_scan_deadline_rules},
      {"clock_regression", clock_regression},
      {"scan_cursor", scan_cursor},
      {"deadline_helpers", deadline_helpers},
      {"bounds", bounds},
      {"split_excludes_branch_source", split_excludes_branch_source},
      {"split_attempt_names_new_site", split_attempt_names_new_site},
      {"avoid_hint_split_collision", avoid_hint_split_collision},
      {"expired_policy_evictable", expired_policy_evictable},
      {"saturated_hold_never_expires", saturated_hold_never_expires},
      {"rebind_outcome_lands_on_proven_site", rebind_outcome_lands_on_proven_site},
      {"rebind_to_held_site_aborts", rebind_to_held_site_aborts},
      {"failed_proxy_yields_to_alternate", failed_proxy_yields_to_alternate},
      {"failed_proxy_tracked_by_mac", failed_proxy_tracked_by_mac},
      {"select_and_begin_atomicity", select_and_begin_atomicity},
      {"r4_bind_held_site_cross_key_refused", r4_bind_held_site_cross_key_refused},
      {"r4_three_site_split_attempt_follows_proof", r4_three_site_split_attempt_follows_proof},
      {"r4_all_failed_prefers_other_site", r4_all_failed_prefers_other_site},
      {"r4_failure_records_attempt_mac", r4_failure_records_attempt_mac},
      {"r4_no_stale_mark_double_begin_rejected", r4_no_stale_mark_double_begin_rejected},
      {"r4_removed_no_membership_clears_streak", r4_removed_no_membership_clears_streak},
      {"selected_proxy_snapshot_survives_offer_churn", selected_proxy_snapshot_survives_offer_churn},
      {"split_starts_with_site_local_path_memory", split_starts_with_site_local_path_memory},
      {"proxy_suppression_deadline_drives_scan", proxy_suppression_deadline_drives_scan},
  };
  for (const auto& c : cases) {
    current = c.name;
    c.fn();
  }
  if (failures == 0) {
    std::printf("join candidate tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", failures);
  return 1;
}
