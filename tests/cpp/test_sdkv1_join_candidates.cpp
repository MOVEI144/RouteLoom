// SDK v1 zero-touch join candidate table (plan P3-4 PR 2,
// sdkv1_join_candidates.hpp). Table-driven coverage of the 8-record
// observation/avoid views: bounded insertion and protected records, the
// hint-collision split by authenticated site_id, the selection order,
// policy timers (6 h / 24 h / retry_after / transient backoff), DISCOVER
// avoid hints, the multi-anchor scan cursor, clock regression and the
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

JoinSelect pick(JoinCandidates& t, const MonotonicMs now) {
  JoinSelect s{};
  const Status st = t.select(now, s);
  CHECK(st.ok());
  return s;
}

JoinCandidate* record_of(JoinCandidates& t, const JoinCandidateKey& k) {
  return const_cast<JoinCandidate*>(t.find(k));
}

// --- Cases -----------------------------------------------------------------------------

void observe_insert_select() {
  JoinCandidates t;
  CHECK(t.size() == 0);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  CHECK(t.size() == 1);
  const JoinSelect s = pick(t, 1000);
  CHECK(s.candidate != nullptr && s.candidate->key == key(7, 42, 0xA5));
  CHECK(s.proxy != nullptr && s.proxy->mac == mac(1));
  // Second OFFER refreshes evidence; policy untouched.
  CHECK(offer(t, 7, 42, 0xA5, 2, -40, 0, 2000) == JoinObserve::Updated);
  const JoinSelect s2 = pick(t, 2000);
  CHECK(s2.proxy != nullptr && s2.proxy->mac == mac(2));  // hops 0 beats hops 1
}

void offer_never_releases_policy() {
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  JoinCandidate* r = record_of(t, key(7, 42, 0xA5));
  CHECK(r != nullptr);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::DenyNotHere, 0, 1100, entropy).ok());
  CHECK(r->policy == JoinCandidatePolicy::AvoidNotHere);
  // A new OFFER refreshes evidence only — the 6 h hold stays (design §5.1
  // rule 2: OFFERs never reset unexpired policies, and never a cooldown).
  CHECK(offer(t, 7, 42, 0xA5, 1, -30, 0, 2000) == JoinObserve::Updated);
  CHECK(pick(t, 2000).candidate == nullptr);
  CHECK(r->policy == JoinCandidatePolicy::AvoidNotHere);
}

void j04_deny_then_other_site() {
  // V1-J04 selection half: strong A denies -> B tried; A stays avoided for
  // the full 6 h, hints on the wire, then A is eligible again.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -30, 0, 1000) == JoinObserve::Inserted);  // A strong
  CHECK(offer(t, 7, 43, 0xA5, 2, -70, 2, 1000) == JoinObserve::Inserted);  // B weaker
  JoinCandidate* a = record_of(t, key(7, 42, 0xA5));
  t.mark_attempt(*a, 0, 1100);
  CHECK(t.apply_outcome(*a, JoinAttemptOutcome::DenyNotHere, 0, 1200, entropy).ok());
  const JoinSelect s = pick(t, 1200);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 43);
  // B tries too — denied harder (24 h); nothing eligible meanwhile.
  JoinCandidate* b = record_of(t, key(7, 43, 0xA5));
  t.mark_attempt(*b, 0, 1300);
  CHECK(t.apply_outcome(*b, JoinAttemptOutcome::DenyBlocked, 0, 1300, entropy).ok());
  CHECK(pick(t, 1400).candidate == nullptr);
  // A is in the avoid hints for this org.
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, 1400, hints) == 2);
  // 6 h - 1 ms: still not eligible even with a fresh route.
  const MonotonicMs almost = 1200 + kJoinAvoidNotHereMs - 1;
  CHECK(offer(t, 7, 42, 0xA5, 1, -20, 0, almost - 10) == JoinObserve::Updated);
  CHECK(pick(t, almost).candidate == nullptr);
  // 6 h elapsed with a fresh route: A is eligible again (B still blocked).
  const MonotonicMs after = 1200 + kJoinAvoidNotHereMs;
  CHECK(offer(t, 7, 42, 0xA5, 1, -20, 0, after) == JoinObserve::Updated);
  const JoinSelect s2 = pick(t, after);
  CHECK(s2.candidate != nullptr && s2.candidate->key.site_hint == 42);
}

void j05_pending_retry_after() {
  // V1-J05 selection half: pending site is retried exactly at retry_after,
  // never earlier; an avoided site never competes meanwhile.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -30, 0, 1000) == JoinObserve::Inserted);  // A
  CHECK(offer(t, 7, 43, 0xA5, 2, -40, 1, 1000) == JoinObserve::Inserted);  // B assigned
  JoinCandidate* a = record_of(t, key(7, 42, 0xA5));
  t.mark_attempt(*a, 0, 1100);
  CHECK(t.apply_outcome(*a, JoinAttemptOutcome::DenyNotHere, 0, 1200, entropy).ok());
  JoinCandidate* b = record_of(t, key(7, 43, 0xA5));
  t.mark_attempt(*b, 0, 1300);
  CHECK(t.apply_outcome(*b, JoinAttemptOutcome::PendingAssignment, 30, 1300, entropy).ok());
  CHECK(b->policy == JoinCandidatePolicy::Pending);
  CHECK(b->eligible_at_ms == 1300 + 30000);
  CHECK(pick(t, 1400).candidate == nullptr);
  CHECK(pick(t, 31299).candidate == nullptr);                // 1 ms early
  const JoinSelect s = pick(t, 31300);                       // exactly retry_after
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 43);
}

void ordering() {
  JoinCandidates t;
  // Untried beats transient-eligible; among untried, hops asc decides.
  CHECK(offer(t, 7, 10, 0xA5, 1, -50, 2, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 11, 0xA5, 2, -50, 1, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 12, 0xA5, 3, -50, 3, 1000) == JoinObserve::Inserted);
  JoinSelect s = pick(t, 1000);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 11);  // hops 1
  // Transient-failed but expired record loses to a never-tried one.
  JoinCandidate* r11 = record_of(t, key(7, 11, 0xA5));
  t.mark_attempt(*r11, 0, 1100);
  CHECK(t.apply_outcome(*r11, JoinAttemptOutcome::Failed, 0, 1200, entropy).ok());
  const MonotonicMs after = r11->eligible_at_ms + 10;
  CHECK(offer(t, 7, 10, 0xA5, 1, -50, 2, after - 5) == JoinObserve::Updated);
  s = pick(t, after);
  // r10 (untried, hops2) vs r12 (untried, hops3) vs r11 (transient, hops1):
  // untried first, then hops -> r10.
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 10);
  // Same quality: RSSI desc, then oldest last_attempt (0 = never tried).
  JoinCandidates t2;
  CHECK(offer(t2, 7, 20, 0xA5, 1, -40, 2, 1000) == JoinObserve::Inserted);
  CHECK(offer(t2, 7, 21, 0xA5, 2, -40, 2, 1000) == JoinObserve::Inserted);
  s = pick(t2, 1000);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 20);  // key order
  JoinCandidate* r21 = record_of(t2, key(7, 21, 0xA5));
  t2.mark_attempt(*r21, 0, 1500);
  CHECK(t2.apply_outcome(*r21, JoinAttemptOutcome::AllowVerified, 0, 1500, entropy).ok());
  s = pick(t2, 1600);
  // Equal hops/RSSI: r21 attempted at 1500, r20 never (0) -> older wins.
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 20);
  // Preferred membership outranks everything.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 30, 0xA5, 1, -30, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t3, 7, 31, 0xA5, 2, -60, 4, 1000) == JoinObserve::Inserted);
  JoinCandidate* r31 = nullptr;
  CHECK(t3.bind_authenticated(key(7, 31, 0xA5), 0xAAAA, 1100, r31).ok());
  t3.set_preferred(0xAAAA, 7, 31);
  CHECK(r31->preferred);
  s = pick(t3, 1200);
  CHECK(s.candidate != nullptr && s.candidate->key.site_hint == 31);
}

void freshness_and_flags() {
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 1, 1000) == JoinObserve::Inserted);
  // Evidence older than 60 s is stale: not eligible.
  CHECK(pick(t, 1000 + kJoinOfferFreshMs).candidate != nullptr);
  CHECK(pick(t, 1000 + kJoinOfferFreshMs + 1).candidate == nullptr);
  // Flags gate: unreachable or busy proxies never satisfy eligibility.
  JoinCandidates t2;
  CHECK(t2.observe(key(7, 1, 0xA5), obs(1, 0x1001, 1, -30, 0, false, false), 1000) ==
        JoinObserve::Inserted);
  CHECK(pick(t2, 1000).candidate == nullptr);
  CHECK(t2.observe(key(7, 1, 0xA5), obs(1, 0x1001, 1, -30, 0, true, true), 2000) ==
        JoinObserve::Updated);
  CHECK(pick(t2, 2000).candidate == nullptr);
  // Second usable proxy keeps the site eligible.
  CHECK(t2.observe(key(7, 1, 0xA5), obs(2, 0x1002, 1, -40, 1, true, false), 3000) ==
        JoinObserve::Updated);
  const JoinSelect s = pick(t2, 3000);
  CHECK(s.proxy != nullptr && s.proxy->mac == mac(2));
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
  JoinSelect s = pick(t, 1000);
  CHECK(s.proxy != nullptr && s.proxy->mac == mac(2));
  // Both suppressed -> site not eligible until the hold passes.
  t.suppress_proxy(*r, mac(2), 4000, 1000);  // mac2 held until 5000
  CHECK(pick(t, 1000).candidate == nullptr);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 5001) == JoinObserve::Updated);
  s = pick(t, 5001);
  CHECK(s.candidate != nullptr && s.proxy->mac == mac(2));  // mac1 still held
  s = pick(t, 6001);
  CHECK(s.candidate != nullptr && s.proxy->mac == mac(1));  // 5 s hold over
  // Transient failure: policy Transient, backoff in [1000,1250], the
  // attempted proxy suppressed to the same instant.
  r = record_of(t, k);
  t.mark_attempt(*r, 0, 6100);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::Failed, 0, 6100, entropy).ok());
  CHECK(r->policy == JoinCandidatePolicy::Transient);
  CHECK(r->eligible_at_ms >= 7100 && r->eligible_at_ms <= 7350);
  CHECK(r->failures == 1);
  CHECK(r->proxies[0].suppressed_until_ms == r->eligible_at_ms);
  // Second consecutive failure widens the bound: base 2000 -> [2000,2500].
  const MonotonicMs was = r->eligible_at_ms;
  t.mark_attempt(*r, 0, was);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::Failed, 0, was, entropy).ok());
  CHECK(r->failures == 2);
  CHECK(r->eligible_at_ms >= was + 2000 && r->eligible_at_ms <= was + 2500);
  // k saturates at 10 -> base pinned at the 600 s cap, delay flat.
  JoinCandidates t3;
  const JoinCandidateKey k3 = key(7, 1, 0xA5);
  CHECK(t3.observe(k3, obs(1, 0x1001, 1, -50, 0, true), 1000) == JoinObserve::Inserted);
  JoinCandidate* r3 = record_of(t3, k3);
  for (int i = 0; i < 12; ++i) {
    t3.mark_attempt(*r3, 0, 2000 + i);
    CHECK(t3.apply_outcome(*r3, JoinAttemptOutcome::Failed, 0, 2000 + i, entropy2).ok());
  }
  CHECK(r3->policy == JoinCandidatePolicy::Transient);
  CHECK(r3->eligible_at_ms == 2011 + 600000);
}

void authenticated_outcomes() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  JoinCandidate* r = record_of(t, k);
  // AuthorityBusy: wire retry_after taken as-is (never folded into 600 s).
  t.mark_attempt(*r, 0, 1100);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::AuthorityBusy, 3600, 1100, entropy).ok());
  CHECK(r->policy == JoinCandidatePolicy::Busy);
  CHECK(r->eligible_at_ms == 1100 + 3600000);
  // DenyBlocked -> 24 h.
  t.mark_attempt(*r, 0, 1200);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::DenyBlocked, 0, 1200, entropy).ok());
  CHECK(r->policy == JoinCandidatePolicy::AvoidBlocked);
  CHECK(r->eligible_at_ms == 1200 + kJoinAvoidBlockedMs);
  // MalformedResult -> 24 h on the authenticated record.
  t.mark_attempt(*r, 0, 1300);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::MalformedResult, 0, 1300, entropy).ok());
  CHECK(r->eligible_at_ms == 1300 + kJoinAvoidBlockedMs);
  // AuthenticationFailed -> 24 h on the observed key.
  t.mark_attempt(*r, 0, 1400);
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::AuthenticationFailed, 0, 1400, entropy).ok());
  CHECK(r->eligible_at_ms == 1400 + kJoinAvoidBlockedMs);
  // Removed without membership evidence -> 600 s suppression only.
  JoinCandidates t2;
  CHECK(offer(t2, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  JoinCandidate* r2 = record_of(t2, key(7, 1, 0xA5));
  CHECK(t2.apply_outcome(*r2, JoinAttemptOutcome::RemovedNoMembership, 0, 1100, entropy).ok());
  CHECK(r2->policy == JoinCandidatePolicy::Transient);
  CHECK(r2->eligible_at_ms == 1100 + kJoinSuppressNoMemberMs);
  CHECK(r2->failures == 0);
  // Verified removal evicts the record entirely.
  CHECK(t2.apply_outcome(*r2, JoinAttemptOutcome::RemovedVerified, 0, 1200, entropy).ok());
  CHECK(t2.find(key(7, 1, 0xA5)) == nullptr);
  CHECK(t2.size() == 0);
  // Allow clears the streak and the scan cycle counter.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  JoinCandidate* r3 = record_of(t3, key(7, 1, 0xA5));
  t3.mark_attempt(*r3, 0, 1100);
  CHECK(t3.apply_outcome(*r3, JoinAttemptOutcome::Failed, 0, 1100, entropy).ok());
  CHECK(r3->failures == 1);
  for (int i = 0; i < 12; ++i) t3.note_scan_cycle_failed();
  MonotonicMs d = 0;
  // Saturated cycle backoff loses to the record's near transient retry.
  CHECK(t3.next_scan_deadline(2000, entropy2, d).ok());
  CHECK(d == r3->eligible_at_ms);
  t3.mark_attempt(*r3, 0, r3->eligible_at_ms);
  CHECK(t3.apply_outcome(*r3, JoinAttemptOutcome::AllowVerified, 0, r3->eligible_at_ms,
                         entropy)
            .ok());
  CHECK(r3->policy == JoinCandidatePolicy::Untried && r3->failures == 0);
  CHECK(t3.next_scan_deadline(r3->eligible_at_ms, entropy2, d).ok());
  CHECK(d <= r3->eligible_at_ms + 1250);  // cycle counter reset by success
  CHECK(pick(t3, r3->eligible_at_ms).candidate != nullptr);
}

void capacity_and_protection() {
  JoinCandidates t;
  // Fill all 8 with protected records: 4 avoided, 2 pending, 1 busy, 1
  // in-flight attempt (selected).
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000) ==
          JoinObserve::Inserted);
  }
  for (std::uint32_t i = 1; i <= 4; ++i) {
    JoinCandidate* r = record_of(t, key(7, i, 0xA5));
    CHECK(t.apply_outcome(*r, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  }
  CHECK(t.apply_outcome(*record_of(t, key(7, 5, 0xA5)), JoinAttemptOutcome::PendingAssignment,
                        60, 1100, entropy)
            .ok());
  CHECK(t.apply_outcome(*record_of(t, key(7, 6, 0xA5)), JoinAttemptOutcome::PendingAssignment,
                        60, 1100, entropy)
            .ok());
  CHECK(t.apply_outcome(*record_of(t, key(7, 7, 0xA5)), JoinAttemptOutcome::AuthorityBusy, 60,
                        1100, entropy)
            .ok());
  t.mark_attempt(*record_of(t, key(7, 8, 0xA5)), 0, 1100);
  // All protected: the 9th site is dropped, counted, and nothing is evicted.
  CHECK(offer(t, 7, 9, 0xA5, 9, -20, 0, 1200) == JoinObserve::NoCapacity);
  CHECK(t.size() == 8);
  CHECK(t.stats().dropped_no_capacity == 1);
  // Now a table of untried/transient records: the stalest is replaced.
  JoinCandidates t2;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t2, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1,
                1000 + i) == JoinObserve::Inserted);
  }
  CHECK(t2.apply_outcome(*record_of(t2, key(7, 3, 0xA5)), JoinAttemptOutcome::Failed, 0,
                         2000, entropy)
            .ok());
  const MonotonicMs evictable_deadline =
      record_of(t2, key(7, 3, 0xA5))->eligible_at_ms;
  // Site 1 has the stalest observation (t=1001); site 3 is transient but its
  // hold expired -> both evictable; the stalest last_seen is replaced.
  CHECK(offer(t2, 7, 9, 0xA5, 9, -20, 0, evictable_deadline + 10) == JoinObserve::Evicted);
  CHECK(t2.find(key(7, 1, 0xA5)) == nullptr);
  CHECK(t2.find(key(7, 9, 0xA5)) != nullptr);
  CHECK(t2.stats().evicted == 1);
}

void hint_collision_split() {
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  JoinCandidate* r = nullptr;
  CHECK(t.bind_authenticated(k, 0x1111, 1100, r).ok() && r != nullptr);
  CHECK(r->site_id_authenticated && r->site_id == 0x1111);
  // Same site again: same record, no split.
  JoinCandidate* r2 = nullptr;
  CHECK(t.bind_authenticated(k, 0x1111, 1200, r2).ok());
  CHECK(r2 == r && t.size() == 1);
  // Colliding hint resolves to a DIFFERENT site: split into a second record
  // that inherits the key-level observation but none of the policy.
  CHECK(t.apply_outcome(*r, JoinAttemptOutcome::DenyBlocked, 0, 1250, entropy).ok());
  JoinCandidate* r3 = nullptr;
  CHECK(t.bind_authenticated(k, 0x2222, 1300, r3).ok() && r3 != nullptr);
  CHECK(r3 != r && r3->site_id == 0x2222 && r3->site_id_authenticated);
  CHECK(r3->policy == JoinCandidatePolicy::Untried);
  CHECK(r3->proxies[0].present);  // evidence is key-level, copied on split
  CHECK(t.size() == 2 && t.stats().auth_splits == 1);
  // The split record stays eligible (different authenticated site) — a
  // hold on one site_id does not punish the other.
  const JoinSelect s = pick(t, 1400);
  CHECK(s.candidate == r3);
  // OFFER updates BOTH records sharing the key.
  CHECK(offer(t, 7, 42, 0xA5, 5, -30, 0, 1500) == JoinObserve::Updated);
  CHECK(r->last_seen_ms == 1500 && r3->last_seen_ms == 1500);
}

void policy_merge_same_site() {
  // Two different keys resolve to the same authenticated site_id: the
  // stronger hold merges — a colliding key cannot bypass a 24 h avoid.
  JoinCandidates t;
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 8, 42, 0xB5, 2, -60, 1, 1000) == JoinObserve::Inserted);
  JoinCandidate *a = nullptr, *b = nullptr;
  CHECK(t.bind_authenticated(key(7, 42, 0xA5), 0x7777, 1100, a).ok());
  CHECK(t.bind_authenticated(key(8, 42, 0xB5), 0x7777, 1100, b).ok());
  CHECK(a != b && t.size() == 2);
  CHECK(t.apply_outcome(*a, JoinAttemptOutcome::DenyBlocked, 0, 1200, entropy).ok());
  CHECK(pick(t, 1300).candidate == nullptr);  // B merged to A's 24 h hold
  // Once the hold expires, either key can carry the site again.
  const MonotonicMs after = 1200 + kJoinAvoidBlockedMs;
  CHECK(offer(t, 8, 42, 0xB5, 2, -60, 1, after - 5) == JoinObserve::Updated);
  const JoinSelect s = pick(t, after);
  CHECK(s.candidate == b);  // untried beats A's expired avoid
}

void split_no_capacity() {
  JoinCandidates t;
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(offer(t, 7, i, 0xA5, static_cast<std::uint8_t>(i), -50, 1, 1000) ==
          JoinObserve::Inserted);
  }
  // The key is already bound to site 0x8888, so a different site_id must
  // split — which needs a slot the fully-protected table cannot give.
  JoinCandidate* first = nullptr;
  CHECK(t.bind_authenticated(key(7, 1, 0xA5), 0x8888, 1050, first).ok());
  for (std::uint32_t i = 1; i <= 8; ++i) {
    CHECK(t.apply_outcome(*record_of(t, key(7, i, 0xA5)), JoinAttemptOutcome::DenyBlocked, 0,
                          1100, entropy)
              .ok());
  }
  // Bind a colliding site to an existing key: no evictable record -> abort.
  JoinCandidate* r = nullptr;
  const Status st = t.bind_authenticated(key(7, 1, 0xA5), 0x9999, 1200, r);
  CHECK(!st.ok() && st.code == StatusCode::NoCapacity);
  CHECK(r == nullptr && t.stats().auth_split_failed == 1);
}

void avoid_hint_rules() {
  JoinCandidates t;
  CHECK(offer(t, 7, 11, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 22, 0xA5, 2, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 7, 33, 0xA5, 3, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t, 8, 11, 0xB5, 4, -50, 0, 1000) == JoinObserve::Inserted);  // other org
  CHECK(t.apply_outcome(*record_of(t, key(7, 11, 0xA5)), JoinAttemptOutcome::DenyNotHere, 0,
                        1100, entropy)
            .ok());
  CHECK(t.apply_outcome(*record_of(t, key(7, 22, 0xA5)), JoinAttemptOutcome::DenyBlocked, 0,
                        1100, entropy)
            .ok());
  CHECK(t.apply_outcome(*record_of(t, key(7, 33, 0xA5)), JoinAttemptOutcome::DenyBlocked, 0,
                        1100, entropy)
            .ok());
  CHECK(t.apply_outcome(*record_of(t, key(8, 11, 0xB5)), JoinAttemptOutcome::DenyBlocked, 0,
                        1100, entropy)
            .ok());
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
  JoinCandidate* bound = nullptr;
  CHECK(t2.bind_authenticated(key(7, 55, 0xA5), 0xAAAA, 1050, bound).ok());
  t2.set_preferred(0xAAAA, 7, 55);
  CHECK(bound->preferred);
  CHECK(t2.apply_outcome(*bound, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
  CHECK(t2.avoid_hints(7, 1200, hints) == 0);
  CHECK(t2.preferred_hint(7) == 55 && t2.preferred_hint(8) == 0);
  // Ambiguous hint: two DIFFERENT keys carrying site_hint 77 — excluded.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 77, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(offer(t3, 7, 77, 0xC3, 2, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(t3.apply_outcome(*record_of(t3, key(7, 77, 0xA5)), JoinAttemptOutcome::DenyBlocked,
                         0, 1100, entropy)
            .ok());
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
  CHECK(t2.apply_outcome(*record_of(t2, key(7, 1, 0xA5)),
                         JoinAttemptOutcome::PendingAssignment, 30, 1100, entropy2)
            .ok());
  CHECK(t2.next_scan_deadline(1200, entropy2, d).ok());
  // min(backoff, eligibility): the ~1 s backoff wakes first and the pending
  // site is retried when its own deadline arrives on a later ask.
  CHECK(d >= 2200 && d <= 2450 && d < 31100);
  // A 3600 s pending still yields a scan every <=600 s for unknown sites.
  JoinCandidates t3;
  CHECK(offer(t3, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(t3.apply_outcome(*record_of(t3, key(7, 1, 0xA5)),
                         JoinAttemptOutcome::PendingAssignment, 3600, 1100, entropy2)
            .ok());
  CHECK(t3.next_scan_deadline(1200, entropy2, d).ok());
  CHECK(d <= 601200 && d >= 2200);  // in [backoff, 600 s] — never the 3600 s
  // Long avoids likewise: 24 h holds never postpone rediscovery past 600 s.
  JoinCandidates t4;
  CHECK(offer(t4, 7, 1, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  CHECK(t4.apply_outcome(*record_of(t4, key(7, 1, 0xA5)), JoinAttemptOutcome::DenyBlocked, 0,
                          1100, entropy2)
            .ok());
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
  JoinSelect s{};
  CHECK(!t.select(9999, s).ok());
  MonotonicMs d = 0;
  CHECK(!t.next_scan_deadline(9999, entropy, d).ok());
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, 9999, hints) == 0);
  CHECK(t.clock_uncertain());
  CHECK(t.stats().clock_regressions >= 4);
  // Time catches up again: operation resumes, nothing released early.
  CHECK(offer(t, 7, 43, 0xA5, 2, -50, 0, 10000) == JoinObserve::Inserted);
  CHECK(pick(t, 10000).candidate != nullptr);
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
  JoinCandidate* source = nullptr;
  CHECK(t.bind_authenticated(key(7, 1, 0xA5), 0xAAAA, 1100, source).ok());
  CHECK(source != nullptr);
  JoinCandidate* split = nullptr;
  CHECK(t.bind_authenticated(key(7, 1, 0xA5), 0xBBBB, 1200, split).ok());
  CHECK(split != nullptr);
  if (split != nullptr) {
    CHECK(split->occupied);
    CHECK(split->site_id == 0xBBBB && split->site_id_authenticated);
    CHECK(split->policy == JoinCandidatePolicy::Untried);
    CHECK(split->proxies[0].present);  // key-level evidence copied, not lost
  }
  CHECK(t.size() == 8);  // a victim was replaced — the table never shrinks
  CHECK(t.stats().evicted == 1);
  // The victim is the stalest record that is NOT the source.
  CHECK(t.find(key(7, 2, 0xA5)) == nullptr);
  const JoinCandidate* kept = t.find(key(7, 1, 0xA5));
  CHECK(kept != nullptr);
  if (kept != nullptr) {
    CHECK(kept->site_id_authenticated && kept->site_id == 0xAAAA);
    CHECK(kept != split);
  }
}

void split_moves_attempt_state() {
  // The in-flight attempt (selected + proxy choice) belongs to the newly
  // proven site after a split; the source must not keep `selected` forever
  // (a stuck selected flag makes the source unevictable).
  JoinCandidates t;
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  JoinCandidate* source = nullptr;
  CHECK(t.bind_authenticated(k, 0xAAAA, 1100, source).ok());
  CHECK(source != nullptr);
  if (source == nullptr) return;
  t.mark_attempt(*source, 0, 1200);
  CHECK(source->selected);
  JoinCandidate* split = nullptr;
  CHECK(t.bind_authenticated(k, 0xBBBB, 1300, split).ok());
  CHECK(split != nullptr);
  if (split != nullptr) {
    CHECK(split->selected);
    CHECK(split->attempted_proxy == 0);
    CHECK(split->last_attempt_ms == 1200);
  }
  CHECK(!source->selected);
  CHECK(source->attempted_proxy == -1);
  // The released source is evictable again: fill the table, then the 9th
  // key replaces the stalest record — the source observed at t=1000.
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
  const JoinCandidateKey k = key(7, 42, 0xA5);
  CHECK(offer(t, 7, 42, 0xA5, 1, -50, 0, 1000) == JoinObserve::Inserted);
  JoinCandidate* a = nullptr;
  CHECK(t.bind_authenticated(k, 0xAAAA, 1100, a).ok());
  CHECK(a != nullptr);
  if (a == nullptr) return;
  CHECK(t.apply_outcome(*a, JoinAttemptOutcome::DenyBlocked, 0, 1200, entropy).ok());
  JoinCandidate* b = nullptr;
  CHECK(t.bind_authenticated(k, 0xBBBB, 1300, b).ok());
  CHECK(b != nullptr);
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, 1400, hints) == 0);  // hint 42 suppressed, not sent
  // B is a different authenticated site: eligible despite A's hold.
  const JoinSelect s = pick(t, 1400);
  CHECK(s.candidate == b);
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
    JoinCandidate* r = record_of(t, key(7, i, 0xA5));
    CHECK(r != nullptr);
    if (r != nullptr) {
      CHECK(t.apply_outcome(*r, JoinAttemptOutcome::DenyBlocked, 0, 1100, entropy).ok());
    }
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
    JoinCandidate* r = record_of(t2, key(7, i, 0xA5));
    CHECK(r != nullptr);
    if (r != nullptr) {
      CHECK(t2.apply_outcome(*r, JoinAttemptOutcome::PendingAssignment, 60, 1100, entropy)
                .ok());
    }
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
    JoinCandidate* r = record_of(t, key(7, i, 0xA5));
    CHECK(r != nullptr);
    if (r != nullptr) {
      CHECK(t.apply_outcome(*r, JoinAttemptOutcome::DenyBlocked, 0, t0, entropy).ok());
      CHECK(r->eligible_at_ms == kMax);
    }
  }
  CHECK(pick(t, kMax).candidate == nullptr);  // still held, not selectable
  CHECK(offer(t, 7, 9, 0xA5, 9, -20, 0, kMax) == JoinObserve::NoCapacity);
  CHECK(t.size() == 8);
  std::array<std::uint32_t, kZtAvoidHints> hints{};
  CHECK(t.avoid_hints(7, kMax, hints) == 2);  // saturated avoids stay on wire
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
      {"split_no_capacity", split_no_capacity},
      {"avoid_hint_rules", avoid_hint_rules},
      {"next_scan_deadline_rules", next_scan_deadline_rules},
      {"clock_regression", clock_regression},
      {"scan_cursor", scan_cursor},
      {"deadline_helpers", deadline_helpers},
      {"bounds", bounds},
      {"split_excludes_branch_source", split_excludes_branch_source},
      {"split_moves_attempt_state", split_moves_attempt_state},
      {"avoid_hint_split_collision", avoid_hint_split_collision},
      {"expired_policy_evictable", expired_policy_evictable},
      {"saturated_hold_never_expires", saturated_hold_never_expires},
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
