#pragma once

// SDK v1 zero-touch join candidate table (docs/design/sdk-v1/02-zero-touch-join.md
// §5, §10; design P3-4 §5, §9; plan P3-4 PR 2). One fixed table of at most 8
// observed sites that serves both views: the candidate list and the
// avoid/penalty view — no second list, no unbounded state, no NVS.
//
// A record's search key is the *observed* tuple (org_hint, site_hint,
// network_low32): 32-bit hints that a site cannot authenticate by itself.
// Only a successful m2 binds an authenticated site_id to a record, and the
// same key may then split into two records when colliding hints resolve to
// different site_ids (design §5.2). Authorization is never reused across
// records or sites sharing a hint: records that resolve to the same
// authenticated site_id merge their policy to the *stronger* hold (the later
// eligible_at), so a 24 h avoid cannot be bypassed by a colliding OFFER.
//
// Scope: OFFER observations, policy bookkeeping, bounded selection, the
// multi-anchor scan cursor, DISCOVER avoid-hint packing and the retry/backoff
// math. No cookies, no crypto, no link ownership — the Joiner (PR 3) drives
// the windows, the attempts and the outcomes.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery.hpp"  // EntropySource
#include "routeloom/sdkv1_join_handshake.hpp"  // JoinAttemptOutcome
#include "routeloom/sdkv1_join_transport.hpp"  // kZtAvoidHints, kZtHopsUnknown
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- Bounds and timing (design §5, §9, §4.1) ---------------------------------------
constexpr std::size_t kJoinCandidateMax = 8;       // one physical table
constexpr std::size_t kJoinCandidateProxyMax = 2;  // best 2 proxies per site
constexpr std::size_t kJoinScanChannelMax = 3;     // default {1,6,11}
constexpr std::size_t kJoinAnchorMax = 3;          // active Site CA hints
// OFFER evidence expires after 60 s without observation; policy holds (6 h /
// 24 h / retry_after) are NOT erased by observation expiry.
constexpr std::uint64_t kJoinOfferFreshMs = 60000;
constexpr std::uint64_t kJoinScanWindowMs = 320;
constexpr std::uint64_t kJoinChannelTuneMs = 250;
constexpr std::uint64_t kJoinMinM1IntervalMs = 2000;
constexpr std::uint64_t kJoinAvoidNotHereMs = 21600000;   // 6 h from m4
constexpr std::uint64_t kJoinAvoidBlockedMs = 86400000;   // 24 h
constexpr std::uint64_t kJoinSuppressNoMemberMs = 600000; // Removed w/o evidence
constexpr std::uint64_t kJoinBackoffMaxMs = 600000;       // scan/avoid cap
constexpr std::uint32_t kJoinTransientBaseMs = 1000;      // 1000*2^k, k<=10
constexpr std::uint8_t kJoinTransientMaxK = 10;
constexpr std::size_t kJoinCandidateRecordMax = 160;      // size gate, §9
// Sentinel of next_eligible_ms when no record has a pending eligibility.
constexpr MonotonicMs kJoinNoDeadline = ~MonotonicMs{0};

// m1->m2 and m3->m4 wait bounds (design §4.1): hops is unauthenticated and
// used only inside its bound; 255 (unknown) takes the cap.
constexpr std::uint32_t join_m2_deadline_ms(std::uint8_t authority_hops) noexcept {
  return authority_hops == kZtHopsUnknown
             ? 6000u
             : static_cast<std::uint32_t>(
                   std::min<std::uint32_t>(6000, 2000 + 300u * authority_hops));
}
constexpr std::uint32_t join_m4_deadline_ms(std::uint8_t authority_hops,
                                            std::uint32_t decision_timeout_ms) noexcept {
  const std::uint64_t t = static_cast<std::uint64_t>(join_m2_deadline_ms(authority_hops)) +
                          decision_timeout_ms;
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(10000, t));
}

// --- Record ------------------------------------------------------------------------
// Observed search key; NOT an authenticated identity.
struct JoinCandidateKey {
  std::uint32_t org_hint{0};
  std::uint32_t site_hint{0};
  std::uint32_t network_low32{0};

  bool operator==(const JoinCandidateKey& o) const noexcept {
    return org_hint == o.org_hint && site_hint == o.site_hint &&
           network_low32 == o.network_low32;
  }
};

// What one OFFER told us about a route to the site (unauthenticated).
struct JoinProxyObservation {
  MacAddress mac{};
  NodeId node{kInvalidNodeId};
  std::uint8_t channel{0};
  std::int16_t rssi{0};
  std::uint8_t authority_hops{kZtHopsUnknown};
  bool authority_reachable{false};
  bool proxy_busy{false};
};

// Stored proxy evidence: the observation plus freshness/suppression timers.
// Cookies and nonces are never kept (design §5.1).
struct JoinCandidateProxy {
  bool present{false};
  MacAddress mac{};
  NodeId node{kInvalidNodeId};
  std::uint8_t channel{0};
  std::int16_t rssi{0};
  std::uint8_t authority_hops{kZtHopsUnknown};
  bool authority_reachable{false};
  bool proxy_busy{false};
  MonotonicMs last_seen_ms{0};
  MonotonicMs suppressed_until_ms{0};  // transient path failure / busy hint
};

enum class JoinCandidatePolicy : std::uint8_t {
  Untried = 0,
  Transient,      // temporary failure backoff (bounded, saturated)
  Pending,        // authenticated PendingAssignment; retry_after applies
  Busy,           // authenticated AuthorityBusy; retry_after applies
  AvoidNotHere,   // authenticated DenyNotHere; 6 h
  AvoidBlocked,   // authenticated DenyBlocked / invalid / bad m2; 24 h
};

struct JoinCandidate {
  bool occupied{false};
  JoinCandidateKey key{};
  // Authenticated binding, set only after m2 verified the SiteCert chain and
  // the responder signature. Never filled from OFFERs alone.
  std::uint64_t site_id{0};
  bool site_id_authenticated{false};
  JoinCandidateProxy proxies[kJoinCandidateProxyMax]{};
  JoinCandidatePolicy policy{JoinCandidatePolicy::Untried};
  MonotonicMs eligible_at_ms{0};    // hold expiry of the current policy
  MonotonicMs last_seen_ms{0};      // newest OFFER for this key
  MonotonicMs last_attempt_ms{0};   // 0 = never attempted
  std::uint8_t failures{0};         // consecutive transient failures (k)
  bool preferred{false};            // authenticated former membership (RAM)
  bool selected{false};             // an attempt is currently bound here
  std::int8_t attempted_proxy{-1};  // index of the proxy the attempt uses
  // MAC of the proxy the last Failed outcome used (zero = none). The record
  // and proxy holds of a failure expire together, so rank alone would
  // reselect the same failed path; selection prefers a usable alternate
  // while this remembers it. Tracked by MAC — not by slot index — because
  // later OFFERs may replace proxy slots before the next selection.
  MacAddress last_failed_proxy{};
};
static_assert(sizeof(JoinCandidate) <= kJoinCandidateRecordMax,
              "join candidate record must stay within the 160 B bound");

// --- Scan cursor ---------------------------------------------------------------------
// Channels (1..14, unique, <=3) x active Site CA org hints (unique, <=3):
// one 320 ms DISCOVER window per pair, channel outer so each tune serves up
// to three windows (design §4.1, §9).
struct JoinScanConfig {
  std::array<std::uint8_t, kJoinScanChannelMax> channels{};
  std::uint8_t channel_count{0};
  std::array<std::uint32_t, kJoinAnchorMax> org_hints{};
  std::uint8_t org_hint_count{0};
};

struct JoinScanStep {
  std::uint8_t channel{0};
  std::uint32_t org_hint{0};
  bool valid{false};
};

// --- Results ---------------------------------------------------------------------------
enum class JoinObserve : std::uint8_t {
  Updated = 0,   // existing key: evidence refreshed, policy untouched
  Inserted,      // new key into a free slot
  Evicted,       // new key replaced an old untried/transient record
  NoCapacity,    // all 8 records protected: candidate dropped (counted)
  Rejected,      // malformed key/proxy evidence or clock regression
};

struct JoinSelect {
  const JoinCandidate* candidate{nullptr};
  const JoinCandidateProxy* proxy{nullptr};
};

struct JoinCandidatesStats {
  std::uint32_t observations{0};
  std::uint32_t inserted{0};
  std::uint32_t evicted{0};
  std::uint32_t dropped_no_capacity{0};
  std::uint32_t rejected{0};
  std::uint32_t auth_splits{0};         // hint collision resolved by site_id
  std::uint32_t auth_split_failed{0};   // collision but table full
  std::uint32_t selections{0};
  std::uint32_t selections_empty{0};
  std::uint32_t proxy_suppressions{0};
  std::uint32_t entropy_failures{0};
  std::uint32_t clock_regressions{0};
};

// --- The table ---------------------------------------------------------------------------
// Single-threaded, allocation-free; the caller serializes access like the
// rest of the join core. Time is the uint64 monotonic ms contract of design
// §4.1: every entry taking `now_ms` refuses while the clock is uncertain. A
// regression sets clock_uncertain() once, counts it once, and the flag stays
// until a new instance — catching up does not resume this table.
class JoinCandidates {
 public:
  JoinCandidates() noexcept = default;
  JoinCandidates(const JoinCandidates&) = delete;
  JoinCandidates& operator=(const JoinCandidates&) = delete;

  // --- scan cursor ---
  // Validates the config (channels 1..14 unique, hints deduped to <=3). The
  // cursor starts at scan_begin(); each step is one 320 ms window for the
  // caller. scan_advance() returns false when the 9 windows are exhausted.
  Status configure_scan(const JoinScanConfig& config) noexcept;
  JoinScanStep scan_begin() noexcept;
  bool scan_advance() noexcept;
  JoinScanStep scan_step() const noexcept;

  // --- observation ---
  // One OFFER that already passed the codec, admission and current-org gate.
  // Updates proxy evidence on every record sharing the key (observation is
  // key-level), keeps at most the best 2 proxies, and never resets an
  // unexpired pending/busy/avoid policy to untried (design §5.1 rule 2).
  JoinObserve observe(const JoinCandidateKey& key, const JoinProxyObservation& proxy,
                      MonotonicMs now_ms) noexcept;

  // --- authentication ---
  // After m2 authenticated: bind site_id to the record at `key`. If the key
  // is already bound to a DIFFERENT site_id (hint collision), split into a
  // second record sharing the key; the in-flight attempt state (selected,
  // proxy choice) moves to the new record and the source drops back to idle.
  // Refuses when no slot can be made (design §5.2: full table aborts the
  // attempt rather than conflating). Re-proving an already-known site on a
  // split key likewise moves the in-flight state onto that record — and is
  // refused with InvalidState when the proven site is still held, so no m3
  // is sent to it; both records are left idle then.
  Status bind_authenticated(const JoinCandidateKey& key, std::uint64_t site_id,
                            MonotonicMs now_ms, JoinCandidate*& record) noexcept;

  // --- attempt bookkeeping ---
  // Mark the start of an exchange through `proxy_index` of `record`.
  void mark_attempt(JoinCandidate& record, std::uint8_t proxy_index,
                    MonotonicMs now_ms) noexcept;
  // Begin the attempt chosen by select(): validates that `sel` still points
  // into this table's current records and marks that record/proxy. Foreign,
  // stale or empty selections are rejected with InvalidArgument.
  Status mark_selected(const JoinSelect& sel, MonotonicMs now_ms) noexcept;
  // Map one authenticated or local outcome onto the record (design §5.2 /
  // §8). Authenticated verdicts clear the transient failure streak; Failed
  // grows it and applies the jittered transient backoff to both the record
  // and the attempted proxy. RemovedVerified evicts the record. On entropy
  // failure the lower backoff bound is used and the stat is counted — an
  // entropy failure must never lengthen a hold or start crypto.
  Status apply_outcome(JoinCandidate& record, JoinAttemptOutcome outcome,
                       std::uint32_t retry_after_s, MonotonicMs now_ms,
                       EntropySource& entropy) noexcept;
  // Suppress one proxy path for up to 600 s (unauthenticated RelayStatus
  // busy/unreachable/aborted or a link delivery failure — never a site deny).
  void suppress_proxy(JoinCandidate& record, const MacAddress& proxy_mac,
                      std::uint32_t suppress_ms, MonotonicMs now_ms) noexcept;

  // --- selection ---
  // The best eligible candidate and its best proxy (design §5.1 rule 4):
  // eligible means the effective hold expired AND a fresh proxy observation
  // with authority_reachable && !proxy_busy exists. Ordering: preferred,
  // untried, hops asc (unknown last), RSSI desc, oldest last_attempt, then
  // key/MAC lexicographic. Unauthenticated flags steer routing only. Among
  // the usable proxies of the winning record, a proxy other than the last
  // failed one wins; the failed path is reused only when alone.
  Status select(MonotonicMs now_ms, JoinSelect& out) noexcept;
  // Earliest future effective eligibility across the table (kJoinNoDeadline
  // when nothing is pending or after a clock regression).
  MonotonicMs next_eligible_ms(MonotonicMs now_ms) noexcept;
  // Deadline of the next scan when nothing is eligible: a jittered
  // saturated backoff in the cycle counter k, cut by the nearest pending
  // eligibility and hard-capped at +600 s so unknown sites are still
  // rediscovered under long avoids (design §4.1). k counts failed scan
  // cycles; an OFFER alone never resets it.
  Status next_scan_deadline(MonotonicMs now_ms, EntropySource& entropy,
                            MonotonicMs& deadline) noexcept;
  void note_scan_cycle_failed() noexcept;  // k++ (saturated)

  // --- DISCOVER avoid hints ---
  // Up to 2 nonzero distinct hints of unexpired avoid records for `org_hint`,
  // latest expiry first then hint order; the preferred site's hint, hints
  // colliding with another record's key, and hints shared with a different
  // authenticated site_id (a split: the hint cannot name one site without
  // suppressing the other) are excluded (design §5.2).
  std::size_t avoid_hints(std::uint32_t org_hint, MonotonicMs now_ms,
                          std::array<std::uint32_t, kZtAvoidHints>& out) noexcept;

  // --- preferred former membership ---
  // The authenticated previous membership kept in RAM. site_id is retained
  // even when site_hint is 0 (the DISCOVER hint is then omitted but the
  // binding still steers selection). Preferred records are chosen first.
  void set_preferred(std::uint64_t site_id, std::uint32_t org_hint,
                     std::uint32_t site_hint) noexcept;
  std::uint32_t preferred_hint(std::uint32_t org_hint) const noexcept;

  // --- accessors ---
  // First occupied record carrying `key` (or nullptr). The mutable overload
  // hands a record to the attempt/outcome APIs without a cast; fields stay
  // owned by the table.
  const JoinCandidate* find(const JoinCandidateKey& key) const noexcept;
  JoinCandidate* find(const JoinCandidateKey& key) noexcept;
  std::size_t size() const noexcept;
  const JoinCandidatesStats& stats() const noexcept { return stats_; }
  bool clock_uncertain() const noexcept { return clock_uncertain_; }

 private:
  bool clock_ok(MonotonicMs now_ms) noexcept;
  JoinCandidate* acquire(MonotonicMs now_ms, bool& evicted,
                         const JoinCandidate* exclude = nullptr) noexcept;
  void upsert_proxy(JoinCandidate& record, const JoinProxyObservation& proxy,
                    MonotonicMs now_ms) noexcept;
  MonotonicMs effective_eligible_at(const JoinCandidate& record) const noexcept;
  static bool proxy_fresh(const JoinCandidateProxy& proxy, MonotonicMs now_ms) noexcept;
  static bool proxy_usable(const JoinCandidateProxy& proxy, MonotonicMs now_ms) noexcept;
  static const JoinCandidateProxy* best_proxy(const JoinCandidate& record,
                                              MonotonicMs now_ms) noexcept;
  static bool better(const JoinCandidate& a, const JoinCandidateProxy& ap,
                     const JoinCandidate& b, const JoinCandidateProxy& bp) noexcept;
  static bool key_less(const JoinCandidateKey& a, const JoinCandidateKey& b) noexcept;
  static bool mac_less(const MacAddress& a, const MacAddress& b) noexcept;
  static MonotonicMs sat_add(MonotonicMs a, std::uint64_t delta_ms) noexcept;
  Status transient_delay(std::uint8_t k, EntropySource& entropy,
                         std::uint64_t& delay_ms) noexcept;

  std::array<JoinCandidate, kJoinCandidateMax> records_{};
  JoinScanConfig scan_{};
  std::uint8_t scan_channel_i_{0};
  std::uint8_t scan_org_i_{0};
  bool scan_active_{false};
  MonotonicMs last_now_ms_{0};
  bool clock_uncertain_{false};
  std::uint8_t scan_failures_{0};  // saturated cycle counter k
  std::uint64_t preferred_site_id_{0};
  std::uint32_t preferred_org_hint_{0};
  std::uint32_t preferred_site_hint_{0};
  JoinCandidatesStats stats_{};
};

}  // namespace routeloom::sdkv1
