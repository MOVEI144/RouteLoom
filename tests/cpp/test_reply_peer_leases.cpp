// ExpectedReply (reply-direction) peer leases (issue #117, design-q116 §6-§7):
// the portable Owner-side lease table — 3 binding entries keyed by
// (BindingId, BindingGeneration) and shared by every transaction on the key,
// 8 use handles with strictly increasing non-reusable serials — plus the
// single driver-release gate and the ReplyPeerPort contract. A FakeOwner
// (binding directory + recording FakeDriver) plays the radio Owner the real
// ESP-NOW runtime must mirror: Stale keeps the driver for reserved replies
// while new DATA stops, revoke/rebind retires unstarted replies without
// reusing handles, physically-unknown TX holds the driver, and late
// completions never resolve a newer binding's send.
//
// Q117-01..04/06/09/13 exercise the Owner-side contract.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/congestion.hpp"
#include "routeloom/reply_peer_leases.hpp"
#include "routeloom/routeloom.h"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                     \
    if (!(expr)) {                                                         \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,   \
                   #expr);                                                 \
      ++failures;                                                          \
    }                                                                      \
  } while (false)
#define CHECK_OK(expr)                                                     \
  do {                                                                     \
    const auto _status = (expr);                                           \
    if (!_status.ok()) {                                                   \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,       \
                   __LINE__, #expr, _status.detail);                       \
      ++failures;                                                          \
    }                                                                      \
  } while (false)
#define CHECK_CODE(expr, want)                                             \
  do {                                                                     \
    const auto _status = (expr);                                           \
    if (_status.code != (want)) {                                          \
      std::fprintf(stderr, "CODE failed %s:%d: %s -> %d, want %d (%s)\n",    \
                   __FILE__, __LINE__, #expr,                              \
                   static_cast<int>(_status.code), static_cast<int>(want),  \
                   _status.detail);                                        \
      ++failures;                                                          \
    }                                                                      \
  } while (false)

using routeloom::BindingGeneration;
using routeloom::BindingId;
using routeloom::ByteView;
using routeloom::ExpectedReplyLeases;
using routeloom::MonotonicMs;
using routeloom::NodeId;
using routeloom::ReplyBinding;
using routeloom::ReplyLeaseToken;
using routeloom::ReplyPeerPort;
using routeloom::Status;
using routeloom::StatusCode;

constexpr NodeId kPeerA = 0xA1;
constexpr NodeId kPeerB = 0xB2;
constexpr NodeId kPeerC = 0xC3;
constexpr NodeId kPeerD = 0xD4;

ReplyBinding binding(const NodeId peer, const std::uint32_t id,
                     const std::uint32_t generation,
                     const std::uint32_t rx_context = 7) noexcept {
  ReplyBinding out{};
  out.peer = peer;
  out.id = BindingId{id};
  out.generation = BindingGeneration{generation};
  out.rx_context_id = rx_context;
  return out;
}

// --- Table: capacity, sharing, handles (Q117-01/02/13) ------------------------

void test_three_bindings_shared_per_key() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken a{}, b{}, c{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, a));
  CHECK_OK(leases.acquire(binding(kPeerB, 2, 1), 1500, 0, b));
  CHECK_OK(leases.acquire(binding(kPeerC, 3, 1), 1500, 0, c));
  CHECK(leases.live_entry_count() == 3);
  CHECK(leases.live_use_count() == 3);
  CHECK(leases.check_invariants());
  // A fourth *binding* is refused even though use slots are free: the pool
  // is 3 per Owner, never 3 per peer (Q117-01).
  ReplyLeaseToken d{};
  CHECK_CODE(leases.acquire(binding(kPeerD, 4, 1), 1500, 0, d), StatusCode::NoCapacity);
  CHECK(leases.live_entry_count() == 3);
  CHECK(leases.live_use_count() == 3);
  // Same key shares the entry but mints a distinct use (Q117-01).
  ReplyLeaseToken a2{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, a2));
  CHECK(!(a == a2));
  CHECK(leases.live_entry_count() == 3);
  CHECK(leases.live_use_count() == 4);
  CHECK(leases.check_invariants());
  CHECK_OK(leases.release(a));
  CHECK_OK(leases.release(b));
  CHECK_OK(leases.release(c));
  CHECK_OK(leases.release(a2));
  CHECK(leases.live_entry_count() == 0);
  CHECK(leases.live_use_count() == 0);
  CHECK(leases.check_invariants());
}

void test_probe_acquire_agrees_with_acquire() {
  // The read-only probe must return acquire's verdict without spending
  // anything: empty table, shared key, full bindings, full uses, retired
  // key, changed identity, dead clock — then the real acquire agrees.
  ExpectedReplyLeases leases{};
  CHECK_OK(leases.probe_acquire(binding(kPeerA, 1, 1), 1500, 0));
  CHECK(leases.live_entry_count() == 0);
  CHECK(leases.live_use_count() == 0);
  ReplyLeaseToken a{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, a));
  CHECK_OK(leases.probe_acquire(binding(kPeerA, 1, 1), 1500, 0));
  ReplyLeaseToken b{}, c{};
  CHECK_OK(leases.acquire(binding(kPeerB, 2, 1), 1500, 0, b));
  CHECK_OK(leases.acquire(binding(kPeerC, 3, 1), 1500, 0, c));
  CHECK_CODE(leases.probe_acquire(binding(kPeerD, 4, 1), 1500, 0),
             StatusCode::NoCapacity);
  ReplyLeaseToken d{};
  CHECK_CODE(leases.acquire(binding(kPeerD, 4, 1), 1500, 0, d),
             StatusCode::NoCapacity);
  CHECK_CODE(leases.probe_acquire(binding(kPeerA, 1, 2), 1500, 0),
             StatusCode::NoCapacity);
  CHECK_CODE(leases.probe_acquire(binding(kPeerD, 1, 1), 1500, 0),
             StatusCode::Conflict);
  CHECK_CODE(leases.probe_acquire(binding(kPeerA, 0, 1), 1500, 0),
             StatusCode::InvalidArgument);
  CHECK_CODE(leases.probe_acquire(binding(kPeerA, 1, 1), 0, 0),
             StatusCode::InvalidArgument);
  CHECK(leases.check_invariants());
  // Retired keys conflict in both.
  CHECK_OK(leases.invalidate_binding(BindingId{2}));
  CHECK_CODE(leases.probe_acquire(binding(kPeerB, 2, 1), 1500, 0),
             StatusCode::Conflict);
  CHECK(leases.live_entry_count() == 3);
  CHECK(leases.live_use_count() == 3);
  CHECK_OK(leases.release(a));
  CHECK_OK(leases.release(b));
  CHECK_OK(leases.release(c));
  CHECK(leases.check_invariants());
  // Eight live uses refuse a ninth in both.
  ReplyLeaseToken uses[8]{};
  for (int i = 0; i < 8; ++i) {
    CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, uses[i]));
  }
  CHECK_CODE(leases.probe_acquire(binding(kPeerA, 1, 1), 1500, 0),
             StatusCode::NoCapacity);
  ReplyLeaseToken ninth{};
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, ninth),
             StatusCode::NoCapacity);
  for (int i = 0; i < 8; ++i) CHECK_OK(leases.release(uses[i]));
  CHECK(leases.check_invariants());
}

void test_eight_uses_then_refused() {
  ExpectedReplyLeases leases{};
  std::array<ReplyLeaseToken, routeloom::kReplyLeaseUsesMax> uses{};
  for (std::size_t i = 0; i < uses.size(); ++i) {
    CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, uses[i]));
  }
  CHECK(leases.live_entry_count() == 1);
  CHECK(leases.live_use_count() == routeloom::kReplyLeaseUsesMax);
  CHECK(leases.check_invariants());
  ReplyLeaseToken extra{};
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, extra),
             StatusCode::NoCapacity);
  // A free use slot on another key is still available.
  CHECK_OK(leases.release(uses[0]));
  ReplyLeaseToken moved{};
  CHECK_OK(leases.acquire(binding(kPeerB, 2, 1), 1500, 0, moved));
  CHECK(leases.live_entry_count() == 2);
  for (std::size_t i = 1; i < uses.size(); ++i) CHECK_OK(leases.release(uses[i]));
  CHECK_OK(leases.release(moved));
  CHECK(leases.live_entry_count() == 0);
  CHECK(leases.check_invariants());
}

void test_keys_split_by_id_and_generation() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken a1{}, a2{}, b1{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, a1));
  // Same NodeId, other generation: a different key, a different entry.
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 2), 1500, 0, a2));
  // Same NodeId, other BindingId: also a different key.
  CHECK_OK(leases.acquire(binding(kPeerA, 9, 1), 1500, 0, b1));
  CHECK(leases.live_entry_count() == 3);
  CHECK(leases.holds_binding(BindingId{1}, BindingGeneration{1}));
  CHECK(leases.holds_binding(BindingId{1}, BindingGeneration{2}));
  CHECK(leases.holds_binding(BindingId{9}, BindingGeneration{1}));
  CHECK(!leases.holds_binding(BindingId{1}, BindingGeneration{3}));
  CHECK(!leases.holds_binding(BindingId{2}, BindingGeneration{1}));
  CHECK(leases.check_invariants());
  CHECK_OK(leases.release(a1));
  CHECK(!leases.holds_binding(BindingId{1}, BindingGeneration{1}));
  CHECK(leases.holds_binding(BindingId{1}, BindingGeneration{2}));
  CHECK_OK(leases.release(a2));
  CHECK_OK(leases.release(b1));
  CHECK(leases.live_entry_count() == 0);
  CHECK(leases.check_invariants());
}

void test_same_key_cannot_change_peer_or_rx_context() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken held{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1, 7), 1500, 0, held));
  ReplyLeaseToken refused{};
  CHECK_CODE(leases.acquire(binding(kPeerB, 1, 1, 7), 1500, 0, refused),
             StatusCode::Conflict);
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1, 8), 1500, 0, refused),
             StatusCode::Conflict);
  CHECK(leases.live_entry_count() == 1);
  CHECK(leases.live_use_count() == 1);
  ReplyBinding owner{};
  CHECK_OK(leases.use_binding(held, owner));
  CHECK(owner == binding(kPeerA, 1, 1, 7));
  CHECK(leases.check_invariants());
  CHECK_OK(leases.release(held));
}

void test_stale_tokens_never_touch_the_new_owner() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken first{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, first));
  CHECK_CODE(leases.release(routeloom::kInvalidReplyLeaseToken), StatusCode::NotFound);
  ReplyLeaseToken forged{first.use_slot, first.serial + 1};
  CHECK_CODE(leases.release(forged), StatusCode::NotFound);
  CHECK(leases.live_use_count() == 1);
  CHECK_OK(leases.release(first));
  CHECK_CODE(leases.release(first), StatusCode::NotFound);  // second release
  // The slot is reused under a new serial; the old token stays dead and the
  // new owner's reference is untouched by stale releases (Q117-02).
  ReplyLeaseToken second{};
  CHECK_OK(leases.acquire(binding(kPeerB, 2, 1), 1500, 0, second));
  CHECK(second.serial != first.serial);
  CHECK_CODE(leases.release(first), StatusCode::NotFound);
  CHECK_CODE(leases.validate(first, 10), StatusCode::NotFound);
  CHECK_OK(leases.validate(second, 10));
  CHECK(leases.live_use_count() == 1);
  CHECK(leases.check_invariants());
  CHECK_OK(leases.release(second));
}

void test_use_serials_never_wrap() {
  std::uint32_t next = 0;
  CHECK(routeloom::next_use_serial(0, next) && next == 1);
  CHECK(routeloom::next_use_serial(1, next) && next == 2);
  CHECK(routeloom::next_use_serial(UINT32_MAX - 1, next) && next == UINT32_MAX);
  CHECK(!routeloom::next_use_serial(UINT32_MAX, next));
  CHECK(next == UINT32_MAX);  // failed issuance leaves the output alone
}

// --- Table: deadlines and the clock (Q117-13, ttl 1500 ms) ---------------------

void test_deadline_clamped_to_now_plus_ttl() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken token{};
  // A far-future request is clamped to now + 1500 ms, never extended.
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 5000, 100, token));
  // A nearer request keeps its own deadline.
  ReplyLeaseToken tight{};
  CHECK_OK(leases.acquire(binding(kPeerB, 2, 1), 900, 100, tight));
  CHECK_OK(leases.validate(token, 100));
  CHECK_OK(leases.validate(tight, 899));
  CHECK_CODE(leases.validate(tight, 900), StatusCode::Expired);
  CHECK_OK(leases.validate(token, 1599));
  CHECK_CODE(leases.validate(token, 1600), StatusCode::Expired);  // now >= deadline
  CHECK_CODE(leases.validate(token, 1601), StatusCode::Expired);
  CHECK_OK(leases.release(token));
  CHECK_OK(leases.release(tight));
}

void test_rejects_unusable_time_and_bindings() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken token{};
  // Already-expired requests are refused, never admitted dead.
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1), 100, 100, token),
             StatusCode::InvalidArgument);
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1), 50, 100, token),
             StatusCode::InvalidArgument);
  // now + ttl must be representable: near the u64 ceiling the admission is
  // refused instead of wrapping the deadline.
  constexpr MonotonicMs kHuge = UINT64_MAX - 100;
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1), UINT64_MAX, kHuge, token),
             StatusCode::CounterExhausted);
  CHECK(leases.live_use_count() == 0);
  CHECK(leases.check_invariants());
  // Zero identity fields are never accepted.
  CHECK_CODE(leases.acquire(binding(0, 1, 1), 1500, 0, token),
             StatusCode::InvalidArgument);
  CHECK_CODE(leases.acquire(binding(kPeerA, 0, 1), 1500, 0, token),
             StatusCode::InvalidArgument);
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 0), 1500, 0, token),
             StatusCode::InvalidArgument);
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1, 0), 1500, 0, token),
             StatusCode::InvalidArgument);
  CHECK(leases.live_use_count() == 0);
}

void test_clock_regression_stops_admission() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken token{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 5000, 1000, token));
  // An earlier observation afterwards is clock uncertainty, not elapsed 0:
  // new admissions stop, and validations cannot be trusted either.
  ReplyLeaseToken other{};
  CHECK_CODE(leases.acquire(binding(kPeerB, 2, 1), 5000, 999, other),
             StatusCode::TimeUncertain);
  CHECK_CODE(leases.validate(token, 999), StatusCode::TimeUncertain);
  CHECK(leases.live_use_count() == 1);
  // Forward time still works; cleanup never depends on the clock.
  CHECK_OK(leases.validate(token, 1000));
  CHECK_OK(leases.release(token));
  CHECK(leases.check_invariants());
}

void test_validated_clock_cannot_regress_on_new_admission() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken first{}, second{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, first));
  CHECK_OK(leases.validate(first, 1000));
  CHECK_CODE(leases.acquire(binding(kPeerB, 2, 1), 1500, 999, second),
             StatusCode::TimeUncertain);
  CHECK(leases.live_use_count() == 1);
  CHECK_OK(leases.release(first));
}

// --- Table: binding invalidation (Q117-04) --------------------------------------

void test_invalidate_binding_retires_uses_keeps_slot_until_released() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken old1{}, old2{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, old1));
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, old2));
  CHECK_OK(leases.invalidate_binding(BindingId{1}));
  // Outstanding uses are dead for validation but still occupy the entry
  // until released: draining, not erased (Q117-04).
  CHECK_CODE(leases.validate(old1, 10), StatusCode::Conflict);
  CHECK(leases.holds_binding(BindingId{1}, BindingGeneration{1}));
  CHECK(leases.live_entry_count() == 1);
  ReplyLeaseToken late{};
  CHECK_CODE(leases.acquire(binding(kPeerA, 1, 1), 1500, 10, late),
             StatusCode::Conflict);
  // The rebound generation is a new key and may be acquired while the old
  // one drains; releasing the old uses frees the old entry.
  ReplyLeaseToken fresh{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 2), 1500, 10, fresh));
  CHECK(leases.live_entry_count() == 2);
  CHECK_OK(leases.release(old1));
  CHECK(leases.live_entry_count() == 2);
  CHECK_OK(leases.release(old2));
  CHECK(leases.live_entry_count() == 1);
  CHECK(leases.check_invariants());
  CHECK_OK(leases.release(fresh));
  CHECK(leases.live_entry_count() == 0);
  CHECK(leases.check_invariants());
}

void test_invalidate_all_and_empty_entries_recycled() {
  ExpectedReplyLeases leases{};
  ReplyLeaseToken a{}, b{};
  CHECK_OK(leases.acquire(binding(kPeerA, 1, 1), 1500, 0, a));
  CHECK_OK(leases.acquire(binding(kPeerB, 2, 1), 1500, 0, b));
  CHECK_OK(leases.invalidate_all());
  CHECK_CODE(leases.validate(a, 10), StatusCode::Conflict);
  CHECK_CODE(leases.validate(b, 10), StatusCode::Conflict);
  CHECK_OK(leases.release(a));
  CHECK_OK(leases.release(b));
  CHECK(leases.live_entry_count() == 0);
  // Fresh keys are acquirable again afterwards.
  ReplyLeaseToken c{};
  CHECK_OK(leases.acquire(binding(kPeerC, 3, 1), 1500, 10, c));
  CHECK_OK(leases.release(c));
  CHECK(leases.check_invariants());
  // Invalidating an unknown id is a no-op, never an error.
  CHECK_OK(leases.invalidate_binding(BindingId{99}));
}

// --- Driver-release gate: the pure decision (Q117-03/06/09 core) -----------------

void test_driver_release_gate_conjunction() {
  using routeloom::DriverReleaseEvidence;
  using routeloom::driver_release_allowed;
  using routeloom::driver_transfer_allowed;
  DriverReleaseEvidence drained{};
  drained.callbacks_drained = true;
  CHECK(driver_release_allowed(drained));
  DriverReleaseEvidence reply = drained;
  reply.reply_uses_live = true;
  CHECK(!driver_release_allowed(reply));  // 1500 ms is not a delete permit
  DriverReleaseEvidence tx = drained;
  tx.tx_in_flight = true;
  CHECK(!driver_release_allowed(tx));
  DriverReleaseEvidence fence = drained;
  fence.fence_or_quarantine = true;
  CHECK(!driver_release_allowed(fence));
  DriverReleaseEvidence pin = drained;
  pin.other_lease_hold = true;
  CHECK(!driver_release_allowed(pin));
  DriverReleaseEvidence topology = drained;
  topology.topology_pin_live = true;
  CHECK(!driver_release_allowed(topology));
  CHECK(driver_transfer_allowed(topology));
  CHECK(!driver_transfer_allowed(reply));
  CHECK(!driver_transfer_allowed(tx));
  DriverReleaseEvidence undrained{};
  CHECK(!driver_release_allowed(undrained));  // owed callbacks hold the peer
}

// --- FakeOwner: reference radio Owner (binding directory + FakeDriver) ----------
//
// The FakeDriver fails sends to unregistered MACs, so dropping a registration
// while a reply is owed is observable in the test.

struct FakeMac {
  std::array<std::uint8_t, 6> bytes{};
};

bool operator==(const FakeMac& a, const FakeMac& b) noexcept { return a.bytes == b.bytes; }

constexpr std::size_t kFakePeersMax = 20;

class FakeDriver {
 public:
  bool fail_next_add{false};
  bool fail_next_del{false};
  // When armed, send() runs the completion synchronously to model a driver
  // context that must never re-enter the Owner's mutators.
  bool sync_completion{false};

  struct Peer {
    FakeMac mac{};
    bool registered{false};
    std::uint32_t owed{0};  // submitted sends awaiting their completion
  };

  bool registered(const FakeMac& mac) const noexcept {
    const Peer* peer = find(mac);
    return peer != nullptr && peer->registered;
  }

  std::uint32_t owed(const FakeMac& mac) const noexcept {
    const Peer* peer = find(mac);
    return peer == nullptr ? 0 : peer->owed;
  }

  std::size_t registered_count() const noexcept {
    std::size_t n = 0;
    for (const auto& peer : peers_) {
      if (peer.registered) ++n;
    }
    return n;
  }

  // Records the send; returns false (and records nothing) for an
  // unregistered MAC.
  bool send(const FakeMac& mac, std::uint32_t binding_tag) noexcept {
    Peer* peer = find(mac);
    if (peer == nullptr || !peer->registered) {
      ++send_unregistered_;
      return false;
    }
    ++peer->owed;
    ++sends_;
    if (sync_completion && completion_ != nullptr) {
      completion_(mac, binding_tag);
    }
    return true;
  }

  using Completion = void (*)(const FakeMac& mac, std::uint32_t binding_tag);

  void set_completion(Completion completion) noexcept { completion_ = completion; }

  // The owed completion lands: resolves only when the binding tag still
  // matches, otherwise it is stale evidence, never a misattributed result.
  void complete(const FakeMac& mac, std::uint32_t binding_tag,
                std::uint32_t current_tag, bool& stale_out) noexcept {
    stale_out = binding_tag != current_tag;
    Peer* peer = find(mac);
    if (peer != nullptr && peer->owed > 0) --peer->owed;
    ++completions_;
  }

  bool add(const FakeMac& mac) noexcept {
    ++adds_;
    if (fail_next_add) {
      fail_next_add = false;
      return false;
    }
    Peer* peer = find(mac);
    if (peer == nullptr) {
      for (auto& slot : peers_) {
        if (!slot.registered && slot.owed == 0) {
          peer = &slot;
          break;
        }
      }
    }
    if (peer == nullptr) return false;
    peer->mac = mac;
    peer->registered = true;
    return true;
  }

  bool del(const FakeMac& mac) noexcept {
    ++dels_;
    if (fail_next_del) {
      fail_next_del = false;
      return false;
    }
    Peer* peer = find(mac);
    if (peer != nullptr) peer->registered = false;
    return true;
  }

  std::uint32_t sends() const noexcept { return sends_; }
  std::uint32_t send_unregistered() const noexcept { return send_unregistered_; }
  std::uint32_t completions() const noexcept { return completions_; }
  std::uint32_t adds() const noexcept { return adds_; }
  std::uint32_t dels() const noexcept { return dels_; }

 private:
  Peer* find(const FakeMac& mac) noexcept {
    for (auto& peer : peers_) {
      if (peer.mac == mac && (peer.registered || peer.owed > 0)) return &peer;
    }
    return nullptr;
  }
  const Peer* find(const FakeMac& mac) const noexcept {
    for (const auto& peer : peers_) {
      if (peer.mac == mac && (peer.registered || peer.owed > 0)) return &peer;
    }
    return nullptr;
  }

  std::array<Peer, kFakePeersMax> peers_{};
  Completion completion_{nullptr};
  std::uint32_t sends_{0};
  std::uint32_t send_unregistered_{0};
  std::uint32_t completions_{0};
  std::uint32_t adds_{0};
  std::uint32_t dels_{0};
};

FakeMac mac_for(const NodeId peer) noexcept {
  FakeMac mac{};
  mac.bytes[0] = 0x02;
  for (std::size_t i = 0; i < 5; ++i) {
    mac.bytes[i + 1] = static_cast<std::uint8_t>((peer >> (8 * i)) & 0xff);
  }
  return mac;
}

enum class FakePhase : std::uint8_t { Reachable, Stale, Suspended, Revoked };

// Reference ReplyPeerPort: the binding directory, the lease table and the
// driver form one Owner behind a reentry guard, exactly the shape the
// production runtime must adopt. Driver callbacks run under the guard, so a
// callback that reaches back into the port sees Busy and changes nothing.
class FakeOwner final : public ReplyPeerPort {
 public:
  struct Mapping {
    NodeId peer{0};
    FakeMac mac{};
    BindingId id{0};
    BindingGeneration generation{0};
    std::uint32_t rx_context{0};
    FakePhase phase{FakePhase::Reachable};
    bool driver_registered{false};
    bool other_hold{false};  // AuthExchange/Migration/Topology pin equivalent
    bool used{false};
  };

  FakeDriver driver;

  bool bind(const NodeId peer, const std::uint32_t id, const std::uint32_t generation,
            const std::uint32_t rx_context) noexcept {
    Mapping* slot = find(peer);
    if (slot == nullptr) {
      for (auto& candidate : directory_) {
        if (!candidate.used) {
          slot = &candidate;
          break;
        }
      }
    }
    if (slot == nullptr) return false;
    slot->peer = peer;
    slot->mac = mac_for(peer);
    slot->id = BindingId{id};
    slot->generation = BindingGeneration{generation};
    slot->rx_context = rx_context;
    slot->phase = FakePhase::Reachable;
    slot->driver_registered = driver.registered(slot->mac);
    slot->other_hold = false;
    slot->used = true;
    return true;
  }

  bool set_phase(const NodeId peer, const FakePhase phase) noexcept {
    Mapping* slot = find(peer);
    if (slot == nullptr) return false;
    slot->phase = phase;
    return true;
  }

  bool set_other_hold(const NodeId peer, const bool hold) noexcept {
    Mapping* slot = find(peer);
    if (slot == nullptr) return false;
    slot->other_hold = hold;
    return true;
  }

  std::uint32_t key_erases() const noexcept { return key_erases_; }
  std::uint32_t stale_completions() const noexcept { return stale_completions_; }
  ExpectedReplyLeases& leases() noexcept { return leases_; }

  // --- ReplyPeerPort ------------------------------------------------------
  Status acquire(const ReplyBinding captured, const MonotonicMs deadline,
                 const MonotonicMs now, ReplyLeaseToken& out) noexcept override {
    if (in_callback_) return Status::error(StatusCode::Busy, "reentrant acquire");
    if (left_) return Status::error(StatusCode::InvalidState, "local membership left");
    const Mapping* slot = find(captured.peer);
    if (slot == nullptr || slot->id != captured.id ||
        slot->generation != captured.generation ||
        slot->rx_context != captured.rx_context_id ||
        slot->phase == FakePhase::Revoked) {
      return Status::error(StatusCode::Conflict, "binding mapping changed");
    }
    const Status status = leases_.acquire(captured, deadline, now, out);
    if (!status) return status;
    // The lease is worthless without the driver record: pin or register it
    // now, and roll the lease back when the driver refuses (Q117-09).
    Mapping* owned = find(captured.peer);
    if (owned == nullptr || !ensure_driver(*owned)) {
      (void)leases_.release(out);
      out = routeloom::kInvalidReplyLeaseToken;
      return Status::error(StatusCode::RadioFailure, "driver register refused");
    }
    return Status::success();
  }

  Status release(const ReplyLeaseToken token) noexcept override {
    if (in_callback_) return Status::error(StatusCode::Busy, "reentrant release");
    return leases_.release(token);
  }

  Status validate(const ReplyLeaseToken token, const MonotonicMs now) noexcept override {
    if (in_callback_) return Status::error(StatusCode::Busy, "reentrant validate");
    return leases_.validate(token, now);
  }

  Status send_reply(const ReplyLeaseToken token, const std::uint64_t /*tx_token*/,
                    const ByteView /*frame*/, const MonotonicMs now) noexcept override {
    if (in_callback_) return Status::error(StatusCode::Busy, "reentrant send_reply");
    const Status valid = leases_.validate(token, now);
    if (!valid) return valid;
    ReplyBinding held{};
    const Status resolved = leases_.use_binding(token, held);
    if (!resolved) return resolved;
    const Mapping* slot = find(held.peer);
    if (slot == nullptr || slot->id != held.id || slot->generation != held.generation ||
        slot->rx_context != held.rx_context_id || slot->phase == FakePhase::Revoked) {
      return Status::error(StatusCode::Conflict, "binding mapping changed");
    }
    // Unlike new DATA, a reserved reply may still use the Stale/Suspended
    // registration of its own binding — nothing else is derived from it.
    if (!slot->driver_registered ||
        !driver.send(slot->mac, held.generation.value)) {
      return Status::error(StatusCode::RadioFailure, "reply send refused");
    }
    return Status::success();
  }

  Status snapshot_binding(const NodeId peer, ReplyBinding& out) noexcept override {
    if (in_callback_) {
      return Status::error(StatusCode::Busy, "reentrant snapshot_binding");
    }
    const Mapping* slot = find(peer);
    if (slot == nullptr || slot->phase == FakePhase::Revoked) {
      return Status::error(StatusCode::NotFound, "no live binding");
    }
    out.peer = slot->peer;
    out.id = slot->id;
    out.generation = slot->generation;
    out.rx_context_id = slot->rx_context;
    return Status::success();
  }

  Status send_bound(const ReplyBinding captured, const std::uint64_t /*tx_token*/,
                    const ByteView /*frame*/) noexcept override {
    if (in_callback_) return Status::error(StatusCode::Busy, "reentrant send_bound");
    const Mapping* slot = find(captured.peer);
    if (slot == nullptr || slot->id != captured.id ||
        slot->generation != captured.generation ||
        slot->rx_context != captured.rx_context_id ||
        slot->phase == FakePhase::Revoked) {
      return Status::error(StatusCode::Conflict, "binding mapping changed");
    }
    if (slot->phase != FakePhase::Reachable || !slot->driver_registered ||
        !driver.send(slot->mac, captured.generation.value)) {
      return Status::error(StatusCode::WouldBlock, "new DATA needs Reachable");
    }
    return Status::success();
  }

  // --- Owner lifecycle ------------------------------------------------------
  // Revoke: the binding dies now — unstarted replies stop, key material is
  // erased through the hook, and the old handle is never redirected.
  void revoke(const NodeId peer) noexcept {
    Mapping* slot = find(peer);
    if (slot == nullptr) return;
    (void)leases_.invalidate_binding(slot->id);
    slot->phase = FakePhase::Revoked;
    ++key_erases_;
  }

  // Rebind: same id, next generation, fresh RX context. The old uses die;
  // the driver registration survives (same MAC) for the new binding.
  void rebind(const NodeId peer, const std::uint32_t rx_context) noexcept {
    Mapping* slot = find(peer);
    if (slot == nullptr) return;
    (void)leases_.invalidate_binding(slot->id);
    ++slot->generation.value;
    slot->rx_context = rx_context;
    slot->phase = FakePhase::Reachable;
  }

  void leave() noexcept {
    (void)leases_.invalidate_all();
    left_ = true;
  }

  // Single physical-release entry: consult the shared gate, and on a denied
  // or failed delete keep the registration instead of counting free space.
  void release_driver(const NodeId peer) noexcept {
    Mapping* slot = find(peer);
    if (slot == nullptr || !slot->driver_registered) return;
    routeloom::DriverReleaseEvidence evidence{};
    evidence.reply_uses_live = leases_.holds_binding(slot->id, slot->generation);
    evidence.tx_in_flight = driver.owed(slot->mac) > 0;
    evidence.other_lease_hold = slot->other_hold;
    evidence.callbacks_drained = driver.owed(slot->mac) == 0;
    if (!routeloom::driver_release_allowed(evidence)) return;
    if (driver.del(slot->mac)) slot->driver_registered = false;
  }

  // A driver completion lands: attributed only when the binding tag still
  // matches the live mapping, otherwise stale evidence (Q117-06).
  void on_completion(const FakeMac& mac, const std::uint32_t binding_tag) noexcept {
    CallbackScope scope(in_callback_);
    const Mapping* slot = find_mac(mac);
    const std::uint32_t current =
        slot == nullptr ? 0xFFFFFFFFu : slot->generation.value;
    bool stale = false;
    driver.complete(mac, binding_tag, current, stale);
    if (stale) ++stale_completions_;
  }

  static void completion_entry(const FakeMac& mac,
                               const std::uint32_t binding_tag) noexcept {
    if (completion_owner_ != nullptr) completion_owner_->on_completion(mac, binding_tag);
  }

  void arm_sync_completion() noexcept {
    completion_owner_ = this;
    driver.sync_completion = true;
    driver.set_completion(&FakeOwner::completion_entry);
  }

  // Probed only by the reentry test: attempts port calls from the driver
  // context and records their outcomes.
  struct ReentryProbe {
    StatusCode acquire_code{StatusCode::Ok};
    StatusCode release_code{StatusCode::Ok};
  };
  ReentryProbe probe_from_callback() noexcept {
    CallbackScope scope(in_callback_);
    ReentryProbe probe{};
    ReplyLeaseToken token{};
    probe.acquire_code =
        acquire(binding(kPeerA, 1, 1), 1500, 0, token).code;
    probe.release_code = release(token).code;
    return probe;
  }

 private:
  struct CallbackScope {
    explicit CallbackScope(bool& flag) noexcept : flag_(flag) { flag_ = true; }
    ~CallbackScope() noexcept { flag_ = false; }
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;
    bool& flag_;
  };

  Mapping* find(const NodeId peer) noexcept {
    for (auto& slot : directory_) {
      if (slot.used && slot.peer == peer) return &slot;
    }
    return nullptr;
  }
  const Mapping* find(const NodeId peer) const noexcept {
    for (const auto& slot : directory_) {
      if (slot.used && slot.peer == peer) return &slot;
    }
    return nullptr;
  }
  const Mapping* find_mac(const FakeMac& mac) const noexcept {
    for (const auto& slot : directory_) {
      if (slot.used && slot.mac == mac) return &slot;
    }
    return nullptr;
  }

  bool ensure_driver(Mapping& slot) noexcept {
    if (slot.driver_registered) return true;
    if (driver.registered_count() >= 19) return false;  // nonbroadcast cap
    if (!driver.add(slot.mac)) return false;
    slot.driver_registered = true;
    return true;
  }

  static FakeOwner* completion_owner_;
  std::array<Mapping, 8> directory_{};
  ExpectedReplyLeases leases_{};
  bool in_callback_{false};
  bool left_{false};
  std::uint32_t key_erases_{0};
  std::uint32_t stale_completions_{0};
};

FakeOwner* FakeOwner::completion_owner_ = nullptr;

// --- Owner: acquire pins the driver, release frees it ----------------------------

void test_acquire_registers_once_release_deletes() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken first{}, second{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, first));
  CHECK(owner.driver.adds() == 1);
  // The second use on the same binding pins the same record: no re-add.
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, second));
  CHECK(owner.driver.adds() == 1);
  const FakeMac mac = mac_for(kPeerA);
  CHECK(owner.driver.registered(mac));
  // One live use still holds the driver after the other is released.
  CHECK_OK(owner.release(first));
  owner.release_driver(kPeerA);
  CHECK(owner.driver.registered(mac));
  CHECK(owner.driver.dels() == 0);
  CHECK_OK(owner.release(second));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac));
  CHECK(owner.driver.dels() == 1);
  CHECK(owner.leases().check_invariants());
}

void test_stale_keeps_reserved_reply_blocks_new_data() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken reply{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  const FakeMac mac = mac_for(kPeerA);
  const std::uint8_t frame[4] = {1, 2, 3, 4};
  // Stale/Suspended stops new DATA and route use, but the reserved reply's
  // own registration survives (Q117-03).
  CHECK(owner.set_phase(kPeerA, FakePhase::Stale));
  owner.release_driver(kPeerA);
  CHECK(owner.driver.registered(mac));
  CHECK(owner.driver.dels() == 0);
  CHECK_OK(owner.send_reply(reply, 1, ByteView{frame, sizeof(frame)}, 10));
  ReplyBinding snap{};
  CHECK_OK(owner.snapshot_binding(kPeerA, snap));
  CHECK_CODE(owner.send_bound(snap, 2, ByteView{frame, sizeof(frame)}),
             StatusCode::WouldBlock);
  // ... and the Suspended phase behaves the same way.
  CHECK(owner.set_phase(kPeerA, FakePhase::Suspended));
  owner.release_driver(kPeerA);
  CHECK(owner.driver.registered(mac));
  CHECK_OK(owner.send_reply(reply, 3, ByteView{frame, sizeof(frame)}, 20));
  // Land both owed completions then release: only now may the driver go.
  owner.on_completion(mac, 1);
  owner.on_completion(mac, 1);
  CHECK(owner.driver.owed(mac) == 0);
  CHECK_OK(owner.release(reply));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac));
}

void test_revoke_stops_unstarted_replies_erases_keys() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken reply{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  const std::uint8_t frame[4] = {1, 2, 3, 4};
  owner.revoke(kPeerA);
  CHECK(owner.key_erases() == 1);
  // The old handle is dead for validation and sends — never redirected.
  CHECK_CODE(owner.validate(reply, 10), StatusCode::Conflict);
  CHECK_CODE(owner.send_reply(reply, 1, ByteView{frame, sizeof(frame)}, 10),
             StatusCode::Conflict);
  ReplyLeaseToken late{};
  CHECK_CODE(owner.acquire(binding(kPeerA, 1, 1), 1500, 10, late),
             StatusCode::Conflict);
  CHECK_OK(owner.release(reply));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
  CHECK(owner.leases().check_invariants());
}

void test_rebind_moves_uses_without_driver_churn() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken old{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, old));
  const std::uint8_t frame[4] = {1, 2, 3, 4};
  owner.rebind(kPeerA, 8);
  CHECK_CODE(owner.send_reply(old, 1, ByteView{frame, sizeof(frame)}, 10),
             StatusCode::Conflict);
  // The new generation acquires cleanly on the surviving registration.
  ReplyLeaseToken fresh{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 2, 8), 1500, 10, fresh));
  CHECK(owner.driver.adds() == 1);
  CHECK(owner.driver.dels() == 0);
  CHECK_OK(owner.send_reply(fresh, 2, ByteView{frame, sizeof(frame)}, 10));
  owner.on_completion(mac_for(kPeerA), 2);
  CHECK_OK(owner.release(old));
  CHECK_OK(owner.release(fresh));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
  CHECK(owner.leases().check_invariants());
}

void test_unknown_tx_holds_driver_stale_completion_misattributes_nothing() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken first{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, first));
  const FakeMac mac = mac_for(kPeerA);
  const std::uint8_t frame[4] = {1, 2, 3, 4};
  CHECK_OK(owner.send_reply(first, 1, ByteView{frame, sizeof(frame)}, 10));
  CHECK(owner.driver.owed(mac) == 1);
  // The last logical reference is gone but the physical result is unknown:
  // the driver stays until the owed callback lands (Q117-06).
  CHECK_OK(owner.release(first));
  owner.release_driver(kPeerA);
  CHECK(owner.driver.registered(mac));
  CHECK(owner.driver.dels() == 0);
  // Meanwhile the binding moves on; the late completion is stale evidence
  // that resolves nothing on the new binding.
  owner.rebind(kPeerA, 8);
  ReplyLeaseToken second{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 2, 8), 1500, 10, second));
  CHECK_OK(owner.send_reply(second, 2, ByteView{frame, sizeof(frame)}, 10));
  owner.on_completion(mac, 1);  // gen-1 send's late callback
  CHECK(owner.stale_completions() == 1);
  CHECK(owner.driver.owed(mac) == 1);  // the gen-2 send is still owed
  owner.on_completion(mac, 2);
  CHECK(owner.stale_completions() == 1);
  CHECK(owner.driver.owed(mac) == 0);
  CHECK_OK(owner.release(second));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac));
  CHECK(owner.leases().check_invariants());
}

void test_other_pin_holds_driver_too() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken reply{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  CHECK(owner.set_other_hold(kPeerA, true));
  CHECK_OK(owner.release(reply));
  owner.release_driver(kPeerA);
  CHECK(owner.driver.registered(mac_for(kPeerA)));
  CHECK(owner.set_other_hold(kPeerA, false));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
}

void test_register_failure_rolls_lease_back() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  owner.driver.fail_next_add = true;
  ReplyLeaseToken reply{};
  CHECK_CODE(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply),
             StatusCode::RadioFailure);
  CHECK(reply == routeloom::kInvalidReplyLeaseToken);
  CHECK(owner.leases().live_use_count() == 0);
  CHECK(owner.leases().live_entry_count() == 0);
  CHECK(owner.leases().check_invariants());
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
  // The next attempt succeeds: nothing was left half-reserved.
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  CHECK_OK(owner.release(reply));
}

void test_delete_failure_keeps_registration_until_retry() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken reply{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  CHECK_OK(owner.release(reply));
  owner.driver.fail_next_del = true;
  owner.release_driver(kPeerA);
  // A failed delete never counts as free space (Q117-09).
  CHECK(owner.driver.registered(mac_for(kPeerA)));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
  CHECK(owner.driver.dels() == 2);
}

void test_nineteenth_nonbroadcast_peer_is_the_ceiling() {
  FakeOwner owner{};
  // Fill the nonbroadcast budget through the driver (broadcast excluded).
  for (std::uint32_t i = 0; i < 19; ++i) {
    CHECK(owner.driver.add(mac_for(0x100 + i)));
  }
  CHECK(owner.driver.registered_count() == 19);
  // The 20th registration — and therefore its lease — is refused with the
  // table untouched (Q117-09).
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken reply{};
  CHECK_CODE(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply),
             StatusCode::RadioFailure);
  CHECK(owner.leases().live_use_count() == 0);
  CHECK(owner.leases().check_invariants());
}

void test_local_leave_stops_admission_and_retires_uses() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  ReplyLeaseToken reply{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  owner.leave();
  CHECK_CODE(owner.validate(reply, 10), StatusCode::Conflict);
  ReplyLeaseToken late{};
  CHECK_CODE(owner.acquire(binding(kPeerA, 1, 1), 1500, 10, late),
             StatusCode::InvalidState);
  CHECK_OK(owner.release(reply));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
}

void test_driver_callback_cannot_reenter_the_port() {
  FakeOwner owner{};
  CHECK(owner.bind(kPeerA, 1, 1, 7));
  const FakeOwner::ReentryProbe probe = owner.probe_from_callback();
  CHECK(probe.acquire_code == StatusCode::Busy);
  CHECK(probe.release_code == StatusCode::Busy);
  CHECK(owner.leases().live_use_count() == 0);
  CHECK(owner.leases().live_entry_count() == 0);
  CHECK(owner.leases().check_invariants());
  // A real send whose completion runs synchronously still succeeds outside
  // the callback, and the completion resolves normally.
  owner.arm_sync_completion();
  ReplyLeaseToken reply{};
  CHECK_OK(owner.acquire(binding(kPeerA, 1, 1), 1500, 0, reply));
  const std::uint8_t frame[4] = {1, 2, 3, 4};
  CHECK_OK(owner.send_reply(reply, 1, ByteView{frame, sizeof(frame)}, 10));
  CHECK(owner.driver.owed(mac_for(kPeerA)) == 0);
  CHECK(owner.stale_completions() == 0);
  CHECK_OK(owner.release(reply));
  owner.release_driver(kPeerA);
  CHECK(!owner.driver.registered(mac_for(kPeerA)));
}

// --- RX metadata carries the binding (Owner capture contract) -------------------

void test_rx_metadata_v2_carries_binding_id() {
  routeloom::RadioRxMetadataV2 meta{};
  meta.binding = BindingId{42};
  meta.binding_generation = BindingGeneration{3};
  CHECK(meta.binding == BindingId{42});
  CHECK(meta.binding_generation == BindingGeneration{3});
  CHECK(meta.identity_current);
  static_assert(sizeof(routeloom::RadioRxMetadataV2) <= 48, "bounded RX metadata");
}

// --- C ABI: the versioned reply-peer surface -------------------------------------

void test_c_reply_peer_surface() {
  rl_reply_peer_vtable_t vtable{};
  rl_reply_peer_vtable_init(&vtable);
  CHECK(vtable.struct_size == sizeof(vtable));
  CHECK(vtable.version == RL_REPLY_PEER_VERSION);
  CHECK(vtable.user == nullptr);
  CHECK(vtable.acquire == nullptr);
  // Argument validation without a context.
  CHECK(rl_attach_reply_peer(nullptr, &vtable) == RL_STATUS_INVALID_ARGUMENT);
  CHECK(rl_attach_reply_peer(nullptr, nullptr) == RL_STATUS_INVALID_ARGUMENT);
  rl_on_radio_receive_with_binding(nullptr, 1, nullptr, 0, 0, 1, 1, 0);
  // A short/foreign struct is refused, never read past its size.
  rl_reply_peer_vtable_t short_vtable = vtable;
  short_vtable.struct_size = sizeof(short_vtable) - 1;
  CHECK(rl_attach_reply_peer(nullptr, &short_vtable) == RL_STATUS_INVALID_ARGUMENT);
}

// --- Sizes ------------------------------------------------------------------------

void test_sizes() {
  static_assert(sizeof(routeloom::ExpectedReplyLeases) <= 384, "lease table bound");
  std::fprintf(stderr, "  reply leases: sizeof(ExpectedReplyLeases) = %zu bytes\n",
               sizeof(routeloom::ExpectedReplyLeases));
  std::fprintf(stderr, "  reply leases: sizeof(RadioRxMetadataV2) = %zu bytes\n",
               sizeof(routeloom::RadioRxMetadataV2));
}

}  // namespace

int main() {
  test_three_bindings_shared_per_key();
  test_probe_acquire_agrees_with_acquire();
  test_eight_uses_then_refused();
  test_keys_split_by_id_and_generation();
  test_same_key_cannot_change_peer_or_rx_context();
  test_stale_tokens_never_touch_the_new_owner();
  test_use_serials_never_wrap();
  test_deadline_clamped_to_now_plus_ttl();
  test_rejects_unusable_time_and_bindings();
  test_clock_regression_stops_admission();
  test_validated_clock_cannot_regress_on_new_admission();
  test_invalidate_binding_retires_uses_keeps_slot_until_released();
  test_invalidate_all_and_empty_entries_recycled();
  test_driver_release_gate_conjunction();
  test_acquire_registers_once_release_deletes();
  test_stale_keeps_reserved_reply_blocks_new_data();
  test_revoke_stops_unstarted_replies_erases_keys();
  test_rebind_moves_uses_without_driver_churn();
  test_unknown_tx_holds_driver_stale_completion_misattributes_nothing();
  test_other_pin_holds_driver_too();
  test_register_failure_rolls_lease_back();
  test_delete_failure_keeps_registration_until_retry();
  test_nineteenth_nonbroadcast_peer_is_the_ceiling();
  test_local_leave_stops_admission_and_retires_uses();
  test_driver_callback_cannot_reenter_the_port();
  test_rx_metadata_v2_carries_binding_id();
  test_c_reply_peer_surface();
  test_sizes();
  if (failures != 0) {
    std::fprintf(stderr, "%d reply-lease check(s) failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom reply-lease tests passed");
  return 0;
}
