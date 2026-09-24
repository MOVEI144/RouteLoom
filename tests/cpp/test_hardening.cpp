// Regression tests for the Secure Unicast hardening contract:
//  - Link vs EndToEnd scope separation (hop key never used for end sealing)
//  - link-layer authentication is not origin authorization
//  - crypto counters are provider-owned, independent of Message ID
//  - replay windows + epoch floors under simulated power cuts / store loss
//  - flash-wear bounds: replay ceiling reservation, TX lease checkpoints
//  - EXPERIMENTAL security-profile enforcement and no plaintext DATA path

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "routeloom/counter_store.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/fail_policy.hpp"
#include "routeloom/node.hpp"
#include "routeloom/replay.hpp"
#include "routeloom/secure_clear.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::TestSecurity;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimWorld;

// Records every SecurityContext handed to the provider so tests can assert
// which scope, identities and epoch actually reached the crypto boundary.
class RecordingSecurity final : public SecurityProvider {
 public:
  std::vector<SecurityContext> counters;
  std::vector<SecurityContext> sealed;
  std::vector<SecurityContext> opened;

  bool ready() const noexcept override { return inner_.ready(); }
  Status next_counter(const SecurityContext& context,
                      std::uint64_t& counter) noexcept override {
    counters.push_back(context);
    return inner_.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView plaintext,
              const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    sealed.push_back(context);
    return inner_.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    opened.push_back(context);
    return inner_.open(context, counter, aad, ciphertext, tag, plaintext);
  }

 private:
  TestSecurity inner_{};
};

// Wraps TestSecurity but claims the production profile marker, to prove the
// EXPERIMENTAL diagnostic is keyed on security_profile() and not hardwired.
class ProductionSecurity final : public SecurityProvider {
 public:
  bool ready() const noexcept override { return inner_.ready(); }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Production;
  }
  Status next_counter(const SecurityContext& context,
                      std::uint64_t& counter) noexcept override {
    return inner_.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView plaintext,
              const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    return inner_.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    return inner_.open(context, counter, aad, ciphertext, tag, plaintext);
  }

 private:
  TestSecurity inner_{};
};

class MemoryCounterStore final : public CounterStore {
 public:
  Status load(std::uint32_t slot, CounterRecord& record, bool& found) noexcept override {
    const auto it = records.find(slot);
    found = it != records.end();
    if (found) record = it->second;
    return Status::success();
  }
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override {
    if (fail_commits) {
      return Status::error(StatusCode::StorageFailure, "commit dropped");
    }
    records[slot] = record;
    ++commits;
    return Status::success();
  }
  std::map<std::uint32_t, CounterRecord> records;
  bool fail_commits{false};
  std::size_t commits{0};  // durable commits = flash writes on device
};

// ReplayStore test double that can lose window blobs, corrupt records and
// fail commits, while keeping whatever was durably committed across
// "restarts" (a new ReplayGuard over the same maps).
class FlakyReplayStore final : public ReplayStore {
 public:
  Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                     bool& found) noexcept override {
    if (fail_loads) {
      return Status::error(StatusCode::StorageFailure, "window load failed");
    }
    const auto it = windows.find(slot);
    found = it != windows.end();
    if (found) record = it->second;
    return Status::success();
  }
  Status commit_window(std::uint32_t slot,
                       const ReplayWindowRecord& record) noexcept override {
    if (fail_commits) {
      return Status::error(StatusCode::StorageFailure, "window commit dropped");
    }
    windows[slot] = record;
    ++window_commits;
    return Status::success();
  }
  Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                    bool& found) noexcept override {
    if (fail_loads) {
      return Status::error(StatusCode::StorageFailure, "floor load failed");
    }
    const auto it = floors.find(slot);
    found = it != floors.end();
    if (found) record = it->second;
    return Status::success();
  }
  Status commit_floor(std::uint32_t slot,
                      const ReplayFloorRecord& record) noexcept override {
    if (fail_commits) {
      return Status::error(StatusCode::StorageFailure, "floor commit dropped");
    }
    floors[slot] = record;
    ++floor_commits;
    return Status::success();
  }

  std::map<std::uint32_t, ReplayWindowRecord> windows;
  std::map<std::uint32_t, ReplayFloorRecord> floors;
  bool fail_loads{false};
  bool fail_commits{false};
  // Durable commits = NVS flash writes on device (issue #30 budget).
  std::size_t window_commits{0};
  std::size_t floor_commits{0};
};

wire::PlainFrame data_plain(std::uint8_t flags) {
  wire::PlainFrame plain{};
  plain.header.type = FrameType::Data;
  plain.header.flags = flags;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.hop_remaining = 4;
  plain.header.network = 1;
  plain.header.origin = 1;
  plain.header.destination = 3;
  plain.header.previous_hop = 1;
  plain.header.next_hop = 2;
  plain.header.message = MessageId{7, 42};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 1;
  plain.header.end_epoch = 2;
  const char* text = "route-loom";
  plain.payload_size = std::strlen(text);
  std::memcpy(plain.payload.data(), text, plain.payload_size);
  return plain;
}

std::uint64_t header_u64(const wire::EncodedFrame& frame, const std::size_t offset) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value = (value << 8U) | frame.bytes[offset + i];
  return value;
}

std::uint64_t header_u48(const wire::EncodedFrame& frame, const std::size_t offset) {
  std::uint64_t value = 0;
  for (int i = 0; i < 6; ++i) value = (value << 8U) | frame.bytes[offset + i];
  return value;
}

// --- Task 1: hop/end key separation ---------------------------------------

void test_scope_separation_on_wire() {
  RecordingSecurity security;
  wire::PlainFrame plain = data_plain(wire::kFlagEndProtected);
  wire::EncodedFrame encoded{};
  CHECK_OK(wire::encode_new(plain, security, encoded));

  // Counters come from provider-owned per-context leases, link first.
  CHECK(security.counters.size() == 2);
  CHECK(security.counters[0].scope == SecurityScope::Link);
  CHECK(security.counters[0].sender == 1 && security.counters[0].receiver == 2 &&
        security.counters[0].epoch == 1);
  CHECK(security.counters[1].scope == SecurityScope::EndToEnd);
  CHECK(security.counters[1].sender == 1 && security.counters[1].receiver == 3 &&
        security.counters[1].epoch == 2);

  // The payload is sealed under the end context; the envelope under the link
  // context. The hop context is never reused for end sealing and vice versa.
  CHECK(security.sealed.size() == 2);
  CHECK(security.sealed[0].scope == SecurityScope::EndToEnd);
  CHECK(security.sealed[0].sender == 1 && security.sealed[0].receiver == 3);
  CHECK(security.sealed[1].scope == SecurityScope::Link);
  CHECK(security.sealed[1].sender == 1 && security.sealed[1].receiver == 2);

  RecordingSecurity receiver;
  wire::LinkOpenedFrame opened{};
  CHECK_OK(wire::open_link(encoded.view(), 2, receiver, opened));
  CHECK(receiver.opened.size() == 1);
  CHECK(receiver.opened[0].scope == SecurityScope::Link);
  CHECK(receiver.opened[0].sender == 1 && receiver.opened[0].receiver == 2);
}

void test_scope_keys_not_interchangeable() {
  TestSecurity security;
  const SecurityContext link{SecurityScope::Link, 7, 1, 2, 1};
  const SecurityContext end{SecurityScope::EndToEnd, 7, 1, 2, 1};
  const std::array<std::uint8_t, 4> aad{{9, 8, 7, 6}};
  const std::array<std::uint8_t, 16> plaintext{{
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}};
  std::array<std::uint8_t, 16> ciphertext{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK_OK(security.seal(link, 5, ByteView{aad.data(), aad.size()},
                         ByteView{plaintext.data(), plaintext.size()},
                         MutableByteView{ciphertext.data(), ciphertext.size()}, tag));
  std::array<std::uint8_t, 16> out{};
  // Identical identities/epoch/counter under the other scope must not open:
  // the scope is bound into the context the AEAD is keyed by.
  CHECK(security.open(end, 5, ByteView{aad.data(), aad.size()},
                      ByteView{ciphertext.data(), ciphertext.size()}, tag,
                      MutableByteView{out.data(), out.size()}).code ==
        StatusCode::AuthenticationFailed);
  CHECK_OK(security.open(link, 5, ByteView{aad.data(), aad.size()},
                         ByteView{ciphertext.data(), ciphertext.size()}, tag,
                         MutableByteView{out.data(), out.size()}));
  CHECK(std::memcmp(out.data(), plaintext.data(), plaintext.size()) == 0);
}

// --- Task 2: link authentication is not origin authorization ---------------

void test_link_open_is_not_origin_verification() {
  TestSecurity sender, relay, destination;
  wire::PlainFrame plain = data_plain(wire::kFlagEndProtected);
  wire::EncodedFrame encoded{};
  CHECK_OK(wire::encode_new(plain, sender, encoded));

  // The relay authenticates the immediate peer only.
  wire::LinkOpenedFrame at_relay{};
  CHECK_OK(wire::open_link(encoded.view(), 2, relay, at_relay));
  // Link success does not authorize the claimed origin: the relay is not the
  // bound destination and must not treat the frame as end-verified.
  wire::PlainFrame out{};
  CHECK(wire::open_end(at_relay, 2, relay, out).code == StatusCode::AuthorizationFailed);

  // Only the bound destination verifies the origin end-to-end.
  wire::EncodedFrame onward{};
  CHECK_OK(wire::forward(at_relay, 2, 3, /*link_epoch=*/1, 4900, relay, onward));
  wire::LinkOpenedFrame at_destination{};
  CHECK_OK(wire::open_link(onward.view(), 3, destination, at_destination));
  CHECK_OK(wire::open_end(at_destination, 3, destination, out));
}

// --- Task 3: Message ID vs nonce counter separation ------------------------

void test_counters_independent_of_message_id() {
  TestSecurity security;
  const wire::PlainFrame plain = data_plain(wire::kFlagEndProtected);
  wire::EncodedFrame first{}, second{};
  CHECK_OK(wire::encode_new(plain, security, first));
  CHECK_OK(wire::encode_new(plain, security, second));

  // Identical message (same Message ID and payload) → different ciphertext
  // because crypto counters advance independently of message.sequence.
  CHECK(first.size == second.size);
  CHECK(std::memcmp(first.bytes.data(), second.bytes.data(), first.size) != 0);
  CHECK(header_u64(first, 52) == 42 && header_u64(second, 52) == 42);  // sequence
  CHECK(header_u48(first, 76) == 0 && header_u48(second, 76) == 1);    // link counter
  CHECK(header_u48(first, 82) == 0 && header_u48(second, 82) == 1);    // end counter
}

// --- Task 4: replay persistence under power cuts ---------------------------

const SecurityContext kCtx{SecurityScope::EndToEnd, 1, 10, 20, 3};

void test_replay_window_basics() {
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  CHECK_OK(guard.accept(window, 0));
  CHECK_OK(guard.accept(window, 2));
  CHECK_OK(guard.accept(window, 1));  // inside the window, still fresh
  CHECK(guard.accept(window, 1).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(window, 0).code == StatusCode::ReplayRejected);
  CHECK_OK(guard.accept(window, 100));
  // Counters that fell out of the 64-bit window are old.
  CHECK(guard.accept(window, 36).code == StatusCode::ReplayRejected);
}

void test_replay_window_survives_restart() {
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    CHECK_OK(guard.accept(window, 10));
    CHECK_OK(guard.accept(window, 11));
  }
  // Simulated restart: new guard, same persisted store; the RAM window is
  // gone and only the reservation ceiling committed by the first accept
  // (10 + kReplayReservationAhead) survived.
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  // The persisted ceiling still rejects every counter it covers.
  CHECK(guard.accept(window, 10).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(window, 11).code == StatusCode::ReplayRejected);
  // Counter 5 was never accepted, but the out-of-order bitmap that proved
  // it fresh lived in RAM: after a restart everything at or below the
  // ceiling is conservatively treated as seen (reject, never re-admit).
  CHECK(guard.accept(window, 5).code == StatusCode::ReplayRejected);
  const std::uint64_t ceiling = 10 + kReplayReservationAhead;
  CHECK(guard.accept(window, 12).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(window, ceiling).code == StatusCode::ReplayRejected);
  // Above the ceiling nothing can have been accepted before the restart.
  CHECK_OK(guard.accept(window, ceiling + 2));
  CHECK_OK(guard.accept(window, ceiling + 1));  // out of order, still fresh
  CHECK(guard.accept(window, ceiling + 1).code == StatusCode::ReplayRejected);
}

void test_replay_window_loss_requires_new_epoch() {
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    CHECK_OK(guard.accept(window, 5));
  }
  // Selective loss: the window blobs are gone but the peer floor survived.
  store.windows.clear();
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  // Same epoch: reject-or-rehandshake. Without the persisted window the node
  // cannot prove counters at or below the last persisted maximum are fresh.
  CHECK(guard.open_context(kCtx, window).code == StatusCode::ReplayRejected);
  // A missing window is lost state, not a foreign fingerprint — the
  // collision counter stays at zero.
  CHECK(guard.foreign_fingerprint_rejects() == 0);
  // Older epoch: stale by the floor, always rejected.
  SecurityContext older = kCtx;
  older.epoch = 2;
  CHECK(guard.open_context(older, window).code == StatusCode::ReplayRejected);
  // Newer epoch (rehandshake): admitted, fresh counter space.
  SecurityContext newer = kCtx;
  newer.epoch = 4;
  CHECK_OK(guard.open_context(newer, window));
  CHECK_OK(guard.accept(window, 0));
  // The stale epoch stays rejected afterwards.
  CHECK(guard.open_context(kCtx, window).code == StatusCode::ReplayRejected);
  CHECK(guard.open_context(older, window).code == StatusCode::ReplayRejected);
}

void test_replay_floor_enforced_per_frame() {
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window epoch3{};
  CHECK_OK(guard.open_context(kCtx, epoch3));
  CHECK_OK(guard.accept(epoch3, 5));
  // The peer re-handshakes to epoch 4: the floor advances past epoch 3.
  SecurityContext newer = kCtx;
  newer.epoch = 4;
  ReplayGuard::Window epoch4{};
  CHECK_OK(guard.open_context(newer, epoch4));
  // A cached epoch-3 window still contains admissible counters, but windows
  // share one persisted slot per peer pair: accept() re-checks the floor so
  // a stale window can never commit over the live epoch-4 record. Providers
  // still run check_floor per frame as the primary gate.
  CHECK(guard.accept(epoch3, 6).code == StatusCode::ReplayRejected);
  CHECK(guard.check_floor(kCtx).code == StatusCode::ReplayRejected);
  CHECK_OK(guard.check_floor(newer));
  // The epoch-4 record is intact: its own window still accepts normally.
  CHECK_OK(guard.accept(epoch4, 0));
}

void test_replay_epoch_advance_rekeys_shared_slot() {
  // Windows persist at one slot per peer pair. A peer booting onto a newer
  // epoch re-keys the same record in place — storage stays O(peers) across
  // any number of epoch advances instead of leaking one record per boot.
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window epoch3{};
    CHECK_OK(guard.open_context(kCtx, epoch3));
    CHECK_OK(guard.accept(epoch3, 42));
  }
  const auto records_after_epoch3 = store.windows.size();
  SecurityContext newer = kCtx;
  newer.epoch = 4;
  ReplayGuard guard(store);
  ReplayGuard::Window epoch4{};
  CHECK_OK(guard.open_context(newer, epoch4));
  // Re-keyed, not corrupted: the counter space is fresh for the new epoch.
  CHECK_OK(guard.accept(epoch4, 0));
  CHECK(store.windows.size() == records_after_epoch3);
  // Epoch 3 is permanently below the floor now.
  ReplayGuard::Window stale{};
  CHECK(guard.open_context(kCtx, stale).code == StatusCode::ReplayRejected);
}

void test_replay_stale_record_at_floor_epoch_is_state_lost() {
  // Interrupted transition: floor ratcheted to epoch 4 but the epoch-4
  // window was never committed (crash between ratchet and first accept).
  // The slot still holds the epoch-3 record. Reopening epoch 4 must NOT
  // treat the stale record as the live window — at the floor epoch a
  // foreign record is a missing window, i.e. REPLAY_STATE_LOST. Recovery
  // is the next epoch advance, exactly like the absent-blob case.
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window epoch3{};
    CHECK_OK(guard.open_context(kCtx, epoch3));
    CHECK_OK(guard.accept(epoch3, 7));
  }
  {
    ReplayGuard guard(store);
    ReplayGuard::Window epoch4{};
    SecurityContext newer = kCtx;
    newer.epoch = 4;
    CHECK_OK(guard.open_context(newer, epoch4));  // ratchets floor, no commit
  }
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  SecurityContext at4 = kCtx;
  at4.epoch = 4;
  CHECK(guard.open_context(at4, window).code == StatusCode::ReplayRejected);
  // The stale foreign-fingerprint record forcing REPLAY_STATE_LOST is the
  // counted collision signature; the epoch-advance re-key below is not.
  CHECK(guard.foreign_fingerprint_rejects() == 1);
  SecurityContext at5 = kCtx;
  at5.epoch = 5;
  CHECK_OK(guard.open_context(at5, window));  // advance recovers
  CHECK(guard.foreign_fingerprint_rejects() == 1);
}

void test_replay_corruption_is_not_a_fresh_context() {
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    CHECK_OK(guard.accept(window, 7));
  }
  // Bit rot inside the persisted window must not turn into a fresh accept.
  store.windows.begin()->second.accepted_ceiling ^= 0x1fULL;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK(guard.open_context(kCtx, window).code == StatusCode::IntegrityError);

  // Same for a corrupted peer floor.
  FlakyReplayStore corrupt_floor;
  {
    ReplayGuard setup(corrupt_floor);
    ReplayGuard::Window seeded{};
    CHECK_OK(setup.open_context(kCtx, seeded));
    CHECK_OK(setup.accept(seeded, 1));
  }
  corrupt_floor.floors.begin()->second.minimum_epoch ^= 0x1U;
  ReplayGuard guard2(corrupt_floor);
  ReplayGuard::Window window2{};
  CHECK(guard2.open_context(kCtx, window2).code == StatusCode::IntegrityError);
}

void test_replay_commit_failure_rolls_back() {
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  CHECK_OK(guard.accept(window, 5));

  store.fail_commits = true;
  // The floor ratchet fails closed too: a context cannot be admitted when its
  // epoch cannot be persisted.
  FlakyReplayStore floorless;
  floorless.fail_commits = true;
  ReplayGuard blocked(floorless);
  ReplayGuard::Window blocked_window{};
  CHECK(!blocked.open_context(kCtx, blocked_window));

  // Counters under the reserved ceiling need no commit at all, so a failing
  // store does not affect them.
  CHECK_OK(guard.accept(window, 6));
  // Crossing the ceiling needs a commit. A failed one leaves the in-memory
  // window untouched: the frame is not accepted and the counter can be
  // retried once the store recovers.
  const std::uint64_t beyond = 5 + kReplayReservationAhead + 1;
  CHECK(guard.accept(window, beyond).code == StatusCode::StorageFailure);
  CHECK_OK(guard.accept(window, 7));  // the window did not slide
  store.fail_commits = false;
  CHECK_OK(guard.accept(window, beyond));
  CHECK(guard.accept(window, beyond).code == StatusCode::ReplayRejected);
}

void test_replay_floor_cold_start_semantics() {
  // With no persisted floor at all, first boot and a total wipe cannot be
  // told apart (no trusted monotonic store exists). The documented cold-start
  // rule adopts the incoming epoch; from then on older epochs are stale.
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  SecurityContext high = kCtx;
  high.epoch = 9;
  CHECK_OK(guard.open_context(high, window));
  CHECK_OK(guard.accept(window, 0));
  ReplayGuard::Window stale{};
  CHECK(guard.open_context(kCtx, stale).code == StatusCode::ReplayRejected);
}

// --- TX counter leases under power cuts ------------------------------------

void test_counter_lease_commit_failure_issues_nothing() {
  MemoryCounterStore store;
  CounterLease lease(store, 1, 99, 1, 0, 4);
  CHECK_OK(lease.initialize());
  store.fail_commits = true;
  std::uint64_t value = 0;
  // A reservation must commit before the counter may be used; a dropped
  // commit issues nothing rather than risking nonce reuse.
  CHECK(lease.next(value).code == StatusCode::StorageFailure);
  store.fail_commits = false;
  CHECK_OK(lease.next(value));
  CHECK(value == 0);
}

void test_counter_lease_never_reissues_across_restarts() {
  MemoryCounterStore store;
  std::set<std::uint64_t> issued;
  for (int round = 0; round < 12; ++round) {
    CounterLease lease(store, 7, 99, 1, 0, 4);  // fresh boot each round
    CHECK_OK(lease.initialize());
    std::uint64_t value = 0;
    CHECK_OK(lease.next(value));
    CHECK(issued.insert(value).second);
  }
}

void test_counter_lease_context_mismatch_rejected() {
  MemoryCounterStore store;
  CounterLease first(store, 7, 99, 1, 0, 4);
  CHECK_OK(first.initialize());
  std::uint64_t value = 0;
  CHECK_OK(first.next(value));
  CounterLease mismatched(store, 7, 55, 1, 0, 4);  // different context id
  CHECK(mismatched.initialize().code == StatusCode::Conflict);
}

void test_counter_lease_epoch_advance_rekeys_same_slot() {
  // Boot-advancing epochs share one slot per peer pair: a newer epoch
  // re-keys the record in place (fresh counter space is safe — nonces are
  // epoch-scoped), while a regression stays fail-closed.
  MemoryCounterStore store;
  std::uint64_t value = 0;
  {
    CounterLease lease(store, 7, 99, 1, 0, 4);
    CHECK_OK(lease.initialize());
    CHECK_OK(lease.next(value));
    CHECK_OK(lease.next(value));
  }
  {
    CounterLease lease(store, 7, 99, 2, 0, 4);  // next boot, same peer pair
    CHECK_OK(lease.initialize());
    CHECK_OK(lease.next(value));
    CHECK(value == 0);  // new epoch -> fresh counter space
  }
  {
    CounterLease regressed(store, 7, 99, 1, 0, 4);
    CHECK(regressed.initialize().code == StatusCode::Conflict);
  }
}

void test_counter_lease_stale_context_cannot_rewind_newer_epoch() {
  // Two cached contexts at different epochs share one slot. If the stale
  // epoch-1 lease outlives the epoch-2 re-key, its next reservation must
  // fail instead of overwriting the epoch-2 record — otherwise the epoch-2
  // counter space rewinds into nonce reuse.
  MemoryCounterStore store;
  std::uint64_t value = 0;
  CounterLease epoch1(store, 7, 99, 1, 0, 4);
  CHECK_OK(epoch1.initialize());
  CHECK_OK(epoch1.next(value));  // reserves [0,4) at epoch 1
  {
    CounterLease epoch2(store, 7, 99, 2, 0, 4);
    CHECK_OK(epoch2.initialize());  // re-keys the slot to epoch 2
    CHECK_OK(epoch2.next(value));
    CHECK(value == 0);  // fresh epoch-2 counter space
  }
  // The stale epoch-1 lease can still drain its pre-reserved block (safe:
  // those counters live under the epoch-1 context and the peer floor
  // rejects them), but its next reservation must not clobber the record.
  CHECK_OK(epoch1.next(value));  // drains the old [1,4) reservation
  CHECK_OK(epoch1.next(value));
  CHECK_OK(epoch1.next(value));
  CHECK(epoch1.next(value).code == StatusCode::Conflict);
  // The epoch-2 record is untouched: a fresh lease resumes past the
  // committed water mark — epoch-2's reserved space was not rewound.
  CounterLease epoch2_again(store, 7, 99, 2, 0, 4);
  CHECK_OK(epoch2_again.initialize());
  CHECK_OK(epoch2_again.next(value));
  CHECK(value == 4);
}

void test_counter_record_rewound_rejected() {
  MemoryCounterStore store;
  {
    CounterLease lease(store, 7, 99, 1, 0, 4);
    CHECK_OK(lease.initialize());
    std::uint64_t value = 0;
    CHECK_OK(lease.next(value));
  }
  // A tampered or rolled-back high-water must never be adopted silently:
  // rewinding the counter would reuse AES-GCM nonces under the same key.
  store.records[7].high_water_exclusive = 0;
  store.records[7].crc = 0;
  CounterLease lease(store, 7, 99, 1, 0, 4);
  CHECK(lease.initialize().code == StatusCode::IntegrityError);
  // Any field touched without recomputing the CRC is rejected the same way.
  store.records[7].high_water_exclusive = 0;
  CounterRecord forged = store.records[7];
  forged.generation += 1;
  store.records[7] = forged;
  CounterLease second(store, 7, 99, 1, 0, 4);
  CHECK(second.initialize().code == StatusCode::IntegrityError);
}

// --- Task 5: EXPERIMENTAL enforcement / no plaintext DATA -------------------

void test_security_profile_marker() {
  TestSecurity dev;
  CHECK(dev.security_profile() == SecurityProfile::Development);
  ProductionSecurity production;
  CHECK(production.security_profile() == SecurityProfile::Production);

  SimWorld world;
  world.add(1);
  world.start_all();
  // A development-profile provider is surfaced as EXPERIMENTAL at start.
  CHECK(world.obs(1)->has_diag("SECURITY_PROFILE_EXPERIMENTAL"));

  SimNetwork net;
  ProductionSecurity prod_security;
  CapturingObserver prod_observer;
  SimRadio prod_radio(net, 9);
  NodeConfig prod_config{1, 9, 190};
  MeshNode prod_node(prod_config, prod_radio, prod_security, prod_observer);
  CHECK_OK(prod_node.start(0));
  CHECK(!prod_observer.has_diag("SECURITY_PROFILE_EXPERIMENTAL"));
}

void test_plaintext_data_rejected() {
  SimWorld world;
  world.add(1);
  world.add(2);
  world.add(3);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.link(2, 3, 1, 1);
  world.run(500);
  CHECK(world.at(1)->routes().best(3).valid);

  // The wire codec itself still accepts an unprotected DATA frame (the format
  // is shared with link-only control types); MeshNode must refuse it.
  wire::PlainFrame transit = data_plain(0);  // flags: no end protection
  wire::EncodedFrame encoded{};
  CHECK_OK(wire::encode_new(transit, *world.security[1], encoded));

  const std::size_t sights_before = world.net.sights.size();
  world.at(2)->on_radio_receive(1, encoded.view(), RadioRxMetadata{-60}, world.now);
  world.net.flush(world.now);
  // A transit node drops plaintext DATA instead of relaying it onward.
  CHECK(world.obs(2)->has_diag("END_PROTECTION_REQUIRED"));
  CHECK(world.obs(3)->messages.empty());
  bool forwarded_data = false;
  for (std::size_t i = sights_before; i < world.net.sights.size(); ++i) {
    if (world.net.sights[i].type == FrameType::Data && world.net.sights[i].to == 3) {
      forwarded_data = true;
    }
  }
  CHECK(!forwarded_data);

  // Plaintext DATA addressed to the receiving node is never delivered either.
  wire::PlainFrame terminal = transit;
  terminal.header.destination = 2;
  wire::EncodedFrame encoded_terminal{};
  CHECK_OK(wire::encode_new(terminal, *world.security[1], encoded_terminal));
  world.at(2)->on_radio_receive(1, encoded_terminal.view(), RadioRxMetadata{-60}, world.now);
  CHECK(world.obs(2)->messages.empty());

  // END_RECEIPT is end-protected for the same reason; an unprotected receipt
  // would let any hop forge delivery confirmation.
  wire::PlainFrame receipt = terminal;
  receipt.header.type = FrameType::EndReceipt;
  wire::EncodedFrame encoded_receipt{};
  CHECK_OK(wire::encode_new(receipt, *world.security[1], encoded_receipt));
  const std::size_t diagnostics_before = world.obs(2)->diagnostics.size();
  world.at(2)->on_radio_receive(1, encoded_receipt.view(), RadioRxMetadata{-60}, world.now);
  CHECK(world.obs(2)->diagnostics.size() > diagnostics_before);
  CHECK(world.obs(2)->has_diag("END_PROTECTION_REQUIRED"));
}

// Non-elidable zeroization (issue #34): volatile-store clearing of key
// material — the buffer must read as all-zero afterwards, including via a
// read that the compiler cannot fold into the write.
void test_secure_clear() {
  std::array<std::uint8_t, 32> secret{};
  secret.fill(0xA5);
  routeloom::secure_clear(secret);
  for (const auto byte : secret) CHECK(byte == 0);

  // Pointer form over a prefix clears exactly the prefix.
  std::array<std::uint8_t, 16> buffer{};
  buffer.fill(0xFF);
  routeloom::secure_clear(buffer.data(), 8);
  for (std::size_t i = 0; i < buffer.size(); ++i) {
    CHECK(buffer[i] == (i < 8 ? 0 : 0xFF));
  }

  routeloom::secure_clear(nullptr, 0);  // null + zero size is a no-op
}

// Boot-fault escalation (issue #34): a fatal during boot first ran a silent
// infinite vTaskDelay loop — dead until the next power cycle — and then a
// plain esp_restart loop, which commits one NVS session write per iteration
// forever under a persistent fault. The shared streak policy bounds the
// cadence: exponential backoff capped at 32 s, then one retry per long
// deep sleep.
void test_fail_policy_backoff_schedule() {
  CHECK(!routeloom::fail_action(0).deep_sleep);
  CHECK(routeloom::fail_action(0).delay_ms == 500);
  CHECK(routeloom::fail_action(1).delay_ms == 1000);
  CHECK(routeloom::fail_action(5).delay_ms == 16000);
  CHECK(routeloom::fail_action(6).delay_ms == 32000);
  CHECK(routeloom::fail_action(7).delay_ms == 32000);  // capped, still restart
  // Below the streak cap every action is a restart; at/over it the node
  // must stop restarting and deep sleep instead.
  CHECK(!routeloom::fail_action(routeloom::kFailSleepStreakMin - 1)
             .deep_sleep);
  CHECK(routeloom::fail_action(routeloom::kFailSleepStreakMin).deep_sleep);
  CHECK(routeloom::fail_action(routeloom::kFailSleepStreakMin).delay_ms ==
        routeloom::kFailSleepMs);
  CHECK(routeloom::fail_action(1000000).deep_sleep);
}

void test_fail_policy_bounds_boot_loop_writes() {
  // The issue's scenario, arithmetically: NVS init fails on every boot and
  // each boot commits one session write. Under the policy the first
  // kFailSleepStreakMin boots cost only their backoff; every further boot
  // costs a full deep sleep — so the number of boots per day is bounded
  // instead of one write per uncapped restart iteration.
  std::uint64_t elapsed_ms = 0;
  std::uint64_t boots = 0;
  std::uint32_t streak = 0;
  constexpr std::uint64_t kDayMs = 24ULL * 60 * 60 * 1000;
  while (elapsed_ms < kDayMs) {
    ++boots;
    elapsed_ms += routeloom::fail_action(streak++).delay_ms;
  }
  CHECK(boots <= routeloom::kFailSleepStreakMin +
                     kDayMs / routeloom::kFailSleepMs + 1);
}


// Issue #29/#48 (Wire v2): epochs are 32-bit, so a node that has booted more
// than 65,535 times keeps working. v1 wrapped the u16 epoch 0xFFFF -> 1,
// after which every peer's replay floor rejected the node forever and its
// own TX counter lease refused the "older" epoch (self-bricking). Walk one
// peer pair across the old wrap point, one epoch per simulated boot.
void test_epochs_survive_past_u16_boot_budget() {
  MemoryCounterStore counters;
  FlakyReplayStore replay;
  std::uint64_t value = 0;
  for (std::uint32_t epoch = 65530; epoch <= 65542; ++epoch) {
    // Sender side: each boot opens a fresh lease for the new epoch on the
    // same slot. A regressed epoch would be refused as Conflict.
    CounterLease lease(counters, 1, 99, epoch, 0, 4);
    CHECK_OK(lease.initialize());
    CHECK_OK(lease.next(value));
    CHECK(value == 0);  // epoch-scoped counter space restarts
    // Receiver side: the floor ratchets to the new epoch and accepts it.
    ReplayGuard guard(replay);
    ReplayGuard::Window window{};
    SecurityContext ctx = kCtx;
    ctx.epoch = epoch;
    CHECK_OK(guard.open_context(ctx, window));
    CHECK_OK(guard.accept(window, value));
  }
  // Far past the old budget, in one jump (a long-lived node).
  CounterLease far(counters, 1, 99, 1000000, 0, 4);
  CHECK_OK(far.initialize());
  CHECK_OK(far.next(value));
  ReplayGuard guard(replay);
  ReplayGuard::Window window{};
  SecurityContext ctx = kCtx;
  ctx.epoch = 1000000;
  CHECK_OK(guard.open_context(ctx, window));
  CHECK_OK(guard.accept(window, value));
  // Anti-replay still holds: an epoch behind the floor — including the
  // value a v1 wrap would have produced — is rejected, not resurrected.
  for (const std::uint32_t stale : {1U, 65535U, 999999U}) {
    SecurityContext old = kCtx;
    old.epoch = stale;
    ReplayGuard::Window w{};
    CHECK(guard.open_context(old, w).code == StatusCode::ReplayRejected);
    CounterLease back(counters, 1, 99, stale, 0, 4);
    CHECK(back.initialize().code == StatusCode::Conflict);
  }
}

// --- Flash wear: replay ceiling reservation (issue #30) ---------------------

std::uint64_t next_random(std::uint64_t& state) {
  state = state * 6364136223846793005ULL + 1442695040888963407ULL;
  return state >> 33;
}

void test_replay_commits_bounded_per_reservation() {
  // Before #30 every accepted frame committed the window (one NVS write per
  // authenticated frame). The persisted ceiling is now raised only when the
  // live maximum crosses it: one commit per kReplayReservationAhead + 1
  // counters advanced.
  constexpr std::uint64_t kFrames = 10000;
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  const std::size_t floor_commits = store.floor_commits;
  CHECK(floor_commits == 1);  // cold-start floor, written once
  for (std::uint64_t counter = 0; counter < kFrames; ++counter) {
    CHECK_OK(guard.accept(window, counter));
  }
  CHECK(store.window_commits ==
        (kFrames + kReplayReservationAhead) / (kReplayReservationAhead + 1));
  CHECK(store.floor_commits == floor_commits);  // only on epoch change

  // Jittered delivery (neighbouring frames swapped) costs the same.
  FlakyReplayStore jitter_store;
  ReplayGuard jitter(jitter_store);
  ReplayGuard::Window jitter_window{};
  CHECK_OK(jitter.open_context(kCtx, jitter_window));
  for (std::uint64_t counter = 0; counter < kFrames; counter += 2) {
    CHECK_OK(jitter.accept(jitter_window, counter + 1));
    CHECK_OK(jitter.accept(jitter_window, counter));
  }
  CHECK(jitter_store.window_commits <= kFrames / kReplayReservationAhead + 1);

  // reservation_ahead = 0 reproduces the old cost: a commit per advance.
  FlakyReplayStore eager_store;
  ReplayGuard eager(eager_store, 0);
  ReplayGuard::Window eager_window{};
  CHECK_OK(eager.open_context(kCtx, eager_window));
  for (std::uint64_t counter = 0; counter < 100; ++counter) {
    CHECK_OK(eager.accept(eager_window, counter));
  }
  CHECK(eager_store.window_commits == 100);
}

void test_replay_out_of_order_within_window_before_crash() {
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    // Out-of-order frames below the live maximum are admitted from the RAM
    // bitmap exactly once, with no extra commit.
    CHECK_OK(guard.accept(window, 10));
    CHECK_OK(guard.accept(window, 13));
    CHECK_OK(guard.accept(window, 11));
    CHECK_OK(guard.accept(window, 12));
    CHECK_OK(guard.accept(window, 60));
    CHECK_OK(guard.accept(window, 20));
    CHECK_OK(guard.accept(window, 70));
    CHECK_OK(guard.accept(window, 7));  // 63 behind: last bit of the window
    CHECK(guard.accept(window, 6).code == StatusCode::ReplayRejected);
    CHECK(guard.accept(window, 11).code == StatusCode::ReplayRejected);
    CHECK(guard.accept(window, 20).code == StatusCode::ReplayRejected);
    CHECK(store.window_commits == 1);  // all under ceiling 10 + ahead
    CHECK_OK(guard.accept(window, 10 + kReplayReservationAhead + 1));
    CHECK(store.window_commits == 2);
    // Power cut here: no close_context, the RAM window is simply lost.
  }
  const std::uint64_t ceiling = 10 + kReplayReservationAhead + 1 +
                                kReplayReservationAhead;
  CHECK(store.windows.begin()->second.accepted_ceiling == ceiling);
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  for (const std::uint64_t seen : {7ULL, 10ULL, 11ULL, 12ULL, 13ULL, 20ULL,
                                   60ULL, 70ULL,
                                   10ULL + kReplayReservationAhead + 1}) {
    CHECK(guard.accept(window, seen).code == StatusCode::ReplayRejected);
  }
  // Never accepted, but at or below the ceiling: conservatively rejected.
  CHECK(guard.accept(window, 8).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(window, ceiling).code == StatusCode::ReplayRejected);
  CHECK_OK(guard.accept(window, ceiling + 1));
}

void test_replay_crash_never_reaccepts() {
  // Randomized power cuts: a peer keeps sending increasing counters with
  // gaps, stragglers and replays; the receiver loses its RAM at random
  // points (sometimes after a clean close_context). No counter may ever be
  // accepted twice, fresh counters above the persisted ceiling are always
  // accepted, and fresh counters at or below it are the only (bounded) loss.
  FlakyReplayStore store;
  std::set<std::uint64_t> accepted;
  std::vector<std::uint64_t> sent;
  std::uint64_t state = 0x5eed5eed5eedULL;
  std::uint64_t sender = 0;
  std::size_t lost_fresh = 0;
  constexpr int kBoots = 40;
  for (int boot = 0; boot < kBoots; ++boot) {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    const bool had_ceiling = window.live;
    const std::uint64_t ceiling_at_open = window.maximum_counter;
    for (const std::uint64_t old : accepted) {
      CHECK(guard.accept(window, old).code == StatusCode::ReplayRejected);
    }
    std::size_t lost_this_boot = 0;
    const std::uint64_t frames = 1 + next_random(state) % 300;
    for (std::uint64_t frame = 0; frame < frames; ++frame) {
      if (!sent.empty() && next_random(state) % 4 == 0) {
        // Straggler or replay of something already sent.
        const std::uint64_t pick = sent[next_random(state) % sent.size()];
        const auto status = guard.accept(window, pick);
        if (status.ok()) CHECK(accepted.insert(pick).second);
        continue;
      }
      const std::uint64_t fresh = sender;
      sender += 1 + (next_random(state) % 5 == 0 ? next_random(state) % 90 : 0);
      sent.push_back(fresh);
      const auto status = guard.accept(window, fresh);
      if (had_ceiling && fresh <= ceiling_at_open) {
        CHECK(status.code == StatusCode::ReplayRejected);
        ++lost_this_boot;
      } else {
        CHECK_OK(status);
      }
      if (status.ok()) CHECK(accepted.insert(fresh).second);
    }
    CHECK(lost_this_boot <= kReplayReservationAhead);
    lost_fresh += lost_this_boot;
    if (boot % 3 == 0) {
      (void)guard.close_context(window);  // clean shutdown tightens
    }
  }
  CHECK(lost_fresh <= kBoots * kReplayReservationAhead);
  CHECK(!accepted.empty());
  // Commit budget: one per reservation step of counter space advanced, plus
  // at most a re-reservation and a tighten per boot.
  CHECK(store.window_commits <=
        sender / (kReplayReservationAhead + 1) + 2 * kBoots + 1);
}

void test_replay_close_context_tightens_ceiling() {
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  for (std::uint64_t counter = 0; counter < 10; ++counter) {
    CHECK_OK(guard.accept(window, counter));
  }
  CHECK(store.window_commits == 1);
  // Eviction / clean shutdown: lower the ceiling to the live maximum so a
  // reopen loses no fresh counter.
  CHECK_OK(guard.close_context(window));
  CHECK(!window.open);
  CHECK(store.window_commits == 2);
  CHECK(store.windows.begin()->second.accepted_ceiling == 9);
  ReplayGuard::Window reopened{};
  CHECK_OK(guard.open_context(kCtx, reopened));
  CHECK(guard.accept(reopened, 9).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(reopened, 3).code == StatusCode::ReplayRejected);
  CHECK_OK(guard.accept(reopened, 10));  // the very next fresh counter
  CHECK(store.window_commits == 3);
  // Nothing outstanding (maximum == ceiling right after a reopen): no write.
  ReplayGuard restarted(store);
  ReplayGuard::Window idle{};
  CHECK_OK(restarted.open_context(kCtx, idle));
  CHECK_OK(restarted.close_context(idle));
  CHECK(store.window_commits == 3);

  // A stale-epoch window never tightens over the re-keyed record.
  FlakyReplayStore rekey_store;
  ReplayGuard rekey(rekey_store);
  ReplayGuard::Window epoch3{};
  CHECK_OK(rekey.open_context(kCtx, epoch3));
  CHECK_OK(rekey.accept(epoch3, 100));
  SecurityContext newer = kCtx;
  newer.epoch = 4;
  ReplayGuard::Window epoch4{};
  CHECK_OK(rekey.open_context(newer, epoch4));
  CHECK_OK(rekey.accept(epoch4, 0));
  const ReplayWindowRecord live = rekey_store.windows.begin()->second;
  CHECK(rekey.close_context(epoch3).code == StatusCode::ReplayRejected);
  CHECK(std::memcmp(&live, &rekey_store.windows.begin()->second,
                    sizeof(live)) == 0);
}

void test_replay_duplicate_window_cannot_lower_ceiling() {
  // Callers keep one Window per context, but a second one must never be
  // able to overwrite (and so lower) a ceiling it did not write: that would
  // re-admit the other window's counters after a restart.
  FlakyReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window first{};
  CHECK_OK(guard.open_context(kCtx, first));
  ReplayGuard::Window twin = first;  // duplicated fresh state
  for (std::uint64_t counter = 0; counter <= 10; ++counter) {
    CHECK_OK(guard.accept(first, counter));
  }
  // The fresh twin would re-key the slot over first's record: refused.
  CHECK(guard.accept(twin, 11).code == StatusCode::ReplayRejected);

  ReplayGuard::Window late{};
  CHECK_OK(guard.open_context(kCtx, late));  // starts at first's ceiling
  const std::uint64_t above = 10 + kReplayReservationAhead + 1;
  CHECK_OK(guard.accept(late, above));  // raises the ceiling past `above`
  // `first` still believes its (older) ceiling is current. Tightening to
  // its live maximum 10 would re-admit `above` after a restart.
  CHECK(guard.close_context(first).code == StatusCode::ReplayRejected);
  CHECK(store.windows.begin()->second.accepted_ceiling >= above);
  ReplayGuard restarted(store);
  ReplayGuard::Window window{};
  CHECK_OK(restarted.open_context(kCtx, window));
  CHECK(restarted.accept(window, above).code == StatusCode::ReplayRejected);
}

void test_replay_legacy_window_record_read_conservatively() {
  // A pre-reservation record (layout 0) stored the maximum accepted counter
  // where the ceiling lives now. Reading it as a ceiling rejects a superset
  // of what it used to reject; an unknown layout is corruption.
  FlakyReplayStore store;
  {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    CHECK_OK(guard.accept(window, 1));
  }
  ReplayWindowRecord& record = store.windows.begin()->second;
  record.layout = 0;
  record.accepted_ceiling = 40;  // legacy maximum_counter
  record.legacy_bitmap = 0x5;
  record.crc = crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&record),
               offsetof(ReplayWindowRecord, crc)});
  {
    ReplayGuard guard(store);
    ReplayGuard::Window window{};
    CHECK_OK(guard.open_context(kCtx, window));
    CHECK(guard.accept(window, 40).code == StatusCode::ReplayRejected);
    CHECK(guard.accept(window, 39).code == StatusCode::ReplayRejected);
    CHECK_OK(guard.accept(window, 41));
  }
  CHECK(store.windows.begin()->second.layout == kReplayRecordLayout);
  ReplayWindowRecord& rewritten = store.windows.begin()->second;
  rewritten.layout = 7;
  rewritten.crc = crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&rewritten),
               offsetof(ReplayWindowRecord, crc)});
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK(guard.open_context(kCtx, window).code == StatusCode::IntegrityError);
}

// --- Flash wear: evicted TX leases resume their block (issue #57) ---------

void test_counter_lease_resume_skips_block_commit() {
  MemoryCounterStore store;
  std::uint64_t value = 0;
  CounterLeaseCheckpoint parked{};
  {
    CounterLease lease(store, 7, 99, 1, 0, 8);
    CHECK_OK(lease.initialize());
    for (std::uint64_t expect = 0; expect < 3; ++expect) {
      CHECK_OK(lease.next(value));
      CHECK(value == expect);
    }
    parked = lease.checkpoint();  // cache eviction: cut, then drop
  }
  CHECK(parked.cursor == 3 && parked.end == 8);
  CHECK(store.commits == 1);
  CounterLease resumed(store, 7, 99, 1, 0, 8);
  CHECK_OK(resumed.resume(parked));
  for (std::uint64_t expect = 3; expect < 8; ++expect) {
    CHECK_OK(resumed.next(value));
    CHECK(value == expect);
  }
  CHECK(store.commits == 1);  // the parked remainder cost no flash write
  CHECK_OK(resumed.next(value));
  CHECK(value == 8);
  CHECK(store.commits == 2);
}

void test_counter_lease_resume_refuses_stale_checkpoint() {
  MemoryCounterStore store;
  std::uint64_t value = 0;
  CounterLease lease(store, 7, 99, 1, 0, 4);
  CHECK_OK(lease.initialize());
  CHECK_OK(lease.next(value));  // reserves [0,4)
  const CounterLeaseCheckpoint stale = lease.checkpoint();
  // A newer reservation was committed after the cut (by this or another
  // lease): the block may have been issued, so the checkpoint is void.
  CounterLease other(store, 7, 99, 1, 0, 4);
  CHECK_OK(other.initialize());
  CHECK_OK(other.next(value));
  CHECK(value == 4);
  CounterLease resumed(store, 7, 99, 1, 0, 4);
  CHECK_OK(resumed.resume(stale));
  CHECK_OK(resumed.next(value));
  CHECK(value == 8);  // fresh block past the persisted water mark

  // A checkpoint cut from another lease identity is ignored even when the
  // records happen to carry the same high-water and generation.
  MemoryCounterStore twin_store;
  CounterLease left(twin_store, 1, 99, 1, 0, 4);
  CounterLease right(twin_store, 2, 99, 1, 0, 4);
  CHECK_OK(left.initialize());
  CHECK_OK(right.initialize());
  CHECK_OK(left.next(value));
  CHECK_OK(right.next(value));
  const CounterLeaseCheckpoint foreign = left.checkpoint();
  CounterLease wrong(twin_store, 2, 99, 1, 0, 4);
  CHECK_OK(wrong.resume(foreign));
  CHECK_OK(wrong.next(value));
  CHECK(value == 4);
  // Nor is one for another epoch or direction of the same slot.
  CounterLeaseCheckpoint other_direction = right.checkpoint();
  other_direction.direction = 1;
  CounterLease direction_lease(twin_store, 2, 99, 1, 0, 4);
  CHECK_OK(direction_lease.resume(other_direction));
  CHECK_OK(direction_lease.next(value));
  CHECK(value == 8);
}

void test_counter_checkpoint_cache_single_use_and_bounded() {
  MemoryCounterStore store;
  std::uint64_t value = 0;
  std::vector<CounterLeaseCheckpoint> checkpoints;
  for (std::uint32_t slot = 1; slot <= 3; ++slot) {
    CounterLease lease(store, slot, 99, 1, 0, 4);
    CHECK_OK(lease.initialize());
    CHECK_OK(lease.next(value));
    checkpoints.push_back(lease.checkpoint());
  }
  const CounterLeaseCheckpoint probe1 = checkpoints[0];
  const CounterLeaseCheckpoint probe3 = checkpoints[2];
  CounterCheckpointCache<2> cache;
  CounterLeaseCheckpoint out{};
  cache.park(checkpoints[0]);
  CHECK(cache.size() == 1);
  CHECK(cache.take(probe1, out));
  CHECK(out.slot == 1 && out.cursor == 1);
  CHECK(!cache.take(probe1, out));  // single use
  // Nothing left to resume: not parked.
  CounterLeaseCheckpoint drained = checkpoints[0];
  drained.cursor = drained.end;
  cache.park(drained);
  CHECK(cache.size() == 0);
  // Bounded: the oldest checkpoint is dropped (forfeit, never reused).
  cache.park(checkpoints[0]);
  cache.park(checkpoints[1]);
  cache.park(checkpoints[2]);
  CHECK(cache.size() == 2);
  CHECK(!cache.take(probe1, out));
  CHECK(cache.take(probe3, out));
  // Re-parking one identity replaces its entry.
  cache.park(checkpoints[1]);
  CHECK(cache.size() == 1);
  cache.clear();
  CHECK(cache.size() == 0);
}

// Models DevelopmentPskSecurityProvider's TX pool: kPool live leases (LRU),
// evictions parked in a kParked checkpoint cache, random reboots. Returns
// the number of counter commits; `duplicate` flags any reissued counter.
std::size_t run_lease_churn(const bool park, bool& duplicate) {
  constexpr std::size_t kPool = 2;
  constexpr std::uint32_t kContexts = 5;
  MemoryCounterStore store;
  CounterCheckpointCache<3> cache;
  std::array<std::optional<CounterLease>, kPool> pool{};
  std::array<std::uint32_t, kPool> owner{};
  std::array<std::uint64_t, kPool> stamp{};
  std::set<std::pair<std::uint32_t, std::uint64_t>> issued;
  std::uint64_t state = 0xC0FFEEULL;
  std::uint64_t clock = 0;
  for (int step = 0; step < 6000; ++step) {
    if (next_random(state) % 700 == 0) {  // power cut: RAM gone
      for (auto& lease : pool) lease.reset();
      cache.clear();
    }
    const std::uint32_t slot =
        1 + static_cast<std::uint32_t>(next_random(state) % kContexts);
    std::size_t index = kPool;
    for (std::size_t i = 0; i < kPool; ++i) {
      if (pool[i].has_value() && owner[i] == slot) index = i;
    }
    if (index == kPool) {
      index = 0;
      for (std::size_t i = 0; i < kPool; ++i) {
        if (!pool[i].has_value()) {
          index = i;
          break;
        }
        if (stamp[i] < stamp[index]) index = i;
      }
      // Same order as the provider: claim this context's checkpoint before
      // parking the evicted lease, so a full cache cannot drop it first.
      CounterLeaseCheckpoint identity{};
      identity.slot = slot;
      identity.context_id = 99;
      identity.key_epoch = 1;
      CounterLeaseCheckpoint parked{};
      const bool resume = park && cache.take(identity, parked);
      if (pool[index].has_value()) {
        if (park) cache.park(pool[index]->checkpoint());
        pool[index].reset();
      }
      pool[index].emplace(store, slot, 99, 1, 0, 16);
      owner[index] = slot;
      CHECK_OK(resume ? pool[index]->resume(parked)
                      : pool[index]->initialize());
    }
    stamp[index] = ++clock;
    std::uint64_t value = 0;
    CHECK_OK(pool[index]->next(value));
    if (!issued.insert({slot, value}).second) duplicate = true;
  }
  return store.commits;
}

void test_counter_lease_eviction_churn_never_reissues() {
  bool duplicate = false;
  const std::size_t without_parking = run_lease_churn(false, duplicate);
  CHECK(!duplicate);
  const std::size_t with_parking = run_lease_churn(true, duplicate);
  CHECK(!duplicate);
  // Five contexts round-robin through a two-lease pool: without parking
  // nearly every eviction commits a fresh block; with the checkpoint cache
  // only block exhaustion and reboots do (about 400 vs 3600 here).
  CHECK(with_parking * 5 < without_parking);
}

}  // namespace

int main() {
  test_epochs_survive_past_u16_boot_budget();
  test_scope_separation_on_wire();
  test_scope_keys_not_interchangeable();
  test_link_open_is_not_origin_verification();
  test_counters_independent_of_message_id();
  test_replay_window_basics();
  test_replay_window_survives_restart();
  test_replay_window_loss_requires_new_epoch();
  test_replay_floor_enforced_per_frame();
  test_replay_epoch_advance_rekeys_shared_slot();
  test_replay_corruption_is_not_a_fresh_context();
  test_replay_commit_failure_rolls_back();
  test_replay_floor_cold_start_semantics();
  test_counter_lease_commit_failure_issues_nothing();
  test_counter_lease_never_reissues_across_restarts();
  test_counter_lease_context_mismatch_rejected();
  test_counter_lease_epoch_advance_rekeys_same_slot();
  test_counter_lease_stale_context_cannot_rewind_newer_epoch();
  test_replay_stale_record_at_floor_epoch_is_state_lost();
  test_counter_record_rewound_rejected();
  test_replay_commits_bounded_per_reservation();
  test_replay_out_of_order_within_window_before_crash();
  test_replay_crash_never_reaccepts();
  test_replay_close_context_tightens_ceiling();
  test_replay_duplicate_window_cannot_lower_ceiling();
  test_replay_legacy_window_record_read_conservatively();
  test_counter_lease_resume_skips_block_commit();
  test_counter_lease_resume_refuses_stale_checkpoint();
  test_counter_checkpoint_cache_single_use_and_bounded();
  test_counter_lease_eviction_churn_never_reissues();
  test_security_profile_marker();
  test_plaintext_data_rejected();
  test_secure_clear();
  test_fail_policy_backoff_schedule();
  test_fail_policy_bounds_boot_loop_writes();
  if (failures != 0) {
    std::fprintf(stderr, "%d hardening checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom security hardening tests passed");
  return 0;
}
