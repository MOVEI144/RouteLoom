// Regression tests for the Secure Unicast hardening contract:
//  - Link vs EndToEnd scope separation (hop key never used for end sealing)
//  - link-layer authentication is not origin authorization
//  - crypto counters are provider-owned, independent of Message ID
//  - replay windows + epoch floors under simulated power cuts / store loss
//  - EXPERIMENTAL security-profile enforcement and no plaintext DATA path

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <vector>

#include "routeloom/counter_store.hpp"
#include "routeloom/node.hpp"
#include "routeloom/replay.hpp"
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
    return Status::success();
  }
  std::map<std::uint32_t, CounterRecord> records;
  bool fail_commits{false};
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
    return Status::success();
  }

  std::map<std::uint32_t, ReplayWindowRecord> windows;
  std::map<std::uint32_t, ReplayFloorRecord> floors;
  bool fail_loads{false};
  bool fail_commits{false};
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
  CHECK_OK(wire::forward(at_relay, 2, 3, 4900, relay, onward));
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
  CHECK(header_u64(first, 72) == 0 && header_u64(second, 72) == 1);    // link counter
  CHECK(header_u64(first, 80) == 0 && header_u64(second, 80) == 1);    // end counter
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
  // Simulated restart: new guard, same persisted store.
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  CHECK_OK(guard.open_context(kCtx, window));
  // The persisted window still rejects counters it covers.
  CHECK(guard.accept(window, 10).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(window, 11).code == StatusCode::ReplayRejected);
  // Counter 5 is inside the window and was never accepted — out-of-order
  // delivery keeps it admissible, exactly once.
  CHECK_OK(guard.accept(window, 5));
  CHECK(guard.accept(window, 5).code == StatusCode::ReplayRejected);
  CHECK_OK(guard.accept(window, 12));
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
  // A cached epoch-3 window still contains admissible counters — only the
  // per-frame floor check stops old-epoch frames. This is why providers must
  // call check_floor on cached contexts, not just at window creation.
  CHECK_OK(guard.accept(epoch3, 6));  // window alone would admit it
  CHECK(guard.check_floor(kCtx).code == StatusCode::ReplayRejected);
  CHECK_OK(guard.check_floor(newer));
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
  store.windows.begin()->second.bitmap ^= 0x1fULL;
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

  // A failed window commit rolls the in-memory window back: the frame is not
  // accepted and the counter can be retried once the store recovers.
  CHECK(guard.accept(window, 6).code == StatusCode::StorageFailure);
  store.fail_commits = false;
  CHECK_OK(guard.accept(window, 6));
  CHECK(guard.accept(window, 6).code == StatusCode::ReplayRejected);
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

}  // namespace

int main() {
  test_scope_separation_on_wire();
  test_scope_keys_not_interchangeable();
  test_link_open_is_not_origin_verification();
  test_counters_independent_of_message_id();
  test_replay_window_basics();
  test_replay_window_survives_restart();
  test_replay_window_loss_requires_new_epoch();
  test_replay_floor_enforced_per_frame();
  test_replay_corruption_is_not_a_fresh_context();
  test_replay_commit_failure_rolls_back();
  test_replay_floor_cold_start_semantics();
  test_counter_lease_commit_failure_issues_nothing();
  test_counter_lease_never_reissues_across_restarts();
  test_counter_lease_context_mismatch_rejected();
  test_security_profile_marker();
  test_plaintext_data_rejected();
  if (failures != 0) {
    std::fprintf(stderr, "%d hardening checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom security hardening tests passed");
  return 0;
}
