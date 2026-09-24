#pragma once

// ExpectedReply (reply-direction) peer leases (issue #117, design-q116 §6):
// the portable Owner-side table behind ReplyPeerPort. One instance per radio
// Owner; MeshNode holds only the port (PR-C wires admission to it).
//
// Capacity (docs/reference/resource-profiles.json admission.*):
//   - 3 binding entries for the whole Owner, keyed by
//     (BindingId, BindingGeneration) — never 3 per peer. Every live
//     transaction on the same key shares the entry.
//   - 8 use handles. Each acquire mints its own use with a strictly
//     increasing per-slot serial; a token names one use, so a second release
//     or a stale token can never decrement another owner's reference.
// A use lives at most 1500 ms past acquisition (transaction_lifetime_ms);
// the entry's deadline is the live uses' maximum and diagnostic only —
// sweeping an entry on its own expiry while work references it is forbidden.
//
// The table never touches the driver or the binding directory: the Owner
// rechecks its live mapping, pins/registers the driver record, and rolls
// the lease back when registration fails. Revoke/rebind/context-retire and
// local leave retire entries through invalidate_*; outstanding uses drain
// via release. Physical deletion additionally needs the shared
// driver_release_allowed gate — a live use, an owed callback or any other
// pin denies it regardless of timers.
//
// Portable-core discipline: bounded, no heap, no exceptions, noexcept.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/peer_directory.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// resource-profiles.json admission.reply_peer_leases_max: simultaneous reply
// bindings for the whole Owner.
constexpr std::size_t kExpectedReplyBindingsMax = 3;
// Outstanding acquire handles; each names one use, not one binding.
constexpr std::size_t kReplyLeaseUsesMax = 8;
// resource-profiles.json admission.transaction_lifetime_ms: longest life of
// one acquired use, measured from acquisition.
constexpr std::uint32_t kReplyLeaseTtlMs = 1500;

// A binding as captured for one reply lease: the verified identity plus the
// Owner's current RX security-context identity for it. The Owner rechecks
// every field against its live mapping before the lease may send — equality
// only, contexts are never ordered or substituted.
struct ReplyBinding {
  NodeId peer{kInvalidNodeId};
  BindingId id{kInvalidBindingId};
  BindingGeneration generation{};
  std::uint32_t rx_context_id{0};

  friend constexpr bool operator==(const ReplyBinding& a,
                                   const ReplyBinding& b) noexcept {
    return a.peer == b.peer && a.id == b.id &&
           a.generation == b.generation && a.rx_context_id == b.rx_context_id;
  }
  friend constexpr bool operator!=(const ReplyBinding& a,
                                   const ReplyBinding& b) noexcept {
    return !(a == b);
  }
};

// One acquired use: the slot plus the serial issued for it. Slot numbers
// alone never authenticate a handle.
struct ReplyLeaseToken {
  std::uint32_t use_slot{0};
  std::uint32_t serial{0};

  friend constexpr bool operator==(const ReplyLeaseToken& a,
                                   const ReplyLeaseToken& b) noexcept {
    return a.use_slot == b.use_slot && a.serial == b.serial;
  }
  friend constexpr bool operator!=(const ReplyLeaseToken& a,
                                   const ReplyLeaseToken& b) noexcept {
    return !(a == b);
  }
};
constexpr ReplyLeaseToken kInvalidReplyLeaseToken{0xFFFFFFFFu, 0};

// Serial policy for ReplyLeaseToken (Q117-13): strictly increasing per use
// slot, starting at 1; exhaustion retires the slot instead of reusing a
// handle. A failed issuance leaves `next` alone.
constexpr bool next_use_serial(const std::uint32_t current,
                               std::uint32_t& next) noexcept {
  if (current == UINT32_MAX) return false;
  next = current + 1;
  return true;
}

// The Owner's reply-lease surface toward MeshNode (PR-C caller). All methods
// are noexcept and bounded; re-entry from a driver/observer callback returns
// Busy with zero observable change.
class ReplyPeerPort {
 public:
  virtual ~ReplyPeerPort() = default;
  // Reserve a reply use for `captured`, pinned to a driver record before
  // returning success. `deadline` is clamped to now + kReplyLeaseTtlMs.
  virtual Status acquire(ReplyBinding captured, MonotonicMs deadline,
                         MonotonicMs now, ReplyLeaseToken& out) noexcept = 0;
  // Drop one use. Unknown or stale tokens report NotFound and change nothing.
  virtual Status release(ReplyLeaseToken token) noexcept = 0;
  // Liveness of one use: NotFound (unknown token), Conflict (binding
  // retired), Expired (now >= deadline) or Ok.
  virtual Status validate(ReplyLeaseToken token, MonotonicMs now) noexcept = 0;
  // Send a reserved reply: the token's binding is rechecked against the
  // live mapping and the use deadline before anything transmits.
  virtual Status send_reply(ReplyLeaseToken token, std::uint64_t tx_token,
                            ByteView frame, MonotonicMs now) noexcept = 0;
  // Capture the Owner's current binding for an ACK-awaiting TX. The job
  // records the snapshot; the lease table spends no entry on it.
  virtual Status snapshot_binding(NodeId peer, ReplyBinding& out) noexcept = 0;
  // Send an ACK-awaiting TX only while the Owner's mapping still equals the
  // submitted binding; a changed mapping refuses instead of misdelivering.
  virtual Status send_bound(ReplyBinding binding, std::uint64_t tx_token,
                            ByteView frame) noexcept = 0;
};

// Evidence for the single physical driver-peer release decision, collected
// by the Owner from its own state and judged by driver_release_allowed:
// delete only with no ExpectedReply reference, no in-flight or quarantined
// TX, no other lease hold, and every submitted callback accounted for.
struct DriverReleaseEvidence {
  bool reply_uses_live{false};
  bool tx_in_flight{false};
  bool fence_or_quarantine{false};
  bool other_lease_hold{false};
  bool callbacks_drained{false};
};

constexpr bool driver_release_allowed(
    const DriverReleaseEvidence& evidence) noexcept {
  return !evidence.reply_uses_live && !evidence.tx_in_flight &&
         !evidence.fence_or_quarantine && !evidence.other_lease_hold &&
         evidence.callbacks_drained;
}

// The portable lease table. One instance per radio Owner, driven only from
// the Owner worker — never directly from a driver callback. Copying would
// duplicate live serials, so instances are neither copyable nor movable.
class ExpectedReplyLeases {
 public:
  ExpectedReplyLeases() noexcept = default;
  ExpectedReplyLeases(const ExpectedReplyLeases&) = delete;
  ExpectedReplyLeases& operator=(const ExpectedReplyLeases&) = delete;

  // Reserve one use on `captured`'s key. Shares the key's entry when one is
  // live; otherwise spends one of the 3 binding entries plus one use slot,
  // all-or-nothing. Busy (re-entry), InvalidArgument (zero identity field
  // or an already-expired deadline), TimeUncertain (regressed clock),
  // CounterExhausted (now + ttl unrepresentable, or every use slot retired
  // by serial exhaustion), Conflict (the key's entry was retired),
  // NoCapacity (3 bindings or 8 uses already live).
  Status acquire(ReplyBinding captured, MonotonicMs deadline, MonotonicMs now,
                 ReplyLeaseToken& out) noexcept;
  // Drop the named use; the entry frees once its last use is gone.
  // NotFound for an unknown slot or a rotated serial; Busy on re-entry.
  Status release(ReplyLeaseToken token) noexcept;
  // Liveness of one use; see ReplyPeerPort::validate. TimeUncertain on a
  // regressed clock, Busy on re-entry. Read-only apart from the guard.
  Status validate(ReplyLeaseToken token, MonotonicMs now) noexcept;
  // Retire every entry of one binding id (revoke/rebind/context-retire):
  // outstanding uses drain via release, new acquires on the id conflict,
  // and empty entries recycle immediately. Unknown ids are a no-op.
  Status invalidate_binding(BindingId id) noexcept;
  // Retire everything (local membership leave, Owner stop): same per-entry
  // semantics as invalidate_binding, applied to the whole table.
  Status invalidate_all() noexcept;

  // Resolve a live use to its captured binding for the send path: the
  // caller still validates the deadline itself. NotFound/Conflict mirror
  // release/validate. Read-only.
  Status use_binding(ReplyLeaseToken token, ReplyBinding& out) const noexcept;
  // Whether any unreleased use — live or retired — still references the
  // key: the reply-hold input of the driver-release gate. Read-only.
  bool holds_binding(BindingId id, BindingGeneration generation) const noexcept;
  std::size_t live_use_count() const noexcept;
  std::size_t live_entry_count() const noexcept;
  // Structural audit for tests (L-I2): every used entry's refcount equals
  // its holder bitmap's popcount, every link resolves both ways, no retired
  // slot is used, no serial is 0 on a live use. Read-only.
  bool check_invariants() const noexcept;

 private:
  struct Entry {
    ReplyBinding binding{};
    std::uint16_t refcount{0};    // live uses; add-checked though 8 « 64K
    std::uint16_t holder_mask{0};  // bit i: use slot i references this entry
    MonotonicMs deadline_max{0};  // live uses' maximum; diagnostic only
    bool used{false};
    bool retired{false};  // invalidated by the Owner; drains, never reopens
  };
  struct Use {
    std::uint8_t entry{kExpectedReplyBindingsMax};  // Entry index when used
    bool used{false};
    bool retired{false};  // serial exhausted: never reused in this lifetime
    std::uint32_t serial{0};  // last issued; 0 = never issued
    MonotonicMs deadline{0};
  };
  static_assert(sizeof(Entry) <= 64, "reply lease entry bound");
  static_assert(sizeof(Use) <= 16, "reply lease use bound");

  struct Guard {
    explicit Guard(bool& flag) noexcept : flag_(flag) { flag_ = true; }
    ~Guard() noexcept { flag_ = false; }
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    bool& flag_;
  };

  const Entry* find_entry(BindingId id, BindingGeneration generation) const noexcept;
  Entry* find_entry(BindingId id, BindingGeneration generation) noexcept;
  const Use* resolve(ReplyLeaseToken token) const noexcept;
  void recompute_deadline(Entry& entry) noexcept;

  std::array<Entry, kExpectedReplyBindingsMax> entries_{};
  std::array<Use, kReplyLeaseUsesMax> uses_{};
  MonotonicMs last_now_{0};  // admission clock anchor; regression is TimeUncertain
  bool in_call_{false};      // re-entry guard: mutators Busy while set
};
static_assert(sizeof(ExpectedReplyLeases) <= 384, "reply lease table bound");

}  // namespace routeloom
