#include "routeloom/reply_peer_leases.hpp"

namespace routeloom {

const ExpectedReplyLeases::Entry* ExpectedReplyLeases::find_entry(
    const BindingId id, const BindingGeneration generation) const noexcept {
  for (const auto& entry : entries_) {
    if (entry.used && entry.binding.id == id &&
        entry.binding.generation == generation) {
      return &entry;
    }
  }
  return nullptr;
}

ExpectedReplyLeases::Entry* ExpectedReplyLeases::find_entry(
    const BindingId id, const BindingGeneration generation) noexcept {
  for (auto& entry : entries_) {
    if (entry.used && entry.binding.id == id &&
        entry.binding.generation == generation) {
      return &entry;
    }
  }
  return nullptr;
}

const ExpectedReplyLeases::Use* ExpectedReplyLeases::resolve(
    const ReplyLeaseToken token) const noexcept {
  if (token.use_slot >= uses_.size()) return nullptr;
  const Use& use = uses_[token.use_slot];
  if (!use.used || use.serial != token.serial) return nullptr;
  return &use;
}

void ExpectedReplyLeases::recompute_deadline(Entry& entry) noexcept {
  MonotonicMs max = 0;
  for (std::size_t i = 0; i < uses_.size(); ++i) {
    const Use& use = uses_[i];
    if (use.used && use.entry < entries_.size() &&
        &entries_[use.entry] == &entry && use.deadline > max) {
      max = use.deadline;
    }
  }
  entry.deadline_max = max;
}

Status ExpectedReplyLeases::acquire(const ReplyBinding captured,
                                    const MonotonicMs deadline,
                                    const MonotonicMs now,
                                    ReplyLeaseToken& out) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant acquire");
  Guard guard(in_call_);
  out = kInvalidReplyLeaseToken;
  if (now < last_now_) {
    return Status::error(StatusCode::TimeUncertain, "clock regressed");
  }
  if (captured.peer == kInvalidNodeId || captured.id == kInvalidBindingId ||
      captured.generation == BindingGeneration{0} ||
      captured.rx_context_id == 0) {
    return Status::error(StatusCode::InvalidArgument, "zero identity field");
  }
  if (deadline <= now) {
    // now >= deadline is already the expiry boundary: refuse instead of
    // admitting a dead use.
    return Status::error(StatusCode::InvalidArgument, "deadline already passed");
  }
  if (now > UINT64_MAX - kReplyLeaseTtlMs) {
    return Status::error(StatusCode::CounterExhausted, "ttl unrepresentable");
  }
  const MonotonicMs cap = now + kReplyLeaseTtlMs;
  const MonotonicMs grant = deadline < cap ? deadline : cap;
  // Select both slots before mutating anything: the commit below cannot
  // fail, so no rollback path exists to get wrong.
  Entry* entry = find_entry(captured.id, captured.generation);
  if (entry != nullptr && entry->retired) {
    return Status::error(StatusCode::Conflict, "binding retired");
  }
  if (entry != nullptr && entry->binding != captured) {
    return Status::error(StatusCode::Conflict, "binding identity changed");
  }
  std::size_t entry_index = entries_.size();
  if (entry != nullptr) {
    entry_index = static_cast<std::size_t>(entry - entries_.data());
  } else {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
      if (!entries_[i].used) {
        entry_index = i;
        break;
      }
    }
    if (entry_index == entries_.size()) {
      return Status::error(StatusCode::NoCapacity, "3 reply bindings live");
    }
  }
  std::size_t use_index = uses_.size();
  std::uint32_t grant_serial = 0;
  bool retired_seen = false;
  for (std::size_t i = 0; i < uses_.size(); ++i) {
    if (uses_[i].used) continue;
    if (uses_[i].retired) {
      retired_seen = true;
      continue;
    }
    if (!next_use_serial(uses_[i].serial, grant_serial)) {
      uses_[i].retired = true;  // serial exhausted: park the slot for good
      retired_seen = true;
      continue;
    }
    use_index = i;
    break;
  }
  if (use_index == uses_.size()) {
    return Status::error(retired_seen ? StatusCode::CounterExhausted
                                      : StatusCode::NoCapacity,
                         retired_seen ? "use serials exhausted" : "8 uses live");
  }
  if (entry != nullptr && entry->refcount == UINT16_MAX) {
    // Unreachable while uses stay 8 « 64K, but a wrapped refcount would
    // free a referenced entry — refuse rather than corrupt it.
    return Status::error(StatusCode::InternalError, "entry refcount saturated");
  }
  // --- Commit: plain assignments, infallible from here. ---
  last_now_ = now;
  Use& use = uses_[use_index];
  if (entry == nullptr) {
    entry = &entries_[entry_index];
    entry->binding = captured;
    entry->refcount = 0;
    entry->holder_mask = 0;
    entry->deadline_max = 0;
    entry->used = true;
    entry->retired = false;
  }
  ++entry->refcount;
  entry->holder_mask |= static_cast<std::uint16_t>(1u << use_index);
  use.serial = grant_serial;
  use.entry = static_cast<std::uint8_t>(entry_index);
  use.used = true;
  use.deadline = grant;
  recompute_deadline(*entry);
  out.use_slot = static_cast<std::uint32_t>(use_index);
  out.serial = use.serial;
  return Status::success();
}

Status ExpectedReplyLeases::probe_acquire(const ReplyBinding captured,
                                           const MonotonicMs deadline,
                                           const MonotonicMs now) const noexcept {
  // Same check sequence as acquire; no mutation, no clock anchor advance.
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant probe");
  if (now < last_now_) {
    return Status::error(StatusCode::TimeUncertain, "clock regressed");
  }
  if (captured.peer == kInvalidNodeId || captured.id == kInvalidBindingId ||
      captured.generation == BindingGeneration{0} ||
      captured.rx_context_id == 0) {
    return Status::error(StatusCode::InvalidArgument, "zero identity field");
  }
  if (deadline <= now) {
    return Status::error(StatusCode::InvalidArgument, "deadline already passed");
  }
  if (now > UINT64_MAX - kReplyLeaseTtlMs) {
    return Status::error(StatusCode::CounterExhausted, "ttl unrepresentable");
  }
  const Entry* entry = find_entry(captured.id, captured.generation);
  if (entry != nullptr && entry->retired) {
    return Status::error(StatusCode::Conflict, "binding retired");
  }
  if (entry != nullptr && entry->binding != captured) {
    return Status::error(StatusCode::Conflict, "binding identity changed");
  }
  if (entry == nullptr) {
    bool free_entry = false;
    for (const auto& candidate : entries_) {
      if (!candidate.used) {
        free_entry = true;
        break;
      }
    }
    if (!free_entry) {
      return Status::error(StatusCode::NoCapacity, "3 reply bindings live");
    }
  }
  bool retired_seen = false;
  bool free_use = false;
  for (const auto& use : uses_) {
    if (use.used) continue;
    if (use.retired) {
      retired_seen = true;
      continue;
    }
    std::uint32_t ignored = 0;
    if (!next_use_serial(use.serial, ignored)) {
      retired_seen = true;  // acquire would park this slot; probe must not
      continue;
    }
    free_use = true;
    break;
  }
  if (!free_use) {
    return Status::error(retired_seen ? StatusCode::CounterExhausted
                                      : StatusCode::NoCapacity,
                         retired_seen ? "use serials exhausted" : "8 uses live");
  }
  if (entry != nullptr && entry->refcount == UINT16_MAX) {
    return Status::error(StatusCode::InternalError, "entry refcount saturated");
  }
  return Status::success();
}

Status ExpectedReplyLeases::release(const ReplyLeaseToken token) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant release");
  Guard guard(in_call_);
  if (token.use_slot >= uses_.size()) {
    return Status::error(StatusCode::NotFound, "unknown use slot");
  }
  Use& use = uses_[token.use_slot];
  if (!use.used || use.serial != token.serial) {
    // Unknown slot or rotated serial: no state may change, in particular
    // never the reference of whatever owner holds the slot now.
    return Status::error(StatusCode::NotFound, "stale token");
  }
  if (use.entry >= entries_.size()) {
    return Status::error(StatusCode::InternalError, "use without entry");
  }
  Entry& entry = entries_[use.entry];
  const std::uint16_t bit = static_cast<std::uint16_t>(1u << token.use_slot);
  if (!entry.used || entry.refcount == 0 || (entry.holder_mask & bit) == 0) {
    return Status::error(StatusCode::InternalError, "entry link broken");
  }
  use.used = false;
  --entry.refcount;
  entry.holder_mask &= static_cast<std::uint16_t>(~bit);
  if (entry.refcount == 0) {
    // The last reference — live or retired — recycles the entry at once;
    // nothing lingers until a timer.
    entry.used = false;
    entry.retired = false;
    entry.binding = ReplyBinding{};
    entry.deadline_max = 0;
  } else {
    recompute_deadline(entry);
  }
  return Status::success();
}

Status ExpectedReplyLeases::validate(const ReplyLeaseToken token,
                                     const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant validate");
  Guard guard(in_call_);
  if (now < last_now_) {
    return Status::error(StatusCode::TimeUncertain, "clock regressed");
  }
  last_now_ = now;
  const Use* use = resolve(token);
  if (use == nullptr) return Status::error(StatusCode::NotFound, "stale token");
  if (use->entry >= entries_.size()) {
    return Status::error(StatusCode::InternalError, "use without entry");
  }
  const Entry& entry = entries_[use->entry];
  if (!entry.used || entry.retired) {
    return Status::error(StatusCode::Conflict, "binding retired");
  }
  if (now >= use->deadline) {
    return Status::error(StatusCode::Expired, "use deadline passed");
  }
  return Status::success();
}

Status ExpectedReplyLeases::invalidate_binding(const BindingId id) noexcept {
  if (in_call_) {
    return Status::error(StatusCode::Busy, "reentrant invalidate_binding");
  }
  Guard guard(in_call_);
  for (auto& entry : entries_) {
    if (entry.used && entry.binding.id == id) {
      entry.retired = true;
      if (entry.refcount == 0) {
        entry.used = false;
        entry.retired = false;
        entry.binding = ReplyBinding{};
        entry.deadline_max = 0;
      }
    }
  }
  return Status::success();
}

Status ExpectedReplyLeases::invalidate_all() noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant invalidate_all");
  Guard guard(in_call_);
  for (auto& entry : entries_) {
    if (!entry.used) continue;
    entry.retired = true;
    if (entry.refcount == 0) {
      entry.used = false;
      entry.retired = false;
      entry.binding = ReplyBinding{};
      entry.deadline_max = 0;
    }
  }
  return Status::success();
}

Status ExpectedReplyLeases::use_binding(const ReplyLeaseToken token,
                                        ReplyBinding& out) const noexcept {
  out = ReplyBinding{};
  const Use* use = resolve(token);
  if (use == nullptr) return Status::error(StatusCode::NotFound, "stale token");
  if (use->entry >= entries_.size()) {
    return Status::error(StatusCode::InternalError, "use without entry");
  }
  const Entry& entry = entries_[use->entry];
  if (!entry.used || entry.retired) {
    return Status::error(StatusCode::Conflict, "binding retired");
  }
  out = entry.binding;
  return Status::success();
}

bool ExpectedReplyLeases::holds_binding(
    const BindingId id, const BindingGeneration generation) const noexcept {
  const Entry* entry = find_entry(id, generation);
  return entry != nullptr && entry->refcount > 0;
}

std::size_t ExpectedReplyLeases::live_use_count() const noexcept {
  std::size_t count = 0;
  for (const auto& use : uses_) {
    if (use.used) ++count;
  }
  return count;
}

std::size_t ExpectedReplyLeases::live_entry_count() const noexcept {
  std::size_t count = 0;
  for (const auto& entry : entries_) {
    if (entry.used) ++count;
  }
  return count;
}

bool ExpectedReplyLeases::check_invariants() const noexcept {
  for (std::size_t e = 0; e < entries_.size(); ++e) {
    const Entry& entry = entries_[e];
    if (!entry.used) {
      if (entry.refcount != 0 || entry.holder_mask != 0) return false;
      continue;
    }
    // refcount equals the holder bitmap's popcount and covers live uses.
    std::uint16_t popcount = 0;
    MonotonicMs max = 0;
    for (std::size_t i = 0; i < uses_.size(); ++i) {
      if ((entry.holder_mask & static_cast<std::uint16_t>(1u << i)) == 0) continue;
      ++popcount;
      const Use& use = uses_[i];
      if (!use.used || use.entry != e || use.serial == 0) return false;
      if (use.deadline > max) max = use.deadline;
    }
    if (entry.refcount != popcount || entry.refcount == 0) return false;
    if (entry.deadline_max != max) return false;
  }
  for (std::size_t i = 0; i < uses_.size(); ++i) {
    const Use& use = uses_[i];
    if (use.retired && use.used) return false;
    if (!use.used) continue;
    if (use.serial == 0 || use.entry >= entries_.size()) return false;
    const Entry& entry = entries_[use.entry];
    if (!entry.used) return false;
    if ((entry.holder_mask & static_cast<std::uint16_t>(1u << i)) == 0) return false;
  }
  return true;
}

}  // namespace routeloom
