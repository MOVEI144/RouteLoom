#include "routeloom/group_replay.hpp"

namespace routeloom {

Status GroupReplayTable::accept(const SecurityContext& context,
                                const std::uint64_t counter) noexcept {
  if (context.scope != SecurityScope::Group || counter > kMaxCryptoCounter) {
    return Status::error(StatusCode::InvalidArgument, "not a group replay context");
  }
  Entry* entry = nullptr;
  Entry* free_slot = nullptr;
  for (Entry& candidate : entries_) {
    if (!candidate.used) {
      if (free_slot == nullptr) free_slot = &candidate;
      continue;
    }
    if (candidate.network == context.network && candidate.sender == context.sender &&
        candidate.group == context.receiver) {
      entry = &candidate;
      break;
    }
  }
  if (entry == nullptr) {
    if (free_slot == nullptr) {
      ++capacity_refusals_;
      return Status::error(StatusCode::NoCapacity, "GROUP_REPLAY_TABLE_FULL");
    }
    *free_slot = Entry{context.network, context.sender, context.receiver, context.epoch,
                       counter, 1, true};
    return Status::success();
  }
  if (context.epoch < entry->epoch) {
    ++stale_epochs_;
    return Status::error(StatusCode::ReplayRejected, "GROUP_EPOCH_STALE");
  }
  if (context.epoch > entry->epoch) {
    // The sender rebooted: its new epoch is a new key, the window restarts.
    entry->epoch = context.epoch;
    entry->maximum = counter;
    entry->bitmap = 1;
    return Status::success();
  }
  if (counter > entry->maximum) {
    const std::uint64_t shift = counter - entry->maximum;
    entry->bitmap = shift >= kWindow ? 0 : (entry->bitmap << shift);
    entry->bitmap |= 1;
    entry->maximum = counter;
    return Status::success();
  }
  const std::uint64_t distance = entry->maximum - counter;
  if (distance >= kWindow || ((entry->bitmap >> distance) & 1ULL) != 0) {
    ++replays_;
    return Status::error(StatusCode::ReplayRejected, "GROUP_REPLAY");
  }
  entry->bitmap |= 1ULL << distance;
  return Status::success();
}

std::size_t GroupReplayTable::size() const noexcept {
  std::size_t count = 0;
  for (const Entry& entry : entries_) count += entry.used ? 1U : 0U;
  return count;
}

void GroupReplayTable::clear() noexcept {
  for (Entry& entry : entries_) entry = Entry{};
}

}  // namespace routeloom
