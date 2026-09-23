#include "routeloom/replay.hpp"

#include <cstddef>
#include <cstring>
#include <limits>

#include "routeloom/crc32.hpp"

namespace routeloom {
namespace {

constexpr std::uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

std::uint64_t fnv_add(std::uint64_t hash, const std::uint64_t value) noexcept {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    hash ^= static_cast<std::uint8_t>(value >> shift);
    hash *= kFnvPrime;
  }
  return hash;
}

std::uint32_t fold(std::uint64_t fingerprint) noexcept {
  return static_cast<std::uint32_t>(fingerprint ^ (fingerprint >> 32U));
}

std::uint32_t window_crc(const ReplayWindowRecord& record) noexcept {
  return crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&record),
               offsetof(ReplayWindowRecord, crc)});
}

std::uint32_t floor_crc(const ReplayFloorRecord& record) noexcept {
  return crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&record),
               offsetof(ReplayFloorRecord, crc)});
}

}  // namespace

std::uint64_t replay_context_fingerprint(const SecurityContext& context) noexcept {
  std::uint64_t hash = kFnvOffset;
  hash = fnv_add(hash, static_cast<std::uint64_t>(context.scope));
  hash = fnv_add(hash, context.network);
  hash = fnv_add(hash, context.sender);
  hash = fnv_add(hash, context.receiver);
  hash = fnv_add(hash, context.epoch);
  return hash;
}

std::uint64_t replay_peer_fingerprint(const SecurityContext& context) noexcept {
  std::uint64_t hash = kFnvOffset;
  hash = fnv_add(hash, static_cast<std::uint64_t>(context.scope));
  hash = fnv_add(hash, context.network);
  hash = fnv_add(hash, context.sender);
  hash = fnv_add(hash, context.receiver);
  // Domain-separate from the context fingerprint so a peer fingerprint can
  // never alias a concrete context.
  hash = fnv_add(hash, 0x524c50454c4f4f52ULL);  // "RLPELOOR" domain tag
  return hash;
}

std::uint32_t ReplayGuard::window_slot(const SecurityContext& context) noexcept {
  return fold(replay_context_fingerprint(context));
}

std::uint32_t ReplayGuard::floor_slot(const SecurityContext& context) noexcept {
  return fold(replay_peer_fingerprint(context));
}

Status ReplayGuard::floor_state(const SecurityContext& context,
                                ReplayFloorRecord& floor,
                                bool& found) noexcept {
  found = false;
  const auto status =
      store_.load_floor(floor_slot(context), floor, found);
  if (!status) return status;
  if (found && floor.crc == floor_crc(floor) && floor.initialized != 0 &&
      floor.layout == kReplayRecordLayout &&
      floor.peer_fingerprint != replay_peer_fingerprint(context)) {
    // A structurally valid floor owned by a different peer pair is a u32
    // slot collision (or foreign replay state): the pairs would reject each
    // other forever, so the reject is counted separately for diagnosis.
    ++foreign_fingerprint_rejects_;
    return Status::error(StatusCode::IntegrityError,
                         "replay floor foreign fingerprint");
  }
  if (found && (floor.crc != floor_crc(floor) || floor.initialized == 0 ||
                 floor.layout != kReplayRecordLayout ||
                floor.peer_fingerprint != replay_peer_fingerprint(context))) {
    // Corrupt replay state is never treated as a fresh context.
    return Status::error(StatusCode::IntegrityError,
                         "replay epoch floor corrupt");
  }
  return Status::success();
}

Status ReplayGuard::ratchet_floor(const SecurityContext& context,
                                  const ReplayFloorRecord& floor,
                                  const bool found) noexcept {
  if (found && context.epoch <= floor.minimum_epoch) {
    return Status::success();
  }
  ReplayFloorRecord next{};
  next.peer_fingerprint = replay_peer_fingerprint(context);
  next.minimum_epoch = context.epoch;
  next.initialized = 1;
  next.layout = kReplayRecordLayout;
  next.generation = found ? floor.generation + 1U : 1U;
  next.crc = floor_crc(next);
  return store_.commit_floor(floor_slot(context), next);
}

Status ReplayGuard::check_floor(const SecurityContext& context) noexcept {
  ReplayFloorRecord floor{};
  bool floor_found = false;
  auto status = floor_state(context, floor, floor_found);
  if (!status) return status;
  if (floor_found && context.epoch < floor.minimum_epoch) {
    return Status::error(StatusCode::ReplayRejected, "REPLAY_EPOCH_STALE");
  }
  // A missing or regressed floor is restored eagerly; failing to persist it
  // fails closed.
  return ratchet_floor(context, floor, floor_found);
}

Status ReplayGuard::open_context(const SecurityContext& context,
                                 Window& window) noexcept {
  window = Window{};

  ReplayFloorRecord floor{};
  bool floor_found = false;
  auto status = floor_state(context, floor, floor_found);
  if (!status) return status;
  if (floor_found && context.epoch < floor.minimum_epoch) {
    return Status::error(StatusCode::ReplayRejected, "REPLAY_EPOCH_STALE");
  }

  ReplayWindowRecord record{};
  bool window_found = false;
  // Windows share one slot per peer pair (the epoch-free floor slot), so an
  // epoch advance rewrites the same record instead of leaking one record
  // per boot. Epochs below the floor are rejected before this load, so a
  // valid-CRC record with a foreign fingerprint can only be a stale
  // previous-epoch window — safe to replace, never serve.
  const std::uint32_t slot = floor_slot(context);
  status = store_.load_window(slot, record, window_found);
  if (!status) return status;
  if (window_found) {
    // Layout 0 is the pre-reservation (per-frame) record: its maximum
    // accepted counter sits where the ceiling sits now, so adopting it as a
    // ceiling rejects a superset of what the old window rejected.
    if (record.crc != window_crc(record) || record.initialized == 0 ||
        (record.layout != 0 && record.layout != kReplayRecordLayout)) {
      return Status::error(StatusCode::IntegrityError,
                           "replay window corrupt");
    }
    if (record.context_fingerprint != replay_context_fingerprint(context)) {
      // A foreign-fingerprint record at this slot is a previous epoch's
      // window. Re-key it only on an actual epoch advance; at the existing
      // floor epoch the live window is absent, which is exactly the
      // mid-epoch loss condition — the floor stays fail-closed and the
      // peer must advance to a newer epoch to recover.
      if (floor_found && context.epoch <= floor.minimum_epoch) {
        ++foreign_fingerprint_rejects_;
        return Status::error(StatusCode::ReplayRejected, "REPLAY_STATE_LOST");
      }
      record = ReplayWindowRecord{};
      record.context_fingerprint = replay_context_fingerprint(context);
    }
  } else {
    // A missing window at the current floor epoch means the persisted replay
    // state was lost mid-epoch. Accepting it would re-admit every counter at
    // or below the last persisted maximum, so the context stays rejected
    // until the peer re-handshakes onto a newer epoch.
    if (floor_found && context.epoch == floor.minimum_epoch) {
      return Status::error(StatusCode::ReplayRejected, "REPLAY_STATE_LOST");
    }
    record.context_fingerprint = replay_context_fingerprint(context);
  }

  // Ratchet the floor before admitting the context; failing to persist it
  // fails closed.
  status = ratchet_floor(context, floor, floor_found);
  if (!status) return status;

  window.record = record;
  if (record.initialized != 0) {
    // The RAM window is gone (restart or cache eviction): everything at or
    // below the persisted ceiling may have been accepted before, so the
    // window restarts AT the ceiling with every bit set. Counters above it
    // were never accepted — accept() commits a ceiling before admitting.
    window.maximum_counter = record.accepted_ceiling;
    window.bitmap = ~0ULL;
    window.live = true;
  }
  window.slot = slot;
  window.epoch = context.epoch;
  window.peer_fingerprint = replay_peer_fingerprint(context);
  window.open = true;
  return Status::success();
}

Status ReplayGuard::check_window_floor(const Window& window) noexcept {
  // The slot is shared per peer pair: the floor is re-validated before any
  // use of a cached window so a stale in-memory window can never commit
  // over the live record, whatever the caller did between open and now.
  ReplayFloorRecord floor{};
  bool floor_found = false;
  const auto floor_status = store_.load_floor(window.slot, floor, floor_found);
  if (!floor_status) return floor_status;
  if (!floor_found) {
    return Status::error(StatusCode::ReplayRejected, "REPLAY_STATE_LOST");
  }
  if (floor.crc == floor_crc(floor) && floor.initialized != 0 &&
      floor.layout == kReplayRecordLayout &&
      floor.peer_fingerprint != window.peer_fingerprint) {
    // Same collision signature as floor_state: a valid floor owned by a
    // different peer pair at this window's shared slot.
    ++foreign_fingerprint_rejects_;
    return Status::error(StatusCode::IntegrityError,
                         "replay floor foreign fingerprint");
  }
  if (floor.crc != floor_crc(floor) || floor.initialized == 0 ||
      floor.layout != kReplayRecordLayout ||
      floor.peer_fingerprint != window.peer_fingerprint) {
    return Status::error(StatusCode::IntegrityError,
                         "replay epoch floor corrupt");
  }
  if (window.epoch < floor.minimum_epoch) {
    return Status::error(StatusCode::ReplayRejected, "REPLAY_EPOCH_STALE");
  }
  return Status::success();
}

Status ReplayGuard::commit_ceiling(Window& window,
                                   const std::uint64_t ceiling) noexcept {
  // Compare-and-swap against the persisted record. Raising or lowering
  // (close_context) the ceiling is safe only while this window has been the
  // sole writer since its last commit/load: a second window for the same
  // context could have raised the ceiling over counters it accepted, and
  // overwriting that with a lower value would re-admit them after a
  // restart. Anything unexpected at the slot fails closed.
  ReplayWindowRecord persisted{};
  bool found = false;
  const auto load_status = store_.load_window(window.slot, persisted, found);
  if (!load_status) return load_status;
  if (window.record.initialized != 0) {
    if (!found ||
        std::memcmp(&persisted, &window.record, sizeof(persisted)) != 0) {
      return Status::error(StatusCode::ReplayRejected,
                           "REPLAY_WINDOW_SUPERSEDED");
    }
  } else if (found && persisted.context_fingerprint ==
                          window.record.context_fingerprint) {
    // A fresh window, yet the slot already carries this context's record:
    // another window committed first. Only a previous epoch's record (a
    // foreign fingerprint, gated by the floor check) may be re-keyed.
    return Status::error(StatusCode::ReplayRejected,
                         "REPLAY_WINDOW_SUPERSEDED");
  }

  ReplayWindowRecord next = window.record;
  next.accepted_ceiling = ceiling;
  next.legacy_bitmap = 0;
  next.initialized = 1;
  next.layout = kReplayRecordLayout;
  for (auto& byte : next.reserved) byte = 0;
  ++next.generation;
  next.crc = window_crc(next);
  const auto status = store_.commit_window(window.slot, next);
  if (!status) return status;
  window.record = next;
  return Status::success();
}

Status ReplayGuard::accept(Window& window, const std::uint64_t counter) noexcept {
  if (!window.open) {
    return Status::error(StatusCode::InvalidState, "replay window not open");
  }
  const auto floor_status = check_window_floor(window);
  if (!floor_status) return floor_status;

  std::uint64_t maximum = window.maximum_counter;
  std::uint64_t bitmap = window.bitmap;
  if (!window.live) {
    maximum = counter;
    bitmap = 1;
  } else if (counter > maximum) {
    const std::uint64_t delta = counter - maximum;
    bitmap = delta >= 64 ? 1ULL : ((bitmap << delta) | 1ULL);
    maximum = counter;
  } else {
    const std::uint64_t delta = maximum - counter;
    if (delta >= 64 || (bitmap & (1ULL << delta)) != 0) {
      return Status::error(StatusCode::ReplayRejected,
                           "replayed security counter");
    }
    bitmap |= 1ULL << delta;
  }

  // Invariant: every accepted counter is <= the DURABLE ceiling at the time
  // it is reported accepted. Only a new maximum above the ceiling needs a
  // commit, and it reserves reservation_ahead_ counters past the maximum so
  // the following frames are free. The RAM window changes only after the
  // commit succeeded — a failed commit leaves the frame unaccepted.
  if (window.record.initialized == 0 ||
      maximum > window.record.accepted_ceiling) {
    constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t ceiling = maximum > kMax - reservation_ahead_
                                      ? kMax
                                      : maximum + reservation_ahead_;
    const auto status = commit_ceiling(window, ceiling);
    if (!status) return status;
  }
  window.maximum_counter = maximum;
  window.bitmap = bitmap;
  window.live = true;
  return Status::success();
}

Status ReplayGuard::close_context(Window& window) noexcept {
  Status status = Status::success();
  if (window.open && window.live && window.record.initialized != 0 &&
      window.maximum_counter < window.record.accepted_ceiling) {
    // The live maximum is >= every counter this window accepted (a window
    // reopened from the store starts AT the old ceiling), and the CAS in
    // commit_ceiling proves no other window committed since — so the live
    // maximum is a valid, lower ceiling.
    status = check_window_floor(window);
    if (status) status = commit_ceiling(window, window.maximum_counter);
  }
  window = Window{};
  return status;
}

}  // namespace routeloom
