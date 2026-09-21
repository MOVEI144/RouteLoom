#include "routeloom/replay.hpp"

#include <cstddef>

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
  if (found && (floor.crc != floor_crc(floor) || floor.initialized == 0 ||
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
    if (record.crc != window_crc(record) || record.initialized == 0) {
      return Status::error(StatusCode::IntegrityError,
                           "replay window corrupt");
    }
    if (record.context_fingerprint != replay_context_fingerprint(context)) {
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
  window.slot = slot;
  window.epoch = context.epoch;
  window.open = true;
  return Status::success();
}

Status ReplayGuard::accept(Window& window, const std::uint64_t counter) noexcept {
  if (!window.open) {
    return Status::error(StatusCode::InvalidState, "replay window not open");
  }
  // The slot is shared per peer pair: if the floor advanced past this
  // window's epoch (peer re-handshake), the live record belongs to a newer
  // context and this stale window must not commit over it.
  {
    ReplayFloorRecord floor{};
    bool floor_found = false;
    const auto floor_status = store_.load_floor(window.slot, floor, floor_found);
    if (!floor_status) return floor_status;
    if (floor_found && floor.crc == floor_crc(floor) && floor.initialized != 0 &&
        window.epoch < floor.minimum_epoch) {
      return Status::error(StatusCode::ReplayRejected, "REPLAY_EPOCH_STALE");
    }
  }
  ReplayWindowRecord next = window.record;
  if (next.initialized == 0) {
    next.maximum_counter = counter;
    next.bitmap = 1;
    next.initialized = 1;
  } else if (counter > next.maximum_counter) {
    const std::uint64_t delta = counter - next.maximum_counter;
    next.bitmap = delta >= 64 ? 1ULL : ((next.bitmap << delta) | 1ULL);
    next.maximum_counter = counter;
  } else {
    const std::uint64_t delta = next.maximum_counter - counter;
    if (delta >= 64 || (next.bitmap & (1ULL << delta)) != 0) {
      return Status::error(StatusCode::ReplayRejected,
                         "replayed security counter");
    }
    next.bitmap |= 1ULL << delta;
  }
  ++next.generation;
  next.crc = window_crc(next);
  const ReplayWindowRecord previous = window.record;
  window.record = next;
  const auto status = store_.commit_window(window.slot, next);
  if (!status) {
    window.record = previous;
  }
  return status;
}

}  // namespace routeloom
