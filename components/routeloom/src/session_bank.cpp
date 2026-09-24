#include "routeloom/session_bank.hpp"

#include <cstring>

#include "routeloom/discovery_scope.hpp"  // hmac_sha256
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

constexpr char kSlotLabel[] = "RouteLoom/v1/session-slot";

bool keys_equal(const SessionBankEntry& entry, const ContextKeys& keys) noexcept {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < kSessionKeySize; ++i) {
    diff |= static_cast<std::uint8_t>(entry.tx_key[i] ^ keys.tx_key[i]);
    diff |= static_cast<std::uint8_t>(entry.rx_key[i] ^ keys.rx_key[i]);
  }
  for (std::size_t i = 0; i < kSessionIvSize; ++i) {
    diff |= static_cast<std::uint8_t>(entry.tx_iv[i] ^ keys.tx_iv[i]);
    diff |= static_cast<std::uint8_t>(entry.rx_iv[i] ^ keys.rx_iv[i]);
  }
  return diff == 0;
}

bool id_valid(const std::uint64_t id) noexcept {
  return id != kInvalidNodeId && id != kBroadcastNodeId;
}

bool unicast_scope(const SecurityScope scope) noexcept {
  return scope == SecurityScope::Link || scope == SecurityScope::EndToEnd;
}

}  // namespace

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::configure(const LocalView& local,
                                                           const AeadGcm& aead,
                                                           const RandomSource& random,
                                                           const MonotonicMs now) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!id_valid(local.self) || local.network == 0 ||
      (local.network & 0xFFFFFFFFU) == 0 || aead.seal == nullptr || aead.open == nullptr ||
      random.fn == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "session bank view invalid");
  }
  // Draw the salt before touching state: a failed configure keeps working
  // state (or stays unconfigured) instead of half-wiping it.
  std::array<std::uint8_t, 32> salt{};
  if (!random.fn(random.ctx, salt.data(), salt.size())) {
    return Status::error(StatusCode::InvalidState, "session entropy not ready");
  }
  wipe_all();
  local_ = local;
  aead_ = aead;
  random_ = random;
  slot_salt_ = salt;
  secure_clear(salt);
  slot_salt_ready_ = true;
  last_tick_ = now;
  install_serial_ = 0;
  configured_ = true;
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::tick(const MonotonicMs now) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (now < last_tick_) {
    // A backwards clock extends no lifetime.
    return Status::error(StatusCode::InvalidArgument, "session clock regressed");
  }
  const std::uint64_t elapsed = now - last_tick_;
  last_tick_ = now;
  if (elapsed == 0) return Status::success();
  auto age = [elapsed](std::uint32_t& remaining) {
    remaining = elapsed >= remaining ? 0 : static_cast<std::uint32_t>(remaining - elapsed);
  };
  for (std::size_t i = 0; i < kLinkCapacity; ++i) {
    if (!link_used_[i]) continue;
    age(link_[i].remaining_ms);
    if (link_[i].remaining_ms == 0 || !entry_usable(link_[i])) wipe_entry(link_[i], link_used_[i]);
  }
  for (std::size_t i = 0; i < kEndCapacity; ++i) {
    if (!end_used_[i]) continue;
    age(end_[i].remaining_ms);
    if (end_[i].remaining_ms == 0 || !entry_usable(end_[i])) wipe_entry(end_[i], end_used_[i]);
  }
  for (std::size_t i = 0; i < kOverlapCapacity; ++i) {
    if (!overlap_used_[i]) continue;
    age(overlap_[i].remaining_ms);
    if (overlap_[i].remaining_ms == 0) wipe_overlap(overlap_[i], overlap_used_[i]);
  }
  for (auto& demand : demand_) {
    if (!demand.used) continue;
    age(demand.hold_ms);
    if (demand.hold_ms == 0) demand.used = false;
  }
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::set_gk_epoch(const std::uint32_t gk_epoch) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (gk_epoch < local_.gk_epoch) {
    return Status::error(StatusCode::Conflict, "session gk epoch regressed");
  }
  local_.gk_epoch = gk_epoch;
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::reset_membership(const LocalView& local,
                                                                 const MonotonicMs now) noexcept {
  // configure() already draws-then-wipes, so a site change is exactly a
  // re-configure with the current ports.
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  return configure(local, aead_, random_, now);
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::map_network(
    const NetworkId context_network) const noexcept {
  if (context_network == local_.network) return true;
  return context_network == (local_.network & 0xFFFFFFFFU);
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::entry_usable(
    const SessionBankEntry& entry) const noexcept {
  if (entry.remaining_ms == 0) return false;
  const std::uint64_t created = entry.created_gk;
  const std::uint64_t current = local_.gk_epoch;
  // A context born more than one GK epoch ago, or from the future, is dead.
  // u64 arithmetic: created+2 must not wrap.
  if (current < created || current >= created + 2U) return false;
  return true;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
std::size_t SessionBank<kLinkCapacity, kEndCapacity>::hash_start(
    const SecurityScope scope, const NodeId peer) const noexcept {
  std::array<std::uint8_t, 64> input{};
  std::size_t at = 0;
  const auto put = [&](const void* data, const std::size_t size) {
    if (at + size > input.size()) return;
    std::memcpy(input.data() + at, data, size);
    at += size;
  };
  put(kSlotLabel, sizeof(kSlotLabel));  // includes the single NUL
  const std::uint8_t scope_byte = static_cast<std::uint8_t>(scope);
  put(&scope_byte, 1);
  std::uint8_t be[8];
  for (const std::uint64_t word : {local_.network, local_.self, peer}) {
    for (std::size_t i = 0; i < 8; ++i) be[i] = static_cast<std::uint8_t>(word >> (56U - 8U * i));
    put(be, 8);
  }
  ScopeDigest digest{};
  hmac_sha256(ByteView{slot_salt_.data(), slot_salt_.size()}, ByteView{input.data(), at}, digest);
  secure_clear(input);
  const std::uint32_t start = (static_cast<std::uint32_t>(digest[0]) << 24U) |
                              (static_cast<std::uint32_t>(digest[1]) << 16U) |
                              (static_cast<std::uint32_t>(digest[2]) << 8U) |
                              static_cast<std::uint32_t>(digest[3]);
  const std::size_t capacity = scope == SecurityScope::Link ? kLinkCapacity : kEndCapacity;
  return capacity == 0 ? 0 : static_cast<std::size_t>(start % capacity);
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
SessionBankEntry* SessionBank<kLinkCapacity, kEndCapacity>::find_current(
    const SecurityScope scope, const NodeId peer) noexcept {
  const SessionBank* self = this;
  return const_cast<SessionBankEntry*>(self->find_current(scope, peer));
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
const SessionBankEntry* SessionBank<kLinkCapacity, kEndCapacity>::find_current(
    const SecurityScope scope, const NodeId peer) const noexcept {
  if (!unicast_scope(scope)) return nullptr;
  const std::size_t capacity = scope == SecurityScope::Link ? kLinkCapacity : kEndCapacity;
  if (capacity == 0) return nullptr;
  const std::size_t start = hash_start(scope, peer);
  // Bounded open-addressing walk over the whole table: no tombstones, so a
  // hash collision can never wedge a lookup or mix two peers' windows — the
  // full (scope, peer) tuple decides, never the hash.
  for (std::size_t step = 0; step < capacity; ++step) {
    const std::size_t i = (start + step) % capacity;
    const bool used = scope == SecurityScope::Link ? link_used_[i] : end_used_[i];
    if (!used) continue;
    const SessionBankEntry& entry = scope == SecurityScope::Link ? link_[i] : end_[i];
    if (entry.peer == peer) return &entry;
  }
  return nullptr;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
void SessionBank<kLinkCapacity, kEndCapacity>::record_demand(const SecurityScope scope,
                                                             const NodeId peer) noexcept {
  for (auto& demand : demand_) {
    if (demand.used && demand.scope == scope && demand.peer == peer) {
      demand.hold_ms = local_.demand_hold_ms;
      return;
    }
  }
  for (auto& demand : demand_) {
    if (demand.used) continue;
    demand.used = true;
    demand.scope = scope;
    demand.peer = peer;
    demand.hold_ms = local_.demand_hold_ms;
    return;
  }
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
void SessionBank<kLinkCapacity, kEndCapacity>::wipe_entry(SessionBankEntry& entry,
                                                          bool& used) noexcept {
  secure_clear(entry.tx_key);
  secure_clear(entry.rx_key);
  secure_clear(entry.tx_iv);
  secure_clear(entry.rx_iv);
  secure_clear(entry.peer_cert_id);
  entry = SessionBankEntry{};
  used = false;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
void SessionBank<kLinkCapacity, kEndCapacity>::wipe_overlap(SessionOverlapEntry& entry,
                                                            bool& used) noexcept {
  secure_clear(entry.rx_key);
  secure_clear(entry.rx_iv);
  entry = SessionOverlapEntry{};
  used = false;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
void SessionBank<kLinkCapacity, kEndCapacity>::wipe_all() noexcept {
  for (std::size_t i = 0; i < kLinkCapacity; ++i) wipe_entry(link_[i], link_used_[i]);
  for (std::size_t i = 0; i < kEndCapacity; ++i) {
    wipe_entry(end_[i], end_used_[i]);
    end_lru_[i] = 0;
  }
  for (std::size_t i = 0; i < kOverlapCapacity; ++i) wipe_overlap(overlap_[i], overlap_used_[i]);
  for (auto& demand : demand_) demand = DemandEntry{};
  secure_clear(slot_salt_);
  secure_clear(staging_);
  slot_salt_ready_ = false;
  configured_ = false;
  install_serial_ = 0;
  lru_clock_ = 0;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::context_id_live(
    const std::uint32_t id) const noexcept {
  if (id == 0) return true;
  for (std::size_t i = 0; i < kLinkCapacity; ++i) {
    if (link_used_[i] && link_[i].rx_cid == id) return true;
  }
  for (std::size_t i = 0; i < kEndCapacity; ++i) {
    if (end_used_[i] && end_[i].rx_cid == id) return true;
  }
  for (std::size_t i = 0; i < kOverlapCapacity; ++i) {
    if (overlap_used_[i] && overlap_[i].rx_cid == id) return true;
  }
  return false;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::allocate_context_id(std::uint32_t& out) noexcept {
  out = 0;
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  for (std::size_t attempt = 0; attempt < kCidRetries; ++attempt) {
    std::uint8_t raw[4] = {0, 0, 0, 0};
    if (!random_.fn(random_.ctx, raw, sizeof(raw))) {
      return Status::error(StatusCode::InvalidState, "session entropy not ready");
    }
    const std::uint32_t id = (static_cast<std::uint32_t>(raw[0]) << 24U) |
                             (static_cast<std::uint32_t>(raw[1]) << 16U) |
                             (static_cast<std::uint32_t>(raw[2]) << 8U) |
                             static_cast<std::uint32_t>(raw[3]);
    if (!context_id_live(id)) {
      out = id;
      return Status::success();
    }
  }
  return Status::error(StatusCode::NoCapacity, "session context id unavailable");
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::install_verified(
    const ContextKeys& keys, const InstallAttestation& att) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  const Status shape = check_context_keys(keys);
  if (!shape) return shape;
  if (!map_network(keys.network)) {
    return Status::error(StatusCode::InvalidArgument, "session network mismatch");
  }
  if (keys.peer == local_.self) {
    return Status::error(StatusCode::InvalidArgument, "session self peer");
  }
  // The attested GK birthday must be usable NOW: from the future, or already
  // two epochs behind, is a dead install.
  const std::uint64_t created = att.created_gk_epoch;
  const std::uint64_t current = local_.gk_epoch;
  if (current < created || current >= created + 2U) {
    return Status::error(StatusCode::Conflict, "session gk lifetime");
  }
  if (install_serial_ == 0xFFFFFFFFU) {
    return Status::error(StatusCode::CounterExhausted, "session install serial exhausted");
  }
  const std::size_t capacity =
      keys.scope == SecurityScope::Link ? kLinkCapacity : kEndCapacity;
  if (capacity == 0) return Status::error(StatusCode::NoCapacity, "session table missing");

  SessionBankEntry* existing = find_current(keys.scope, keys.peer);
  if (existing != nullptr && existing->tx_cid == keys.tx_context_id &&
      existing->rx_cid == keys.rx_context_id && keys_equal(*existing, keys)) {
    // A repeated install of the same keys: keep the live counters, never
    // rewind them to 0.
    return Status::error(StatusCode::Conflict, "session install duplicate");
  }
  // The new RX id must be unambiguous everywhere else: live currents other
  // than the replaced one, and every overlap entry.
  for (std::size_t i = 0; i < kLinkCapacity; ++i) {
    if (link_used_[i] && &link_[i] != existing && link_[i].rx_cid == keys.rx_context_id) {
      return Status::error(StatusCode::Conflict, "session rx id collision");
    }
  }
  for (std::size_t i = 0; i < kEndCapacity; ++i) {
    if (end_used_[i] && &end_[i] != existing && end_[i].rx_cid == keys.rx_context_id) {
      return Status::error(StatusCode::Conflict, "session rx id collision");
    }
  }
  for (std::size_t i = 0; i < kOverlapCapacity; ++i) {
    if (overlap_used_[i] && overlap_[i].rx_cid == keys.rx_context_id) {
      return Status::error(StatusCode::Conflict, "session rx id collision");
    }
  }

  // Locate the slot before mutating anything: a full table refuses without
  // disturbing the live state.
  const std::size_t start = hash_start(keys.scope, keys.peer);
  constexpr std::size_t kNone = static_cast<std::size_t>(-1);
  std::size_t free_slot = kNone;
  for (std::size_t step = 0; step < capacity; ++step) {
    const std::size_t i = (start + step) % capacity;
    const bool used = keys.scope == SecurityScope::Link ? link_used_[i] : end_used_[i];
    if (!used && free_slot == kNone) free_slot = i;
  }
  if (existing == nullptr && free_slot == kNone) {
    return Status::error(StatusCode::NoCapacity, "session table full");
  }

  // Demote the replaced current to RX-only overlap (best effort: a full
  // overlap table drops the old key rather than blocking the new one).
  if (existing != nullptr) {
    for (std::size_t i = 0; i < kOverlapCapacity; ++i) {
      if (overlap_used_[i]) continue;
      overlap_[i].scope = keys.scope;
      overlap_[i].peer = existing->peer;
      overlap_[i].rx_key = existing->rx_key;
      overlap_[i].rx_iv = existing->rx_iv;
      overlap_[i].rx_max = existing->rx_max;
      overlap_[i].rx_bitmap = existing->rx_bitmap;
      overlap_[i].rx_cid = existing->rx_cid;
      overlap_[i].remaining_ms = existing->remaining_ms > kOverlapLifetimeMs
                                     ? kOverlapLifetimeMs
                                     : existing->remaining_ms;
      overlap_[i].install_serial = existing->install_serial;
      overlap_used_[i] = true;
      break;
    }
  }

  SessionBankEntry fresh{};
  fresh.peer = keys.peer;
  fresh.tx_key = keys.tx_key;
  fresh.rx_key = keys.rx_key;
  fresh.tx_iv = keys.tx_iv;
  fresh.rx_iv = keys.rx_iv;
  fresh.peer_cert_id = keys.peer_cert_id;
  fresh.tx_cid = keys.tx_context_id;
  fresh.rx_cid = keys.rx_context_id;
  fresh.peer_generation = keys.peer_generation;
  fresh.peer_role = att.peer_role;
  fresh.created_gk = att.created_gk_epoch;
  fresh.remaining_ms = kContextLifetimeMs;
  fresh.install_serial = ++install_serial_;
  if (existing != nullptr) {
    secure_clear(existing->tx_key);
    secure_clear(existing->rx_key);
    secure_clear(existing->tx_iv);
    secure_clear(existing->rx_iv);
    *existing = fresh;
    if (keys.scope == SecurityScope::EndToEnd) {
      for (std::size_t i = 0; i < kEndCapacity; ++i) {
        if (&end_[i] == existing) {
          end_lru_[i] = ++lru_clock_;
          break;
        }
      }
    }
  } else {
    if (keys.scope == SecurityScope::Link) {
      link_[free_slot] = fresh;
      link_used_[free_slot] = true;
    } else {
      end_[free_slot] = fresh;
      end_used_[free_slot] = true;
      end_lru_[free_slot] = ++lru_clock_;
    }
  }
  // A satisfied demand leaves with the install.
  for (auto& demand : demand_) {
    if (demand.used && demand.scope == keys.scope && demand.peer == keys.peer) demand.used = false;
  }
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::install(const ContextKeys& keys) noexcept {
  InstallAttestation att{};
  att.created_gk_epoch = local_.gk_epoch;
  return install_verified(keys, att);
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::retire(const SecurityScope scope,
                                                        const NodeId peer) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (!unicast_scope(scope)) return Status::error(StatusCode::Unsupported, "session scope");
  SessionBankEntry* existing = find_current(scope, peer);
  if (existing != nullptr) {
    bool* used = nullptr;
    if (scope == SecurityScope::Link) {
      for (std::size_t i = 0; i < kLinkCapacity; ++i) {
        if (&link_[i] == existing) {
          used = &link_used_[i];
          break;
        }
      }
    } else {
      for (std::size_t i = 0; i < kEndCapacity; ++i) {
        if (&end_[i] == existing) {
          used = &end_used_[i];
          break;
        }
      }
    }
    if (used != nullptr) wipe_entry(*existing, *used);
  }
  for (std::size_t i = 0; i < kOverlapCapacity; ++i) {
    if (overlap_used_[i] && overlap_[i].scope == scope && overlap_[i].peer == peer) {
      wipe_overlap(overlap_[i], overlap_used_[i]);
    }
  }
  for (auto& demand : demand_) {
    if (demand.used && demand.scope == scope && demand.peer == peer) demand.used = false;
  }
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::retire_all(const NodeId peer) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  const Status link = retire(SecurityScope::Link, peer);
  if (!link) return link;
  return retire(SecurityScope::EndToEnd, peer);
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::evict_idle_end(NodeId& evicted) noexcept {
  evicted = kInvalidNodeId;
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  constexpr std::size_t kNone = static_cast<std::size_t>(-1);
  std::size_t victim = kNone;
  for (std::size_t i = 0; i < kEndCapacity; ++i) {
    if (!end_used_[i]) continue;
    if ((end_[i].flags & (kFlagSealReserved | kFlagPinned)) != 0) continue;
    if (victim == kNone || end_lru_[i] < end_lru_[victim]) victim = i;
  }
  if (victim == kNone) return Status::error(StatusCode::NotFound, "no idle end context");
  evicted = end_[victim].peer;
  return retire(SecurityScope::EndToEnd, evicted);
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::set_pinned(const SecurityScope scope,
                                                            const NodeId peer,
                                                            const bool pinned) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  SessionBankEntry* entry = find_current(scope, peer);
  if (entry == nullptr) return Status::error(StatusCode::NotFound, "session not found");
  if (pinned) {
    entry->flags |= kFlagPinned;
  } else {
    entry->flags &= ~kFlagPinned;
  }
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::take_demand(SessionDemand& out) noexcept {
  out = SessionDemand{};
  if (reentered() || !configured_) return false;
  for (auto& demand : demand_) {
    if (!demand.used) continue;
    demand.used = false;
    out.scope = demand.scope;
    out.peer = demand.peer;
    const std::uint64_t deadline = last_tick_ + demand.hold_ms;
    out.deadline_ms = deadline < last_tick_ ? 0xFFFFFFFFFFFFFFFFULL : deadline;
    return true;
  }
  return false;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::demand_pending(
    const SecurityScope scope, const NodeId peer) const noexcept {
  for (const auto& demand : demand_) {
    if (demand.used && demand.scope == scope && demand.peer == peer) return true;
  }
  return false;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::tx_epoch(SecurityScope scope, NodeId peer,
                                                          std::uint32_t& epoch) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (!unicast_scope(scope)) {
    return Status::error(StatusCode::Unsupported, "session scope");
  }
  if (!id_valid(peer)) return Status::error(StatusCode::InvalidArgument, "session peer invalid");
  const SessionBankEntry* entry = find_current(scope, peer);
  if (entry != nullptr && entry_usable(*entry) &&
      check_tx_counter(entry->tx_next) != TxCounterVerdict::Refuse) {
    epoch = entry->tx_cid;
    return Status::success();
  }
  // No usable context: idempotently note the demand and refuse WITHOUT
  // spending a counter. The node holds the frame against its deadline.
  record_demand(scope, peer);
  return Status::error(StatusCode::AuthRequired, "session establishment required");
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
ContextState SessionBank<kLinkCapacity, kEndCapacity>::context_state(
    const SecurityScope scope, const NodeId peer) const noexcept {
  if (!configured_) return ContextState::None;
  const SessionBankEntry* entry = find_current(scope, peer);
  if (entry != nullptr && entry_usable(*entry) &&
      check_tx_counter(entry->tx_next) != TxCounterVerdict::Refuse) {
    if ((entry->flags & kFlagRekeyPending) != 0 ||
        check_tx_counter(entry->tx_next) == TxCounterVerdict::IssueRekeyDue) {
      return ContextState::Rekeying;
    }
    return ContextState::Ready;
  }
  // Past the hard counter limit the old key stays silent even though its
  // bytes are still present: usable() alone must never answer Ready.
  if (demand_pending(scope, peer)) return ContextState::Establishing;
  return ContextState::None;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::next_counter(const SecurityContext& context,
                                                              std::uint64_t& counter) noexcept {
  counter = 0;
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (!unicast_scope(context.scope)) {
    return Status::error(StatusCode::Unsupported, "session scope");
  }
  if (!map_network(context.network) || context.sender != local_.self ||
      !id_valid(context.receiver)) {
    return Status::error(StatusCode::InvalidArgument, "session direction invalid");
  }
  SessionBankEntry* entry = find_current(context.scope, context.receiver);
  if (entry == nullptr || !entry_usable(*entry) ||
      check_tx_counter(entry->tx_next) == TxCounterVerdict::Refuse) {
    record_demand(context.scope, context.receiver);
    return Status::error(StatusCode::AuthRequired, "session establishment required");
  }
  if (entry->tx_next > kMaxCryptoCounter) {
    return Status::error(StatusCode::CounterExhausted, "session counter exhausted");
  }
  // Consumed here, whatever seal() says later: a counter is never re-issued
  // under the same key.
  counter = entry->tx_next++;
  if (check_tx_counter(counter) == TxCounterVerdict::IssueRekeyDue) {
    entry->flags |= kFlagRekeyPending;
  }
  entry->flags |= kFlagSealReserved;
  if (context.scope == SecurityScope::EndToEnd) {
    for (std::size_t i = 0; i < kEndCapacity; ++i) {
      if (&end_[i] == entry) {
        end_lru_[i] = ++lru_clock_;
        break;
      }
    }
  }
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::seal(
    const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
    const ByteView plaintext, const MutableByteView ciphertext,
    std::array<std::uint8_t, kAeadTagSize>& tag) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (!unicast_scope(context.scope)) {
    return Status::error(StatusCode::Unsupported, "session scope");
  }
  if (plaintext.data == nullptr || ciphertext.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "session null buffer");
  }
  if (!map_network(context.network) || context.sender != local_.self ||
      !id_valid(context.receiver)) {
    return Status::error(StatusCode::InvalidArgument, "session direction invalid");
  }
  SessionBankEntry* entry = find_current(context.scope, context.receiver);
  if (entry == nullptr || !entry_usable(*entry)) {
    return Status::error(StatusCode::AuthRequired, "session establishment required");
  }
  // Exactly the outstanding reservation seals: the epoch the node stamped,
  // the counter just drawn, and a live reservation — no double seal, no
  // counter reuse under another AAD.
  if (context.epoch != entry->tx_cid || counter != entry->tx_next - 1 ||
      (entry->flags & kFlagSealReserved) == 0) {
    return Status::error(StatusCode::InvalidArgument, "session seal without reservation");
  }
  if (ciphertext.size < plaintext.size) {
    return Status::error(StatusCode::NoCapacity, "session ciphertext short");
  }
  keys::AeadNonce nonce{};
  const Status nonce_status = keys::aead_nonce(entry->tx_iv, counter, nonce);
  if (!nonce_status) return nonce_status;
  // Consumed before the crypto callback: a port failure still retires the
  // reservation (a fresh counter starts over).
  entry->flags &= ~kFlagSealReserved;
  in_port_ = true;
  const bool sealed = aead_.seal(aead_.ctx, entry->tx_key.data(), nonce.data(), aad, plaintext,
                                 ciphertext.data, tag.data());
  in_port_ = false;
  if (!sealed) return Status::error(StatusCode::InternalError, "session aead seal failed");
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
Status SessionBank<kLinkCapacity, kEndCapacity>::open(
    const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
    const ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
    const MutableByteView plaintext) noexcept {
  if (reentered()) return Status::error(StatusCode::Busy, "session bank re-entered");
  if (!configured_) return Status::error(StatusCode::InvalidState, "session bank not configured");
  if (!unicast_scope(context.scope)) {
    return Status::error(StatusCode::Unsupported, "session scope");
  }
  if (ciphertext.data == nullptr || plaintext.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "session null buffer");
  }
  if (!map_network(context.network) || context.receiver != local_.self ||
      !id_valid(context.sender)) {
    return Status::error(StatusCode::InvalidArgument, "session direction invalid");
  }
  // The RX key is selected by (scope, sender, stamped id): current first,
  // then the RX-only overlap. An unknown id refuses WITHOUT recording
  // demand — stranger RF never starts a handshake by itself.
  const SessionBankEntry* current = find_current(context.scope, context.sender);
  const std::array<std::uint8_t, kSessionKeySize>* rx_key = nullptr;
  const std::array<std::uint8_t, kSessionIvSize>* rx_iv = nullptr;
  std::uint64_t rx_max = 0;
  std::uint64_t rx_bitmap = 0;
  bool from_overlap = false;
  std::size_t overlap_index = 0;
  if (current != nullptr && current->rx_cid == context.epoch && entry_usable(*current)) {
    rx_key = &current->rx_key;
    rx_iv = &current->rx_iv;
    rx_max = current->rx_max;
    rx_bitmap = current->rx_bitmap;
  } else {
    for (std::size_t i = 0; i < kOverlapCapacity; ++i) {
      if (!overlap_used_[i] || overlap_[i].scope != context.scope ||
          overlap_[i].peer != context.sender || overlap_[i].rx_cid != context.epoch ||
          overlap_[i].remaining_ms == 0) {
        continue;
      }
      rx_key = &overlap_[i].rx_key;
      rx_iv = &overlap_[i].rx_iv;
      rx_max = overlap_[i].rx_max;
      rx_bitmap = overlap_[i].rx_bitmap;
      from_overlap = true;
      overlap_index = i;
      break;
    }
  }
  if (rx_key == nullptr || rx_iv == nullptr) {
    return Status::error(StatusCode::AuthRequired, "session unknown context");
  }
  // A live peer never emits past the use budget: beyond it lies only forgery.
  if (!rx_counter_admissible(counter)) {
    return Status::error(StatusCode::AuthenticationFailed, "session counter forged");
  }
  if (plaintext.size < ciphertext.size) {
    return Status::error(StatusCode::NoCapacity, "session plaintext short");
  }
  if (ciphertext.size > staging_.size()) {
    return Status::error(StatusCode::NoCapacity, "session frame oversized");
  }
  if (counter <= rx_max) {
    const std::uint64_t distance = rx_max - counter;
    if (distance >= 64 || ((rx_bitmap >> distance) & 1U) != 0U) {
      return Status::error(StatusCode::ReplayRejected, "session replay");
    }
  }
  keys::AeadNonce nonce{};
  const Status nonce_status = keys::aead_nonce(*rx_iv, counter, nonce);
  if (!nonce_status) return nonce_status;
  // Verify into staging first: a failed open updates no window, no LRU, no
  // membership — and exposes no plaintext.
  in_port_ = true;
  const bool opened = aead_.open(aead_.ctx, rx_key->data(), nonce.data(), aad, ciphertext,
                                 tag.data(), staging_.data());
  in_port_ = false;
  if (!opened) {
    secure_clear(staging_);
    return Status::error(StatusCode::AuthenticationFailed, "session tag mismatch");
  }
  if (counter > rx_max) {
    const std::uint64_t shift = counter - rx_max;
    rx_bitmap = shift >= 64 ? 1U : (rx_bitmap << shift) | 1U;
    rx_max = counter;
  } else {
    rx_bitmap |= std::uint64_t{1} << (rx_max - counter);
  }
  if (from_overlap) {
    overlap_[overlap_index].rx_max = rx_max;
    overlap_[overlap_index].rx_bitmap = rx_bitmap;
  } else {
    SessionBankEntry* live = find_current(context.scope, context.sender);
    if (live == nullptr || live->rx_cid != context.epoch) {
      // The port cannot mutate the bank (Busy), so this is unreachable —
      // but a window update to the wrong entry would be fatal, so check.
      secure_clear(staging_);
      return Status::error(StatusCode::InternalError, "session context moved");
    }
    live->rx_max = rx_max;
    live->rx_bitmap = rx_bitmap;
  }
  std::memcpy(plaintext.data, staging_.data(), ciphertext.size);
  secure_clear(staging_);
  return Status::success();
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
std::size_t SessionBank<kLinkCapacity, kEndCapacity>::live_count(
    const SecurityScope scope) const noexcept {
  std::size_t count = 0;
  if (scope == SecurityScope::Link) {
    for (const bool used : link_used_) count += used ? 1 : 0;
  } else if (scope == SecurityScope::EndToEnd) {
    for (const bool used : end_used_) count += used ? 1 : 0;
  }
  return count;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::has_usable(const SecurityScope scope,
                                                          const NodeId peer) const noexcept {
  if (!configured_) return false;
  const SessionBankEntry* entry = find_current(scope, peer);
  return entry != nullptr && entry_usable(*entry) &&
         check_tx_counter(entry->tx_next) != TxCounterVerdict::Refuse;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
bool SessionBank<kLinkCapacity, kEndCapacity>::peer_summary(const SecurityScope scope,
                                                            const NodeId peer,
                                                            std::uint32_t& generation,
                                                            std::uint32_t& role) const noexcept {
  generation = 0;
  role = 0;
  if (!configured_) return false;
  const SessionBankEntry* entry = find_current(scope, peer);
  if (entry == nullptr || !entry_usable(*entry)) return false;
  if (entry->peer_generation == 0 || entry->peer_role == 0) return false;
  generation = entry->peer_generation;
  role = entry->peer_role;
  return true;
}

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
std::size_t SessionBank<kLinkCapacity, kEndCapacity>::demand_count() const noexcept {
  std::size_t count = 0;
  for (const auto& demand : demand_) count += demand.used ? 1 : 0;
  return count;
}

template class SessionBank<32, 8>;
template class SessionBank<32, 128>;

}  // namespace routeloom::sdkv1
