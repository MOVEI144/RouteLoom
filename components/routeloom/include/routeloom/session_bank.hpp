#pragma once

// RAM session bank and provider (G-SEC P4 design §4): the production unicast
// session owner for Link and EndToEnd scopes. Current contexts, the 8-entry
// old-RX overlap, the 8-entry establishment demand table, counters, replay
// windows and lifetimes live here; NOTHING persists (a reboot loses every
// key and window together, so a captured frame is never re-accepted, V1-K04).
//
// Cryptography arrives through the narrow `AeadGcm` port (AES-GCM-128,
// key16/nonce12/tag16): the ESP-IDF adapter backs it, host tests use an
// OpenSSL EVP adapter — never a hand-rolled primitive. The bank never calls
// Session/transport/store code; the handshake engine installs through
// install_verified() and the Owner drains take_demand().
//
// Re-entry: every mutating entry refuses with Busy (changing nothing) while
// a call is inside the AEAD port. Side-effect-free queries stay readable.
// No heap, no exceptions; all tables are fixed (P4-C01).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/key_schedule.hpp"  // aead_nonce
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- AEAD port ---------------------------------------------------------------
// seal writes exactly plaintext.size bytes plus the 16-byte tag; open takes
// the ciphertext and tag separately and returns false unless the tag
// verified. On failure the bank's staging (never the caller's buffer) holds
// whatever the port wrote, so a failed open leaks no plaintext.
struct AeadGcm {
  bool (*seal)(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
               ByteView aad, ByteView plaintext, std::uint8_t* out_ciphertext,
               std::uint8_t out_tag[16]) noexcept{nullptr};
  bool (*open)(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
               ByteView aad, ByteView ciphertext, const std::uint8_t tag[16],
               std::uint8_t* out_plaintext) noexcept{nullptr};
  void* ctx{nullptr};
};

using SessionRandomFn = bool (*)(void* ctx, std::uint8_t* out, std::size_t size) noexcept;

// Verified peer summary the handshake engine attests next to ContextKeys.
// The public SessionInstaller::install() cannot mint one: it installs with
// role 0 (unknown), which refuses relay duties but allows unicast.
struct InstallAttestation {
  std::uint32_t peer_role{0};
  std::uint32_t created_gk_epoch{0};
};

struct SessionDemand {
  SecurityScope scope{SecurityScope::Link};
  NodeId peer{kInvalidNodeId};
  // Hold the NO-key refusal pending (node-bounded by the frame deadline).
  MonotonicMs deadline_ms{0};
};

// One installed unicast context. The natural-alignment layout below is 128 B
// and a compile gate pins it (P4 §4.1): network/self/local generation stay
// bank-global (a site change wipes the bank), RMS/certificates never enter.
struct SessionBankEntry {
  NodeId peer{kInvalidNodeId};
  std::uint64_t tx_next{0};
  std::uint64_t rx_max{0};
  std::uint64_t rx_bitmap{0};
  std::array<std::uint8_t, kSessionKeySize> tx_key{};
  std::array<std::uint8_t, kSessionKeySize> rx_key{};
  std::array<std::uint8_t, kSessionIvSize> tx_iv{};
  std::array<std::uint8_t, kSessionIvSize> rx_iv{};
  std::array<std::uint8_t, 8> peer_cert_id{};
  std::uint32_t tx_cid{0};
  std::uint32_t rx_cid{0};
  std::uint32_t peer_generation{0};
  std::uint32_t peer_role{0};
  std::uint32_t created_gk{0};
  std::uint32_t remaining_ms{0};
  std::uint32_t install_serial{0};
  std::uint32_t flags{0};
};
static_assert(sizeof(SessionBankEntry) == 128, "P4 §4.1: current entry <= 128 B");

// Superseded RX-only context: the duplicate tolerance is a maximum, not a
// guarantee — when the 8 overlap slots are full the old key is dropped and
// the new key takes over immediately.
struct SessionOverlapEntry {
  SecurityScope scope{SecurityScope::Link};
  NodeId peer{kInvalidNodeId};
  std::array<std::uint8_t, kSessionKeySize> rx_key{};
  std::array<std::uint8_t, kSessionIvSize> rx_iv{};
  std::uint64_t rx_max{0};
  std::uint64_t rx_bitmap{0};
  std::uint32_t rx_cid{0};
  std::uint32_t remaining_ms{0};
  std::uint32_t install_serial{0};
};
static_assert(sizeof(SessionOverlapEntry) <= 88, "P4 §4.1: old-RX entry <= 88 B");

template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
class SessionBank {
 public:
  static constexpr std::size_t kOverlapCapacity = 8;
  static constexpr std::size_t kDemandCapacity = 8;
  // Use budget (P4 §4.2): the u48 span is the codec ceiling, never the
  // budget. Rekey is due at 2^32-1024; TX stops at 2^32 and never wraps.
  static constexpr std::uint64_t kRekeySoftCounter = (std::uint64_t{1} << 32) - 1024;
  static constexpr std::uint64_t kMaxUseCounter = std::uint64_t{1} << 32;
  static constexpr std::uint32_t kContextLifetimeMs = 24U * 3600U * 1000U;
  static constexpr std::uint32_t kOverlapLifetimeMs = 60U * 1000U;
  static constexpr std::size_t kStagingBytes = kMaxEspNowBody;  // 250
  static constexpr std::size_t kCidRetries = 8;

  // The frozen TX use-budget rule (P4 §4.2), as a pure function so the
  // 2^32 boundary is testable without issuing four billion counters:
  // below the soft mark counters issue, from the soft mark the rekey flag
  // rides along, at the hard mark TX stops and never wraps.
  enum class TxCounterVerdict : std::uint8_t { Issue = 0, IssueRekeyDue = 1, Refuse = 2 };
  static constexpr TxCounterVerdict check_tx_counter(const std::uint64_t tx_next) noexcept {
    if (tx_next < kRekeySoftCounter) return TxCounterVerdict::Issue;
    if (tx_next < kMaxUseCounter) return TxCounterVerdict::IssueRekeyDue;
    return TxCounterVerdict::Refuse;
  }
  // RX admits exactly what a live peer may emit; the u48 span stays the
  // codec ceiling, never the budget.
  static constexpr bool rx_counter_admissible(const std::uint64_t counter) noexcept {
    return counter < kMaxUseCounter;
  }

  struct LocalView {
    NodeId self{kInvalidNodeId};
    NetworkId network{0};  // full64 from the adopted RLS1
    std::uint32_t gk_epoch{0};
    std::uint32_t demand_hold_ms{8000};
  };

  struct RandomSource {
    SessionRandomFn fn{nullptr};
    void* ctx{nullptr};
  };

  SessionBank() noexcept = default;
  SessionBank(const SessionBank&) = delete;
  SessionBank& operator=(const SessionBank&) = delete;
  ~SessionBank() { wipe_all(); }

  // Binds identity, AEAD and entropy; draws the device-local slot salt
  // (P4 §4.3: never derived from a shared PSK). Fails without wiping prior
  // state when the view is invalid or entropy is not READY.
  Status configure(const LocalView& local, const AeadGcm& aead, const RandomSource& random,
                   MonotonicMs now) noexcept;
  bool configured() const noexcept { return configured_; }

  // The Owner calls this before every operation batch: subtracts elapsed
  // time from all lifetimes (saturating; entries at 0 are wiped), drops
  // expired demands. A backwards `now` is refused and changes nothing.
  Status tick(MonotonicMs now) noexcept;

  // Current GK epoch (monotonic; a decrease is a site change and must go
  // through reset_membership, never a quiet accept).
  Status set_gk_epoch(std::uint32_t gk_epoch) noexcept;
  // Site/network change: wipes every key, window, demand and reservation.
  Status reset_membership(const LocalView& local, MonotonicMs now) noexcept;

  // Atomic full replacement of the (scope, peer) context: the new context
  // becomes current-TX with counters at 0, the previous current (if any)
  // demotes to RX-only overlap. Re-checks scope/network/peer/cids, refuses
  // an rx id already live elsewhere (Conflict), a full table (NoCapacity —
  // the link table never evicts; end eviction is the explicit
  // evict_idle_end below) and a repeated install of the same keys
  // (Conflict, counters untouched).
  Status install_verified(const ContextKeys& keys, const InstallAttestation& att) noexcept;
  // SessionInstaller path: installs with role 0 (unknown). Relay duties
  // stay refused until a handshake attests the real role.
  Status install(const ContextKeys& keys) noexcept;
  Status retire(SecurityScope scope, NodeId peer) noexcept;
  Status retire_all(NodeId peer) noexcept;
  // Drops the oldest idle (no live seal reservation), unpinned end context
  // and reports it; NotFound when everything is busy or pinned.
  Status evict_idle_end(NodeId& evicted) noexcept;
  Status set_pinned(SecurityScope scope, NodeId peer, bool pinned) noexcept;

  // Establishment demand for the Owner: idempotent per (scope, peer).
  bool take_demand(SessionDemand& out) noexcept;
  bool demand_pending(SecurityScope scope, NodeId peer) const noexcept;
  // Re-records a demand the Owner popped but could not act on yet (the
  // demand driver's push-back when its link staging is full). Same
  // idempotent path tx_epoch uses; a full table keeps refusing until the
  // application retries. Refuses on an unconfigured bank like tx_epoch.
  void note_demand(SecurityScope scope, NodeId peer) noexcept {
    if (reentered() || !configured_) return;
    if (scope != SecurityScope::Link && scope != SecurityScope::EndToEnd) return;
    if (peer == kInvalidNodeId || peer == kBroadcastNodeId) return;
    record_demand(scope, peer);
  }

  // A nonzero RX id unique across live/overlap contexts (the handshake
  // engine additionally keeps its in-flight ids out); 8 draws max.
  Status allocate_context_id(std::uint32_t& out) noexcept;
  bool context_id_live(std::uint32_t id) const noexcept;

  // SecurityProvider surface (delegated by RamSessionProvider): tx_epoch
  // writes the tx context id or records demand and refuses AuthRequired
  // (never spending a counter); unknown RX ids refuse AuthRequired and
  // never start a handshake by themselves.
  Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept;
  ContextState context_state(SecurityScope scope, NodeId peer) const noexcept;
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept;
  Status seal(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept;
  Status open(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept;

  // Inspection for the Owner/tests (side-effect-free, guard-transparent).
  std::size_t live_count(SecurityScope scope) const noexcept;
  bool has_usable(SecurityScope scope, NodeId peer) const noexcept;
  std::size_t demand_count() const noexcept;

 private:
  struct DemandEntry {
    NodeId peer{kInvalidNodeId};
    std::uint32_t hold_ms{0};
    SecurityScope scope{SecurityScope::Link};
    bool used{false};
  };
  static_assert(sizeof(DemandEntry) <= 16, "P4 §4.1: demand entry <= 16 B");

  static constexpr std::uint32_t kFlagSealReserved = 0x01;
  static constexpr std::uint32_t kFlagRekeyPending = 0x02;
  static constexpr std::uint32_t kFlagPinned = 0x04;

  bool reentered() const noexcept { return in_port_; }
  // P4 §8.1: the wire carries low32 only, so the provider entry maps a
  // low32 context network onto the adopted full64 — and nothing else.
  bool map_network(NetworkId context_network) const noexcept;
  bool entry_usable(const SessionBankEntry& entry) const noexcept;
  SessionBankEntry* find_current(SecurityScope scope, NodeId peer) noexcept;
  const SessionBankEntry* find_current(SecurityScope scope, NodeId peer) const noexcept;
  std::size_t hash_start(SecurityScope scope, NodeId peer) const noexcept;
  // Idempotent per (scope, peer): re-record refreshes the hold, a full
  // table keeps the old entries (the node's frame deadline bounds the hold).
  void record_demand(SecurityScope scope, NodeId peer) noexcept;
  void wipe_entry(SessionBankEntry& entry, bool& used) noexcept;
  void wipe_overlap(SessionOverlapEntry& entry, bool& used) noexcept;
  void wipe_all() noexcept;

  LocalView local_{};
  AeadGcm aead_{};
  RandomSource random_{};
  std::array<std::uint8_t, 32> slot_salt_{};
  bool slot_salt_ready_{false};
  bool configured_{false};
  MonotonicMs last_tick_{0};
  std::uint32_t install_serial_{0};
  std::uint32_t lru_clock_{0};
  mutable bool in_port_{false};

  std::array<SessionBankEntry, kLinkCapacity> link_{};
  std::array<bool, kLinkCapacity> link_used_{};
  std::array<SessionBankEntry, kEndCapacity> end_{};
  std::array<bool, kEndCapacity> end_used_{};
  std::array<std::uint32_t, kEndCapacity> end_lru_{};
  std::array<SessionOverlapEntry, kOverlapCapacity> overlap_{};
  std::array<bool, kOverlapCapacity> overlap_used_{};
  std::array<DemandEntry, kDemandCapacity> demand_{};
  std::array<std::uint8_t, kStagingBytes> staging_{};
};

using NodeSessionBank = SessionBank<32, 8>;
using GatewaySessionBank = SessionBank<32, 128>;

// The provider view over a bank: tx_epoch/context_state/next_counter/
// seal/open plus SessionInstaller, for the node and the handshake engine.
// ready() is the bank's configured state; the profile stays Development
// until the P8 qualification gate (never claimed by omission).
template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
class RamSessionProvider final : public SecurityProvider, public SessionInstaller {
 public:
  explicit RamSessionProvider(SessionBank<kLinkCapacity, kEndCapacity>& bank) noexcept
      : bank_(bank) {}

  bool ready() const noexcept override { return bank_.configured(); }
  Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept override {
    return bank_.tx_epoch(scope, peer, epoch);
  }
  ContextState context_state(SecurityScope scope, NodeId peer) const noexcept override {
    return bank_.context_state(scope, peer);
  }
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override {
    return bank_.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    return bank_.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override {
    return bank_.open(context, counter, aad, ciphertext, tag, plaintext);
  }
  Status install(const ContextKeys& keys) noexcept override { return bank_.install(keys); }
  Status retire(SecurityScope scope, NodeId peer) noexcept override {
    return bank_.retire(scope, peer);
  }
  Status retire_all(NodeId peer) noexcept override { return bank_.retire_all(peer); }

 private:
  SessionBank<kLinkCapacity, kEndCapacity>& bank_;
};

}  // namespace routeloom::sdkv1
