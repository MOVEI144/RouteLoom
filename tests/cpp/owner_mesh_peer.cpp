// Multi-node mesh peer (D04, issue #168): one process runs ONE real
// firmware node — EspNowSecurityOwner + EspNowRuntime + MeshNode over the
// host ESP-IDF stubs, NVS-backed Sdkv1Stores over a fake NVS, and (on a
// gateway) the real UsbBridge. The Rust harness
// (host/routeloom-host/src/site/owner_mesh/) spawns one peer
// per node, switches radio frames between them, and relays the gateway's
// USB bytes to the real Site Authority. No mock ACKs: every lifecycle,
// GK and cutover receipt the harness observes comes out of this Owner.
//
// Boot is the firmware's own path: routeloom::Device::open_storage (rlboot
// witness, rlsec stores, boot-session reconcile) and Device::begin (owner,
// runtime, entropy, attach_runtime/attach_usb, owner.boot, authority sink),
// then Device::step per tick (bridge.poll, runtime.poll_once, owner.poll).
// Only the ESP platform shell (flash layout, board-config gate, USB driver,
// Owner task) stays in device_esp.cpp. Radio frames leave through the
// stub's esp_now_send capture and re-enter through inject_rx; USB bytes
// cross the pipe raw.
//
// Framing: u16le length (1..65535) + payload over stdin/stdout; stderr
// is diagnostics only and never carries key material. First payload byte
// is the tag. Rust -> C++:
//
//   T <now u64le>              advance virtual time, run one pump turn,
//                              report X/B/G/D (see below)
//   R <src_mac 6><dst_mac 6><frame>
//                              inject one radio RX frame now (the observed
//                              destination: broadcast for broadcasts —
//                              the member-scope rule drops anything else)
//   U <usb bytes>              USB RX bytes now (gateway only)
//   K <results...>             complete outstanding esp_now_send calls in
//                              FIFO order (1 = success, 0 = fail); the
//                              harness decides per frame from its switch
//                              (unicast succeeds iff delivered)
//   S <dst u64le><payload>      app-level MeshNode send (reliable, 30 s
//                              lifetime); at most 16 tracked at once
//   V <index u8>               register one synthetic regular neighbor through
//                              the real runtime; reply v <ok u8><peers u8>
//   I <index u8> / J <index u8> occupy/release one test driver transient;
//                              reply i/j <ok u8><peers u8>
//   E <fail u8>                inject driver peer deletion failure (no reply)
//   H <count u8><dst u64le>    untracked application burst through the
//                              real runtime; reply h <accepted u8><queued u8>
//   h <count u8><dst u64le>    tracked burst; reply h <accepted u8><queued u8>
//                              <count u8> then status u8, session u32, seq u64
//   N                          dump the fake-NVS image (reply: N <image>)
//   r                          drain up to 64 application receipts; reply
//                              r <overflow u32><count u8> then source u64,
//                              session u32, seq u64, len u8, payload
//   P                          power-cycle: persist the NVS image and take
//                              the reboot marker (exit 42), like a field
//                              power cut mid-RAM — the respawn recovers
//                              through the production boot path only
//   F                          arm one power cut after RLX1 Switching commits
//                              (exit 43); the saved NVS is the real write
//   Z <gateway u64><payload>   explicit gateway send (Service=21, SDK_RAM
//                              scope): resolve `gateway` through
//                              Device::gateway(), then send once Ready;
//                              the snapshot tail reports both outcomes
//   Q                          quit (exit 0)
//   O <next_hop u64le><dst u64le><type u8><minor u8><traffic u8><payload>
//                              seal one end-protected frame of any type
//                              (P04: extension types, newer minors) with
//                              this node's live sessions, as if routed to
//                              next_hop; reply o <encoded frame> (the
//                              harness injects it at next_hop, nothing is
//                              transmitted here)
//   M <group u16le><payload>   application group send (Normal, 5 s)
//   W <mode u8><key>           arm one fault at the next write of `key`:
//                              0 fails it, 1 cuts power before it lands,
//                              2 cuts power after its commit (exit 43),
//                              3 as 2 on the key's second write
//   L                          Device::leave; reply l <status u8><op u32>
//                              (tracked sends cancelled by it are
//                              refreshed before the reply)
//   Y                          Device::request_join; reply y <status u8><op u32>
//   A <dst u64><class u8><key u16le><payload>
//                              tracked send with a delivery class and a
//                              coalesce key (the longest lifetime)
//   C                          reply c <this node's APPLIED lease 16>
//   B <dst u64><lease 16><payload>
//                              tracked APPLIED send (10 s lifetime)
//   D <delay_ms u32le>         defer every APPLIED request and complete it
//                              (Success) `delay_ms` after it arrived
//   G <on u8>                  from inside Device callbacks, try send and
//                              leave and count the Busy answers (F05)
//   X <holdoff_s u32le><expected u32le>[<isolation_notice_s u32le>]
//                              Device::set_join_policy with that removal
//                              holdoff (and isolation notice); reply
//                              x <status u8><revision u32>
//
// C++ -> Rust, emitted after each T in this order:
//
//   X <dst_mac 6><frame>       one captured radio TX frame, FIFO
//   B <usb bytes>              USB TX bytes (chunked to the frame bound)
//   G <snapshot>               bounded state snapshot (see emit_snapshot)
//   D                          end of the TICK response
//   N <image>                  fake-NVS image (power-cut handover; also
//                              written to --nvs-save on esp_restart)
//   E <text>                   fatal error; the peer exits nonzero after it
//
// G snapshot (all le): coord_mode u8 | membership u8 |
// authority_started u8 | authority_ready u8 | join_confirmed u8 |
// link_sessions u32 | end_sessions u32 | lifecycle_phase u8 |
// stores_healthy u8 | adopted_network u64 | own_generation u32 |
// applied_rs u32 | applied_gk u32 | holdoff_remaining_ms u64 |
// gk_current u32 | gk_next u32 | has_identity u8 | has_site u8 |
// site_generation u32 | usb_state u8 (0xFF without a bridge) |
// channel u8 | committed_channel u8 | tx_overruns u32 | send_count u32 |
// journal_kind u8 | journal_epoch u32 | journal_detail u32 |
// rrs_applied u32 | recoveries u32 | app_rx_count u32 | app_rx_src u64 |
// app_rx_len u8 | app_rx[0..96] | app_tx_count u8 |
// (seq u64 | state u8 | reason[0..12])* | demux_drops u32 |
// link_established u32 | link_failed u32 | link_last_error u8 |
// link_requests u32 | link_send_failures u32 |
// end_established u32 | end_failed u32 | end_last_error u8 |
// has_discovery u8 | discovers_rx u32 | offers_tx u32 | offers_rx u32 |
// proves_rx u32 | auths_completed u32 | kind_rejects u32 |
// cookie_rejects u32 | auth_tag_rejects u32 | send_failures u32 |
// scope_raw_rx u32 | scope_hint_mismatch u32 | scope_mac_rejected u32 |
// scope_unknown_generation u32 | scope_accepted u32 |
// scope_key_unavailable u32 | scope_budget_dropped u32 |
// id_fp u64 (first 8 bytes of the RLI1 kid, 0 without an identity —
// the nonsecret fingerprint a revoke must leave untouched) |
// join_state u8 | join_error u8 | proxy_disc_rx u32 |
// proxy_offers_tx u32 | proxy_suppressed u32 | proxy_relays_started u32 |
// proxy_relays_completed u32 (the ZT legs a recovery must cross) |
// auth_rx u64 | auth_tx u64 (verified authority RX / TX carriers —
// the quiet-channel evidence a present-check probe samples) |
// strikes u8 (refresh strikes — the recovery evidence ladder) |
// j_attempts u32 | j_m1 u32 | j_dropped u32 (the joiner's attempt/M1/
// dropped-offer counters — the ZT attempt evidence) |
// notice_down_live u8 | unknown_peer_rx u32 |
// proxy_frames_rejected u32 | proxy_cookie_rejects u32
// | probes_tx u32 | peer_capacity u32 | stale_expirations u32 |
// repair_demands u32 | neighbor_count u8 | world_nodes u8 |
// phase[0..world_nodes] u8*world_nodes |
// transit_conflicts u32 | receipt_conflicts u32 | no_route u32 |
// stale_tx_results u32
// | driver_peers u8
// | queued u8 | admissions_rejected u32
// | member_starts u32 | link_request_failures u32
// | owner_polls u32 | owner_empty_polls u32 | rx_queue_max u32 |
// expiry_slots_scanned u64 | hop_accept_expired u64
// | ext_unsupported u32 (EXTENSION_UNSUPPORTED refusals) |
// group_delivered u32 | group_rejected u32 | key_fault_hits u32
// | gw_endpoint u8 | gw_send u8 | gw_reason u8 (the Z send: endpoint
// state, send state, Service reason; 0 before any) | gw_receipts u32 |
// gw_sdk_ram_receipts u32 | gw_mailbox_stored u32 | gw_resolves_failed u32
// (this node's GatewayDelivery counters, 0 without one)
// | plan_phase u8 (ParticipantPhase, 0xFF without a channel plan) |
// plan_epoch u32 | plan_channel u8 (the participant's active record)
// | stage u8 | membership_events u32 | last_cause u16 | op_last u32 |
// op_result u16 | connectivity u8 | connectivity_events u32 |
// connectivity_reason u16 | reentry_calls u32 | reentry_busy u32 |
// applied_requests u32 | applied_completed u32 | applied_refused u32 |
// policy_revision u32 (the Device events and ops count across restarts)
// | c_checks u32 | c_check_failures u32 | c_posted_runs u32 |
// c_messages u32 (the --c-app application; 0 without it)
//
// Setup arrives on argv (all integers accept 0x hex; blobs are hex):
//
//   --node <u64> --mac <12hex> --role <u8> --t0 <ms> --seed <u64>
//   --join-cap <u8>    override the joiner's role capability (negative tests)
//   --world-nodes <2..32>  nodes in the scenario snapshot (default 3)
//   --gateway | --member
//   --devram             adopt the shared development session profile
//   --usb-secret <hex>   (gateway: the USB dev secret, test material)
//   --cap <u32>           (gateway: USB HelloAck capability bitmap)
//   --channel <u8>        (operating channel, default 6)
//   --netlow <u32>        (wire network low32 before adoption, like the
//                         firmware's trust/Kconfig image; the adopted
//                         network comes from the real ApplyMemberConfig)
//   --gw1 <u64> --gw2 <u64>  (scoped route gateways for the pre-adoption
//                            node config; the adopted config comes from
//                            the real ApplyMemberConfig path)
//   --flat                 use the product flat-route timers for route-loss tests
//   --c-app                (member: S/A/B, C, D, L and Y, the Device events
//                         and the APPLIED endpoint go through the C
//                         application on the Device C API, device.h)
//   --remote-config        (member: Device's remote-config target)
//   --channel-plan         (Device's manual channel plan, Manual mode;
//                         the gateway is the site's plan authority)
//   --channel-plan-observe (Device's observation-only migration mode)
//   --nvs-load <file>    (optional fake-NVS preload image)
//   --flash <file>       (optional 4096 B legacy slot image: identity
//                         slots, site slots — imported into the fake NVS
//                         so a member provisioned by the joiner peer can
//                         boot here; erased (0xFF) slots stay missing keys)
//   --flash-ext <file>   (optional 4562 B legacy image: RRS slots, then
//                         lifecycle journal slots)
//   --nvs-save <file>    (esp_restart writes the image here, exits 42)
//   --nvs-fail <k>       (F02: the k-th NVS write of this boot fails once
//                         with NOT_ENOUGH_SPACE; a boot that fails on it
//                         takes the firmware's restart path, exit 42)
//
// Test keys only; every byte on argv is test material. Entropy is a
// seeded PRNG (deterministic); all session/channel/EDHOC crypto is the
// real builtin AES-GCM/CCM, shared by every peer.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "bootloader_random.h"
#include "esp_sleep.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "psa/crypto.h"
#include "routeloom/aead_gcm.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/edhoc.hpp"
#include "routeloom/espnow_autonomy.hpp"
#include "routeloom/espnow_power.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/sdkv1_blob_storage.hpp"
#include "routeloom/sdkv1_group_keys.hpp"
#include "routeloom/sdkv1_lifecycle_store.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/usb_bridge.hpp"

#include "routeloom/device.hpp"
#include "routeloom/gateway.hpp"
#include "idf_stubs.hpp"
#include "owner_mesh_c_app.h"
#include "../../examples/standalone_gateway/main/app.hpp"

esp_err_t esp_sleep_enable_timer_wakeup(std::uint64_t) { return ESP_OK; }
esp_err_t esp_sleep_enable_gpio_wakeup_on_hp_periph_powerdown(std::uint64_t,
                                                              esp_sleep_gpio_wake_up_mode_t) {
  return ESP_OK;
}
void esp_deep_sleep_start() {}

namespace {

// --- Fake NVS ----------------------------------------------------------------
// In-memory (partition, namespace, key) -> blob store with the real NVS
// error vocabulary the firmware paths expect: missing reads erase to
// NOT_FOUND, an exhausted iterator reports NOT_FOUND, erase of a missing
// key reports NOT_FOUND (callers map it), commit always succeeds (the
// fake is durably written on set). u32 values ride as 4-byte LE blobs.
// Dump/load carries the whole image across power cuts and reboots.

using BlobMap = std::map<std::string, std::vector<std::uint8_t>>;
using SpaceMap = std::map<std::string, BlobMap>;
using PartitionMap = std::map<std::string, SpaceMap>;

PartitionMap g_nvs;
// Harness counters that must survive the peer's restarts (Device events
// reported right before a lifecycle restart): saved into the fake flash
// image under a harness-only partition the firmware never opens.
void (*g_before_restart)() = nullptr;
std::string g_nvs_save_path;
bool g_cut_after_switching{false};
// F02 fault: the k-th NVS write (set/erase/commit, counted from process
// start) fails once with ESP_ERR_NVS_NOT_ENOUGH_SPACE (0 = off).
std::uint32_t g_nvs_fail_at{0};
std::uint32_t g_nvs_writes{0};
bool g_nvs_fault_fired{false};

bool nvs_write_fault() {
  if (g_nvs_fail_at == 0 || g_nvs_fault_fired) return false;
  if (++g_nvs_writes != g_nvs_fail_at) return false;
  g_nvs_fault_fired = true;
  return true;
}

// F01/F02 at one record key (the `W` command): the next write of that key
// fails once with NOT_ENOUGH_SPACE (0), loses power before it lands (1),
// or loses power after its commit, before anything acknowledges it (2).
// Mode 3 is mode 2 on the key's second write: a sealed record lands in two
// writes (pending, then sealed), so this cuts after the sealed one.
std::string g_key_fault;
std::uint8_t g_key_fault_mode{0};
bool g_key_cut_after_commit{false};
std::uint32_t g_key_fault_hits{0};

struct NvsHandle {
  bool used{false};
  std::string partition;
  std::string space;
};
constexpr std::size_t kNvsHandlesMax = 16;
NvsHandle g_nvs_handles[kNvsHandlesMax];

struct NvsFakeIterator {
  std::vector<std::string> keys;
  std::size_t index{0};
  std::string space;
};

// Deterministic RNG behind psa_generate_random (test-only; the seed
// arrives on argv). The real EspOwnerEntropy state machine draws from
// it, so begin/fill/probe/failure paths are the production code.
std::uint64_t g_rng_state = 0x9E3779B97F4A7C15ULL;

void rng_seed(std::uint64_t seed) {
  g_rng_state = seed ^ 0xBF58476D1CE4E5B9ULL;
  if (g_rng_state == 0) g_rng_state = 1;
}

std::uint64_t rng_next() {
  std::uint64_t x = g_rng_state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  g_rng_state = x;
  return x * 0x2545F4914F6CDD1DULL;
}

const char* kDefaultPartition = "nvs";

bool nvs_lookup(nvs_handle_t handle, SpaceMap*& spaces, BlobMap*& blobs) {
  if (handle == 0 || handle > kNvsHandlesMax || !g_nvs_handles[handle - 1].used) return false;
  NvsHandle& entry = g_nvs_handles[handle - 1];
  spaces = &g_nvs[entry.partition];
  blobs = &(*spaces)[entry.space];
  return true;
}

}  // namespace

[[noreturn]] void switching_power_cut();

esp_err_t nvs_open(const char* name_space, int mode, nvs_handle_t* handle) {
  (void)mode;
  if (name_space == nullptr || handle == nullptr) return ESP_ERR_INVALID_ARG;
  for (std::size_t i = 0; i < kNvsHandlesMax; ++i) {
    if (!g_nvs_handles[i].used) {
      g_nvs_handles[i].used = true;
      g_nvs_handles[i].partition = kDefaultPartition;
      g_nvs_handles[i].space = name_space;
      *handle = static_cast<nvs_handle_t>(i + 1);
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
}

esp_err_t nvs_open_from_partition(const char* partition, const char* name_space, int mode,
                                  nvs_handle_t* handle) {
  (void)mode;
  if (partition == nullptr || name_space == nullptr || handle == nullptr) {
    return ESP_ERR_INVALID_ARG;
  }
  for (std::size_t i = 0; i < kNvsHandlesMax; ++i) {
    if (!g_nvs_handles[i].used) {
      g_nvs_handles[i].used = true;
      g_nvs_handles[i].partition = partition;
      g_nvs_handles[i].space = name_space;
      *handle = static_cast<nvs_handle_t>(i + 1);
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
}

esp_err_t nvs_get_u32(nvs_handle_t handle, const char* key, std::uint32_t* out) {
  if (key == nullptr || out == nullptr) return ESP_ERR_INVALID_ARG;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  const auto found = blobs->find(key);
  if (found == blobs->end() || found->second.size() != 4) return ESP_ERR_NVS_NOT_FOUND;
  const std::uint8_t* bytes = found->second.data();
  *out = static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8) |
         (static_cast<std::uint32_t>(bytes[2]) << 16) | (static_cast<std::uint32_t>(bytes[3]) << 24);
  return ESP_OK;
}

esp_err_t nvs_set_u32(nvs_handle_t handle, const char* key, std::uint32_t value) {
  if (nvs_write_fault()) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  if (key == nullptr) return ESP_ERR_INVALID_ARG;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  (*blobs)[key] = std::vector<std::uint8_t>{
      static_cast<std::uint8_t>(value & 0xFFU), static_cast<std::uint8_t>((value >> 8) & 0xFFU),
      static_cast<std::uint8_t>((value >> 16) & 0xFFU),
      static_cast<std::uint8_t>((value >> 24) & 0xFFU)};
  return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out, std::size_t* length) {
  if (key == nullptr || length == nullptr) return ESP_ERR_INVALID_ARG;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  const auto found = blobs->find(key);
  if (found == blobs->end()) return ESP_ERR_NVS_NOT_FOUND;
  if (out == nullptr) {
    *length = found->second.size();
    return ESP_OK;
  }
  if (*length < found->second.size()) return ESP_ERR_INVALID_ARG;
  std::memcpy(out, found->second.data(), found->second.size());
  *length = found->second.size();
  return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* data, std::size_t length) {
  if (nvs_write_fault()) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  if (key == nullptr || (data == nullptr && length != 0)) return ESP_ERR_INVALID_ARG;
  if (!g_key_fault.empty() && g_key_fault == key && g_key_fault_mode == 3) {
    g_key_fault_mode = 2;  // the next write of the key is the sealed one
  } else if (!g_key_fault.empty() && g_key_fault == key) {
    g_key_fault.clear();
    ++g_key_fault_hits;
    if (g_key_fault_mode == 0) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    if (g_key_fault_mode == 1) switching_power_cut();
    g_key_cut_after_commit = true;
  }
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  (*blobs)[key] = std::vector<std::uint8_t>(bytes, bytes + length);
  return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key) {
  if (nvs_write_fault()) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  if (key == nullptr) return ESP_ERR_INVALID_ARG;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  const auto found = blobs->find(key);
  if (found == blobs->end()) return ESP_ERR_NVS_NOT_FOUND;
  blobs->erase(found);
  return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle) {
  if (nvs_write_fault()) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  if (g_key_cut_after_commit) switching_power_cut();
  if (g_cut_after_switching &&
      g_nvs_handles[handle - 1].space == routeloom::sdkv1::kLifecycleNamespace) {
    for (const char* key : {routeloom::sdkv1::kLifecycleKey0,
                            routeloom::sdkv1::kLifecycleKey1}) {
      const auto found = blobs->find(key);
      if (found == blobs->end()) continue;
      const auto& slot = found->second;
      if (slot.size() < 88 || slot.size() > routeloom::sdkv1::kLifecycleSlotBytes) continue;
      const std::size_t used = (static_cast<std::size_t>(slot[6]) << 8U) | slot[7];
      if (used < 88 || used > slot.size()) continue;
      routeloom::sdkv1::LifecycleRecord record{};
      const auto decoded = routeloom::sdkv1::lifecycle_record_decode(
          routeloom::ByteView{slot.data(), used}, record);
      if (decoded.ok() &&
          record.mode == routeloom::sdkv1::LifecycleMode::Switching) {
        g_cut_after_switching = false;
        switching_power_cut();
      }
    }
  }
  return ESP_OK;
}

void nvs_close(nvs_handle_t handle) {
  if (handle == 0 || handle > kNvsHandlesMax) return;
  g_nvs_handles[handle - 1].used = false;
}

esp_err_t nvs_entry_find(const char* partition, const char* name_space, int type,
                         nvs_iterator_t* out) {
  (void)type;
  if (partition == nullptr || name_space == nullptr || out == nullptr) {
    return ESP_ERR_INVALID_ARG;
  }
  *out = nullptr;
  const auto partitions = g_nvs.find(partition);
  if (partitions == g_nvs.end()) return ESP_ERR_NVS_NOT_FOUND;
  const auto spaces = partitions->second.find(name_space);
  if (spaces == partitions->second.end() || spaces->second.empty()) {
    return ESP_ERR_NVS_NOT_FOUND;
  }
  auto* iterator = new (std::nothrow) NvsFakeIterator();
  if (iterator == nullptr) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  iterator->space = name_space;
  for (const auto& entry : spaces->second) iterator->keys.push_back(entry.first);
  *out = reinterpret_cast<nvs_iterator_t>(iterator);
  return ESP_OK;
}

esp_err_t nvs_entry_info(nvs_iterator_t iterator, nvs_entry_info_t* out) {
  auto* fake = reinterpret_cast<NvsFakeIterator*>(iterator);
  if (fake == nullptr || out == nullptr) return ESP_ERR_INVALID_ARG;
  if (fake->index >= fake->keys.size()) return ESP_ERR_NVS_NOT_FOUND;
  *out = nvs_entry_info_t{};
  std::strncpy(out->namespace_name, fake->space.c_str(), sizeof(out->namespace_name) - 1);
  std::strncpy(out->key, fake->keys[fake->index].c_str(), sizeof(out->key) - 1);
  return ESP_OK;
}

esp_err_t nvs_entry_next(nvs_iterator_t* iterator) {
  if (iterator == nullptr || *iterator == nullptr) return ESP_ERR_INVALID_ARG;
  auto* fake = reinterpret_cast<NvsFakeIterator*>(*iterator);
  ++fake->index;
  if (fake->index >= fake->keys.size()) return ESP_ERR_NVS_NOT_FOUND;
  return ESP_OK;
}

void nvs_release_iterator(nvs_iterator_t iterator) {
  delete reinterpret_cast<NvsFakeIterator*>(iterator);
}

esp_err_t nvs_erase_all(nvs_handle_t handle) {
  if (nvs_write_fault()) return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  blobs->clear();
  return ESP_OK;
}

esp_err_t nvs_get_used_entry_count(nvs_handle_t handle, std::size_t* out) {
  if (out == nullptr) return ESP_ERR_INVALID_ARG;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  *out = blobs->size();
  return ESP_OK;
}

extern "C" void bootloader_random_enable(void) {}
extern "C" void bootloader_random_disable(void) {}
extern "C" psa_status_t psa_crypto_init(void) { return PSA_SUCCESS; }
extern "C" psa_status_t psa_generate_random(std::uint8_t* output, const std::size_t length) {
  for (std::size_t i = 0; i < length; ++i) {
    if (i % 8 == 0) {
      const std::uint64_t word = rng_next();
      std::memcpy(output + i, &word, length - i >= 8 ? 8 : length - i);
    }
  }
  return PSA_SUCCESS;
}

namespace routeloom {

// The harness snapshot reads the Owner, stores, runtime and bridge the
// Device booted — the same objects the firmware runs.
struct DeviceTestAccess {
  static espnow::EspNowSecurityOwner& owner(Device& device) noexcept { return *device.owner_; }
  static espnow::Sdkv1Stores& stores(Device& device) noexcept { return *device.stores_; }
  static espnow::EspNowRuntime& runtime(Device& device) noexcept { return *device.runtime_; }
  static usb::UsbBridge* bridge(Device& device) noexcept { return device.bridge_; }
  static const GatewayDelivery* gateway(Device& device) noexcept { return device.gateway_; }
  static NodeObserver* app(Device& device) noexcept { return device.app_; }
  static PowerEvents& power_events() noexcept { return Device::observer(); }
};

}  // namespace routeloom

namespace routeloom::espnow {

struct EspNowSecurityOwnerTestAccess {
  static bool down_live_to(EspNowSecurityOwner& owner, NodeId node) noexcept {
    return owner.authority_live_ && owner.gateway_role() && owner.gateway()->down_live_to(node);
  }
};

// --- Platform hooks (test process only) --------------------------------------
// Real builtin crypto backends shared by every peer, and a reboot that
// hands the NVS image to the harness instead of resetting silicon.

// Seeded before begin(); the harness passes a fixed --seed per test.
void mesh_peer_seed_entropy(std::uint64_t seed);

namespace {

// Session-bank AEAD over the real builtin AES-GCM: seal/open split and
// join the trailing 16-byte tag around the portable backend.
bool session_seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12], ByteView aad,
                  ByteView plaintext, std::uint8_t* out_ciphertext,
                  std::uint8_t out_tag[16]) noexcept {
  (void)ctx;
  const AeadGcm* backend = builtin_aead_gcm();
  if (backend == nullptr || plaintext.size > 512) return false;
  std::uint8_t combined[512 + 16]{};
  if (!backend->seal(backend->ctx, key, nonce, aad, plaintext, combined)) return false;
  std::memcpy(out_ciphertext, combined, plaintext.size);
  std::memcpy(out_tag, combined + plaintext.size, 16);
  return true;
}

bool session_open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12], ByteView aad,
                  ByteView ciphertext, const std::uint8_t tag[16],
                  std::uint8_t* out_plaintext) noexcept {
  (void)ctx;
  const AeadGcm* backend = builtin_aead_gcm();
  if (backend == nullptr || ciphertext.size > 512) return false;
  std::uint8_t combined[512 + 16]{};
  std::memcpy(combined, ciphertext.data, ciphertext.size);
  std::memcpy(combined + ciphertext.size, tag, 16);
  return backend->open(backend->ctx, key, nonce, aad,
                       ByteView{combined, ciphertext.size + 16}, out_plaintext);
}

}  // namespace

// Fake-NVS image writer, defined with the pipe loop below.
void write_nvs_image_file(const char* path);

void mesh_peer_seed_entropy(std::uint64_t seed) { rng_seed(seed); }

const AeadGcm* psa_aead_gcm() noexcept { return builtin_aead_gcm(); }

sdkv1::AeadGcm psa_session_aead_gcm() noexcept {
  return sdkv1::AeadGcm{&session_seal, &session_open, nullptr};
}

const edhoc::AeadCcm* psa_edhoc_aead_ccm() noexcept { return edhoc::builtin_aead_ccm(); }

void EspNowDiscoveryObserver::on_discovery_event(const char* reason, NodeId peer) noexcept {
  (void)tag_;
  if (runtime_ != nullptr && reason != nullptr) runtime_->note_diagnostic(reason, peer);
}

}  // namespace routeloom::espnow

[[noreturn]] void esp_restart() {
  if (g_before_restart != nullptr) g_before_restart();
  // A lifecycle AdoptNetwork/RestartUnassigned reboot: persist the NVS
  // image for the respawn (like flash surviving the reset) and exit with
  // the reboot marker. The harness respawns with --nvs-load; anything
  // still in RAM is lost, exactly like silicon.
  if (!g_nvs_save_path.empty()) {
    routeloom::espnow::write_nvs_image_file(g_nvs_save_path.c_str());
  }
  std::fflush(stderr);
  std::_Exit(42);
}

[[noreturn]] void switching_power_cut() {
  if (g_before_restart != nullptr) g_before_restart();
  if (!g_nvs_save_path.empty()) {
    routeloom::espnow::write_nvs_image_file(g_nvs_save_path.c_str());
  }
  std::_Exit(43);
}

namespace {

using routeloom::ByteView;
using routeloom::MonotonicMs;
using routeloom::MutableByteView;
using routeloom::NodeId;
using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kRpcMax = 65535;
constexpr std::size_t kUsbChunkMax = 4096;
constexpr std::size_t kAppRxKeep = 96;
// 16 tracked app sends: refusal loops (D04 R1) retry a revoked leg
// for minutes, and every attempt stays observable (host-side peer).
constexpr std::size_t kAppTxMax = 16;

[[noreturn]] void fatal(const char* detail) {
  Bytes payload;
  payload.push_back('E');
  for (const char* p = detail; *p != '\0'; ++p) payload.push_back(static_cast<std::uint8_t>(*p));
  const auto length = static_cast<std::uint16_t>(payload.size());
  std::uint8_t head[2] = {static_cast<std::uint8_t>(length & 0xFFU),
                          static_cast<std::uint8_t>((length >> 8) & 0xFFU)};
  std::fwrite(head, 1, 2, stdout);
  std::fwrite(payload.data(), 1, payload.size(), stdout);
  std::fflush(stdout);
  std::fprintf(stderr, "owner_mesh_peer fatal: %s\n", detail);
  std::exit(2);
}

bool read_exact(void* data, std::size_t size) {
  auto* bytes = static_cast<std::uint8_t*>(data);
  std::size_t got = 0;
  while (got < size) {
    const std::size_t more = std::fread(bytes + got, 1, size - got, stdin);
    if (more == 0) return false;
    got += more;
  }
  return true;
}

void write_frame(const Bytes& payload) {
  if (payload.empty() || payload.size() > kRpcMax) fatal("rpc bound");
  const auto length = static_cast<std::uint16_t>(payload.size());
  std::uint8_t head[2] = {static_cast<std::uint8_t>(length & 0xFFU),
                          static_cast<std::uint8_t>((length >> 8) & 0xFFU)};
  if (std::fwrite(head, 1, 2, stdout) != 2 ||
      std::fwrite(payload.data(), 1, payload.size(), stdout) != payload.size()) {
    std::exit(2);
  }
  std::fflush(stdout);
}

void put_u32(Bytes& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFU));
}

void put_u64(Bytes& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFU));
}

std::uint64_t parse_u64(const char* text) {
  if (text == nullptr) fatal("missing integer");
  char* end = nullptr;
  const unsigned long long value = std::strtoull(text, &end, 0);
  if (end == text || *end != '\0') fatal("bad integer");
  return static_cast<std::uint64_t>(value);
}

Bytes parse_hex(const char* text) {
  if (text == nullptr) fatal("missing hex blob");
  const std::size_t digits = std::strlen(text);
  if (digits % 2 != 0) fatal("odd hex blob");
  Bytes out;
  out.reserve(digits / 2);
  for (std::size_t i = 0; i < digits; i += 2) {
    unsigned byte = 0;
    for (int j = 0; j < 2; ++j) {
      const char c = text[i + static_cast<std::size_t>(j)];
      byte <<= 4;
      if (c >= '0' && c <= '9') byte |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') byte |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') byte |= static_cast<unsigned>(c - 'A' + 10);
      else fatal("bad hex blob");
    }
    out.push_back(static_cast<std::uint8_t>(byte));
  }
  return out;
}

// --- Fake-NVS image ----------------------------------------------------------
// count u32le, then entries: plen u8 | partition | slen u8 | space |
// klen u8 | key | blob_len u32le | blob.

Bytes encode_nvs_image() {
  Bytes out;
  std::uint32_t count = 0;
  for (const auto& partition : g_nvs) {
    for (const auto& space : partition.second) count += static_cast<std::uint32_t>(space.second.size());
  }
  put_u32(out, count);
  for (const auto& partition : g_nvs) {
    for (const auto& space : partition.second) {
      for (const auto& entry : space.second) {
        if (partition.first.size() > 255 || space.first.size() > 255 || entry.first.size() > 255) {
          fatal("nvs label too long");
        }
        out.push_back(static_cast<std::uint8_t>(partition.first.size()));
        out.insert(out.end(), partition.first.begin(), partition.first.end());
        out.push_back(static_cast<std::uint8_t>(space.first.size()));
        out.insert(out.end(), space.first.begin(), space.first.end());
        out.push_back(static_cast<std::uint8_t>(entry.first.size()));
        out.insert(out.end(), entry.first.begin(), entry.first.end());
        put_u32(out, static_cast<std::uint32_t>(entry.second.size()));
        out.insert(out.end(), entry.second.begin(), entry.second.end());
      }
    }
  }
  return out;
}

void decode_nvs_image(const Bytes& image) {
  g_nvs.clear();
  std::size_t pos = 0;
  if (image.size() < 4) fatal("short nvs image");
  std::uint32_t count = 0;
  for (int i = 0; i < 4; ++i) count |= static_cast<std::uint32_t>(image[pos++]) << (8 * i);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (pos + 3 > image.size()) fatal("short nvs entry");
    const std::size_t plen = image[pos++];
    if (pos + plen + 1 > image.size()) fatal("short nvs partition");
    const std::string partition(image.begin() + static_cast<std::ptrdiff_t>(pos),
                                image.begin() + static_cast<std::ptrdiff_t>(pos + plen));
    pos += plen;
    const std::size_t slen = image[pos++];
    if (pos + slen + 1 > image.size()) fatal("short nvs space");
    const std::string space(image.begin() + static_cast<std::ptrdiff_t>(pos),
                            image.begin() + static_cast<std::ptrdiff_t>(pos + slen));
    pos += slen;
    const std::size_t klen = image[pos++];
    if (pos + klen + 4 > image.size()) fatal("short nvs key");
    const std::string key(image.begin() + static_cast<std::ptrdiff_t>(pos),
                          image.begin() + static_cast<std::ptrdiff_t>(pos + klen));
    pos += klen;
    std::uint32_t blob_len = 0;
    for (int b = 0; b < 4; ++b) blob_len |= static_cast<std::uint32_t>(image[pos++]) << (8 * b);
    if (pos + blob_len > image.size()) fatal("short nvs blob");
    g_nvs[partition][space][key] =
        std::vector<std::uint8_t>(image.begin() + static_cast<std::ptrdiff_t>(pos),
                                  image.begin() + static_cast<std::ptrdiff_t>(pos + blob_len));
    pos += blob_len;
  }
  if (pos != image.size()) fatal("trailing nvs bytes");
}

Bytes read_file_bytes(const char* path) {
  Bytes out;
  std::FILE* file = std::fopen(path, "rb");
  if (file == nullptr) fatal("nvs-load open failed");
  std::uint8_t chunk[4096];
  for (;;) {
    const std::size_t got = std::fread(chunk, 1, sizeof(chunk), file);
    out.insert(out.end(), chunk, chunk + got);
    if (got < sizeof(chunk)) break;
  }
  std::fclose(file);
  return out;
}

void write_file_bytes(const char* path, const Bytes& bytes) {
  std::FILE* file = std::fopen(path, "wb");
  if (file == nullptr) fatal("nvs-save open failed");
  if (!bytes.empty() && std::fwrite(bytes.data(), 1, bytes.size(), file) != bytes.size()) {
    std::fclose(file);
    fatal("nvs-save write failed");
  }
  std::fclose(file);
}

// Legacy slot-image import: the joiner peer dumps raw slot bytes (the
// portable stores define the format, so backends agree byte for byte).
// A 0xFF slot is the erased state and must stay a MISSING NVS key — a
// present-but-erased blob would read back corrupt, not erased.
void import_flash_slot(const char* name_space, const char* key, const std::uint8_t* slot,
                       std::size_t slot_bytes) {
  bool erased = true;
  for (std::size_t i = 0; i < slot_bytes; ++i) {
    if (slot[i] != 0xFF) {
      erased = false;
      break;
    }
  }
  if (erased) return;
  g_nvs[routeloom::espnow::kSecurityNvsPartition][name_space][key] =
      std::vector<std::uint8_t>(slot, slot + slot_bytes);
}

void import_flash_images(const std::string& flash_path, const std::string& flash_ext_path) {
  using namespace routeloom::sdkv1;
  if (!flash_path.empty()) {
    const Bytes image = read_file_bytes(flash_path.c_str());
    if (image.size() != 4096) fatal("bad flash image size");
    if (kIdentitySlotBytes > 1024 || kSiteSlotBytes > 1024) fatal("slot size mismatch");
    const std::uint8_t* base = image.data();
    import_flash_slot(kIdentityNamespace, kIdentityKey0, base, kIdentitySlotBytes);
    import_flash_slot(kIdentityNamespace, kIdentityKey1, base + 1024, kIdentitySlotBytes);
    import_flash_slot(kSiteNamespace, kSiteKey0, base + 2048, kSiteSlotBytes);
    import_flash_slot(kSiteNamespace, kSiteKey1, base + 3072, kSiteSlotBytes);
  }
  if (!flash_ext_path.empty()) {
    const Bytes image = read_file_bytes(flash_ext_path.c_str());
    constexpr std::size_t kExtBytes = 2 * kRevocationSlotBytes + 2 * kLifecycleSlotBytes;
    if (image.size() != kExtBytes) fatal("bad flash-ext image size");
    if (kLifecycleSlotBytes != 88 + 1521) {
      fatal("ext slot size mismatch");
    }
    const std::uint8_t* base = image.data();
    import_flash_slot(kRevocationNamespace, kRevocationKey0, base, kRevocationSlotBytes);
    import_flash_slot(kRevocationNamespace, kRevocationKey1, base + kRevocationSlotBytes, kRevocationSlotBytes);
    import_flash_slot(kLifecycleNamespace, kLifecycleKey0, base + 2 * kRevocationSlotBytes, kLifecycleSlotBytes);
    import_flash_slot(kLifecycleNamespace, kLifecycleKey1, base + 2 * kRevocationSlotBytes + kLifecycleSlotBytes,
                      kLifecycleSlotBytes);
  }
}

}  // namespace

namespace routeloom::espnow {
void write_nvs_image_file(const char* path) { write_file_bytes(path, encode_nvs_image()); }
}  // namespace routeloom::espnow

namespace {

struct Setup {
  NodeId node{routeloom::kInvalidNodeId};
  routeloom::MacAddress mac{};
  std::uint8_t role{0};
  std::uint8_t join_cap{0};
  MonotonicMs t0{0};
  std::uint64_t seed{0};
  std::uint8_t world_nodes{3};
  bool gateway{false};
  bool devram{false};
  Bytes usb_secret;
  std::uint32_t usb_cap{0};
  std::uint8_t channel{6};
  std::uint32_t netlow{0};
  NodeId gw1{routeloom::kInvalidNodeId};
  NodeId gw2{routeloom::kInvalidNodeId};
  bool flat{false};
  bool remote_config{false};
  bool c_app{false};
  bool standalone{false};
  std::uint8_t channel_plan{0};
  std::string nvs_load;
  std::string flash;
  std::string flash_ext;
};

bool take_arg(int argc, char** argv, int& i, const char*& value) {
  if (i + 1 >= argc) return false;
  value = argv[++i];
  return true;
}

Setup parse_argv(int argc, char** argv) {
  Setup setup{};
  bool have_node = false, have_mac = false, have_role = false, have_t0 = false, have_seed = false,
       have_mode = false;
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    const char* value = nullptr;
    if (arg == std::string("--node") && take_arg(argc, argv, i, value)) {
      setup.node = parse_u64(value);
      have_node = true;
    } else if (arg == std::string("--mac") && take_arg(argc, argv, i, value)) {
      const Bytes mac = parse_hex(value);
      if (mac.size() != 6) fatal("--mac wants 12 hex digits");
      std::memcpy(setup.mac.data(), mac.data(), 6);
      have_mac = true;
    } else if (arg == std::string("--role") && take_arg(argc, argv, i, value)) {
      setup.role = static_cast<std::uint8_t>(parse_u64(value));
      have_role = true;
    } else if (arg == std::string("--join-cap") && take_arg(argc, argv, i, value)) {
      setup.join_cap = static_cast<std::uint8_t>(parse_u64(value));
    } else if (arg == std::string("--t0") && take_arg(argc, argv, i, value)) {
      setup.t0 = parse_u64(value);
      have_t0 = true;
    } else if (arg == std::string("--seed") && take_arg(argc, argv, i, value)) {
      setup.seed = parse_u64(value);
      have_seed = true;
    } else if (arg == std::string("--world-nodes") && take_arg(argc, argv, i, value)) {
      const std::uint64_t nodes = parse_u64(value);
      if (nodes < 2 || nodes > 32) fatal("--world-nodes must be 2..32");
      setup.world_nodes = static_cast<std::uint8_t>(nodes);
    } else if (arg == std::string("--gateway")) {
      setup.gateway = true;
      have_mode = true;
    } else if (arg == std::string("--member")) {
      setup.gateway = false;
      have_mode = true;
    } else if (arg == std::string("--devram")) {
      setup.devram = true;
    } else if (arg == std::string("--usb-secret") && take_arg(argc, argv, i, value)) {
      setup.usb_secret = parse_hex(value);
    } else if (arg == std::string("--cap") && take_arg(argc, argv, i, value)) {
      setup.usb_cap = static_cast<std::uint32_t>(parse_u64(value));
    } else if (arg == std::string("--channel") && take_arg(argc, argv, i, value)) {
      setup.channel = static_cast<std::uint8_t>(parse_u64(value));
    } else if (arg == std::string("--netlow") && take_arg(argc, argv, i, value)) {
      setup.netlow = static_cast<std::uint32_t>(parse_u64(value));
    } else if (arg == std::string("--gw1") && take_arg(argc, argv, i, value)) {
      setup.gw1 = parse_u64(value);
    } else if (arg == std::string("--gw2") && take_arg(argc, argv, i, value)) {
      setup.gw2 = parse_u64(value);
    } else if (arg == std::string("--flat")) {
      setup.flat = true;
    } else if (arg == std::string("--c-app")) {
      setup.c_app = true;
    } else if (arg == std::string("--standalone")) {
      setup.standalone = true;
    } else if (arg == std::string("--remote-config")) {
      setup.remote_config = true;
    } else if (arg == std::string("--channel-plan")) {
      setup.channel_plan = 2;
    } else if (arg == std::string("--channel-plan-observe")) {
      setup.channel_plan = 1;
    } else if (arg == std::string("--nvs-load") && take_arg(argc, argv, i, value)) {
      setup.nvs_load = value;
    } else if (arg == std::string("--flash") && take_arg(argc, argv, i, value)) {
      setup.flash = value;
    } else if (arg == std::string("--flash-ext") && take_arg(argc, argv, i, value)) {
      setup.flash_ext = value;
    } else if (arg == std::string("--nvs-save") && take_arg(argc, argv, i, value)) {
      g_nvs_save_path = value;
    } else if (arg == std::string("--nvs-fail") && take_arg(argc, argv, i, value)) {
      g_nvs_fail_at = static_cast<std::uint32_t>(parse_u64(value));
    } else {
      fatal("unknown argument");
    }
  }
  if (!have_node || !have_mac || !have_role || !have_t0 || !have_seed || !have_mode) {
    fatal("missing --node/--mac/--role/--t0/--seed/--gateway|--member");
  }
  if (setup.node == routeloom::kInvalidNodeId || setup.node == routeloom::kBroadcastNodeId) {
    fatal("bad node id");
  }
  return setup;
}

// The pipe end of the gateway USB: device TX accumulates here and the
// tick drains it into B frames.
class PipeByteStream final : public routeloom::usb::ByteStream {
 public:
  routeloom::Status write(ByteView data, std::size_t& written) noexcept override {
    written = data.size;
    bytes_.insert(bytes_.end(), data.data, data.data + data.size);
    return routeloom::Status::success();
  }
  Bytes take() {
    Bytes out;
    out.swap(bytes_);
    return out;
  }

 private:
  Bytes bytes_;
};

// NodeObserver that records traffic evidence. On a gateway the bridge
// stays the firmware's observer (deliveries ride the real USB frames to
// the host); this tee keeps the same evidence for the snapshot.
class TeeObserver final : public routeloom::NodeObserver {
 public:
  struct Receipt {
    routeloom::MessageKey key{};
    NodeId source{0};
    std::array<std::uint8_t, routeloom::kMaxApplicationPayload> payload{};
    std::uint8_t length{0};
  };
  explicit TeeObserver(routeloom::NodeObserver* next) noexcept : next_(next) {}
  void chain(routeloom::NodeObserver* next) noexcept { next_ = next; }
  void bind_device(routeloom::Device& device) noexcept { device_ = &device; }

  void on_message(const routeloom::MessageKey& key, NodeId source,
                  ByteView payload) noexcept override {
    constexpr char kAttachGateway[] = "attach-gateway";
    if (device_ != nullptr && payload.size == sizeof(kAttachGateway) - 1 &&
        std::memcmp(payload.data, kAttachGateway, sizeof(kAttachGateway) - 1) == 0) {
      (void)device_->gateway();
    }
    if (on_rx_ != nullptr) on_rx_();
    ++rx_count_;
    rx_src_ = source;
    rx_len_ = payload.size > kAppRxKeep ? kAppRxKeep : payload.size;
    std::memcpy(rx_, payload.data, rx_len_);
    if (receipts_size_ < receipts_.size()) {
      Receipt& receipt = receipts_[receipts_size_++];
      receipt.key = key;
      receipt.source = source;
      receipt.length = static_cast<std::uint8_t>(payload.size);
      std::memcpy(receipt.payload.data(), payload.data, payload.size);
    } else {
      ++receipts_overflow_;
    }
    if (next_ != nullptr) next_->on_message(key, source, payload);
  }
  void on_delivery(const routeloom::DeliveryResult& result) noexcept override {
    delivery_events_.push_back(result);
    if (next_ != nullptr) next_->on_delivery(result);
  }
  void on_diagnostic(const char* reason, NodeId peer,
                     const routeloom::MessageId* id) noexcept override {
    if (std::strcmp(reason, "TRANSIT_DEDUP_CONFLICT") == 0) ++transit_conflicts_;
    if (std::strcmp(reason, "RECEIPT_DEDUP_CONFLICT") == 0) ++receipt_conflicts_;
    if (std::strcmp(reason, "NO_ROUTE") == 0) ++no_route_;
    if (std::strcmp(reason, "EXTENSION_UNSUPPORTED") == 0) ++ext_unsupported_;
    if (next_ != nullptr) next_->on_diagnostic(reason, peer, id);
  }

  std::uint32_t rx_count_{0};
  std::array<Receipt, 64> receipts_{};
  std::size_t receipts_size_{0};
  std::uint32_t receipts_overflow_{0};
  NodeId rx_src_{routeloom::kInvalidNodeId};
  std::uint8_t rx_[kAppRxKeep]{};
  std::size_t rx_len_{0};
  std::vector<routeloom::DeliveryResult> delivery_events_;
  std::uint32_t transit_conflicts_{0};
  std::uint32_t receipt_conflicts_{0};
  void (*on_rx_)() = nullptr;
  std::uint32_t no_route_{0};
  std::uint32_t ext_unsupported_{0};

 private:
  routeloom::NodeObserver* next_;
  routeloom::Device* device_{nullptr};
};

struct AppTx {
  bool used{false};
  routeloom::MessageId id{};
  routeloom::DeliveryState state{routeloom::DeliveryState::Empty};
  char reason[13]{};
};

// The explicit gateway sends Z commands drive: one resolved endpoint,
// reused while Ready for the same gateway, and the latest send.
struct GatewayTx {
  bool endpoint_valid{false};
  routeloom::NodeId gateway{routeloom::kInvalidNodeId};
  bool want_send{false};
  bool sent{false};
  routeloom::GatewayEndpoint endpoint{};
  Bytes payload;
  routeloom::MessageId id{};
  std::uint8_t endpoint_state{0};
  std::uint8_t send_state{0};
  std::uint8_t reason{0};
};

// The origin's terminal outcome arrives once through the observer; the
// send record is released right after, so it is kept here.
class GatewayTxObserver final : public routeloom::GatewayDeliveryObserver {
 public:
  explicit GatewayTxObserver(GatewayTx& tx) noexcept : tx_(tx) {}
  void on_gateway_resolved(const routeloom::GatewayEndpoint&, routeloom::NodeId,
                           routeloom::Status) noexcept override {}
  void on_gateway_result(const routeloom::GatewaySendResult& result) noexcept override {
    if (!tx_.sent || result.id != tx_.id) return;
    tx_.send_state = static_cast<std::uint8_t>(result.state);
    tx_.reason = static_cast<std::uint8_t>(result.reason);
  }

 private:
  GatewayTx& tx_;
};

// Device events and operation results (the harness asserts one event per
// change). The counters ride the fake flash image across restarts, since a
// finished leave is reported right before the unassigned restart.
// Only the non-returning platform sleep syscall is modeled. Security
// parking, RTC persistence, driver quiescence and recovery use the adapter.
class SleepPort final : public routeloom::PowerPort {
 public:
  explicit SleepPort(routeloom::espnow::EspNowRuntime& runtime) : adapter(runtime) {}
  routeloom::espnow::EspNowPowerPort adapter;
  bool asleep{false};
  routeloom::Status prepare_sleep(routeloom::MonotonicMs now) noexcept override {
    return adapter.prepare_sleep(now);
  }
  void abort_sleep(routeloom::MonotonicMs now) noexcept override { adapter.abort_sleep(now); }
  bool matches_context(const routeloom::PowerImage& image,
                       routeloom::NetworkId network) const noexcept override {
    return adapter.matches_context(image, network);
  }
  routeloom::Status capture_cache(routeloom::PowerImage& image) noexcept override {
    return adapter.capture_cache(image);
  }
  routeloom::Status quiesce_radio() noexcept override { return adapter.quiesce_radio(); }
  routeloom::Status start_radio(const routeloom::PowerImage* image) noexcept override {
    asleep = false;
    return adapter.start_radio(image);
  }
  routeloom::Status configure_wake(const routeloom::WakePlan& plan) noexcept override {
    return adapter.configure_wake(plan);
  }
  routeloom::Status enter_sleep() noexcept override {
    if (esp_wifi_stop() != ESP_OK)
      return routeloom::Status::error(routeloom::StatusCode::RadioFailure, "sleep radio stop");
    asleep = true;
    return routeloom::Status::success();
  }
  routeloom::Status start_discovery(const routeloom::PowerImage& image) noexcept override {
    return adapter.start_discovery(image);
  }
};

struct DeviceEvents final : public routeloom::DeviceObserver {
  std::uint32_t membership_events{0};
  std::uint16_t last_cause{0};
  std::uint32_t op_last{0};
  std::uint16_t op_result{0};
  std::uint32_t connectivity_events{0};
  // F05: calls from inside a callback, and how many answered Busy.
  bool probe{false};
  std::uint32_t reentry_calls{0};
  std::uint32_t reentry_busy{0};
  routeloom::Device* device{nullptr};

  static constexpr const char* kPartition = "harness";
  void save() const {
    Bytes blob;
    put_u32(blob, membership_events);
    put_u32(blob, last_cause);
    put_u32(blob, op_last);
    put_u32(blob, op_result);
    put_u32(blob, connectivity_events);
    put_u32(blob, reentry_calls);
    put_u32(blob, reentry_busy);
    g_nvs[kPartition]["ev"]["e"] = blob;
  }
  void load() {
    const auto part = g_nvs.find(kPartition);
    if (part == g_nvs.end()) return;
    const Bytes& blob = part->second["ev"]["e"];
    if (blob.size() != 28) return;
    const auto get = [&](std::size_t i) {
      std::uint32_t value = 0;
      for (int b = 0; b < 4; ++b) value |= static_cast<std::uint32_t>(blob[i * 4 + b]) << (8 * b);
      return value;
    };
    membership_events = get(0);
    last_cause = static_cast<std::uint16_t>(get(1));
    op_last = get(2);
    op_result = static_cast<std::uint16_t>(get(3));
    connectivity_events = get(4);
    reentry_calls = get(5);
    reentry_busy = get(6);
  }
  void try_reentry() {
    if (!probe || device == nullptr) return;
    const std::uint8_t byte = 0x5A;
    routeloom::MessageId id{};
    routeloom::OperationId op = 0;
    reentry_calls += 2;
    if (device->send(0x00A1000000000001ULL, ByteView{&byte, 1}, routeloom::SendOptions{}, id)
            .code == routeloom::StatusCode::Busy) {
      ++reentry_busy;
    }
    if (device->leave(op).code == routeloom::StatusCode::Busy) ++reentry_busy;
  }
  void on_membership(const routeloom::MembershipSnapshot& snapshot, std::uint16_t cause) noexcept override {
    if (device != nullptr && device->membership().stage != snapshot.stage) {
      fatal("membership callback disagrees with snapshot API");
    }
    ++membership_events;
    last_cause = cause;
    try_reentry();
  }
  void on_connectivity(const routeloom::ConnectivitySnapshot&) noexcept override {
    ++connectivity_events;
  }
  void on_operation(routeloom::OperationId operation, std::uint16_t result) noexcept override {
    op_last = operation;
    op_result = result;
  }
};
DeviceEvents* g_device_events = nullptr;
// --c-app: the C application observes the Device instead of DeviceEvents;
// its counters are copied into DeviceEvents for the snapshot and restart.
mesh_c_app_t* g_c_app = nullptr;
void sync_c_app() {
  if (g_c_app == nullptr || g_device_events == nullptr) return;
  DeviceEvents& events = *g_device_events;
  events.membership_events = g_c_app->membership_events;
  events.last_cause = g_c_app->last_cause;
  events.op_last = g_c_app->op_last;
  events.op_result = g_c_app->op_result;
  events.connectivity_events = g_c_app->connectivity_events;
  events.reentry_calls = g_c_app->reentry_calls;
  events.reentry_busy = g_c_app->reentry_busy;
}
void save_device_events() {
  sync_c_app();
  if (g_device_events != nullptr) g_device_events->save();
}

// P05: an application endpoint that defers every APPLIED request and
// completes it (Success) `delay_ms` after it arrived, from the Owner task.
struct DeferredApplied final : public routeloom::AppliedEndpointSink {
  struct Open {
    std::uint64_t ticket{0};
    MonotonicMs due{0};
  };
  MonotonicMs delay_ms{0};
  MonotonicMs now{0};
  std::vector<Open> open;
  std::uint32_t requests{0};
  std::uint32_t completed{0};
  std::uint32_t refused{0};
  void on_applied_request(const routeloom::AppliedRequest& request,
                          routeloom::AppliedReply& reply) noexcept override {
    ++requests;
    if (g_device_events != nullptr) g_device_events->try_reentry();
    reply.deferred = true;
    open.push_back(Open{request.ticket, now + delay_ms});
  }
  void poll(routeloom::Device& device, MonotonicMs at) {
    now = at;
    for (auto it = open.begin(); it != open.end();) {
      if (at < it->due) {
        ++it;
        continue;
      }
      routeloom::AppliedReply reply{};
      reply.outcome = routeloom::endpoint::AppResultOutcome::Success;
      if (device.complete_applied(it->ticket, reply)) {
        ++completed;
      } else {
        ++refused;
      }
      it = open.erase(it);
    }
  }
};

void emit_snapshot(routeloom::espnow::EspNowSecurityOwner& owner,
                   routeloom::espnow::Sdkv1Stores& stores,
                   routeloom::espnow::EspNowRuntime& runtime,
                   const routeloom::usb::UsbBridge* bridge, const TeeObserver& observer,
                   AppTx* app_tx, std::uint32_t send_count_base,
                   std::uint8_t world_nodes, const GatewayTx& gw_tx,
                   const routeloom::GatewayDelivery* gateway, routeloom::Device& device,
                   const DeviceEvents& events, const DeferredApplied& applied) {
  using namespace routeloom;
  using namespace routeloom::espnow;
  using namespace routeloom::sdkv1;
  Bytes out;
  out.push_back('G');
  const CoordinatorSnapshot coord = owner.coordinator().snapshot();
  out.push_back(static_cast<std::uint8_t>(coord.mode));
  // MembershipState lives beside the mode in the coordinator snapshot.
  out.push_back(static_cast<std::uint8_t>(coord.membership));
  out.push_back(coord.authority_started ? 1 : 0);
  out.push_back(coord.authority_ready ? 1 : 0);
  out.push_back(coord.join_confirmed ? 1 : 0);
  put_u32(out, coord.link_sessions);
  put_u32(out, coord.end_sessions);
  const LifecycleSnapshot life = owner.lifecycle().snapshot();
  out.push_back(static_cast<std::uint8_t>(life.phase));
  out.push_back(life.stores_healthy ? 1 : 0);
  put_u64(out, life.adopted_network);
  put_u32(out, life.own_generation);
  put_u32(out, life.applied_rs_epoch);
  put_u32(out, life.applied_gk_epoch);
  put_u64(out, life.holdoff_remaining_ms);
  const bool has_site = stores.site().has_site();
  put_u32(out, has_site ? stores.site().site().gk_epoch_current : 0);
  put_u32(out, has_site ? stores.site().site().gk_epoch_next : 0);
  out.push_back(stores.identity().has_identity() ? 1 : 0);
  out.push_back(has_site ? 1 : 0);
  put_u32(out, has_site ? stores.site().site().assignment_generation : 0);
  if (bridge == nullptr) {
    out.push_back(0xFF);
  } else {
    out.push_back(static_cast<std::uint8_t>(bridge->state()));
  }
  out.push_back(runtime.channel());
  out.push_back(runtime.committed_channel());
  put_u32(out, static_cast<std::uint32_t>(idf_stub::tx_overruns()));
  put_u32(out, static_cast<std::uint32_t>(idf_stub::send_count() - send_count_base));
  const LifecycleJournal::LastEvent last = owner.lifecycle_journal().last();
  out.push_back(last.valid ? static_cast<std::uint8_t>(last.event.kind) : 0);
  put_u32(out, last.valid ? last.event.epoch : 0);
  put_u32(out, last.valid ? last.event.detail : 0);
  put_u32(out, life.rrs_applied);
  put_u32(out, life.recoveries);
  put_u32(out, observer.rx_count_);
  put_u64(out, observer.rx_src_);
  out.push_back(static_cast<std::uint8_t>(observer.rx_len_));
  out.insert(out.end(), observer.rx_, observer.rx_ + observer.rx_len_);
  std::uint8_t tx_count = 0;
  for (std::size_t i = 0; i < kAppTxMax; ++i) {
    if (app_tx[i].used) ++tx_count;
  }
  out.push_back(tx_count);
  for (std::size_t i = 0; i < kAppTxMax; ++i) {
    if (!app_tx[i].used) continue;
    put_u64(out, app_tx[i].id.sequence);
    out.push_back(static_cast<std::uint8_t>(app_tx[i].state));
    const std::size_t reason_len = std::strlen(app_tx[i].reason);
    out.push_back(static_cast<std::uint8_t>(reason_len > 12 ? 12 : reason_len));
    for (std::size_t r = 0; r < reason_len && r < 12; ++r) {
      out.push_back(static_cast<std::uint8_t>(app_tx[i].reason[r]));
    }
  }
  const CoordinatorCounters& counters = owner.coordinator().counters();
  put_u32(out, counters.demux_drops);
  put_u32(out, counters.link_established);
  put_u32(out, counters.link_failed);
  out.push_back(static_cast<std::uint8_t>(counters.link_last_error));
  put_u32(out, counters.link_requests);
  put_u32(out, counters.link_send_failures);
  put_u32(out, counters.end_established);
  put_u32(out, counters.end_failed);
  out.push_back(static_cast<std::uint8_t>(counters.end_last_error));
  const NeighborDiscovery* discovery = owner.discovery();
  out.push_back(discovery != nullptr ? 1 : 0);
  const DiscoveryStats no_stats{};
  const ScopeStats no_scope{};
  const DiscoveryStats& stats = discovery != nullptr ? discovery->stats() : no_stats;
  const ScopeStats& scope = discovery != nullptr ? discovery->scope_stats() : no_scope;
  put_u32(out, stats.discovers_rx);
  put_u32(out, stats.offers_tx);
  put_u32(out, stats.offers_rx);
  put_u32(out, stats.proves_rx);
  put_u32(out, stats.auths_completed);
  put_u32(out, stats.kind_rejects);
  put_u32(out, stats.cookie_rejects);
  put_u32(out, stats.auth_tag_rejects);
  put_u32(out, stats.send_failures);
  put_u32(out, scope.raw_rx);
  put_u32(out, scope.hint_mismatch);
  put_u32(out, scope.mac_rejected);
  put_u32(out, scope.unknown_generation);
  put_u32(out, scope.scope_accepted);
  put_u32(out, scope.key_unavailable);
  put_u32(out, scope.budget_dropped);
  // RLI1 fingerprint (D04 R2): the kid's first 8 bytes, never key
  // material — the harness compares it across the erasure.
  std::uint64_t id_fp = 0;
  if (stores.identity().has_identity()) {
    const auto& kid = stores.identity().identity().kid;
    for (int i = 0; i < 8; ++i) id_fp |= static_cast<std::uint64_t>(kid[i]) << (8 * i);
  }
  put_u64(out, id_fp);
  // ZT legs (D04 §5.1): the joiner's state/error and the member
  // proxy's discover/offer/relay counters — all secret-free.
  out.push_back(static_cast<std::uint8_t>(coord.joiner));
  out.push_back(static_cast<std::uint8_t>(coord.joiner_last_error));
  const JoinProxyStats proxy = owner.coordinator().proxy_stats();
  put_u32(out, proxy.discovers_rx);
  put_u32(out, proxy.offers_tx);
  put_u32(out, proxy.offers_suppressed);
  put_u32(out, proxy.relays_started);
  put_u32(out, proxy.relays_completed);
  const AuthoritySnapshot auth = owner.coordinator().authority_snapshot();
  put_u64(out, auth.rx_accepted);
  put_u64(out, auth.tx_sent);
  out.push_back(coord.refresh_strikes);
  const JoinSnapshot joiner = owner.coordinator().joiner_snapshot();
  put_u32(out, joiner.counters.attempts);
  put_u32(out, joiner.counters.m1_sent);
  put_u32(out, joiner.counters.rx_dropped);
  // One bounded diagnostic for the R1 Notice target: a live gateway
  // down slot is sampled before the RRS enforcement tick cancels it.
  out.push_back(EspNowSecurityOwnerTestAccess::down_live_to(owner, 0x00A1000000000101ULL) ? 1 : 0);
  put_u32(out, runtime.unknown_peer_rx());
  put_u32(out, proxy.frames_rejected);
  put_u32(out, proxy.cookie_rejects);
  put_u32(out, stats.probes_tx);
  put_u32(out, stats.peer_capacity);
  put_u32(out, stats.stale_expirations);
  put_u32(out, stats.repair_demands);
  out.push_back(discovery != nullptr ? static_cast<std::uint8_t>(discovery->neighbor_count()) : 0);
  out.push_back(world_nodes);
  for (std::uint8_t index = 0; index < world_nodes; ++index) {
    const NodeId peer = index == 0 ? 0x00A1000000000001ULL
                                   : 0x00A1000000000101ULL + index - 1;
    NeighborPhase phase{};
    out.push_back(discovery != nullptr && discovery->phase_of(peer, phase)
                      ? static_cast<std::uint8_t>(phase)
                      : 0xFF);
  }
  put_u32(out, observer.transit_conflicts_);
  put_u32(out, observer.receipt_conflicts_);
  put_u32(out, observer.no_route_);
  put_u32(out, runtime.stale_tx_results());
  out.push_back(static_cast<std::uint8_t>(idf_stub::peer_count()));
  const CongestionStats congestion = runtime.node().congestion_stats();
  out.push_back(static_cast<std::uint8_t>(congestion.queued));
  put_u32(out, static_cast<std::uint32_t>(congestion.admissions_rejected));
  put_u32(out, counters.member_starts);
  put_u32(out, counters.link_request_failures);
  // Owner work counters.
  const EspNowRuntime::OwnerStats& owner_work = runtime.owner_stats();
  put_u32(out, owner_work.polls);
  put_u32(out, owner_work.empty_polls);
  put_u32(out, owner_work.rx_queue_max);
  put_u64(out, runtime.node().work_stats().expiry_slots_scanned);
  put_u64(out, runtime.node().work_stats().hop_accept_expired);
  put_u32(out, observer.ext_unsupported_);
  put_u32(out, static_cast<std::uint32_t>(runtime.node().group_stats().delivered));
  put_u32(out, static_cast<std::uint32_t>(runtime.node().group_stats().rejected));
  put_u32(out, g_key_fault_hits);
  out.push_back(gw_tx.endpoint_state);
  out.push_back(gw_tx.send_state);
  out.push_back(gw_tx.reason);
  const GatewayStats no_gateway{};
  const GatewayStats& gw = gateway != nullptr ? gateway->stats() : no_gateway;
  put_u32(out, gw.receipts_verified);
  put_u32(out, gw.sdk_ram_receipts);
  put_u32(out, gw.mailbox_stored);
  put_u32(out, gw.resolves_failed);
  // The runtime's migration sink is the Device's MigrationAgent.
  const auto* plan = static_cast<const MigrationAgent*>(runtime.migration());
  out.push_back(plan != nullptr ? static_cast<std::uint8_t>(plan->participant().phase()) : 0xFF);
  put_u32(out, plan != nullptr ? plan->participant().active_epoch().value : 0);
  out.push_back(plan != nullptr ? plan->participant().active_channel() : 0);
  out.push_back(static_cast<std::uint8_t>(device.membership().stage));
  put_u32(out, events.membership_events);
  out.push_back(static_cast<std::uint8_t>(events.last_cause & 0xFFU));
  out.push_back(static_cast<std::uint8_t>(events.last_cause >> 8));
  put_u32(out, events.op_last);
  out.push_back(static_cast<std::uint8_t>(events.op_result & 0xFFU));
  out.push_back(static_cast<std::uint8_t>(events.op_result >> 8));
  const ConnectivitySnapshot connectivity = device.connectivity();
  out.push_back(static_cast<std::uint8_t>(connectivity.state));
  put_u32(out, events.connectivity_events);
  out.push_back(static_cast<std::uint8_t>(connectivity.reason & 0xFFU));
  out.push_back(static_cast<std::uint8_t>(connectivity.reason >> 8));
  put_u32(out, events.reentry_calls);
  put_u32(out, events.reentry_busy);
  put_u32(out, applied.requests);
  put_u32(out, applied.completed);
  put_u32(out, applied.refused);
  JoinPolicy policy{};
  std::uint32_t revision = 0;
  (void)device.join_policy(policy, revision);
  put_u32(out, revision);
  put_u32(out, g_c_app != nullptr ? g_c_app->checks : 0);
  put_u32(out, g_c_app != nullptr ? g_c_app->check_failures : 0);
  put_u32(out, g_c_app != nullptr ? g_c_app->posted_runs : 0);
  put_u32(out, g_c_app != nullptr ? g_c_app->messages : 0);
  write_frame(out);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--harness-version") == 0) {
    std::fputs("8\n", stdout);
    return 0;
  }
  using namespace routeloom;
  using namespace routeloom::espnow;
  using namespace routeloom::sdkv1;
  using namespace routeloom::usb;

  int antenna_level = -2;
  unsigned gpio_fail_call = 0;
  if (argc >= 4 && std::strcmp(argv[1], "--check-board-rf") == 0) {
    antenna_level = std::atoi(argv[2]);
    gpio_fail_call = static_cast<unsigned>(std::atoi(argv[3]));
    argc -= 3;
    argv += 3;
  }
  const Setup setup = parse_argv(argc, argv);
  if (!setup.nvs_load.empty()) {
    if (!setup.flash.empty() || !setup.flash_ext.empty()) fatal("nvs-load with flash import");
    decode_nvs_image(read_file_bytes(setup.nvs_load.c_str()));
  }
  if (!setup.devram) import_flash_images(setup.flash, setup.flash_ext);
  mesh_peer_seed_entropy(setup.seed);

  idf_stub::reset();
  idf_stub::fail_gpio_call(gpio_fail_call);
  idf_stub::set_peer_limit(20);
  idf_stub::set_mac(setup.mac.data());
  idf_stub::set_now_us(static_cast<std::int64_t>(setup.t0) * 1000);
  MonotonicMs now = setup.t0;

  // The production boot: Device::open_storage then Device::begin.
  PipeByteStream usb_stream;
  TeeObserver observer(nullptr);
  routeloom_example::StandaloneApp standalone;
  Device device;
  observer.bind_device(device);
  device.observe(&observer);
  if (setup.standalone) {
    if (!setup.gateway) fatal("--standalone needs a gateway");
    observer.chain(&standalone);
    device.on_poll([](Device& target, MonotonicMs, void* app) {
      static_cast<routeloom_example::StandaloneApp*>(app)->answer(target);
    }, &standalone);
  }
  DeviceEvents events;
  events.device = &device;
  events.load();
  g_device_events = &events;
  g_before_restart = &save_device_events;
  device.observe_device(&events);
  observer.on_rx_ = [] {
    if (g_device_events != nullptr) g_device_events->try_reentry();
  };
  DeferredApplied applied;
  // A boot failure restarts like the firmware's fail() when the injected
  // NVS fault caused it; anything else is a harness error.
  const auto boot_failed = [](const Status& failed) {
    if (g_nvs_fault_fired) {
      std::fprintf(stderr, "mesh_peer: boot failed on the injected NVS fault: %s\n",
                   failed.detail);
      esp_restart();
    }
    fatal(failed.detail);
  };
  const DeviceSecurity security = setup.devram ? DeviceSecurity::DevRam : DeviceSecurity::Member;
  Status status = device.open_storage(setup.gateway ? profile::Role::Gateway : profile::kRole,
                                      security);
  if (!status) boot_failed(status);
  static routeloom::sdkv1::RtcSessionImage sleep_image{};
  DeviceConfig config{};
  config.sleep_image = &sleep_image;
  config.log_tag = "mesh_peer";
  config.role = setup.gateway ? profile::Role::Gateway : profile::kRole;
  config.security = security;
  if (setup.devram) {
    config.dev_psk.fill(0x42);
    config.config_authority = 1;
  }
  config.mac = setup.mac;
  config.role_capability =
      setup.join_cap != 0 ? setup.join_cap : profile::role_mask(config.role);
  config.requested_role = setup.role;
  config.flat_group_routing = setup.flat;
  config.remote_config = setup.remote_config;
  config.channel_plan = setup.channel_plan;
  config.radio.node.network = setup.netlow;
  config.radio.node.node = setup.node;
  if (!setup.flat) {
    config.radio.node.route_gateways[0] = setup.gw1;
    if (setup.gw2 != kInvalidNodeId) config.radio.node.route_gateways[1] = setup.gw2;
  }
  config.radio.node.route_advertisement_period_ms = 5000;
  config.radio.node.route_lifetime_ms = setup.flat ? 15000 : 90000;
  config.radio.channel = setup.channel;
  config.radio.max_tx_power_qdbm = 80;
  if (setup.gateway) {
    config.usb = &usb_stream;
    config.usb_secret = ByteView{setup.usb_secret.data(), setup.usb_secret.size()};
    config.usb_capability = setup.usb_cap;
    // Deterministic device nonce from the peer seed (firmware draws it from
    // the post-RF entropy; the harness needs repeatability).
    config.usb_device_nonce = setup.seed ^ 0xD15EA5ED00B1E5ULL;
  }
  status = device.begin(config, now);
  if (gpio_fail_call != 0) {
    if (status.ok() || status.code != StatusCode::RadioFailure ||
        std::strcmp(status.detail, "rf switch GPIO setup failed") != 0 ||
        idf_stub::wifi_init_called() || idf_stub::log_contains("rf switch: enabled")) {
      fatal("GPIO failure did not stop RF startup");
    }
    return 0;
  }
  if (!status) boot_failed(status);
  if (antenna_level != -2) {
    if (!idf_stub::board_rf_before_wifi(antenna_level)) fatal("board RF startup ordering");
    if (antenna_level < 0) {
      if (idf_stub::log_contains("rf switch: enabled")) fatal("unexpected RF switch log");
    } else if (!idf_stub::log_contains(antenna_level == 0
                                         ? "rf switch: enabled, antenna: internal"
                                         : "rf switch: enabled, antenna: external")) {
      fatal("missing RF switch antenna log");
    }
    return 0;
  }
  if (!idf_stub::log_contains(setup.devram ? "security profile: Development"
                                         : "security profile: Candidate")) {
    fatal("boot security profile is not visible");
  }
  EspNowSecurityOwner& owner = DeviceTestAccess::owner(device);
  Sdkv1Stores& stores = DeviceTestAccess::stores(device);
  EspNowRuntime& runtime = DeviceTestAccess::runtime(device);
  UsbBridge* bridge = DeviceTestAccess::bridge(device);
  mesh_c_app_t c_app{};
  if (setup.c_app) {
    if (setup.gateway) fatal("--c-app on the gateway");
    c_app.membership_events = events.membership_events;
    c_app.last_cause = events.last_cause;
    c_app.op_last = events.op_last;
    c_app.op_result = events.op_result;
    c_app.connectivity_events = events.connectivity_events;
    c_app.reentry_calls = events.reentry_calls;
    c_app.reentry_busy = events.reentry_busy;
    rl_dev_observer_t c_observer;
    mesh_c_app_observer(&c_app, &c_observer);
    rl_dev_observer_t invalid = c_observer;
    invalid.struct_size = sizeof(invalid) - 1;
    if (device_c_bind(device, &invalid) != nullptr) fatal("short C observer accepted");
    invalid = c_observer;
    invalid.version = RL_DEV_API_VERSION + 1;
    if (device_c_bind(device, &invalid) != nullptr) fatal("unknown C observer accepted");
    c_app.device = device_c_bind(device, &c_observer);
    if (c_app.device == nullptr) fatal("valid C observer refused");
    if (device_c_bind(device, nullptr) != nullptr) fatal("second C binding accepted");
    g_c_app = &c_app;
    // The harness tee stays first so the snapshot sees every message.
    observer.chain(DeviceTestAccess::app(device));
    device.observe(&observer);
  }

  SleepPort sleep_port(runtime);
  std::array<std::uint8_t, routeloom::sdkv1::kRtcSessionRecordSize> rtc_bytes{};
  routeloom::sdkv1::BufferRtcSessionPort rtc({rtc_bytes.data(), rtc_bytes.size()});
  sleep_port.adapter.bind_owner(owner, &rtc);
  routeloom::espnow::NvsBlobNamespace power_namespace;
  if (!power_namespace.open(routeloom::espnow::kSecurityNvsPartition, "rlpwrmem"))
    fatal("power namespace");
  routeloom::sdkv1::BlobPowerStorage power_storage(power_namespace);
  routeloom::PowerCoordinator power(routeloom::PowerConfig{}, runtime.node(), sleep_port,
                                    power_storage, DeviceTestAccess::power_events());
  bool power_bound = false;
  const std::uint32_t send_count_base = idf_stub::send_count();
  AppTx app_tx[kAppTxMax]{};
  GatewayTx gw_tx{};
  GatewayTxObserver gw_observer(gw_tx);

  // Pre-provisioned peers boot with an RLS1 already committed; the first
  // pump turns adopt it like a field reboot. The harness learns the
  // adoption from the G snapshots.
  for (;;) {
    std::uint8_t head[2];
    if (!read_exact(head, 2)) return 0;
    const std::size_t length = static_cast<std::size_t>(head[0]) |
                               (static_cast<std::size_t>(head[1]) << 8);
    if (length == 0 || length > kRpcMax) fatal("rpc bound");
    Bytes payload(length);
    if (!read_exact(payload.data(), length)) return 0;
    switch (payload[0]) {
      case 'd': {
        if (length != 1) fatal("bad d");
        Bytes reply{'d'};
        put_u64(reply, device.next_deadline(now));
        write_frame(reply);
        break;
      }
      case 's': {
        if (length != 18) fatal("bad s");
        const std::uint64_t at = ([&] {
          std::uint64_t v = 0;
          for (unsigned i = 0; i < 8; ++i) v |= std::uint64_t{payload[2 + i]} << (8 * i);
          return v;
        }());
        const std::uint64_t duration = ([&] {
          std::uint64_t v = 0;
          for (unsigned i = 0; i < 8; ++i) v |= std::uint64_t{payload[10 + i]} << (8 * i);
          return v;
        }());
        if (at < now) fatal("sleep clock regressed");
        now = at;
        idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
        Status status = Status::success();
        if (payload[1] == 0) {
          if (!power_bound) {
            status = device.bind_sleep(power, routeloom::ResetCause::ColdBoot, {}, now);
            power_bound = status.ok();
          }
          if (status) {
            routeloom::SleepRequest request{};
            request.wake.wake_after_ms = duration;
            status = device.prepare_sleep(request);
          }
        } else if (payload[1] == 1) {
          status = device.enter_sleep(device.sleep_ticket());
        } else if (payload[1] == 2) {
          runtime.set_radio_deadline(UINT64_MAX);
          status =
              device.wake(routeloom::ResetCause::DeepSleepWake, {duration, duration, true}, now);
        } else if (payload[1] == 3) {
          status = device.abort_sleep();
        } else if (payload[1] == 5) {
          runtime.set_radio_deadline(now > UINT64_MAX - duration ? UINT64_MAX : now + duration);
        } else if (payload[1] != 4)
          fatal("sleep operation");
        Bytes reply{'s', static_cast<std::uint8_t>(status.code),
                    static_cast<std::uint8_t>(power.state()),
                    static_cast<std::uint8_t>(device.sleep_ticket().issued),
                    static_cast<std::uint8_t>(owner.coordinator().snapshot().sleeping)};
        put_u64(reply, power.stats().sleeps);
        put_u64(reply, power.stats().wakes);
        reply.push_back(static_cast<std::uint8_t>(rtc_bytes[0] != 0));
        put_u32(reply, idf_stub::send_count());
        write_frame(reply);
        break;
      }
      case 'T': {
        if (length != 9) fatal("bad T");
        std::uint64_t next = 0;
        for (int i = 0; i < 8; ++i) {
          next |= static_cast<std::uint64_t>(payload[1 + i]) << (8 * i);
        }
        if (next < now) fatal("clock regressed");
        now = next;
        idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
        applied.now = now;
        device.step(now);
        if (!applied.open.empty()) applied.poll(device, now);
        if (setup.c_app) {
          sync_c_app();
          applied.requests = c_app.applied_requests;
          applied.completed = c_app.applied_completed;
          applied.refused = c_app.applied_refused;
        }
        if (gw_tx.endpoint_valid) {
          GatewayDelivery& delivery = *device.gateway();
          const EndpointState state = delivery.endpoint_state(gw_tx.endpoint);
          gw_tx.endpoint_state = static_cast<std::uint8_t>(state);
          if (gw_tx.want_send && state == EndpointState::Ready) {
            gw_tx.want_send = false;
            const Status sent =
                delivery.send(gw_tx.endpoint, ByteView{gw_tx.payload.data(), gw_tx.payload.size()},
                              /*lifetime_ms=*/5000, now, gw_tx.id);
            gw_tx.sent = sent.ok();
            if (!sent) gw_tx.send_state = static_cast<std::uint8_t>(GatewaySendState::Failed);
          } else if (state == EndpointState::Failed || state == EndpointState::Stale) {
            gw_tx.want_send = false;
            gw_tx.endpoint_valid = false;
            delivery.endpoint_release(gw_tx.endpoint);
          }
          // Live states until the observer reports the terminal one.
          if (gw_tx.sent &&
              gw_tx.send_state < static_cast<std::uint8_t>(GatewaySendState::EndpointReceived)) {
            gw_tx.send_state = static_cast<std::uint8_t>(delivery.send_result(gw_tx.id).state);
          }
        }
        idf_stub::TxFrame tx{};
        while (idf_stub::take_tx(tx)) {
          Bytes frame;
          frame.push_back('X');
          frame.insert(frame.end(), tx.dest, tx.dest + 6);
          frame.insert(frame.end(), tx.bytes, tx.bytes + tx.length);
          write_frame(frame);
        }
        const Bytes usb_tx = usb_stream.take();
        for (std::size_t off = 0; off < usb_tx.size();) {
          const std::size_t chunk =
              usb_tx.size() - off > kUsbChunkMax ? kUsbChunkMax : usb_tx.size() - off;
          Bytes frame;
          frame.push_back('B');
          frame.insert(frame.end(), usb_tx.begin() + static_cast<std::ptrdiff_t>(off),
                       usb_tx.begin() + static_cast<std::ptrdiff_t>(off + chunk));
          write_frame(frame);
          off += chunk;
        }
        for (std::size_t i = 0; i < kAppTxMax; ++i) {
          // A refused send keeps its refusal (it never had a delivery).
          if (!app_tx[i].used || app_tx[i].id.sequence == 0) continue;
          // The production delivery table is bounded; retain a terminal
          // observation before its id ages out of that table.
          if (app_tx[i].state == DeliveryState::Delivered ||
              app_tx[i].state == DeliveryState::Failed ||
              app_tx[i].state == DeliveryState::Expired ||
              app_tx[i].state == DeliveryState::CancelledBeforeTx ||
              app_tx[i].state == DeliveryState::Indeterminate) {
            continue;
          }
          DeliveryResult result = device.delivery(app_tx[i].id);
          if (result.state == DeliveryState::Empty) {
            // Evicted from the bounded delivery table: its last reported
            // state is the one the observer saw.
            for (auto it = observer.delivery_events_.rbegin();
                 it != observer.delivery_events_.rend(); ++it) {
              if (it->id == app_tx[i].id) {
                result = *it;
                break;
              }
            }
          }
          app_tx[i].state = result.state;
          std::strncpy(app_tx[i].reason, result.reason != nullptr ? result.reason : "?",
                       sizeof(app_tx[i].reason) - 1);
          app_tx[i].reason[sizeof(app_tx[i].reason) - 1] = '\0';
        }
        emit_snapshot(owner, stores, runtime, bridge, observer, app_tx, send_count_base,
                      setup.world_nodes, gw_tx, DeviceTestAccess::gateway(device), device,
                      events, applied);
        write_frame(Bytes{'D'});
        break;
      }
      case 'r': {
        Bytes reply{'r'};
        put_u32(reply, observer.receipts_overflow_);
        reply.push_back(static_cast<std::uint8_t>(observer.receipts_size_));
        for (std::size_t i = 0; i < observer.receipts_size_; ++i) {
          const auto& receipt = observer.receipts_[i];
          put_u64(reply, receipt.source);
          put_u32(reply, receipt.key.id.session);
          put_u64(reply, receipt.key.id.sequence);
          reply.push_back(receipt.length);
          reply.insert(reply.end(), receipt.payload.begin(),
                       receipt.payload.begin() + receipt.length);
        }
        observer.receipts_size_ = 0;
        observer.receipts_overflow_ = 0;
        write_frame(reply);
        break;
      }
      case 'R': {
        if (length < 14) fatal("bad R");
        if (!idf_stub::inject_rx(payload.data() + 1, payload.data() + 7, payload.data() + 13,
                                 length - 13)) {
          fatal("rx rejected");
        }
        break;
      }
      case 'U': {
        if (!setup.gateway) fatal("usb on a member");
        if (length > 1) {
          device.usb_receive(ByteView{payload.data() + 1, length - 1}, now);
        }
        break;
      }
      case 'K': {
        for (std::size_t i = 1; i < length; ++i) {
          idf_stub::complete_send(payload[i] != 0);
        }
        break;
      }
      case 'S':
      case 'A':
      case 'B': {
        // S: reliable, A: class + coalesce key, B: APPLIED with a lease.
        const std::size_t head = payload[0] == 'S' ? 9 : payload[0] == 'A' ? 12 : 25;
        const std::size_t max = payload[0] == 'B' ? kAppliedUserPayloadMax : kMaxApplicationPayload;
        if (length <= head || length - head > max) fatal("bad S/A/B");
        NodeId dst = 0;
        for (int i = 0; i < 8; ++i) dst |= static_cast<NodeId>(payload[1 + i]) << (8 * i);
        AppTx* slot = nullptr;
        for (auto& entry : app_tx) {
          if (!entry.used) {
            slot = &entry;
            break;
          }
        }
        if (slot == nullptr) {
          for (auto& entry : app_tx) {
            if (entry.state == DeliveryState::Delivered || entry.state == DeliveryState::Failed ||
                entry.state == DeliveryState::Expired ||
                entry.state == DeliveryState::CancelledBeforeTx ||
                entry.state == DeliveryState::Indeterminate ||
                entry.state == DeliveryState::Empty) {
              slot = &entry;
              break;
            }
          }
        }
        if (slot == nullptr) fatal("app tx full");
        SendOptions options{};
        options.lifetime_ms = 30000;
        MessageId id{};
        const ByteView body{payload.data() + head, length - head};
        if (setup.c_app) {
          rl_message_id_t c_id{};
          if (payload[0] == 'B') {
            status.code = static_cast<StatusCode>(mesh_c_app_send_applied(
                &c_app, dst, payload.data() + 9, body.data, body.size, &c_id));
          } else {
            const std::uint8_t delivery = payload[0] == 'A' ? payload[9] : 1;
            const std::uint16_t key =
                payload[0] == 'A' ? static_cast<std::uint16_t>(payload[10] | (payload[11] << 8)) : 0;
            status.code = static_cast<StatusCode>(mesh_c_app_send(
                &c_app, dst, body.data, body.size, delivery, key,
                payload[0] == 'A' ? kMaxMessageLifetimeMs : 30000, &c_id));
          }
          status.detail = rl_status_code_name(static_cast<rl_status_code_t>(status.code));
          id = MessageId{c_id.session, c_id.sequence};
        } else if (payload[0] == 'A') {
          options.lifetime_ms = kMaxMessageLifetimeMs;
          options.delivery = static_cast<DeliveryClass>(payload[9]);
          options.coalesce_key = static_cast<std::uint16_t>(payload[10] | (payload[11] << 8));
          status = device.send(dst, body, options, id);
        } else if (payload[0] == 'B') {
          ExecutionLease lease{};
          std::memcpy(lease.data(), payload.data() + 9, lease.size());
          options.delivery = DeliveryClass::Applied;
          options.lifetime_ms = 10000;
          status = device.send_applied(dst, body, lease, options, id);
        } else {
          status = device.send(dst, body, options, id);
        }
        slot->used = true;
        slot->id = id;
        if (status) {
          slot->state = device.delivery(id).state;
          std::strncpy(slot->reason, "SENT", sizeof(slot->reason) - 1);
        } else {
          slot->state = DeliveryState::Empty;
          std::strncpy(slot->reason, status.detail != nullptr ? status.detail : "refused",
                       sizeof(slot->reason) - 1);
        }
        slot->reason[sizeof(slot->reason) - 1] = '\0';
        break;
      }
      case 'L':
      case 'Y': {
        OperationId op = 0;
        if (setup.c_app) {
          status.code = static_cast<StatusCode>(mesh_c_app_operation(&c_app, payload[0] == 'L', &op));
        } else {
          status = payload[0] == 'L' ? device.leave(op) : device.request_join(op);
        }
        if (status && payload[0] == 'L' && device.membership().stage != MembershipStage::Leaving) {
          fatal("leave must expose its durable intent immediately");
        }
        // Tracked sends a leave cancelled report before the restart.
        for (auto& entry : app_tx) {
          if (!entry.used || entry.id.sequence == 0) continue;
          const DeliveryResult result = device.delivery(entry.id);
          entry.state = result.state;
          std::strncpy(entry.reason, result.reason != nullptr ? result.reason : "?",
                       sizeof(entry.reason) - 1);
          entry.reason[sizeof(entry.reason) - 1] = '\0';
        }
        Bytes reply{payload[0] == 'L' ? std::uint8_t{'l'} : std::uint8_t{'y'},
                    static_cast<std::uint8_t>(status.code)};
        put_u32(reply, op);
        write_frame(reply);
        break;
      }
      case 'C': {
        ExecutionLease lease = runtime.node().applied_lease();
        if (setup.c_app && rl_dev_applied_lease(c_app.device, lease.data()) != RL_STATUS_OK) {
          fatal("c app lease");
        }
        Bytes reply{'c'};
        reply.insert(reply.end(), lease.begin(), lease.end());
        write_frame(reply);
        break;
      }
      case 'D': {
        if (length != 5) fatal("bad D");
        applied.delay_ms = static_cast<MonotonicMs>(payload[1] | (payload[2] << 8) |
                                                    (payload[3] << 16) |
                                                    (static_cast<std::uint32_t>(payload[4]) << 24));
        if (setup.c_app) {
          c_app.delay_ms = static_cast<std::uint32_t>(applied.delay_ms);
          break;
        }
        status = device.set_applied_sink(&applied);
        if (!status) fatal(status.detail);
        break;
      }
      case 'G':
        if (length != 2) fatal("bad G");
        events.probe = payload[1] != 0;
        break;
      case 'X': {
        if (length != 9 && length != 13) fatal("bad X");
        const auto u32_at = [&](std::size_t at) {
          return static_cast<std::uint32_t>(payload[at] | (payload[at + 1] << 8) |
                                            (payload[at + 2] << 16) |
                                            (static_cast<std::uint32_t>(payload[at + 3]) << 24));
        };
        JoinPolicy policy{};
        policy.removal_holdoff_s = u32_at(1);
        if (length == 13) policy.isolation_notice_s = u32_at(9);
        std::uint32_t revision = 0;
        status = device.set_join_policy(policy, u32_at(5), revision);
        Bytes reply{'x', static_cast<std::uint8_t>(status.code)};
        put_u32(reply, revision);
        write_frame(reply);
        break;
      }
      case 'V': {
        if (length != 2) fatal("bad V");
        const std::uint8_t index = payload[1];
        const routeloom::espnow::MacAddress mac{{0x02, 0xEE, 0, 0, 0, index}};
        const Status registered = runtime.register_neighbor(
            0x00A1000000001000ULL + index, mac, 1);
        write_frame(Bytes{'v', registered.ok() ? std::uint8_t{1} : std::uint8_t{0},
                          static_cast<std::uint8_t>(idf_stub::peer_count())});
        break;
      }
      case 'H':
      case 'h': {
        if (length != 10) fatal("bad H");
        const bool tracked = payload[0] == 'h';
        if (tracked) {
          if (payload[1] > kAppTxMax) fatal("tracked burst too large");
          for (auto& entry : app_tx) {
            if (entry.state == DeliveryState::Empty || entry.state >= DeliveryState::Delivered)
              entry = AppTx{};
          }
        }
        NodeId dst = 0;
        for (int i = 0; i < 8; ++i) dst |= static_cast<NodeId>(payload[2 + i]) << (8 * i);
        std::uint8_t accepted = 0;
        Bytes evidence;
        for (std::uint8_t i = 0; i < payload[1]; ++i) {
          const std::uint8_t byte = i;
          SendOptions options{};
          options.lifetime_ms = 30000;
          MessageId id{};
          const Status sent = device.send(dst, ByteView{&byte, 1}, options, id);
          if (sent) ++accepted;
          if (tracked) {
            evidence.push_back(static_cast<std::uint8_t>(sent.code));
            put_u32(evidence, id.session);
            put_u64(evidence, id.sequence);
            if (sent) {
              AppTx* slot = nullptr;
              for (auto& entry : app_tx) {
                if (!entry.used) {
                  slot = &entry;
                  break;
                }
              }
              if (slot == nullptr) fatal("tracked burst evidence full");
              slot->used = true;
              slot->id = id;
              slot->state = device.delivery(id).state;
              std::strncpy(slot->reason, "SENT", sizeof(slot->reason) - 1);
            }
          }
        }
        Bytes reply{'h', accepted,
                    static_cast<std::uint8_t>(runtime.node().congestion_stats().queued)};
        if (tracked) {
          reply.push_back(payload[1]);
          reply.insert(reply.end(), evidence.begin(), evidence.end());
        }
        write_frame(reply);
        break;
      }
      case 'I':
      case 'J': {
        if (length != 2) fatal("bad I/J");
        const std::uint8_t index = payload[1];
        const std::uint8_t mac[6] = {0x02, 0xFD, 0, 0, 0, index};
        esp_err_t result = ESP_FAIL;
        if (payload[0] == 'I') {
          esp_now_peer_info_t info{};
          std::memcpy(info.peer_addr, mac, 6);
          info.ifidx = WIFI_IF_STA;
          result = esp_now_add_peer(&info);
        } else {
          result = esp_now_del_peer(mac);
        }
        write_frame(Bytes{payload[0] == 'I' ? std::uint8_t{'i'} : std::uint8_t{'j'},
                          result == ESP_OK ? std::uint8_t{1} : std::uint8_t{0},
                          static_cast<std::uint8_t>(idf_stub::peer_count())});
        break;
      }
      case 'E':
        if (length != 2) fatal("bad E");
        idf_stub::fail_del_peer(payload[1] != 0);
        break;
      case 'N': {
        Bytes reply;
        reply.push_back('N');
        const Bytes image = encode_nvs_image();
        reply.insert(reply.end(), image.begin(), image.end());
        write_frame(reply);
        break;
      }
      case 'P':
        // A harness-driven power cut (D04 C3): the NVS image persists
        // and the process takes the same reboot marker as a lifecycle
        // esp_restart — the respawned peer recovers from flash through
        // the production boot path, with no test-written state.
        // (noreturn: no break — the marker exits the process.)
        esp_restart();
      case 'F':
        g_cut_after_switching = true;
        break;
      case 'O': {
        if (length < 20 || length - 20 > kMaxApplicationPayload) fatal("bad O");
        NodeId next_hop = 0, dst = 0;
        for (int i = 0; i < 8; ++i) {
          next_hop |= static_cast<NodeId>(payload[1 + i]) << (8 * i);
          dst |= static_cast<NodeId>(payload[9 + i]) << (8 * i);
        }
        wire::PlainFrame plain{};
        plain.header.type = static_cast<FrameType>(payload[17]);
        plain.header.minor = payload[18];
        plain.header.traffic = payload[19];
        plain.header.flags = wire::kFlagEndProtected;
        plain.header.network = static_cast<std::uint32_t>(stores.site().site().network);
        plain.header.origin = setup.node;
        plain.header.destination = dst;
        plain.header.previous_hop = setup.node;
        plain.header.next_hop = next_hop;
        // A test-only message session keeps these ids apart from the node's.
        static std::uint64_t crafted = 0;
        plain.header.message = MessageId{0xC0FFEEU, ++crafted};
        plain.header.remaining_deadline_ms = 5000;
        plain.header.original_lifetime_ms = 5000;
        plain.payload_size = length - 20;
        std::memcpy(plain.payload.data(), payload.data() + 20, plain.payload_size);
        wire::EncodedFrame encoded{};
        status = wire::encode_new(plain, owner.coordinator().session_provider(), encoded);
        if (!status) fatal(status.detail);
        Bytes reply{'o'};
        reply.insert(reply.end(), encoded.bytes.begin(),
                     encoded.bytes.begin() + static_cast<std::ptrdiff_t>(encoded.size));
        write_frame(reply);
        break;
      }
      case 'W': {
        if (length < 3) fatal("bad W");
        g_key_fault_mode = payload[1];
        g_key_fault.assign(reinterpret_cast<const char*>(payload.data() + 2), length - 2);
        break;
      }
      case 'M': {
        if (length < 4 || length - 3 > kGroupPayloadMax) fatal("bad M");
        const GroupId group = static_cast<GroupId>(payload[1] | (payload[2] << 8));
        GroupSendOptions options{};
        MessageId id{};
        status = device.send_group(group, ByteView{payload.data() + 3, length - 3}, options, id);
        if (!status) std::fprintf(stderr, "mesh_peer: group send refused: %s\n", status.detail);
        break;
      }
      case 'Z': {
        if (length < 10 || length - 9 > kGatewayPayloadMaxBytes) fatal("bad Z");
        NodeId gateway_id = 0;
        for (int i = 0; i < 8; ++i) gateway_id |= static_cast<NodeId>(payload[1 + i]) << (8 * i);
        GatewayDelivery* delivery = device.gateway();
        if (delivery == nullptr) fatal("gateway delivery unavailable");
        // A USB gateway's bridge observes its own endpoint.
        if (!setup.gateway) delivery->set_observer(gw_observer);
        gw_tx.payload.assign(payload.begin() + 9, payload.end());
        gw_tx.want_send = true;
        gw_tx.sent = false;
        gw_tx.send_state = 0;
        gw_tx.reason = 0;
        // Reuse the endpoint while its lease still covers a send's lifetime.
        GatewayEndpointInfo info{};
        if (gw_tx.endpoint_valid && gw_tx.gateway == gateway_id &&
            delivery->endpoint_info(gw_tx.endpoint, info) && info.state == EndpointState::Ready &&
            info.lease_deadline_ms > now + 5000) {
          break;
        }
        if (gw_tx.endpoint_valid) delivery->endpoint_release(gw_tx.endpoint);
        gw_tx.gateway = gateway_id;
        const Status resolved =
            delivery->resolve(gateway_id, endpoint::GatewayScope::GatewaySdkRam, HostDigest{},
                              /*resolve_deadline_ms=*/5000, now, gw_tx.endpoint);
        gw_tx.endpoint_valid = resolved.ok();
        gw_tx.want_send = resolved.ok();
        gw_tx.endpoint_state = static_cast<std::uint8_t>(
            resolved.ok() ? EndpointState::Resolving : EndpointState::Failed);
        break;
      }
      case 'Q':
        return 0;
      default:
        fatal("unknown tag");
    }
  }
}
