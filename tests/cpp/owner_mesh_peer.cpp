// Multi-node mesh peer (D04, issue #168): one process runs ONE real
// firmware node — EspNowSecurityOwner + EspNowRuntime + MeshNode over the
// host ESP-IDF stubs, NVS-backed Sdkv1Stores over a fake NVS, and (on a
// gateway) the real UsbBridge. The Rust harness
// (host/routeloom-host/src/site/owner_mesh_interop.rs) spawns one peer
// per node, switches radio frames between them, and relays the gateway's
// USB bytes to the real Site Authority. No mock ACKs: every lifecycle,
// GK and cutover receipt the harness observes comes out of this Owner.
//
// Boot mirrors firmware/{bridge,reference}_node/main/main.cpp: rlboot
// witness, stores open/initialize + boot-session reconcile, owner.begin,
// runtime construction/initialize, entropy.begin, attach_runtime (+
// attach_usb on a gateway), owner.boot, config-sink install, then the
// same pump order (bridge.poll, runtime.poll_once, owner.poll). Radio
// frames leave through the stub's esp_now_send capture and re-enter
// through inject_rx; USB bytes cross the pipe raw.
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
//   N                          dump the fake-NVS image (reply: N <image>)
//   P                          power-cycle: persist the NVS image and take
//                              the reboot marker (exit 42), like a field
//                              power cut mid-RAM — the respawn recovers
//                              through the production boot path only
//   F                          arm one power cut after RLX1 Switching commits
//                              (exit 43); the saved NVS is the real write
//   Q                          quit (exit 0)
//
// C++ -> Rust, emitted after each T in this order:
//
//   X <dst_mac 6><frame>       one captured radio TX frame, FIFO
//   B <usb bytes>              USB TX bytes (chunked to the frame bound)
//   G <snapshot>               fixed-shape state snapshot (see emit_g)
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
// dropped-offer counters — the ZT attempt evidence)
//
// Setup arrives on argv (all integers accept 0x hex; blobs are hex):
//
//   --node <u64> --mac <12hex> --role <u8> --t0 <ms> --seed <u64>
//   --gateway | --member
//   --usb-secret <hex>   (gateway: the USB dev secret, test material)
//   --cap <u32>           (gateway: USB HelloAck capability bitmap)
//   --channel <u8>        (operating channel, default 6)
//   --netlow <u32>        (wire network low32 before adoption, like the
//                         firmware's trust/Kconfig image; the adopted
//                         network comes from the real ApplyMemberConfig)
//   --gw1 <u64> --gw2 <u64>  (scoped route gateways for the pre-adoption
//                            node config; the adopted config comes from
//                            the real ApplyMemberConfig path)
//   --nvs-load <file>    (optional fake-NVS preload image)
//   --flash <file>       (optional 4096 B legacy slot image: identity
//                         slots, site slots — imported into the fake NVS
//                         so a member provisioned by the joiner peer can
//                         boot here; erased (0xFF) slots stay missing keys)
//   --flash-ext <file>   (optional 4498 B legacy image: RRS slots, then
//                         lifecycle journal slots)
//   --nvs-save <file>    (esp_restart writes the image here, exits 42)
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
#include "nvs.h"
#include "psa/crypto.h"
#include "routeloom/aead_gcm.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/edhoc.hpp"
#include "routeloom/espnow_autonomy.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/sdkv1_blob_storage.hpp"
#include "routeloom/sdkv1_group_keys.hpp"
#include "routeloom/sdkv1_lifecycle_store.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/usb_bridge.hpp"

#include "../../firmware/bridge_node/main/bridge_network.hpp"
#include "idf_stubs.hpp"

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
std::string g_nvs_save_path;
bool g_cut_after_switching{false};

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
  if (key == nullptr || (data == nullptr && length != 0)) return ESP_ERR_INVALID_ARG;
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  (*blobs)[key] = std::vector<std::uint8_t>(bytes, bytes + length);
  return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key) {
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
  SpaceMap* spaces = nullptr;
  BlobMap* blobs = nullptr;
  if (!nvs_lookup(handle, spaces, blobs)) return ESP_ERR_INVALID_ARG;
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

namespace routeloom::espnow {

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
    constexpr std::size_t kExtBytes = 2 * 640 + 2 * (88 + 1521);
    if (image.size() != kExtBytes) fatal("bad flash-ext image size");
    if (kRevocationSlotBytes != 640 || kLifecycleSlotBytes != 88 + 1521) {
      fatal("ext slot size mismatch");
    }
    const std::uint8_t* base = image.data();
    import_flash_slot(kRevocationNamespace, kRevocationKey0, base, kRevocationSlotBytes);
    import_flash_slot(kRevocationNamespace, kRevocationKey1, base + 640, kRevocationSlotBytes);
    import_flash_slot(kLifecycleNamespace, kLifecycleKey0, base + 1280, kLifecycleSlotBytes);
    import_flash_slot(kLifecycleNamespace, kLifecycleKey1, base + 1280 + kLifecycleSlotBytes,
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
  MonotonicMs t0{0};
  std::uint64_t seed{0};
  bool gateway{false};
  Bytes usb_secret;
  std::uint32_t usb_cap{0};
  std::uint8_t channel{6};
  std::uint32_t netlow{0};
  NodeId gw1{routeloom::kInvalidNodeId};
  NodeId gw2{routeloom::kInvalidNodeId};
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
    } else if (arg == std::string("--t0") && take_arg(argc, argv, i, value)) {
      setup.t0 = parse_u64(value);
      have_t0 = true;
    } else if (arg == std::string("--seed") && take_arg(argc, argv, i, value)) {
      setup.seed = parse_u64(value);
      have_seed = true;
    } else if (arg == std::string("--gateway")) {
      setup.gateway = true;
      have_mode = true;
    } else if (arg == std::string("--member")) {
      setup.gateway = false;
      have_mode = true;
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
    } else if (arg == std::string("--nvs-load") && take_arg(argc, argv, i, value)) {
      setup.nvs_load = value;
    } else if (arg == std::string("--flash") && take_arg(argc, argv, i, value)) {
      setup.flash = value;
    } else if (arg == std::string("--flash-ext") && take_arg(argc, argv, i, value)) {
      setup.flash_ext = value;
    } else if (arg == std::string("--nvs-save") && take_arg(argc, argv, i, value)) {
      g_nvs_save_path = value;
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
  if (setup.gateway && setup.usb_secret.empty()) fatal("gateway needs --usb-secret");
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
  explicit TeeObserver(routeloom::NodeObserver* next) noexcept : next_(next) {}

  void on_message(const routeloom::MessageKey& key, NodeId source,
                  ByteView payload) noexcept override {
    ++rx_count_;
    rx_src_ = source;
    rx_len_ = payload.size > kAppRxKeep ? kAppRxKeep : payload.size;
    std::memcpy(rx_, payload.data, rx_len_);
    if (next_ != nullptr) next_->on_message(key, source, payload);
  }
  void on_delivery(const routeloom::DeliveryResult& result) noexcept override {
    delivery_events_.push_back(result);
    if (next_ != nullptr) next_->on_delivery(result);
  }
  void on_diagnostic(const char* reason, NodeId peer,
                     const routeloom::MessageId* id) noexcept override {
    if (next_ != nullptr) next_->on_diagnostic(reason, peer, id);
  }

  std::uint32_t rx_count_{0};
  NodeId rx_src_{routeloom::kInvalidNodeId};
  std::uint8_t rx_[kAppRxKeep]{};
  std::size_t rx_len_{0};
  std::vector<routeloom::DeliveryResult> delivery_events_;

 private:
  routeloom::NodeObserver* next_;
};

struct AppTx {
  bool used{false};
  routeloom::MessageId id{};
  routeloom::DeliveryState state{routeloom::DeliveryState::Empty};
  char reason[13]{};
};

void emit_snapshot(routeloom::espnow::EspNowSecurityOwner& owner,
                   routeloom::espnow::Sdkv1Stores& stores,
                   const routeloom::espnow::EspNowRuntime& runtime,
                   const routeloom::usb::UsbBridge* bridge, const TeeObserver& observer,
                   AppTx* app_tx, std::uint32_t send_count_base) {
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
  write_frame(out);
}

}  // namespace

int main(int argc, char** argv) {
  using namespace routeloom;
  using namespace routeloom::espnow;
  using namespace routeloom::sdkv1;
  using namespace routeloom::usb;

  const Setup setup = parse_argv(argc, argv);
  if (!setup.nvs_load.empty()) {
    if (!setup.flash.empty() || !setup.flash_ext.empty()) fatal("nvs-load with flash import");
    decode_nvs_image(read_file_bytes(setup.nvs_load.c_str()));
  }
  import_flash_images(setup.flash, setup.flash_ext);
  mesh_peer_seed_entropy(setup.seed);

  idf_stub::reset();
  idf_stub::set_mac(setup.mac.data());
  idf_stub::set_now_us(static_cast<std::int64_t>(setup.t0) * 1000);
  MonotonicMs now = setup.t0;

  // Firmware boot order (bridge_node / reference_node main): rlboot
  // witness, stores, owner.begin, runtime, entropy.begin, attaches,
  // owner.boot, config sink, then the pump.
  std::uint32_t message_session = 0;
  Status status = next_boot_session(message_session);
  if (!status) fatal(status.detail);
  Sdkv1Stores stores(setup.gateway ? kResumeGatewaySlots : kResumeNodeSlots);
  status = stores.open(kSecurityNvsPartition);
  if (!status) fatal(status.detail);
  status = stores.initialize();
  if (!status) fatal(status.detail);
  status = reconcile_boot_session(stores.site(), message_session);
  if (!status) fatal(status.detail);

  EspNowSecurityOwner::Config owner_config{};
  owner_config.local_node = setup.node;
  owner_config.local_mac = setup.mac;
  owner_config.joiner.node = setup.node;
  owner_config.joiner.mac = setup.mac;
  owner_config.joiner.capability =
      kMemberRoleEndpoint | kMemberRoleRelay | (setup.gateway ? kMemberRoleGateway : 0);
  owner_config.joiner.requested_role = setup.role;
  owner_config.log_tag = "mesh_peer";
  owner_config.gateway = setup.gateway;

  EspOwnerEntropy entropy;
  EspNowSecurityOwner owner{};
  status = owner.begin(stores, entropy, owner_config);
  if (!status) fatal(status.detail);

  PipeByteStream usb_stream;
  UsbBridge::Config bridge_config{};
  bridge_config.secret = ByteView{setup.usb_secret.data(), setup.usb_secret.size()};
  bridge_config.node = setup.node;
  bridge_config.network = bridge_node::usb_boot_network(stores.site(), setup.netlow);
  bridge_config.boot_id = message_session;
  bridge_config.capability = setup.usb_cap;
  // Deterministic device nonce from the peer seed (firmware samples
  // esp_random post-radio; the harness needs repeatability).
  bridge_config.device_nonce = setup.seed ^ 0xD15EA5ED00B1E5ULL;
  UsbBridge bridge(bridge_config, usb_stream);
  TeeObserver observer(setup.gateway ? static_cast<NodeObserver*>(&bridge) : nullptr);

  EspNowRuntimeConfig radio_config{};
  radio_config.node.network = static_cast<std::uint32_t>(bridge_config.network);
  radio_config.node.node = setup.node;
  radio_config.node.message_session = message_session;
  radio_config.node.boot_session = message_session;
  radio_config.node.boot_incarnation = message_session;
  radio_config.node.route_generation = message_session;
  radio_config.node.link_epoch = message_session;
  radio_config.node.end_epoch = message_session;
  radio_config.node.route_gateways[0] = setup.gw1;
  if (setup.gw2 != kInvalidNodeId) radio_config.node.route_gateways[1] = setup.gw2;
  radio_config.node.route_advertisement_period_ms = 5000;
  radio_config.node.route_lifetime_ms = 90000;
  radio_config.channel = setup.channel;
  radio_config.max_tx_power_qdbm = 80;
  EspNowRuntime runtime(radio_config, owner.session_provider(), observer);
  status = runtime.initialize();
  if (!status) fatal(status.detail);
  status = entropy.begin();
  if (!status) fatal(status.detail);
  status = owner.attach_runtime(runtime);
  if (!status) fatal(status.detail);
  if (setup.gateway) {
    status = owner.attach_usb(bridge);
    if (!status) fatal(status.detail);
  }
  status = owner.boot(message_session, /*rlboot_prepared=*/true, setup.gateway, now);
  if (!status) fatal(status.detail);
  runtime.node().set_config_sink(owner.authority_mesh_sink());
  if (setup.gateway) bridge.set_mesh(&runtime.node());

  const std::uint32_t send_count_base = idf_stub::send_count();
  AppTx app_tx[kAppTxMax]{};

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
      case 'T': {
        if (length != 9) fatal("bad T");
        std::uint64_t next = 0;
        for (int i = 0; i < 8; ++i) {
          next |= static_cast<std::uint64_t>(payload[1 + i]) << (8 * i);
        }
        if (next < now) fatal("clock regressed");
        now = next;
        idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
        if (setup.gateway) bridge.poll(now);
        runtime.poll_once();
        owner.poll(now);
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
          if (!app_tx[i].used) continue;
          const DeliveryResult result = runtime.node().delivery(app_tx[i].id);
          app_tx[i].state = result.state;
          std::strncpy(app_tx[i].reason, result.reason != nullptr ? result.reason : "?",
                       sizeof(app_tx[i].reason) - 1);
          app_tx[i].reason[sizeof(app_tx[i].reason) - 1] = '\0';
        }
        emit_snapshot(owner, stores, runtime, setup.gateway ? &bridge : nullptr, observer, app_tx,
                      send_count_base);
        write_frame(Bytes{'D'});
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
          bridge.on_bytes(ByteView{payload.data() + 1, length - 1}, now);
        }
        break;
      }
      case 'K': {
        for (std::size_t i = 1; i < length; ++i) {
          idf_stub::complete_send(payload[i] != 0);
        }
        break;
      }
      case 'S': {
        if (length < 10 || length - 9 > kMaxApplicationPayload) fatal("bad S");
        NodeId dst = 0;
        for (int i = 0; i < 8; ++i) dst |= static_cast<NodeId>(payload[1 + i]) << (8 * i);
        AppTx* slot = nullptr;
        for (auto& entry : app_tx) {
          if (!entry.used) {
            slot = &entry;
            break;
          }
        }
        if (slot == nullptr) fatal("app tx full");
        SendOptions options{};
        options.lifetime_ms = 30000;
        MessageId id{};
        status = runtime.send_application(
            dst, ByteView{payload.data() + 9, length - 9}, options, id);
        slot->used = true;
        slot->id = id;
        if (status) {
          slot->state = runtime.node().delivery(id).state;
          std::strncpy(slot->reason, "SENT", sizeof(slot->reason) - 1);
        } else {
          slot->state = DeliveryState::Empty;
          std::strncpy(slot->reason, status.detail != nullptr ? status.detail : "refused",
                       sizeof(slot->reason) - 1);
        }
        slot->reason[sizeof(slot->reason) - 1] = '\0';
        break;
      }
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
      case 'Q':
        return 0;
      default:
        fatal("unknown tag");
    }
  }
}
