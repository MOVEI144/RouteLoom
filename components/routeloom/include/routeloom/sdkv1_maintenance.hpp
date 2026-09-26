#pragma once

// Factory maintenance console engine (docs/design/sdk-v1/07 §6 steps 1-5,
// 08 P7): the portable logic behind the firmware's USB-console maintenance
// verb (sdk-completion/04 §4.4 P-A2). The office flow is: `keygen` answers
// the office challenge with a device-generated key's proof of possession,
// the office issues the DevCert plus the `routeloom-identity-bundle-v1`
// bundle, and `identity` seals that bundle into `rlident` as the committed
// RLI1 twin pair. The ESP-IDF side (USB line I/O, entropy, NVS stores) is a
// thin runner over this class; every rule here is host-tested.
//
// Protocol (one line in, one line out, no newlines inside; hex is
// lowercase on output and case-insensitive on input):
//   status                                    -> OK identity=<none|sealed> pending=<0|1> locked=<0|1>
//                                              (+ node=<16hex> kid=<64hex> serial=<u32>
//                                                devcert_sha256=<64hex> when sealed)
//   keygen <node:16hex> <challenge:64hex>    -> OK pop_hex=<366hex>
//   identity <bundle:hex of the bundle JSON> -> OK sealed kid=<64hex>
//   lock <kid:64hex>                          -> OK locked kid=<64hex>
//   deprovision                               -> OK deprovision node=<16hex|none>
//                                                kid=<64hex|none> nonce=<32hex>
//   deprovision_confirm <nonce:32hex> <kid:64hex|none>
//                                             -> OK deprovisioned node=<16hex|none>
// A sealed `status` is the manufacturing receipt (non-secret identifiers
// only): the office matches the device against its inventory row after a
// lost response, after a lock, after a USB mixup. `lock` is the idempotent
// finalize bound to the matched seal; an identical `identity` resend
// replays the seal success instead of refusing. The deprovision pair is
// the formal reprovision entry: it returns a provisioned device to
// unprovisioned (v1 never reissues a revoked NodeId, so the device
// reprovisions with a NEW NodeId afterwards). The challenge names the
// sealed target and carries a single-use nonce; the confirm must echo
// both. v1 authentication is the physical maintenance entry (this console
// only runs pre-RF in a maintenance build) plus that freshness/target
// binding — a CA-signed authorization order is impossible, since the
// device holds no Device CA key (sdkv1_records.hpp). The wipe covers
// identity, site, revocation, local-revocation, resume and lifecycle
// state (identity last, so a power cut stays re-runnable); the rlboot
// witness is kept (monotonic).
// Failures are `ERR <token>` with a stable token: `locked` (a locked seal
// refuses every verb except `status`, `lock` and the deprovision pair),
// `invalid_argument`, `entropy_not_ready` (keygen before entropy READY,
// security §9), `already_provisioned` (keygen, or an `identity` bundle that
// differs from the seal), `no_identity` (lock without a seal),
// `store_unavailable` (quarantined/uncertain/fault), `no_pending_key`
// (identity without a keygen first), `node_mismatch`, `key_mismatch`
// (bundle/DevCert key is not the pending one, a lock kid is not the
// sealed one, or a deprovision confirm names the wrong target),
// `seal_failed`, `lock_failed`, `unsupported` (deprovision without the
// wipe set), `no_challenge` (a confirm with no live challenge),
// `wipe_failed`, `internal_error`.
// State refusals dominate input errors (a locked device reports `locked`
// even for a malformed line — unless the line names `status`, `lock` or
// the deprovision pair, which validate their arguments normally);
// process_line itself returns Ok whenever a response line was produced.
//
// Keygen draws one 32-byte scalar per attempt from the entropy port and
// refuses on the first fill error — key generation before entropy READY is
// refused (security §9), never retried into a weak key. The generated key
// lives in RAM only until `identity` seals it; a reboot loses it (the old
// PoP is then useless, which is safe: the challenge is single-use).
// Sealing re-reads the store like a fresh boot and compares the adopted
// record field-by-field before reporting success.
//
// Stack: process_line holds the decoded bundle (2 KiB) plus the parsed
// record beside it — about 4 KiB in the worst case. Run it on a task with
// headroom (the firmware runner uses its own 8 KiB task), not on a small
// shared stack.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery.hpp"  // EntropySource
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_lifecycle_store.hpp"
#include "routeloom/sdkv1_membership.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// The stores a `deprovision` wipes back to unprovisioned: identity (the
// console's own store) plus the site, revocation, local-revocation,
// resume and lifecycle state. Every pointer must be non-null and outlive
// the console; without them the deprovision pair answers `unsupported`.
struct MaintenanceWipeStores {
  SiteStore* site{nullptr};
  RevocationStore* revocation{nullptr};
  LocalRevocationStore* local_revocation{nullptr};
  ResumeCache2* resume{nullptr};
  LifecycleStore* lifecycle{nullptr};
};

// Largest accepted bundle JSON: the office emitter's worst case (3 anchors,
// longest enum spellings, 256-byte DevCert) is 1591 bytes.
constexpr std::size_t kMaintenanceBundleMax = 2048;
// Longest input line: "identity " + the bundle as hex.
constexpr std::size_t kMaintenanceLineMax = 9 + 2 * kMaintenanceBundleMax;
// Longest response (`OK pop_hex=` + 366 hex) plus the NUL terminator;
// responses are always NUL-terminated with size excluding the NUL.
constexpr std::size_t kMaintenanceResponseMax = 384;
// Longest firmware version the `status` receipt reports (ESP-IDF stamps at
// most 31 chars plus NUL; anything longer fails closed as `unknown`).
constexpr std::size_t kMaintenanceFwVersionMax = 32;

class MaintenanceConsole {
 public:
  // The store should be default-constructed; the console initializes it on
  // every line so impairment is always observed fresh. Both references must
  // outlive the console.
  MaintenanceConsole(IdentityStore& store, EntropySource& entropy) noexcept;
  // With the deprovision wipe set: the firmware passes all six stores so
  // the console can return a provisioned device to unprovisioned.
  MaintenanceConsole(IdentityStore& store, EntropySource& entropy,
                     const MaintenanceWipeStores& wipe) noexcept;
  ~MaintenanceConsole() noexcept;

  MaintenanceConsole(const MaintenanceConsole&) = delete;
  MaintenanceConsole& operator=(const MaintenanceConsole&) = delete;

  // The running firmware's version for the `status` receipt (07 §6: the
  // office verifies the maintenance image before the field switch, and
  // records which build sealed the device). Borrowed — must outlive the
  // console. Unset, empty, over-long or non-token bytes report `unknown`.
  void set_firmware_version(ByteView version) noexcept { firmware_version_ = version; }

  // Process one console line (`line` without the newline). Always produces
  // a response line when it returns Ok; errors are caller bugs (a short
  // response buffer) only. `response_capacity` must be at least
  // kMaintenanceResponseMax.
  Status process_line(ByteView line, char* response, std::size_t response_capacity,
                      std::size_t& response_size) noexcept;

 private:
  bool wipe_ready() const noexcept {
    return wipe_.site != nullptr && wipe_.revocation != nullptr &&
           wipe_.local_revocation != nullptr && wipe_.resume != nullptr &&
           wipe_.lifecycle != nullptr;
  }
  void burn_deprovision_challenge() noexcept;

  static constexpr std::size_t kDeprovisionNonceSize = 16;

  IdentityStore& store_;
  EntropySource& entropy_;
  MaintenanceWipeStores wipe_{};
  ByteView firmware_version_{};
  bool has_pending_{false};
  NodeId pending_node_{kInvalidNodeId};
  std::array<std::uint8_t, 32> pending_scalar_{};
  P256PublicKey pending_pubkey_{};
  bool deprovision_pending_{false};
  bool deprovision_bound_{false};  // the challenge named a sealed identity
  NodeId deprovision_node_{kInvalidNodeId};
  Digest256 deprovision_kid_{};
  std::array<std::uint8_t, kDeprovisionNonceSize> deprovision_nonce_{};
};

}  // namespace routeloom::sdkv1
