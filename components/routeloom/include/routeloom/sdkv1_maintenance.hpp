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
//   status                                    -> OK identity=<none|sealed> pending=<0|1>
//   keygen <node:16hex> <challenge:64hex>    -> OK pop_hex=<366hex>
//   identity <bundle:hex of the bundle JSON> -> OK sealed kid=<64hex>
// Failures are `ERR <token>` with a stable token: `locked` (RLI1 sealed
// with console_locked — every verb refused), `invalid_argument`,
// `entropy_not_ready` (keygen before entropy READY, security §9),
// `already_provisioned`, `store_unavailable` (quarantined/uncertain/fault),
// `no_pending_key` (identity without a keygen first), `node_mismatch`,
// `key_mismatch` (bundle/DevCert key is not the pending one), `seal_failed`.
// State refusals dominate input errors (a locked device reports `locked`
// even for a malformed line); process_line itself returns Ok whenever a
// response line was produced.
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
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// Largest accepted bundle JSON: the office emitter's worst case (3 anchors,
// longest enum spellings, 256-byte DevCert) is 1591 bytes.
constexpr std::size_t kMaintenanceBundleMax = 2048;
// Longest input line: "identity " + the bundle as hex.
constexpr std::size_t kMaintenanceLineMax = 9 + 2 * kMaintenanceBundleMax;
// Longest response (`OK pop_hex=` + 366 hex) plus the NUL terminator;
// responses are always NUL-terminated with size excluding the NUL.
constexpr std::size_t kMaintenanceResponseMax = 384;

class MaintenanceConsole {
 public:
  // The store should be default-constructed; the console initializes it on
  // every line so impairment is always observed fresh. Both references must
  // outlive the console.
  MaintenanceConsole(IdentityStore& store, EntropySource& entropy) noexcept;
  ~MaintenanceConsole() noexcept;

  MaintenanceConsole(const MaintenanceConsole&) = delete;
  MaintenanceConsole& operator=(const MaintenanceConsole&) = delete;

  // Process one console line (`line` without the newline). Always produces
  // a response line when it returns Ok; errors are caller bugs (a short
  // response buffer) only. `response_capacity` must be at least
  // kMaintenanceResponseMax.
  Status process_line(ByteView line, char* response, std::size_t response_capacity,
                      std::size_t& response_size) noexcept;

 private:
  IdentityStore& store_;
  EntropySource& entropy_;
  bool has_pending_{false};
  NodeId pending_node_{kInvalidNodeId};
  std::array<std::uint8_t, 32> pending_scalar_{};
  P256PublicKey pending_pubkey_{};
};

}  // namespace routeloom::sdkv1
