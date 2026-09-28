#pragma once

// Shared field-image board identity (design-devflow §4.1, meshviz §0.4):
// one signed image serves every board of a chip x role pair, so the
// durable BoardConfig (rlcfg) and its bound BoardSecrets (rlkeys) are the
// only source of NodeId/network/channel/secret at boot. BoardStores owns
// both NVS namespaces and the two sealed-slot stores; the generic field
// path calls resolve_field_identity() (board_secrets.hpp) before any
// radio setup, and the setup console (benchcfg/benchsecret verbs) uses
// the same stores read-write.

#include <cstdint>

#include "routeloom/board_config.hpp"
#include "routeloom/board_secrets.hpp"
#include "routeloom/hex.hpp"
#include "routeloom/nvs_sdkv1_store.hpp"
#include "routeloom/status.hpp"

namespace routeloom::espnow {

class BoardStores {
 public:
  BoardStores() noexcept;
  // Mounts rlcfg + rlkeys and opens the `board`/`keys` namespaces.
  // `writable=false` is the field-boot mode: the namespaces open
  // NVS_READONLY — nothing is created and the driver refuses writes, so
  // read-only is enforced by NVS itself, not just by convention. A
  // namespace that was never created (erased board) is NotFound with the
  // gate's "board configuration required" detail.
  Status open(bool writable) noexcept;
  // Re-reads both slot pairs; faults leave the stores impaired, which the
  // field gate (and the setup console) then refuse through.
  Status initialize() noexcept;
  BoardConfigStore& config() noexcept { return config_; }
  BoardSecretsStore& secrets() noexcept { return secrets_; }

 private:
  NvsBlobNamespace config_ns_{};
  NvsBlobNamespace secrets_ns_{};
  sdkv1::BlobRecordSlotStorage config_slots_;
  sdkv1::BlobRecordSlotStorage secrets_slots_;
  BoardConfigStore config_;
  BoardSecretsStore secrets_;
};

// The compile-target chip id this image was built for (board_config.hpp
// constants); 0 on an unknown target — the committed record then can
// never match, which fails closed.
std::uint8_t board_chip() noexcept;

}  // namespace routeloom::espnow
