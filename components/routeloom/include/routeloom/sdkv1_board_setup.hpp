#pragma once

// Board provisioning verbs of the factory maintenance console
// (design-devflow §4.1, meshviz §0.4): the same field image boots every
// board of a chip x role pair, so the per-device identity is committed
// here, pre-RF, by the setup image — never by Kconfig.
//
//   benchcfg stage <hex>        stage the public document (RLC1, fixed
//                               layout, strict field allowlist)
//   benchcfg validate           parse + field-check the staged document
//   benchcfg commit <gen>       commit staged secrets (if any) then the
//                               public record at generation <gen>, each
//                               with its own commit/readback; the config
//                               embeds the secrets generation + content
//                               fingerprint it binds
//   benchcfg status             committed board record + bound fingerprint
//   benchsecret stage <kind> <gen> <hex>
//                               stage one secret kind in RAM until the
//                               next benchcfg commit; kind = psk (32 B)
//                               or usb (1..63 printable ASCII bytes)
//   benchsecret status          committed record's kinds + fingerprint —
//                               never the secret bytes
//
// Discipline (same as the identity console): a console-locked RLI1 seal
// refuses every mutating verb; status verbs stay readable. Stores are
// re-initialized per line so impairment is observed, never cached. A
// failed commit leaves the store unready — commits and field RF refuse
// until a fresh readback proves the durable state. Staged secret material
// is secure-cleared in the destructor and after every successful commit;
// it never reaches a response.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/board_config.hpp"
#include "routeloom/board_secrets.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// The staged public document bound (design-devflow §4.1: "小さい
// （≤2 KiB）binary document"). The v1 RLC1 layout itself is 42 bytes.
constexpr std::size_t kBoardSetupDocMax = 2048;
constexpr std::size_t kBoardSetupLineMax = sizeof("benchcfg stage ") - 1 +
                                           2 * kBoardSetupDocMax;
constexpr std::size_t kBoardDocV1Bytes = 42;

// RLC1 document layout (42 B, big-endian like the records):
//   0 u32 magic "RLC1" | 4 u8 version(1) | u8 reserved | u16 len(=42)
//   8 u64 node_id | 16 sta_mac[6]
//  22 u8 chip | 23 u8 role | 24 u8 security | 25 u8 channel
//  26 u32 network | 30 u8 reserved[8] | 38 u32 crc32 over [0,38)
// Generation is deliberately NOT in the document: it is the commit
// argument, so a replayed stale document cannot smuggle an old ordinal.
constexpr std::uint32_t kBoardDocMagic = 0x524C4331U;  // "RLC1"

class BoardSetupConsole {
 public:
  // `expected` is the field image profile this setup build serves (chip,
  // role, security, eFuse station MAC — the app passes its own boot
  // identity): a staged document naming anything else cannot commit, so
  // a C6 bridge record can never land on a C3 reference board (design
  // §4.2 setup row). Every setup image is bound to one field profile;
  // `expected` must outlive the console.
  BoardSetupConsole(BoardConfigStore& config, BoardSecretsStore& secrets,
                    IdentityStore& identity,
                    const BoardBootIdentity& expected) noexcept;
  ~BoardSetupConsole() noexcept;

  // One full console line ("benchcfg ..." / "benchsecret ..."). The
  // caller owns the response buffer (kMaintenanceResponseMax).
  Status process_line(ByteView line, char* response, std::size_t response_capacity,
                      std::size_t& response_size) noexcept;

 private:
  BoardConfigStore& config_;
  BoardSecretsStore& secrets_;
  IdentityStore& identity_;
  const BoardBootIdentity& expected_;
  // RAM staging: the staged document and the staged secret kinds are the
  // commit call's inputs; nothing here is durable until benchcfg commit.
  std::array<std::uint8_t, kBoardSetupDocMax> staged_doc_{};
  std::size_t staged_doc_len_{0};
  std::uint32_t staged_generation_{0};
  bool staged_psk_{false};
  keys::Secret psk_value_{};
  std::array<std::uint8_t, kBoardUsbSecretMax> usb_value_{};
  std::uint8_t usb_len_{0};  // >0 stages the usb kind
};

}  // namespace routeloom::sdkv1
