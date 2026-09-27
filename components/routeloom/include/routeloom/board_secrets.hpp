#pragma once

// Per-device secret material for the shared field image — the RLK1 record
// (rlkeys partition, sealed dual slot) holds the kinds the public
// BoardConfig binds by generation + content fingerprint (meshviz §0.4,
// design-devflow §4.1): the DevRam mesh PSK and the USB session secret.
// Secrets never appear in console responses; status reports the
// fingerprint only. Same storage/readback discipline as BoardConfigStore:
// a torn or unacknowledged write leaves the store unusable until a fresh
// initialize() readback proves the durable state again.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/board_config.hpp"
#include "routeloom/key_schedule.hpp"  // keys::Secret
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// USB session secret contract (routeloom-host --usb-dev-secret-file):
// 1..63 printable non-space ASCII bytes.
constexpr std::size_t kBoardUsbSecretMax = 63;
constexpr std::size_t kBoardPskBytes = 32;

// RLK1 record (127 B):
//   0 u32 magic | 4 u8 reserved | u8 version(1) | u8 reserved | u8 len
//   8 u32 schema(1) | 12 u32 seal | 16 u32 commit_seq
//  20 u32 generation | 24 u8 flags | 25 u8 usb_len | 26 u16 reserved
//  28 32B dev psk | 60 usb_secret[63] | 123 u32 crc32 over [0,123)
// flags: bit0 psk present, bit1 usb secret present. Canonical form keeps
// absent kinds zeroed so the fingerprint below is unambiguous.
constexpr std::size_t kBoardSecretsRecordBytes = 127;
constexpr std::size_t kBoardSecretsSlotBytes = kBoardSecretsRecordBytes;
constexpr std::uint8_t kBoardSecretsFlagPsk = 0x01;
constexpr std::uint8_t kBoardSecretsFlagUsb = 0x02;
constexpr std::uint8_t kBoardSecretsFlagMask = 0x03;

struct BoardSecrets {
  std::uint32_t generation{0};
  bool has_psk{false};
  keys::Secret psk{};
  std::uint8_t usb_len{0};
  std::array<std::uint8_t, kBoardUsbSecretMax> usb_secret{};
};

// What a (security, role) configuration needs from the secrets record:
// the DevRam profile needs the mesh PSK; every USB bridge role needs its
// session secret. Member non-bridge devices need no secrets record.
struct BoardSecretsNeed {
  bool psk{false};
  bool usb{false};
};

constexpr BoardSecretsNeed board_secrets_need(const BoardSecurity security,
                                              const BoardRole role) noexcept {
  return BoardSecretsNeed{security == BoardSecurity::DevRam,
                          role == BoardRole::Bridge};
}

// Canonical-field checks: nonzero generation, known flag semantics, the
// USB secret printable ASCII, absent kinds zeroed.
Status board_secrets_validate(const BoardSecrets& secrets) noexcept;

bool board_secrets_equal(const BoardSecrets& a, const BoardSecrets& b) noexcept;

// The value the public BoardConfig binds in secrets_fingerprint:
// SHA-256 over a domain tag and the record's canonical content
// (generation | flags | usb_len | reserved | psk | usb_secret) — the
// fingerprint is public, the hashed content is the proof of binding.
Status board_secrets_fingerprint(const BoardSecrets& secrets, Digest256& out) noexcept;

class BoardSecretsStore {
 public:
  explicit BoardSecretsStore(sdkv1::RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  // Generation must strictly increase over the committed record, like the
  // public config. A failed acknowledgement marks the store unready:
  // commits and authorize() refuse until initialize() re-reads the slots.
  Status commit(const BoardSecrets& secrets) noexcept;
  bool has_secrets() const noexcept { return pair_.has_active(); }
  const BoardSecrets& secrets() const noexcept { return secrets_; }
  bool readback_ready() const noexcept { return readback_ready_; }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  // The field-boot half of the binding: when the committed BoardConfig
  // names a secrets generation, this store must hold that record, its
  // fingerprint must match, and the kinds that (security, role) needs
  // must be present. A zero binding is allowed only when nothing is
  // needed (Member non-bridge).
  Status authorize(const BoardConfig& config) const noexcept;

 private:
  ByteBuffer<kBoardSecretsSlotBytes> scratch_{};
  sdkv1::SealedSlotPair pair_;
  BoardSecrets secrets_{};
  bool readback_ready_{false};
};

// The generic field image's pre-RF gate (design-devflow §4.1): the
// committed board record must match the live chip/MAC/role/security (and
// the sealed RLI1 node for Member), then the secrets it binds must be
// committed and intact. `secrets_out` borrows the adopted secrets record
// on success — nullptr when the config binds no secrets record.
Status resolve_field_identity(const BoardConfigStore& board,
                              const BoardSecretsStore& secrets,
                              const BoardBootIdentity& identity,
                              const BoardSecrets*& secrets_out) noexcept;

}  // namespace routeloom
