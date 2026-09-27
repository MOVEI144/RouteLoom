#pragma once

// Pre-radio board configuration. The same field image can load different
// committed rlcfg records; a missing, uncertain or mismatched record cannot
// authorize RF. Storage is supplied by the platform and is not an app image.
#include <array>
#include <cstdint>

#include "routeloom/sdkv1_store.hpp"

namespace routeloom {

enum class BoardRole : std::uint8_t { Bridge = 1, Reference = 2 };
enum class BoardSecurity : std::uint8_t { DevRam = 1, Member = 2 };

// Compile-target chip identifiers written into a committed record (the
// firmware maps CONFIG_IDF_TARGET_* onto these — espnow_board_config.cpp).
constexpr std::uint8_t kBoardChipEsp32C3 = 1;
constexpr std::uint8_t kBoardChipEsp32S3 = 2;
constexpr std::uint8_t kBoardChipEsp32C5 = 3;
constexpr std::uint8_t kBoardChipEsp32C6 = 4;

struct BoardConfig {
  std::uint32_t generation{0};
  NodeId node{kInvalidNodeId};
  std::array<std::uint8_t, 6> sta_mac{};
  std::uint8_t chip{0};
  BoardRole role{BoardRole::Reference};
  BoardSecurity security{BoardSecurity::Member};
  std::uint32_t network{0};
  std::uint8_t channel{0};
  // Binding to the rlkeys record committed in the same setup pass
  // (meshviz §0.4): zero when this configuration needs no secrets
  // (Member non-bridge), else the secrets record's generation and its
  // canonical-content fingerprint. The field gate re-verifies both
  // against the durable secrets record before RF.
  std::uint32_t secrets_generation{0};
  Digest256 secrets_fingerprint{};
};

struct BoardBootIdentity {
  std::uint8_t chip{0};
  std::array<std::uint8_t, 6> sta_mac{};
  BoardRole role{BoardRole::Reference};
  BoardSecurity security{BoardSecurity::Member};
  // Member: verified sealed RLI1 node. DevRam: unused (zero).
  NodeId rli_node{kInvalidNodeId};
};

// RLB1 record (50 B header/fields + 4 B secrets generation + 32 B secrets
// fingerprint + 4 B crc32):
//   0 u32 magic | 4 u8 reserved | u8 version(1) | u8 reserved | u8 len
//   8 u32 schema(1) | 12 u32 seal | 16 u32 commit_seq
//  20 u32 generation | 24 u64 node | 32 sta_mac[6]
//  38 u8 chip | 39 u8 role | 40 u8 security | 41 u8 channel
//  42 u32 network | 46 u32 secrets_generation | 50 32B secrets_fingerprint
//  82 u32 crc32 over [0,82)
constexpr std::size_t kBoardConfigRecordBytes = 86;
constexpr std::size_t kBoardConfigSlotBytes = kBoardConfigRecordBytes;

// Field-level validity shared by the record decoder and the setup
// console's document parser (the generation is not checked here — the
// durable path supplies it at commit).
Status board_config_fields_valid(const BoardConfig& config) noexcept;

// Field-equal over every committed field; the setup console replays a
// benchcfg commit only when the durable record already equals this.
bool board_config_equal(const BoardConfig& a, const BoardConfig& b) noexcept;

class BoardConfigStore {
 public:
  explicit BoardConfigStore(sdkv1::RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  Status commit(const BoardConfig& config) noexcept;
  bool has_config() const noexcept { return pair_.has_active(); }
  const BoardConfig& config() const noexcept { return config_; }
  bool readback_ready() const noexcept { return readback_ready_; }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  Status authorize_rf(const BoardBootIdentity& identity) const noexcept;

 private:
  ByteBuffer<kBoardConfigSlotBytes> scratch_{};
  sdkv1::SealedSlotPair pair_;
  BoardConfig config_{};
  bool readback_ready_{false};
};

}  // namespace routeloom
