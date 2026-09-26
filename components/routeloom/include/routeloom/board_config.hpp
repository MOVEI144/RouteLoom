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

struct BoardConfig {
  std::uint32_t generation{0};
  NodeId node{kInvalidNodeId};
  std::array<std::uint8_t, 6> sta_mac{};
  std::uint8_t chip{0};
  BoardRole role{BoardRole::Reference};
  BoardSecurity security{BoardSecurity::Member};
  std::uint32_t network{0};
  std::uint8_t channel{0};
};

struct BoardBootIdentity {
  std::uint8_t chip{0};
  std::array<std::uint8_t, 6> sta_mac{};
  BoardRole role{BoardRole::Reference};
  BoardSecurity security{BoardSecurity::Member};
  // Member: verified sealed RLI1 node. DevRam: unused (zero).
  NodeId rli_node{kInvalidNodeId};
};

constexpr std::size_t kBoardConfigRecordBytes = 50;
constexpr std::size_t kBoardConfigSlotBytes = kBoardConfigRecordBytes;

class BoardConfigStore {
 public:
  explicit BoardConfigStore(sdkv1::RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  Status commit(const BoardConfig& config) noexcept;
  bool has_config() const noexcept { return pair_.has_active(); }
  const BoardConfig& config() const noexcept { return config_; }
  Status authorize_rf(const BoardBootIdentity& identity) const noexcept;

 private:
  ByteBuffer<kBoardConfigSlotBytes> scratch_{};
  sdkv1::SealedSlotPair pair_;
  BoardConfig config_{};
};

}  // namespace routeloom
