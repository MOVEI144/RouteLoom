#include "routeloom/board_config.hpp"

#include "routeloom/crc32.hpp"
#include "routeloom/group.hpp"

namespace routeloom {
namespace {
constexpr std::uint32_t kMagic = 0x524C4231U;  // RLB1
constexpr std::uint32_t kSeal = 0xB04DC0F1U;

void put32(std::uint8_t* p, const std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 24U);
  p[1] = static_cast<std::uint8_t>(v >> 16U);
  p[2] = static_cast<std::uint8_t>(v >> 8U);
  p[3] = static_cast<std::uint8_t>(v);
}
std::uint32_t get32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}
void put64(std::uint8_t* p, const std::uint64_t v) noexcept {
  put32(p, static_cast<std::uint32_t>(v >> 32U));
  put32(p + 4, static_cast<std::uint32_t>(v));
}
std::uint64_t get64(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint64_t>(get32(p)) << 32U) | get32(p + 4);
}

Status validate(const BoardConfig& c) noexcept {
  if (c.generation == 0 || reserved_node_id(c.node) || c.chip == 0 ||
      (c.sta_mac[0] & 1U) != 0 ||
      (c.sta_mac == std::array<std::uint8_t, 6>{}) ||
      (c.role != BoardRole::Bridge && c.role != BoardRole::Reference) ||
      (c.security != BoardSecurity::DevRam && c.security != BoardSecurity::Member) ||
      c.network == 0 || c.channel < 1 || c.channel > 13) {
    return Status::error(StatusCode::InvalidArgument, "board configuration invalid");
  }
  return Status::success();
}

Status structure(const ByteView bytes) noexcept {
  if (bytes.data == nullptr || bytes.size != kBoardConfigRecordBytes ||
      get32(bytes.data) != kMagic || bytes.data[4] != 0 || bytes.data[5] != 1 ||
      bytes.data[6] != 0 || bytes.data[7] != kBoardConfigRecordBytes ||
      get32(bytes.data + 16) == 0) {
    return Status::error(StatusCode::IntegrityError, "board record header");
  }
  return Status::success();
}

Status decode(const ByteView bytes, BoardConfig& out) noexcept {
  if (!structure(bytes) || get32(bytes.data + 8) != 1 || get32(bytes.data + 12) != kSeal ||
      get32(bytes.data + 46) != crc32_iso_hdlc(ByteView{bytes.data, 46})) {
    return Status::error(StatusCode::IntegrityError, "board record seal");
  }
  BoardConfig config{};
  config.generation = get32(bytes.data + 20);
  config.node = get64(bytes.data + 24);
  for (std::size_t i = 0; i < 6; ++i) config.sta_mac[i] = bytes.data[32 + i];
  config.chip = bytes.data[38];
  config.role = static_cast<BoardRole>(bytes.data[39]);
  config.security = static_cast<BoardSecurity>(bytes.data[40]);
  config.channel = bytes.data[41];
  config.network = get32(bytes.data + 42);
  const Status status = validate(config);
  if (status) out = config;
  return status;
}

Status semantic(const ByteView bytes, void* context) noexcept {
  return decode(bytes, *static_cast<BoardConfig*>(context));
}

const sdkv1::SealedRecordFormat kFormat{kMagic, kSeal, kBoardConfigSlotBytes,
                                        kBoardConfigRecordBytes, kBoardConfigRecordBytes,
                                        true, &structure, &semantic};
}  // namespace

BoardConfigStore::BoardConfigStore(sdkv1::RecordSlotStorage& storage) noexcept
    : pair_(storage, kFormat, scratch_.writable(), &config_) {}

Status BoardConfigStore::initialize() noexcept {
  const Status status = pair_.initialize();
  config_ = BoardConfig{};
  if (pair_.has_active()) {
    ByteView record{};
    Status loaded = pair_.load_active(record);
    if (loaded) loaded = decode(record, config_);
    if (!loaded) return loaded;
  }
  return status;
}

Status BoardConfigStore::commit(const BoardConfig& config) noexcept {
  if (!pair_.initialized()) return Status::error(StatusCode::InvalidState, "board store unopened");
  Status status = validate(config);
  if (!status) return status;
  if (pair_.has_active() && config.generation <= config_.generation) {
    return Status::error(StatusCode::Conflict, "board generation must increase");
  }
  auto* p = scratch_.bytes.data();
  put32(p, kMagic);
  p[4] = 0; p[5] = 1;
  p[6] = 0; p[7] = kBoardConfigRecordBytes;
  put32(p + 8, 1);
  put32(p + 12, 0);  // SealedSlotPair commits in two writes.
  put32(p + 16, 0);  // SealedSlotPair owns the sequence.
  put32(p + 20, config.generation);
  put64(p + 24, config.node);
  for (std::size_t i = 0; i < 6; ++i) p[32 + i] = config.sta_mac[i];
  p[38] = config.chip;
  p[39] = static_cast<std::uint8_t>(config.role);
  p[40] = static_cast<std::uint8_t>(config.security);
  p[41] = config.channel;
  put32(p + 42, config.network);
  put32(p + 46, 0);  // SealedSlotPair writes CRC after sequence and seal.
  status = pair_.commit_prepared(kBoardConfigRecordBytes);
  if (status) config_ = config;
  return status;
}

Status BoardConfigStore::authorize_rf(const BoardBootIdentity& identity) const noexcept {
  if (!pair_.initialized() || !pair_.has_active() || pair_.uncertain() || pair_.quarantined()) {
    return Status::error(StatusCode::InvalidState, "board configuration required");
  }
  if (config_.chip != identity.chip || config_.sta_mac != identity.sta_mac ||
      config_.role != identity.role || config_.security != identity.security ||
      (config_.security == BoardSecurity::Member && config_.node != identity.rli_node)) {
    return Status::error(StatusCode::Conflict, "board identity mismatch");
  }
  return Status::success();
}
}  // namespace routeloom
