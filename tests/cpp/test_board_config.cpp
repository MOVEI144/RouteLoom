// Board configuration boot gate and byte-granular interrupted commit regression.
#include <cstdio>
#include <cstring>
#include <limits>
#include "routeloom/board_config.hpp"
#include "routeloom/group.hpp"

using namespace routeloom;
namespace {
class FaultyRecordStorage final : public sdkv1::RecordSlotStorage {
 public:
  explicit FaultyRecordStorage(std::size_t) {
    for (auto& slot : slots_) slot.fill(0xFF);
  }
  Status read(std::uint8_t index, MutableByteView target) noexcept override {
    if (index > 1 || target.size != kBoardConfigSlotBytes) {
      return Status::error(StatusCode::InvalidArgument, "slot read");
    }
    std::memcpy(target.data, slots_[index].data(), target.size);
    return Status::success();
  }
  Status write(std::uint8_t index, ByteView data) noexcept override {
    if (index > 1 || data.size != kBoardConfigRecordBytes) {
      return Status::error(StatusCode::InvalidArgument, "slot write");
    }
    const auto call = write_calls++;
    const auto bytes = call == cut_call ? cut_bytes : data.size;
    std::memcpy(slots_[index].data(), data.data, bytes);
    if (call == cut_call) return Status::error(StatusCode::StorageFailure, "power cut");
    return Status::success();
  }
  void disarm() { cut_call = std::numeric_limits<std::size_t>::max(); }
  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
 private:
  std::array<std::array<std::uint8_t, kBoardConfigSlotBytes>, 2> slots_{};
};
int failures = 0;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (false)

BoardConfig board(const NodeId node, const std::uint8_t mac) {
  BoardConfig c{};
  c.generation = 1;
  c.node = node;
  c.sta_mac = {0x02, 0, 0, 0, 0, mac};
  c.chip = 3;
  c.role = BoardRole::Reference;
  c.security = BoardSecurity::Member;
  c.network = 42;
  c.channel = 6;
  return c;
}

void test_three_boards_and_boot_gate() {
  for (std::uint8_t i = 0; i < 3; ++i) {
    FaultyRecordStorage storage(kBoardConfigSlotBytes);
    BoardConfigStore setup(storage);
    CHECK(setup.initialize().ok());
    const auto c = board(10 + i, i + 1);
    CHECK(setup.commit(c).ok());
    BoardConfigStore field(storage);  // same loader with three distinct persistent slots
    CHECK(field.initialize().ok());
    BoardBootIdentity boot{3, c.sta_mac, BoardRole::Reference, BoardSecurity::Member, c.node};
    CHECK(field.authorize_rf(boot).ok());
    boot.sta_mac[5] ^= 0x01;
    CHECK(!field.authorize_rf(boot).ok());
    boot.sta_mac = c.sta_mac;
    boot.role = BoardRole::Bridge;
    CHECK(!field.authorize_rf(boot).ok());
    boot.role = BoardRole::Reference;
    boot.rli_node = 99;
    CHECK(!field.authorize_rf(boot).ok());
  }
  FaultyRecordStorage empty(kBoardConfigSlotBytes);
  BoardConfigStore field(empty);
  CHECK(field.initialize().ok());
  CHECK(!field.authorize_rf({3, board(10, 1).sta_mac, BoardRole::Reference,
                              BoardSecurity::Member, 10}).ok());
}

void test_rejected_records() {
  FaultyRecordStorage storage(kBoardConfigSlotBytes);
  BoardConfigStore store(storage);
  CHECK(store.initialize().ok());
  auto c = board(10, 1);
  c.node = kGroupAddressBase;
  CHECK(!store.commit(c).ok());
  c.node = 10;
  c.sta_mac[0] |= 1;
  CHECK(!store.commit(c).ok());
  c = board(10, 1);
  CHECK(store.commit(c).ok());
  CHECK(!store.commit(c).ok());
  c.generation = 2;
  c.channel = 14;
  CHECK(!store.commit(c).ok());
  auto identity = BoardBootIdentity{3, board(10, 1).sta_mac, BoardRole::Reference,
                                    BoardSecurity::Member, 10};
  identity.security = BoardSecurity::DevRam;
  CHECK(!store.authorize_rf(identity).ok());
}

void test_interrupted_commit_preserves_old() {
  const auto old = board(11, 1);
  auto next = board(12, 1);
  next.generation = 2;
  for (std::size_t call = 0; call < 2; ++call) {
    for (std::size_t byte = 0; byte < kBoardConfigRecordBytes; ++byte) {
      FaultyRecordStorage storage(kBoardConfigSlotBytes);
      BoardConfigStore setup(storage);
      CHECK(setup.initialize().ok());
      CHECK(setup.commit(old).ok());
      storage.cut_call = storage.write_calls + call;
      storage.cut_bytes = byte;
      CHECK(!setup.commit(next).ok());
      storage.disarm();
      BoardConfigStore reboot(storage);
      const auto status = reboot.initialize();
      // Pending/corrupt sibling must never be mistaken for the new generation.
      CHECK(!reboot.has_config() || reboot.config().node == old.node);
      if (status.ok()) CHECK(reboot.has_config() && reboot.config().node == old.node);
    }
  }
  // A lost response after all bytes landed is resolved by readback on reboot.
  {
    FaultyRecordStorage lost_ack(kBoardConfigSlotBytes);
    BoardConfigStore writer(lost_ack);
    CHECK(writer.initialize().ok());
    CHECK(writer.commit(old).ok());
    lost_ack.cut_call = lost_ack.write_calls + 1;
    lost_ack.cut_bytes = kBoardConfigRecordBytes;
    CHECK(!writer.commit(next).ok());
    lost_ack.disarm();
    BoardConfigStore reboot(lost_ack);
    CHECK(reboot.initialize().ok());
    CHECK(reboot.has_config() && reboot.config().node == next.node);
  }
  FaultyRecordStorage storage(kBoardConfigSlotBytes);
  BoardConfigStore initial(storage);
  CHECK(initial.initialize().ok());
  CHECK(initial.commit(old).ok());
  CHECK(initial.commit(next).ok());
  BoardConfigStore updated(storage);  // app-only flash does not touch configuration
  CHECK(updated.initialize().ok());
  CHECK(updated.has_config() && updated.config().node == next.node);
}
}
int main() {
  test_three_boards_and_boot_gate();
  test_rejected_records();
  test_interrupted_commit_preserves_old();
  return failures ? 1 : 0;
}
