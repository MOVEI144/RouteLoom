// Board configuration boot gate and byte-granular interrupted commit regression.
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "routeloom/sdkv1_blob_storage.hpp"
#include "routeloom/board_config.hpp"
#include "routeloom/board_secrets.hpp"
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
  Status erase(std::uint8_t index) noexcept override {
    if (index > 1) return Status::error(StatusCode::InvalidArgument, "slot erase");
    slots_[index].fill(0xFF);
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

// NVS commits a whole blob or nothing. The config namespace is independent
// of rlsec, so an app-only update must not change either namespace.
class ConfigNvs final : public sdkv1::BlobNamespace {
 public:
  Status blob_size(const char* key, std::size_t& size, bool& found) noexcept override {
    const auto it = blobs.find(key);
    found = it != blobs.end();
    size = found ? it->second.size() : 0;
    return Status::success();
  }
  Status blob_read(const char* key, MutableByteView target, std::size_t& size) noexcept override {
    const auto it = blobs.find(key);
    if (it == blobs.end() || target.size < it->second.size())
      return Status::error(StatusCode::StorageFailure, "missing blob");
    std::memcpy(target.data, it->second.data(), it->second.size());
    size = it->second.size();
    return Status::success();
  }
  Status blob_write(const char* key, ByteView data) noexcept override {
    const auto call = writes++;
    if (call == cut_at) {
      if (!cut_lands) return Status::error(StatusCode::StorageFailure, "power cut");
    }
    blobs[key].assign(data.data, data.data + data.size);
    if (call == cut_at) return Status::error(StatusCode::StorageFailure, "lost ack");
    return Status::success();
  }
  Status blob_erase(const char* key) noexcept override {
    blobs.erase(key);
    return Status::success();
  }
  std::map<std::string, std::vector<std::uint8_t>> blobs;
  std::size_t writes{0};
  std::size_t cut_at{std::numeric_limits<std::size_t>::max()};
  bool cut_lands{false};
};

void test_nvs_app_update_and_power_cut() {
  for (std::uint8_t i = 0; i < 3; ++i) {
    ConfigNvs nvs;
    auto slot = sdkv1::BlobRecordSlotStorage::board_config(nvs);
    BoardConfigStore setup(slot);
    auto c = board(20 + i, 10 + i);
    CHECK(setup.initialize().ok());
    CHECK(setup.commit(c).ok());
    CHECK(nvs.blobs.count("b0") == 1);
    // Independent durable security state survives the app image replacement.
    nvs.blobs["rlsec-boot-witness"] = {1, 2, 3};
    auto newer = c;
    newer.node += 10;
    newer.generation++;
    nvs.cut_at = nvs.writes;
    CHECK(!setup.commit(newer).ok());
    CHECK(!setup.authorize_rf({c.chip, c.sta_mac, c.role, c.security, c.node}).ok());
    nvs.cut_at = std::numeric_limits<std::size_t>::max();
    auto app_slot = sdkv1::BlobRecordSlotStorage::board_config(nvs);
    BoardConfigStore updated(app_slot);
    CHECK(updated.initialize().ok());
    CHECK(updated.config().node == c.node);
    CHECK(nvs.blobs["rlsec-boot-witness"] == std::vector<std::uint8_t>({1, 2, 3}));
    CHECK(updated.authorize_rf({c.chip, c.sta_mac, c.role, c.security, c.node}).ok());
  }
  // A lost acknowledgement at each durable write boundary has an
  // unambiguous readback: before the seal use the old record; after it,
  // use the new one. Neither case overwrites the boot witness.
  for (std::size_t phase = 0; phase < 2; ++phase) {
    for (bool lands : {false, true}) {
      ConfigNvs nvs;
      auto slot = sdkv1::BlobRecordSlotStorage::board_config(nvs);
      BoardConfigStore writer(slot);
      CHECK(writer.initialize().ok());
      auto c = board(30, 10);
      CHECK(writer.commit(c).ok());
      nvs.blobs["rlsec-boot-witness"] = {1, 2, 3};
      auto newer = c;
      newer.node = 31;
      newer.generation = 2;
      nvs.cut_at = nvs.writes + phase;
      nvs.cut_lands = lands;
      CHECK(!writer.commit(newer).ok());
      // An acknowledged failure can still have landed the seal; the live
      // writer must not authorize the stale in-memory identity before readback.
      CHECK(!writer.authorize_rf({c.chip, c.sta_mac, c.role, c.security, c.node}).ok());
      nvs.cut_at = std::numeric_limits<std::size_t>::max();
      CHECK(!writer.commit(newer).ok());  // reconcile the possibly landed seal first
      auto app_slot = sdkv1::BlobRecordSlotStorage::board_config(nvs);
      BoardConfigStore reboot(app_slot);
      CHECK(reboot.initialize().ok());
      CHECK(reboot.config().node == ((phase == 1 && lands) ? newer.node : c.node));
      CHECK(reboot.authorize_rf({c.chip, c.sta_mac, c.role, c.security,
                                reboot.config().node}).ok());
      CHECK(nvs.blobs["rlsec-boot-witness"] == std::vector<std::uint8_t>({1, 2, 3}));
    }
  }
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
  // An erased board (no rlcfg blobs; the ESP adapter maps a missing
  // namespace to the same detail) is CONFIG_REQUIRED, never a fault.
  ConfigNvs erased;
  auto config_slots = sdkv1::BlobRecordSlotStorage::board_config(erased);
  auto secret_slots = sdkv1::BlobRecordSlotStorage::board_secrets(erased);
  BoardConfigStore field(config_slots);
  BoardSecretsStore secrets(secret_slots);
  CHECK(field.initialize().ok());
  CHECK(secrets.initialize().ok());
  const BoardSecrets* resolved = nullptr;
  const Status gate = resolve_field_identity(
      field, secrets, {3, board(10, 1).sta_mac, BoardRole::Reference,
                       BoardSecurity::Member, 10}, resolved);
  CHECK(!gate.ok() && resolved == nullptr);
  CHECK(std::strcmp(gate.detail, "board configuration required") == 0);
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
      CHECK(!setup.authorize_rf({old.chip, old.sta_mac, old.role, old.security, old.node}).ok());
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
  test_nvs_app_update_and_power_cut();
  test_three_boards_and_boot_gate();
  test_rejected_records();
  test_interrupted_commit_preserves_old();
  return failures ? 1 : 0;
}
