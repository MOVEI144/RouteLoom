#include <cstdint>
#include <cstdio>

#include "routeloom/sdkv1_boot_session.hpp"

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
struct Fake final : BootSessionPort {
  Status read(std::uint32_t& value, bool& exists) noexcept override {
    if (read_error) return Status::error(StatusCode::StorageFailure, "read");
    value = stored;
    exists = found;
    return Status::success();
  }
  Status commit(std::uint32_t value) noexcept override {
    ++writes;
    if (write_error) return Status::error(StatusCode::StorageFailure, "write");
    if (lost_write) return Status::success();
    stored = value;
    found = true;
    return Status::success();
  }
  std::uint32_t stored{0};
  int writes{0};
  bool found{false};
  bool read_error{false};
  bool write_error{false};
  bool lost_write{false};
};
struct DevFake final : DevBootHighWaterPort {
  Status read(std::uint32_t& value, bool& exists) noexcept override {
    if (read_error) return Status::error(StatusCode::StorageFailure, "dev read");
    value = high;
    exists = found;
    return Status::success();
  }
  Status commit(std::uint32_t value) noexcept override {
    ++writes;
    if (write_error) return Status::error(StatusCode::StorageFailure, "dev write");
    if (!lost_write) { high = value; found = true; }
    return Status::success();
  }
  std::uint32_t high{0};
  int writes{0};
  bool found{false};
  bool read_error{false};
  bool write_error{false};
  bool lost_write{false};
};
int failures = 0;
void check(bool value, int line) {
  if (!value) { std::fprintf(stderr, "boot session check failed: %d\n", line); ++failures; }
}
#define CHECK(expr) check(static_cast<bool>(expr), __LINE__)
}  // namespace

int main() {
  Fake port;
  BootSessionStore store(port);
  std::uint32_t token = 0;
  CHECK(store.advance(false, 0, token).ok() && token == 1);
  // Site becomes visible only after the independent system-NVS increment.
  CHECK(store.reconcile_site(100, token).ok() && token == 100 + (1U << 20));
  const int repaired_writes = port.writes;
  CHECK(store.reconcile_site(100, token).ok() && port.writes == repaired_writes);
  CHECK(store.reconcile_site(0, token).code == StatusCode::RecoveryRequired &&
        port.writes == repaired_writes);
  CHECK(store.reconcile_site(UINT32_MAX, token).code == StatusCode::CounterExhausted &&
        port.writes == repaired_writes);
  port.read_error = true;
  CHECK(store.reconcile_site(100, token).code == StatusCode::StorageFailure &&
        port.writes == repaired_writes);
  port.read_error = false;
  port.lost_write = true;
  CHECK(store.reconcile_site(token, token).code == StatusCode::StorageFailure &&
        token == 100 + (1U << 20));
  port.lost_write = false;
  port.stored = 1;
  CHECK(store.reconcile_site(100, token).code == StatusCode::StorageFailure &&
        token == 100 + (1U << 20));
  token = 1;
  CHECK(store.advance(true, 1, token).ok() && token == 2);
  port.stored = 1;
  CHECK(store.advance(true, 100, token).ok() && token == 100 + (1U << 20));
  port.found = false;
  CHECK(store.advance(true, 100, token).ok() && token == 100 + (1U << 20));
  const auto before = token;
  port.read_error = true;
  CHECK(store.advance(true, 100, token).code == StatusCode::StorageFailure && token == before);
  port.read_error = false;
  port.found = true;
  port.stored = UINT32_MAX;
  CHECK(store.advance(false, 0, token).code == StatusCode::CounterExhausted && token == before);
  port.stored = UINT32_MAX - (1U << 20);
  CHECK(store.advance(true, UINT32_MAX - 1, token).code == StatusCode::CounterExhausted);
  port.stored = 1;
  port.write_error = true;
  CHECK(store.advance(false, 0, token).code == StatusCode::StorageFailure && token == before);
  port.write_error = false;
  port.lost_write = true;
  CHECK(store.advance(false, 0, token).code == StatusCode::StorageFailure && token == before);
  port.lost_write = false;
  CHECK(store.advance(false, 0, token).ok() && token == 2);
  CHECK(port.writes >= 6);

  // A committed system candidate behind boot_hi must skip the last group
  // epoch, including after either interrupted write.
  Fake system;
  DevFake dev;
  BootSessionStore dev_store(system);
  std::uint32_t group_boot = 999;
  system.stored = 4;
  system.found = true;
  dev.high = 8;
  dev.found = true;
  std::uint32_t candidate = 4;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).ok() && group_boot == 9);
  CHECK(system.stored == 9 && dev.high == 9 && dev.writes == 1);
  // The already committed system candidate is ahead of boot_hi: do not
  // spend another system write merely to synchronize the fixed ceiling.
  system.stored = 11;
  candidate = 11;
  const int writes = system.writes;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).ok() && group_boot == 11);
  CHECK(system.writes == writes && dev.high == 11);
  dev.high = UINT32_MAX;
  const auto old_group = group_boot;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::CounterExhausted &&
        group_boot == old_group);
  dev.high = 11;
  dev.read_error = true;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::StorageFailure &&
        group_boot == old_group);
  dev.read_error = false;
  dev.lost_write = true;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::StorageFailure &&
        group_boot == old_group && system.stored == 11);
  dev.lost_write = false;
  system.write_error = true;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::StorageFailure &&
        group_boot == old_group && dev.high == 12);
  system.write_error = false;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).ok() && group_boot == 13);
  candidate = 13;
  system.lost_write = true;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::StorageFailure &&
        group_boot == 13 && dev.high == 14);
  system.lost_write = false;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).ok() && group_boot == 15);
  candidate = 15;
  system.stored = UINT32_MAX;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::StorageFailure &&
        group_boot == 15);
  system.stored = 15;
  dev.high = 0;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::RecoveryRequired &&
        group_boot == 15);
  dev.high = UINT32_MAX;
  CHECK(dev_store.advance_dev_group(dev, candidate, group_boot).code == StatusCode::CounterExhausted &&
        group_boot == 15);
  return failures == 0 ? 0 : 1;
}
