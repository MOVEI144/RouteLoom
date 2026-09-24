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
    stored = value;
    found = true;
    return Status::success();
  }
  std::uint32_t stored{0};
  int writes{0};
  bool found{false};
  bool read_error{false};
  bool write_error{false};
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
  return failures == 0 ? 0 : 1;
}
