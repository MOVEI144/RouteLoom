#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <string>

#include "nvs.h"
#include "routeloom/nvs_sdkv1_store.hpp"

static_assert(sizeof(routeloom::espnow::NvsBlobNamespace) <= 128,
              "six persistent namespaces must fit the esp32c3 RAM floor");

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (false)

namespace {
// Scriptable NVS fake: fail_op selects the call that refuses, fail_code the
// native error it returns. Everything else succeeds against one blob slot.
enum class FailOp { kNone, kOpen, kSize, kRead, kWrite, kErase, kCommit };
FailOp fail_op = FailOp::kNone;
esp_err_t fail_code = ESP_OK;
std::string stored;
bool stored_live = false;
char last_log[128]{};

bool ShouldFail(FailOp op, esp_err_t* code) {
  if (fail_op == op) {
    *code = fail_code;
    return true;
  }
  return false;
}
}  // namespace

extern "C" void routeloom_test_log_error(const char* tag, const char* format, ...) {
  (void)tag;
  std::va_list args;
  va_start(args, format);
  std::vsnprintf(last_log, sizeof last_log, format, args);
  va_end(args);
}

esp_err_t nvs_open(const char*, int, nvs_handle_t* handle) {
  *handle = 1;
  return ESP_OK;
}
esp_err_t nvs_open_from_partition(const char*, const char*, int, nvs_handle_t* handle) {
  esp_err_t code = ESP_OK;
  if (ShouldFail(FailOp::kOpen, &code)) return code;
  *handle = 1;
  return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t, const char*, void* out, std::size_t* length) {
  esp_err_t code = ESP_OK;
  if (out == nullptr) {
    if (ShouldFail(FailOp::kSize, &code)) return code;
  } else {
    if (ShouldFail(FailOp::kRead, &code)) return code;
  }
  if (!stored_live) return ESP_ERR_NVS_NOT_FOUND;
  if (out == nullptr) {
    *length = stored.size();
    return ESP_OK;
  }
  if (*length < stored.size()) return ESP_ERR_INVALID_ARG;
  std::memcpy(out, stored.data(), stored.size());
  *length = stored.size();
  return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t, const char*, const void* data, std::size_t length) {
  esp_err_t code = ESP_OK;
  if (ShouldFail(FailOp::kWrite, &code)) return code;
  stored.assign(static_cast<const char*>(data), length);
  stored_live = true;
  return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t, const char*) {
  esp_err_t code = ESP_OK;
  if (ShouldFail(FailOp::kErase, &code)) return code;
  if (!stored_live) return ESP_ERR_NVS_NOT_FOUND;
  stored_live = false;
  return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t) {
  esp_err_t code = ESP_OK;
  if (ShouldFail(FailOp::kCommit, &code)) return code;
  return ESP_OK;
}
void nvs_close(nvs_handle_t) {}

namespace {
void Reset() {
  fail_op = FailOp::kNone;
  fail_code = ESP_OK;
  stored.clear();
  stored_live = false;
  last_log[0] = '\0';
}

// The store is neither copyable nor movable, so each check owns a local.
bool OpenStore(routeloom::espnow::NvsBlobNamespace& store) {
  return store.open("rlsec", "rl").ok();
}

int CheckWriteSpace() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(OpenStore(store));
  CHECK(store.is_open());
  fail_op = FailOp::kWrite;
  fail_code = ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  const routeloom::ByteView data{reinterpret_cast<const std::uint8_t*>("v"), 1};
  const routeloom::Status status = store.blob_write("k", data);
  CHECK(!status.ok());
  CHECK(status.code == routeloom::StatusCode::StorageFailure);
  // Capacity refuses must read differently from generic failures so the
  // operator picks the right remedy (free space vs investigate).
  CHECK(std::strstr(status.detail, "space") != nullptr);
  CHECK(std::strstr(last_log, "rlsec/rl") != nullptr);
  CHECK(std::strstr(last_log, "blob_write") != nullptr);
  char native[32]{};
  std::snprintf(native, sizeof native, "native=0x%x", ESP_ERR_NVS_NOT_ENOUGH_SPACE);
  CHECK(std::strstr(last_log, native) != nullptr);
  const auto last = store.last_error();
  CHECK(last.op != nullptr && std::strcmp(last.op, "blob_write") == 0);
  CHECK(last.native == ESP_ERR_NVS_NOT_ENOUGH_SPACE);
  CHECK(std::strcmp(last.partition, "rlsec") == 0);
  CHECK(std::strcmp(last.name_space, "rl") == 0);
  CHECK(std::strcmp(store.partition(), "rlsec") == 0);
  CHECK(std::strcmp(store.name_space(), "rl") == 0);
  return 0;
}

int CheckWriteGeneric() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(OpenStore(store));
  CHECK(store.is_open());
  fail_op = FailOp::kWrite;
  fail_code = ESP_ERR_INVALID_ARG;
  const routeloom::ByteView data{reinterpret_cast<const std::uint8_t*>("v"), 1};
  const routeloom::Status status = store.blob_write("k", data);
  CHECK(!status.ok());
  CHECK(std::strstr(status.detail, "space") == nullptr);
  char native[32]{};
  std::snprintf(native, sizeof native, "native=0x%x", ESP_ERR_INVALID_ARG);
  CHECK(std::strstr(last_log, native) != nullptr);
  const auto last = store.last_error();
  CHECK(last.op != nullptr && std::strcmp(last.op, "blob_write") == 0);
  CHECK(last.native == ESP_ERR_INVALID_ARG);
  return 0;
}

int CheckCommitSpace() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(OpenStore(store));
  CHECK(store.is_open());
  fail_op = FailOp::kCommit;
  fail_code = ESP_ERR_NVS_NO_FREE_PAGES;
  const routeloom::ByteView data{reinterpret_cast<const std::uint8_t*>("v"), 1};
  const routeloom::Status status = store.blob_write("k", data);
  CHECK(!status.ok());
  CHECK(std::strstr(status.detail, "space") != nullptr);
  const auto last = store.last_error();
  CHECK(last.op != nullptr && std::strcmp(last.op, "commit") == 0);
  CHECK(last.native == ESP_ERR_NVS_NO_FREE_PAGES);
  return 0;
}

int CheckRoundTrip() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(OpenStore(store));
  CHECK(store.is_open());
  const routeloom::ByteView data{reinterpret_cast<const std::uint8_t*>("hello"), 5};
  CHECK(store.blob_write("k", data).ok());
  std::size_t size = 0;
  bool found = false;
  CHECK(store.blob_size("k", size, found).ok());
  CHECK(found && size == 5);
  std::uint8_t out[8]{};
  routeloom::MutableByteView target{out, sizeof(out)};
  std::size_t read_len = 0;
  CHECK(store.blob_read("k", target, read_len).ok());
  CHECK(read_len == 5 && std::memcmp(out, "hello", 5) == 0);
  return 0;
}

int CheckEraseFailuresAndAbsence() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(OpenStore(store));
  CHECK(store.blob_erase("k").ok());
  CHECK(store.write_stats().commits == 0);
  const routeloom::ByteView data{reinterpret_cast<const std::uint8_t*>("v"), 1};
  CHECK(store.blob_write("k", data).ok());
  fail_op = FailOp::kErase;
  fail_code = ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  const auto erase = store.blob_erase("k");
  CHECK(!erase.ok() && erase.code == routeloom::StatusCode::StorageFailure);
  CHECK(std::strstr(erase.detail, "space") != nullptr);
  CHECK(std::strcmp(store.last_error().op, "blob_erase") == 0);
  CHECK(store.last_error().native == ESP_ERR_NVS_NOT_ENOUGH_SPACE);
  CHECK(store.write_stats().commits == 1);
  fail_op = FailOp::kCommit;
  fail_code = ESP_ERR_INVALID_ARG;
  const auto commit = store.blob_erase("k");
  CHECK(!commit.ok() && commit.code == routeloom::StatusCode::StorageFailure);
  CHECK(std::strcmp(store.last_error().op, "commit") == 0);
  CHECK(store.last_error().native == ESP_ERR_INVALID_ARG);
  CHECK(store.write_stats().commits == 1);
  fail_op = FailOp::kNone;
  CHECK(store.blob_write("k", data).ok());
  CHECK(store.blob_erase("k").ok());
  CHECK(store.write_stats().commits == 3);
  return 0;
}
}  // namespace

int CheckLastErrorSticky() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(store.last_error().op == nullptr);
  CHECK(OpenStore(store));
  fail_op = FailOp::kWrite;
  fail_code = ESP_ERR_NVS_NOT_ENOUGH_SPACE;
  const routeloom::ByteView bad{reinterpret_cast<const std::uint8_t*>("v"), 1};
  CHECK(!store.blob_write("k", bad).ok());
  // A later success must not wipe the retained cause.
  fail_op = FailOp::kNone;
  const routeloom::ByteView good{reinterpret_cast<const std::uint8_t*>("ok"), 2};
  CHECK(store.blob_write("k", good).ok());
  const auto last = store.last_error();
  CHECK(last.op != nullptr && std::strcmp(last.op, "blob_write") == 0);
  CHECK(last.native == ESP_ERR_NVS_NOT_ENOUGH_SPACE);
  return 0;
}

int CheckOpenFailureAttributed() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  fail_op = FailOp::kOpen;
  fail_code = ESP_ERR_NVS_NOT_FOUND;
  CHECK(!store.open("rlsec", "rl").ok());
  CHECK(!store.is_open());
  const auto last = store.last_error();
  CHECK(last.op != nullptr && std::strcmp(last.op, "open") == 0);
  CHECK(last.native == ESP_ERR_NVS_NOT_FOUND);
  CHECK(std::strcmp(store.partition(), "rlsec") == 0);
  CHECK(std::strcmp(store.name_space(), "rl") == 0);
  return 0;
}

int CheckLastErrorKeepsItsNamespace() {
  Reset();
  routeloom::espnow::NvsBlobNamespace store;
  CHECK(OpenStore(store));
  fail_op = FailOp::kWrite;
  fail_code = ESP_ERR_INVALID_ARG;
  const routeloom::ByteView data{reinterpret_cast<const std::uint8_t*>("v"), 1};
  CHECK(!store.blob_write("k", data).ok());
  fail_op = FailOp::kNone;
  CHECK(store.open("other", "next").ok());
  const auto last = store.last_error();
  CHECK(std::strcmp(last.partition, "rlsec") == 0);
  CHECK(std::strcmp(last.name_space, "rl") == 0);
  CHECK(std::strcmp(store.partition(), "other") == 0);
  return 0;
}

int main() {
  if (CheckWriteSpace() != 0) return 1;
  if (CheckWriteGeneric() != 0) return 1;
  if (CheckCommitSpace() != 0) return 1;
  if (CheckRoundTrip() != 0) return 1;
  if (CheckEraseFailuresAndAbsence() != 0) return 1;
  if (CheckLastErrorSticky() != 0) return 1;
  if (CheckOpenFailureAttributed() != 0) return 1;
  if (CheckLastErrorKeepsItsNamespace() != 0) return 1;
  std::puts("PASS test_nvs_sdkv1_store");
  return 0;
}
