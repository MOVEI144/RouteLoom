// firmware/bench_node: the bundled bench application (design-devflow.md §5).
// All bring-up and the Owner loop are the shared routeloom_device path, the
// same as firmware/reference_node. This file only wires the portable
// routeloom::bench::BenchApp onto the Device and supplies the small ESP-IDF
// platform/probe ports the portable module declares (§5.1: no ESP
// dependencies in the portable half).

#include <cstdint>
#include <cstring>

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "routeloom/bench/app.hpp"
#include "routeloom/device.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/node.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/sdkv1_store.hpp"

namespace {

using routeloom::MonotonicMs;

MonotonicMs now_ms() noexcept {
  return static_cast<MonotonicMs>(esp_timer_get_time() / 1000);
}

// BenchPlatform over ESP-IDF. The largest-block figure uses the internal-RAM
// capability so the reported headroom matches what ram-budget.md guards
// (PSRAM is never part of the bench budget — §5.4).
class EspNowBenchPlatform final : public routeloom::bench::BenchPlatform {
 public:
  std::uint32_t heap_free_bytes() const noexcept override {
    return esp_get_free_internal_heap_size();
  }
  std::uint32_t heap_min_free_bytes() const noexcept override {
    return esp_get_minimum_free_heap_size();
  }
  std::uint32_t heap_largest_free_bytes() const noexcept override {
    return heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL |
                                            MALLOC_CAP_8BIT);
  }
  // High-water of the Owner task, whose stack hosts the bench poll step.
  std::uint32_t stack_high_water_bytes() const noexcept override {
    return static_cast<std::uint32_t>(uxTaskGetStackHighWaterMark(nullptr)) *
           sizeof(StackType_t);
  }
  std::uint8_t reset_cause() const noexcept override {
    return static_cast<std::uint8_t>(esp_reset_reason());
  }
  void restart() noexcept override { esp_restart(); }
};

// BenchProbe over the Device's read-only views (site store and coordinator
// snapshot) — never a private core table (§5.1). Fields whose public
// contract is still being built (D02 board config digest, D05
// NodeHealth/LifecycleSnapshot) keep the zero "unknown" value.
class EspNowBenchProbe final : public routeloom::bench::BenchProbe {
 public:
  void bind(routeloom::Device* device) noexcept { device_ = device; }

  void sample(routeloom::bench::BenchProbeSample& out) noexcept override {
    if (device_ == nullptr) return;
    const routeloom::espnow::Sdkv1Stores* stores = device_->stores();
    if (stores != nullptr && stores->site().has_site()) {
      const routeloom::sdkv1::SiteRecord& site = stores->site().site();
      out.site_valid = true;
      out.site_id = site.site_id;
      out.assignment_generation = site.assignment_generation;
      out.role = site.role;
      out.gk_epoch_current = site.gk_epoch_current;
      out.gk_epoch_next = site.gk_epoch_next;
    }
    const routeloom::sdkv1::SecurityCoordinator* coordinator = device_->security();
    if (coordinator != nullptr) {
      const routeloom::sdkv1::CoordinatorSnapshot snap = coordinator->snapshot();
      out.participation_valid = true;
      out.mode = static_cast<std::uint8_t>(snap.mode);
      out.membership = static_cast<std::uint8_t>(snap.membership);
      out.joiner = static_cast<std::uint8_t>(snap.joiner);
      out.joiner_error = static_cast<std::uint8_t>(snap.joiner_last_error);
      out.joiner_observations = snap.joiner_observations;
      out.radio_generation = snap.radio_generation;
      out.authority_flags =
          static_cast<std::uint8_t>((snap.authority_started ? 1 : 0) |
                                    (snap.authority_ready ? 2 : 0) |
                                    (snap.authority_busy ? 4 : 0) |
                                    (snap.join_confirmed ? 8 : 0));
      out.refresh_strikes = snap.refresh_strikes;
      out.link_sessions = snap.link_sessions > 0xFFFF
                              ? 0xFFFF
                              : static_cast<std::uint16_t>(snap.link_sessions);
      out.end_sessions = snap.end_sessions > 0xFFFF
                             ? 0xFFFF
                             : static_cast<std::uint16_t>(snap.end_sessions);
      // The live engine pair supersedes the adopted record's staged epochs.
      std::uint32_t current = 0;
      std::uint32_t next = 0;
      if (coordinator->group_epochs(current, next)) {
        out.gk_epoch_current = current;
        out.gk_epoch_next = next;
      }
    }
    const routeloom::MeshNode* node = device_->mesh();
    if (node != nullptr) {
      const routeloom::NodeConfig& config = node->config();
      out.route_profile = config.route_gateways[0] != routeloom::kInvalidNodeId ? 1 : 0;
      out.gateway = config.route_gateways[0];
    }
  }

 private:
  routeloom::Device* device_{nullptr};
};

struct BenchContext {
  BenchContext() noexcept : app(config) {}
  routeloom::bench::BenchConfig config{};
  routeloom::bench::BenchApp app;
  EspNowBenchPlatform platform;
  EspNowBenchProbe probe;
  bool attached{false};
};
static_assert(sizeof(BenchContext) <= 2048,
              "bench application state exceeds the 2 KiB budget");

// The BenchApp binds to the booted node on the first Owner pass.
void bench_poll(routeloom::Device& device, MonotonicMs now, void* ctx) {
  auto* bench = static_cast<BenchContext*>(ctx);
  if (!bench->attached) {
    bench->probe.bind(&device);
    bench->app.set_platform(&bench->platform);
    bench->app.set_probe(&bench->probe);
    bench->app.attach(*device.mesh(), now);
    bench->attached = true;
  }
  bench->app.poll(now);
}

// Static storage: the app's full state (the 2 KiB increment the design
// budgets) is .bss, so tools/firmware_ram_report.py accounts it against
// the bench floor directly.
BenchContext s_bench{};
routeloom::Device s_device;

}  // namespace

extern "C" void app_main(void) {
  // The authorized controller defaults to the adopted route gateway; the
  // Kconfig pin exists for flat dev builds that adopt no gateway.
  // The D02 BoardConfig digest is what this field becomes per-device.
  s_bench.config.controller = CONFIG_ROUTELOOM_BENCH_CONTROLLER;
  // App-image fingerprint for the STATUS identity page: first word of the
  // ELF SHA-256 IDF stamps into the image header.
  const esp_app_desc_t* desc = esp_app_get_description();
  if (desc != nullptr) {
    std::memcpy(&s_bench.config.firmware_digest, desc->app_elf_sha256,
                sizeof(s_bench.config.firmware_digest));
  }
  s_bench.app.configure(s_bench.config);
  routeloom::DeviceConfig config = routeloom::device_config_from_kconfig();
  config.log_tag = "RouteLoomBench";
  s_device.observe(&s_bench.app);
  s_device.on_poll(bench_poll, &s_bench);
  s_device.start(config);
}
