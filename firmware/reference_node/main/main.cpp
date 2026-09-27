// Reference node observation hooks for the shared node boot. The source and
// console live on app_main's frame, so the reference image adds no static
// observation allocation to the C3 RAM floor.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_rom_serial_output.h"
#include "esp_rom_sys.h"
#include "esp_system.h"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/node_boot.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/session_bank.hpp"
#include "sdkconfig.h"
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/espnow_security_owner.hpp"
#endif

namespace {
using routeloom::NodeId;

// --- Read-only remote observation (subtypes 7/8) -------------------------------
// Same read-only section fills as the bridge's USB observation, served to
// end-protected Diagnostic(48) queries when the remote opt-in is on.
// app_main frame, not statics (same .bss discipline as the bridge).
class RefSystemHealthPort final : public routeloom::SystemHealthPort {
 public:
  std::uint32_t heap_free_bytes() const noexcept override {
    return static_cast<std::uint32_t>(esp_get_free_heap_size());
  }
  std::uint32_t heap_min_bytes() const noexcept override {
    return static_cast<std::uint32_t>(esp_get_minimum_free_heap_size());
  }
  std::uint32_t heap_largest_bytes() const noexcept override {
    return static_cast<std::uint32_t>(
        heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
  }
  std::uint8_t reset_code() const noexcept override {
    // Mask-ROM reason, never esp_reset_reason() (same .bss discipline as
    // the bridge: the cached IDF API pulls guarded DRAM for no new
    // evidence here).
    switch (esp_rom_get_reset_reason(0)) {
      case RESET_REASON_CHIP_POWER_ON:
        return routeloom::kResetPowerOn;
      case RESET_REASON_CORE_SW:
      case RESET_REASON_CPU0_SW:
        return routeloom::kResetSoftware;
      case RESET_REASON_CORE_MWDT0:
      case RESET_REASON_CORE_MWDT1:
      case RESET_REASON_CORE_RTC_WDT:
      case RESET_REASON_CPU0_MWDT0:
      case RESET_REASON_CPU0_MWDT1:
      case RESET_REASON_CPU0_RTC_WDT:
      case RESET_REASON_SYS_RTC_WDT:
      case RESET_REASON_SYS_SUPER_WDT:
        return routeloom::kResetWatchdog;
      case RESET_REASON_CORE_DEEP_SLEEP:
        return routeloom::kResetDeepSleepWake;
      case RESET_REASON_SYS_BROWN_OUT:
        return routeloom::kResetBrownout;
      default:
        return routeloom::kResetUnknown;
    }
  }
};

class ReferenceObservationSource final : public routeloom::ObservationSource {
 public:
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  ReferenceObservationSource(const routeloom::MeshNode& node,
                             const routeloom::SystemHealthPort& port,
                             std::uint64_t boot_id, std::uint8_t profile)
      : node_(node), port_(port), boot_id_(boot_id), profile_(profile) {}
#else
  ReferenceObservationSource(const routeloom::MeshNode& node,
                             const routeloom::sdkv1::SecurityCoordinator* coordinator,
                             const routeloom::SystemHealthPort& port,
                             std::uint64_t boot_id, std::uint8_t profile)
      : node_(node),
        coordinator_(coordinator),
        port_(port),
        boot_id_(boot_id),
        profile_(profile) {}
#endif

  bool fill_system(routeloom::MonotonicMs now_ms,
                   routeloom::ObservationSystem& out) const noexcept override {
    std::uint8_t mode = routeloom::kCoordModeUnknown;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) {
      mode = map_coord_mode(coordinator_->snapshot().mode);
    }
#endif
    // Legacy fixture has no coordinator: unknown, like the bridge.
    routeloom::fill_observation_system(boot_id_, now_ms, port_,
                                       routeloom::kPowerRunning, mode, profile_,
                                       out);
    return true;
  }

  bool fill_tables(routeloom::MonotonicMs now_ms,
                   routeloom::ObservationTables& out) const noexcept override {
    std::uint16_t link = 0, link_cap = 0, end = 0, end_cap = 0;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) {
      const routeloom::sdkv1::CoordinatorSnapshot snapshot =
          coordinator_->snapshot();
      link = snapshot.link_sessions > UINT16_MAX
                 ? UINT16_MAX
                 : static_cast<std::uint16_t>(snapshot.link_sessions);
      end = snapshot.end_sessions > UINT16_MAX
                ? UINT16_MAX
                : static_cast<std::uint16_t>(snapshot.end_sessions);
      link_cap = static_cast<std::uint16_t>(
          routeloom::sdkv1::GatewaySessionBank::link_capacity());
      end_cap = static_cast<std::uint16_t>(
          routeloom::sdkv1::GatewaySessionBank::end_capacity());
    }
#endif
    routeloom::fill_observation_tables(node_, now_ms, link, link_cap, end,
                                       end_cap, out);
    return true;
  }

  bool fill_milestones(routeloom::MonotonicMs now_ms,
                       routeloom::JoinMilestones& out) const noexcept override {
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) {
      out = coordinator_->milestones(now_ms);
      return true;
    }
#endif
    out = routeloom::JoinMilestones{};
    return true;
  }

  bool fill_summary(routeloom::MonotonicMs now_ms,
                    routeloom::ObservationSummary& out) const noexcept override {
    routeloom::fill_observation_summary(node_, now_ms, 0, out);
    out.neighbor_digest = routeloom::observation_neighbor_source_digest(*this, now_ms);
    return true;
  }

  std::size_t route_detail_page(
      routeloom::NodeId after, routeloom::RouteDetailEntry* out,
      std::size_t capacity, routeloom::MonotonicMs now_ms,
      bool& more) const noexcept override {
    return node_.route_detail_page(after, out, capacity, now_ms, more);
  }

  bool route_detail_exact(routeloom::NodeId destination,
                          routeloom::MonotonicMs now_ms,
                          routeloom::RouteDetailEntry& out) const noexcept override {
    return node_.route_detail(destination, now_ms, out);
  }

  std::size_t neighbor_detail_page(
      routeloom::NodeId after, routeloom::NeighborDetailEntry* out,
      std::size_t capacity, routeloom::MonotonicMs now_ms,
      bool& more) const noexcept override {
    return routeloom::neighbor_detail_page(node_, live_discovery(), after, out,
                                           capacity, now_ms, more);
  }

  bool neighbor_detail_exact(routeloom::NodeId peer,
                             routeloom::MonotonicMs now_ms,
                             routeloom::NeighborDetailEntry& out) const noexcept override {
    return routeloom::neighbor_detail_exact(node_, live_discovery(), peer,
                                            now_ms, out);
  }

 private:
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  static std::uint8_t map_coord_mode(
      routeloom::sdkv1::CoordinatorMode mode) noexcept {
    switch (mode) {
      case routeloom::sdkv1::CoordinatorMode::Fresh:
        return routeloom::kCoordModeFresh;
      case routeloom::sdkv1::CoordinatorMode::ZeroTouch:
        return routeloom::kCoordModeZeroTouch;
      case routeloom::sdkv1::CoordinatorMode::Member:
        return routeloom::kCoordModeMember;
      case routeloom::sdkv1::CoordinatorMode::Dev:
        return routeloom::kCoordModeDev;
      case routeloom::sdkv1::CoordinatorMode::Removed:
        return routeloom::kCoordModeRemoved;
      case routeloom::sdkv1::CoordinatorMode::Recovery:
        return routeloom::kCoordModeRecovery;
    }
    return routeloom::kCoordModeUnknown;
  }
#endif

  const routeloom::NeighborDiscovery* live_discovery() const noexcept {
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) return coordinator_->discovery();
#endif
    return nullptr;
  }

  const routeloom::MeshNode& node_;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  const routeloom::sdkv1::SecurityCoordinator* coordinator_;
#endif
  const routeloom::SystemHealthPort& port_;
  std::uint64_t boot_id_;
  std::uint8_t profile_;
};

#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE && !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
// Owner-profile answer rule for subtype-7 queries: only adopted modes
// answer. Fresh (never enrolled), ZeroTouch (still joining), Removed
// (evicted) and Recovery refuse — the Kconfig symbol only compiles the
// responder in, this runtime decision opens or closes it.
bool observation_member_mode(
    routeloom::sdkv1::CoordinatorMode mode) noexcept {
  return mode == routeloom::sdkv1::CoordinatorMode::Member ||
         mode == routeloom::sdkv1::CoordinatorMode::Dev;
}
#endif

// One bounded read-only request per line, at most once per second. The
// active console channel is polled in the owner loop, never an RF callback.
class ReferenceObsConsole final {
 public:
  void poll(const ReferenceObservationSource& source, const NodeId observer,
            const routeloom::MonotonicMs now_ms) noexcept {
    for (unsigned i = 0; i < 32; ++i) {
      std::uint8_t byte = 0;
      if (esp_rom_output_rx_one_char(&byte) != 0) break;
      if (byte == '\n') {
        if (!overflow_ && length_ > 0 && line_[length_ - 1] == '\r') --length_;
        if (!overflow_ && length_ == 11 &&
            std::memcmp(line_, "obs1 health", 11) == 0) {
          if (answered_ && (now_ms < last_answer_ms_ ||
                            now_ms - last_answer_ms_ < 1000)) {
            emit("OBS1 {\"error\":\"rate_limited\"}\n");
          } else {
            routeloom::ObservationSystem system{};
            char response[512]{};
            std::size_t used = 0;
            if (source.fill_system(now_ms, system) &&
                routeloom::format_observation_console_system(
                    observer, system, response, sizeof(response), used)) {
              for (std::size_t j = 0; j < used; ++j) {
                esp_rom_output_putc(response[j]);
              }
              last_answer_ms_ = now_ms;
              answered_ = true;
            } else {
              emit("OBS1 {\"error\":\"unavailable\"}\n");
            }
          }
        } else if (length_ >= 4 && std::memcmp(line_, "obs1", 4) == 0) {
          emit("OBS1 {\"error\":\"invalid_request\"}\n");
        }
        length_ = 0;
        overflow_ = false;
      } else if (length_ < sizeof(line_)) {
        line_[length_++] = static_cast<char>(byte);
      } else {
        overflow_ = true;  // drain to newline before accepting another command
      }
    }
  }

 private:
  static void emit(const char* line) noexcept {
    for (const char* p = line; *p != '\0'; ++p) esp_rom_output_putc(*p);
  }
  char line_[32]{};
  std::size_t length_{0};
  routeloom::MonotonicMs last_answer_ms_{0};
  bool answered_{false};
  bool overflow_{false};
};

struct ReferenceObservationContext {
  RefSystemHealthPort port{};
  std::optional<ReferenceObservationSource> source{};
  ReferenceObsConsole console{};
  routeloom::espnow::EspNowRuntime* runtime{nullptr};
#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0 && \
    !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  routeloom::MonotonicMs hil_next_ms{0};
  std::uint32_t hil_attempt{0};
#endif
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  routeloom::espnow::EspNowSecurityOwner* owner{nullptr};
#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE
  bool remote_allowed{false};
#endif
#endif
};

void require_observation(const routeloom::Status status) {
  if (status) return;
  ESP_LOGE("RouteLoomRef", "observation attach failed: %s", status.detail);
  esp_restart();
  for (;;) {}
}

void reference_attach(routeloom::espnow::EspNowRuntime& runtime,
                      routeloom::espnow::EspNowSecurityOwner* owner,
                      routeloom::espnow::Sdkv1Stores*, void* opaque) {
  auto& ctx = *static_cast<ReferenceObservationContext*>(opaque);
  ctx.runtime = &runtime;
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  (void)owner;
  ctx.source.emplace(runtime.node(), ctx.port,
                     runtime.node().config().boot_incarnation,
                     routeloom::kProfileLegacyFixture);
#else
  ctx.owner = owner;
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
  constexpr std::uint8_t profile = routeloom::kProfileMemberEdhoc;
#else
  constexpr std::uint8_t profile = routeloom::kProfileDevRam;
#endif
  ctx.source.emplace(runtime.node(), &owner->coordinator(), ctx.port,
                     runtime.node().config().boot_incarnation, profile);
#endif
  require_observation(runtime.node().set_observation_source(&*ctx.source));
#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  require_observation(runtime.node().set_observation_remote(true));
#else
  ctx.remote_allowed = observation_member_mode(owner->coordinator().snapshot().mode);
  require_observation(runtime.node().set_observation_remote(ctx.remote_allowed));
#endif
#endif
}

#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0 && \
    !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
void poll_hil_send(ReferenceObservationContext& ctx,
                   routeloom::MonotonicMs now_ms) {
  if (ctx.hil_next_ms == 0) ctx.hil_next_ms = now_ms + 10000;
  if (ctx.hil_attempt >= CONFIG_ROUTELOOM_HIL_SEND_COUNT ||
      now_ms < ctx.hil_next_ms) return;

  const std::array<std::uint8_t, 8> payload{
      'R', 'L', 'H', 'I', 'L', 'D',
      static_cast<std::uint8_t>(ctx.hil_attempt >> 8),
      static_cast<std::uint8_t>(ctx.hil_attempt)};
  routeloom::MessageId id{};
  const auto sent = ctx.runtime->node().send(
      CONFIG_ROUTELOOM_HIL_SEND_DESTINATION,
      routeloom::ByteView{payload.data(), payload.size()},
      routeloom::SendOptions{}, now_ms, id);
  ESP_LOGI("RouteLoomRef", "HIL DEVICE SEND attempt=%lu dest=%llu admitted=%u detail=%s",
           static_cast<unsigned long>(ctx.hil_attempt),
           static_cast<unsigned long long>(CONFIG_ROUTELOOM_HIL_SEND_DESTINATION),
           static_cast<unsigned>(static_cast<bool>(sent)), sent.detail);
  ++ctx.hil_attempt;
  ctx.hil_next_ms = now_ms + 2000;
}
#endif

void reference_poll(routeloom::MonotonicMs now_ms, void* opaque) {
  auto& ctx = *static_cast<ReferenceObservationContext*>(opaque);
  ctx.console.poll(*ctx.source, ctx.runtime->node().node_id(), now_ms);
#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE && !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // Adoption and revocation change whether this member may answer over RF.
  const bool allow = observation_member_mode(ctx.owner->coordinator().snapshot().mode);
  if (allow != ctx.remote_allowed &&
      ctx.runtime->node().set_observation_remote(allow)) {
    ctx.remote_allowed = allow;
  }
#endif
#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0 && \
    !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  poll_hil_send(ctx, now_ms);
#endif
}

}  // namespace

extern "C" void app_main(void) {
  ReferenceObservationContext observation{};
  routeloom::espnow::NodeBootHooks hooks{};
  hooks.log_tag = "RouteLoomRef";
  hooks.attach = reference_attach;
  hooks.poll = reference_poll;
  hooks.ctx = &observation;
  routeloom::espnow::run_node(hooks);
}
