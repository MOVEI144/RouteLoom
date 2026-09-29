#pragma once

// routeloom::Device — the one boot path and the application facade of an
// ESP-NOW node (v2 plan V2-07). Every image (reference, bench, bridge,
// example) and the host mesh harness peer boot through the same calls:
// open_storage() (boot session + rlsec stores), begin() (security owner,
// runtime, USB bridge, node start deferral) and step() (one Owner pass).
// On ESP-IDF, start() does all of it on a dedicated Owner task whose stack
// and priority come from Kconfig; device_config_from_kconfig() fills the
// configuration in one place.
//
// The facade holds no mesh state: membership, routes and sessions stay in
// the Owner and MeshNode, and every call delegates to them. Only post() may
// be called from another task; every other call belongs to the Owner task
// (a poll/observer callback or a posted job).

#include <array>
#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/node.hpp"
#include "routeloom/profile.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_bridge.hpp"
#include "sdkconfig.h"

// Remote-config target of a DevRam or Member node (V2-08, issue #17): the
// SDK-namespace journal on the node's routed config lane. Firmware images
// compile it with CONFIG_ROUTELOOM_CONFIG; the host mesh harness peer
// defines it to 1 (LegacyFixture keeps its own wiring until its removal).
#ifndef ROUTELOOM_DEVICE_REMOTE_CONFIG
#if defined(ESP_PLATFORM)
#define ROUTELOOM_DEVICE_REMOTE_CONFIG \
  (CONFIG_ROUTELOOM_CONFIG && !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE)
#else
#define ROUTELOOM_DEVICE_REMOTE_CONFIG 0
#endif
#endif

// Manual channel plan of a Member node (V2-08, issue #5 manual): the
// migration participant on every member and the site's plan authority on
// the gateway, both verifying under the adopted site's SAK. Firmware
// images compile it with CONFIG_ROUTELOOM_MIGRATION on MemberEdhoc; the
// host mesh harness peer defines it to 1.
#ifndef ROUTELOOM_DEVICE_MIGRATION
#if defined(ESP_PLATFORM)
#define ROUTELOOM_DEVICE_MIGRATION \
  (CONFIG_ROUTELOOM_MIGRATION && CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC)
#else
#define ROUTELOOM_DEVICE_MIGRATION 0
#endif
#endif

namespace routeloom {

class EntropySource;
struct DeviceChannelPlan;
class GatewayDelivery;
class ObservationSource;
struct DeviceRemoteConfig;

namespace sdkv1 {
class SecurityCoordinator;
struct RtcSessionImage;
}  // namespace sdkv1

namespace espnow {
class EspNowSecurityOwner;
class Sdkv1Stores;
}  // namespace espnow

// Session security of a non-legacy image. LegacyFixture is a compile-time
// profile (CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE) until its removal.
enum class DeviceSecurity : std::uint8_t { DevRam = 1, Member = 2 };

struct DeviceConfig {
  const char* log_tag{"RouteLoomNode"};
  profile::Role role{profile::kRole};
  DeviceSecurity security{DeviceSecurity::DevRam};
  // Pre-adoption identity, channel, TX power and route profile. begin()
  // sets the boot-session fields; Member rewrites the rest at adoption.
  espnow::EspNowRuntimeConfig radio{};
  // Station MAC the runtime reads back after Wi-Fi init.
  MacAddress mac{};
  // Join capability and requested role bits; 0 derives them from `role`
  // (a gateway requests the gateway role, other roles their full mask).
  std::uint8_t role_capability{0};
  std::uint8_t requested_role{0};
  // Flat group profile: SitePackage gateways become group roots.
  bool flat_group_routing{false};
  // DevRam: the committed rlkeys PSK. begin() and start() clear this copy.
  keys::Secret dev_psk{};
  // Gateway role: the USB byte stream, the session secret (outlives the
  // device), the HelloAck capability bitmap and the device nonce (0 draws
  // one from the radio RNG after RF start).
  usb::ByteStream* usb{nullptr};
  ByteView usb_secret{};
  std::uint32_t usb_capability{0};
  std::uint64_t usb_device_nonce{0};
  // Remote-config target (non-gateway roles, ROUTELOOM_DEVICE_REMOTE_CONFIG
  // builds). Member binds the journal to the adopted site's SAK; DevRam
  // verifies the development permit key derived from its PSK, issued by
  // `config_authority` at `config_authority_generation`.
  bool remote_config{false};
  NodeId config_authority{kInvalidNodeId};
  std::uint32_t config_authority_generation{1};
  // Manual channel plan (Member, ROUTELOOM_DEVICE_MIGRATION builds): the
  // MigrationMode (0 off, 1 Observe, 2 Manual) and the deployment's
  // measured bounds a plan must fit: management RTT P99, control delivery,
  // prepare transfer and local switch, in ms.
  std::uint8_t channel_plan{0};
  std::uint32_t plan_rtt_p99_ms{250};
  std::uint32_t plan_delivery_bound_ms{2000};
  std::uint32_t plan_transfer_bound_ms{2000};
  std::uint32_t plan_switch_bound_ms{50};
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  SecurityProvider* legacy_security{nullptr};
#else
  // Member deep sleep: the retained RTC session image the Owner restores.
  sdkv1::RtcSessionImage* sleep_image{nullptr};
#endif
};

struct DeviceCapabilities {
  profile::Role role{profile::Role::Endpoint};
  bool member{false};          // MemberEdhoc (false: DevRam or LegacyFixture)
  bool usb_gateway{false};     // USB bridge attached
  bool scoped_routing{false};  // gateway-scoped route profile in force
  bool group_send{false};      // send_group() admissible on this node now
  std::uint16_t max_payload{0};
  std::uint16_t max_group_payload{0};
};

// USB authentication binds the committed Member network (full u64) after a
// cutover; a gateway still awaiting its first join has no site record and
// uses its provisioned bootstrap network. The mesh header keeps the low word.
inline NetworkId usb_boot_network(const sdkv1::SiteStore& site, NetworkId bootstrap) noexcept {
  return site.has_site() ? site.site().network : bootstrap;
}

#if defined(ESP_PLATFORM)
// The build's configuration: Kconfig identity, role, security mode,
// channel, TX power and route profile, plus the USB settings on a gateway
// image. Field images replace the identity from the verified BoardConfig.
DeviceConfig device_config_from_kconfig() noexcept;
#endif

class Device {
 public:
  using Job = void (*)(Device& device, void* ctx);
  using PollHook = void (*)(Device& device, MonotonicMs now_ms, void* ctx);
  static constexpr std::uint8_t kPostCapacity = 8;

  Device() noexcept = default;
  Device(const Device&) = delete;
  Device& operator=(const Device&) = delete;

  // Application callbacks, set before begin()/start(). `app` receives every
  // NodeObserver callback (on_message, on_delivery, group and diagnostic)
  // after the Device's own handling; the poll hook runs once per Owner pass.
  void observe(NodeObserver* app) noexcept { app_ = app; }
  void on_poll(PollHook hook, void* ctx) noexcept {
    poll_hook_ = hook;
    poll_ctx_ = ctx;
  }

#if defined(ESP_PLATFORM)
  // Serves the read-only observation source: observation() and, with
  // CONFIG_ROUTELOOM_OBSERVATION_REMOTE, remote queries. Call before
  // start(). Gateway and remote-query images serve it anyway; any other
  // image that never calls this links none of the observation code.
  void enable_observation() noexcept;

  // Runs the whole node on a dedicated Owner task. Copies the configuration
  // and clears the caller's DevRam PSK before returning. Boot failures take
  // the fail-streak restart/sleep path.
  void start(DeviceConfig& config) noexcept;
#endif

  // Boot session and rlsec stores (the resume capacity follows the role).
  Status open_storage(profile::Role role, DeviceSecurity security) noexcept;
  std::uint32_t boot_session() const noexcept { return boot_session_; }
  // Security owner, runtime, USB bridge and the membership boot/adoption.
  // The node itself starts on adoption (Member) or right away (DevRam).
  Status begin(DeviceConfig& config, MonotonicMs now_ms) noexcept;

  // One Owner pass: USB, runtime drain, owner, posted jobs, poll hook.
  void step(MonotonicMs now_ms) noexcept;
  // Latest time the next step() may run. Fixed at one Owner poll period
  // until the components report their deadlines.
  MonotonicMs next_deadline(MonotonicMs now_ms) const noexcept;
  // Gateway USB input for the next step().
  void usb_receive(ByteView bytes, MonotonicMs now_ms) noexcept;

  // The only call another task may make: queues `job` for the Owner task.
  // Busy when kPostCapacity jobs are waiting.
  Status post(Job job, void* ctx) noexcept;

  Status send(NodeId destination, ByteView payload, const SendOptions& options,
              MessageId& id) noexcept;
  Status send_group(GroupId group, ByteView payload, const GroupSendOptions& options,
                    MessageId& id) noexcept;
  Status cancel(const MessageId& id) noexcept;
  DeliveryResult delivery(const MessageId& id) const noexcept;
  DeviceCapabilities capabilities() const noexcept;

  // Read-only views for diagnostics apps (bench, observation console).
  NodeId node_id() const noexcept;
  const ObservationSource* observation() const noexcept { return observation_; }
  const sdkv1::SecurityCoordinator* security() const noexcept;
  const espnow::Sdkv1Stores* stores() const noexcept { return stores_; }
  // Portable modules written against the core MeshNode API (routeloom_bench).
  MeshNode* mesh() noexcept;
  // Explicit gateway delivery (Service=21, 03-explicit-gateway): an origin
  // resolves a named gateway and sends to it; a USB gateway attaches the
  // responder half. Null before begin() or while sink attachment is busy;
  // retry on the next Owner call. An image that never calls it links none
  // of it.
  GatewayDelivery* gateway() noexcept;

 private:
  friend struct DeviceTestAccess;
  class Observer final : public NodeObserver {
   public:
    // Constant-initialized, so begin() holds it without a guard and an
    // image that never begins (maintenance console) links none of it.
    constexpr Observer() noexcept = default;
    void bind(Device& device) noexcept { device_ = &device; }
    void on_message(const MessageKey& key, NodeId source, ByteView payload) noexcept override;
    void on_message(const MessageKey& key, NodeId source, ByteView payload,
                    const DeliveryAssurance& assurance) noexcept override;
    void on_group_message(const GroupMessageInfo& info, ByteView payload) noexcept override;
    void on_delivery(const DeliveryResult& result) noexcept override;
    void on_group_delivery(const GroupDeliveryResult& result) noexcept override;
    void on_applied_result(const MessageKey& key,
                           const AppliedResultView& result) noexcept override;
    void on_diagnostic(const char* reason, NodeId peer,
                       const MessageId* message) noexcept override;

   private:
    Device* device_{nullptr};
  };
  struct Posted {
    Job job{nullptr};
    void* ctx{nullptr};
  };

  void run_posted() noexcept;
  void update_observation_remote() noexcept;
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
  Status begin_remote_config(const DeviceConfig& config, const keys::Secret& dev_psk,
                             EntropySource& entropy, MonotonicMs now_ms) noexcept;
  void poll_remote_config(MonotonicMs now_ms) noexcept;
#endif
#if ROUTELOOM_DEVICE_MIGRATION
  Status begin_channel_plan(const DeviceConfig& config) noexcept;
  void poll_channel_plan(MonotonicMs now_ms) noexcept;
#endif
#if defined(ESP_PLATFORM)
  static void task_entry(void* self) noexcept;
  [[noreturn]] void boot_and_run(DeviceConfig& config) noexcept;
#endif

  const char* tag_{"RouteLoomNode"};
  NodeObserver* app_{nullptr};
  PollHook poll_hook_{nullptr};
  void* poll_ctx_{nullptr};
  espnow::Sdkv1Stores* stores_{nullptr};
  espnow::EspNowRuntime* runtime_{nullptr};
  espnow::EspNowSecurityOwner* owner_{nullptr};
  usb::UsbBridge* bridge_{nullptr};
  GatewayDelivery* gateway_{nullptr};
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
  DeviceRemoteConfig* remote_config_{nullptr};
#endif
#if ROUTELOOM_DEVICE_MIGRATION
  DeviceChannelPlan* channel_plan_{nullptr};
#endif
  const ObservationSource* observation_{nullptr};
#if defined(ESP_PLATFORM)
  // Builds the source in the Owner frame's slot; set by enable_observation().
  const ObservationSource* (*observation_build_)(void* slot, Device& device,
                                                 std::uint8_t profile) noexcept {nullptr};
#endif
  std::uint32_t boot_session_{0};
  DeviceSecurity security_{DeviceSecurity::DevRam};
  profile::Role role_{profile::Role::Endpoint};
  bool observation_remote_{false};
  std::array<Posted, kPostCapacity> posted_{};
  std::uint8_t posted_head_{0};
  std::uint8_t posted_count_{0};
  portMUX_TYPE posted_lock_ = portMUX_INITIALIZER_UNLOCKED;
};

}  // namespace routeloom
