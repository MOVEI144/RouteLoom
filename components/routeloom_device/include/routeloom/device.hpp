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
// the Owner and MeshNode, and every call delegates to them. It keeps only
// what its own events need (the last reported stage and connectivity with
// their times, and the one operation in progress). Only post() may be
// called from another task; every other call belongs to the Owner task (a
// poll hook or a posted job). A call made from inside a Device callback
// returns Busy.

#include <array>
#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/node.hpp"
#include "routeloom/power.hpp"
#include "routeloom/app_object.hpp"
#include "routeloom/profile.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_bridge.hpp"
#include "sdkconfig.h"

// Firmware reserves sleep state only in its explicit deep-sleep build.
// Host harnesses exercise the same API with caller-owned storage.
#ifndef ROUTELOOM_DEVICE_SLEEP
#if defined(ESP_PLATFORM)
#define ROUTELOOM_DEVICE_SLEEP CONFIG_ROUTELOOM_DEEP_SLEEP
#else
#define ROUTELOOM_DEVICE_SLEEP 1
#endif
#endif

// Remote-config target of a DevRam or Member node (V2-08, issue #17): the
// SDK-namespace journal on the node's routed config lane. Firmware images
// compile it with CONFIG_ROUTELOOM_CONFIG; the host mesh harness peer
// defines it to 1.
#ifndef ROUTELOOM_DEVICE_REMOTE_CONFIG
#if defined(ESP_PLATFORM)
#define ROUTELOOM_DEVICE_REMOTE_CONFIG CONFIG_ROUTELOOM_CONFIG
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

struct rl_dev;
struct rl_dev_observer;

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

// Session security of an image.
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
  // one from the radio RNG after RF start). An attached stream with an
  // unset secret is rejected by begin() before Owner/radio startup.
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
  // Member deep sleep: the retained RTC session image the Owner restores.
  sdkv1::RtcSessionImage* sleep_image{nullptr};
};

struct DeviceCapabilities {
  profile::Role role{profile::Role::Endpoint};
  bool member{false};          // MemberEdhoc (false: DevRam)
  // Development (DevRam) or Candidate (MemberEdhoc until certified).
  SecurityProfile security_profile{SecurityProfile::Development};
  bool usb_gateway{false};     // USB bridge attached
  bool scoped_routing{false};  // gateway-scoped route profile in force
  bool group_send{false};      // send_group() admissible on this node now
  std::uint16_t max_payload{0};
  std::uint16_t max_group_payload{0};
  bool object_transfer{false};
  std::uint16_t max_object_bytes{0};
  std::uint8_t object_rx_slots{0};
};

// --- Membership, connectivity and operations (#191, #192, #193) ------------------

using JoinPolicy = sdkv1::JoinPolicy;
// A request_join/leave, unique within one boot; 0 is none.
using OperationId = std::uint32_t;

enum class MembershipStage : std::uint8_t {
  Unprovisioned = 0,  // no device identity: nothing to join with
  Joining = 1,        // zero-touch or re-verifying a retained membership
  PendingAuthority = 2,  // the site answered Pending for the last attempt
  Member = 3,
  Removed = 4,        // the site removed this device; erasure or holdoff runs
  Recovery = 5,       // the stores need recovery before any membership
  Leaving = 6,        // a local leave is erasing the membership
};

// Read from the security owner and the stores at each call.
struct MembershipSnapshot {
  MembershipStage stage{MembershipStage::Unprovisioned};
  std::uint64_t site_id{0};
  NetworkId network{0};      // full 64-bit network
  NodeId node{kInvalidNodeId};
  std::uint32_t generation{0};  // assignment generation
  std::uint8_t role{0};         // granted member role bits
  MonotonicMs since_ms{0};      // this boot's monotonic clock only
  std::uint32_t boot{0};        // boot incarnation
  std::uint16_t reason{0};      // reason id of the last stage change
  OperationId operation{0};     // request_join/leave in progress
};

// Reachability of this site's gateways from authenticated evidence only: a
// verified message from a gateway, or a route to a gateway refreshed by the
// gateway directly (never a relay's route lease). RSSI or a table entry alone never counts.
// Membership is separate: Isolated never drops the membership.
enum class Connectivity : std::uint8_t {
  Unknown = 0,    // no evidence yet this boot, or not a member
  Reachable = 1,  // gateway evidence within kConnectivityFreshMs and a route
  Degraded = 2,   // evidence older than fresh, or no route, for < kConnectivityIsolatedMs
  Isolated = 3,   // no gateway evidence for kConnectivityIsolatedMs
  Sleeping = 4,   // in deep sleep (set by the sleep path)
};
enum class ConnectivityScope : std::uint8_t { SiteGateway = 0 };
constexpr std::uint32_t kConnectivityFreshMs = 60000;
constexpr std::uint32_t kConnectivityIsolatedMs = 120000;

struct ConnectivitySnapshot {
  Connectivity state{Connectivity::Unknown};
  ConnectivityScope scope{ConnectivityScope::SiteGateway};
  MonotonicMs since_ms{0};
  std::uint32_t boot{0};
  bool contact_valid{false};
  MonotonicMs last_contact_ms{0};  // last verified gateway evidence
  std::uint16_t reason{0};
};

// Device events, on the Owner task after the step that observed them.
// Each stage or connectivity change is reported once.
class DeviceObserver {
 public:
  virtual ~DeviceObserver() = default;
  virtual void on_membership(const MembershipSnapshot& snapshot, std::uint16_t cause) noexcept {
    (void)snapshot;
    (void)cause;
  }
  virtual void on_connectivity(const ConnectivitySnapshot& snapshot) noexcept { (void)snapshot; }
  // Durable sleep pending was re-injected (Ok) or refused/expired. Ok is
  // admission only; on_delivery reports the subsequent delivery outcome.
  virtual void on_sleep_pending_result(const PendingDeliveryRecord&, StatusCode) noexcept {}
  // A request_join or leave ended: JOINED, JOIN_DENIED, JOIN_PENDING,
  // JOIN_TIMEOUT, LEFT or RECOVERY_REQUIRED (reason ids).
  virtual void on_operation(OperationId operation, std::uint16_t result) noexcept {
    (void)operation;
    (void)result;
  }
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

class Device;
// The C API handle (device.h) over `device`, for an application that boots
// the Device itself with begin() and step(). One handle per image: it
// takes over observe(), observe_device() and on_poll(), and copies
// `observer` (may be null). rl_dev_start() is the Kconfig boot path.
// Returns null for an invalid observer header or a second binding, without
// changing the existing observer or starting a task.
rl_dev* device_c_bind(Device& device, const rl_dev_observer* observer) noexcept;

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
  void observe_device(DeviceObserver* observer) noexcept { device_observer_ = observer; }
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
  // Minimum component deadline bounded by the role ceiling (endpoint
  // 1000 ms, relay 100 ms, gateway 20 ms); unsupported work keeps 2 ms.
  MonotonicMs next_deadline(MonotonicMs now_ms) const noexcept;
  // Caller-owned coordinator over mesh(), with an Owner-aware PowerPort.
  // Bind once after adoption; all sleep work then runs through step().
  Status bind_sleep(PowerCoordinator& power, ResetCause cause, ElapsedInterval elapsed,
                    MonotonicMs now_ms) noexcept;
  Status prepare_sleep(const SleepRequest& request) noexcept;
  Status enter_sleep(const SleepTicket& ticket) noexcept;
  Status abort_sleep() noexcept;
  Status wake(ResetCause cause, ElapsedInterval elapsed, MonotonicMs now_ms) noexcept;
  SleepTicket sleep_ticket() const noexcept;
  ResumeOutcome wake_info() const noexcept;
  // Gateway USB input for the next step().
  void usb_receive(ByteView bytes, MonotonicMs now_ms) noexcept;

  // The only call another task may make: queues `job` for the Owner task.
  // Busy when kPostCapacity jobs are waiting or sleep handoff has begun.
  Status post(Job job, void* ctx) noexcept;

  Status send(NodeId destination, ByteView payload, const SendOptions& options,
              MessageId& id) noexcept;
  void observe_object(ObjectObserver* observer) noexcept {
#if ROUTELOOM_APP_OBJECT_TRANSFER
    object_observer_ = observer;
#else
    (void)observer;
#endif
  }
  Status send_object(NodeId destination, ByteView data, const ObjectOptions& options,
                     ObjectId& id) noexcept;
  Status cancel_object(ObjectId id) noexcept;
  Status register_object_buffer(MutableByteView storage) noexcept;

  Status send_group(GroupId group, ByteView payload, const GroupSendOptions& options,
                    MessageId& id) noexcept;
  Status cancel(const MessageId& id) noexcept;
  DeliveryResult delivery(const MessageId& id) const noexcept;
  DeviceCapabilities capabilities() const noexcept;

  // APPLIED: the destination's lease comes from its StaleLease answer. The
  // sink may defer (AppliedReply::deferred) and complete_applied() later;
  // at most kAppliedTicketMax tickets are open at once.
  Status send_applied(NodeId destination, ByteView payload, const ExecutionLease& lease,
                      const SendOptions& options, MessageId& id) noexcept;
  Status set_applied_sink(AppliedEndpointSink* sink) noexcept;
  Status complete_applied(std::uint64_t ticket, const AppliedReply& reply) noexcept;

  MembershipSnapshot membership() const noexcept;
  ConnectivitySnapshot connectivity() const noexcept;
  // Unassigned: the zero-touch scan starts now (avoid holds stay). Member:
  // re-verifies the membership with the site. Ends with on_operation.
  // Opaque installation mark for the expected-device policy. Keep it
  // private: possession permits correlating this device's light probes.
  Status join_mark(sdkv1::JoinMark& out) noexcept;
  Status request_join(OperationId& operation) noexcept;
  // Leaves the site: the intent is durable before anything is erased, and
  // a power cut resumes it at the next boot. The site membership, resume
  // state and site trust are erased; the device identity, boot counter,
  // board config and keys stay. Untransmitted sends end CANCELLED_LEAVE.
  // The device then restarts unassigned; on_operation(LEFT) comes first.
  Status leave(OperationId& operation) noexcept;
  // Range-checked (join_policy_check) and compare-and-set: Conflict unless
  // `expected_revision` is the stored revision (0 before any). Stored
  // (RLJP1), read back, then applied from the next decision on.
  Status set_join_policy(const JoinPolicy& policy, std::uint32_t expected_revision,
                         std::uint32_t& revision) noexcept;
  Status join_policy(JoinPolicy& policy, std::uint32_t& revision) noexcept;

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
  friend struct ::rl_dev;
  friend struct DeviceTestAccess;
  void bind_runtime(espnow::EspNowRuntime& runtime) noexcept;
  class Observer final : public NodeObserver
#if ROUTELOOM_DEVICE_SLEEP
                       , public PowerEvents
#endif
#if ROUTELOOM_APP_OBJECT_TRANSFER
                       , public ObjectObserver
#endif
                       {
   public:
    // Constant-initialized, so begin() holds it without a guard and an
    // image that never begins (maintenance console) links none of it.
    constexpr Observer() noexcept = default;
    void bind(Device& device) noexcept { device_ = &device; }
#if ROUTELOOM_DEVICE_SLEEP
    void on_transition(PowerState, PowerState, const char*) noexcept override {}
    void on_pending_result(const PendingDeliveryRecord& record,
                           StatusCode result) noexcept override;
    void on_diagnostic(const char* reason) noexcept override {
      on_diagnostic(reason, kInvalidNodeId, nullptr);
    }
#endif
#if ROUTELOOM_APP_OBJECT_TRANSFER
    bool object_receive_ready() const noexcept override;
    std::size_t object_receive_slots() const noexcept override;
    void on_object(const ObjectRxInfo& info, ByteView data) noexcept override;
    void on_object_result(const ObjectResult& result) noexcept override;
#endif
    void on_message(const MessageKey& key, NodeId source, ByteView payload) noexcept override;
    void on_message(const MessageKey& key, NodeId source, ByteView payload,
                    const DeliveryAssurance& assurance) noexcept override;
    void on_group_message(const GroupMessageInfo& info, ByteView payload) noexcept override;
    void on_verified_contact(NodeId source, MonotonicMs now_ms) noexcept override;
    void on_delivery(const DeliveryResult& result) noexcept override;
    void on_group_delivery(const GroupDeliveryResult& result) noexcept override;
    void on_applied_result(const MessageKey& key,
                           const AppliedResultView& result) noexcept override;
    void on_diagnostic(const char* reason, NodeId peer,
                       const MessageId* message) noexcept override;

   private:
    Device* device_{nullptr};
  };
  static Observer& observer() noexcept {
    static Observer value;
    return value;
  }
  struct Posted {
    Job job{nullptr};
    void* ctx{nullptr};
  };

  enum class Operation : std::uint8_t { None = 0, Join, Leave };

  bool callback_active() const noexcept;
  void run_posted(std::uint8_t budget) noexcept;
  void update_observation_remote() noexcept;
  Status apply_join_policy(const JoinPolicy& policy) noexcept;
  MembershipStage current_stage() const noexcept;
  void update_membership(MonotonicMs now_ms) noexcept;
  void update_connectivity(MonotonicMs now_ms) noexcept;
  void note_gateway_contact(NodeId source, MonotonicMs now_ms) noexcept;
  void finish_operation(std::uint16_t result) noexcept;
  static void on_restart(void* self, bool leave) noexcept;
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
  Status begin_remote_config(const DeviceConfig& config, const keys::Secret& dev_psk,
                             EntropySource& entropy, MonotonicMs now_ms) noexcept;
  void poll_remote_config(MonotonicMs now_ms) noexcept;
#endif
#if ROUTELOOM_DEVICE_MIGRATION
  Status begin_channel_plan(const DeviceConfig& config) noexcept;
  void poll_channel_plan(MonotonicMs now_ms) noexcept;
  void search_stranded(DeviceChannelPlan& plan, MonotonicMs now_ms) noexcept;
#endif
#if defined(ESP_PLATFORM)
  static void task_entry(void* self) noexcept;
  [[noreturn]] void boot_and_run(DeviceConfig& config) noexcept;
#endif

  const char* tag_{"RouteLoomNode"};
  NodeObserver* app_{nullptr};
#if ROUTELOOM_APP_OBJECT_TRANSFER
  ObjectObserver* object_observer_{nullptr};
  AppObject* object_{nullptr};
#endif
  PollHook poll_hook_{nullptr};
  void* poll_ctx_{nullptr};
  espnow::Sdkv1Stores* stores_{nullptr};
  espnow::EspNowRuntime* runtime_{nullptr};
  espnow::EspNowSecurityOwner* owner_{nullptr};
  usb::UsbBridge* bridge_{nullptr};
  GatewayDelivery* gateway_{nullptr};
#if ROUTELOOM_DEVICE_SLEEP
  PowerCoordinator* power_{nullptr};
  RadioGeneration sleep_radio_generation_{};
#endif
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
  // Event bookkeeping (see the header comment), widest fields first.
  MonotonicMs stage_since_ms_{0};
  MonotonicMs connectivity_since_ms_{0};
  MonotonicMs contact_ms_{0};
  MonotonicMs member_since_ms_{0};
  MonotonicMs operation_deadline_ms_{0};
  DeviceObserver* device_observer_{nullptr};
  std::uint32_t seen_attempts_{0};
  std::uint32_t pending_base_{0};
  OperationId operation_id_{0};  // the last one issued; live while operation_ != None
  std::uint32_t operation_denies_{0};
  std::uint32_t operation_pendings_{0};
  bool smart_join_{false};
  std::uint32_t search_ms_{60000};
  std::uint32_t isolation_notice_ms_{0};  // JoinPolicy
  std::uint16_t stage_reason_{0};
  std::uint16_t connectivity_reason_{0};
  bool in_callback_{false};
  bool stage_known_{false};
  MembershipStage stage_{MembershipStage::Unprovisioned};
  bool pending_authority_{false};
  Connectivity connectivity_{Connectivity::Unknown};
  bool contact_valid_{false};
  bool isolation_noticed_{false};
  Operation operation_{Operation::None};
  bool operation_left_member_{false};
  // The image's requested role and the role bits a JoinPolicy may request.
  std::uint8_t default_role_{0};
  std::uint8_t allowed_roles_{0};
  std::array<Posted, kPostCapacity> posted_{};
  std::uint8_t posted_head_{0};
  std::uint8_t posted_count_{0};
#if ROUTELOOM_DEVICE_SLEEP
  bool sleep_post_blocked_{false};  // guarded by posted_lock_
#endif
  portMUX_TYPE posted_lock_ = portMUX_INITIALIZER_UNLOCKED;
};

}  // namespace routeloom
