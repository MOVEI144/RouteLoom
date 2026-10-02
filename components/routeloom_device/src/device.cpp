// Device core: storage, security owner, runtime and USB bring-up plus the
// Owner pass. Shared verbatim by the ESP-IDF images (device_esp.cpp) and
// the host mesh harness peer, so the harness boots the production path.

#include "routeloom/device.hpp"

#include <cstring>

#include "esp_attr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "routeloom/config_wire.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_board_config.hpp"
#include "routeloom/gateway.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_sdkv1_store.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/secure_clear.hpp"
#include "routeloom/version.h"

// Long-lived CPU-only state resides in LP SRAM on the C5 Owner profiles and
// the gateway store set in the C3 RTC bank; radio buffers stay in HP SRAM.
#if CONFIG_IDF_TARGET_ESP32C5
#define ROUTELOOM_OWNER_C5_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_OWNER_C5_LP
#endif

// USB gateway endpoints: a firmware image fixes its HelloAck bitmap in
// Kconfig, so an endpoint it does not name reserves no gateway RAM; the
// host harness selects them per run with the capability bitmap.
#if defined(ESP_PLATFORM)
#define ROUTELOOM_DEVICE_GATEWAY_ENDPOINT \
  (CONFIG_ROUTELOOM_ROLE_GATEWAY && (CONFIG_ROUTELOOM_CAPABILITY & 0x8))
#define ROUTELOOM_DEVICE_CONFIG_ENDPOINT \
  (CONFIG_ROUTELOOM_ROLE_GATEWAY && (CONFIG_ROUTELOOM_CAPABILITY & 0x10))
#else
#define ROUTELOOM_DEVICE_GATEWAY_ENDPOINT ROUTELOOM_PROFILE_HAS_GATEWAY
#define ROUTELOOM_DEVICE_CONFIG_ENDPOINT ROUTELOOM_PROFILE_HAS_GATEWAY
#endif

namespace routeloom {

// A firmware image compiles one security mode (Kconfig) and leaves the
// other mode's Owner paths out; the host harness, which has no Kconfig,
// compiles both and selects at run time.
#define ROUTELOOM_DEVICE_DEV_RAM !CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
#define ROUTELOOM_DEVICE_MEMBER !CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM

namespace {

// Marks a Device callback: Device calls made inside it return Busy, so no
// application code re-enters the Owner from its own callbacks.
class CallbackScope {
 public:
  explicit CallbackScope(bool& flag) noexcept : flag_(flag), prior_(flag) { flag_ = true; }
  ~CallbackScope() { flag_ = prior_; }
  CallbackScope(const CallbackScope&) = delete;
  CallbackScope& operator=(const CallbackScope&) = delete;

 private:
  bool& flag_;
  bool prior_;
};

std::uint16_t membership_cause(const MembershipStage stage) noexcept {
  switch (stage) {
    case MembershipStage::Member: return ROUTELOOM_REASON_JOINED;
    case MembershipStage::PendingAuthority: return ROUTELOOM_REASON_JOIN_PENDING;
    case MembershipStage::Leaving: return ROUTELOOM_REASON_LEAVING;
    case MembershipStage::Removed: return ROUTELOOM_REASON_REMOVED;
    case MembershipStage::Recovery: return ROUTELOOM_REASON_RECOVERY_REQUIRED;
    default: return ROUTELOOM_REASON_MEMBERSHIP_CHANGED;
  }
}

}  // namespace

// --- Observer -------------------------------------------------------------------
// The runtime's single NodeObserver: logs on nodes without a USB host, feeds
// the Owner's group-key backstop, then forwards to the bridge and the app.

void Device::Observer::on_message(const MessageKey& key, const NodeId source,
                                  const ByteView payload) noexcept {
  on_message(key, source, payload, DeliveryAssurance{});
}

void Device::Observer::on_message(const MessageKey& key, const NodeId source,
                                  const ByteView payload,
                                  const DeliveryAssurance& assurance) noexcept {
  if (device_->bridge_ == nullptr) {
    ESP_LOGI(device_->tag_, "message origin=%llu session=%lu sequence=%llu bytes=%u",
             static_cast<unsigned long long>(source),
             static_cast<unsigned long>(key.id.session),
             static_cast<unsigned long long>(key.id.sequence),
             static_cast<unsigned>(payload.size));
  }
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_message(key, source, payload, assurance);
#endif
  DeliveryAssurance verified = assurance;
  if (assurance.origin_verified && device_->runtime_ != nullptr) {
    device_->note_gateway_contact(source, device_->runtime_->now_ms());
#if ROUTELOOM_DEVICE_MEMBER
    // The origin's role comes from its verified member credential.
    std::uint32_t generation = 0, role = 0;
    if (device_->security_ == DeviceSecurity::Member && device_->stores_->site().has_site() &&
        device_->owner_->coordinator().authenticated(
            source, device_->stores_->site().site().network, generation, role)) {
      verified.source_role = static_cast<std::uint8_t>(role);
    }
#endif
  }
  if (device_->app_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->app_->on_message(key, source, payload, verified);
  }
}

void Device::Observer::on_group_message(const GroupMessageInfo& info,
                                        const ByteView payload) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_group_message(info, payload);
#endif
  if (device_->app_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->app_->on_group_message(info, payload);
  }
}

void Device::Observer::on_verified_contact(const NodeId source,
                                           const MonotonicMs now_ms) noexcept {
  device_->note_gateway_contact(source, now_ms);
}

#if ROUTELOOM_DEVICE_SLEEP
void Device::Observer::on_pending_result(const PendingDeliveryRecord& record,
                                         const StatusCode result) noexcept {
  ESP_LOGI(device_->tag_, "sleep pending session=%lu sequence=%llu status=%u",
           static_cast<unsigned long>(record.original_id.session),
           static_cast<unsigned long long>(record.original_id.sequence),
           static_cast<unsigned>(result));
  if (device_->device_observer_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->device_observer_->on_sleep_pending_result(record, result);
  }
}
#endif

void Device::Observer::on_delivery(const DeliveryResult& result) noexcept {
  if (device_->bridge_ == nullptr) {
    ESP_LOGI(device_->tag_, "delivery session=%lu sequence=%llu state=%u reason=%s",
             static_cast<unsigned long>(result.id.session),
             static_cast<unsigned long long>(result.id.sequence),
             static_cast<unsigned>(result.state), result.reason);
  }
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_delivery(result);
#endif
  if (device_->app_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->app_->on_delivery(result);
  }
}

void Device::Observer::on_group_delivery(const GroupDeliveryResult& result) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_group_delivery(result);
#endif
  if (device_->app_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->app_->on_group_delivery(result);
  }
}

void Device::Observer::on_applied_result(const MessageKey& key,
                                         const AppliedResultView& result) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_applied_result(key, result);
#endif
  if (device_->app_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->app_->on_applied_result(key, result);
  }
}

void Device::Observer::on_diagnostic(const char* reason, const NodeId peer,
                                     const MessageId* message) noexcept {
  if (device_->bridge_ == nullptr) {
    ESP_LOGW(device_->tag_, "diagnostic reason=%s peer=%llu message=%s", reason,
             static_cast<unsigned long long>(peer), message == nullptr ? "none" : "present");
  }
  // Unknown-epoch group traffic is the backstop pull trigger for a missed
  // rotation Wake (records only; the owner polls the flag).
  if (device_->owner_ != nullptr && reason != nullptr &&
      std::strcmp(reason, "GROUP_KEY_RETIRED") == 0) {
    device_->owner_->note_group_key_retired();
  }
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_diagnostic(reason, peer, message);
#endif
  if (device_->app_ != nullptr) {
    CallbackScope scope(device_->in_callback_);
    device_->app_->on_diagnostic(reason, peer, message);
  }
}

// --- Boot -----------------------------------------------------------------------

Status Device::open_storage(const profile::Role role, const DeviceSecurity security) noexcept {
  // Every boot — even one that fails below — consumes a session, which
  // keeps TX epochs strictly fresh. The session lives in the default NVS
  // partition, so an exhausted security partition can never block it.
  Status status = next_boot_session(boot_session_);
  if (!status) return status;
  // Security state lives in its own partition (issue #37). Never erase
  // automatically: that would turn a storage fault into key/counter
  // rollback.
  const esp_err_t error = nvs_flash_init_partition(espnow::kSecurityNvsPartition);
  if (error != ESP_OK) {
    ESP_LOGE(tag_,
             "security NVS partition '%s' init failed (0x%x); automatic erase is disabled: "
             "flash the partition table and erase NVS explicitly",
             espnow::kSecurityNvsPartition, static_cast<unsigned>(error));
    return Status::error(StatusCode::StorageFailure, "security NVS initialization failed");
  }
  // SDK v1 stores (rlident/rlsite/rlrevo/rlres behind the dual-slot
  // discipline). Impairment is never node-fatal and never erases: an
  // impaired store is reported and its consumers fail closed.
  static ROUTELOOM_OWNER_C5_LP espnow::Sdkv1Stores stores(
      role == profile::Role::Gateway ? sdkv1::kResumeGatewaySlots : sdkv1::kResumeNodeSlots);
  status = stores.open(espnow::kSecurityNvsPartition);
  // The security owner (and a factory console) cannot work without
  // stores — continuing would run a dead node.
  if (!status) return status;
  stores_ = &stores;
  status = stores.initialize();
  if (!status) ESP_LOGE(tag_, "sdkv1 stores init: %s", status.detail);
  stores.log_state(tag_);
#if CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
  static_cast<void>(security);
  return Status::success();
#else
  // Member boot binds the advanced token to the adopted RLS1; DevRam
  // reserves its group boot above the security-partition high-water.
#if ROUTELOOM_DEVICE_DEV_RAM
  if (security == DeviceSecurity::DevRam) {
    return reserve_dev_group_boot_session(boot_session_, boot_session_);
  }
#endif
#if ROUTELOOM_DEVICE_MEMBER
  if (security == DeviceSecurity::Member) return reconcile_boot_session(stores.site(), boot_session_);
#endif
  return Status::error(StatusCode::Unsupported, "security mode not in this image");
#endif
}

Status Device::begin(DeviceConfig& config, const MonotonicMs now_ms) noexcept {
#if ROUTELOOM_DEVICE_DEV_RAM
  struct SecretGuard {
    keys::Secret value;
    ~SecretGuard() noexcept { secure_clear(value); }
  } dev_psk{config.dev_psk};
#endif
  // The caller's temporary must be cleared even if storage, RF or Owner
  // bring-up fails before the DevRam adoption path.
  secure_clear(config.dev_psk);
  tag_ = config.log_tag;
  role_ = config.role;
  security_ = config.security;
  ESP_LOGI(tag_, "security profile: %s",
           security_ == DeviceSecurity::DevRam ? "Development" : "Candidate");
  // A channel plan is rooted in the adopted site's SAK: DevRam has no Site
  // Authority and keeps its fixed (SitePackage/Kconfig) channel.
  if (config.channel_plan != 0 && config.security != DeviceSecurity::Member) {
    return Status::error(StatusCode::InvalidArgument, "CHANNEL_PLAN_MEMBER_ONLY");
  }
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  // An empty HostLink key would make every session proof publicly derivable.
  // Refuse before constructing the bridge or starting the Owner/radio.
  if (config.usb != nullptr &&
      (config.usb_secret.data == nullptr || config.usb_secret.size == 0)) {
    return Status::error(StatusCode::InvalidArgument, "USB_SECRET_REQUIRED");
  }
#endif
  NodeConfig& node = config.radio.node;
  // The persisted monotonic boot session is the message session, the
  // durable boot token, the telemetry incarnation, the route generation
  // and both replay epochs: all must rise every boot (a reused epoch can
  // never re-establish a lost replay window).
  node.message_session = boot_session_;
  node.boot_session = boot_session_;
  node.boot_incarnation = boot_session_;
  node.route_generation = boot_session_;
  node.link_epoch = boot_session_;
  node.end_epoch = boot_session_;
  Status status = Status::success();

  if (stores_ == nullptr) return Status::error(StatusCode::InvalidState, "storage not open");
  // The owner boots after radio-up (entropy + attach + boot below); the
  // node start stays deferred to ApplyMemberConfig or adopt_dev.
  static espnow::EspOwnerEntropy entropy;
  static espnow::EspNowSecurityOwner owner;
  espnow::EspNowSecurityOwner::Config owner_config{};
  owner_config.local_node = node.node;
  owner_config.local_mac = config.mac;
  owner_config.joiner.node = node.node;
  owner_config.joiner.mac = config.mac;
  // begin() refuses a role above the resource profile before RF starts.
  owner_config.role = config.role;
  const std::uint8_t capability =
      config.role_capability != 0 ? config.role_capability : profile::role_mask(config.role);
  owner_config.joiner.capability = capability;
  owner_config.joiner.requested_role =
      config.requested_role != 0 ? config.requested_role
      : config.role == profile::Role::Gateway
          ? static_cast<std::uint8_t>(sdkv1::kMemberRoleGateway)
          : capability;
  owner_config.log_tag = tag_;
  owner_config.flat_group_routing = config.flat_group_routing;
  status = owner.begin(*stores_, entropy, owner_config, config.sleep_image);
  if (!status) return status;
  owner_ = &owner;
  owner.set_restart_hook(&Device::on_restart, this);
  default_role_ = owner_config.joiner.requested_role;
  allowed_roles_ = static_cast<std::uint8_t>(
      (capability | sdkv1::kMemberRoleEndpoint) & sdkv1::kMemberRoleMask);
#if ROUTELOOM_DEVICE_MEMBER
  if (config.security == DeviceSecurity::Member) {
    // The stored JoinPolicy applies before the owner boots its Joiner. An
    // unreadable record keeps the defaults; set_join_policy() replaces it.
    JoinPolicy policy{};
    std::uint32_t revision = 0;
    const Status loaded = stores_->join_policy().load(policy, revision);
    if (!loaded) {
      ESP_LOGW(tag_, "join policy unreadable (%s): defaults", loaded.detail);
    } else if (revision != 0 && !apply_join_policy(policy)) {
      ESP_LOGW(tag_, "stored join policy not applicable: defaults");
    }
  }
#endif
  SecurityProvider& provider = owner.session_provider();

#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (config.usb != nullptr) {
    usb::UsbBridge::Config bridge_config{};
    bridge_config.secret = config.usb_secret;
    bridge_config.node = node.node;
    bridge_config.network = node.network;
#if ROUTELOOM_DEVICE_MEMBER
    if (stores_ != nullptr && config.security == DeviceSecurity::Member) {
      bridge_config.network = usb_boot_network(stores_->site(), node.network);
    }
#endif
    // A host tells a reboot from a reconnect by the boot id, which never
    // regresses.
    bridge_config.boot_id = boot_session_;
    bridge_config.capability = config.usb_capability;
    bridge_config.device_nonce = config.usb_device_nonce;
    static usb::UsbBridge bridge(bridge_config, *config.usb);
    bridge_ = &bridge;
  }
#endif

  Observer& node_observer = observer();
  node_observer.bind(*this);
  static espnow::EspNowRuntime runtime(config.radio, provider, node_observer);
#if CONFIG_IDF_TARGET_ESP32C6
  status = espnow::initialize_board_rf();
  if (!status) return status;
#endif
  status = runtime.initialize();
  if (!status) return status;
  bind_runtime(runtime);
  runtime.bind_wake_task(xTaskGetCurrentTaskHandle());

  // Post-RF randomness first: boot() arms the cookie sealer from it.
  status = entropy.begin();
  if (!status) return status;
  status = owner.attach_runtime(runtime);
  if (!status) return status;
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr) {
    // The device nonce seeds the USB session transcript; drawn post-RF
    // before the pump can serve a HELLO.
    if (config.usb_device_nonce == 0) {
      std::uint64_t nonce = 0;
      status = entropy.fill(MutableByteView{reinterpret_cast<std::uint8_t*>(&nonce), sizeof nonce});
      if (!status) return status;
      bridge_->set_device_nonce(nonce);
    }
    status = owner.attach_usb(*bridge_);
    if (!status) return status;
  }
#endif
  bool adopted = false;
#if ROUTELOOM_DEVICE_DEV_RAM
  if (config.security == DeviceSecurity::DevRam) {
    // Dev route: adoption without joining, from the verified identity and
    // the committed PSK.
    espnow::EspNowSecurityOwner::DevConfig dev{};
    dev.psk = dev_psk.value;
    dev.network = node.network;
    dev.node = node.node;
    dev.channel = config.radio.channel;
    dev.boot = boot_session_;
    // A DevRam gateway keeps the endpoint|relay allow-role; its gateway
    // role is the USB lane.
    dev.role = profile::role_mask(config.role == profile::Role::Gateway ? profile::Role::Relay
                                                                        : config.role);
    // The scoped route profile rides the dev config (no BoardConfig carrier
    // yet): a missing list would silently fall back to flat on apply.
    if (node.route_gateways[0] != kInvalidNodeId) {
      dev.route_gateways[0] = node.route_gateways[0];
      dev.route_gateways[1] = node.route_gateways[1];
      dev.route_gateway_count = 2;
    }
    status = owner.adopt_dev(dev, now_ms);
    secure_clear(dev.psk);
    if (!status) return status;
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
    if (config.remote_config) {
      status = begin_remote_config(config, dev_psk.value, entropy, now_ms);
      if (!status) return status;
    }
#endif
    adopted = true;
  }
#endif
#if ROUTELOOM_DEVICE_MEMBER
  if (config.security == DeviceSecurity::Member) {
#if ROUTELOOM_DEVICE_MIGRATION
    // The stored plan channel must reach the coordinator before Boot
    // adopts the site.
    if (config.channel_plan != 0) {
      status = begin_channel_plan(config);
      if (!status) return status;
    }
#endif
    // usb_direct selects the gateway's USB local-join transport.
    status = owner.boot(boot_session_, /*rlboot_prepared=*/true, bridge_ != nullptr, now_ms);
    if (!status) return status;
    // Authority lane: R2, JoinConfirm and GK updates arrive on this mesh
    // sink (subtype-9 carriers and kind-7 objects). A remote-config target
    // takes the sink and routes the authority frames to the same demux.
    runtime.node().set_config_sink(owner.authority_mesh_sink());
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
    if (config.remote_config) {
      status = begin_remote_config(config, keys::Secret{}, entropy, now_ms);
      if (!status) return status;
    }
#endif
    adopted = true;
  }
#endif
  if (!adopted) return Status::error(StatusCode::Unsupported, "security mode not in this image");
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr) {
    bridge_->set_mesh(&runtime.node());
    // Gateway endpoint (scope-gateway-config P3) and config endpoint (P5):
    // the bridge advertises only what is attached here.
#if ROUTELOOM_DEVICE_GATEWAY_ENDPOINT
    if ((config.usb_capability & usb::kCapGatewayEndpointV1) != 0) {
      GatewayDelivery* delivery = gateway();
      if (delivery == nullptr) {
        return Status::error(StatusCode::Busy, "gateway sink unavailable");
      }
      status = bridge_->attach_gateway(*delivery);
      if (!status) return status;
    }
#endif
#if ROUTELOOM_DEVICE_CONFIG_ENDPOINT
    if ((config.usb_capability & usb::kCapConfigEndpointV1) != 0) {
      static MeshConfigPort config_port(runtime.node());
      static ConfigGateway config_gateway(config_port, *bridge_);
      status = bridge_->attach_config(config_gateway);
      if (!status) return status;
      if (config.security == DeviceSecurity::Member) {
        config_gateway.attach_authority(owner_->authority_demux());
      }
    }
#endif
  }
#endif
#if ROUTELOOM_APP_OBJECT_TRANSFER
  static AppObject object(runtime.node(), provider, node_observer);
  object_ = &object;
  status = object.attach();
  if (!status) return status;
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr) {
    status = bridge_->attach_object(object);
    if (!status) return status;
  }
#endif
#endif
  return Status::success();
}

// --- Owner pass -----------------------------------------------------------------

void Device::usb_receive(const ByteView bytes, const MonotonicMs now_ms) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr && bytes.size > 0) bridge_->on_bytes(bytes, now_ms);
#else
  static_cast<void>(bytes);
  static_cast<void>(now_ms);
#endif
}

void Device::step(const MonotonicMs now_ms) noexcept {
  if (runtime_ == nullptr) return;
  // Only jobs waiting at the start of this Owner pass may run. Callbacks
  // reached below can post, but their jobs belong to the next pass.
  portENTER_CRITICAL(&posted_lock_);
  const std::uint8_t posted_budget = posted_count_;
  portEXIT_CRITICAL(&posted_lock_);
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr) bridge_->poll(now_ms);
#endif
  runtime_->poll_once();
  if (owner_ != nullptr) owner_->poll(now_ms);
#if ROUTELOOM_DEVICE_SLEEP
  if (power_ != nullptr) {
    CallbackScope scope(in_callback_);
    if (runtime_->radio_generation() != sleep_radio_generation_) {
      sleep_radio_generation_ = runtime_->radio_generation();
      (void)power_->notify_radio_reset(now_ms);
    }
    if (posted_budget != 0) (void)power_->notify_app_event(now_ms);
    power_->poll(now_ms);
  }
#endif
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
  if (remote_config_ != nullptr) poll_remote_config(now_ms);
#endif
#if ROUTELOOM_DEVICE_MIGRATION
  if (channel_plan_ != nullptr) poll_channel_plan(now_ms);
#endif
  update_membership(now_ms);
  update_connectivity(now_ms);
  run_posted(posted_budget);
  update_observation_remote();
  if (poll_hook_ != nullptr) poll_hook_(*this, now_ms, poll_ctx_);
}

MonotonicMs Device::next_deadline(const MonotonicMs now_ms) const noexcept {
  const MonotonicMs ceiling = role_ == profile::Role::Endpoint ? 1000
                              : role_ == profile::Role::Relay  ? 100
                                                               : 20;
  MonotonicMs due = now_ms > UINT64_MAX - ceiling ? UINT64_MAX : now_ms + ceiling;
  const auto sooner = [&](const MonotonicMs at) {
    if (at < due) due = at;
  };
  if (runtime_ != nullptr) sooner(runtime_->next_deadline(now_ms));
  if (owner_ != nullptr) sooner(owner_->next_deadline(now_ms));
#if ROUTELOOM_DEVICE_SLEEP
  if (power_ != nullptr) sooner(power_->next_deadline(now_ms));
#endif
  // Application hooks, USB and optional configuration ports have no
  // deadline callback yet, so preserve their documented cadence.
  if (bridge_ != nullptr || poll_hook_ != nullptr || operation_ != Operation::None) {
    sooner(now_ms > UINT64_MAX - kOwnerPollPeriodMs ? UINT64_MAX : now_ms + kOwnerPollPeriodMs);
  }
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
  if (remote_config_ != nullptr) sooner(now_ms > UINT64_MAX - 2 ? UINT64_MAX : now_ms + 2);
#endif
#if ROUTELOOM_DEVICE_MIGRATION
  if (channel_plan_ != nullptr) sooner(now_ms > UINT64_MAX - 2 ? UINT64_MAX : now_ms + 2);
#endif
  return due < now_ms ? now_ms : due;
}

void Device::bind_runtime(espnow::EspNowRuntime& runtime) noexcept {
  // post() may run before Owner startup finishes. Publish the runtime
  // under the same lock that protects the producer's notification target.
  portENTER_CRITICAL(&posted_lock_);
  runtime_ = &runtime;
  portEXIT_CRITICAL(&posted_lock_);
}

Status Device::post(const Job job, void* ctx) noexcept {
  if (job == nullptr) return Status::error(StatusCode::InvalidArgument, "post job missing");
  portENTER_CRITICAL(&posted_lock_);
#if ROUTELOOM_DEVICE_SLEEP
  if (sleep_post_blocked_) {
    portEXIT_CRITICAL(&posted_lock_);
    return Status::error(StatusCode::Busy, "sleep handoff in progress");
  }
#endif
  const bool full = posted_count_ == kPostCapacity;
  if (!full) {
    posted_[static_cast<std::size_t>((posted_head_ + posted_count_) % kPostCapacity)] =
        Posted{job, ctx};
    ++posted_count_;
  }
  espnow::EspNowRuntime* const target = runtime_;
  portEXIT_CRITICAL(&posted_lock_);
  if (!full && target != nullptr) target->notify_owner();
  return full ? Status::error(StatusCode::Busy, "post queue full") : Status::success();
}

void Device::run_posted(std::uint8_t budget) noexcept {
  while (budget-- > 0) {
    Posted next{};
    portENTER_CRITICAL(&posted_lock_);
    if (posted_count_ > 0) {
      next = posted_[posted_head_];
      posted_head_ = static_cast<std::uint8_t>((posted_head_ + 1) % kPostCapacity);
      --posted_count_;
    }
    portEXIT_CRITICAL(&posted_lock_);
    if (next.job == nullptr) return;
    next.job(*this, next.ctx);
  }
}

void Device::update_observation_remote() noexcept {
#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE
  // Only adopted modes answer remote observation queries; adoption and
  // revocation open and close the responder.
  if (owner_ == nullptr || observation_ == nullptr) return;
  const sdkv1::CoordinatorMode mode = owner_->coordinator().mode();
  const bool allow =
      mode == sdkv1::CoordinatorMode::Member || mode == sdkv1::CoordinatorMode::Dev;
  if (allow != observation_remote_ && runtime_->node().set_observation_remote(allow)) {
    observation_remote_ = allow;
  }
#endif
}

#if ROUTELOOM_DEVICE_SLEEP
Status Device::bind_sleep(PowerCoordinator& power, const ResetCause cause,
                          const ElapsedInterval elapsed, const MonotonicMs now_ms) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr || !runtime_->node().started() || power_ != nullptr ||
      !power.owns_node(runtime_->node())) {
    return Status::error(StatusCode::InvalidState, "sleep coordinator binding");
  }
  power_ = &power;
  sleep_radio_generation_ = runtime_->radio_generation();
  CallbackScope scope(in_callback_);
  return power.begin(cause, elapsed, now_ms);
}

Status Device::prepare_sleep(const SleepRequest& request) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (power_ == nullptr) return Status::error(StatusCode::Unsupported, "sleep not bound");
  CallbackScope scope(in_callback_);
  return power_->sleep_prepare(request, runtime_->now_ms());
}

Status Device::enter_sleep(const SleepTicket& ticket) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (power_ == nullptr) return Status::error(StatusCode::Unsupported, "sleep not bound");
  CallbackScope scope(in_callback_);
  portENTER_CRITICAL(&posted_lock_);
  const bool posted = posted_count_ != 0;
  // Freeze acceptance before the final gate; no producer can leave a
  // newly accepted job behind while the platform enters sleep.
  if (!posted) sleep_post_blocked_ = true;
  portEXIT_CRITICAL(&posted_lock_);
  const MonotonicMs now = runtime_->now_ms();
  if (posted || !runtime_->sleep_quiescent()) (void)power_->notify_app_event(now);
  if (runtime_->radio_generation() != sleep_radio_generation_) {
    (void)power_->notify_radio_reset(now);
  }
  const Status status = power_->sleep_enter(ticket, now);
  if (power_->state() != PowerState::Sleeping) {
    portENTER_CRITICAL(&posted_lock_);
    sleep_post_blocked_ = false;
    portEXIT_CRITICAL(&posted_lock_);
  }
  return status;
}

Status Device::abort_sleep() noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (power_ == nullptr) return Status::error(StatusCode::Unsupported, "sleep not bound");
  CallbackScope scope(in_callback_);
  return power_->sleep_abort(nullptr, runtime_->now_ms());
}

Status Device::wake(const ResetCause cause, const ElapsedInterval elapsed,
                    const MonotonicMs now_ms) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (power_ == nullptr) return Status::error(StatusCode::Unsupported, "sleep not bound");
  CallbackScope scope(in_callback_);
  portENTER_CRITICAL(&posted_lock_);
  sleep_post_blocked_ = false;
  portEXIT_CRITICAL(&posted_lock_);
  const Status status = power_->wake(cause, elapsed, now_ms);
  sleep_radio_generation_ = runtime_->radio_generation();
  return status;
}

SleepTicket Device::sleep_ticket() const noexcept {
  return power_ == nullptr ? SleepTicket{} : power_->ticket();
}

ResumeOutcome Device::wake_info() const noexcept {
  return power_ == nullptr ? ResumeOutcome::None : power_->resume_outcome();
}

#else
Status Device::bind_sleep(PowerCoordinator&, ResetCause, ElapsedInterval, MonotonicMs) noexcept {
  return Status::error(StatusCode::Unsupported, "sleep not compiled");
}
Status Device::prepare_sleep(const SleepRequest&) noexcept {
  return Status::error(StatusCode::Unsupported, "sleep not compiled");
}
Status Device::enter_sleep(const SleepTicket&) noexcept {
  return Status::error(StatusCode::Unsupported, "sleep not compiled");
}
Status Device::abort_sleep() noexcept {
  return Status::error(StatusCode::Unsupported, "sleep not compiled");
}
Status Device::wake(ResetCause, ElapsedInterval, MonotonicMs) noexcept {
  return Status::error(StatusCode::Unsupported, "sleep not compiled");
}
SleepTicket Device::sleep_ticket() const noexcept { return {}; }
ResumeOutcome Device::wake_info() const noexcept { return ResumeOutcome::None; }
#endif

// --- Facade ---------------------------------------------------------------------

bool Device::callback_active() const noexcept {
  return in_callback_ || (runtime_ != nullptr && runtime_->node().in_external_callback());
}

Status Device::send(const NodeId destination, const ByteView payload,
                    const SendOptions& options, MessageId& id) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->send_application(destination, payload, options, id);
}

Status Device::send_object(NodeId destination, ByteView data, const ObjectOptions& options,
                           ObjectId& id) noexcept {
  id = 0;
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
#if ROUTELOOM_APP_OBJECT_TRANSFER
  if (object_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return object_->send(destination, data, options, runtime_->now_ms(), id);
#else
  (void)destination; (void)data; (void)options;
  return Status::error(StatusCode::Unsupported, "object transfer disabled");
#endif
}
Status Device::cancel_object(ObjectId id) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
#if ROUTELOOM_APP_OBJECT_TRANSFER
  if (object_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return object_->cancel(id);
#else
  (void)id;
  return Status::error(StatusCode::Unsupported, "object transfer disabled");
#endif
}
Status Device::register_object_buffer(MutableByteView storage) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
#if ROUTELOOM_APP_OBJECT_TRANSFER
  if (object_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return object_->register_buffer(storage);
#else
  (void)storage;
  return Status::error(StatusCode::Unsupported, "object transfer disabled");
#endif
}
#if ROUTELOOM_APP_OBJECT_TRANSFER
bool Device::Observer::object_receive_ready() const noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_ != nullptr && device_->bridge_ != nullptr) return device_->bridge_->object_receive_ready();
#endif
  return true;
}
std::size_t Device::Observer::object_receive_slots() const noexcept {
  return ROUTELOOM_APP_OBJECT_RX_SLOTS;
}
void Device::Observer::on_object(const ObjectRxInfo& info, ByteView data) noexcept {
  if (device_ == nullptr) return;
  device_->in_callback_ = true;
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_object(info, data);
#endif
  if (device_->object_observer_ != nullptr) device_->object_observer_->on_object(info, data);
  device_->in_callback_ = false;
}
void Device::Observer::on_object_result(const ObjectResult& result) noexcept {
  if (device_ == nullptr) return;
  device_->in_callback_ = true;
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_->bridge_ != nullptr) device_->bridge_->on_object_result(result);
#endif
  if (device_->object_observer_ != nullptr) device_->object_observer_->on_object_result(result);
  device_->in_callback_ = false;
}
#endif

Status Device::send_group(const GroupId group, const ByteView payload,
                          const GroupSendOptions& options, MessageId& id) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->node().send_group(group, payload, options, runtime_->now_ms(), id);
}

Status Device::cancel(const MessageId& id) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->node().cancel(id);
}

DeliveryResult Device::delivery(const MessageId& id) const noexcept {
  if (runtime_ == nullptr) return DeliveryResult{};
  return runtime_->delivery(id);
}

DeviceCapabilities Device::capabilities() const noexcept {
  DeviceCapabilities caps{};
  caps.role = role_;
  caps.member = security_ == DeviceSecurity::Member;
  caps.security_profile =
      caps.member ? SecurityProfile::Candidate : SecurityProfile::Development;
  caps.usb_gateway = bridge_ != nullptr;
#if ROUTELOOM_APP_OBJECT_TRANSFER
  caps.object_transfer = object_ != nullptr;
  caps.max_object_bytes = object_wire::kMaxBytes;
  caps.object_rx_slots = ROUTELOOM_APP_OBJECT_RX_SLOTS;
#endif
  caps.max_payload = static_cast<std::uint16_t>(kMaxApplicationPayload);
  caps.max_group_payload = static_cast<std::uint16_t>(kGroupPayloadMax);
  if (runtime_ != nullptr) {
    caps.scoped_routing = runtime_->node().gateway_scoped();
    caps.group_send = runtime_->node().group_origin_servable();
  }
  return caps;
}

NodeId Device::node_id() const noexcept {
  return runtime_ == nullptr ? kInvalidNodeId : runtime_->node().node_id();
}

const sdkv1::SecurityCoordinator* Device::security() const noexcept {
  return owner_ == nullptr ? nullptr : &owner_->coordinator();
}

MeshNode* Device::mesh() noexcept {
  return runtime_ == nullptr ? nullptr : &runtime_->node();
}

GatewayDelivery* Device::gateway() noexcept {
  if (runtime_ == nullptr) return nullptr;
  // The node object survives membership adoption (it is rebuilt in place
  // and keeps its Service sink). A callback may call here while the node
  // rejects sink changes; retry attachment on the next Owner call.
  static ROUTELOOM_OWNER_C5_LP GatewayDelivery delivery(runtime_->node());
  if (runtime_->node().gateway_sink() != &delivery) {
    delivery.attach();
    if (runtime_->node().gateway_sink() != &delivery) return nullptr;
  }
  gateway_ = &delivery;
  return gateway_;
}

// --- APPLIED --------------------------------------------------------------------

Status Device::send_applied(const NodeId destination, const ByteView payload,
                            const ExecutionLease& lease, const SendOptions& options,
                            MessageId& id) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->node().send_applied(destination, payload, lease, options, runtime_->now_ms(),
                                       id);
}

Status Device::set_applied_sink(AppliedEndpointSink* sink) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->node().set_applied_sink(sink);
}

Status Device::complete_applied(const std::uint64_t ticket, const AppliedReply& reply) noexcept {
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->node().complete_applied(ticket, reply, runtime_->now_ms());
}

// --- Membership ---------------------------------------------------------------------

MembershipStage Device::current_stage() const noexcept {
  if (owner_ == nullptr) return MembershipStage::Unprovisioned;
  const sdkv1::CoordinatorMode mode = owner_->coordinator().mode();
  if (mode == sdkv1::CoordinatorMode::Dev) return MembershipStage::Member;
  const sdkv1::LifecyclePhase phase = owner_->lifecycle().snapshot().phase;
  const sdkv1::LifecycleStore& journal = stores_->lifecycle();
  if (phase == sdkv1::LifecyclePhase::StorageBlocked) return MembershipStage::Recovery;
  if (journal.has_record() && journal.record().mode == sdkv1::LifecycleMode::LocalLeave) {
    return MembershipStage::Leaving;
  }
  if (phase == sdkv1::LifecyclePhase::UnassignedReady && journal.has_record() &&
      journal.record().mode == sdkv1::LifecycleMode::LeftReady) {
    return MembershipStage::Joining;
  }
  if (phase == sdkv1::LifecyclePhase::Removing || phase == sdkv1::LifecyclePhase::Holdoff ||
      mode == sdkv1::CoordinatorMode::Removed) {
    return MembershipStage::Removed;
  }
  if (mode == sdkv1::CoordinatorMode::Recovery) {
    return MembershipStage::Recovery;
  }
  if (mode == sdkv1::CoordinatorMode::Member) return MembershipStage::Member;
  if (mode == sdkv1::CoordinatorMode::ZeroTouch && stores_->identity().has_identity()) {
    return pending_authority_ ? MembershipStage::PendingAuthority : MembershipStage::Joining;
  }
  return MembershipStage::Unprovisioned;
}

MembershipSnapshot Device::membership() const noexcept {
  MembershipSnapshot out{};
  out.stage = current_stage();
  const bool observed = out.stage == stage_;
  out.since_ms = observed ? stage_since_ms_ : (runtime_ != nullptr ? runtime_->now_ms() : 0);
  out.reason = observed ? stage_reason_ : membership_cause(out.stage);
  out.boot = boot_session_;
  out.operation = operation_ != Operation::None ? operation_id_ : 0;
  if (runtime_ != nullptr) out.node = runtime_->node().node_id();
  if (out.stage == MembershipStage::Member && security_ == DeviceSecurity::DevRam &&
      runtime_ != nullptr) {
    out.network = runtime_->node().config().network;
  } else if (stores_ != nullptr && stores_->site().has_site()) {
    const sdkv1::SiteRecord& site = stores_->site().site();
    out.site_id = site.site_id;
    out.network = site.network;
    out.generation = site.assignment_generation;
    out.role = site.role;
  }
  return out;
}

void Device::update_membership(const MonotonicMs now_ms) noexcept {
  if (owner_ == nullptr) return;
  const sdkv1::JoinSnapshot joiner = owner_->coordinator().joiner_snapshot();
  if (joiner.counters.attempts != seen_attempts_) {
    // A new attempt (or a new Joiner) starts from no verdict.
    seen_attempts_ = joiner.counters.attempts;
    pending_base_ = joiner.counters.pendings;
  }
  pending_authority_ = joiner.counters.pendings > pending_base_;
  const MembershipStage stage = current_stage();
  if (!stage_known_) {
    // The stage this boot starts in is not a change: no event.
    stage_known_ = true;
    stage_ = stage;
    stage_since_ms_ = now_ms;
    if (stage == MembershipStage::Member) member_since_ms_ = now_ms;
  } else if (stage != stage_) {
    const std::uint16_t cause = membership_cause(stage);
    stage_ = stage;
    stage_since_ms_ = now_ms;
    stage_reason_ = cause;
    if (stage == MembershipStage::Member) member_since_ms_ = now_ms;
    if (device_observer_ != nullptr) {
      const MembershipSnapshot snapshot = membership();
      CallbackScope scope(in_callback_);
      device_observer_->on_membership(snapshot, cause);
    }
  }
  if (operation_ == Operation::Join) {
    if (stage != MembershipStage::Member) operation_left_member_ = true;
    const StatusCode result = owner_->coordinator().join_search_result();
    if (result == StatusCode::AuthorizationFailed) {
      finish_operation(ROUTELOOM_REASON_JOIN_DENIED);
    } else if (result == StatusCode::ApprovalRequired) {
      finish_operation(ROUTELOOM_REASON_JOIN_PENDING);
    } else if (result == StatusCode::Expired) {
      finish_operation(ROUTELOOM_REASON_JOIN_TIMEOUT);
    } else if (stage == MembershipStage::Member && operation_left_member_) {
      finish_operation(ROUTELOOM_REASON_JOINED);
    } else if (stage == MembershipStage::Removed || joiner.counters.denies > operation_denies_) {
      finish_operation(ROUTELOOM_REASON_JOIN_DENIED);
    } else if (stage == MembershipStage::Recovery) {
      finish_operation(ROUTELOOM_REASON_RECOVERY_REQUIRED);
    } else if (joiner.counters.pendings > operation_pendings_) {
      finish_operation(ROUTELOOM_REASON_JOIN_PENDING);
    } else if (now_ms >= operation_deadline_ms_ ||
               (smart_join_ && joiner.state == sdkv1::JoinState::Stopped)) {
      finish_operation(ROUTELOOM_REASON_JOIN_TIMEOUT);
    }
  } else if (operation_ == Operation::Leave && stage == MembershipStage::Recovery) {
    finish_operation(ROUTELOOM_REASON_RECOVERY_REQUIRED);
  }
}

void Device::finish_operation(const std::uint16_t result) noexcept {
  const OperationId id = operation_id_;
  operation_ = Operation::None;
  if (device_observer_ != nullptr) {
    CallbackScope scope(in_callback_);
    device_observer_->on_operation(id, result);
  }
}

void Device::on_restart(void* self, const bool leave) noexcept {
  // The Owner restarts the device right after this returns: a finished
  // local leave is reported here, since the next boot keeps no trace of it.
  auto& device = *static_cast<Device*>(self);
  if (!leave) return;
  device.stage_ = MembershipStage::Joining;
  device.stage_since_ms_ = device.runtime_ != nullptr ? device.runtime_->now_ms() : 0;
  device.stage_reason_ = ROUTELOOM_REASON_LEFT;
  if (device.device_observer_ != nullptr) {
    const MembershipSnapshot snapshot = device.membership();
    CallbackScope scope(device.in_callback_);
    device.device_observer_->on_membership(snapshot, ROUTELOOM_REASON_LEFT);
  }
  if (device.operation_ == Operation::Leave) device.finish_operation(ROUTELOOM_REASON_LEFT);
}

Status Device::join_mark(sdkv1::JoinMark& out) noexcept {
  out = {};
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (stores_ == nullptr || !stores_->identity().has_identity()) {
    return Status::error(StatusCode::InvalidState, "identity unavailable");
  }
  return sdkv1::identity_join_mark(stores_->identity().identity(), out);
}

Status Device::request_join(OperationId& operation) noexcept {
  operation = 0;
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (owner_ == nullptr || runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "device not started");
  }
  if (security_ != DeviceSecurity::Member) {
    return Status::error(StatusCode::Unsupported, "DevRam has no join");
  }
  if (operation_ != Operation::None) return Status::error(StatusCode::Busy, "OPERATION_IN_PROGRESS");
  const MonotonicMs now_ms = runtime_->now_ms();
  const Status status = owner_->request_join(now_ms);
  if (!status) return status;
  // The baseline is the Joiner that runs now (a member's re-verification
  // starts a new one).
  const sdkv1::JoinSnapshot joiner = owner_->coordinator().joiner_snapshot();
  operation_denies_ = joiner.counters.denies;
  operation_pendings_ = joiner.counters.pendings;
  operation_left_member_ = owner_->coordinator().mode() != sdkv1::CoordinatorMode::Member;
  operation_deadline_ms_ = now_ms + search_ms_;
  if (++operation_id_ == 0) ++operation_id_;
  operation_ = Operation::Join;
  operation = operation_id_;
  return Status::success();
}

Status Device::leave(OperationId& operation) noexcept {
  operation = 0;
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (owner_ == nullptr || runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "device not started");
  }
  if (security_ != DeviceSecurity::Member) {
    return Status::error(StatusCode::Unsupported, "DevRam has no membership");
  }
  if (operation_ != Operation::None) return Status::error(StatusCode::Busy, "OPERATION_IN_PROGRESS");
  // Deliveries cancelled by the leave report to the app inside this call.
  const Status status = owner_->local_leave(runtime_->now_ms());
  if (!status) return status;
  if (++operation_id_ == 0) ++operation_id_;
  operation_ = Operation::Leave;
  operation = operation_id_;
  return Status::success();
}

// --- JoinPolicy -----------------------------------------------------------------------

Status Device::apply_join_policy(const JoinPolicy& policy) noexcept {
  sdkv1::JoinerConfig timing{};
  timing.requested_role = policy.role != 0 ? policy.role : default_role_;
  timing.avoid_not_here_ms = policy.avoid_not_here_s * 1000U;
  timing.avoid_blocked_ms = policy.avoid_blocked_s * 1000U;
  timing.retry_max_ms = policy.retry_max_s * 1000U;
  timing.start_jitter_ms = policy.start_jitter_ms;
  timing.smart_join = policy.smart_join;
  timing.boot_join = policy.boot_join;
  timing.same_site_only = policy.same_site_only;
  timing.listen_ms = policy.listen_ms;
  timing.search_ms = policy.search_ms;
  const Status status = owner_->apply_join_policy(timing, policy.removal_holdoff_s * 1000U);
  if (status) {
    isolation_notice_ms_ = policy.isolation_notice_s * 1000U;
    smart_join_ = policy.smart_join;
    search_ms_ = policy.search_ms;
  }
  return status;
}

Status Device::join_policy(JoinPolicy& policy, std::uint32_t& revision) noexcept {
  policy = JoinPolicy{};
  revision = 0;
  if (stores_ == nullptr) return Status::error(StatusCode::InvalidState, "storage not open");
  return stores_->join_policy().load(policy, revision);
}

Status Device::set_join_policy(const JoinPolicy& policy, const std::uint32_t expected_revision,
                               std::uint32_t& revision) noexcept {
  revision = 0;
  if (callback_active()) return Status::error(StatusCode::Busy, "reentrant call");
  if (owner_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  if (security_ != DeviceSecurity::Member) {
    return Status::error(StatusCode::Unsupported, "DevRam has no join");
  }
  Status status = sdkv1::join_policy_check(policy, allowed_roles_);
  if (!status) return status;
  JoinPolicy stored{};
  std::uint32_t current = 0;
  status = stores_->join_policy().load(stored, current);
  // A corrupt record reads as revision 0: expected 0 replaces it.
  if (!status && status.code != StatusCode::IntegrityError) return status;
  if (expected_revision != current) return Status::error(StatusCode::Conflict, "JOIN_POLICY_REVISION");
  if (current == UINT32_MAX) return Status::error(StatusCode::NoCapacity, "JOIN_POLICY_REVISION");
  status = stores_->join_policy().commit(policy, current + 1U);
  if (!status) return status;
  revision = current + 1U;
  return apply_join_policy(policy);
}

// --- Connectivity -----------------------------------------------------------------

void Device::note_gateway_contact(const NodeId source, const MonotonicMs now_ms) noexcept {
  if (stores_ == nullptr || !stores_->site().has_site()) {
    if (runtime_ == nullptr) return;
    for (const NodeId gateway : runtime_->node().config().route_gateways) {
      if (gateway == source && gateway != kInvalidNodeId) {
        contact_ms_ = now_ms;
        contact_valid_ = true;
      }
    }
    return;
  }
  const sdkv1::SiteRecord& site = stores_->site().site();
  for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
    if (site.gateways[i] == source) {
      contact_ms_ = now_ms;
      contact_valid_ = true;
    }
  }
}

ConnectivitySnapshot Device::connectivity() const noexcept {
  ConnectivitySnapshot out{};
  out.state = connectivity_;
  out.since_ms = connectivity_since_ms_;
  out.boot = boot_session_;
  out.contact_valid = contact_valid_;
  out.last_contact_ms = contact_ms_;
  out.reason = connectivity_reason_;
  return out;
}

void Device::update_connectivity(const MonotonicMs now_ms) noexcept {
  if (runtime_ == nullptr) return;
  Connectivity state = Connectivity::Unknown;
  std::uint16_t reason = ROUTELOOM_REASON_NOT_MEMBER;
  // A member re-verifying its retained site is still a member here.
  const bool member = stage_ == MembershipStage::Member ||
                      ((stage_ == MembershipStage::Joining ||
                        stage_ == MembershipStage::PendingAuthority) &&
                       stores_->site().has_site());
#if ROUTELOOM_DEVICE_SLEEP
  if (power_ != nullptr && power_->state() == PowerState::Sleeping) {
    state = Connectivity::Sleeping;
    reason = 0;
  } else
#endif
      if (!member) {
    contact_valid_ = false;
  } else if (security_ == DeviceSecurity::DevRam
                 ? role_ == profile::Role::Gateway
                 : stores_->site().has_site() &&
                       (stores_->site().site().role & sdkv1::kMemberRoleGateway) != 0) {
    state = Connectivity::Reachable;
    reason = ROUTELOOM_REASON_SELF_GATEWAY;
  } else {
    // This site's gateways: the committed site record, or the DevRam route
    // profile's gateways.
    std::array<NodeId, sdkv1::kSiteGatewayMax> gateways{};
    std::size_t count = 0;
    const MeshNode& node = runtime_->node();
    if (stores_->site().has_site() && security_ == DeviceSecurity::Member) {
      const sdkv1::SiteRecord& site = stores_->site().site();
      for (std::uint8_t i = 0; i < site.gateway_count && count < gateways.size(); ++i) {
        gateways[count++] = site.gateways[i];
      }
    } else {
      for (const NodeId gateway : node.config().route_gateways) {
        if (gateway != kInvalidNodeId && count < gateways.size()) gateways[count++] = gateway;
      }
    }
    bool routed = false;
    for (std::size_t i = 0; i < count; ++i) {
      if (!node.routes().best(gateways[i]).valid) continue;
      routed = true;
      // Only authenticated frames heard from the gateway itself count.
      // Relays can renew a route lease after the gateway has stopped.
      NodeStatus status{};
      if (node.node_status(gateways[i], now_ms, status) &&
          (status.flags & kNodeStatusHeardValid) != 0 &&
          (status.flags & kNodeStatusTelemetryStale) == 0 &&
          status.heard_age_ms <= now_ms) {
        const MonotonicMs heard = now_ms - status.heard_age_ms;
        if (!contact_valid_ || heard > contact_ms_) {
          contact_ms_ = heard;
          contact_valid_ = true;
        }
      }
    }
    if (count == 0) {
      reason = ROUTELOOM_REASON_NO_EVIDENCE;  // no gateway named: scope unknown
    } else if (!contact_valid_) {
      reason = ROUTELOOM_REASON_NO_EVIDENCE;
      if (now_ms - member_since_ms_ >= kConnectivityIsolatedMs) state = Connectivity::Isolated;
    } else {
      const MonotonicMs age = now_ms >= contact_ms_ ? now_ms - contact_ms_ : 0;
      reason = !routed ? ROUTELOOM_REASON_NO_GATEWAY_ROUTE
               : age < kConnectivityFreshMs ? ROUTELOOM_REASON_GATEWAY_CONTACT
                                           : ROUTELOOM_REASON_GATEWAY_STALE;
      state = age >= kConnectivityIsolatedMs ? Connectivity::Isolated
              : routed && age < kConnectivityFreshMs ? Connectivity::Reachable
                                                    : Connectivity::Degraded;
    }
  }
  if (state != connectivity_) {
    connectivity_ = state;
    connectivity_since_ms_ = now_ms;
    connectivity_reason_ = reason;
    isolation_noticed_ = false;
    if (device_observer_ != nullptr) {
      const ConnectivitySnapshot snapshot = connectivity();
      CallbackScope scope(in_callback_);
      device_observer_->on_connectivity(snapshot);
    }
  } else if (state == Connectivity::Isolated && isolation_notice_ms_ != 0 && !isolation_noticed_ &&
             now_ms - connectivity_since_ms_ >= isolation_notice_ms_) {
    // An isolation trigger only verifies the retained site; automatic
    // switching while retaining membership requires A2 (#196b).
    if (smart_join_ && operation_ == Operation::None) {
      OperationId operation = 0;
      (void)request_join(operation);
    }
    isolation_noticed_ = true;
    if (device_observer_ != nullptr) {
      ConnectivitySnapshot snapshot = connectivity();
      snapshot.reason = ROUTELOOM_REASON_ISOLATION_NOTICE;
      CallbackScope scope(in_callback_);
      device_observer_->on_connectivity(snapshot);
    }
  }
}

}  // namespace routeloom
