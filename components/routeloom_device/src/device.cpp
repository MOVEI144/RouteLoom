// Device core: storage, security owner, runtime and USB bring-up plus the
// Owner pass. Shared verbatim by the ESP-IDF images (device_esp.cpp) and
// the host mesh harness peer, so the harness boots the production path.

#include "routeloom/device.hpp"

#include <cstring>

#include "esp_attr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/secure_clear.hpp"
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#endif

// Long-lived CPU-only state resides in LP SRAM on the C5 Owner profiles and
// the gateway store set in the C3 RTC bank; radio buffers stay in HP SRAM.
#if (CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC || CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM) && \
    CONFIG_IDF_TARGET_ESP32C5
#define ROUTELOOM_OWNER_C5_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_OWNER_C5_LP
#endif

namespace routeloom {

// A firmware image compiles one security mode (Kconfig) and leaves the
// other mode's Owner paths out; the host harness, which has no Kconfig,
// compiles both and selects at run time.
#define ROUTELOOM_DEVICE_DEV_RAM !CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
#define ROUTELOOM_DEVICE_MEMBER !CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM

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
  if (device_.bridge_ == nullptr) {
    ESP_LOGI(device_.tag_, "message origin=%llu session=%lu sequence=%llu bytes=%u",
             static_cast<unsigned long long>(source),
             static_cast<unsigned long>(key.id.session),
             static_cast<unsigned long long>(key.id.sequence),
             static_cast<unsigned>(payload.size));
  }
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_.bridge_ != nullptr) device_.bridge_->on_message(key, source, payload, assurance);
#endif
  if (device_.app_ != nullptr) device_.app_->on_message(key, source, payload, assurance);
}

void Device::Observer::on_group_message(const GroupMessageInfo& info,
                                        const ByteView payload) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_.bridge_ != nullptr) device_.bridge_->on_group_message(info, payload);
#endif
  if (device_.app_ != nullptr) device_.app_->on_group_message(info, payload);
}

void Device::Observer::on_delivery(const DeliveryResult& result) noexcept {
  if (device_.bridge_ == nullptr) {
    ESP_LOGI(device_.tag_, "delivery session=%lu sequence=%llu state=%u reason=%s",
             static_cast<unsigned long>(result.id.session),
             static_cast<unsigned long long>(result.id.sequence),
             static_cast<unsigned>(result.state), result.reason);
  }
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_.bridge_ != nullptr) device_.bridge_->on_delivery(result);
#endif
  if (device_.app_ != nullptr) device_.app_->on_delivery(result);
}

void Device::Observer::on_group_delivery(const GroupDeliveryResult& result) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_.bridge_ != nullptr) device_.bridge_->on_group_delivery(result);
#endif
  if (device_.app_ != nullptr) device_.app_->on_group_delivery(result);
}

void Device::Observer::on_applied_result(const MessageKey& key,
                                         const AppliedResultView& result) noexcept {
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_.bridge_ != nullptr) device_.bridge_->on_applied_result(key, result);
#endif
  if (device_.app_ != nullptr) device_.app_->on_applied_result(key, result);
}

void Device::Observer::on_diagnostic(const char* reason, const NodeId peer,
                                     const MessageId* message) noexcept {
  if (device_.bridge_ == nullptr) {
    ESP_LOGW(device_.tag_, "diagnostic reason=%s peer=%llu message=%s", reason,
             static_cast<unsigned long long>(peer), message == nullptr ? "none" : "present");
  }
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // Unknown-epoch group traffic is the backstop pull trigger for a missed
  // rotation Wake (records only; the owner polls the flag).
  if (device_.owner_ != nullptr && reason != nullptr &&
      std::strcmp(reason, "GROUP_KEY_RETIRED") == 0) {
    device_.owner_->note_group_key_retired();
  }
#endif
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (device_.bridge_ != nullptr) device_.bridge_->on_diagnostic(reason, peer, message);
#endif
  if (device_.app_ != nullptr) device_.app_->on_diagnostic(reason, peer, message);
}

// --- Boot -----------------------------------------------------------------------

Status Device::open_storage(const profile::Role role, const DeviceSecurity security) noexcept {
  // Every boot — even one that fails below — consumes a session, which
  // keeps TX epochs strictly fresh. The session lives in the default NVS
  // partition, so an exhausted security partition can never block it.
  Status status = next_boot_session(boot_session_);
  if (!status) return status;
  // Per-peer security state lives in its own partition (issue #37). Never
  // erase automatically: that would turn a storage fault into key/counter
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
  if (!status) {
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE && !CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
    ESP_LOGE(tag_, "sdkv1 stores open failed: %s", status.detail);
    return Status::success();
#else
    // The security owner (and a factory console) cannot work without
    // stores — continuing would run a dead node.
    return status;
#endif
  }
  stores_ = &stores;
  status = stores.initialize();
  if (!status) ESP_LOGE(tag_, "sdkv1 stores init: %s", status.detail);
  stores.log_state(tag_);
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE || CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
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
  tag_ = config.log_tag;
  role_ = config.role;
  security_ = config.security;
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

#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  if (config.legacy_security == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "legacy security provider missing");
  }
  SecurityProvider& provider = *config.legacy_security;
#else
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
  SecurityProvider& provider = owner.session_provider();
#endif

#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (config.usb != nullptr) {
    usb::UsbBridge::Config bridge_config{};
    bridge_config.secret = config.usb_secret;
    bridge_config.node = node.node;
    bridge_config.network = node.network;
#if ROUTELOOM_DEVICE_MEMBER && !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
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

  static espnow::EspNowRuntime runtime(config.radio, provider, observer_);
  status = runtime.initialize();
  if (!status) return status;
  runtime_ = &runtime;

#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
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
    dev.psk = config.dev_psk;
    secure_clear(config.dev_psk);
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
    adopted = true;
  }
#endif
#if ROUTELOOM_DEVICE_MEMBER
  if (config.security == DeviceSecurity::Member) {
    // usb_direct selects the gateway's USB local-join transport.
    status = owner.boot(boot_session_, /*rlboot_prepared=*/true, bridge_ != nullptr, now_ms);
    if (!status) return status;
    // Authority lane: R2, JoinConfirm and GK updates arrive on this mesh
    // sink (subtype-9 carriers and kind-7 objects).
    runtime.node().set_config_sink(owner.authority_mesh_sink());
    adopted = true;
  }
#endif
  if (!adopted) return Status::error(StatusCode::Unsupported, "security mode not in this image");
#endif
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr) bridge_->set_mesh(&runtime.node());
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
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr) bridge_->poll(now_ms);
#endif
  runtime_->poll_once();
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  if (owner_ != nullptr) owner_->poll(now_ms);
#endif
  run_posted();
  update_observation_remote();
  if (poll_hook_ != nullptr) poll_hook_(*this, now_ms, poll_ctx_);
}

MonotonicMs Device::next_deadline(const MonotonicMs now_ms) const noexcept {
  return now_ms + kOwnerPollPeriodMs;
}

Status Device::post(const Job job, void* ctx) noexcept {
  if (job == nullptr) return Status::error(StatusCode::InvalidArgument, "post job missing");
  portENTER_CRITICAL(&posted_lock_);
  const bool full = posted_count_ == kPostCapacity;
  if (!full) {
    posted_[static_cast<std::size_t>((posted_head_ + posted_count_) % kPostCapacity)] =
        Posted{job, ctx};
    ++posted_count_;
  }
  portEXIT_CRITICAL(&posted_lock_);
  return full ? Status::error(StatusCode::Busy, "post queue full") : Status::success();
}

void Device::run_posted() noexcept {
  // Bounded drain: jobs posted by a running job wait for the next pass.
  std::uint8_t budget = kPostCapacity;
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
#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE && !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
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

// --- Facade ---------------------------------------------------------------------

Status Device::send(const NodeId destination, const ByteView payload,
                    const SendOptions& options, MessageId& id) noexcept {
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->send_application(destination, payload, options, id);
}

Status Device::send_group(const GroupId group, const ByteView payload,
                          const GroupSendOptions& options, MessageId& id) noexcept {
  if (runtime_ == nullptr) return Status::error(StatusCode::InvalidState, "device not started");
  return runtime_->node().send_group(group, payload, options, runtime_->now_ms(), id);
}

Status Device::cancel(const MessageId& id) noexcept {
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
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  caps.member = false;
#endif
  caps.usb_gateway = bridge_ != nullptr;
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
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  return nullptr;
#else
  return owner_ == nullptr ? nullptr : &owner_->coordinator();
#endif
}

MeshNode* Device::mesh() noexcept {
  return runtime_ == nullptr ? nullptr : &runtime_->node();
}

}  // namespace routeloom
