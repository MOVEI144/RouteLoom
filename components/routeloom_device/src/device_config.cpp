// Remote-config target of a DevRam or Member node (V2-08, issue #17): the
// SDK-namespace ConfigJournal on the node's routed config lane, with the
// NVS journal, value and RLF1 floor stores.
// Member verifies permits under the adopted site's SAK and binds once the
// membership is adopted; DevRam verifies the development permit key derived
// from its PSK and binds at boot.

#include "routeloom/device.hpp"

#if ROUTELOOM_DEVICE_REMOTE_CONFIG

#include <array>
#include <cstring>

#include "device_config_provider.hpp"
#include "esp_log.h"
#include "routeloom/config.hpp"
#include "routeloom/config_cose.hpp"
#include "routeloom/config_dev.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/nvs_config_store.hpp"
#include "routeloom/nvs_security_floor.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/secure_clear.hpp"
#include "routeloom/site_signed.hpp"

namespace routeloom {

#define ROUTELOOM_DEVICE_DEV_RAM !CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
#define ROUTELOOM_DEVICE_MEMBER !CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM

struct DeviceRemoteConfig {
  explicit DeviceRemoteConfig(MeshNode& node) noexcept
      : floor(floor_storage), port(node), target(port, limiter) {}

  espnow::NvsConfigStore store;
  espnow::NvsSecurityFloorStore floor_storage;
  SecurityFloorStore floor;
  DeviceConfigProvider provider;
  // Mesh-only management: a change that could cut the node off is refused.
  DeviceMaintenanceGate gate{/*independent_admin_path=*/false};
  ConfigRateLimiter limiter;
  MeshConfigPort port;
  ConfigTarget target;
  EntropySource* entropy{nullptr};
  ConfigJournal* journal{nullptr};
  bool bind_tried{false};
};

namespace {

// One journal per boot. Storage and floor faults are not node-fatal
// (04 §4.7, 06 §6.3): the impaired journal refuses intake with honest
// verdicts while the node keeps routing.
Status open_journal(DeviceRemoteConfig& rc, const ConfigJournalConfig& config,
                    ConfigAuthorityVerifier& verifier, const char* tag,
                    const MonotonicMs now_ms) noexcept {
  // Binding is the managed provisioning point of the RLF1 floor.
  Status status = config_floor_ensure(rc.floor_storage, rc.floor, config.network, config.target);
  if (!status) ESP_LOGE(tag, "config floor unavailable: %s", status.detail);
  static ConfigJournal journal(config, rc.store, rc.floor, verifier, *rc.entropy, rc.limiter,
                               &rc.provider, /*validator=*/nullptr, &rc.gate);
  status = journal.initialize(now_ms);
  if (!status) {
    ESP_LOGE(tag, "config journal init failed: %s — config intake refuses", status.detail);
  }
  rc.journal = &journal;
  return rc.target.add_journal(endpoint::kConfigNamespaceSdk, journal);
}

}  // namespace

Status Device::begin_remote_config(const DeviceConfig& config, const keys::Secret& dev_psk,
                                   EntropySource& entropy, const MonotonicMs now_ms) noexcept {
  if (config.role == profile::Role::Gateway) {
    return Status::error(StatusCode::Unsupported, "remote config target on a gateway");
  }
  MeshNode& node = runtime_->node();
  static DeviceRemoteConfig rc(node);
  rc.entropy = &entropy;
  const Status bound = rc.target.bind_crypto_worker(owner_->crypto_worker());
  if (!bound) return bound;
  Status status = rc.store.open("rlcfg");
  if (!status) ESP_LOGE(tag_, "config store open failed: %s", status.detail);
  status = rc.provider.open("rlcfgv", tag_);
  if (!status) ESP_LOGE(tag_, "config provider open failed: %s", status.detail);
  status = rc.floor_storage.open("rlfloor", espnow::kSecurityNvsPartition);
  if (!status) ESP_LOGE(tag_, "security floor open failed: %s", status.detail);
  // Authority carriers (Member) route through the target to the Owner's
  // demux before the config path; DevRam has no authority lane (null).
  rc.target.attach_authority(owner_->authority_demux());
  status = node.set_config_sink(&rc.target);
  if (!status) return status;
  rc.provider.attach_node(&node);
  remote_config_ = &rc;
#if ROUTELOOM_DEVICE_DEV_RAM
  if (config.security == DeviceSecurity::DevRam) {
    // config_dev_key = SHA256("RouteLoom/config-dev/v1" || PSK): the host
    // derives the same bytes (routeloom-host config_dev_key) and neither
    // side signs with the link key itself.
    constexpr char kConfigDevDomain[] = "RouteLoom/config-dev/v1";
    static ScopeDigest dev_key{};
    std::array<std::uint8_t, sizeof(kConfigDevDomain) - 1 + sizeof(keys::Secret)> material{};
    std::memcpy(material.data(), kConfigDevDomain, sizeof(kConfigDevDomain) - 1);
    std::memcpy(material.data() + sizeof(kConfigDevDomain) - 1, dev_psk.data(), dev_psk.size());
    sha256(ByteView{material.data(), material.size()}, dev_key);
    secure_clear(material);
    static DevConfigAuthorityVerifier verifier(ByteView{dev_key.data(), dev_key.size()});
    ConfigJournalConfig journal{};
    journal.network = config.radio.node.network;
    journal.target = config.radio.node.node;
    journal.config_namespace = endpoint::kConfigNamespaceSdk;
    journal.boot_incarnation = boot_session_;
    journal.authorized_issuer = config.config_authority;
    journal.authority_generation = config.config_authority_generation;
    return open_journal(rc, journal, verifier, tag_, now_ms);
  }
#else
  static_cast<void>(dev_psk);
  static_cast<void>(now_ms);
#endif
  return Status::success();
}

void Device::poll_remote_config(const MonotonicMs now_ms) noexcept {
  DeviceRemoteConfig& rc = *remote_config_;

#if ROUTELOOM_DEVICE_MEMBER
  // The site's SAK and the adopted NodeId exist only after adoption: bind
  // once the member node runs. A failed bind leaves intake off this boot.
  if (rc.journal == nullptr && !rc.bind_tried && security_ == DeviceSecurity::Member &&
      runtime_->node().started() &&
      owner_->coordinator().mode() == sdkv1::CoordinatorMode::Member &&
      stores_->site().has_site()) {
    rc.bind_tried = true;
    static CoseEsp256AuthorityVerifier verifier;
    const MeshNode& node = runtime_->node();
    ConfigJournalConfig journal{};
    Status status = site_config_bind(stores_->site().site(), node.node_id(),
                                     node.config().boot_incarnation, journal, verifier);
    if (status) status = open_journal(rc, journal, verifier, tag_, now_ms);
    if (!status) ESP_LOGE(tag_, "remote config bind failed: %s", status.detail);
  }
#else
  static_cast<void>(now_ms);
#endif
  rc.provider.sync_relay();
}

}  // namespace routeloom

#endif  // ROUTELOOM_DEVICE_REMOTE_CONFIG
