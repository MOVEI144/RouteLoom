#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

#include "routeloom/aead_gcm.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/psa_aead_gcm.hpp"
#include "routeloom/psa_edhoc_aead.hpp"
#include "routeloom/psa_session_aead.hpp"

#include "routeloom/device.hpp"
#include "idf_stubs.hpp"
#include "test_sdkv1.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace routeloom::sdkv1 {
struct SecurityCoordinatorTestAccess {
  static bool apply_pending(const SecurityCoordinator& coordinator) noexcept {
    return coordinator.member_apply_pending_;
  }
  static void fail_link(SecurityCoordinator& coordinator, MonotonicMs now) noexcept {
    coordinator.note_link_failed(now);
  }
  static void disable_refresh_scan(SecurityCoordinator& coordinator) noexcept {
    coordinator.deps_.joiner_config.scan_channel_count = 0;
  }
};
}  // namespace routeloom::sdkv1

namespace routeloom::espnow {
struct EspNowSecurityOwnerTestAccess {
  static void install_coordinator(EspNowSecurityOwner& owner,
                                  const sdkv1::SecurityCoordinator::Deps& deps) noexcept {
    owner.config_.log_tag = "owner_reapply";
    new (owner.coordinator_box_.data()) sdkv1::SecurityCoordinator(deps);
    owner.coordinator_live_ = true;
  }
  static void attach_runtime(EspNowSecurityOwner& owner, EspNowRuntime& runtime) noexcept {
    owner.runtime_ = &runtime;
  }
  static void attach_bridge(EspNowSecurityOwner& owner, usb::UsbBridge& bridge) noexcept {
    owner.bridge_ = &bridge;
  }
  static void apply(EspNowSecurityOwner& owner,
                    const sdkv1::CoordinatorMemberConfig& config) noexcept {
    owner.on_member_config(config, owner.runtime_->now_ms());
  }
  static NetworkId adopted_network(const EspNowSecurityOwner& owner) noexcept {
    return owner.adopted_network_;
  }
  static void set_flat_group_routing(EspNowSecurityOwner& owner, bool flat) noexcept {
    owner.config_.flat_group_routing = flat;
  }
};

// The real Owner's boot-only PSA and NVS wiring is outside this test. Its
// apply method, coordinator, MeshNode and ESP-NOW runtime all execute.
const AeadGcm* psa_aead_gcm() noexcept { return builtin_aead_gcm(); }
sdkv1::AeadGcm psa_session_aead_gcm() noexcept { return {}; }
const edhoc::AeadCcm* psa_edhoc_aead_ccm() noexcept { return edhoc::builtin_aead_ccm(); }
Status EspOwnerEntropy::fill(MutableByteView) noexcept {
  return Status::error(StatusCode::InvalidState, "unused entropy");
}
void EspNowDiscoveryObserver::on_discovery_event(const char* reason, NodeId peer) noexcept {
  (void)tag_;
  if (runtime_ != nullptr && reason != nullptr) runtime_->note_diagnostic(reason, peer);
}
}  // namespace routeloom::espnow

[[noreturn]] void esp_restart() { std::abort(); }

namespace {

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace routeloom::espnow;
using namespace sdkv1_test;

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  ++failures; } } while (false)

constexpr MonotonicMs kStart = 100000;
constexpr std::uint32_t kBoot = 1234;
constexpr routeloom::MacAddress kMac{{0x02, 0, 0, 0, 0x12, 0x34}};

class Entropy final : public EntropySource {
 public:
  Status fill(MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) out.data[i] = next_++;
    return Status::success();
  }
 private:
  std::uint8_t next_{1};
};

class Sealer final : public JoinCookieSealer {
 public:
  Status seal(const JoinCookieMaterial&, JoinCookieBytes& out) noexcept override {
    out.fill(0x5A);
    return Status::success();
  }
};

bool bank_seal(void*, const std::uint8_t[16], const std::uint8_t[12], ByteView,
               ByteView plain, std::uint8_t* cipher, std::uint8_t tag[16]) noexcept {
  std::memcpy(cipher, plain.data, plain.size);
  std::memset(tag, 0, 16);
  return true;
}
bool bank_open(void*, const std::uint8_t[16], const std::uint8_t[12], ByteView,
               ByteView cipher, const std::uint8_t[16], std::uint8_t* plain) noexcept {
  std::memcpy(plain, cipher.data, cipher.size);
  return true;
}

struct Stores {
  FaultyRecordStorage identity_storage{kIdentitySlotBytes};
  FaultyRecordStorage site_storage{kSiteSlotBytes};
  FaultyRecordStorage revocation_storage{kRevocationSlotBytes};
  FaultyRecordStorage local_revocation_storage{kLocalRevocationSlotBytes};
  FaultyResumeStorage2 resume_storage{kResume2NodeLinkQuota + kResume2NodeEndQuota};
  IdentityStore identity{identity_storage};
  SiteStore site{site_storage};
  RevocationStore revocations{revocation_storage};
  LocalRevocationStore local_revocation{local_revocation_storage};
  StoreCredentialVerifier verifier{identity, site};
  Entropy entropy{};
  Sealer sealer{};

  bool init() {
    return identity.initialize().ok() && site.initialize().ok() &&
           revocations.initialize().ok() && local_revocation.initialize().ok() &&
           identity.commit(identity_record()).ok() && site.commit(site_record()).ok();
  }
  SecurityCoordinator::Deps deps(EspNowSecurityOwner& owner) {
    SecurityCoordinator::Deps out{};
    out.identity = &identity;
    out.site = &site;
    out.revocations = &revocations;
    out.local_revocation = &local_revocation;
    out.resume_storage = &resume_storage;
    out.entropy = &entropy;
    out.rld1 = &owner;
    out.mesh = &owner;
    out.usb = &owner;
    out.verifier = &verifier;
    out.bank_aead = sdkv1::AeadGcm{&bank_seal, &bank_open, nullptr};
    out.crypto_aead = *builtin_aead_gcm();
    out.proxy_sealer = &sealer;
    out.local_mac = kMac;
    out.local_node = kNode;
    out.joiner_config.node = kNode;
    out.joiner_config.mac = kMac;
    out.joiner_config.capability = kRld1CapMemberEdhocV1;
    out.joiner_config.requested_role = static_cast<std::uint8_t>(kMemberRoleEndpoint);
    return out;
  }
};

EspNowRuntimeConfig radio_config() {
  EspNowRuntimeConfig config{};
  config.node.network = static_cast<std::uint32_t>(kNetwork);
  config.node.node = kNode;
  config.node.message_session = 1;
  config.node.boot_incarnation = 1;
  config.node.link_epoch = 1;
  config.node.end_epoch = 1;
  config.channel = site_record().channel;
  config.max_tx_power_qdbm = 80;
  return config;
}

bool poll(SecurityCoordinator& coordinator, MonotonicMs now) {
  CoordinatorEvent event{};
  event.kind = CoordinatorEventKind::Poll;
  event.now = now;
  return coordinator.step(event).ok();
}

bool take_apply(SecurityCoordinator& coordinator, MonotonicMs& now,
                CoordinatorMemberConfig& member) {
  for (int i = 0; i < 50; ++i) {
    now += 100;
    idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
    if (!poll(coordinator, now)) return false;
    CoordinatorAction action{};
    while (coordinator.take_action(action).ok()) {
      if (action.kind == CoordinatorActionKind::ApplyMemberConfig) {
        member = action.member;
        return true;
      }
      if (action.kind == CoordinatorActionKind::TuneChannel) {
        CoordinatorEvent ready{};
        ready.kind = CoordinatorEventKind::ChannelReady;
        ready.now = now;
        ready.channel_token = action.tune.token;
        ready.channel_result = StatusCode::Ok;
        ready.channel = action.tune.channel;
        if (!coordinator.step(ready).ok()) return false;
      }
    }
  }
  return false;
}

void test_usb_network_after_cutover() {
  // A restarted gateway has a committed RLS1 for epoch 2, but the mesh
  // header and the legacy trust/bootstrap network still carry epoch 1.
  Stores stores{};
  CHECK(stores.init());
  const auto next = site_record(3, 204, kNetwork + (1ULL << 32U));
  CHECK(stores.site.commit(next).ok());
  const NetworkId bootstrap = static_cast<std::uint32_t>(next.network);
  CHECK(routeloom::usb_boot_network(stores.site, bootstrap) == next.network);
  CHECK(static_cast<std::uint32_t>(routeloom::usb_boot_network(stores.site, bootstrap)) ==
        bootstrap);

  FaultyRecordStorage empty_storage{kSiteSlotBytes};
  SiteStore empty{empty_storage};
  CHECK(empty.initialize().ok());
  CHECK(routeloom::usb_boot_network(empty, bootstrap) == bootstrap);
}

void test_same_boot_reapply(bool change_site_epoch) {
  idf_stub::reset();
  Stores stores{};
  CHECK(stores.init());
  EspNowSecurityOwner owner{};
  EspNowSecurityOwnerTestAccess::install_coordinator(owner, stores.deps(owner));
  routeloom_test::CapturingObserver observer{};
  EspNowRuntime runtime(radio_config(), owner.session_provider(), observer);
  EspNowSecurityOwnerTestAccess::attach_runtime(owner, runtime);
  CHECK(runtime.initialize().ok());

  CoordinatorEvent boot{};
  boot.kind = CoordinatorEventKind::Boot;
  boot.now = kStart;
  boot.boot_witness = kBoot;
  boot.boot_prepared = true;
  const Status booted = owner.coordinator().step(boot);
  if (!booted) std::fprintf(stderr, "boot: %s\n", booted.detail);
  CHECK(booted.ok());
  if (!booted) return;
  MonotonicMs now = kStart;
  CoordinatorMemberConfig first{};
  CHECK(take_apply(owner.coordinator(), now, first));
  EspNowSecurityOwnerTestAccess::apply(owner, first);
  CHECK(runtime.node().started());
  CHECK(first.role == kMemberRoleEndpoint);
  CHECK(!runtime.node().transit_permitted());
  CHECK(!SecurityCoordinatorTestAccess::apply_pending(owner.coordinator()));
  CHECK(runtime.node().config().network == static_cast<std::uint32_t>(first.network));
  CHECK(first.network >> 32U != 0);

  CHECK(poll(owner.coordinator(), ++now));
  CoordinatorAction discovery{};
  CHECK(owner.coordinator().take_action(discovery).ok());
  CHECK(discovery.kind == CoordinatorActionKind::StartMemberDiscovery);
  SecurityCoordinatorTestAccess::disable_refresh_scan(owner.coordinator());
  for (int i = 0; i < 3; ++i) SecurityCoordinatorTestAccess::fail_link(owner.coordinator(), now);
  CHECK(owner.coordinator().snapshot().refresh_strikes == 3);
  CHECK(poll(owner.coordinator(), ++now));
  CoordinatorMemberConfig second{};
  CHECK(take_apply(owner.coordinator(), now, second));
  CHECK(SecurityCoordinatorTestAccess::apply_pending(owner.coordinator()));
  if (change_site_epoch) second.network += (1ULL << 32U);
  idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
  EspNowSecurityOwnerTestAccess::apply(owner, second);
  CHECK(!SecurityCoordinatorTestAccess::apply_pending(owner.coordinator()));
  if (change_site_epoch) {
    CHECK(owner.coordinator().snapshot().mode == CoordinatorMode::Recovery);
    CHECK(EspNowSecurityOwnerTestAccess::adopted_network(owner) == first.network);
  } else {
    CHECK(owner.coordinator().snapshot().mode == CoordinatorMode::Member);
    CHECK(runtime.node().started());
    CHECK(poll(owner.coordinator(), ++now));
    CoordinatorAction resumed{};
    CHECK(owner.coordinator().take_action(resumed).ok());
    CHECK(resumed.kind == CoordinatorActionKind::StartMemberDiscovery);
  }
  runtime.stop();
}

// MemberEdhoc root mapping (dev-flow §6.1): the verified SitePackage
// gateway list lands on route_gateways (scoped) or group_roots (flat
// profile, Config::flat_group_routing) — the routing policy stays
// separate from the root set.
void test_member_root_mapping(bool flat) {
  idf_stub::reset();
  Stores stores{};
  CHECK(stores.init());
  EspNowSecurityOwner owner{};
  EspNowSecurityOwnerTestAccess::install_coordinator(owner, stores.deps(owner));
  EspNowSecurityOwnerTestAccess::set_flat_group_routing(owner, flat);
  routeloom_test::CapturingObserver observer{};
  EspNowRuntime runtime(radio_config(), owner.session_provider(), observer);
  EspNowSecurityOwnerTestAccess::attach_runtime(owner, runtime);
  CHECK(runtime.initialize().ok());

  CoordinatorEvent boot{};
  boot.kind = CoordinatorEventKind::Boot;
  boot.now = kStart;
  boot.boot_witness = kBoot;
  boot.boot_prepared = true;
  CHECK(owner.coordinator().step(boot).ok());
  MonotonicMs now = kStart;
  CoordinatorMemberConfig member{};
  CHECK(take_apply(owner.coordinator(), now, member));
  EspNowSecurityOwnerTestAccess::apply(owner, member);
  CHECK(runtime.node().started());
  const NodeConfig& node = runtime.node().config();
  if (flat) {
    CHECK(node.group_roots[0] == site_record().gateways[0] &&
          node.group_roots[1] == site_record().gateways[1]);
    CHECK(node.route_gateways[0] == kInvalidNodeId);
  } else {
    CHECK(node.route_gateways[0] == site_record().gateways[0] &&
          node.route_gateways[1] == site_record().gateways[1]);
    CHECK(node.group_roots[0] == kInvalidNodeId);
  }
  runtime.stop();
}

class NullStream final : public usb::ByteStream {
 public:
  Status write(const ByteView data, std::size_t& written) noexcept override {
    written = data.size;
    return Status::success();
  }
};

// D07/D09: bridge firmware binds the group lane BEFORE the member joins —
// the pre-adoption node is no group root, so the requested capability bit
// is masked out of HelloAck. Adoption installs the site gateway list; the
// owner refreshes the bridge and the next HelloAck advertises group
// delivery again.
void test_member_adoption_restores_group_capability() {
  idf_stub::reset();
  Stores stores{};
  CHECK(stores.init());
  EspNowSecurityOwner owner{};
  EspNowSecurityOwnerTestAccess::install_coordinator(owner, stores.deps(owner));
  routeloom_test::CapturingObserver observer{};
  EspNowRuntime runtime(radio_config(), owner.session_provider(), observer);
  EspNowSecurityOwnerTestAccess::attach_runtime(owner, runtime);
  CHECK(runtime.initialize().ok());

  NullStream stream{};
  const std::array<std::uint8_t, 16> secret{};
  usb::UsbBridge::Config bridge_cfg{};
  bridge_cfg.secret = ByteView{secret.data(), secret.size()};
  bridge_cfg.node = kNode;
  bridge_cfg.network = kNetwork;
  bridge_cfg.boot_id = 1;
  bridge_cfg.capability = usb::kCapGroupDeliveryV1;
  usb::UsbBridge bridge(bridge_cfg, stream);
  bridge.set_mesh(&runtime.node());
  CHECK(bridge.attach_group().ok());
  CHECK((bridge.capability() & usb::kCapGroupDeliveryV1) == 0);
  EspNowSecurityOwnerTestAccess::attach_bridge(owner, bridge);

  CoordinatorEvent boot{};
  boot.kind = CoordinatorEventKind::Boot;
  boot.now = kStart;
  boot.boot_witness = kBoot;
  boot.boot_prepared = true;
  CHECK(owner.coordinator().step(boot).ok());
  MonotonicMs now = kStart;
  CoordinatorMemberConfig member{};
  CHECK(take_apply(owner.coordinator(), now, member));
  // A gateway member: the adopted gateway list names this node.
  member.route_gateways[0] = kNode;
  member.role = static_cast<std::uint8_t>(kMemberRoleGateway);
  EspNowSecurityOwnerTestAccess::apply(owner, member);
  CHECK(runtime.node().started());
  CHECK(runtime.node().group_origin_servable());
  CHECK((bridge.capability() & usb::kCapGroupDeliveryV1) != 0);
  runtime.stop();
}

}  // namespace

int main() {
  test_usb_network_after_cutover();
  test_same_boot_reapply(false);
  test_same_boot_reapply(true);
  test_member_root_mapping(false);
  test_member_root_mapping(true);
  test_member_adoption_restores_group_capability();
  return failures == 0 ? 0 : 1;
}
