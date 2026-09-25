#include "routeloom/espnow_security_owner.hpp"

#include "esp_log.h"
#include "routeloom/secure_clear.hpp"

namespace routeloom::espnow {
namespace {

constexpr std::uint32_t kTuneDeadlineMs = 3000;
constexpr int kApplyCutoverRetries = 3;

}  // namespace

EspNowSecurityOwner::~EspNowSecurityOwner() noexcept {
  if (dev_live_) {
    dev_provider().sdkv1::DevGroupProvider::~DevGroupProvider();
    dev_live_ = false;
  }
  if (discovery_live_) {
    discovery()->~NeighborDiscovery();
    discovery_live_ = false;
  }
  if (coordinator_live_) {
    coordinator().~SecurityCoordinator();
    coordinator_live_ = false;
  }
  if (begun_) {
    verifier().~StoreCredentialVerifier();
    sealer().~HmacJoinCookie();
    begun_ = false;
  }
}

sdkv1::HmacJoinCookie& EspNowSecurityOwner::sealer() noexcept {
  return *reinterpret_cast<sdkv1::HmacJoinCookie*>(sealer_box_.data());
}

sdkv1::StoreCredentialVerifier& EspNowSecurityOwner::verifier() noexcept {
  return *reinterpret_cast<sdkv1::StoreCredentialVerifier*>(verifier_box_.data());
}

sdkv1::SecurityCoordinator& EspNowSecurityOwner::coordinator() noexcept {
  return *reinterpret_cast<sdkv1::SecurityCoordinator*>(coordinator_box_.data());
}

SecurityProvider& EspNowSecurityOwner::session_provider() noexcept {
  if (dev_live_) return dev_provider();
  return coordinator().session_provider();
}

sdkv1::DevGroupProvider& EspNowSecurityOwner::dev_provider() noexcept {
  return *reinterpret_cast<sdkv1::DevGroupProvider*>(dev_box_.data());
}

NeighborDiscovery* EspNowSecurityOwner::discovery() noexcept {
  if (!discovery_live_) return nullptr;
  return reinterpret_cast<NeighborDiscovery*>(discovery_box_.data());
}

Status EspNowSecurityOwner::begin(Sdkv1Stores& stores, EspOwnerEntropy& entropy,
                                  const Config& config) noexcept {
  if (begun_) return Status::error(StatusCode::AlreadyExists, "owner already begun");
  if (config.local_node == kInvalidNodeId || config.local_node == kBroadcastNodeId ||
      config.local_mac == routeloom::MacAddress{}) {
    return Status::error(StatusCode::InvalidArgument, "owner identity");
  }
  // The sealer is constructed UNKEYED here: begin() runs before the
  // radio is up (the runtime constructor needs the provider view first),
  // and the cookie key must be drawn only after the radio entropy source
  // is ready (G-SEC P4 §8.4) — boot() arms it once entropy.begin() has
  // run. seal() refuses until then; nothing seals before boot.
  config_ = config;
  stores_ = &stores;
  entropy_ = &entropy;
  new (sealer_box_.data()) sdkv1::HmacJoinCookie();
  new (verifier_box_.data()) sdkv1::StoreCredentialVerifier(stores_->identity(), stores_->site());
  sdkv1::SecurityCoordinator::Deps deps{};
  deps.identity = &stores_->identity();
  deps.site = &stores_->site();
  deps.revocations = &stores_->revocation();
  deps.local_revocation = &stores_->local_revocation();
  deps.resume_storage = &stores_->resume2();
  deps.entropy = entropy_;
  deps.rld1 = this;
  deps.mesh = this;
  deps.usb = this;
  deps.verifier = &verifier();
  deps.bank_aead = psa_session_aead_gcm();
  deps.proxy_sealer = &sealer();
  deps.local_mac = config_.local_mac;
  deps.local_node = config_.local_node;
  deps.joiner_config = config_.joiner;
  new (coordinator_box_.data()) sdkv1::SecurityCoordinator(deps);
  coordinator_live_ = true;
  begun_ = true;
  observer_store_ = EspNowDiscoveryObserver(config_.log_tag, runtime_);
  ESP_LOGI(config_.log_tag, "security owner ready (node 0x%llx)",
           static_cast<unsigned long long>(config_.local_node));
  return Status::success();
}

Status EspNowSecurityOwner::attach_runtime(EspNowRuntime& runtime) noexcept {
  if (!begun_) return Status::error(StatusCode::InvalidState, "owner not begun");
  if (runtime_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists, "runtime already attached");
  }
  const Status status = runtime.attach_bootstrap_sink(*this);
  if (!status) return status;
  runtime_ = &runtime;
  observer_store_ = EspNowDiscoveryObserver(config_.log_tag, runtime_);
  return Status::success();
}

Status EspNowSecurityOwner::attach_usb(usb::UsbBridge& bridge) noexcept {
  if (!begun_) return Status::error(StatusCode::InvalidState, "owner not begun");
  if (bridge_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists, "usb already attached");
  }
  const Status status = bridge.attach_security_owner(*this);
  if (!status) return status;
  bridge_ = &bridge;
  return Status::success();
}

Status EspNowSecurityOwner::boot(const std::uint32_t rlboot_witness, const bool rlboot_prepared,
                                 const bool usb_direct, const MonotonicMs now_ms) noexcept {
  if (!begun_ || booted_) {
    return Status::error(StatusCode::InvalidState, "owner boot state");
  }
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  if (!rlboot_prepared || rlboot_witness == 0) {
    return Status::error(StatusCode::InvalidArgument, "boot witness unavailable");
  }
  // Arm the ZT OFFER cookie sealer from post-radio-up entropy (boot runs
  // after entropy.begin() in main): boot-RAM-only, so a reboot
  // invalidates every outstanding cookie. Unbegun entropy fails the boot
  // — an unkeyed coordinator must never run.
  std::array<std::uint8_t, 32> cookie_key{};
  Status key_status = entropy_->fill(MutableByteView{cookie_key.data(), cookie_key.size()});
  if (!key_status) return key_status;
  key_status = sealer().install_key(cookie_key);
  secure_clear(cookie_key.data(), cookie_key.size());
  if (!key_status) return key_status;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Boot;
  event.now = now_ms;
  event.boot_witness = rlboot_witness;
  event.boot_prepared = rlboot_prepared;
  event.usb_direct = usb_direct;
  const Status status = coordinator().step(event);
  if (!status) return status;
  boot_witness_ = rlboot_witness;
  booted_ = true;
  ESP_LOGI(config_.log_tag, "booted (%s)", usb_direct ? "usb-direct" : "radio");
  return Status::success();
}

Status EspNowSecurityOwner::adopt_dev(const DevGroupConfig& config,
                                        const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!begun_) return Status::error(StatusCode::InvalidState, "owner not begun");
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  if (booted_ || dev_live_) {
    return Status::error(StatusCode::InvalidState, "owner already running");
  }
  if (config.network == 0 || config.node == kInvalidNodeId ||
      config.node == kBroadcastNodeId || config.node == 0 || config.boot == 0 ||
      config.channel == 0) {
    return Status::error(StatusCode::InvalidArgument, "dev config");
  }
  bool psk_zero = true;
  for (const std::uint8_t byte : config.psk) {
    if (byte != 0) psk_zero = false;
  }
  if (psk_zero) return Status::error(StatusCode::InvalidArgument, "dev psk");
  // The dev route has no cutover: the static channel must already match
  // the radio (firmware boots the runtime on it).
  if (runtime_->committed_channel() != config.channel) {
    return Status::error(StatusCode::InvalidArgument, "dev channel");
  }
  const Status sender_status =
      dev_sender_.configure(config.psk, config.network, config.node, config.boot);
  if (!sender_status) return sender_status;
  dev_aead_ = psa_session_aead_gcm();
  new (dev_box_.data()) sdkv1::DevGroupProvider(dev_sender_, config.psk, config.network,
                                                dev_aead_, config.node);
  dev_live_ = true;
  NodeConfig node = runtime_->node().config();
  node.network = config.network;
  node.node = config.node;
  node.message_session = config.boot;
  node.boot_session = config.boot;
  node.link_epoch = 1;
  node.end_epoch = 1;
  node.boot_incarnation = 0;  // unknown on the dev route (telemetry only)
  node.route_generation = config.boot;  // reserved boots rise every boot
  for (NodeId& gateway : node.route_gateways) gateway = kInvalidNodeId;
  const Status adopted = runtime_->adopt_member_node(node);
  if (!adopted) {
    dev_provider().sdkv1::DevGroupProvider::~DevGroupProvider();
    dev_live_ = false;
    dev_sender_.clear();
    return adopted;
  }
  runtime_->node().set_relay_enabled(config.role != 0);
  const Status started = runtime_->start();
  if (!started) {
    ESP_LOGE(config_.log_tag, "dev node start failed: %s", started.detail);
    return started;
  }
  ESP_LOGI(config_.log_tag, "dev adopted (node 0x%llx, boot %lu)",
           static_cast<unsigned long long>(config.node),
           static_cast<unsigned long>(config.boot));
  return Status::success();
}

void EspNowSecurityOwner::poll(const MonotonicMs now_ms) noexcept {
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Poll;
  event.now = now_ms;
  (void)coordinator().step(event);
  poll_tune(now_ms);
  drain_actions(now_ms);
}

Status EspNowSecurityOwner::prepare_sleep(const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  // Drain first: a pending action (tune/member/discovery) is owed work,
  // not sleep permission. The coordinator re-checks the slot anyway.
  poll_tune(now_ms);
  drain_actions(now_ms);
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::PrepareSleep;
  event.now = now_ms;
  return coordinator().step(event);
}

Status EspNowSecurityOwner::wake(const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Wake;
  event.now = now_ms;
  return coordinator().step(event);
}

void EspNowSecurityOwner::on_bootstrap_rld1(const sdkv1::JoinRxMeta& meta,
                                            const std::uint32_t radio_generation,
                                            const ByteView frame,
                                            const MonotonicMs received_ms) noexcept {
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Rld1Rx;
  event.now = received_ms;
  event.rld1_meta = meta;
  event.rld1_frame = frame;
  event.radio_generation = radio_generation;
  (void)coordinator().step(event);
}

Status EspNowSecurityOwner::join_down(const NodeId to_proxy, const sdkv1::RelayObject& object,
                                      const ByteView raw_object,
                                      const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  const NodeId self =
      adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
  if (to_proxy == self) {
    // LocalJoin (§8.2): exact match only — Down to self, our relay id,
    // our radio MAC. Anything else is refused, never forwarded.
    const sdkv1::RelayHeader& header = object.header;
    if (header.dir != sdkv1::RelayDirection::Down || header.proxy != self ||
        !sdkv1::local_join_token_matches(sdkv1::relay_token_of(header),
                                         boot_witness_, local_join_relay_id_) ||
        header.joiner_mac != config_.local_mac) {
      return Status::error(StatusCode::InvalidArgument, "local join mismatch");
    }
    if (header.state == sdkv1::RelayState::Abort) {
      // Abort-via-down: the attempt dies like on session loss.
      local_join_relay_id_ = 0;
      sdkv1::CoordinatorEvent abort{};
      abort.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
      abort.now = now_ms;
      (void)coordinator().step(abort);
      return Status::success();
    }
    sdkv1::CoordinatorEvent down{};
    down.kind = sdkv1::CoordinatorEventKind::UsbLocalDown;
    down.now = now_ms;
    down.usb_phase = header.phase;
    down.usb_step = header.step;
    down.usb_body = object.message;
    return coordinator().step(down);
  }
  sdkv1::CoordinatorEvent down{};
  down.kind = sdkv1::CoordinatorEventKind::UsbRelayDown;
  down.now = now_ms;
  down.usb_proxy = to_proxy;
  down.usb_object = raw_object;
  return coordinator().step(down);
}

Status EspNowSecurityOwner::join_abort(const NodeId proxy, const sdkv1::RelayToken token,
                                       const std::uint8_t reason,
                                       const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  const NodeId self =
      adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
  if (proxy == self &&
      sdkv1::local_join_token_matches(token, boot_witness_, local_join_relay_id_)) {
    // The host is aborting our own LocalJoin attempt.
    local_join_relay_id_ = 0;
    sdkv1::CoordinatorEvent abort{};
    abort.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
    abort.now = now_ms;
    (void)coordinator().step(abort);
    return Status::success();
  }
  sdkv1::CoordinatorEvent abort{};
  abort.kind = sdkv1::CoordinatorEventKind::UsbRelayAbort;
  abort.now = now_ms;
  abort.usb_proxy = proxy;
  abort.usb_relay_id = token.relay_id;
  abort.usb_gateway_epoch = token.gateway_epoch;
  abort.usb_proxy_epoch = token.proxy_epoch;
  abort.usb_reason = reason;
  return coordinator().step(abort);
}

void EspNowSecurityOwner::join_session_down(const MonotonicMs now_ms) noexcept {
  local_join_relay_id_ = 0;
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
  event.now = now_ms;
  (void)coordinator().step(event);
}

Status EspNowSecurityOwner::send_rld1(const routeloom::MacAddress& destination,
                                      const ByteView frame) noexcept {
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  return runtime_->send_rld1(destination, frame);
}

Status EspNowSecurityOwner::send_bootstrap(const NodeId destination, const FrameType type,
                                           const ByteView payload, const std::uint32_t lifetime_ms,
                                           const MonotonicMs now_ms, MessageId& id) noexcept {
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  return runtime_->node().send_bootstrap(destination, type, payload, lifetime_ms, now_ms, id);
}

Status EspNowSecurityOwner::send_local_join_up(const sdkv1::JoinAuthPhase phase,
                                               const std::uint8_t step,
                                               const ByteView message) noexcept {
  if (bridge_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  if (local_join_relay_id_ == 0) {
    std::uint32_t id = 0;
    const Status drawn = entropy_->fill(
        MutableByteView{reinterpret_cast<std::uint8_t*>(&id), sizeof(id)});
    if (!drawn) return drawn;
    local_join_relay_id_ = id != 0 ? id : 1;  // nonzero within the session
  }
  const NodeId self =
      adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
  sdkv1::RelayObject up{};
  up.header.dir = sdkv1::RelayDirection::Up;
  up.header.relay_id = local_join_relay_id_;
  up.header.proxy = self;
  up.header.joiner_mac = config_.local_mac;
  up.header.phase = phase;
  up.header.step = step;
  up.header.state = sdkv1::RelayState::Continue;
  const sdkv1::RelayToken token =
      sdkv1::local_join_token(boot_witness_, local_join_relay_id_);
  up.header.gateway_epoch = token.gateway_epoch;
  up.header.proxy_epoch = token.proxy_epoch;
  up.message = message;
  std::array<std::uint8_t, sdkv1::kRelayObjectMax> encoded{};
  std::size_t written = 0;
  const Status status = sdkv1::relay_object_encode(
      up, MutableByteView{encoded.data(), encoded.size()}, written);
  if (!status) return status;
  return bridge_->relay_up(self, 0, ByteView{encoded.data(), written});
}

Status EspNowSecurityOwner::send_relay_up_to_host(const NodeId proxy, const std::uint8_t hops,
                                                  const ByteView object) noexcept {
  if (bridge_ == nullptr) {
    // No host: the gateway engine sheds with authority_unreachable.
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  return bridge_->relay_up(proxy, hops, object);
}

Status EspNowSecurityOwner::send_relay_abort_to_host(
    const NodeId proxy, const sdkv1::RelayToken token,
    const sdkv1::RelayAbortReason reason) noexcept {
  if (bridge_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  return bridge_->relay_abort(proxy, token, reason);
}

SecurityProfile EspNowSecurityOwner::security_profile() const noexcept {
  // EXPERIMENTAL until P8 declares production (§15): the node surfaces
  // SECURITY_PROFILE_EXPERIMENTAL and nothing claims production status.
  return SecurityProfile::Development;
}

bool EspNowSecurityOwner::binds_scope() const noexcept {
  // Vacuously true: member discovery never runs PROVE/CONFIRM (proofs are
  // engine-minted), so no transcript binding is needed — but Required
  // refuses to start without the flag, and the GK scope binds
  // DISCOVER/OFFER through the scope provider instead.
  return true;
}

Status EspNowSecurityOwner::cookie_seal(const CookieMaterial& material, AuthTag& out) noexcept {
  const sdkv1::MemberCookie* cookie = coordinator().member_cookie();
  if (cookie == nullptr) {
    return Status::error(StatusCode::InvalidState, "member cookie not live");
  }
  if (material.time_bucket > UINT64_MAX / sdkv1::MemberCookie::kBucketMs) {
    return Status::error(StatusCode::InvalidArgument, "cookie bucket overflow");
  }
  return cookie->seal(material.requester_mac, material.requester_nonce, material.network,
                      material.time_bucket * sdkv1::MemberCookie::kBucketMs, out);
}

Status EspNowSecurityOwner::cookie_verify(const CookieMaterial& material,
                                          const AuthTag& tag) noexcept {
  const sdkv1::MemberCookie* cookie = coordinator().member_cookie();
  if (cookie == nullptr) {
    return Status::error(StatusCode::InvalidState, "member cookie not live");
  }
  if (material.time_bucket > UINT64_MAX / sdkv1::MemberCookie::kBucketMs) {
    return Status::error(StatusCode::InvalidArgument, "cookie bucket overflow");
  }
  return cookie->verify(material.requester_mac, material.requester_nonce, material.network,
                        ByteView{tag.data(), tag.size()},
                        material.time_bucket * sdkv1::MemberCookie::kBucketMs);
}

Status EspNowSecurityOwner::attest(const autonomy::AuthPhase, const AuthTranscript&,
                                   AuthTag&) noexcept {
  return Status::error(StatusCode::Unsupported, "member proofs are engine-minted");
}

Status EspNowSecurityOwner::verify(const autonomy::AuthPhase, const AuthTranscript&,
                                   const AuthTag&) noexcept {
  return Status::error(StatusCode::Unsupported, "member proofs are engine-minted");
}

Status EspNowSecurityOwner::issue_proof(const AuthTranscript&, const NodeId, const AuthTag&,
                                        AuthenticatedPeerProof&) noexcept {
  return Status::error(StatusCode::Unsupported, "member proofs are engine-minted");
}

void EspNowSecurityOwner::drain_actions(const MonotonicMs now_ms) noexcept {
  for (;;) {
    sdkv1::CoordinatorAction action{};
    if (!coordinator().take_action(action).ok()) return;
    switch (action.kind) {
      case sdkv1::CoordinatorActionKind::TuneChannel:
        on_tune_channel(action.tune, now_ms);
        break;
      case sdkv1::CoordinatorActionKind::ApplyMemberConfig:
        on_member_config(action.member, now_ms);
        break;
      case sdkv1::CoordinatorActionKind::StartMemberDiscovery:
        on_start_discovery(now_ms);
        break;
      case sdkv1::CoordinatorActionKind::ReportRemoval:
        ESP_LOGE(config_.log_tag,
                 "membership removed (site 0x%llx gen %lu): traffic stopped, "
                 "cleanup rides maintenance",
                 static_cast<unsigned long long>(action.removal.site_id),
                 static_cast<unsigned long>(action.removal.generation));
        runtime_->node().set_relay_enabled(false);
        break;
      case sdkv1::CoordinatorActionKind::ReportRecovery:
        ESP_LOGE(config_.log_tag, "membership recovery required (reason %u): see maintenance",
                 static_cast<unsigned>(action.recovery));
        break;
      case sdkv1::CoordinatorActionKind::None:
        break;
    }
  }
}

void EspNowSecurityOwner::on_tune_channel(const sdkv1::CoordinatorTune& tune,
                                          const MonotonicMs now_ms) noexcept {
  if (tune_.active) {
    // Unreachable: the Joiner waits for ChannelReady before the next
    // tune. Drop defensively rather than misattribute completions.
    ESP_LOGW(config_.log_tag, "tune dropped: another tune outstanding");
    return;
  }
  // The join PHY rides the radio's existing rate selection (LR250 peers
  // stay LR250); the cutover only moves the channel.
  (void)tune.phy;
  const Status requested = request_cutover(tune.channel, tune.token, now_ms);
  if (!requested) {
    ESP_LOGW(config_.log_tag, "tune request failed: %s", requested.detail);
    report_tune(Tune{tune.token, kInvalidOperationToken, tune.channel, true},
                StatusCode::RadioFailure, now_ms);
  }
}

void EspNowSecurityOwner::on_member_config(const sdkv1::CoordinatorMemberConfig& member,
                                           const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  adopted_node_ = member.node;
  adopted_network_ = member.network;
  NodeConfig node = runtime_->node().config();
  node.network = member.network;
  node.node = member.node;
  node.message_session = member.message_session;
  node.boot_session = member.boot_session;
  node.link_epoch = member.link_epoch;
  node.end_epoch = member.end_epoch;
  node.boot_incarnation = member.boot_incarnation;
  node.route_gateways.fill(kInvalidNodeId);
  for (std::size_t i = 0; i < member.route_gateway_count && i < node.route_gateways.size(); ++i) {
    node.route_gateways[i] = member.route_gateways[i];
  }
  const std::uint8_t operating = stores_->site().has_site()
                                     ? stores_->site().site().channel
                                     : runtime_->committed_channel();
  Status status = runtime_->adopt_member_node(node);
  if (!status) {
    ESP_LOGE(config_.log_tag, "member node adopt failed: %s", status.detail);
    report_tune(Tune{0, kInvalidOperationToken, operating, true},
                StatusCode::RadioFailure, runtime_->now_ms());
    return;
  }
  runtime_->node().set_bootstrap_sink(&coordinator());
  // Relay duties are role-gated (unknown role 0 never transits).
  runtime_->node().set_relay_enabled(member.role != 0);
  // The radio may still sit on the join channel: move it to the adopted
  // operating channel before the node starts (no member traffic flows
  // during the move). Already there → start immediately.
  if (operating == runtime_->committed_channel()) {
    report_tune(Tune{0, kInvalidOperationToken, operating, true}, StatusCode::Ok,
                runtime_->now_ms());
    return;
  }
  apply_retries_ = kApplyCutoverRetries;
  apply_channel_ = operating;
  status = request_cutover(operating, 0, runtime_->now_ms());
  if (!status) {
    ESP_LOGE(config_.log_tag, "member channel move failed: %s", status.detail);
    report_tune(Tune{0, kInvalidOperationToken, operating, true},
                StatusCode::RadioFailure, runtime_->now_ms());
  }
}

void EspNowSecurityOwner::on_start_discovery(const MonotonicMs now_ms) noexcept {
  if (discovery_live_) return;
  if (!stores_->site().has_site()) {
    ESP_LOGE(config_.log_tag, "member discovery without adopted site");
    return;
  }
  DiscoveryConfig config{};
  const Status prepared = coordinator().member_discovery_config(config);
  if (!prepared) {
    ESP_LOGE(config_.log_tag, "member discovery config failed: %s", prepared.detail);
    return;
  }
  auto* engine = new (discovery_box_.data()) NeighborDiscovery(config, *runtime_, *this,
                                                         coordinator().membership_hooks(),
                                                         *entropy_, observer_store_);
  discovery_live_ = true;
  Status status = engine->start(now_ms);
  if (!status) {
    ESP_LOGE(config_.log_tag, "member discovery start failed: %s", status.detail);
    abort_discovery_start(now_ms, false);
    return;
  }
  status = coordinator().attach_discovery(*engine);
  if (!status) {
    ESP_LOGE(config_.log_tag, "discovery attach failed: %s", status.detail);
    abort_discovery_start(now_ms, false);
    return;
  }
  status = runtime_->attach_autonomy(*engine);
  if (!status) {
    ESP_LOGE(config_.log_tag, "autonomy attach failed: %s", status.detail);
    abort_discovery_start(now_ms, true);
    return;
  }
  engine->set_member_handshake_mode(true);
  status = engine->begin_discovery(now_ms);
  if (!status) {
    ESP_LOGE(config_.log_tag, "member begin_discovery failed: %s", status.detail);
    abort_discovery_start(now_ms, true);
    return;
  }
  ESP_LOGI(config_.log_tag, "member discovery started");
}

void EspNowSecurityOwner::abort_discovery_start(const MonotonicMs now_ms,
                                                const bool attached) noexcept {
  // Attached ports may retain the discovery pointer. Keep the object alive
  // until runtime teardown, while revoking all session keys and radio work.
  if (!attached && discovery_live_) {
    discovery()->~NeighborDiscovery();
    discovery_live_ = false;
    secure_clear(discovery_box_);
  }
  sdkv1::CoordinatorEvent stop{};
  stop.kind = sdkv1::CoordinatorEventKind::Stop;
  stop.now = now_ms;
  (void)coordinator().step(stop);
  runtime_->stop();
}

void EspNowSecurityOwner::poll_tune(const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!tune_.active) return;
  OperationResult result{};
  if (!runtime_->radio_operation_result(tune_.op, result)) {
    // Evidence expired before a terminal outcome: call it unknown.
    const Tune done = tune_;
    tune_ = Tune{};
    report_tune(done, StatusCode::DriverResultUnknown, runtime_->now_ms());
    return;
  }
  if (result.outcome == OperationOutcome::Pending) return;
  const Tune done = tune_;
  tune_ = Tune{};
  switch (result.outcome) {
    case OperationOutcome::Applied:
      report_tune(done, StatusCode::Ok, runtime_->now_ms());
      break;
    case OperationOutcome::Rejected:
      report_tune(done, StatusCode::AuthorizationFailed, runtime_->now_ms());
      break;
    case OperationOutcome::Failed:
      report_tune(done, StatusCode::RadioFailure, runtime_->now_ms());
      break;
    case OperationOutcome::Indeterminate:
    case OperationOutcome::Pending:
      report_tune(done, StatusCode::DriverResultUnknown, runtime_->now_ms());
      break;
  }
}

void EspNowSecurityOwner::report_tune(const Tune& tune, const StatusCode result_code,
                                      const MonotonicMs now_ms) noexcept {
  StatusCode reported = result_code;
  if (tune.coord_token == 0) {
    // The ApplyMemberConfig channel move: start the node, then report
    // the firmware's apply-time ChannelReady. On a failed move with
    // retries left, re-request instead of reporting.
    if (reported == StatusCode::Ok && runtime_->committed_channel() != tune.channel) {
      reported = StatusCode::RadioFailure;
    }
    if (reported != StatusCode::Ok && apply_retries_ > 0 && apply_channel_ != 0) {
      --apply_retries_;
      const Status retry = request_cutover(apply_channel_, 0, now_ms);
      if (retry) return;
      ESP_LOGW(config_.log_tag, "member channel retry failed: %s", retry.detail);
    }
    apply_retries_ = 0;
    apply_channel_ = 0;
    if (reported == StatusCode::Ok) {
      const Status started = runtime_->start();
      if (!started) {
        ESP_LOGE(config_.log_tag, "member node start failed: %s", started.detail);
        reported = started.code;
      }
    }
  }
  // Report reality, not the request: the coordinator gates RLD1 on the
  // observed (channel, generation), so a failed move must not claim the
  // target.
  sdkv1::CoordinatorEvent ready{};
  ready.kind = sdkv1::CoordinatorEventKind::ChannelReady;
  ready.now = now_ms;
  ready.channel_token = tune.coord_token;
  ready.channel_result = reported;
  ready.channel = runtime_->committed_channel();
  ready.channel_generation = runtime_->radio_generation().value;
  (void)coordinator().step(ready);
}

Status EspNowSecurityOwner::request_cutover(const std::uint8_t channel,
                                            const std::uint32_t coord_token,
                                            const MonotonicMs now_ms) noexcept {
  RadioOperation op{};
  op.kind = RadioOperationKind::ChannelCutover;
  op.deadline_ms = now_ms + kTuneDeadlineMs;
  op.constraints.channel = channel;
  op.constraints.outage_permitted = true;
  const OperationToken token = runtime_->request_radio_operation(op);
  if (token == kInvalidOperationToken) {
    return Status::error(StatusCode::RadioFailure, "cutover not accepted");
  }
  tune_.coord_token = coord_token;
  tune_.op = token;
  tune_.channel = channel;
  tune_.active = true;
  return Status::success();
}

}  // namespace routeloom::espnow
