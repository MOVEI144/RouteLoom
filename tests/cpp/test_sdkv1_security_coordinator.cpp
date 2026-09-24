// The single device security Owner (G-SEC P4 §8, PR4): boot/store
// classification, the RLD1 demux gates, staged bootstrap RX, the USB
// gateway queue-admission verdicts, sleep/wake/stop and the RLV1
// commit veto. The Joiner, engine, proxy and gateway internals stay in
// their own suites — here only the Owner glue is under test.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/usb_host_ops.hpp"

#include "test_sdkv1.hpp"

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,      \
                   current.c_str(), #expr);                                          \
      ++failures;                                                                    \
    }                                                                                \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;

constexpr MacAddress kMac{{0x02, 0, 0, 0, 0x12, 0x34}};
constexpr MacAddress kPeerMac{{0x02, 0, 0, 0, 0x0A, 0x01}};
constexpr std::uint32_t kBoot = 1234;  // site_record().boot_witness
constexpr MonotonicMs kT0 = 100000;

// --- Fakes ----------------------------------------------------------------------

class FakeEntropy final : public EntropySource {
 public:
  Status fill(const MutableByteView out) noexcept override {
    if (out.data == nullptr) return Status::error(StatusCode::InvalidArgument, "null");
    for (std::size_t i = 0; i < out.size; ++i) {
      state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
      out.data[i] = static_cast<std::uint8_t>(state_ >> 33U);
    }
    return Status::success();
  }

 private:
  std::uint64_t state_{0x12345678ULL};
};

bool fake_seal(void*, const std::uint8_t[16], const std::uint8_t[12], ByteView,
               ByteView plaintext, std::uint8_t* out_ciphertext,
               std::uint8_t out_tag[16]) noexcept {
  if (out_ciphertext == nullptr || out_tag == nullptr) return false;
  std::memcpy(out_ciphertext, plaintext.data, plaintext.size);
  std::memset(out_tag, 0, 16);
  return true;
}

bool fake_open(void*, const std::uint8_t[16], const std::uint8_t[12], ByteView,
               ByteView ciphertext, const std::uint8_t[16],
               std::uint8_t* out_plaintext) noexcept {
  if (out_plaintext == nullptr) return false;
  std::memcpy(out_plaintext, ciphertext.data, ciphertext.size);
  return true;
}

class FakeRld1 final : public ZtRld1Port {
 public:
  Status send_rld1(const MacAddress& destination, const ByteView frame) noexcept override {
    sends.push_back({destination, std::vector<std::uint8_t>(frame.data, frame.data + frame.size)});
    return Status::success();
  }
  struct Send {
    MacAddress dest{};
    std::vector<std::uint8_t> bytes{};
  };
  std::vector<Send> sends{};
};

class FakeMesh final : public CoordinatorMeshPort {
 public:
  Status send_bootstrap(const NodeId destination, const FrameType type, const ByteView payload,
                        const std::uint32_t lifetime_ms, const MonotonicMs now_ms,
                        MessageId& id) noexcept override {
    (void)lifetime_ms;
    (void)now_ms;
    sends.push_back({destination, type, std::vector<std::uint8_t>(payload.data,
                                                                  payload.data + payload.size)});
    id = MessageId{1, static_cast<std::uint32_t>(sends.size())};
    return Status::success();
  }
  struct Send {
    NodeId dest{kInvalidNodeId};
    FrameType type{FrameType::Data};
    std::vector<std::uint8_t> bytes{};
  };
  std::vector<Send> sends{};
};

class FakeUsb final : public CoordinatorUsbPort {
 public:
  Status send_local_join_up(const JoinAuthPhase phase, const std::uint8_t step,
                            const ByteView message) noexcept override {
    local_ups.push_back({phase, step, message.size});
    return Status::success();
  }
  Status send_relay_up_to_host(const NodeId proxy, const std::uint8_t hops,
                               const ByteView object) noexcept override {
    relay_ups.push_back({proxy, hops, object.size});
    return Status::success();
  }
  Status send_relay_abort_to_host(const NodeId proxy, const RelayToken token,
                                  const RelayAbortReason reason) noexcept override {
    relay_aborts.push_back({proxy, token, reason});
    return Status::success();
  }
  struct Up {
    JoinAuthPhase phase{JoinAuthPhase::EdhocMessage};
    std::uint8_t step{0};
    std::size_t size{0};
  };
  struct RelayUp {
    NodeId proxy{kInvalidNodeId};
    std::uint8_t hops{0};
    std::size_t size{0};
  };
  struct Abort {
    NodeId proxy{kInvalidNodeId};
    RelayToken token{};
    RelayAbortReason reason{RelayAbortReason::HostAborted};
  };
  std::vector<Up> local_ups{};
  std::vector<RelayUp> relay_ups{};
  std::vector<Abort> relay_aborts{};
};

class FakeSealer final : public JoinCookieSealer {
 public:
  Status seal(const JoinCookieMaterial&, JoinCookieBytes& out) noexcept override {
    out.fill(0x5A);
    return Status::success();
  }
};

class FakeTrustStorage final : public TrustStoreStorage {
 public:
  Status read(const std::uint8_t, const MutableByteView) noexcept override {
    return Status::error(StatusCode::StorageFailure, "no trust fixture");
  }
  Status write(const std::uint8_t, const ByteView) noexcept override {
    return Status::error(StatusCode::StorageFailure, "no trust fixture");
  }
};

class StubDiscoveryPort final : public DiscoveryPort {
 public:
  Status send_rld1(const MacAddress&, const ByteView) noexcept override {
    return Status::success();
  }
  Status send_wire(const BindingId, const MacAddress&, const FrameType,
                   const ByteView) noexcept override {
    return Status::success();
  }
};

class StubAuthenticator final : public NeighborAuthenticator {
 public:
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  Status cookie_seal(const CookieMaterial&, AuthTag&) noexcept override {
    return Status::error(StatusCode::Unsupported, "stub");
  }
  Status cookie_verify(const CookieMaterial&, const AuthTag&) noexcept override {
    return Status::error(StatusCode::Unsupported, "stub");
  }
  Status attest(const autonomy::AuthPhase, const AuthTranscript&, AuthTag&) noexcept override {
    return Status::error(StatusCode::Unsupported, "stub");
  }
  Status verify(const autonomy::AuthPhase, const AuthTranscript&, const AuthTag&) noexcept override {
    return Status::error(StatusCode::Unsupported, "stub");
  }
  Status issue_proof(const AuthTranscript&, const NodeId, const AuthTag&,
                     AuthenticatedPeerProof&) noexcept override {
    return Status::error(StatusCode::Unsupported, "stub");
  }
};

class StubHooks final : public MembershipHooks {
 public:
  bool local_member(NetworkId) const noexcept override { return false; }
  bool known_member(NodeId, NetworkId) const noexcept override { return false; }
  bool approve_join(NodeId, NetworkId) noexcept override { return false; }
};

// --- Fixture --------------------------------------------------------------------

struct Fixture {
  FaultyRecordStorage identity_storage{kIdentitySlotBytes};
  FaultyRecordStorage site_storage{kSiteSlotBytes};
  FaultyRecordStorage revocation_storage{kRevocationSlotBytes};
  FaultyRecordStorage local_revocation_storage{kLocalRevocationSlotBytes};
  FaultyResumeStorage2 resume_storage;
  FakeTrustStorage trust_storage{};
  IdentityStore identity{identity_storage};
  SiteStore site{site_storage};
  RevocationStore revocations{revocation_storage};
  LocalRevocationStore local_revocation{local_revocation_storage};
  TrustStore trust{trust_storage};
  FakeEntropy entropy{};
  FakeRld1 rld1{};
  FakeMesh mesh{};
  FakeUsb usb{};
  StoreCredentialVerifier verifier{identity, site};
  FakeSealer sealer{};
  StubDiscoveryPort discovery_port{};
  StubAuthenticator authenticator{};
  StubHooks hooks{};
  NullDiscoveryObserver observer{};
  DiscoveryConfig discovery_config{};
  NeighborDiscovery discovery{discovery_config, discovery_port, authenticator, hooks, entropy,
                              observer};

  explicit Fixture(const std::size_t slots = kResume2NodeLinkQuota + kResume2NodeEndQuota)
      : resume_storage(slots) {}

  SecurityCoordinator::Deps deps() {
    SecurityCoordinator::Deps d{};
    d.identity = &identity;
    d.site = &site;
    d.revocations = &revocations;
    d.local_revocation = &local_revocation;
    d.resume_storage = &resume_storage;
    d.discovery = &discovery;
    d.entropy = &entropy;
    d.rld1 = &rld1;
    d.mesh = &mesh;
    d.usb = &usb;
    d.verifier = &verifier;
    d.bank_aead = sdkv1::AeadGcm{&fake_seal, &fake_open, nullptr};
    d.proxy_sealer = &sealer;
    d.local_mac = kMac;
    d.local_node = kNode;
    d.joiner_config.node = kNode;
    d.joiner_config.mac = kMac;
    d.joiner_config.capability = kMemberRoleMask;
    d.joiner_config.requested_role = static_cast<std::uint8_t>(kMemberRoleEndpoint);
    return d;
  }

  bool init_stores() {
    return identity.initialize().ok() && site.initialize().ok() && revocations.initialize().ok() &&
           local_revocation.initialize().ok();
  }
};

CoordinatorEvent poll_at(const MonotonicMs now) {
  CoordinatorEvent event{};
  event.kind = CoordinatorEventKind::Poll;
  event.now = now;
  return event;
}

CoordinatorEvent boot_event(const MonotonicMs now, const std::uint32_t witness,
                            const bool usb_direct = false) {
  CoordinatorEvent event{};
  event.kind = CoordinatorEventKind::Boot;
  event.now = now;
  event.boot_witness = witness;
  event.boot_prepared = true;
  event.usb_direct = usb_direct;
  return event;
}

bool poll_until_member(SecurityCoordinator& coordinator, MonotonicMs& now, const int cap = 50) {
  for (int i = 0; i < cap; ++i) {
    now += 100;
    if (!coordinator.step(poll_at(now)).ok()) return false;
    CoordinatorAction action{};
    while (coordinator.take_action(action).ok()) {
    }
    if (coordinator.snapshot().mode == CoordinatorMode::Member) return true;
  }
  return false;
}

SiteRecord gateway_site() {
  SiteRecord r = site_record();
  r.role = static_cast<std::uint8_t>(kMemberRoleGateway);
  CertClaims claims = membercert_claims(r.assignment_generation, r.network);
  claims.role = kMemberRoleGateway;
  r.member_cert = issue(claims, sak());
  return r;
}

// --- Tests ----------------------------------------------------------------------

void test_boot_silent_adoption() {
  current = "boot_silent_adoption";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(!coordinator.session_provider().ready());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  CHECK(coordinator.snapshot().mode == CoordinatorMode::ZeroTouch);

  // The healthy boot check adopts silently: ApplyMemberConfig first, then
  // StartMemberDiscovery once the firmware took the config.
  MonotonicMs now = kT0;
  bool saw_config = false;
  bool saw_discovery = false;
  for (int i = 0; i < 50 && !(saw_config && saw_discovery); ++i) {
    now += 100;
    CHECK(coordinator.step(poll_at(now)).ok());
    CoordinatorAction action{};
    while (coordinator.take_action(action).ok()) {
      if (action.kind == CoordinatorActionKind::ApplyMemberConfig) {
        CHECK(!saw_config);
        saw_config = true;
        CHECK(action.member.network == kNetwork);
        CHECK(action.member.node == kNode);
        CHECK(action.member.boot_session == kBoot);
        CHECK(action.member.message_session != 0);
        CHECK(action.member.link_epoch == 1);
        CHECK(action.member.end_epoch == 1);
        CHECK(action.member.role == kMemberRoleEndpoint);
        CHECK(action.member.route_gateway_count == 2);
        CHECK(action.member.route_gateways[0] == 0x00A1000000000001ULL);
        CHECK(action.member.route_gateways[1] == 0x00A1000000000002ULL);
      } else if (action.kind == CoordinatorActionKind::StartMemberDiscovery) {
        CHECK(saw_config);  // order: config first, discovery second
        saw_discovery = true;
      } else {
        CHECK(false);  // no TuneChannel on a silent adoption
      }
    }
  }
  CHECK(saw_config);
  CHECK(saw_discovery);
  CHECK(coordinator.snapshot().mode == CoordinatorMode::Member);

  // The GK scope went live with the adopted generation; anything else
  // refuses without leaking.
  std::uint32_t generation = 0;
  CHECK(coordinator.gk_scope().current_generation(ScopeRef{}, generation));
  CHECK(generation == 203);
  ScopeTag tag{};
  const std::uint8_t input[3] = {1, 2, 3};
  CHECK(coordinator.gk_scope()
            .scope_tag(ScopeRef{}, 203, ByteView{input, sizeof(input)}, tag)
            .ok());
  ScopeTag refused{};
  CHECK(!coordinator.gk_scope()
             .scope_tag(ScopeRef{}, 204, ByteView{input, sizeof(input)}, refused)
             .ok());
  for (const auto byte : refused) CHECK(byte == 0);

  // Evidence views: local answers from the adopted stores, nothing is
  // authenticated yet, nothing revoked without a set.
  HandshakeLocal local{};
  CHECK(coordinator.local(local));
  CHECK(local.self == kNode);
  CHECK(local.network == kNetwork);
  CHECK(local.generation == 3);
  CHECK(local.role == kMemberRoleEndpoint);
  CHECK(local.boot == kBoot);
  CHECK(local.gk_epoch == 203);
  std::uint32_t peer_generation = 0;
  std::uint32_t peer_role = 0;
  CHECK(!coordinator.authenticated(kNode + 1, kNetwork, peer_generation, peer_role));
  CHECK(!coordinator.revoked(kNode + 1, 1));
  CHECK(coordinator.boot_witness_ok(kBoot));
  CHECK(!coordinator.boot_witness_ok(0));
  CHECK(!coordinator.boot_witness_ok(kBoot + 1));

  // The session provider view went ready with the adoption: an unknown
  // peer records demand (AuthRequired) instead of handshaking on RF input.
  CHECK(coordinator.session_provider().ready());
  std::uint32_t epoch = 0;
  CHECK(coordinator.session_provider().tx_epoch(SecurityScope::Link, kNode + 1, epoch).code ==
        StatusCode::AuthRequired);
  CHECK(coordinator.snapshot().demands == 1);
}

void test_rld1_demux_gates() {
  current = "rld1_demux_gates";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));

  const auto rld1_rx = [&](ByteView frame, std::uint32_t generation) {
    CoordinatorEvent event{};
    event.kind = CoordinatorEventKind::Rld1Rx;
    event.now = now;
    event.rld1_meta.source = kPeerMac;
    event.rld1_meta.destination = kMac;
    event.rld1_meta.channel = 6;
    event.rld1_frame = frame;
    event.radio_generation = generation;
    return coordinator.step(event);
  };

  // A stale radio generation never reaches an owner.
  const std::uint8_t garbage[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  const std::uint32_t drops0 = coordinator.counters().demux_drops;
  CHECK(rld1_rx(ByteView{garbage, sizeof(garbage)}, 77).ok());
  CHECK(coordinator.counters().demux_drops == drops0 + 1);

  // Undecodable bytes on the live generation drop too.
  CHECK(rld1_rx(ByteView{garbage, sizeof(garbage)}, 0).ok());
  CHECK(coordinator.counters().demux_drops == drops0 + 2);

  // Auth bodies are unicast-only: a broadcast Auth drops after decode.
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::BootstrapAuth;
  env.network_hint = static_cast<std::uint32_t>(kNetwork);
  env.claimed_node = kNode + 1;
  autonomy::Rld1Encoded encoded{};
  CHECK(autonomy::rld1_encode(env, encoded).ok());
  CoordinatorEvent broadcast{};
  broadcast.kind = CoordinatorEventKind::Rld1Rx;
  broadcast.now = now;
  broadcast.rld1_meta.source = kPeerMac;
  broadcast.rld1_meta.destination = MacAddress{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  broadcast.rld1_meta.channel = 6;
  broadcast.rld1_frame = encoded.view();
  broadcast.radio_generation = 0;
  CHECK(coordinator.step(broadcast).ok());
  CHECK(coordinator.counters().demux_drops == drops0 + 3);

  // Replies never open an exchange.
  autonomy::Rld1Envelope reply_env{};
  reply_env.kind = FrameType::BootstrapReply;
  autonomy::Rld1Encoded reply_encoded{};
  CHECK(autonomy::rld1_encode(reply_env, reply_encoded).ok());
  CHECK(rld1_rx(reply_encoded.view(), 0).ok());
  CHECK(coordinator.counters().demux_drops == drops0 + 4);
  CHECK(f.rld1.sends.empty());
  CHECK(f.mesh.sends.empty());
}

void test_invalid_proxy_auth_does_not_hold_demux() {
  current = "invalid_proxy_auth_does_not_hold_demux";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));
  CHECK(coordinator.quiescent());

  for (std::uint8_t i = 1; i <= 8; ++i) {
    autonomy::Rld1Envelope env{};
    env.kind = FrameType::BootstrapAuth;
    env.network_hint = static_cast<std::uint32_t>(kNetwork);
    env.claimed_node = kNode + i;
    env.transaction_nonce[0] = i;
    env.body[0] = 1;
    env.body[1] = static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage);
    env.body_size = 2;  // valid lane, invalid join object
    autonomy::Rld1Encoded encoded{};
    CHECK(autonomy::rld1_encode(env, encoded).ok());
    CoordinatorEvent rx{};
    rx.kind = CoordinatorEventKind::Rld1Rx;
    rx.now = now;
    rx.radio_generation = 0;
    rx.rld1_meta.source = kPeerMac;
    rx.rld1_meta.destination = kMac;
    rx.rld1_meta.channel = 6;
    rx.rld1_frame = encoded.view();
    CHECK(coordinator.step(rx).ok());
  }
  CHECK(coordinator.quiescent());
}

void test_clock_regression_refused() {
  current = "clock_regression_refused";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));
  const CoordinatorSnapshot before = coordinator.snapshot();
  CHECK(coordinator.step(poll_at(now - 1)).code == StatusCode::TimeUncertain);
  const CoordinatorSnapshot after = coordinator.snapshot();
  CHECK(after.mode == before.mode);
  CHECK(after.link_sessions == before.link_sessions);
  CHECK(after.end_sessions == before.end_sessions);
  CHECK(after.demands == before.demands);
  CHECK(coordinator.step(poll_at(now + 1)).ok());
}

void test_gateway_resume_quotas() {
  current = "gateway_resume_quotas";
  Fixture f{kResume2GatewayLinkQuota + kResume2GatewayEndQuota};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(gateway_site()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));
  const CoordinatorSnapshot view = coordinator.snapshot();
  CHECK(view.resume_link_slots == kResume2GatewayLinkQuota);
  CHECK(view.resume_end_slots == kResume2GatewayEndQuota);
}

void test_staged_bootstrap_rx() {
  current = "staged_bootstrap_rx";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));

  // The Node RX context only stages: nothing is sent from the callback.
  BootstrapMeta meta{};
  meta.origin = kNode + 1;
  const std::uint8_t end_like[2] = {0x01, 0x04};  // end phase peek, bad body
  CHECK(coordinator.on_frame(meta, FrameType::BootstrapAuth, ByteView{end_like, 2}, now).ok());
  CHECK(f.mesh.sends.empty());
  const std::uint8_t short_body[1] = {0x01};
  CHECK(coordinator.on_frame(meta, FrameType::BootstrapAuth, ByteView{short_body, 1}, now).ok());
  CHECK(f.mesh.sends.empty());

  // Poll drains: the short frame counts staged, the bad end body demux.
  const std::uint32_t staged0 = coordinator.counters().staged_drops;
  const std::uint32_t demux0 = coordinator.counters().demux_drops;
  now += 100;
  CHECK(coordinator.step(poll_at(now)).ok());
  CHECK(coordinator.counters().staged_drops == staged0 + 1);
  CHECK(coordinator.counters().demux_drops == demux0 + 1);

  // The staging queue is bounded: the fifth frame in one RX burst drops.
  for (int i = 0; i < 5; ++i) {
    CHECK(coordinator.on_frame(meta, FrameType::BootstrapAuth, ByteView{short_body, 1}, now).ok());
  }
  CHECK(coordinator.counters().staged_drops == staged0 + 2);
}

void test_usb_queue_admission() {
  current = "usb_queue_admission";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(gateway_site()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));

  // Queue admission returns synchronously (the bridge maps it to the
  // 0x63): malformed bodies answer Invalid instead of queueing.
  CoordinatorEvent down{};
  down.kind = CoordinatorEventKind::UsbRelayDown;
  down.now = now;
  down.usb_proxy = kNode + 9;
  const std::uint8_t bad_object[3] = {0x01, 0x02, 0x03};
  down.usb_object = ByteView{bad_object, sizeof(bad_object)};
  const std::uint32_t drops0 = coordinator.counters().usb_drops;
  CHECK(coordinator.step(down).code == StatusCode::ProtocolError);
  CHECK(coordinator.counters().usb_drops == drops0 + 1);

  // Unknown relays answer NotFound: the host then aborts via 0x61.
  CoordinatorEvent abort{};
  abort.kind = CoordinatorEventKind::UsbRelayAbort;
  abort.now = now;
  abort.usb_proxy = kNode + 9;
  abort.usb_relay_id = 0xDEAD;
  abort.usb_reason = static_cast<std::uint8_t>(RelayAbortReason::HostAborted);
  CHECK(coordinator.step(abort).code == StatusCode::NotFound);
  CHECK(coordinator.counters().usb_drops == drops0 + 2);

  // Only HostAborted arrives from the host; anything else is Invalid.
  CoordinatorEvent rogue{};
  rogue.kind = CoordinatorEventKind::UsbRelayAbort;
  rogue.now = now;
  rogue.usb_reason = static_cast<std::uint8_t>(RelayAbortReason::ProxyAborted);
  CHECK(coordinator.step(rogue).code == StatusCode::InvalidArgument);
  CHECK(coordinator.counters().usb_drops == drops0 + 3);
}

void test_usb_refused_without_gateway_role() {
  current = "usb_refused_without_gateway_role";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());  // endpoint role: no gateway
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));

  CoordinatorEvent down{};
  down.kind = CoordinatorEventKind::UsbRelayDown;
  down.now = now;
  down.usb_proxy = kNode + 9;
  const std::uint8_t body[1] = {0x01};
  down.usb_object = ByteView{body, sizeof(body)};
  const std::uint32_t drops0 = coordinator.counters().usb_drops;
  CHECK(coordinator.step(down).code == StatusCode::InvalidState);
  CHECK(coordinator.counters().usb_drops == drops0 + 1);
}

void test_relay_loopback_and_mesh_send() {
  current = "relay_loopback_and_mesh_send";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));

  // A relay addressed to self loops back without touching the radio.
  const std::uint8_t payload[2] = {0x01, 0x02};
  CHECK(coordinator.send_relay(kNode, FrameType::BootstrapAuth, ByteView{payload, 2}).ok());
  CHECK(f.mesh.sends.empty());

  // Anything else rides the routed bootstrap lane.
  CHECK(coordinator.send_relay(kNode + 5, FrameType::BootstrapChunk, ByteView{payload, 2}).ok());
  CHECK(f.mesh.sends.size() == 1);
  CHECK(f.mesh.sends[0].dest == kNode + 5);
  CHECK(f.mesh.sends[0].type == FrameType::BootstrapChunk);
}

void test_late_discovery_attach() {
  current = "late_discovery_attach";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  // Adoption precedes discovery start: boot and adopt with no discovery.
  auto deps = f.deps();
  deps.discovery = nullptr;
  SecurityCoordinator coordinator(deps);
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));
  CHECK(coordinator.snapshot().membership == MembershipState::Unprovisioned);
  // A member poll with no discovery attached drops nothing and parks no
  // phantom state.
  now += 100;
  CHECK(coordinator.step(poll_at(now)).ok());
  // Late attach: once. The controller state then shows through — after
  // the RRS1 floor the adopted site demands is fetched (a nonzero floor
  // with no set behind it is a lost floor, correctly Revoked).
  CHECK(coordinator.attach_discovery(f.discovery).ok());
  CHECK(coordinator.attach_discovery(f.discovery).code == StatusCode::AlreadyExists);
  CHECK(coordinator.snapshot().membership == MembershipState::Unprovisioned);
  CHECK(f.discovery.membership().initialize(coordinator.membership_hooks(), kNetwork).code ==
        StatusCode::RecoveryRequired);
  CHECK(coordinator.snapshot().membership == MembershipState::Revoked);
  const RevocationSet set = revocation_set(14);
  const auto object = revocation_object(set);
  CHECK(f.revocations.accept(object.view(), sak().pub, kSiteId, kNetwork).ok());
  CHECK(f.discovery.membership().initialize(coordinator.membership_hooks(), kNetwork).ok());
  CHECK(coordinator.snapshot().membership == MembershipState::Member);
}

void test_sleep_wake_stop() {
  current = "sleep_wake_stop";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());
  MonotonicMs now = kT0;
  CHECK(poll_until_member(coordinator, now));

  // Quiescent parks; a staged frame vetoes with Busy.
  BootstrapMeta meta{};
  meta.origin = kNode + 1;
  const std::uint8_t body[1] = {0x01};
  CHECK(coordinator.on_frame(meta, FrameType::BootstrapAuth, ByteView{body, 1}, now).ok());
  CoordinatorEvent sleep{};
  sleep.kind = CoordinatorEventKind::PrepareSleep;
  sleep.now = now;
  CHECK(coordinator.step(sleep).code == StatusCode::Busy);
  CHECK(!coordinator.snapshot().sleeping);
  now += 100;
  CHECK(coordinator.step(poll_at(now)).ok());  // drains the staged frame
  CoordinatorAction drained{};
  while (coordinator.take_action(drained).ok()) {
  }
  sleep.now = now;
  CHECK(coordinator.step(sleep).ok());
  CHECK(coordinator.snapshot().sleeping);
  CHECK(coordinator.counters().sleep_parks == 1);

  // Sleeping naps through Poll and RLD1.
  now += 1000;
  CHECK(coordinator.step(poll_at(now)).ok());
  CoordinatorEvent rx{};
  rx.kind = CoordinatorEventKind::Rld1Rx;
  rx.now = now;
  CHECK(coordinator.step(rx).ok());
  CHECK(coordinator.snapshot().sleeping);

  CoordinatorEvent wake{};
  wake.kind = CoordinatorEventKind::Wake;
  wake.now = now;
  CHECK(coordinator.step(wake).ok());
  CHECK(!coordinator.snapshot().sleeping);

  // Stop wipes the workspace back to Fresh; the evidence views close.
  CoordinatorEvent stop{};
  stop.kind = CoordinatorEventKind::Stop;
  stop.now = now;
  CHECK(coordinator.step(stop).ok());
  CHECK(coordinator.snapshot().mode == CoordinatorMode::Fresh);
  CHECK(coordinator.quiescent());
  HandshakeLocal local{};
  CHECK(!coordinator.local(local));
  std::uint32_t generation = 0;
  CHECK(!coordinator.gk_scope().current_generation(ScopeRef{}, generation));

  // And a second boot adopts again (the bank re-configure path).
  now += 100;
  CHECK(coordinator.step(boot_event(now, kBoot)).ok());
  CHECK(poll_until_member(coordinator, now));
  CHECK(coordinator.local(local));
}

void test_commit_veto() {
  current = "commit_veto";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  SecurityCoordinator coordinator(f.deps());

  // No record: every commit passes.
  SiteRecord candidate = site_record();
  CHECK(coordinator.check(candidate, kT0));

  // A Blocked record vetoes the same site, even past its generation: the
  // cleanup (tombstones + Cleaned + holdoff) has to finish first.
  LocalRevocationRecord blocked{};
  blocked.state = LocalRevocationState::Blocked;
  blocked.cause = LocalRevocationCause::Notice;
  blocked.local_node = kNode;
  blocked.site_id = kSiteId;
  blocked.network = kNetwork;
  blocked.removed_generation = 3;
  blocked.evidence_digest.fill(0xE1);
  CHECK(f.local_revocation.commit_blocked(blocked).ok());
  CHECK(!coordinator.check(candidate, kT0));
  candidate.assignment_generation = 4;
  CHECK(!coordinator.check(candidate, kT0));
}

void test_store_credential_verifier() {
  current = "store_credential_verifier";
  Fixture f{};
  CHECK(f.init_stores());
  StoreCredentialVerifier bare(f.identity, f.site);
  LocalCredential cred{};
  CHECK(!bare.local_credential(cred));  // nothing adopted: closed
  PeerCertClaims claims{};
  CHECK(!bare.verify_peer(ByteView{nullptr, 0}, kNode, claims));

  CHECK(f.identity.commit(identity_record()).ok());
  CHECK(f.site.commit(site_record()).ok());
  StoreCredentialVerifier verifier(f.identity, f.site);
  CHECK(verifier.local_credential(cred));
  CHECK(cred.cred_size == f.site.site().member_cert.size);
  CHECK(cred.privkey == device_key().priv);

  // The adopted MemberCert verifies for its own subject with its claims.
  CHECK(verifier.verify_peer(f.site.site().member_cert.view(), kNode, claims));
  CHECK(claims.node == kNode);
  CHECK(claims.generation == 3);
  CHECK(claims.role == kMemberRoleEndpoint);

  // Another node, another network, and a cert the SAK did not sign all
  // refuse — reported unverified, never an error.
  CHECK(!verifier.verify_peer(f.site.site().member_cert.view(), kNode + 1, claims));
  CertClaims foreign = membercert_claims(3, kNetwork, kNode + 7);
  ByteBuffer<kRlcw1CertMax> forged = issue(foreign, device_ca());
  CHECK(!verifier.verify_peer(forged.view(), kNode + 7, claims));
  const std::uint8_t garbage[4] = {1, 2, 3, 4};
  CHECK(!verifier.verify_peer(ByteView{garbage, sizeof(garbage)}, kNode, claims));
}

void test_channel_ready_flow() {
  current = "channel_ready_flow";
  Fixture f{};
  CHECK(f.init_stores());
  CHECK(f.identity.commit(identity_record()).ok());  // no site: radio scan
  SecurityCoordinator coordinator(f.deps());
  CHECK(coordinator.step(boot_event(kT0, kBoot)).ok());

  // The joiner asks for its first scan channel through TuneChannel.
  MonotonicMs now = kT0;
  CoordinatorAction tune{};
  bool have_tune = false;
  for (int i = 0; i < 20 && !have_tune; ++i) {
    now += 100;
    CHECK(coordinator.step(poll_at(now)).ok());
    CoordinatorAction action{};
    while (coordinator.take_action(action).ok()) {
      if (action.kind == CoordinatorActionKind::TuneChannel) {
        tune = action;
        have_tune = true;
      }
    }
  }
  CHECK(have_tune);
  CHECK(tune.tune.token != 0);
  CHECK(coordinator.snapshot().joiner == JoinState::WaitChannel);

  // A stale token never completes the tune.
  CoordinatorEvent stale{};
  stale.kind = CoordinatorEventKind::ChannelReady;
  stale.now = now;
  stale.channel_token = tune.tune.token + 1;
  stale.channel = tune.tune.channel;
  stale.channel_generation = 9;
  CHECK(coordinator.step(stale).ok());
  CHECK(coordinator.snapshot().joiner == JoinState::WaitChannel);

  // The matching completion advances the scan.
  CoordinatorEvent ready{};
  ready.kind = CoordinatorEventKind::ChannelReady;
  ready.now = now;
  ready.channel_token = tune.tune.token;
  ready.channel_result = StatusCode::Ok;
  ready.channel = tune.tune.channel;
  ready.channel_generation = 9;
  CHECK(coordinator.step(ready).ok());
  now += 100;
  CHECK(coordinator.step(poll_at(now)).ok());
  CHECK(coordinator.snapshot().joiner != JoinState::WaitChannel);
}

}  // namespace

int main() {
  test_boot_silent_adoption();
  test_rld1_demux_gates();
  test_invalid_proxy_auth_does_not_hold_demux();
  test_clock_regression_refused();
  test_gateway_resume_quotas();
  test_staged_bootstrap_rx();
  test_usb_queue_admission();
  test_usb_refused_without_gateway_role();
  test_relay_loopback_and_mesh_send();
  test_late_discovery_attach();
  test_sleep_wake_stop();
  test_commit_veto();
  test_store_credential_verifier();
  test_channel_ready_flow();
  if (failures != 0) {
    std::fprintf(stderr, "FAILURES: %d\n", failures);
    return 1;
  }
  std::printf("coordinator tests passed\n");
  return 0;
}
