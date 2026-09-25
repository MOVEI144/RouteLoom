// Two-node owner/discovery/handshake simulator (host integration harness
// for the P4 sleep + DevRam remainder): two real SecurityCoordinators with
// real NeighborDiscovery engines, looped RLD1 + wire + mesh transports,
// and firmware-shaped action draining (apply-ChannelReady synthesis and
// the owner-mirrored discovery start). Radio timing and NVS wear are NOT
// simulated — the harness proves the security route (adoption, link,
// sessions, bindings, group, sleep save/restore), never RF behavior.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/sdkv1_handshake.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

#include "test_sdkv1.hpp"

namespace owner_sim {

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;

constexpr MonotonicMs kSimT0 = 100000;
constexpr std::uint8_t kSimChannel = 6;

// Deterministic entropy (distinct stream per node seed).
class SimEntropy final : public EntropySource {
 public:
  explicit SimEntropy(const std::uint64_t seed) noexcept : state_(seed) {}
  Status fill(const MutableByteView out) noexcept override {
    if (out.data == nullptr) return Status::error(StatusCode::InvalidArgument, "null");
    for (std::size_t i = 0; i < out.size; ++i) {
      state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
      out.data[i] = static_cast<std::uint8_t>(state_ >> 33U);
    }
    return Status::success();
  }

 private:
  std::uint64_t state_{0};
};

// Keyed test cipher (NOT an AEAD): XOR stream plus a tag over key, nonce,
// AAD and body. Cross-key confusion fails the tag; the bank suite proves
// the same logic against real AES-GCM.
struct SimAead {
  static bool xform(const std::uint8_t key[16], const std::uint8_t nonce[12],
                    const ByteView aad, const ByteView input, std::uint8_t* out,
                    std::uint8_t tag[16], const bool sealing) noexcept {
    std::uint64_t state = 0x51AA6145616400ULL;
    auto mix = [&state](std::uint64_t v) {
      state ^= v + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
      state *= 0xbf58476d1ce4e5b9ULL;
    };
    for (int i = 0; i < 16; ++i) mix(key[i]);
    for (int i = 0; i < 12; ++i) mix(nonce[i]);
    for (std::size_t i = 0; i < aad.size; ++i) mix(aad.data[i]);
    const std::uint64_t stream = state;
    for (std::size_t i = 0; i < input.size; ++i) {
      std::uint64_t s = stream ^ (i + 1);
      s ^= s + 0x9e3779b97f4a7c15ULL;
      out[i] = input.data[i] ^ static_cast<std::uint8_t>(s >> 56U);
    }
    const ByteView tagged = sealing ? ByteView{out, input.size} : input;
    std::uint64_t left = stream, right = stream ^ 0x746167ULL;
    for (std::size_t i = 0; i < aad.size; ++i) {
      left ^= aad.data[i];
      left *= 0xbf58476d1ce4e5b9ULL;
    }
    for (std::size_t i = 0; i < tagged.size; ++i) {
      right ^= tagged.data[i];
      right *= 0xbf58476d1ce4e5b9ULL;
    }
    std::uint8_t expect[16];
    for (int i = 0; i < 8; ++i) {
      expect[i] = static_cast<std::uint8_t>(left >> (56 - i * 8));
      expect[8 + i] = static_cast<std::uint8_t>(right >> (56 - i * 8));
    }
    if (sealing) {
      std::memcpy(tag, expect, 16);
      return true;
    }
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<std::uint8_t>(expect[i] ^ tag[i]);
    return diff == 0;
  }
  static bool seal(void*, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out,
                   std::uint8_t tag[16]) noexcept {
    return xform(key, nonce, aad, plaintext, out, tag, true);
  }
  static bool open(void*, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out) noexcept {
    std::uint8_t copy[16];
    std::memcpy(copy, tag, 16);
    return xform(key, nonce, aad, ciphertext, out, copy, false);
  }
};

struct Rld1Frame {
  MacAddress dest{};
  std::vector<std::uint8_t> bytes{};
};

struct WireFrame {
  MacAddress dest{};
  FrameType type{FrameType::Data};
  std::vector<std::uint8_t> bytes{};
};

struct MeshFrame {
  NodeId dest{kInvalidNodeId};
  FrameType type{FrameType::Data};
  std::vector<std::uint8_t> bytes{};
};

class SimRld1Port final : public ZtRld1Port {
 public:
  Status send_rld1(const MacAddress& destination, const ByteView frame) noexcept override {
    out.push_back({destination, std::vector<std::uint8_t>(frame.data, frame.data + frame.size)});
    return Status::success();
  }
  std::vector<Rld1Frame> out{};
};

class SimMeshPort final : public CoordinatorMeshPort {
 public:
  Status send_bootstrap(const NodeId destination, const FrameType type, const ByteView payload,
                        const std::uint32_t lifetime_ms, const MonotonicMs now_ms,
                        MessageId& id) noexcept override {
    (void)lifetime_ms;
    (void)now_ms;
    out.push_back({destination, type,
                   std::vector<std::uint8_t>(payload.data, payload.data + payload.size)});
    id = MessageId{1, static_cast<std::uint32_t>(out.size())};
    return Status::success();
  }
  std::vector<MeshFrame> out{};
};

class SimUsbPort final : public CoordinatorUsbPort {
 public:
  Status send_local_join_up(JoinAuthPhase, std::uint8_t, ByteView) noexcept override {
    return Status::error(StatusCode::Unsupported, "sim has no usb host");
  }
  Status send_relay_up_to_host(NodeId, std::uint8_t, ByteView) noexcept override {
    return Status::error(StatusCode::Unsupported, "sim has no usb host");
  }
  Status send_relay_abort_to_host(NodeId, RelayToken, RelayAbortReason) noexcept override {
    return Status::success();
  }
};

class SimSealer final : public JoinCookieSealer {
 public:
  Status seal(const JoinCookieMaterial&, JoinCookieBytes& out) noexcept override {
    out.fill(0x5A);
    return Status::success();
  }
};

class SimDiscoveryPort final : public DiscoveryPort {
 public:
  Status send_rld1(const MacAddress& dest, const ByteView encoded) noexcept override {
    rld1.push_back({dest, std::vector<std::uint8_t>(encoded.data, encoded.data + encoded.size)});
    return Status::success();
  }
  Status send_wire(BindingId, const MacAddress& dest, const FrameType type,
                   const ByteView payload) noexcept override {
    wire.push_back({dest, type,
                    std::vector<std::uint8_t>(payload.data, payload.data + payload.size)});
    return Status::success();
  }
  std::vector<Rld1Frame> rld1{};
  std::vector<WireFrame> wire{};
};

class SimObserver final : public DiscoveryObserver {
 public:
  void on_discovery_event(const char* reason, NodeId peer) noexcept override {
    (void)peer;
    if (events.size() < 64) events.emplace_back(reason != nullptr ? reason : "?");
  }
  bool has(const char* reason) const {
    for (const auto& event : events) {
      if (event == reason) return true;
    }
    return false;
  }
  std::vector<std::string> events{};
};

// Owner-mirrored discovery authenticator: OFFER cookies through the live
// member cookie box; attest/verify/issue_proof stay Unsupported (the
// handshake path mints engine proofs instead).
class SimCookieAuth final : public NeighborAuthenticator {
 public:
  SimCookieAuth() noexcept = default;
  void attach(const SecurityCoordinator* coordinator) noexcept { coordinator_ = coordinator; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  bool binds_scope() const noexcept override { return true; }
  Status cookie_seal(const CookieMaterial& material, AuthTag& out) noexcept override {
    const MemberCookie* cookie =
        coordinator_ != nullptr ? coordinator_->member_cookie() : nullptr;
    if (cookie == nullptr) return Status::error(StatusCode::InvalidState, "cookie not live");
    return cookie->seal(material.requester_mac, material.requester_nonce, material.network,
                        material.time_bucket * MemberCookie::kBucketMs, out);
  }
  Status cookie_verify(const CookieMaterial& material, const AuthTag& tag) noexcept override {
    const MemberCookie* cookie =
        coordinator_ != nullptr ? coordinator_->member_cookie() : nullptr;
    if (cookie == nullptr) return Status::error(StatusCode::InvalidState, "cookie not live");
    return cookie->verify(material.requester_mac, material.requester_nonce, material.network,
                          ByteView{tag.data(), tag.size()},
                          material.time_bucket * MemberCookie::kBucketMs);
  }
  Status attest(autonomy::AuthPhase, const AuthTranscript&, AuthTag&) noexcept override {
    return Status::error(StatusCode::Unsupported, "sim has no legacy auth");
  }
  Status verify(autonomy::AuthPhase, const AuthTranscript&, const AuthTag&) noexcept override {
    return Status::error(StatusCode::Unsupported, "sim has no legacy auth");
  }
  Status issue_proof(const AuthTranscript&, NodeId, const AuthTag&,
                     AuthenticatedPeerProof&) noexcept override {
    return Status::error(StatusCode::Unsupported, "sim has no legacy auth");
  }

 private:
  const SecurityCoordinator* coordinator_{nullptr};
};

// One simulated node: real stores, a real coordinator and (after the
// StartMemberDiscovery action) a real discovery engine. The RLD1/mesh
// transports are looped by SimLink; the pump order mirrors the firmware
// (§8.4): inbound RX, coordinator poll, discovery poll, action drain.
class SimNode {
 public:
  SimNode(const NodeId node, const MacAddress& mac, const std::uint64_t entropy_seed,
          const std::size_t resume_slots)
      : node_(node),
        mac_(mac),
        resume_storage_(resume_slots),
        identity_(identity_storage_),
        site_(site_storage_),
        revocations_(revocation_storage_),
        local_revocation_(local_revocation_storage_),
        entropy_(entropy_seed),
        verifier_(identity_, site_) {
    deps_.identity = &identity_;
    deps_.site = &site_;
    deps_.revocations = &revocations_;
    deps_.local_revocation = &local_revocation_;
    deps_.resume_storage = &resume_storage_;
    deps_.discovery = nullptr;  // attaches at StartMemberDiscovery, like firmware
    deps_.entropy = &entropy_;
    deps_.rld1 = &rld1_;
    deps_.mesh = &mesh_;
    deps_.usb = &usb_;
    deps_.verifier = &verifier_;
    deps_.bank_aead = sdkv1::AeadGcm{&SimAead::seal, &SimAead::open, nullptr};
    deps_.crypto_aead = *routeloom::builtin_aead_gcm();
    deps_.proxy_sealer = &sealer_;
    deps_.local_mac = mac_;
    deps_.local_node = node_;
    deps_.joiner_config.node = node_;
    deps_.joiner_config.mac = mac_;
    deps_.joiner_config.capability =
        kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1 | kRld1CapDevRamSessionV1;
    deps_.joiner_config.requested_role = static_cast<std::uint8_t>(kMemberRoleEndpoint);
    coordinator_ = new (coordinator_box_.data()) SecurityCoordinator(deps_);
    auth_.attach(coordinator_);
  }

  SimNode(const SimNode&) = delete;
  SimNode& operator=(const SimNode&) = delete;

  ~SimNode() {
    if (discovery_live_) {
      discovery()->~NeighborDiscovery();
      discovery_live_ = false;
    }
    if (coordinator_ != nullptr) {
      coordinator_->~SecurityCoordinator();
      coordinator_ = nullptr;
    }
  }

  NodeId node() const noexcept { return node_; }
  const MacAddress& mac() const noexcept { return mac_; }
  SecurityCoordinator& coordinator() noexcept { return *coordinator_; }
  NeighborDiscovery* discovery() noexcept {
    return discovery_live_ ? reinterpret_cast<NeighborDiscovery*>(discovery_box_.data())
                           : nullptr;
  }

  IdentityStore& identity() noexcept { return identity_; }
  SiteStore& site() noexcept { return site_; }

  bool init_stores() {
    return identity_.initialize().ok() && site_.initialize().ok() &&
           revocations_.initialize().ok() && local_revocation_.initialize().ok();
  }

  // Member boot through the Joiner (silent adoption from the committed
  // RLS1/RLI1, like firmware with a provisioned site).
  bool boot_member(const MonotonicMs now, const std::uint32_t witness) {
    CoordinatorEvent event{};
    event.kind = CoordinatorEventKind::Boot;
    event.now = now;
    event.boot_witness = witness;
    event.boot_prepared = true;
    if (!coordinator_->step(event).ok()) return false;
    operating_channel_ = kSimChannel;
    return true;
  }

  // One pump turn: coordinator poll, discovery poll, firmware-shaped
  // action drain. Inbound queues must already hold this tick's RX.
  void poll(const MonotonicMs now) {
    CoordinatorEvent event{};
    event.kind = CoordinatorEventKind::Poll;
    event.now = now;
    (void)coordinator_->step(event);
    if (discovery_live_) discovery()->poll(now);
    drain_actions(now);
  }

  void drain_actions(const MonotonicMs now) {
    for (;;) {
      CoordinatorAction action{};
      if (!coordinator_->take_action(action).ok()) return;
      switch (action.kind) {
        case CoordinatorActionKind::TuneChannel: {
          // The sim radio tunes instantly; the generation never moves.
          CoordinatorEvent ready{};
          ready.kind = CoordinatorEventKind::ChannelReady;
          ready.now = now;
          ready.channel_token = action.tune.token;
          ready.channel_result = StatusCode::Ok;
          ready.channel = action.tune.channel;
          ready.channel_generation = 0;
          (void)coordinator_->step(ready);
          break;
        }
        case CoordinatorActionKind::ApplyMemberConfig:
          // The sim has no MeshNode to rebuild: record the adoption and
          // report the apply-time tune as complete on the adopted
          // operating channel (token 0, like the owner apply leg).
          adopted_ = action.member;
          adopted_valid_ = true;
          operating_channel_ = site_.has_site() ? site_.site().channel : kSimChannel;
          {
            CoordinatorEvent ready{};
            ready.kind = CoordinatorEventKind::ChannelReady;
            ready.now = now;
            ready.channel_token = 0;
            ready.channel_result = StatusCode::Ok;
            ready.channel = operating_channel_;
            ready.channel_generation = 0;
            (void)coordinator_->step(ready);
          }
          break;
        case CoordinatorActionKind::StartMemberDiscovery:
          start_discovery(now);
          break;
        case CoordinatorActionKind::ReportRemoval:
        case CoordinatorActionKind::ReportRecovery:
        case CoordinatorActionKind::None:
          break;
      }
    }
  }

  // Owner-mirrored member discovery start (member profile): adopted GK
  // scope, store-backed hooks, owner-style cookie authenticator.
  void start_discovery(const MonotonicMs now) {
    if (discovery_live_) return;
    DiscoveryConfig config{};
    if (!coordinator_->member_discovery_config(config).ok()) return;
    auto* engine = new (discovery_box_.data()) NeighborDiscovery(
        config, discovery_port_, auth_, coordinator_->membership_hooks(), entropy_, observer_);
    discovery_live_ = true;
    if (!engine->start(now).ok()) {
      engine->~NeighborDiscovery();
      discovery_live_ = false;
      return;
    }
    if (!coordinator_->attach_discovery(*engine).ok()) {
      engine->~NeighborDiscovery();
      discovery_live_ = false;
      return;
    }
    engine->set_member_handshake_mode(true);
    if (!engine->begin_discovery(now).ok()) {
      engine->~NeighborDiscovery();
      discovery_live_ = false;
      return;
    }
  }

  // A bank establishment demand through the public provider path (what
  // the wire layer's epoch stamp does when no session stands).
  bool demand_link(const NodeId peer) {
    std::uint32_t epoch = 1;
    return coordinator_->session_provider().tx_epoch(SecurityScope::Link, peer, epoch).code ==
           StatusCode::AuthRequired;
  }

  bool link_session_to(const NodeId peer) {
    std::uint32_t epoch = 1;
    return coordinator_->session_provider().tx_epoch(SecurityScope::Link, peer, epoch).ok();
  }

  const CoordinatorMemberConfig& adopted() const noexcept { return adopted_; }
  bool adopted_valid() const noexcept { return adopted_valid_; }
  std::uint8_t operating_channel() const noexcept { return operating_channel_; }

  SimRld1Port rld1_{};
  SimMeshPort mesh_{};
  SimDiscoveryPort discovery_port_{};
  std::vector<Rld1Frame> inbound_rld1_{};
  std::vector<WireFrame> inbound_wire_{};
  std::vector<MeshFrame> inbound_mesh_{};

 private:
  NodeId node_{kInvalidNodeId};
  MacAddress mac_{};
  FaultyRecordStorage identity_storage_{kIdentitySlotBytes};
  FaultyRecordStorage site_storage_{kSiteSlotBytes};
  FaultyRecordStorage revocation_storage_{kRevocationSlotBytes};
  FaultyRecordStorage local_revocation_storage_{kLocalRevocationSlotBytes};
  FaultyResumeStorage2 resume_storage_;
  IdentityStore identity_;
  SiteStore site_;
  RevocationStore revocations_;
  LocalRevocationStore local_revocation_;
  SimEntropy entropy_;
  SimUsbPort usb_{};
  StoreCredentialVerifier verifier_;
  SimSealer sealer_;
  SecurityCoordinator::Deps deps_{};
  alignas(SecurityCoordinator) std::array<std::uint8_t, sizeof(SecurityCoordinator)>
      coordinator_box_{};
  SecurityCoordinator* coordinator_{nullptr};
  SimCookieAuth auth_;
  SimObserver observer_{};
  alignas(NeighborDiscovery) std::array<std::uint8_t, sizeof(NeighborDiscovery)>
      discovery_box_{};
  bool discovery_live_{false};
  CoordinatorMemberConfig adopted_{};
  bool adopted_valid_{false};
  std::uint8_t operating_channel_{0};
};

// Loops two nodes: moves outbound RLD1/wire/mesh into the peer's inbound
// queues and delivers them through the same entries firmware uses.
class SimLink {
 public:
  SimLink(SimNode& a, SimNode& b) noexcept : a_(a), b_(b) {}

  void move_transports() {
    move_rld1(a_, b_);
    move_rld1(b_, a_);
    move_wire(a_, b_);
    move_wire(b_, a_);
    move_mesh(a_, b_);
    move_mesh(b_, a_);
  }

  void deliver(const MonotonicMs now) {
    deliver_rld1(a_, b_, now);
    deliver_rld1(b_, a_, now);
    deliver_wire(a_, b_, now);
    deliver_wire(b_, a_, now);
    deliver_mesh(a_, b_, now);
    deliver_mesh(b_, a_, now);
  }

  void pump_tick(const MonotonicMs now) {
    move_transports();
    deliver(now);
    a_.poll(now);
    b_.poll(now);
  }

 private:
  static void move_rld1(SimNode& from, SimNode& to) {
    for (auto& frame : from.rld1_.out) to.inbound_rld1_.push_back(std::move(frame));
    from.rld1_.out.clear();
    for (auto& frame : from.discovery_port_.rld1) to.inbound_rld1_.push_back(std::move(frame));
    from.discovery_port_.rld1.clear();
  }
  static void move_wire(SimNode& from, SimNode& to) {
    for (auto& frame : from.discovery_port_.wire) to.inbound_wire_.push_back(std::move(frame));
    from.discovery_port_.wire.clear();
  }
  static void move_mesh(SimNode& from, SimNode& to) {
    for (auto& frame : from.mesh_.out) to.inbound_mesh_.push_back(std::move(frame));
    from.mesh_.out.clear();
  }
  // Every RLD1 frame enters through the coordinator (which fans member
  // Discover/Offer back into discovery), exactly like the runtime's
  // bootstrap sink. The loop has exactly two nodes, so the frame source
  // is always the peer.
  static void deliver_rld1(SimNode& node, const SimNode& peer, const MonotonicMs now) {
    for (auto& frame : node.inbound_rld1_) {
      CoordinatorEvent event{};
      event.kind = CoordinatorEventKind::Rld1Rx;
      event.now = now;
      event.rld1_meta.source = peer.mac();
      event.rld1_meta.destination = frame.dest;
      event.rld1_meta.channel = node.operating_channel();
      event.rld1_frame = ByteView{frame.bytes.data(), frame.bytes.size()};
      event.radio_generation = 0;
      (void)node.coordinator().step(event);
    }
    node.inbound_rld1_.clear();
  }
  static void deliver_wire(SimNode& node, const SimNode& peer, const MonotonicMs now) {
    NeighborDiscovery* discovery = node.discovery();
    if (discovery == nullptr) {
      node.inbound_wire_.clear();
      return;
    }
    for (auto& frame : node.inbound_wire_) {
      discovery->on_wire_rx(peer.mac(), frame.type,
                            ByteView{frame.bytes.data(), frame.bytes.size()}, now);
    }
    node.inbound_wire_.clear();
  }
  static void deliver_mesh(SimNode& node, const SimNode& peer, const MonotonicMs now) {
    for (auto& frame : node.inbound_mesh_) {
      BootstrapMeta meta{};
      meta.origin = peer.node();
      meta.destination = frame.dest;
      meta.id = MessageId{1, 1};
      meta.previous_hop = peer.node();
      meta.hop_remaining = 5;
      meta.remaining_deadline_ms = 5000;
      (void)node.coordinator().on_frame(meta, frame.type,
                                        ByteView{frame.bytes.data(), frame.bytes.size()},
                                        now);
    }
    node.inbound_mesh_.clear();
  }

  SimNode& a_;
  SimNode& b_;
};

}  // namespace owner_sim
