// P6 revocation lifecycle, PR A (04-removal-revocation.md §2-§5; V1-R01
// device parts, V1-R02/R03/R04/R09 device sims, V1-R10 codec part):
//  - StateEpochs/RrsRequest/authority-type-5 codecs (valid + invalid);
//  - Boot adoption (healthy/stored-ahead/missing-RRS/foreign-RRS/self);
//  - the RRS1 -> enforcement -> RLS1-floor apply order across Polls, with
//    the resume sweep killing only revoked-generation slots;
//  - duplicate/equivocation/stale handling; self-revocation + recovery;
//  - link-failure recovery, permits() matrix, re-entry Busy;
//  - the 1+1 kind-6 exchange (timeouts, retries, re-ACK, demux);
//  - gossip over a 3-node line, a 100-node line, and a partition/merge sim;
//  - storage faults mid-apply; RAM budget gates.
// Production P4/P5 adapters are not in main yet, so every port is fake; the
// fakes record enough to prove ordering (RRS commit -> enforce -> floor).

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/node.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_lifecycle_store.hpp"
#include "routeloom/sdkv1_grant_renew.hpp"
#include "routeloom/sdkv1_revocation.hpp"
#include "routeloom/telemetry.hpp"
#include "routeloom/wire.hpp"

#include "test_sdkv1.hpp"
#include "test_sim.hpp"

#ifndef ROUTELOOM_SDKV1_GOLDEN_DIR
#define ROUTELOOM_SDKV1_GOLDEN_DIR "protocol/sdkv1-golden"
#endif

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace sdkv1_test;

// --- Fake ports ----------------------------------------------------------------------

struct FakeAuthorityPort final : public LifecycleAuthorityPort {
  struct Sent {
    std::uint8_t type{0};
    std::vector<std::uint8_t> body;
  };
  std::vector<Sent> sent;
  bool refuse{false};  // WouldBlock everything (port backpressure)
  Status authority_send(const std::uint8_t type, const ByteView body) noexcept override {
    if (refuse || body.data == nullptr) {
      return Status::error(StatusCode::WouldBlock, "authority port busy");
    }
    Sent s{};
    s.type = type;
    s.body.assign(body.data, body.data + body.size);
    sent.push_back(s);
    return Status::success();
  }
};

struct FakePeerPort final : public LifecyclePeerPort {
  struct Sent {
    NodeId peer{kInvalidNodeId};
    FrameType carrier{FrameType::Data};
    std::vector<std::uint8_t> body;
  };
  std::vector<Sent> sent;
  bool refuse{false};
  Status peer_send(const NodeId peer, const FrameType carrier,
                   const ByteView body) noexcept override {
    if (refuse || body.data == nullptr) {
      return Status::error(StatusCode::WouldBlock, "peer port busy");
    }
    Sent s{};
    s.peer = peer;
    s.carrier = carrier;
    s.body.assign(body.data, body.data + body.size);
    sent.push_back(s);
    return Status::success();
  }
};

struct FakeRuntimePort final : public LifecycleRuntimePort {
  struct Enforced {
    RevocationSet set{};
    std::uint32_t site_epoch{0};
    std::uint32_t rrs_epoch_at_call{0};  // store view proving the call order
    std::uint32_t rls_floor_at_call{0};
  };
  std::vector<Enforced> calls;
  bool refuse{false};
  bool enforce_storage_failure{false};
  unsigned retire_wait{0};
  bool trust_erased{false};
  bool runtime_erased{false};
  bool network_retired{false};
  bool trust_installed{false};
  Status retire_network() noexcept override {
    if (retire_wait != 0) {
      --retire_wait;
      return Status::error(StatusCode::WouldBlock, "p4 resume clear pending");
    }
    if (refuse) return Status::error(StatusCode::StorageFailure, "network retirement failed");
    network_retired = true;
    return Status::success();
  }
  Status install_site_trust(const SiteRecord& next) noexcept override {
    if (!network_retired || next.network == kNetwork || refuse)
      return Status::error(StatusCode::StorageFailure, "new site trust not ready");
    trust_installed = true;
    return Status::success();
  }
  Status remove_member_runtime() noexcept override {
    if (refuse) return Status::error(StatusCode::StorageFailure, "runtime removal failed");
    runtime_erased = true;
    return Status::success();
  }
  Status erase_site_trust() noexcept override {
    if (refuse) return Status::error(StatusCode::StorageFailure, "site trust removal failed");
    trust_erased = true;
    return Status::success();
  }
  RevocationStore* revocations{nullptr};  // observed stores (order proof)
  SiteStore* site{nullptr};
  Status enforce_revocation(const RevocationSet& set, const std::uint32_t site_epoch,
                            const MonotonicMs now) noexcept override {
    (void)now;
    if (enforce_storage_failure)
      return Status::error(StatusCode::StorageFailure, "p4 resume sweep failed");
    if (refuse) return Status::error(StatusCode::Busy, "runtime busy");
    Enforced e{};
    e.set = set;
    e.site_epoch = site_epoch;
    e.rrs_epoch_at_call = revocations != nullptr ? revocations->rs_epoch() : 0;
    e.rls_floor_at_call =
        (site != nullptr && site->has_site()) ? site->site().rs_epoch_floor : 0;
    calls.push_back(e);
    return Status::success();
  }
};

struct FakeEntropy final : public routeloom::EntropySource {
  std::uint64_t next{0x123456789ABCDEFULL};
  Status fill(const MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) {
      next = next * 0x5851F42D4C957F2DULL + 0x14057B7EF767814FULL;
      out.data[i] = static_cast<std::uint8_t>(next >> 56U);
    }
    return Status::success();
  }
};

struct FakeObserver final : public LifecycleObserver {
  struct Event {
    LifecycleEvent event{};
    MonotonicMs at{0};
  };
  std::vector<Event> events;
  void on_lifecycle_event(const LifecycleEvent& event, const MonotonicMs now_ms) noexcept override {
    events.push_back(Event{event, now_ms});
  }
};

struct FakeObjectSink final : public RrsObjectSink {
  struct Completed {
    NodeId peer{kInvalidNodeId};
    std::vector<std::uint8_t> object;
  };
  std::vector<Completed> completed;
  void on_rrs_object(const NodeId peer, const ByteView object,
                     const MonotonicMs now_ms) noexcept override {
    (void)now_ms;
    Completed c{};
    c.peer = peer;
    if (object.data != nullptr) c.object.assign(object.data, object.data + object.size);
    completed.push_back(c);
  }
};

// --- Fixtures --------------------------------------------------------------------------

constexpr NodeId kNodeB = 0x00A1000000002001ULL;
constexpr NodeId kNodeC = 0x00A1000000003001ULL;

IdentityRecord identity_for(const NodeId node) {
  IdentityRecord r = identity_record();
  r.node_id = node;
  r.devcert = issue(devcert_claims(node), device_ca());
  return r;
}

SiteRecord site_for(const NodeId node, const std::uint32_t generation,
                    const std::uint32_t floor = 14) {
  SiteRecord r = site_record(generation);
  r.rs_epoch_floor = floor;
  r.member_cert = issue(membercert_claims(generation, kNetwork, node), sak());
  return r;
}

PeerCredentialStamp stamp_for(const NodeId peer, const std::uint32_t generation,
                              const std::uint32_t binding = 7) {
  PeerCredentialStamp stamp{};
  stamp.peer = peer;
  stamp.network = kNetwork;
  stamp.assignment_generation = generation;
  stamp.role = 1;
  stamp.binding_incarnation = binding;
  return stamp;
}

// One device: faulty stores, fake ports, the lifecycle. Resume geometry is
// the fixed 16-slot node profile.
struct NodeFixture {
  FaultyRecordStorage identity_storage{kIdentitySlotBytes};
  FaultyRecordStorage site_storage{kSiteSlotBytes};
  FaultyRecordStorage rrs_storage{kRevocationSlotBytes};
  FaultyResumeStorage resume_storage{16};
  FaultyRecordStorage journal_storage{kLifecycleSlotBytes};
  LifecycleStore journal{journal_storage};
  IdentityStore identity{identity_storage};
  SiteStore site{site_storage};
  RevocationStore revocations{rrs_storage};
  ResumeCache resume{resume_storage};
  FakeAuthorityPort authority{};
  FakePeerPort peer{};
  FakeRuntimePort runtime{};
  FakeEntropy entropy{};
  FakeObserver observer{};
  FakeObjectSink sink{};
  LifecyclePorts ports{authority, peer, runtime, entropy, sink, &observer};
  LifecycleConfig config{};
  MembershipLifecycle lifecycle{config, identity, site, revocations, resume, ports,
                                default_es256_verifier(), &journal};

  explicit NodeFixture(const NodeId node = kNode,
                       const std::uint32_t features = kCapRrsGossipV1 |
                                                      kCapMembershipLifecycleV1) {
    config.self = node;
    config.profile = LifecycleProfile::Node;
    config.enabled_features = features;
    // Rebuild the lifecycle with the configured self id (refs stay valid).
    lifecycle.~MembershipLifecycle();
    new (&lifecycle)
        MembershipLifecycle(config, identity, site, revocations, resume, ports,
                            default_es256_verifier(), &journal);
    runtime.revocations = &revocations;
    runtime.site = &site;
  }

  // Provisions identity + site (+ optionally an adopted RRS1) and boots to
  // Active (or SelfRevoked when the set rejects us). Returns false on any
  // unexpected failure.
  bool provision(const std::uint32_t generation, const std::uint32_t rrs_epoch,
                 const std::uint8_t rrs_count = 2, const std::uint32_t floor = 14) {
    if (!journal.initialize()) return false;
    if (!identity.initialize()) return false;
    if (!identity.commit(identity_for(config.self))) return false;
    if (!site.initialize()) return false;
    if (!site.commit(site_for(config.self, generation, floor))) return false;
    if (!revocations.initialize()) return false;
    if (rrs_epoch != 0) {
      const auto object = revocation_object(revocation_set(rrs_epoch, rrs_count, 2));
      if (!revocations.accept(object.view(), sak().pub, kSiteId, kNetwork)) return false;
    }
    if (!dispatch(LifecycleInput::Boot(true), 0)) return false;
    pump(0, 40);
    return true;
  }

  Status dispatch(const LifecycleInput& input, const MonotonicMs now) {
    return lifecycle.dispatch(input, now);
  }

  // Polls until the phase settles out of ApplyingRrs (or `cap` polls).
  void pump(MonotonicMs now, const int cap = 40) {
    for (int i = 0; i < cap; ++i) {
      (void)lifecycle.dispatch(LifecycleInput::Poll(), now);
      if (lifecycle.snapshot().phase != LifecyclePhase::ApplyingRrs) break;
    }
  }

  LifecycleSnapshot snap() { return lifecycle.snapshot(); }
};

[[gnu::noinline]] void rebuild_with_short_lived_ports(NodeFixture& fixture) {
  LifecyclePorts ports{fixture.authority, fixture.peer, fixture.runtime,
                       fixture.entropy, fixture.sink, &fixture.observer};
  fixture.lifecycle.~MembershipLifecycle();
  new (&fixture.lifecycle)
      MembershipLifecycle(fixture.config, fixture.identity, fixture.site,
                          fixture.revocations, fixture.resume, ports,
                          default_es256_verifier(), &fixture.journal);
}

void test_lifecycle_port_bundle_lifetime() {
  NodeFixture fixture;
  rebuild_with_short_lived_ports(fixture);
  CHECK(fixture.provision(3, 15));
  CHECK(fixture.snap().phase == LifecyclePhase::Active);
}

// --- Wire codecs -------------------------------------------------------------------------

void test_rrs_wire_codecs() {
  std::array<std::uint8_t, kStateEpochsSize> epochs_raw{};
  CHECK_OK(state_epochs_encode(StateEpochs{3, 14, 203}, epochs_raw));
  CHECK(epochs_raw[0] == 1 && epochs_raw[1] == 0x61);
  StateEpochs epochs{};
  CHECK_OK(state_epochs_decode(ByteView{epochs_raw.data(), epochs_raw.size()}, epochs));
  CHECK(epochs.site_epoch == 3 && epochs.applied_rs_epoch == 14 && epochs.gk_epoch == 203);
  epochs_raw[1] = 0x62;
  CHECK(!state_epochs_decode(ByteView{epochs_raw.data(), epochs_raw.size()}, epochs));
  epochs_raw[1] = 0x61;
  CHECK(!state_epochs_decode(ByteView{epochs_raw.data(), epochs_raw.size() - 1}, epochs));

  std::array<std::uint8_t, kRrsRequestSize> req_raw{};
  CHECK_OK(rrs_request_encode(RrsRequest{3, 12}, req_raw));
  CHECK(req_raw[0] == 1 && req_raw[1] == 0x62);
  RrsRequest req{};
  CHECK_OK(rrs_request_decode(ByteView{req_raw.data(), req_raw.size()}, req));
  CHECK(req.site_epoch == 3 && req.have_rs_epoch == 12);
  req_raw[0] = 2;
  CHECK(!rrs_request_decode(ByteView{req_raw.data(), req_raw.size()}, req));

  std::array<std::uint8_t, kRrsAppliedSize> applied_raw{};
  RrsApplied applied{31, {}};
  applied.object_sha256.fill(0xA5);
  CHECK_OK(rrs_applied_encode(applied, applied_raw));
  RrsApplied applied_back{};
  CHECK_OK(rrs_applied_decode(ByteView{applied_raw.data(), applied_raw.size()}, applied_back));
  CHECK(applied_back.rs_epoch == 31 && applied_back.object_sha256 == applied.object_sha256);
  applied_raw[2] = 1;  // reserved must be zero
  CHECK(!rrs_applied_decode(ByteView{applied_raw.data(), applied_raw.size()}, applied_back));

  std::array<std::uint8_t, kRrsGetSize> get_raw{};
  CHECK_OK(rrs_get_encode(RrsGet{0}, get_raw));
  RrsGet get_back{99};
  CHECK_OK(rrs_get_decode(ByteView{get_raw.data(), get_raw.size()}, get_back));
  CHECK(get_back.wanted_rs_epoch == 0);
  CHECK(!rrs_get_decode(ByteView{get_raw.data(), get_raw.size() - 1}, get_back));

  std::array<std::uint8_t, kRrsNoticeAcceptedSize> notice_raw{};
  RrsNoticeAccepted notice{7, {}};
  notice.notice_sha256.fill(0x5A);
  CHECK_OK(rrs_notice_accepted_encode(notice, notice_raw));
  CHECK(notice_raw[1] == 3);
  RrsNoticeAccepted notice_back{};
  CHECK_OK(rrs_notice_accepted_decode(ByteView{notice_raw.data(), notice_raw.size()}, notice_back));
  CHECK(notice_back.rs_epoch == 7 && notice_back.notice_sha256 == notice.notice_sha256);
}

// --- Boot adoption -------------------------------------------------------------------------

void test_boot_adoption() {
  // Healthy stores, RRS ahead of the floor: the boot re-runs enforcement
  // and catches the floor up, then opens.
  NodeFixture node;
  CHECK(node.provision(3, 16));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().applied_rs_epoch == 16);
  CHECK(node.site.site().rs_epoch_floor == 16);
  CHECK(node.runtime.calls.size() == 1);
  CHECK(node.runtime.calls[0].rrs_epoch_at_call == 16);
  CHECK(node.runtime.calls[0].rls_floor_at_call == 14);  // enforce ran pre-floor
  CHECK(node.snap().policy_revision >= 1);  // boot adoption bumps once
  // Normal credential admitted, revoked one refused.
  CHECK(node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK(!node.lifecycle.permits(stamp_for(0x00A1000000000100ULL, 1), TrafficUse::Data));
  CHECK(node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::RecoveryControl));

  // No RRS1 at all: BootGate stays closed and asks the authority.
  NodeFixture bare;
  CHECK(bare.identity.initialize());
  CHECK_OK(bare.identity.commit(identity_for(kNode)));
  CHECK(bare.site.initialize());
  CHECK_OK(bare.site.commit(site_for(kNode, 3)));
  CHECK(bare.revocations.initialize());
  CHECK_OK(bare.dispatch(LifecycleInput::Boot(true), 0));
  CHECK(bare.snap().phase == LifecyclePhase::BootGate);
  CHECK(!bare.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  // Recovery-control-only establishment is allowed for the boot fetch.
  CHECK(bare.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::RecoveryControl));
  CHECK_OK(bare.dispatch(LifecycleInput::Poll(), 0));
  CHECK(bare.authority.sent.size() == 1);
  CHECK(bare.authority.sent[0].type == kAuthorityTypeRevocation);
  RrsGet get{99};
  CHECK_OK(rrs_get_decode(
      ByteView{bare.authority.sent[0].body.data(), bare.authority.sent[0].body.size()}, get));
  CHECK(get.wanted_rs_epoch == 0);

  // The authority answers with the bootstrap set (floor 14): adopt + open.
  const auto object = revocation_object(revocation_set(14, 1, 2));
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(bare.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 100));
  CHECK(bare.snap().phase == LifecyclePhase::ApplyingRrs);
  bare.pump(100);
  CHECK(bare.snap().phase == LifecyclePhase::Active);
  CHECK(bare.snap().applied_rs_epoch == 14);
  CHECK(bare.authority.sent.size() >= 2);  // Get + Applied
  bool acked = false;
  for (const auto& sent : bare.authority.sent) {
    RrsApplied back{};
    if (sent.body.size() == kRrsAppliedSize &&
        rrs_applied_decode(ByteView{sent.body.data(), sent.body.size()}, back) &&
        back.rs_epoch == 14) {
      acked = true;
    }
  }
  CHECK(acked);
}

void test_boot_self_revoked_and_blocked() {
  // Our own (node, generation) is in the adopted set: SelfRevoked + action.
  NodeFixture node;
  CHECK(node.identity.initialize());
  CHECK_OK(node.identity.commit(identity_for(kNode)));
  CHECK(node.site.initialize());
  CHECK_OK(node.site.commit(site_for(kNode, 3)));
  CHECK(node.revocations.initialize());
  RevocationSet set = revocation_set(16, 0, 2);
  set.entries[0] = RevocationEntry{kNode, 4, RevocationReason::Removed};
  set.count = 1;
  CHECK_OK(node.revocations.accept(revocation_object(set).view(), sak().pub, kSiteId, kNetwork));
  CHECK_OK(node.dispatch(LifecycleInput::Boot(true), 0));
  node.pump(0);
  CHECK(node.snap().phase == LifecyclePhase::SelfRevoked);
  CHECK(node.snap().action_pending);
  LifecycleAction action{};
  CHECK_OK(node.lifecycle.take_action(action));
  CHECK(action.tag == LifecycleActionTag::RecoveryRequired);
  CHECK(action.token != 0 && action.reason == LifecycleActionReason::SelfRevocation);
  CHECK(action.site_id == kSiteId && action.network == kNetwork);
  // Every use is closed, including recovery control (zero-touch only).
  for (const auto use : {TrafficUse::Data, TrafficUse::LinkHandshake, TrafficUse::Resume,
                         TrafficUse::EndHandshake, TrafficUse::RouteOrigin,
                         TrafficUse::RecoveryControl}) {
    CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), use));
  }
  // A re-issue (generation 4) re-opens through MemberReady.
  SiteRecord reissued = site_for(kNode, 4, 16);
  CHECK_OK(node.site.commit(reissued));
  CHECK_OK(node.dispatch(
      LifecycleInput::MemberReady(node.site.commit_seq(), 0), 1000));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().own_generation == 4);

  // Unreadable boot trace: nothing opens.
  NodeFixture no_trace;
  CHECK_OK(no_trace.dispatch(LifecycleInput::Boot(false), 0));
  CHECK(no_trace.snap().phase == LifecyclePhase::StorageBlocked);
  NodeFixture blocked;
  CHECK(blocked.provision(3, 14));
  CHECK_OK(blocked.dispatch(LifecycleInput::Boot(false), 1));
  CHECK(blocked.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(!blocked.dispatch(LifecycleInput::MemberReady(blocked.site.commit_seq(), 0), 2));
  CHECK(!blocked.dispatch(LifecycleInput::Recovery(true), 3));
  CHECK(blocked.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK_OK(blocked.dispatch(LifecycleInput::Boot(true), 4));
  CHECK(blocked.snap().phase == LifecyclePhase::Active);

  // Wrong resume geometry (gateway profile, node storage): blocked.
  NodeFixture wrong_geo(kNode, kCapRrsGossipV1 | kCapMembershipLifecycleV1);
  wrong_geo.config.profile = LifecycleProfile::Gateway;
  wrong_geo.lifecycle.~MembershipLifecycle();
  new (&wrong_geo.lifecycle) MembershipLifecycle(
      wrong_geo.config, wrong_geo.identity, wrong_geo.site, wrong_geo.revocations,
      wrong_geo.resume, wrong_geo.ports);
  CHECK(wrong_geo.identity.initialize());
  CHECK_OK(wrong_geo.identity.commit(identity_for(kNode)));
  CHECK(wrong_geo.site.initialize());
  CHECK_OK(wrong_geo.site.commit(site_for(kNode, 3)));
  CHECK(wrong_geo.revocations.initialize());
  CHECK_OK(wrong_geo.dispatch(LifecycleInput::Boot(true), 0));
  CHECK(wrong_geo.snap().phase == LifecyclePhase::StorageBlocked);
}

void test_boot_revalidates_stored_rrs() {
  NodeFixture node;
  CHECK_OK(node.identity.initialize());
  CHECK_OK(node.identity.commit(identity_for(kNode)));
  CHECK_OK(node.site.initialize());
  CHECK_OK(node.site.commit(site_for(kNode, 3, 14)));
  CHECK_OK(node.revocations.initialize());
  // The record is structurally valid and at the RLS1 floor, but its signer
  // is not the SAK certified by this membership's SiteCert.
  const auto foreign = revocation_object(revocation_set(14), other_key());
  CHECK_OK(node.revocations.accept(foreign.view(), other_key().pub, kSiteId, kNetwork));
  CHECK_OK(node.dispatch(LifecycleInput::Boot(true), 0));
  CHECK(node.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));

  NodeFixture old_network;
  CHECK_OK(old_network.identity.initialize());
  CHECK_OK(old_network.identity.commit(identity_for(kNode)));
  CHECK_OK(old_network.site.initialize());
  CHECK_OK(old_network.site.commit(site_for(kNode, 3, 14)));
  CHECK_OK(old_network.revocations.initialize());
  const NetworkId previous = (static_cast<NetworkId>(2) << 32U) | kNetworkLow;
  const auto old_object = revocation_object(revocation_set(14, 0, 2, previous));
  CHECK_OK(old_network.revocations.accept(old_object.view(), sak().pub, kSiteId, previous));
  CHECK_OK(old_network.dispatch(LifecycleInput::Boot(true), 0));
  CHECK(old_network.snap().phase == LifecyclePhase::BootGate);
  CHECK(!old_network.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK_OK(old_network.dispatch(LifecycleInput::Poll(), 0));
  CHECK(!old_network.authority.sent.empty());
}

void test_member_ready_closes_on_floor_advance() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  CHECK_OK(node.site.raise_rs_floor(15));
  CHECK_OK(node.dispatch(LifecycleInput::MemberReady(node.site.commit_seq(), 15), 100));
  CHECK(node.snap().phase == LifecyclePhase::BootGate);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
}

void test_member_ready_fetches_package_epoch_past_old_rrs() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  // A join package can name a newer RRS1 than the already adopted set;
  // the old set must not satisfy the fetch target.
  CHECK_OK(node.dispatch(LifecycleInput::MemberReady(node.site.commit_seq(), 16), 100));
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));
  CHECK(!node.authority.sent.empty());
  RrsGet get{};
  if (!node.authority.sent.empty()) {
    CHECK_OK(rrs_get_decode(ByteView{node.authority.sent.back().body.data(),
                                     node.authority.sent.back().body.size()}, get));
    CHECK(get.wanted_rs_epoch == 0);
  }  // authority returns its latest set
  CHECK(node.snap().rs_epoch_to_fetch == 16);
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(node.dispatch(LifecycleInput::Authority(authority, kAuthorityTypeRevocation,
                       revocation_object(revocation_set(15)).view()), 200));
  node.pump(200);
  CHECK(node.snap().applied_rs_epoch == 15);
  // The intermediate set does not complete the package's fetch obligation.
  CHECK(node.snap().rs_epoch_to_fetch == 16);
  // A same-site member re-adoption carries no fresh package hint, but it
  // must retain the still-unmet target from this join.
  CHECK_OK(node.dispatch(LifecycleInput::MemberReady(node.site.commit_seq(), 0), 300));
  CHECK(node.snap().rs_epoch_to_fetch == 16);
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 60100));
  CHECK(node.snap().authority_gets_sent >= 2);
  CHECK_OK(node.dispatch(LifecycleInput::Authority(authority, kAuthorityTypeRevocation,
                       revocation_object(revocation_set(16)).view()), 60200));
  node.pump(60200);
  CHECK(node.snap().applied_rs_epoch == 16);
  CHECK(node.snap().rs_epoch_to_fetch == 0);
}

void test_apply_does_not_ack_below_a_newer_floor() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  const auto object = revocation_object(revocation_set(15));
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 100));
  for (int step = 0; step < 19; ++step) {
    CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));
  }
  CHECK(node.snap().phase == LifecyclePhase::ApplyingRrs);
  CHECK_OK(node.site.raise_rs_floor(16));
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));
  CHECK(node.snap().phase == LifecyclePhase::BootGate);
  CHECK(node.authority.sent.empty());
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
}

void test_recovery_control_rejects_revoked_credentials() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  CHECK(!node.lifecycle.permits(stamp_for(0x00A1000000000100ULL, 1),
                                TrafficUse::RecoveryControl));
  RevocationSet next = revocation_set(15);
  next.entries[2] = RevocationEntry{kNode, 4, RevocationReason::Removed};
  next.count = 3;
  const auto object = revocation_object(next);
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 100));
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));  // verify
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));  // durable set
  CHECK(node.snap().phase == LifecyclePhase::ApplyingRrs);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::RecoveryControl));
}

// --- RRS application order -----------------------------------------------------------------

void test_apply_order_and_sweep() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  // Resume cache: an old-generation slot (revoked by the next set), a
  // new-generation slot (live) and a GK-expired but unrevoked slot.
  ResumeSlot old = resume_slot(kPeer, 0, 10);
  old.peer_generation = 1;
  ResumeSlot fresh = resume_slot(0x00A1000000000888ULL, 0, 11);
  fresh.peer_generation = 5;
  ResumeSlot expired = resume_slot(0x00A1000000000999ULL, 0, 12);
  expired.peer_generation = 5;
  expired.created_gk_epoch = 100;  // 100 + 2 <= 203: unusable, not revoked
  ResumeContext context{kNetwork, 203, nullptr};
  CHECK_OK(node.resume.put(old, context));
  CHECK_OK(node.resume.put(fresh, context));
  CHECK_OK(node.resume.put(expired, context));

  const std::size_t rrs_writes = node.rrs_storage.write_calls;
  const std::size_t rls_writes = node.site_storage.write_calls;
  RevocationSet next = revocation_set(15, 0, 2);
  next.entries[0] = RevocationEntry{0x00A1000000000100ULL, 2, RevocationReason::Removed};
  next.entries[1] = RevocationEntry{0x00A1000000000107ULL, 3, RevocationReason::Removed};
  next.entries[2] = RevocationEntry{kPeer, 2, RevocationReason::Removed};
  next.count = 3;
  const auto object = revocation_object(next);
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 1000));
  CHECK(node.snap().phase == LifecyclePhase::ApplyingRrs);
  // Traffic closes while the barrier is shut.
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK(node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::RecoveryControl));
  // Step through: Verify, Store, Enforce, 16 sweep polls, Floor, Done.
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 1000));  // Verify
  CHECK(node.rrs_storage.write_calls == rrs_writes);      // verify writes nothing
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 1000));  // Store
  CHECK(node.rrs_storage.write_calls == rrs_writes + 2);  // pending seal + commit
  CHECK(node.site_storage.write_calls == rls_writes);  // RRS1 commits first
  CHECK(node.revocations.rs_epoch() == 15);
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 1000));  // Enforce
  CHECK(node.runtime.calls.size() == 1);
  CHECK(node.runtime.calls[0].rrs_epoch_at_call == 15);
  CHECK(node.runtime.calls[0].rls_floor_at_call == 14);  // enforcement pre-floor
  CHECK(node.runtime.calls[0].site_epoch == kSiteEpoch);
  for (int i = 0; i < 16; ++i) {
    CHECK_OK(node.dispatch(LifecycleInput::Poll(), 1000));  // one slot each
  }
  CHECK(node.site_storage.write_calls == rls_writes);  // floor still last
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 1000));  // Floor
  CHECK(node.site_storage.write_calls == rls_writes + 2);
  CHECK(node.site.site().rs_epoch_floor == 15);
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 1000));  // Done
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().applied_rs_epoch == 15);
  CHECK(node.lifecycle.permits(stamp_for(0x00A1000000000888ULL, 5), TrafficUse::Data));
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 1), TrafficUse::Data));
  // Sweep precision: only the revoked-generation slot died.
  ResumeSlot out{};
  std::size_t index = 0;
  ResumeContext guarded{kNetwork, 203, &node.revocations.set()};
  CHECK(node.resume.find(ResumePurpose::Link, kPeer, guarded, out, index).code ==
        StatusCode::NotFound);
  CHECK_OK(node.resume.find(ResumePurpose::Link, 0x00A1000000000888ULL, guarded, out, index));
  CHECK(out.peer_generation == 5);
  // The GK-expired slot is untouched by the sweep (still on disk, unusable
  // by age rather than by revocation).
  FaultyResumeStorage& raw = node.resume_storage;
  bool expired_present = false;
  for (std::size_t i = 0; i < raw.slot_count(); ++i) {
    bool erased = true;
    for (const auto byte : raw.slot(i)) erased = erased && (byte == 0xFF);
    if (erased) continue;  // the cache reads erased slots as empty, not via decode
    ResumeSlot slot{};
    CHECK_OK(resume_slot_decode(ByteView{raw.slot(i).data(), kResumeSlotBytes}, slot));
    if (slot.valid && slot.peer == 0x00A1000000000999ULL) expired_present = true;
  }
  CHECK(expired_present);
}

void test_duplicate_equivocation_stale() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  const std::size_t rrs_writes = node.rrs_storage.write_calls;
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  // Idempotent duplicate: same epoch, same bytes — no write, ACK re-sent.
  const auto same = revocation_object(revocation_set(14));
  CHECK_OK(
      node.dispatch(LifecycleInput::Authority(authority, kAuthorityTypeRevocation, same.view()), 10));
  node.pump(10);
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.rrs_storage.write_calls == rrs_writes);
  CHECK(node.snap().rrs_duplicates == 1);
  bool reacked = false;
  for (const auto& sent : node.authority.sent) {
    RrsApplied back{};
    if (sent.body.size() == kRrsAppliedSize &&
        rrs_applied_decode(ByteView{sent.body.data(), sent.body.size()}, back) &&
        back.rs_epoch == 14) {
      reacked = true;
    }
  }
  CHECK(reacked);
  // Same epoch, different validly-signed bytes: equivocation — the gate
  // closes and the authority is asked to break the tie.
  RevocationSet evil = revocation_set(14);
  evil.entries[0].min_generation = 9;  // still SAK-signed below
  const auto evil_object = revocation_object(evil);
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, evil_object.view()), 20));
  node.pump(20);
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().equivocated);
  CHECK(node.snap().equivocations == 1);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK(node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::RecoveryControl));
  CHECK(node.rrs_storage.write_calls == rrs_writes);  // the gossip copy never lands
  // Older epoch: stale, ignored.
  const auto older = revocation_object(revocation_set(13));
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, older.view()), 30));
  node.pump(30);
  CHECK(node.snap().rrs_stale == 1);
  // Foreign network: the SAK check is bound to our RLS1 network, so the
  // object does not verify here at all.
  RevocationSet foreign = revocation_set(20, 1, 2, kNetwork + 1);
  const auto foreign_object = revocation_object(foreign);
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, foreign_object.view()), 40));
  node.pump(40);
  CHECK(node.snap().rrs_failed == 1);
  // Newer epoch but dropped history: rejected, never adopted.
  RevocationSet dropped = revocation_set(15, 1, 2);
  const auto dropped_object = revocation_object(dropped);
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, dropped_object.view()), 50));
  node.pump(50);
  CHECK(node.snap().applied_rs_epoch == 14);
  CHECK(node.snap().rrs_failed == 2);
}

void test_enforcement_storage_failure_stays_closed() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  const auto object = revocation_object(revocation_set(15));
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 100));
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));  // verify
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 101));  // durable set
  node.runtime.enforce_storage_failure = true;
  for (int i = 0; i < 3; ++i) CHECK_OK(node.dispatch(LifecycleInput::Poll(), 102 + i));
  CHECK(node.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK(node.site.site().rs_epoch_floor == 14);
}

// --- Link failure, recovery, actions ---------------------------------------------------------

void test_link_failure_and_recovery() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  // Two failures, or failures with usable neighbors: stay Active.
  CHECK_OK(node.dispatch(LifecycleInput::LinkFailure(kPeer, 2, 0), 100));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK_OK(node.dispatch(LifecycleInput::LinkFailure(kPeer, 9, 2), 200));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  // Three consecutive failures with nobody usable: Recovering + action.
  CHECK_OK(node.dispatch(LifecycleInput::LinkFailure(kPeer, 3, 0), 300));
  CHECK(node.snap().phase == LifecyclePhase::Recovering);
  CHECK(node.snap().action_pending);
  LifecycleAction action{};
  CHECK_OK(node.lifecycle.take_action(action));
  CHECK(action.tag == LifecycleActionTag::RecoveryRequired);
  CHECK(action.reason == LifecycleActionReason::LinkFailure);
  const std::uint64_t token = action.token;
  // Taking does not consume: the same action comes back until completed.
  LifecycleAction again{};
  CHECK_OK(node.lifecycle.take_action(again));
  CHECK(again.token == token);
  // Unknown token: NotFound, slot untouched.
  CHECK(node.dispatch(LifecycleInput::ActionDone(token + 1, Status::success()), 300).code ==
        StatusCode::NotFound);
  CHECK(node.snap().action_pending);
  // Failed completion: the Owner retakes the same token.
  CHECK_OK(node.dispatch(
      LifecycleInput::ActionDone(token, Status::error(StatusCode::Busy, "joiner busy")), 300));
  CHECK(node.snap().action_pending);
  CHECK_OK(node.dispatch(LifecycleInput::ActionDone(token, Status::success()), 300));
  CHECK(!node.snap().action_pending);
  CHECK(node.lifecycle.take_action(again).code == StatusCode::NotFound);
  // Closed for normal traffic; recovery control stays available.
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK(node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::RecoveryControl));
  // The recovery join re-provisions the stores: back to Active.
  CHECK_OK(node.dispatch(LifecycleInput::Recovery(true), 400));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().recoveries == 1);
}

// --- 1+1 object exchange -------------------------------------------------------------------

// Pumps raw frames between two exchanges (no Lifecycle): `from` port into
// `to` exchange with decoded payloads.
void pump_exchange(FakePeerPort& from, RrsExchange& to, const NodeId sender,
                   const std::uint32_t binding, const MonotonicMs now) {
  for (const auto& sent : from.sent) {
    if (sent.carrier == FrameType::ControlObject) {
      autonomy::ControlObjectPayload manifest{};
      if (autonomy::control_object_decode(ByteView{sent.body.data(), sent.body.size()},
                                          manifest)) {
        to.on_manifest(sender, binding, manifest, now);
      }
    } else if (sent.carrier == FrameType::ObjectChunk) {
      autonomy::ObjectChunkPayload chunk{};
      if (autonomy::object_chunk_decode(ByteView{sent.body.data(), sent.body.size()}, chunk)) {
        to.on_chunk(sender, binding, chunk, now);
      }
    } else if (sent.carrier == FrameType::ObjectAck) {
      autonomy::ObjectAckPayload ack{};
      if (autonomy::object_ack_decode(ByteView{sent.body.data(), sent.body.size()}, ack)) {
        to.on_ack(sender, binding, ack, now);
      }
    }
  }
  from.sent.clear();
}

void test_rrs_exchange_roundtrip() {
  FakePeerPort port_a, port_b;
  FakeObjectSink sink_a, sink_b;
  RrsExchange a(port_a, sink_a), b(port_b, sink_b);
  const auto object = revocation_object(revocation_set(16, 32));  // max-size 616 B
  CHECK(object.size == kRevocationObjectMax);
  CHECK_OK(a.publish(kNodeB, 7, object.view(), 0));
  CHECK(a.publish(kNodeB, 7, object.view(), 0).code == StatusCode::NoCapacity);  // TX x1
  a.poll(0);
  CHECK(!port_a.sent.empty());
  // Keep the manifest frame: the duplicate below must re-ACK, not re-deliver.
  CHECK(port_a.sent[0].carrier == FrameType::ControlObject);
  const std::vector<std::uint8_t> manifest_frame = port_a.sent[0].body;
  pump_exchange(port_a, b, kNode, 7, 0);
  pump_exchange(port_b, a, kNodeB, 7, 0);
  CHECK(sink_b.completed.size() == 1);
  CHECK(sink_b.completed[0].object.size() == object.size);
  CHECK(std::memcmp(sink_b.completed[0].object.data(), object.bytes.data(), object.size) == 0);
  CHECK(b.delivered() == 1 && !b.busy());
  CHECK(!a.busy());  // the Ok ACK completed the TX side
  autonomy::ControlObjectPayload manifest{};
  CHECK_OK(autonomy::control_object_decode(
      ByteView{manifest_frame.data(), manifest_frame.size()}, manifest));
  port_b.sent.clear();
  b.on_manifest(kNode, 7, manifest, 10);
  CHECK(sink_b.completed.size() == 1 && b.delivered() == 1);
  CHECK(port_b.sent.size() == 1);  // re-ACKed Ok
  autonomy::ObjectAckPayload reack{};
  CHECK_OK(autonomy::object_ack_decode(
      ByteView{port_b.sent[0].body.data(), port_b.sent[0].body.size()}, reack));
  CHECK(reack.status == autonomy::ObjectAckStatus::Ok);
  CHECK(reack.received_len == object.size);
  CHECK(!b.owns_transfer(kNodeB, 7, manifest.object_hash));
  CHECK(!b.owns_transfer(kNode, 9, manifest.object_hash));
  port_b.sent.clear();
  b.on_manifest(kNode, 9, manifest, 11);
  CHECK(b.busy());  // a new binding must assemble and authenticate its own copy
  CHECK(port_b.sent.empty());
  b.abort();
}

void test_rrs_exchange_timeouts_and_demux() {
  FakePeerPort port_a, port_b;
  FakeObjectSink sink_a, sink_b;
  RrsExchange a(port_a, sink_a), b(port_b, sink_b);
  const auto object = revocation_object(revocation_set(16));
  // Silent peer: TX retries 3 rounds, then fails.
  CHECK_OK(a.publish(kNodeB, 7, object.view(), 0));
  a.poll(0);
  const std::size_t first_round = port_a.sent.size();
  CHECK(first_round >= 2);  // manifest + chunks
  port_a.sent.clear();
  a.poll(1999);  // inside the ACK window: quiet
  CHECK(port_a.sent.empty());
  a.poll(2000);  // timeout: re-arms, second round goes out next poll
  a.poll(2000);
  CHECK(port_a.sent.size() == first_round);
  port_a.sent.clear();
  a.poll(4000);
  a.poll(4000);
  CHECK(!port_a.sent.empty());  // third round
  port_a.sent.clear();
  a.poll(6000);  // third timeout: exhausted
  CHECK(!a.busy() && a.failed() == 1);
  // RX assembly deadline: manifest without chunks expires.
  CHECK_OK(a.publish(kNodeB, 7, object.view(), 10000));
  a.poll(10000);
  CHECK(port_a.sent[0].carrier == FrameType::ControlObject);
  autonomy::ControlObjectPayload only_manifest{};
  CHECK_OK(autonomy::control_object_decode(
      ByteView{port_a.sent[0].body.data(), port_a.sent[0].body.size()}, only_manifest));
  port_a.sent.clear();  // the chunks are lost on the air
  b.on_manifest(kNode, 7, only_manifest, 10000);
  port_b.sent.clear();
  CHECK(b.busy());
  // A chunk for another hash is not ours.
  autonomy::ObjectChunkPayload foreign{};
  foreign.object_hash.fill(0xEE);
  foreign.offset = 0;
  CHECK(!b.owns_transfer(kNode, 7, foreign.object_hash));
  b.poll(20001);  // past the 10 s assembly deadline
  CHECK(!b.busy() && b.failed() == 1);
  CHECK(!port_b.sent.empty());  // Failed ACK stops the sender
  // Binding sensitivity: the same hash under another binding is foreign.
  FakePeerPort port_c, port_d;
  FakeObjectSink sink_c, sink_d;
  RrsExchange c(port_c, sink_c), d(port_d, sink_d);
  CHECK_OK(c.publish(kNodeB, 7, object.view(), 30000));
  c.poll(30000);
  CHECK(port_c.sent[0].carrier == FrameType::ControlObject);
  autonomy::ControlObjectPayload live{};
  CHECK_OK(autonomy::control_object_decode(
      ByteView{port_c.sent[0].body.data(), port_c.sent[0].body.size()}, live));
  port_c.sent.clear();
  d.on_manifest(kNode, 7, live, 30000);
  CHECK(d.busy());
  CHECK(d.owns_transfer(kNode, 7, live.object_hash));
  CHECK(!d.owns_transfer(kNode, 9, live.object_hash));
  CHECK(!d.owns_transfer(kNodeB, 7, live.object_hash));
  autonomy::ObjectAckPayload incomplete{};
  incomplete.object_hash = live.object_hash;
  incomplete.received_len = static_cast<std::uint16_t>(object.size);
  incomplete.status = autonomy::ObjectAckStatus::Incomplete;
  c.on_ack(kNodeB, 7, incomplete, 30000);
  CHECK(c.busy());  // a full-length Incomplete is not an Ok transport ACK
  // Garbage kind manifests are ignored, oversize publishes refused.
  autonomy::ControlObjectPayload bad_kind{};
  bad_kind.kind = autonomy::ControlObjectKind::ChannelPlan;
  bad_kind.total_len = 10;
  b.on_manifest(kNode, 7, bad_kind, 30000);
  CHECK(!b.busy());
  RrsExchange e(port_c, sink_c);
  std::array<std::uint8_t, kRevocationObjectMax + 1> huge{};
  CHECK(e.publish(kNodeB, 7, ByteView{huge.data(), huge.size()}, 30000).code ==
        StatusCode::InvalidArgument);
}

void test_owns_rrs_chunk_demux() {
  // The Owner's chunk/ack demux: the lifecycle claims exactly the frames
  // of its live gossip transfer, so those route to VerifiedPeerControl
  // while everything else stays on the migration lane.
  NodeFixture node{};
  CHECK(node.provision(3, 16));
  node.pump(0);
  CHECK(node.snap().phase == LifecyclePhase::Active);
  FakePeerPort tx_port;
  FakeObjectSink tx_sink;
  RrsExchange tx(tx_port, tx_sink);
  const auto object = revocation_object(revocation_set(16));
  CHECK_OK(tx.publish(kNode, 7, object.view(), 0));
  tx.poll(0);
  CHECK(!tx_port.sent.empty());
  CHECK(tx_port.sent[0].carrier == FrameType::ControlObject);
  // Before the manifest, no chunk is ours — not even a well-formed one.
  for (const auto& sent : tx_port.sent) {
    if (sent.carrier != FrameType::ObjectChunk) continue;
    CHECK(!node.lifecycle.owns_rrs_chunk(
        kNodeB, 7, sent.carrier, ByteView{sent.body.data(), sent.body.size()}));
  }
  CHECK_OK(node.dispatch(
      LifecycleInput::PeerControl(
          stamp_for(kNodeB, 3), FrameType::ControlObject,
          ByteView{tx_port.sent[0].body.data(), tx_port.sent[0].body.size()}),
      0));
  // The transfer's chunks and ACKs are claimed; anything else is not.
  bool saw_chunk = false;
  for (const auto& sent : tx_port.sent) {
    if (sent.carrier != FrameType::ObjectChunk) continue;
    saw_chunk = true;
    const ByteView body{sent.body.data(), sent.body.size()};
    CHECK(node.lifecycle.owns_rrs_chunk(kNodeB, 7, sent.carrier, body));
    CHECK(!node.lifecycle.owns_rrs_chunk(kNodeC, 7, sent.carrier, body));
    CHECK(!node.lifecycle.owns_rrs_chunk(kNodeB, 9, sent.carrier, body));
    CHECK(!node.lifecycle.owns_rrs_chunk(kNodeB, 7, FrameType::Control, body));
  }
  CHECK(saw_chunk);
  const std::array<std::uint8_t, 3> garbage{{1, 2, 3}};
  CHECK(!node.lifecycle.owns_rrs_chunk(kNodeB, 7, FrameType::ObjectChunk,
                                       ByteView{garbage.data(), garbage.size()}));
  CHECK(!node.lifecycle.owns_rrs_chunk(kInvalidNodeId, 7, FrameType::ObjectChunk,
                                       ByteView{garbage.data(), garbage.size()}));
}

// --- Re-entry ----------------------------------------------------------------------------------

bool same_snapshot(const LifecycleSnapshot& a, const LifecycleSnapshot& b) {
  return std::memcmp(&a, &b, sizeof(LifecycleSnapshot)) == 0;
}

struct ReentrantPorts {
  MembershipLifecycle* lifecycle{nullptr};
  int busy_dispatch{0};
  int busy_action{0};
  bool snapshots_equal{true};
};

struct ReentrantPeerPort final : public LifecyclePeerPort {
  ReentrantPorts* shared{nullptr};
  Status peer_send(const NodeId peer, const FrameType carrier,
                   const ByteView body) noexcept override {
    (void)peer;
    (void)carrier;
    (void)body;
    if (shared == nullptr || shared->lifecycle == nullptr) return Status::success();
    const LifecycleSnapshot before = shared->lifecycle->snapshot();
    if (shared->lifecycle->dispatch(LifecycleInput::Poll(), 0).code == StatusCode::Busy) {
      ++shared->busy_dispatch;
    }
    LifecycleAction action{};
    if (shared->lifecycle->take_action(action).code == StatusCode::Busy) ++shared->busy_action;
    const LifecycleSnapshot after = shared->lifecycle->snapshot();
    if (!same_snapshot(before, after)) shared->snapshots_equal = false;
    return Status::success();
  }
};

struct ReentrantAuthorityPort final : public LifecycleAuthorityPort {
  ReentrantPorts* shared{nullptr};
  Status authority_send(const std::uint8_t type, const ByteView body) noexcept override {
    (void)type;
    (void)body;
    if (shared == nullptr || shared->lifecycle == nullptr) return Status::success();
    const LifecycleSnapshot before = shared->lifecycle->snapshot();
    if (shared->lifecycle->dispatch(LifecycleInput::Poll(), 0).code == StatusCode::Busy) {
      ++shared->busy_dispatch;
    }
    const LifecycleSnapshot after = shared->lifecycle->snapshot();
    if (!same_snapshot(before, after)) shared->snapshots_equal = false;
    return Status::success();
  }
};

struct ReentrantRuntimePort final : public LifecycleRuntimePort {
  ReentrantPorts* shared{nullptr};
  Status enforce_revocation(const RevocationSet& set, const std::uint32_t site_epoch,
                            const MonotonicMs now) noexcept override {
    (void)set;
    (void)site_epoch;
    (void)now;
    if (shared == nullptr || shared->lifecycle == nullptr) return Status::success();
    if (shared->lifecycle->dispatch(LifecycleInput::Poll(), 0).code == StatusCode::Busy) {
      ++shared->busy_dispatch;
    }
    return Status::success();
  }
};

struct ReentrantObserver final : public LifecycleObserver {
  ReentrantPorts* shared{nullptr};
  void on_lifecycle_event(const LifecycleEvent& event,
                          const MonotonicMs now_ms) noexcept override {
    (void)event;
    (void)now_ms;
    if (shared == nullptr || shared->lifecycle == nullptr) return;
    if (shared->lifecycle->dispatch(LifecycleInput::Poll(), 0).code == StatusCode::Busy) {
      ++shared->busy_dispatch;
    }
  }
};

void test_reentry_is_busy_and_changelss() {
  FaultyRecordStorage identity_storage(kIdentitySlotBytes);
  FaultyRecordStorage site_storage(kSiteSlotBytes);
  FaultyRecordStorage rrs_storage(kRevocationSlotBytes);
  FaultyResumeStorage resume_storage(16);
  IdentityStore identity(identity_storage);
  SiteStore site(site_storage);
  RevocationStore revocations(rrs_storage);
  ResumeCache resume(resume_storage);
  ReentrantAuthorityPort authority{};
  ReentrantPeerPort peer{};
  ReentrantRuntimePort runtime{};
  FakeEntropy entropy{};
  FakeObjectSink sink{};
  ReentrantObserver observer{};
  LifecyclePorts ports{authority, peer, runtime, entropy, sink, &observer};
  LifecycleConfig config{};
  config.self = kNode;
  config.enabled_features = kCapRrsGossipV1 | kCapMembershipLifecycleV1;
  MembershipLifecycle lifecycle(config, identity, site, revocations, resume, ports);
  ReentrantPorts shared{};
  shared.lifecycle = &lifecycle;
  authority.shared = &shared;
  peer.shared = &shared;
  runtime.shared = &shared;
  observer.shared = &shared;

  CHECK(identity.initialize());
  CHECK_OK(identity.commit(identity_for(kNode)));
  CHECK(site.initialize());
  CHECK_OK(site.commit(site_for(kNode, 3)));
  CHECK(revocations.initialize());
  CHECK_OK(lifecycle.dispatch(LifecycleInput::Boot(true), 0));
  CHECK_OK(lifecycle.dispatch(LifecycleInput::Poll(), 0));  // Get -> authority re-entry
  CHECK(shared.busy_dispatch >= 1);
  CHECK(shared.snapshots_equal);
  const std::size_t rrs_writes = rrs_storage.write_calls;
  // Feed the bootstrap set: the apply drives runtime + observer re-entry.
  const auto object = revocation_object(revocation_set(14, 1, 2));
  PeerCredentialStamp authority_stamp{};
  authority_stamp.network = kNetwork;
  CHECK_OK(lifecycle.dispatch(
      LifecycleInput::Authority(authority_stamp, kAuthorityTypeRevocation, object.view()), 10));
  for (int i = 0; i < 40; ++i) {
    (void)lifecycle.dispatch(LifecycleInput::Poll(), 10);
    if (lifecycle.snapshot().phase != LifecyclePhase::ApplyingRrs) break;
  }
  CHECK(lifecycle.snapshot().phase == LifecyclePhase::Active);
  CHECK(shared.busy_dispatch >= 3);  // authority + runtime + observer paths
  CHECK(shared.snapshots_equal);
  // The outer work still completed exactly once despite the re-entry.
  CHECK(rrs_storage.write_calls == rrs_writes + 2);  // pending seal + commit
  // Gossip send path: a lagging peer triggers a StateEpochs send.
  std::array<std::uint8_t, kStateEpochsSize> epochs_raw{};
  CHECK_OK(state_epochs_encode(StateEpochs{3, 5, 203}, epochs_raw));
  const int busy_before = shared.busy_dispatch;
  CHECK_OK(lifecycle.dispatch(
      LifecycleInput::PeerControl(stamp_for(kPeer, 3), FrameType::Control,
                                 ByteView{epochs_raw.data(), epochs_raw.size()}),
      20));
  CHECK_OK(lifecycle.dispatch(LifecycleInput::Poll(), 20));
  CHECK(shared.busy_dispatch > busy_before);  // peer-send re-entry fired
  CHECK(shared.snapshots_equal);
}

// --- Gossip sims (V1-R03 / V1-R09 device parts) --------------------------------------------------

struct GossipSim {
  struct Node {
    NodeFixture* fixture{nullptr};
    std::uint32_t binding{7};
  };
  std::map<NodeId, Node> nodes;
  std::set<std::pair<NodeId, NodeId>> links;
  MonotonicMs now{0};

  void add(const NodeId id, NodeFixture* fixture) { nodes[id] = Node{fixture, 7}; }
  void link(const NodeId a, const NodeId b) {
    links.insert({a, b});
    links.insert({b, a});
  }
  bool linked(const NodeId a, const NodeId b) const {
    return links.count({a, b}) != 0;
  }
  // A link-up surfaces as P4-authenticated epoch observations both ways.
  void link_up(const NodeId a, const NodeId b) {
    link(a, b);
    observe(a, b);
    observe(b, a);
  }
  void observe(const NodeId from, const NodeId to) {
    const std::uint32_t applied = nodes[from].fixture->snap().applied_rs_epoch;
    std::array<std::uint8_t, kStateEpochsSize> raw{};
    (void)state_epochs_encode(StateEpochs{3, applied, 203}, raw);
    (void)nodes[to].fixture->dispatch(
        LifecycleInput::PeerControl(stamp_for(from, 3, nodes[from].binding), FrameType::Control,
                                   ByteView{raw.data(), raw.size()}),
        now);
  }
  void poll_all() {
    for (auto& [id, node] : nodes) {
      (void)node.fixture->dispatch(LifecycleInput::Poll(), now);
    }
  }
  // Routes every queued peer frame to its destination (links only) and
  // feeds every completed object back to its Owner.
  void route() {
    for (auto& [id, node] : nodes) {
      for (const auto& sent : node.fixture->peer.sent) {
        if (!linked(id, sent.peer)) continue;
        auto found = nodes.find(sent.peer);
        if (found == nodes.end()) continue;
        (void)found->second.fixture->dispatch(
            LifecycleInput::PeerControl(stamp_for(id, 3, node.binding), sent.carrier,
                                       ByteView{sent.body.data(), sent.body.size()}),
            now);
      }
      node.fixture->peer.sent.clear();
      for (const auto& done : node.fixture->sink.completed) {
        (void)node.fixture->dispatch(
            LifecycleInput::Completed(done.peer,
                                     ByteView{done.object.data(), done.object.size()}),
            now);
      }
      node.fixture->sink.completed.clear();
    }
  }
  void step(const MonotonicMs dt = 100) {
    poll_all();
    route();
    now += dt;
  }
};

std::size_t count_requests(const FakePeerPort& port) {
  std::size_t count = 0;
  for (const auto& sent : port.sent) {
    RrsRequest request{};
    if (sent.carrier == FrameType::Control && sent.body.size() == kRrsRequestSize &&
        rrs_request_decode(ByteView{sent.body.data(), sent.body.size()}, request)) {
      ++count;
    }
  }
  return count;
}

void test_authenticated_peer_starts_and_stops_gossip() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 100));
  CHECK(node.peer.sent.empty());
  CHECK_OK(node.dispatch(LifecycleInput::PeerBound(stamp_for(kPeer, 3)), 101));
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 101));
  CHECK(node.peer.sent.size() == 1);
  CHECK(node.peer.sent[0].peer == kPeer);
  StateEpochs state{};
  CHECK_OK(state_epochs_decode(ByteView{node.peer.sent[0].body.data(), node.peer.sent[0].body.size()}, state));
  CHECK(state.applied_rs_epoch == 14);
  CHECK_OK(node.dispatch(LifecycleInput::PeerGone(kPeer), 102));
  CHECK_OK(node.dispatch(LifecycleInput::Poll(), 10000));
  CHECK(node.peer.sent.size() == 1);
}

void test_gossip_line_propagates() {
  NodeFixture a(kNode), b(kNodeB), c(kNodeC);
  CHECK(a.provision(3, 16));
  CHECK(b.provision(3, 14));
  CHECK(c.provision(3, 14));
  GossipSim sim;
  sim.add(kNode, &a);
  sim.add(kNodeB, &b);
  sim.add(kNodeC, &c);
  sim.link_up(kNode, kNodeB);
  // B pulls 16 from A and applies it.
  int steps = 0;
  while ((b.snap().applied_rs_epoch < 16 ||
          b.snap().phase == LifecyclePhase::ApplyingRrs) &&
         steps < 500) {
    sim.step();
    ++steps;
  }
  CHECK(b.snap().applied_rs_epoch == 16);
  CHECK(b.snap().phase == LifecyclePhase::Active);
  CHECK(b.snap().fetches_done == 1);
  CHECK(b.snap().authority_acks_sent >= 1);  // the gossip fetch still reports
  // C is still behind and unlinked: silent.
  CHECK(c.snap().applied_rs_epoch == 14);
  CHECK(c.snap().fetches_started == 0);
  // C links to B and converges over the second hop.
  sim.link_up(kNodeB, kNodeC);
  steps = 0;
  while ((c.snap().applied_rs_epoch < 16 ||
          c.snap().phase == LifecyclePhase::ApplyingRrs) &&
         steps < 500) {
    sim.step();
    ++steps;
  }
  CHECK(c.snap().applied_rs_epoch == 16);
  CHECK(c.snap().fetches_done == 1);
}

void test_gossip_rates_and_refresh() {
  NodeFixture a(kNode), b(kNodeB);
  CHECK(a.provision(3, 16));
  CHECK(b.provision(3, 16));
  GossipSim sim;
  sim.add(kNode, &a);
  sim.add(kNodeB, &b);
  sim.link_up(kNode, kNodeB);
  for (int i = 0; i < 50; ++i) sim.step();  // let the pair converge
  // Refresh spacing on one peer: beacons every 5..6 s (5 s + 0..1 s).
  MonotonicMs last = 0;
  bool first = true;
  int beacons_seen = 0;
  for (MonotonicMs now = sim.now; now < sim.now + 30000; now += 100) {
    a.peer.sent.clear();
    CHECK_OK(a.dispatch(LifecycleInput::Poll(), now));
    if (!a.peer.sent.empty()) {
      if (!first) {
        CHECK(now - last >= rrs_const::kGossipRefreshMs);
        CHECK(now - last <= rrs_const::kGossipRefreshMs + rrs_const::kGossipJitterMs);
      }
      first = false;
      last = now;
      ++beacons_seen;
    }
  }
  CHECK(beacons_seen >= 4);
  // Request rate: a newer claim re-triggers at most one request per minute.
  b.peer.sent.clear();
  std::array<std::uint8_t, kStateEpochsSize> newer{};
  CHECK_OK(state_epochs_encode(StateEpochs{3, 17, 203}, newer));
  CHECK_OK(b.dispatch(
      LifecycleInput::PeerControl(stamp_for(kNode, 3), FrameType::Control,
                                 ByteView{newer.data(), newer.size()}),
      40000));
  CHECK(count_requests(b.peer) == 1);
  b.peer.sent.clear();
  CHECK_OK(b.dispatch(
      LifecycleInput::PeerControl(stamp_for(kNode, 3), FrameType::Control,
                                 ByteView{newer.data(), newer.size()}),
      41000));
  CHECK_OK(b.dispatch(LifecycleInput::Poll(), 41000));
  CHECK(count_requests(b.peer) == 0);  // cooldown still holds
  // Let the fetch window lapse (the phantom 17 never arrives), then rebind:
  // the 60 s rate history survives the binding change.
  CHECK_OK(b.dispatch(LifecycleInput::Poll(), 56000));
  CHECK(b.snap().fetch_failures == 1);
  b.peer.sent.clear();
  CHECK_OK(b.dispatch(
      LifecycleInput::PeerControl(stamp_for(kNode, 3, /*binding=*/8), FrameType::Control,
                                 ByteView{newer.data(), newer.size()}),
      56000));
  CHECK_OK(b.dispatch(LifecycleInput::Poll(), 56000));
  CHECK(count_requests(b.peer) == 0);
  // Past the cooldown the request goes out again.
  CHECK_OK(b.dispatch(
      LifecycleInput::PeerControl(stamp_for(kNode, 3, /*binding=*/8), FrameType::Control,
                                 ByteView{newer.data(), newer.size()}),
      101000));
  CHECK(count_requests(b.peer) == 1);
  // Features off: the lifecycle stays silent on the gossip lane.
  NodeFixture quiet(kNodeC, 0);
  CHECK(quiet.provision(3, 16));
  CHECK_OK(quiet.dispatch(
      LifecycleInput::PeerControl(stamp_for(kNode, 3), FrameType::Control,
                                 ByteView{newer.data(), newer.size()}),
      1000));
  CHECK_OK(quiet.dispatch(LifecycleInput::Poll(), 1000));
  CHECK(quiet.peer.sent.empty());
  // A bit-7 route grant is not permission to send RRS gossip: only the
  // bit-5 gossip grant opens the gossip lane.
  NodeFixture route_only(kNodeC, kCapRouteBroadcastV1);
  CHECK(route_only.provision(3, 16));
  CHECK_OK(route_only.dispatch(
      LifecycleInput::PeerControl(stamp_for(kNode, 3), FrameType::Control,
                                 ByteView{newer.data(), newer.size()}),
      1000));
  CHECK_OK(route_only.dispatch(LifecycleInput::Poll(), 1000));
  CHECK(route_only.peer.sent.empty());
}

void test_gossip_line_100_nodes_converges() {
  // V1-R03 scale leg: a 100-deep line converges hop by hop with no fetch
  // storms — every node behind fetches exactly once (the 1+1 exchange).
  constexpr int kNodes = 100;
  constexpr NodeId kBase = 0x00A1000000010000ULL;
  std::vector<std::unique_ptr<NodeFixture>> fixtures;
  fixtures.reserve(kNodes);
  for (int i = 0; i < kNodes; ++i) {
    fixtures.push_back(std::make_unique<NodeFixture>(kBase + static_cast<NodeId>(i)));
    CHECK(fixtures.back()->provision(3, i == 0 ? 16 : 14));
  }
  GossipSim sim;
  for (int i = 0; i < kNodes; ++i) {
    sim.add(kBase + static_cast<NodeId>(i), fixtures[static_cast<std::size_t>(i)].get());
  }
  for (int i = 0; i + 1 < kNodes; ++i) {
    sim.link_up(kBase + static_cast<NodeId>(i), kBase + static_cast<NodeId>(i + 1));
  }
  int steps = 0;
  const int kCap = 20000;
  while (steps < kCap) {
    bool done = true;
    for (auto& fixture : fixtures) {
      const auto snap = fixture->snap();
      if (snap.applied_rs_epoch < 16 || snap.phase == LifecyclePhase::ApplyingRrs) {
        done = false;
        break;
      }
    }
    if (done) break;
    sim.step();
    ++steps;
  }
  CHECK(steps < kCap);
  for (auto& fixture : fixtures) {
    CHECK(fixture->snap().applied_rs_epoch == 16);
    CHECK(fixture->snap().phase == LifecyclePhase::Active);
  }
  for (int i = 1; i < kNodes; ++i) {
    CHECK(fixtures[static_cast<std::size_t>(i)]->snap().fetches_done == 1);
  }
}

void test_partition_continues_and_merge_converges() {
  NodeFixture a(kNode), b(kNodeB), c(kNodeC);
  CHECK(a.provision(3, 14));
  CHECK(b.provision(3, 14));
  CHECK(c.provision(3, 14));
  GossipSim sim;
  sim.add(kNode, &a);
  sim.add(kNodeB, &b);
  sim.add(kNodeC, &c);
  sim.link_up(kNode, kNodeB);  // C is partitioned away
  // The authority revokes into partition 1 only.
  RevocationSet next = revocation_set(15, 0, 2);
  next.entries[0] = RevocationEntry{0x00A1000000000100ULL, 2, RevocationReason::Removed};
  next.entries[1] = RevocationEntry{0x00A1000000000107ULL, 3, RevocationReason::Removed};
  next.entries[2] = RevocationEntry{kPeer, 2, RevocationReason::Removed};
  next.count = 3;
  const auto object = revocation_object(next);
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(a.dispatch(LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()),
                      0));
  int steps = 0;
  while ((a.snap().applied_rs_epoch < 15 || b.snap().applied_rs_epoch < 15) && steps < 600) {
    sim.step();
    ++steps;
  }
  CHECK(a.snap().applied_rs_epoch == 15);
  CHECK(b.snap().applied_rs_epoch == 15);
  // Partition 2 keeps operating on the old set: no upper bound is claimed
  // here (04 §9) — the mechanism records that C never saw epoch 15.
  for (int i = 0; i < 100; ++i) sim.step();
  CHECK(c.snap().phase == LifecyclePhase::Active);
  CHECK(c.snap().applied_rs_epoch == 14);
  CHECK(c.snap().fetches_started == 0);
  CHECK(c.lifecycle.permits(stamp_for(kPeer, 1), TrafficUse::Data));  // stale view
  // Merge: C pulls 15 from B and the stale credential closes.
  sim.link_up(kNodeB, kNodeC);
  steps = 0;
  while (c.snap().applied_rs_epoch < 15 && steps < 600) {
    sim.step();
    ++steps;
  }
  CHECK(c.snap().applied_rs_epoch == 15);
  CHECK(!c.lifecycle.permits(stamp_for(kPeer, 1), TrafficUse::Data));
}

// --- Storage faults --------------------------------------------------------------------------------

void test_apply_storage_faults() {
  // A refused RRS1 commit parks in StorageBlocked; a reboot re-runs the
  // adoption on the old set and the redelivery then applies cleanly.
  NodeFixture node;
  CHECK(node.provision(3, 14));
  const auto object = revocation_object(revocation_set(15));
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  node.rrs_storage.fail_writes = true;
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 0));
  node.pump(0);
  CHECK(node.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  node.rrs_storage.disarm();
  CHECK_OK(node.dispatch(LifecycleInput::Boot(true), 100));
  node.pump(100);
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().applied_rs_epoch == 14);
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object.view()), 200));
  node.pump(200);
  CHECK(node.snap().phase == LifecyclePhase::Active);
  CHECK(node.snap().applied_rs_epoch == 15);

  // A persistently failing sweep parks after 3 attempts; the boot then
  // re-runs the enforcement and completes the apply.
  NodeFixture sweep(kNodeB);
  CHECK(sweep.provision(3, 14));
  ResumeSlot old = resume_slot(kPeer, 0, 10);
  old.peer_generation = 1;
  ResumeContext context{kNetwork, 203, nullptr};
  CHECK_OK(sweep.resume.put(old, context));
  RevocationSet next = revocation_set(15, 0, 2);
  next.entries[0] = RevocationEntry{0x00A1000000000100ULL, 2, RevocationReason::Removed};
  next.entries[1] = RevocationEntry{0x00A1000000000107ULL, 3, RevocationReason::Removed};
  next.entries[2] = RevocationEntry{kPeer, 2, RevocationReason::Removed};
  next.count = 3;
  const auto object2 = revocation_object(next);
  CHECK_OK(sweep.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object2.view()), 0));
  // Verify, Store, Enforce, then the sweep hits the failing flash.
  CHECK_OK(sweep.dispatch(LifecycleInput::Poll(), 0));
  CHECK_OK(sweep.dispatch(LifecycleInput::Poll(), 0));
  CHECK_OK(sweep.dispatch(LifecycleInput::Poll(), 0));
  sweep.resume_storage.fail_writes = true;
  CHECK_OK(sweep.dispatch(LifecycleInput::Poll(), 0));
  CHECK(sweep.snap().phase == LifecyclePhase::ApplyingRrs);  // attempt 1
  CHECK_OK(sweep.dispatch(LifecycleInput::Poll(), 0));
  CHECK(sweep.snap().phase == LifecyclePhase::ApplyingRrs);  // attempt 2
  CHECK_OK(sweep.dispatch(LifecycleInput::Poll(), 0));
  CHECK(sweep.snap().phase == LifecyclePhase::StorageBlocked);  // attempt 3
  sweep.resume_storage.fail_writes = false;
  CHECK_OK(sweep.dispatch(LifecycleInput::Boot(true), 100));
  sweep.pump(100, 60);
  CHECK(sweep.snap().phase == LifecyclePhase::Active);
  CHECK(sweep.snap().applied_rs_epoch == 15);
  CHECK(sweep.site.site().rs_epoch_floor == 15);

  // A single torn sweep write heals on retry: the apply completes.
  NodeFixture torn(kNodeC);
  CHECK(torn.provision(3, 14));
  CHECK_OK(torn.resume.put(old, context));
  CHECK_OK(torn.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, object2.view()), 0));
  CHECK_OK(torn.dispatch(LifecycleInput::Poll(), 0));  // Verify
  CHECK_OK(torn.dispatch(LifecycleInput::Poll(), 0));  // Store
  CHECK_OK(torn.dispatch(LifecycleInput::Poll(), 0));  // Enforce
  torn.resume_storage.cut_call = torn.resume_storage.write_calls;
  torn.resume_storage.cut_bytes = 10;
  torn.pump(0, 60);
  CHECK(torn.snap().phase == LifecyclePhase::Active);
  CHECK(torn.snap().applied_rs_epoch == 15);
}

void test_uncertain_commit_rejects_different_same_epoch_object() {
  NodeFixture node;
  CHECK(node.provision(3, 14));
  const auto candidate = revocation_object(revocation_set(15));
  const auto alternate = revocation_object(revocation_set(15, 3));
  ByteBuffer<kRevocationSlotBytes> record{};
  CHECK_OK(revocation_record_encode(alternate.view(), kRevocationSealCommitted, 2, record));
  node.rrs_storage.substitute_record.assign(record.bytes.data(),
                                             record.bytes.data() + record.size);
  node.rrs_storage.substitute_call = node.rrs_storage.write_calls + 1;
  const std::size_t enforcements_before = node.runtime.calls.size();
  PeerCredentialStamp authority{};
  authority.network = kNetwork;
  CHECK_OK(node.dispatch(
      LifecycleInput::Authority(authority, kAuthorityTypeRevocation, candidate.view()), 0));
  node.pump(0);
  CHECK(node.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(node.authority.sent.empty());
  CHECK(node.runtime.calls.size() == enforcements_before);
  CHECK(!node.lifecycle.permits(stamp_for(kPeer, 3), TrafficUse::Data));
  CHECK(node.revocations.has_set());
  CHECK(node.revocations.rs_epoch() == 15);
  ByteBuffer<kRevocationObjectMax> landed{};
  CHECK_OK(node.revocations.load_object(landed));
  CHECK(landed.size == alternate.size);
  CHECK(std::memcmp(landed.bytes.data(), alternate.bytes.data(), alternate.size) == 0);
}

// --- Sweep/clear cursor units ------------------------------------------------------------------------

void test_sweep_cursor_units() {
  FaultyResumeStorage storage(4);
  ResumeCache cache(storage);
  RevocationSet rrs = revocation_set(15, 0, 2);
  rrs.entries[0] = RevocationEntry{kPeer, 2, RevocationReason::Removed};
  rrs.count = 1;
  ResumeContext plain{kNetwork, 203, nullptr};
  ResumeSlot revoked = resume_slot(kPeer, 0, 10);
  revoked.peer_generation = 1;
  ResumeSlot live = resume_slot(kNodeB, 0, 11);
  live.peer_generation = 5;
  CHECK_OK(cache.put(revoked, plain));
  CHECK_OK(cache.put(live, plain));
  ResumeContext guarded{kNetwork, 203, &rrs};
  std::size_t cursor = 0;
  bool done = true;
  int polls = 0;
  done = false;
  while (!done && polls < 8) {
    CHECK_OK(cache.sweep_revoked(guarded, cursor, done));
    ++polls;
  }
  CHECK(done && polls == 4);  // one slot per call, no restart-from-head
  ResumeSlot out{};
  std::size_t index = 0;
  CHECK(cache.find(ResumePurpose::Link, kPeer, guarded, out, index).code == StatusCode::NotFound);
  CHECK_OK(cache.find(ResumePurpose::Link, kNodeB, guarded, out, index));
  // Past-the-end cursor is immediately done.
  cursor = 99;
  CHECK_OK(cache.sweep_revoked(guarded, cursor, done));
  CHECK(done);
  // clear_step empties every slot under the same discipline.
  cursor = 0;
  done = false;
  polls = 0;
  while (!done && polls < 8) {
    CHECK_OK(cache.clear_step(cursor, done));
    ++polls;
  }
  CHECK(done && polls == 4);
  CHECK(cache.find(ResumePurpose::Link, kNodeB, guarded, out, index).code == StatusCode::NotFound);
}

void test_sweep_scrubs_torn_slot() {
  FaultyResumeStorage storage(4);
  ResumeCache cache(storage);
  ResumeContext context{kNetwork, 203, nullptr};
  ResumeSlot old = resume_slot(kPeer, 0, 10);
  old.peer_generation = 1;
  CHECK_OK(cache.put(old, context));
  ResumeSlot found{};
  std::size_t index = 0;
  CHECK_OK(cache.find(ResumePurpose::Link, kPeer, context, found, index));
  storage.slot(index)[kResumeSlotBytes - 1] ^= 0x01;
  const std::size_t writes = storage.write_calls;
  RevocationSet set = revocation_set(15, 0, 2);
  set.entries[0] = RevocationEntry{kPeer, 2, RevocationReason::Removed};
  set.count = 1;
  context.revocations = &set;
  std::size_t cursor = index;
  bool done = false;
  CHECK_OK(cache.sweep_revoked(context, cursor, done));
  CHECK(cursor == index + 1);
  CHECK(storage.write_calls == writes + 1);
}

// --- RAM budget ----------------------------------------------------------------------------------------

void test_ram_budget() {
  std::printf("sizeof MembershipLifecycle=%zu RrsExchange=%zu RevocationSet=%zu\n",
              sizeof(MembershipLifecycle), sizeof(RrsExchange), sizeof(RevocationSet));
  CHECK(sizeof(MembershipLifecycle) <= 8192);
  CHECK(sizeof(MembershipLifecycle) + sizeof(RevocationStore) + sizeof(ResumeCache) <= 10240);
  CHECK(sizeof(RrsExchange) <= 2 * kRevocationObjectMax + 512);
}

  // --- MeshNode P6 branch ----------------------------------------------------------------------------

struct FakeRrsSink final : public RrsGossipSink {
  struct Frame {
    NodeId peer{kInvalidNodeId};
    FrameType type{FrameType::Data};
    std::vector<std::uint8_t> body;
  };
  std::vector<Frame> frames;
  void on_rrs_frame(const NodeId peer, const FrameType type, const ByteView body,
                    const MonotonicMs now_ms) noexcept override {
    (void)now_ms;
    Frame f{};
    f.peer = peer;
    f.type = type;
    if (body.data != nullptr) f.body.assign(body.data, body.data + body.size);
    frames.push_back(f);
  }
};

wire::EncodedFrame craft_control(routeloom_test::TestSecurity& cipher, const NodeId from,
                                 const NodeId to, const ByteView body,
                                 const std::uint64_t wire_seq) {
  wire::Header h{};
  h.type = FrameType::Control;
  h.delivery = DeliveryClass::BestEffort;
  h.hop_remaining = kDefaultHopLimit;
  h.network = 1;
  h.origin = from;
  h.destination = to;
  h.previous_hop = from;
  h.next_hop = to;
  h.message = MessageId{1, wire_seq};
  h.remaining_deadline_ms = 5000;
  h.original_lifetime_ms = 5000;
  wire::PlainFrame plain{};
  plain.header = h;
  plain.payload_size = body.size;
  if (body.size > 0) std::memcpy(plain.payload.data(), body.data, body.size);
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, cipher, out));
  return out;
}

wire::EncodedFrame craft_manifest_frame(routeloom_test::TestSecurity& cipher, const NodeId from,
                                        const NodeId to,
                                        const autonomy::ControlObjectKind kind,
                                        const std::uint64_t wire_seq) {
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = kind;
  manifest.total_len = 100;
  manifest.object_hash.fill(0x11);
  autonomy::EncodedPayload body{};
  CHECK_OK(autonomy::control_object_encode(manifest, body));
  wire::Header h{};
  h.type = FrameType::ControlObject;
  h.delivery = DeliveryClass::BestEffort;
  h.hop_remaining = kDefaultHopLimit;
  h.network = 1;
  h.origin = from;
  h.destination = to;
  h.previous_hop = from;
  h.next_hop = to;
  h.message = MessageId{1, wire_seq};
  h.remaining_deadline_ms = 5000;
  h.original_lifetime_ms = 5000;
  wire::PlainFrame plain{};
  plain.header = h;
  plain.payload_size = body.size;
  std::memcpy(plain.payload.data(), body.bytes.data(), body.size);
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, cipher, out));
  return out;
}

void test_node_p6_branch() {
  routeloom_test::SimWorld world;
  world.add(1);
  world.add(2);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.run(400, 5);
  FakeRrsSink sink;
  world.at(1)->set_rrs_sink(&sink);
  world.obs(1)->diagnostics.clear();

  std::array<std::uint8_t, kStateEpochsSize> epochs_raw{};
  CHECK_OK(state_epochs_encode(StateEpochs{3, 16, 203}, epochs_raw));
  const auto epochs_frame = craft_control(*world.security[2], 2, 1,
                                          ByteView{epochs_raw.data(), epochs_raw.size()}, 500);
  world.at(1)->on_radio_receive(2, epochs_frame.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 1);
  CHECK(sink.frames[0].peer == 2 && sink.frames[0].type == FrameType::Control);
  CHECK(sink.frames[0].body.size() == kStateEpochsSize);

  std::array<std::uint8_t, kRrsRequestSize> req_raw{};
  CHECK_OK(rrs_request_encode(RrsRequest{3, 14}, req_raw));
  const auto req_frame = craft_control(*world.security[2], 2, 1,
                                       ByteView{req_raw.data(), req_raw.size()}, 501);
  world.at(1)->on_radio_receive(2, req_frame.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 2);

  // Wrong sub / wrong length: still end-protection-required, never P6.
  std::array<std::uint8_t, kStateEpochsSize> bad_sub{};
  bad_sub[0] = 1;
  bad_sub[1] = 0x63;
  const auto bad_frame = craft_control(*world.security[2], 2, 1,
                                       ByteView{bad_sub.data(), bad_sub.size()}, 502);
  world.at(1)->on_radio_receive(2, bad_frame.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 2);
  CHECK(world.obs(1)->has_diag("END_PROTECTION_REQUIRED"));
  const auto short_frame = craft_control(*world.security[2], 2, 1,
                                         ByteView{epochs_raw.data(), kStateEpochsSize - 1}, 503);
  world.at(1)->on_radio_receive(2, short_frame.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 2);

  // Kind-6 manifest routes to the P6 sink; kind 2 stays on autonomy lane.
  const auto rrs_manifest =
      craft_manifest_frame(*world.security[2], 2, 1, autonomy::ControlObjectKind::RevocationSet, 504);
  world.at(1)->on_radio_receive(2, rrs_manifest.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 3);
  CHECK(sink.frames[2].type == FrameType::ControlObject);
  const auto mig_manifest = craft_manifest_frame(*world.security[2], 2, 1,
                                                 autonomy::ControlObjectKind::ChannelPlan, 505);
  world.at(1)->on_radio_receive(2, mig_manifest.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 3);

  // Unwired (the PR A production state): honest P6_NOT_WIRED, no delivery.
  world.at(1)->set_rrs_sink(nullptr);
  const auto unwired = craft_control(*world.security[2], 2, 1,
                                     ByteView{epochs_raw.data(), epochs_raw.size()}, 506);
  world.at(1)->on_radio_receive(2, unwired.view(), RadioRxMetadata{-60}, world.now);
  CHECK(sink.frames.size() == 3);
  CHECK(world.obs(1)->has_diag("P6_NOT_WIRED"));
}

// --- Shared golden vectors (protocol/sdkv1-golden/revocation/) -------------------------------
// Generated by tools/gen_sdkv1_revocation_vectors.py; the Rust twin is
// host/routeloom-wire/tests/revocation.rs. Every valid vector must decode
// to the listed fields and re-encode byte-for-byte; kind-6 chunks must
// reassemble to a manifest-matching RRS1 object that verifies.

using Fields = std::map<std::string, std::string>;
std::string vector_current;

Fields parse_vector_json(const std::string& text) {
  Fields fields;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t key_begin = text.find('"', pos);
    if (key_begin == std::string::npos) break;
    const std::size_t key_end = text.find('"', key_begin + 1);
    if (key_end == std::string::npos) break;
    const std::size_t colon = text.find(':', key_end + 1);
    if (colon == std::string::npos) break;
    std::size_t cursor = colon + 1;
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) {
      ++cursor;
    }
    std::string value;
    if (cursor < text.size() && text[cursor] == '"') {
      const std::size_t value_end = text.find('"', cursor + 1);
      if (value_end == std::string::npos) break;
      value = text.substr(cursor + 1, value_end - cursor - 1);
      pos = value_end + 1;
    } else {
      std::size_t value_end = cursor;
      while (value_end < text.size() &&
             std::isdigit(static_cast<unsigned char>(text[value_end]))) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::uint64_t vector_num(const Fields& fields, const std::string& key) {
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.empty()) {
    std::fprintf(stderr, "[%s] missing numeric field %s\n", vector_current.c_str(), key.c_str());
    ++failures;
    return 0;
  }
  return std::strtoull(it->second.c_str(), nullptr, 10);
}

std::vector<std::uint8_t> vector_hex(const Fields& fields, const std::string& key) {
  std::vector<std::uint8_t> out;
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.size() % 2 != 0) {
    std::fprintf(stderr, "[%s] missing hex field %s\n", vector_current.c_str(), key.c_str());
    ++failures;
    return out;
  }
  for (std::size_t i = 0; i < it->second.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::strtoul(it->second.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> vector_hex_array(const Fields& fields, const std::string& key) {
  std::array<std::uint8_t, N> out{};
  const auto bytes = vector_hex(fields, key);
  if (bytes.size() == N) {
    std::copy(bytes.begin(), bytes.end(), out.begin());
  } else {
    std::fprintf(stderr, "[%s] field %s is not %zu bytes\n", vector_current.c_str(), key.c_str(), N);
    ++failures;
  }
  return out;
}

ByteView vector_view(const std::vector<std::uint8_t>& bytes) {
  return ByteView{bytes.data(), bytes.size()};
}

bool vector_check_object(const std::vector<std::uint8_t>& object, const Fields& fields) {
  RevocationSet set{};
  bool verified = false;
  const Status status = revocation_object_verify(
      vector_view(object), vector_hex_array<kP256PublicKeySize>(fields, "signer_pubkey_hex"),
      vector_num(fields, "site_id"), vector_num(fields, "network"), set, verified);
  CHECK(status.ok());
  CHECK(verified);
  CHECK(set.rs_epoch == static_cast<std::uint32_t>(vector_num(fields, "rs_epoch")));
  CHECK(set.count == static_cast<std::uint8_t>(vector_num(fields, "count")));
  return status.ok() && verified;
}

void test_revocation_wire_vectors() {
  const std::filesystem::path dir =
      std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "revocation" / "valid";
  std::size_t count = 0;
  std::vector<std::uint8_t> reassembled;
  std::array<std::uint8_t, 32> chunk_hash{};
  bool chunk_hash_set = false;
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() == ".json") files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  for (const auto& path : files) {
    ++count;
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    const Fields fields = parse_vector_json(buffer.str());
    vector_current = path.filename().string();
    const std::string& codec = fields.at("codec");
    if (codec == "rrs_state_epochs") {
      const StateEpochs epochs{static_cast<std::uint32_t>(vector_num(fields, "site_epoch")),
                               static_cast<std::uint32_t>(vector_num(fields, "applied_rs_epoch")),
                               static_cast<std::uint32_t>(vector_num(fields, "gk_epoch"))};
      std::array<std::uint8_t, kStateEpochsSize> raw{};
      CHECK_OK(state_epochs_encode(epochs, raw));
      const auto want = vector_hex(fields, "body_hex");
      CHECK(want.size() == raw.size() &&
            std::memcmp(want.data(), raw.data(), raw.size()) == 0);
      StateEpochs back{};
      CHECK_OK(state_epochs_decode(vector_view(want), back));
      CHECK(back.site_epoch == epochs.site_epoch &&
            back.applied_rs_epoch == epochs.applied_rs_epoch &&
            back.gk_epoch == epochs.gk_epoch);
    } else if (codec == "rrs_request") {
      const RrsRequest request{static_cast<std::uint32_t>(vector_num(fields, "site_epoch")),
                               static_cast<std::uint32_t>(vector_num(fields, "have_rs_epoch"))};
      std::array<std::uint8_t, kRrsRequestSize> raw{};
      CHECK_OK(rrs_request_encode(request, raw));
      const auto want = vector_hex(fields, "body_hex");
      CHECK(want.size() == raw.size() &&
            std::memcmp(want.data(), raw.data(), raw.size()) == 0);
      RrsRequest back{};
      CHECK_OK(rrs_request_decode(vector_view(want), back));
      CHECK(back.site_epoch == request.site_epoch &&
            back.have_rs_epoch == request.have_rs_epoch);
    } else if (codec == "rrs_applied") {
      const RrsApplied applied{static_cast<std::uint32_t>(vector_num(fields, "rs_epoch")),
                               vector_hex_array<32>(fields, "object_sha256_hex")};
      std::array<std::uint8_t, kRrsAppliedSize> raw{};
      CHECK_OK(rrs_applied_encode(applied, raw));
      const auto want = vector_hex(fields, "body_hex");
      CHECK(want.size() == raw.size() &&
            std::memcmp(want.data(), raw.data(), raw.size()) == 0);
      RrsApplied back{};
      CHECK_OK(rrs_applied_decode(vector_view(want), back));
      CHECK(back.rs_epoch == applied.rs_epoch && back.object_sha256 == applied.object_sha256);
    } else if (codec == "rrs_get") {
      const RrsGet get{static_cast<std::uint32_t>(vector_num(fields, "wanted_rs_epoch"))};
      std::array<std::uint8_t, kRrsGetSize> raw{};
      CHECK_OK(rrs_get_encode(get, raw));
      const auto want = vector_hex(fields, "body_hex");
      CHECK(want.size() == raw.size() &&
            std::memcmp(want.data(), raw.data(), raw.size()) == 0);
      RrsGet back{99};
      CHECK_OK(rrs_get_decode(vector_view(want), back));
      CHECK(back.wanted_rs_epoch == get.wanted_rs_epoch);
    } else if (codec == "rrs_notice_accepted") {
      const RrsNoticeAccepted accepted{
          static_cast<std::uint32_t>(vector_num(fields, "rs_epoch")),
          vector_hex_array<32>(fields, "notice_sha256_hex")};
      std::array<std::uint8_t, kRrsNoticeAcceptedSize> raw{};
      CHECK_OK(rrs_notice_accepted_encode(accepted, raw));
      const auto want = vector_hex(fields, "body_hex");
      CHECK(want.size() == raw.size() &&
            std::memcmp(want.data(), raw.data(), raw.size()) == 0);
      RrsNoticeAccepted back{};
      CHECK_OK(rrs_notice_accepted_decode(vector_view(want), back));
      CHECK(back.rs_epoch == accepted.rs_epoch && back.notice_sha256 == accepted.notice_sha256);
    } else if (codec == "rrs1_object") {
      const auto object = vector_hex(fields, "object_hex");
      const auto payload = vector_hex(fields, "payload_hex");
      RevocationSet set{};
      CHECK_OK(revocation_payload_decode(vector_view(payload), set));
      CHECK(set.count == static_cast<std::uint8_t>(vector_num(fields, "count")));
      CHECK(set.rs_epoch == static_cast<std::uint32_t>(vector_num(fields, "rs_epoch")));
      vector_check_object(object, fields);
    } else if (codec == "rrs_kind6_manifest") {
      autonomy::ControlObjectPayload payload{};
      payload.kind = autonomy::ControlObjectKind::RevocationSet;
      payload.total_len = static_cast<std::uint16_t>(vector_num(fields, "total_len"));
      payload.object_hash = vector_hex_array<32>(fields, "object_sha256_hex");
      autonomy::EncodedPayload raw{};
      CHECK_OK(autonomy::control_object_encode(payload, raw));
      const auto want = vector_hex(fields, "manifest_hex");
      CHECK(raw.size == want.size() &&
            std::memcmp(raw.bytes.data(), want.data(), want.size()) == 0);
      autonomy::ControlObjectPayload back{};
      CHECK_OK(autonomy::control_object_decode(vector_view(want), back));
      CHECK(back.kind == autonomy::ControlObjectKind::RevocationSet);
      CHECK(back.total_len == payload.total_len && back.object_hash == payload.object_hash);
      // The manifest content is a real SAK-signed RRS1 object.
      const auto object = vector_hex(fields, "object_hex");
      CHECK(object.size() == payload.total_len);
      ScopeDigest digest{};
      sha256(vector_view(object), digest);
      CHECK(std::memcmp(digest.data(), payload.object_hash.data(), digest.size()) == 0);
      vector_check_object(object, fields);
    } else if (codec == "rrs_kind6_chunk") {
      autonomy::ObjectChunkPayload payload{};
      payload.object_hash = vector_hex_array<32>(fields, "object_sha256_hex");
      payload.offset = static_cast<std::uint16_t>(vector_num(fields, "offset"));
      const auto data = vector_hex(fields, "data_hex");
      CHECK(data.size() == static_cast<std::size_t>(vector_num(fields, "length")));
      CHECK(data.size() <= payload.data.size());
      std::copy(data.begin(), data.end(), payload.data.begin());
      payload.data_size = static_cast<std::uint16_t>(data.size());
      autonomy::EncodedPayload raw{};
      CHECK_OK(autonomy::object_chunk_encode(payload, raw));
      const auto want = vector_hex(fields, "chunk_hex");
      CHECK(raw.size == want.size() &&
            std::memcmp(raw.bytes.data(), want.data(), want.size()) == 0);
      autonomy::ObjectChunkPayload back{};
      CHECK_OK(autonomy::object_chunk_decode(vector_view(want), back));
      CHECK(back.offset == payload.offset && back.data_size == payload.data_size);
      CHECK(back.object_hash == payload.object_hash);
      // Collect for the reassembly check below (offsets must tile).
      if (!chunk_hash_set) {
        chunk_hash = payload.object_hash;
        chunk_hash_set = true;
      }
      CHECK(back.object_hash == chunk_hash);
      CHECK(back.offset == reassembled.size());
      reassembled.insert(reassembled.end(), data.begin(), data.end());
    } else {
      std::fprintf(stderr, "[%s] unknown codec %s\n", vector_current.c_str(), codec.c_str());
      ++failures;
    }
  }
  CHECK(count == 15);
  // The chunks reassemble to the manifest's object bytes.
  ScopeDigest digest{};
  sha256(vector_view(reassembled), digest);
  CHECK(chunk_hash_set);
  CHECK(std::memcmp(digest.data(), chunk_hash.data(), digest.size()) == 0);

  const std::filesystem::path bad_dir =
      std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "revocation" / "invalid";
  std::size_t bad_count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(bad_dir)) {
    if (entry.path().extension() != ".json") continue;
    ++bad_count;
    std::ifstream in(entry.path());
    std::stringstream buffer;
    buffer << in.rdbuf();
    const Fields fields = parse_vector_json(buffer.str());
    vector_current = entry.path().filename().string();
    const auto encoded = vector_hex(fields, "encoded_hex");
    const std::string& codec = fields.at("codec");
    if (codec == "rrs_state_epochs") {
      StateEpochs out{};
      CHECK(!state_epochs_decode(vector_view(encoded), out));
    } else if (codec == "rrs_request") {
      RrsRequest out{};
      CHECK(!rrs_request_decode(vector_view(encoded), out));
    } else if (codec == "rrs_applied") {
      RrsApplied out{};
      CHECK(!rrs_applied_decode(vector_view(encoded), out));
    } else if (codec == "rrs_get") {
      RrsGet out{};
      CHECK(!rrs_get_decode(vector_view(encoded), out));
    } else if (codec == "rrs_notice_accepted") {
      RrsNoticeAccepted out{};
      CHECK(!rrs_notice_accepted_decode(vector_view(encoded), out));
    } else if (codec == "rrs_kind6_manifest") {
      autonomy::ControlObjectPayload out{};
      const Status decoded = autonomy::control_object_decode(vector_view(encoded), out);
      CHECK(!decoded || out.kind != autonomy::ControlObjectKind::RevocationSet);
    } else if (codec == "rrs_kind6_chunk") {
      autonomy::ObjectChunkPayload out{};
      CHECK(!autonomy::object_chunk_decode(vector_view(encoded), out));
    } else {
      std::fprintf(stderr, "[%s] unknown codec %s\n", vector_current.c_str(), codec.c_str());
      ++failures;
    }
  }
  CHECK(bad_count == 33);
  vector_current.clear();
}

// V1-R05/R06: no unverified hint may start erasure; a valid signed notice
// must leave a durable Removing intent before any site secret is deleted.
ByteBuffer<kRemovalNoticeObjectSize> signed_removal_notice(std::uint32_t generation,
                                                           std::uint32_t rs_epoch) {
  ByteBuffer<kRemovalNoticePayloadSize> payload{};
  CHECK_OK(removal_notice_payload_encode(
      RemovalNotice{RevocationReason::Removed, kSiteId, kNode, generation, rs_epoch}, payload));
  ByteBuffer<kRemovalNoticeAadSize> aad{};
  CHECK_OK(removal_notice_aad(kNetwork, aad));
  Es256Signature signature{};
  sign_payload(sak(), payload.view(), aad.view(), signature);
  ByteBuffer<kRemovalNoticeObjectSize> object{};
  CHECK_OK(removal_notice_assemble(payload.view(),
                                   ByteView{signature.data(), signature.size()}, object));
  return object;
}

void test_removal_preserves_stored_floor() {
  NodeFixture f{};
  CHECK(f.provision(2, 0, 2, 40));
  CHECK(f.snap().phase == LifecyclePhase::BootGate);
  const auto notice = signed_removal_notice(2, 14);
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(notice.view()), 100));
  CHECK(f.journal.has_record());
  CHECK(f.journal.record().rs_floor >= 40);
}

void test_removal_resumes_with_corrupt_cleared_site_sibling() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  const auto notice = signed_removal_notice(2, 14);
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(notice.view()), 100));
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
  CHECK_OK(f.site.clear());
  f.site_storage.slot(1)[40] ^= 1;
  CHECK(!f.site.initialize());
  CHECK(!f.site.has_site() && f.site.uncertain());
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 200));
  CHECK(f.snap().phase == LifecyclePhase::Removing);
  for (int i = 0; i < 24; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 201 + i));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
}

void test_removal_blocks_when_both_site_slots_are_corrupt() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  const auto notice = signed_removal_notice(2, 14);
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(notice.view()), 100));
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
  f.site_storage.slot(0)[40] ^= 1;
  f.site_storage.slot(1)[40] ^= 1;
  CHECK(!f.site.initialize());
  CHECK(f.site.quarantined());
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 200));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
}

void test_holdoff_blocks_on_corrupt_stores() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  const auto notice = signed_removal_notice(2, 14);
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(notice.view()), 100));
  for (int i = 0; i < 24; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 101 + i));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  f.rrs_storage.slot(0)[20] ^= 1;
  f.rrs_storage.slot(1)[20] ^= 1;
  CHECK(!f.revocations.initialize());
  CHECK(f.revocations.quarantined());
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 200));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 600200));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(f.journal.record().mode == LifecycleMode::Holdoff);
}

void test_removal_ack_queues_after_intent_without_delaying_erasure() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  const auto notice = signed_removal_notice(2, 14);
  const auto before = f.authority.sent.size();
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6,
                                                 notice.view()), 100));
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
  CHECK(f.authority.sent.size() == before + 1);
  if (f.authority.sent.size() == before + 1) {
    const auto& sent = f.authority.sent.back();
    CHECK(sent.type == kAuthorityTypeRevocation);
    RrsNoticeAccepted accepted{};
    CHECK_OK(rrs_notice_accepted_decode(ByteView{sent.body.data(), sent.body.size()}, accepted));
    Digest256 hash{};
    sha256(notice.view(), hash);
    CHECK(accepted.rs_epoch == 14 && accepted.notice_sha256 == hash);
  }
  f.authority.refuse = true;
  for (int i = 0; i < 24; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 101 + i));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
}

void test_removal_notice_intent() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  ByteBuffer<kRemovalNoticePayloadSize> payload{};
  const RemovalNotice notice{RevocationReason::Removed, kSiteId, kNode, 2, 14};
  CHECK_OK(removal_notice_payload_encode(notice, payload));
  ByteBuffer<kRemovalNoticeAadSize> aad{};
  CHECK_OK(removal_notice_aad(kNetwork, aad));
  Es256Signature sig{};
  sign_payload(sak(), payload.view(), aad.view(), sig);
  ByteBuffer<kRemovalNoticeObjectSize> signed_notice{};
  CHECK_OK(removal_notice_assemble(payload.view(), ByteView{sig.data(), sig.size()}, signed_notice));
  auto bad = signed_notice;
  bad.bytes[bad.size - 1] ^= 1;
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6, bad.view()), 100));
  CHECK(f.site.has_site());
  CHECK(!f.journal.has_record());
  ByteBuffer<kRemovalNoticeAadSize> other_aad{};
  CHECK_OK(removal_notice_aad(kNetwork + 1, other_aad));
  Es256Signature wrong_sig{};
  sign_payload(sak(), payload.view(), other_aad.view(), wrong_sig);
  ByteBuffer<kRemovalNoticeObjectSize> wrong_aad{};
  CHECK_OK(removal_notice_assemble(payload.view(), ByteView{wrong_sig.data(), wrong_sig.size()}, wrong_aad));
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6, wrong_aad.view()), 100));
  CHECK(f.site.has_site() && !f.journal.has_record());
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6,
                                                 signed_notice.view()), 101));
  CHECK(f.journal.has_record());
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
  CHECK(f.site.has_site());
  for (int i = 0; i < 24; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 200 + i));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  CHECK(f.runtime.runtime_erased && f.runtime.trust_erased);
  CHECK(!f.site.has_site() && !f.revocations.has_set());
  CHECK(f.identity.has_identity());  // RLI1 and the boot witness remain
  CHECK(f.journal.record().mode == LifecycleMode::Holdoff);
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6,
                                                 signed_notice.view()), 500));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 1000));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 600999));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 601000));
  CHECK(f.snap().phase == LifecyclePhase::UnassignedReady);
  CHECK(f.journal.record().mode == LifecycleMode::UnassignedReady);
  CHECK(f.journal.record().payload.size == 0);
  LifecycleAction action{};
  CHECK_OK(f.lifecycle.take_action(action));
  CHECK(action.tag == LifecycleActionTag::RestartUnassigned);
}

void test_removal_journal_powercuts() {
  NodeFixture fixture{};
  CHECK(fixture.provision(2, 14));
  ByteBuffer<kRemovalNoticePayloadSize> payload{};
  CHECK_OK(removal_notice_payload_encode(
      RemovalNotice{RevocationReason::Removed, kSiteId, kNode, 2, 14}, payload));
  ByteBuffer<kRemovalNoticeAadSize> aad{};
  CHECK_OK(removal_notice_aad(kNetwork, aad));
  Es256Signature signature{};
  sign_payload(sak(), payload.view(), aad.view(), signature);
  ByteBuffer<kRemovalNoticeObjectSize> object{};
  CHECK_OK(removal_notice_assemble(payload.view(), ByteView{signature.data(), signature.size()}, object));
  CHECK_OK(fixture.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6, object.view()), 1));
  const LifecycleRecord intent = fixture.journal.record();
  ByteBuffer<kLifecycleSlotBytes> encoded{};
  CHECK_OK(lifecycle_record_encode(intent, kLifecycleSeal, 1, encoded));
  for (std::size_t byte = 0; byte <= encoded.size; ++byte) {
    FaultyRecordStorage storage{kLifecycleSlotBytes};
    LifecycleStore store{storage};
    CHECK_OK(store.initialize());
    storage.cut_call = 0;
    storage.cut_bytes = byte;
    CHECK(!store.begin_removal(intent));
    LifecycleStore cold{storage};
    (void)cold.initialize();
    CHECK(!cold.has_record() || cold.record().mode == LifecycleMode::Removing);
    // Without a durable intent, the only permitted outcome is unchanged
    // membership. No tombstone is written until a verified readback.
    CHECK(fixture.site.has_site());
  }
  for (std::size_t byte = 0; byte <= encoded.size; ++byte) {
    FaultyRecordStorage storage{kLifecycleSlotBytes};
    LifecycleStore store{storage};
    CHECK_OK(store.initialize());
    CHECK_OK(store.begin_removal(intent));
    storage.cut_call = storage.write_calls;
    storage.cut_bytes = byte;
    CHECK(!store.holdoff());
    LifecycleStore cold{storage};
    (void)cold.initialize();
    CHECK(cold.has_record());
    CHECK(cold.record().mode == LifecycleMode::Removing ||
          cold.record().mode == LifecycleMode::Holdoff);
  }
  LifecycleRecord ready = intent;
  ready.mode = LifecycleMode::UnassignedReady;
  ready.payload.clear();
  CHECK_OK(lifecycle_record_encode(ready, kLifecycleSeal, 3, encoded));
  for (std::size_t call = 0; call < 4; ++call) {
    for (std::size_t byte = 0; byte <= encoded.size; ++byte) {
      FaultyRecordStorage storage{kLifecycleSlotBytes};
      LifecycleStore store{storage};
      CHECK_OK(store.initialize());
      CHECK_OK(store.begin_removal(intent));
      CHECK_OK(store.holdoff());
      storage.cut_call = storage.write_calls + call;
      storage.cut_bytes = byte;
      CHECK(!store.unassigned_ready());
      LifecycleStore cold{storage};
      (void)cold.initialize();
      CHECK(cold.has_record());
      if (cold.has_record()) {
        CHECK(cold.record().mode == LifecycleMode::Holdoff ||
              cold.record().mode == LifecycleMode::UnassignedReady);
        CHECK(cold.record().generation == intent.generation);
        CHECK(cold.commit_seq() >= 2 && cold.commit_seq() <= 3);
      }
    }
  }
}

void test_cutover_journal_powercuts(const LifecycleRecord& prepared,
                                    const LifecycleRecord& switching,
                                    const Digest256& commit_digest) {
  ByteBuffer<kLifecycleSlotBytes> encoded{};
  CHECK_OK(lifecycle_record_encode(switching, kLifecycleSeal, 2, encoded));
  for (std::size_t byte = 0; byte <= encoded.size; ++byte) {
    FaultyRecordStorage storage{kLifecycleSlotBytes};
    LifecycleStore store{storage};
    CHECK_OK(store.initialize());
    CHECK_OK(store.prepare(prepared));
    storage.cut_call = storage.write_calls;
    storage.cut_bytes = byte;
    CHECK(!store.switch_network(switching));
    LifecycleStore cold{storage};
    (void)cold.initialize();
    CHECK(cold.has_record());
    if (cold.has_record()) {
      CHECK(cold.record().mode == LifecycleMode::Prepared ||
            cold.record().mode == LifecycleMode::Switching);
      CHECK(cold.record().generation == prepared.generation);
      CHECK(cold.record().rs_floor >= prepared.rs_floor);
    }
  }

  LifecycleRecord idle = switching;
  idle.mode = LifecycleMode::Idle;
  idle.old_network = switching.new_network;
  idle.new_network = 0;
  idle.payload.clear();
  idle.payload.size = commit_digest.size();
  std::memcpy(idle.payload.bytes.data(), commit_digest.data(), commit_digest.size());
  CHECK_OK(lifecycle_record_encode(idle, kLifecycleSeal, 3, encoded));
  LifecycleRecord first_epoch_idle = idle;
  first_epoch_idle.old_network = (1ULL << 32U) |
                                 static_cast<std::uint32_t>(idle.old_network);
  CHECK_OK(lifecycle_record_encode(first_epoch_idle, kLifecycleSeal, 3, encoded));
  CHECK_OK(lifecycle_record_encode(idle, kLifecycleSeal, 3, encoded));
  for (std::size_t call = 0; call < 4; ++call) {
    for (std::size_t byte = 0; byte <= encoded.size; ++byte) {
      FaultyRecordStorage storage{kLifecycleSlotBytes};
      LifecycleStore store{storage};
      CHECK_OK(store.initialize());
      CHECK_OK(store.prepare(prepared));
      CHECK_OK(store.switch_network(switching));
      storage.cut_call = storage.write_calls + call;
      storage.cut_bytes = byte;
      CHECK(!store.finish_switch(commit_digest));
      LifecycleStore cold{storage};
      (void)cold.initialize();
      CHECK(cold.has_record());
      if (cold.has_record()) {
        CHECK(cold.record().mode == LifecycleMode::Switching ||
              cold.record().mode == LifecycleMode::Idle);
        CHECK(cold.record().generation == switching.generation);
        CHECK(cold.record().rs_floor == switching.rs_floor);
        if (cold.record().mode == LifecycleMode::Idle) {
          CHECK(cold.record().cutover_id == switching.cutover_id);
          CHECK(cold.record().revision == switching.revision);
          CHECK(cold.record().payload.size == commit_digest.size());
          CHECK(std::memcmp(cold.record().payload.bytes.data(), commit_digest.data(),
                            commit_digest.size()) == 0);
        }
      }
    }
  }
}

void test_signed_prepare_stages_without_switching() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  CHECK_OK(f.site.commit(f.site.site()));  // both RLS1 slots hold a valid old membership
  const NetworkId next = kNetwork + (1ULL << 32U);
  const auto site_cert = issue(sitecert_claims(next), site_ca());
  const auto member_cert = issue(membercert_claims(2, next), sak());
  SitePackage package{};
  package.site_id = kSiteId;
  package.network = next;
  package.gk_epoch = f.site.site().gk_epoch_current + 1;
  package.gk.fill(0x51);
  package.channel = f.site.site().channel;
  package.channel_epoch = f.site.site().channel_epoch;
  package.role = f.site.site().role;
  package.gateway_count = f.site.site().gateway_count;
  package.gateways = f.site.site().gateways;
  ByteBuffer<kSitePackageSize> encoded{};
  CHECK_OK(site_package_encode(package, encoded));
  std::array<std::uint8_t, kGrantRenewHeadSize> head{};
  CHECK_OK(grant_renew_head_encode({GrantRenewPhase::Prepare, 7, 1, kNetwork}, head));
  std::array<std::uint8_t, kGrantPrepareMax> wire{};
  std::memcpy(wire.data(), head.data(), head.size());
  auto put16 = [&](std::size_t pos, std::size_t n) {
    wire[pos] = static_cast<std::uint8_t>(n >> 8U);
    wire[pos + 1] = static_cast<std::uint8_t>(n);
  };
  for (int i = 0; i < 8; ++i) wire[24 + i] = static_cast<std::uint8_t>(next >> (56 - 8 * i));
  put16(32, site_cert.size);
  put16(34, member_cert.size);
  std::size_t pos = 36;
  std::memcpy(wire.data() + pos, site_cert.bytes.data(), site_cert.size); pos += site_cert.size;
  std::memcpy(wire.data() + pos, member_cert.bytes.data(), member_cert.size); pos += member_cert.size;
  std::memcpy(wire.data() + pos, encoded.bytes.data(), encoded.size); pos += encoded.size;
  std::memset(wire.data() + pos, 0x62, 32); pos += 32;
  wire[36 + site_cert.size - 1] ^= 1;  // Site CA signature, not a transport hint
  CHECK(!f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7,
                                                   ByteView{wire.data(), pos}), 199));
  CHECK(!f.journal.has_record());
  wire[36 + site_cert.size - 1] ^= 1;
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7,
                                                  ByteView{wire.data(), pos}), 200));
  CHECK(f.journal.has_record());
  CHECK(f.journal.record().mode == LifecycleMode::Prepared);
  const LifecycleRecord prepared_intent = f.journal.record();
  const std::size_t package_offset = 36 + site_cert.size + member_cert.size;
  wire[15] = 2;  // a newer revision cannot reuse an issued GK epoch
  wire[package_offset + 28] ^= 1;
  CHECK(!f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7,
                                               ByteView{wire.data(), pos}), 200));
  CHECK(f.journal.record().revision == 1);
  wire[package_offset + 28] ^= 1;
  wire[15] = 1;
  NodeFixture retry{};
  CHECK(retry.provision(2, 14));
  CHECK_OK(retry.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7,
                                                      ByteView{wire.data(), pos}), 200));
  const auto old_network_rrs = revocation_object(revocation_set(15, 2, 2, kNetwork));
  CHECK_OK(retry.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2),
                                                      kAuthorityTypeRevocation,
                                                      old_network_rrs.view()), 201));
  retry.pump(202);
  CHECK(retry.snap().phase == LifecyclePhase::Prepared);
  CHECK_OK(retry.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7,
                                                      ByteView{wire.data(), pos}), 203));
  CHECK(retry.journal.record().revision == 1);
  CHECK(f.site.site().network == kNetwork);
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 201));
  CHECK(f.site.site().network == kNetwork);
  CHECK(f.snap().phase == LifecyclePhase::Prepared);
  NodeFixture removed{};
  CHECK(removed.provision(2, 14));
  CHECK_OK(removed.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7,
                                                        ByteView{wire.data(), pos}), 200));
  ByteBuffer<kRemovalNoticePayloadSize> notice_payload{};
  CHECK_OK(removal_notice_payload_encode(
      RemovalNotice{RevocationReason::Removed, kSiteId, kNode, 2, 14}, notice_payload));
  ByteBuffer<kRemovalNoticeAadSize> notice_aad{};
  CHECK_OK(removal_notice_aad(kNetwork, notice_aad));
  Es256Signature notice_sig{};
  sign_payload(sak(), notice_payload.view(), notice_aad.view(), notice_sig);
  ByteBuffer<kRemovalNoticeObjectSize> notice{};
  CHECK_OK(removal_notice_assemble(notice_payload.view(),
                                    ByteView{notice_sig.data(), notice_sig.size()}, notice));
  CHECK_OK(removed.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6,
                                                      notice.view()), 201));
  CHECK(removed.journal.record().mode == LifecycleMode::Removing);
  CHECK(removed.snap().phase == LifecyclePhase::Removing);

  auto rrs = revocation_object(revocation_set(15, 0, static_cast<std::uint32_t>(next >> 32U), next));
  Digest256 rrs_hash{};
  sha256(rrs.view(), rrs_hash);
  std::array<std::uint8_t, kCutoverPayloadSize> payload{};
  payload[0] = 1;
  auto put32 = [&](std::size_t offset, std::uint32_t n) {
    for (int i = 0; i < 4; ++i) payload[offset + i] = static_cast<std::uint8_t>(n >> (24 - 8 * i));
  };
  auto put64 = [&](std::size_t offset, std::uint64_t n) {
    for (int i = 0; i < 8; ++i) payload[offset + i] = static_cast<std::uint8_t>(n >> (56 - 8 * i));
  };
  put64(4, kSiteId); put64(12, kNetwork); put64(20, next); put64(28, 7);
  put32(36, 1); put32(40, package.gk_epoch); put32(44, 15);
  std::memcpy(payload.data() + 48, rrs_hash.data(), 32);
  std::array<std::uint8_t, kCutoverAadSize> aad{};
  CHECK_OK(cutover_commit_aad(kNetwork, aad));
  Es256Signature signature{};
  sign_payload(sak(), ByteView{payload.data(), payload.size()},
               ByteView{aad.data(), aad.size()}, signature);
  std::array<std::uint8_t, kCutoverObjectSize> proof{};
  std::size_t proof_size = 0;
  CHECK_OK(cose_es256_assemble(ByteView{payload.data(), payload.size()},
                               ByteView{signature.data(), signature.size()},
                               MutableByteView{proof.data(), proof.size()}, proof_size));
  CHECK(proof_size == proof.size());
  std::array<std::uint8_t, kGrantCommitMax> commit{};
  CHECK_OK(grant_renew_head_encode({GrantRenewPhase::Commit, 7, 1, kNetwork}, head));
  std::memcpy(commit.data(), head.data(), head.size());
  commit[24] = 0; commit[25] = static_cast<std::uint8_t>(proof_size);
  commit[26] = static_cast<std::uint8_t>(rrs.size >> 8U);
  commit[27] = static_cast<std::uint8_t>(rrs.size);
  std::memcpy(commit.data() + 28, proof.data(), proof_size);
  std::memcpy(commit.data() + 28 + proof_size, rrs.bytes.data(), rrs.size);
  const ByteView commit_body{commit.data(), 28 + proof_size + rrs.size};
  // Neither a wrong AAD nor an old revision can write switching intent.
  commit[16] ^= 1;
  CHECK(!f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7, commit_body), 202));
  CHECK(f.journal.record().mode == LifecycleMode::Prepared);
  commit[16] ^= 1;
  std::array<std::uint8_t, kCutoverAadSize> wrong_aad{};
  CHECK_OK(cutover_commit_aad(next, wrong_aad));
  Es256Signature wrong_sig{};
  sign_payload(sak(), ByteView{payload.data(), payload.size()},
               ByteView{wrong_aad.data(), wrong_aad.size()}, wrong_sig);
  std::array<std::uint8_t, kCutoverObjectSize> wrong_proof{};
  std::size_t wrong_size = 0;
  CHECK_OK(cose_es256_assemble(ByteView{payload.data(), payload.size()},
                               ByteView{wrong_sig.data(), wrong_sig.size()},
                               MutableByteView{wrong_proof.data(), wrong_proof.size()}, wrong_size));
  std::memcpy(commit.data() + 28, wrong_proof.data(), wrong_size);
  CHECK(!f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7, commit_body), 203));
  CHECK(f.journal.record().mode == LifecycleMode::Prepared);
  std::memcpy(commit.data() + 28, proof.data(), proof_size);
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 7, commit_body), 203));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  CHECK(f.site.site().network == kNetwork);
  Digest256 commit_digest{};
  sha256(ByteView{proof.data(), proof.size()}, commit_digest);
  test_cutover_journal_powercuts(prepared_intent, f.journal.record(), commit_digest);
  // A valid but unknown RLS1 schema may describe a newer membership. The
  // signed switching intent cannot authorize overwriting an unknown format.
  const auto site_slot0 = f.site_storage.slot(0);
  auto& unknown_site = f.site_storage.slot(0);
  const std::size_t site_used = (static_cast<std::size_t>(unknown_site[6]) << 8U) |
                                unknown_site[7];
  unknown_site[11] = 2;
  const std::uint32_t site_crc = routeloom::crc32_iso_hdlc(
      ByteView{unknown_site.data(), site_used - 4});
  for (std::size_t i = 0; i < 4; ++i)
    unknown_site[site_used - 4 + i] = static_cast<std::uint8_t>(site_crc >> (24 - 8 * i));
  CHECK(!f.site.initialize());
  CHECK(f.site.health().unsupported_mask != 0);
  CHECK(f.site.has_site());
  const std::size_t site_writes_before = f.site_storage.write_calls;
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 204));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  for (int i = 0; i < 30 && f.snap().phase == LifecyclePhase::Switching; ++i)
    (void)f.dispatch(LifecycleInput::Poll(), 205 + i);
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(f.site_storage.write_calls == site_writes_before);
  f.site_storage.slot(0) = site_slot0;
  CHECK_OK(f.site.initialize());
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 210));
  const auto rrs_slot0 = f.rrs_storage.slot(0);
  const auto rrs_slot1 = f.rrs_storage.slot(1);
  f.rrs_storage.slot(1) = rrs_slot0;
  auto& unknown_rrs = f.rrs_storage.slot(0);
  const std::size_t rrs_used = (static_cast<std::size_t>(unknown_rrs[6]) << 8U) |
                               unknown_rrs[7];
  unknown_rrs[11] = 2;
  const std::uint32_t rrs_crc = routeloom::crc32_iso_hdlc(
      ByteView{unknown_rrs.data(), rrs_used - 4});
  for (std::size_t i = 0; i < 4; ++i)
    unknown_rrs[rrs_used - 4 + i] = static_cast<std::uint8_t>(rrs_crc >> (24 - 8 * i));
  CHECK(!f.revocations.initialize());
  CHECK(f.revocations.has_set() && !f.revocations.erasure_safe());
  const std::size_t rrs_writes_before = f.rrs_storage.write_calls;
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 211));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  (void)f.dispatch(LifecycleInput::Poll(), 212);
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(f.rrs_storage.write_calls == rrs_writes_before);
  f.rrs_storage.slot(0) = rrs_slot0;
  f.rrs_storage.slot(1) = rrs_slot1;
  CHECK_OK(f.revocations.initialize());
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 213));
  CHECK(!f.dispatch(LifecycleInput::MemberReady(f.site.commit_seq(), 0), 204));
  CHECK(!f.dispatch(LifecycleInput::Recovery(true), 204));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  f.runtime.refuse = true;
  CHECK(!f.dispatch(LifecycleInput::Poll(), 204));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  f.runtime.refuse = false;
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 205));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  f.runtime.retire_wait = 2;
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 205));
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 206));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  for (int i = 0; i < 25 && f.revocations.set().network != next; ++i)
    CHECK_OK(f.dispatch(LifecycleInput::Poll(), 207 + i));
  CHECK(f.site.site().network == next && f.revocations.set().network == next);
  f.runtime.refuse = true;
  for (int i = 0; i < 3 && f.snap().phase == LifecyclePhase::Switching; ++i)
    (void)f.dispatch(LifecycleInput::Poll(), 235 + i);
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  f.runtime.refuse = false;
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 240));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  const auto retired_slot = f.journal_storage.slot(0);
  for (int i = 0; i < 40 && f.journal.record().mode == LifecycleMode::Switching; ++i)
    CHECK_OK(f.dispatch(LifecycleInput::Poll(), 241 + i));
  CHECK(f.journal.record().mode == LifecycleMode::Idle);
  const auto& idle_payload = f.journal.record().payload;
  CHECK(std::all_of(idle_payload.bytes.begin() + idle_payload.size,
                    idle_payload.bytes.end(), [](std::uint8_t byte) { return byte == 0; }));
  CHECK(f.runtime.network_retired && f.runtime.trust_installed);
  CHECK(f.site.site().network == next);
  CHECK(f.revocations.set().network == next);
  // Model a cut after the first Idle twin write: a valid Switching sibling
  // must be scrubbed before the new network can open.
  f.journal_storage.slot(0) = retired_slot;
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 250));
  CHECK(f.journal_storage.slot(0) != retired_slot);
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  CHECK(!f.lifecycle.permits(stamp_for(kPeer, 2), TrafficUse::Data));
  LifecycleAction action{};
  CHECK_OK(f.lifecycle.take_action(action));
  CHECK(action.tag == LifecycleActionTag::AdoptNetwork);
  CHECK(!f.lifecycle.permits(stamp_for(kPeer, 2), TrafficUse::Data));
  CHECK_OK(f.dispatch(LifecycleInput::ActionDone(action.token, Status::success()), 251));
  CHECK(f.snap().phase == LifecyclePhase::Active);
  // Fresh network authority binding receives APPLIED after the Owner adopts it.
  f.authority.sent.clear();
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 252));
  CHECK(f.authority.sent.size() == 1);
  if (!f.authority.sent.empty()) {
    CHECK(f.authority.sent.back().type == 7);
    CHECK(f.authority.sent.back().body[1] == 4);
    GrantReceipt receipt{};
    const auto& bytes = f.authority.sent.back().body;
    CHECK_OK(grant_receipt_decode(ByteView{bytes.data(), bytes.size()}, receipt));
    Digest256 proof_hash{};
    sha256(ByteView{proof.data(), proof.size()}, proof_hash);
    CHECK(receipt.head.old_network == kNetwork && receipt.new_network == next);
    CHECK(receipt.head.cutover_id == 7 && receipt.head.revision == 1);
    CHECK(receipt.rs_epoch == 15 && receipt.digest == proof_hash);
  }
  f.authority.sent.clear();
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 253));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  CHECK_OK(f.lifecycle.take_action(action));
  CHECK(action.tag == LifecycleActionTag::AdoptNetwork);
  CHECK_OK(f.dispatch(LifecycleInput::ActionDone(action.token, Status::success()), 254));
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 255));
  CHECK(f.authority.sent.size() == 1);
  if (!f.authority.sent.empty()) {
    CHECK(f.authority.sent.back().type == 7);
    CHECK(f.authority.sent.back().body[1] == 4);
    GrantReceipt receipt{};
    const auto& bytes = f.authority.sent.back().body;
    CHECK_OK(grant_receipt_decode(ByteView{bytes.data(), bytes.size()}, receipt));
    Digest256 proof_hash{};
    sha256(ByteView{proof.data(), proof.size()}, proof_hash);
    CHECK(receipt.head.old_network == kNetwork && receipt.new_network == next);
    CHECK(receipt.head.cutover_id == 7 && receipt.head.revision == 1);
    CHECK(receipt.rs_epoch == 15 && receipt.digest == proof_hash);
  }
  CHECK_OK(f.dispatch(LifecycleInput::Boot(false), 256));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(!f.dispatch(LifecycleInput::MemberReady(f.site.commit_seq(), 0), 257));
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 258));
  CHECK(f.snap().phase == LifecyclePhase::Switching);
  CHECK_OK(f.lifecycle.take_action(action));
  CHECK(action.tag == LifecycleActionTag::AdoptNetwork);
  CHECK_OK(f.dispatch(LifecycleInput::ActionDone(action.token, Status::success()), 259));
  CHECK(f.snap().phase == LifecyclePhase::Active);
  CHECK_OK(f.dispatch(LifecycleInput::MemberReady(f.site.commit_seq(), 0), 260));
  CHECK(f.snap().phase == LifecyclePhase::Active);
  CHECK_OK(f.dispatch(LifecycleInput::LinkFailure(kPeer, 3, 0), 261));
  CHECK(f.snap().phase == LifecyclePhase::Recovering);
  CHECK_OK(f.dispatch(LifecycleInput::Recovery(true), 262));
  CHECK(f.snap().phase == LifecyclePhase::Active);
  ByteBuffer<kRemovalNoticePayloadSize> removal_payload{};
  CHECK_OK(removal_notice_payload_encode(
      RemovalNotice{RevocationReason::Removed, kSiteId, kNode, 2, 15}, removal_payload));
  ByteBuffer<kRemovalNoticeAadSize> removal_aad{};
  CHECK_OK(removal_notice_aad(next, removal_aad));
  Es256Signature removal_sig{};
  sign_payload(sak(), removal_payload.view(), removal_aad.view(), removal_sig);
  ByteBuffer<kRemovalNoticeObjectSize> removal{};
  CHECK_OK(removal_notice_assemble(removal_payload.view(),
                                    ByteView{removal_sig.data(), removal_sig.size()}, removal));
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(removal.view()), 263));
  CHECK(f.snap().phase == LifecyclePhase::Removing);
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
}

void test_switching_intent_reboots_closed() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  LifecycleRecord prepared{};
  prepared.mode = LifecycleMode::Prepared;
  prepared.self = kNode;
  prepared.site_id = kSiteId;
  prepared.old_network = kNetwork;
  prepared.new_network = kNetwork + (1ULL << 32U);
  prepared.generation = 2;
  prepared.rs_floor = 14;
  prepared.gk_floor = f.site.site().gk_epoch_current;
  prepared.boot_witness = f.site.site().boot_witness;
  prepared.cutover_id = 3;
  prepared.revision = 1;
  prepared.payload.size = 35;
  prepared.payload.bytes[1] = 1;
  CHECK_OK(f.journal.prepare(prepared));
  LifecycleRecord switching = prepared;
  switching.mode = LifecycleMode::Switching;
  switching.payload.clear();
  switching.payload.size = 6 + 1 + 1 + kCutoverObjectSize + 32;
  switching.payload.bytes[1] = 1;
  switching.payload.bytes[3] = 1;
  switching.payload.bytes[4] = 0;
  switching.payload.bytes[5] = static_cast<std::uint8_t>(kCutoverObjectSize);
  CHECK_OK(f.journal.switch_network(switching));
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 400));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(f.snap().adopted_network == 0);
  CHECK(f.site.has_site());  // do not roll back or erase without proof
}

void test_removal_failure_after_intent_reboots_closed() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  const auto id0 = f.identity_storage.slot(0);
  const auto id1 = f.identity_storage.slot(1);
  ByteBuffer<kRemovalNoticePayloadSize> payload{};
  CHECK_OK(removal_notice_payload_encode(
      RemovalNotice{RevocationReason::Removed, kSiteId, kNode, 2, 14}, payload));
  ByteBuffer<kRemovalNoticeAadSize> aad{};
  CHECK_OK(removal_notice_aad(kNetwork, aad));
  Es256Signature sig{};
  sign_payload(sak(), payload.view(), aad.view(), sig);
  ByteBuffer<kRemovalNoticeObjectSize> notice{};
  CHECK_OK(removal_notice_assemble(payload.view(), ByteView{sig.data(), sig.size()}, notice));
  f.runtime.refuse = true;
  CHECK_OK(f.dispatch(LifecycleInput::Authority(stamp_for(kPeer, 2), 6, notice.view()), 100));
  for (int i = 0; i < 3; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 101 + i));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK(f.site.has_site());
  CHECK(f.journal.record().mode == LifecycleMode::Removing);
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 1000));
  CHECK(f.snap().phase == LifecyclePhase::Removing);
  f.runtime.refuse = false;
  for (int i = 0; i < 24; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 1001 + i));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  CHECK(f.identity_storage.slot(0) == id0 && f.identity_storage.slot(1) == id1);
}

void test_reassigned_member_can_be_removed_again() {
  NodeFixture f{};
  CHECK(f.provision(2, 14));
  const auto first = signed_removal_notice(2, 14);
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(first.view()), 100));
  for (int i = 0; i < 24; ++i) CHECK_OK(f.dispatch(LifecycleInput::Poll(), 101 + i));
  CHECK(f.snap().phase == LifecyclePhase::Holdoff);
  CHECK_OK(f.dispatch(LifecycleInput::Poll(), 600124));
  CHECK(f.snap().phase == LifecyclePhase::UnassignedReady);

  CHECK_OK(f.site.commit(site_for(kNode, 2, 14)));
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 600125));
  CHECK(f.snap().phase == LifecyclePhase::StorageBlocked);
  CHECK_OK(f.site.commit(site_for(kNode, 3, 14)));
  CHECK_OK(f.dispatch(LifecycleInput::Boot(true), 600126));
  CHECK(f.snap().phase == LifecyclePhase::BootGate);
  const auto second = signed_removal_notice(3, 15);
  CHECK_OK(f.dispatch(LifecycleInput::RemovalRequired(second.view()), 600127));
  CHECK(f.snap().phase == LifecyclePhase::Removing);
  CHECK(f.journal.record().generation == 3);

  NodeFixture live{};
  CHECK(live.provision(2, 14));
  CHECK_OK(live.dispatch(LifecycleInput::RemovalRequired(first.view()), 100));
  for (int i = 0; i < 24; ++i) CHECK_OK(live.dispatch(LifecycleInput::Poll(), 101 + i));
  CHECK_OK(live.dispatch(LifecycleInput::Poll(), 600124));
  CHECK(live.snap().phase == LifecyclePhase::UnassignedReady);
  CHECK_OK(live.site.commit(site_for(kNode, 3, 14)));
  CHECK_OK(live.dispatch(LifecycleInput::MemberReady(live.site.commit_seq(), 0), 600125));
  CHECK(live.snap().phase == LifecyclePhase::BootGate);
}

}  // namespace

int main() {
  test_lifecycle_port_bundle_lifetime();
  test_removal_preserves_stored_floor();
  test_removal_resumes_with_corrupt_cleared_site_sibling();
  test_removal_blocks_when_both_site_slots_are_corrupt();
  test_holdoff_blocks_on_corrupt_stores();
  test_removal_ack_queues_after_intent_without_delaying_erasure();
  test_removal_notice_intent();
  test_removal_failure_after_intent_reboots_closed();
  test_reassigned_member_can_be_removed_again();
  test_removal_journal_powercuts();
  test_signed_prepare_stages_without_switching();
  test_switching_intent_reboots_closed();
  test_rrs_wire_codecs();
  test_revocation_wire_vectors();
  test_boot_adoption();
  test_enforcement_storage_failure_stays_closed();
  test_boot_self_revoked_and_blocked();
  test_boot_revalidates_stored_rrs();
  test_member_ready_closes_on_floor_advance();
  test_member_ready_fetches_package_epoch_past_old_rrs();
  test_apply_does_not_ack_below_a_newer_floor();
  test_recovery_control_rejects_revoked_credentials();
  test_apply_order_and_sweep();
  test_duplicate_equivocation_stale();
  test_link_failure_and_recovery();
  test_rrs_exchange_roundtrip();
  test_rrs_exchange_timeouts_and_demux();
  test_owns_rrs_chunk_demux();
  test_reentry_is_busy_and_changelss();
  test_gossip_line_propagates();
  test_authenticated_peer_starts_and_stops_gossip();
  test_gossip_line_100_nodes_converges();
  test_gossip_rates_and_refresh();
  test_partition_continues_and_merge_converges();
  test_apply_storage_faults();
  test_uncertain_commit_rejects_different_same_epoch_object();
  test_sweep_cursor_units();
  test_sweep_scrubs_torn_slot();
  test_node_p6_branch();
  test_ram_budget();
  if (failures != 0) {
    std::fprintf(stderr, "%d p6 revocation check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_revocation_tests: ok");
  return 0;
}
