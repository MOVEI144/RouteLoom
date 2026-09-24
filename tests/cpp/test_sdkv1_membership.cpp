// P4 membership evidence (G-SEC P4 §3; V1-R04/R05/R06 local halves,
// P4-M01 hooks half): SdkMembershipHooks over adopted RLI1/RLS1/RRS1 with
// the RLV1 removal gate — Member only on complete evidence, Revoked sticky
// across reboot, unknown peers never known.

#include <cstdio>

#include "routeloom/discovery.hpp"
#include "routeloom/sdkv1_membership.hpp"

#include "test_sdkv1.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace sdkv1_test;

class FakePeers final : public AuthenticatedPeerView {
 public:
  bool authenticated(const NodeId peer, const NetworkId network, std::uint32_t& generation,
                     std::uint32_t& role) const noexcept override {
    if (network != network_ || peer != peer_) return false;
    generation = generation_;
    role = role_;
    return true;
  }
  NodeId peer_{0x00A1000000000777ULL};
  NetworkId network_{kNetwork};
  std::uint32_t generation_{1};
  std::uint32_t role_{0b011};
};

class FakeBoot final : public BootWitnessView {
 public:
  bool boot_witness_ok(const std::uint32_t witness) const noexcept override {
    return witness != 0 && witness <= boot_;
  }
  std::uint32_t boot_{2000};
};

struct World {
  FaultyRecordStorage identity_storage{kIdentitySlotBytes};
  FaultyRecordStorage site_storage{kSiteSlotBytes};
  FaultyRecordStorage revocation_storage{kRevocationSlotBytes};
  FaultyRecordStorage rlv_storage{kLocalRevocationSlotBytes};
  IdentityStore identity{identity_storage};
  SiteStore site{site_storage};
  RevocationStore revocations{revocation_storage};
  LocalRevocationStore rlv{rlv_storage};
  FakePeers peers{};
  FakeBoot boot{};

  void init_all() {
    CHECK_OK(identity.initialize());
    CHECK_OK(site.initialize());
    CHECK_OK(revocations.initialize());
    CHECK_OK(rlv.initialize());
  }
  // A fully-evidenced member: identity + site (floor 0: revocations not
  // yet fetched, which is consistent for a fresh join).
  void make_member() {
    init_all();
    CHECK_OK(identity.commit(identity_record()));
    SiteRecord site_copy = site_record();
    site_copy.rs_epoch_floor = 0;
    CHECK_OK(site.commit(site_copy));
  }
  SdkMembershipHooks hooks() {
    return SdkMembershipHooks(identity, site, revocations, rlv, &peers, &boot);
  }
};

void test_local_member_matrix() {
  {
    World world;
    world.make_member();
    SdkMembershipHooks hooks = world.hooks();
    CHECK(hooks.local_member(kNetwork));
    CHECK(!hooks.local_member(kNetwork + 1));  // another network: no evidence
    MembershipState state = MembershipState::Unprovisioned;
    CHECK_OK(hooks.local_state(kNetwork, state));
    CHECK(state == MembershipState::Member);
  }
  {  // No site record: Unprovisioned, never Member.
    World world;
    world.init_all();
    CHECK_OK(world.identity.commit(identity_record()));
    SdkMembershipHooks hooks = world.hooks();
    CHECK(!hooks.local_member(kNetwork));
    MembershipState state = MembershipState::Member;
    CHECK_OK(hooks.local_state(kNetwork, state));
    CHECK(state == MembershipState::Unprovisioned);
  }
  {  // Handle-backed keys (location 2/3) are never passed as scalars.
    World world;
    world.make_member();
    IdentityRecord handle = identity_record();
    handle.key_location = CredentialKeyLocation::SecureElement;
    CHECK_OK(world.identity.commit(handle));
    SdkMembershipHooks hooks = world.hooks();
    CHECK(!hooks.local_member(kNetwork));
  }
  {  // A removal on record blocks Member — before and after a reboot.
    World world;
    world.make_member();
    LocalRevocationRecord removal{};
    removal.state = LocalRevocationState::Blocked;
    removal.cause = LocalRevocationCause::Notice;
    removal.local_node = kNode;
    removal.site_id = kSiteId;
    removal.network = kNetwork;
    removal.removed_generation = 3;
    removal.evidence_digest.fill(0xE4);
    CHECK_OK(world.rlv.commit_blocked(removal));
    {
      SdkMembershipHooks hooks = world.hooks();
      CHECK(!hooks.local_member(kNetwork));
      MembershipState state = MembershipState::Unprovisioned;
      CHECK_OK(hooks.local_state(kNetwork, state));
      CHECK(state == MembershipState::Revoked);
    }
    // Reboot: fresh store objects over the same storage stay Revoked.
    IdentityStore identity(world.identity_storage);
    SiteStore site(world.site_storage);
    RevocationStore revocations(world.revocation_storage);
    LocalRevocationStore rlv(world.rlv_storage);
    CHECK_OK(identity.initialize());
    CHECK_OK(site.initialize());
    CHECK_OK(revocations.initialize());
    CHECK_OK(rlv.initialize());
    SdkMembershipHooks hooks(identity, site, revocations, rlv, &world.peers, &world.boot);
    MembershipState state = MembershipState::Unprovisioned;
    CHECK_OK(hooks.local_state(kNetwork, state));
    CHECK(state == MembershipState::Revoked);
  }
  {  // Cleaned + elapsed holdoff + strictly newer generation may rejoin;
    // the removed generation itself never comes back as Member.
    World world;
    world.make_member();
    LocalRevocationRecord removal{};
    removal.state = LocalRevocationState::Blocked;
    removal.cause = LocalRevocationCause::Rrs;
    removal.local_node = kNode;
    removal.site_id = kSiteId;
    removal.network = kNetwork;
    removal.removed_generation = 3;
    removal.evidence_digest.fill(0xE4);
    CHECK_OK(world.rlv.commit_blocked(removal));
    CHECK_OK(world.rlv.commit_cleaned());
    SdkMembershipHooks hooks = world.hooks();
    CHECK(!hooks.local_member(kNetwork));  // holdoff still running
    hooks.set_holdoff_elapsed(true);
    CHECK(!hooks.local_member(kNetwork));  // same generation: still out
    SiteRecord renewed = site_record(4);
    renewed.rs_epoch_floor = 0;
    CHECK_OK(world.site.commit(renewed));
    CHECK(hooks.local_member(kNetwork));  // generation 4 > removed 3
  }
  {  // Boot witness from the future (or missing view) fails closed.
    World world;
    world.make_member();
    world.boot.boot_ = 100;  // witness 1234 is ahead of us
    SdkMembershipHooks hooks = world.hooks();
    CHECK(!hooks.local_member(kNetwork));
    SdkMembershipHooks no_boot(world.identity, world.site, world.revocations, world.rlv,
                               &world.peers, nullptr);
    CHECK(!no_boot.local_member(kNetwork));
  }
}

void test_revocation_view() {
  {  // An adopted RRS1 that names this generation revokes, durably.
    World world;
    world.make_member();
    RevocationSet set = revocation_set(14, 1);
    set.entries[0] = RevocationEntry{kNode, 4, RevocationReason::Removed};
    set.count = 1;
    const auto object = revocation_object(set);
    CHECK_OK(world.revocations.accept(object.view(), sak().pub, kSiteId, kNetwork));
    SdkMembershipHooks hooks = world.hooks();
    CHECK(!hooks.local_member(kNetwork));
    MembershipState state = MembershipState::Unprovisioned;
    CHECK_OK(hooks.local_state(kNetwork, state));
    CHECK(state == MembershipState::Revoked);
  }
  {  // A set that does not name us, at/above the floor, keeps Member.
    World world;
    world.make_member();
    RevocationSet set = revocation_set(14, 1);
    const auto object = revocation_object(set);
    CHECK_OK(world.revocations.accept(object.view(), sak().pub, kSiteId, kNetwork));
    SdkMembershipHooks hooks = world.hooks();
    CHECK(hooks.local_member(kNetwork));
  }
  {  // A nonzero floor with no set behind it is a lost floor: closed.
    World world;
    world.init_all();
    CHECK_OK(world.identity.commit(identity_record()));
    CHECK_OK(world.site.commit(site_record()));  // rs_epoch_floor = 14, no RRS1
    SdkMembershipHooks hooks = world.hooks();
    CHECK(!hooks.local_member(kNetwork));
    MembershipState state = MembershipState::Unprovisioned;
    CHECK(hooks.local_state(kNetwork, state).code == StatusCode::RecoveryRequired);
    CHECK(state == MembershipState::Revoked);
  }
  {  // Unreadable storage gates as Revoked and says so (never Unprovisioned).
    World world;
    world.make_member();
    world.site_storage.read_error = true;
    SiteStore site(world.site_storage);
    CHECK(!site.initialize().ok());
    SdkMembershipHooks hooks(world.identity, site, world.revocations, world.rlv, &world.peers,
                             &world.boot);
    MembershipState state = MembershipState::Unprovisioned;
    CHECK(!hooks.local_state(kNetwork, state).ok());
    CHECK(state == MembershipState::Revoked);
    world.site_storage.disarm();
  }
}

void test_known_member() {
  World world;
  world.make_member();
  SdkMembershipHooks hooks = world.hooks();
  // This boot authenticated the peer: known.
  CHECK(hooks.known_member(0x00A1000000000777ULL, kNetwork));
  CHECK(!hooks.known_member(0x00A1000000000777ULL, kNetwork + 1));
  CHECK(!hooks.known_member(0x00A1000000000999ULL, kNetwork));  // never authenticated
  SdkMembershipHooks no_peers(world.identity, world.site, world.revocations, world.rlv, nullptr,
                              &world.boot);
  CHECK(!no_peers.known_member(0x00A1000000000777ULL, kNetwork));
  // ...until the latest RRS1 revokes it: the handshake-time summary alone
  // is not enough.
  RevocationSet set = revocation_set(14, 1);
  set.entries[0] = RevocationEntry{0x00A1000000000777ULL, 2, RevocationReason::Removed};
  set.count = 1;
  const auto object = revocation_object(set);
  CHECK_OK(world.revocations.accept(object.view(), sak().pub, kSiteId, kNetwork));
  CHECK(!hooks.known_member(0x00A1000000000777ULL, kNetwork));
}

void test_approve_join() {
  World world;
  world.make_member();
  SdkMembershipHooks hooks = world.hooks();
  CHECK(hooks.approve_join(kNode, kNetwork));  // the committed adoption re-examined
  CHECK(!hooks.approve_join(kNode + 1, kNetwork));  // a radio peer is not us
  CHECK(!hooks.approve_join(kNode, kNetwork + 1));
}

void test_controller_wiring() {
  // Revoked boots refuse discovery and authentication; the start error
  // propagates instead of starting traffic silently.
  World world;
  world.make_member();
  LocalRevocationRecord removal{};
  removal.state = LocalRevocationState::Blocked;
  removal.cause = LocalRevocationCause::Notice;
  removal.local_node = kNode;
  removal.site_id = kSiteId;
  removal.network = kNetwork;
  removal.removed_generation = 3;
  removal.evidence_digest.fill(0xE4);
  CHECK_OK(world.rlv.commit_blocked(removal));
  SdkMembershipHooks hooks = world.hooks();
  MembershipController controller{};
  MembershipState state = MembershipState::Unprovisioned;
  CHECK_OK(hooks.local_state(kNetwork, state));
  CHECK(state == MembershipState::Revoked);
  CHECK_OK(controller.initialize(hooks, kNetwork));
  CHECK(controller.state() == MembershipState::Revoked);
  CHECK(controller.begin_discovery().code == StatusCode::AuthorizationFailed);
  CHECK(controller.begin_authentication().code == StatusCode::AuthorizationFailed);
  // Legacy hooks keep the old Member/Unprovisioned behaviour through the
  // default local_state.
  World plain;
  plain.make_member();
  CHECK_OK(controller.initialize(plain.hooks(), kNetwork));
  CHECK(controller.state() == MembershipState::Member);
}

}  // namespace

int main() {
  test_local_member_matrix();
  test_revocation_view();
  test_known_member();
  test_approve_join();
  test_controller_wiring();
  if (failures != 0) {
    std::fprintf(stderr, "%d membership check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_membership_tests: ok");
  return 0;
}
