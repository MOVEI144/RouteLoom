// SDK v1 persistent stores under power-cut injection (docs/design/sdk-v1/08
// P1-3; acceptance V1-J08 store half, V1-N02 slot half):
//  - IdentityStore (RLI1, twin pair), SiteStore (RLS1, A/B), RevocationStore
//    (RRS1, A/B): a cut at EVERY byte boundary of EVERY write of commit /
//    clear / recover, then a reboot. Invariants: the adopted record is always
//    the old or the new one (never a mix); the new one is adopted only if one
//    slot fully sealed it; an unproven sibling is "uncertain" (commits refuse)
//    and noise-only slots quarantine; recover()/clear() always make progress.
//  - ordinal floors proven by CRC-failed records, Unsupported schema slots,
//    equal-sequence divergence, readback mismatch, read faults;
//  - RLS1/RRS1 semantic monotonicity; RRS1 acceptance verdicts;
//  - ResumeCache2 (RLP2) LRU/pin/validity rules, the touch wear rule,
//    the 64-use ceiling and torn-slot handling at every byte boundary.

#include <cstdio>
#include <functional>

#include "routeloom/group.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/secure_clear.hpp"
#include "routeloom/sdkv1_group_keys.hpp"
#include "routeloom/sdkv1_group_security.hpp"
#include "routeloom/sdkv1_membership.hpp"

#include "test_sdkv1.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace sdkv1_test;

// Field comparison without re-validation (the sweeps below run thousands of
// reboots; validation is exercised by every initialize()).
bool same_identity(const IdentityRecord& a, const IdentityRecord& b) {
  if (a.node_id != b.node_id || a.key_location != b.key_location || a.flags != b.flags ||
      a.kid != b.kid || a.pubkey != b.pubkey || a.key_material != b.key_material ||
      a.anchor_count != b.anchor_count || a.devcert.size != b.devcert.size ||
      std::memcmp(a.devcert.bytes.data(), b.devcert.bytes.data(), a.devcert.size) != 0) {
    return false;
  }
  for (std::uint8_t i = 0; i < a.anchor_count; ++i) {
    if (a.anchors[i].anchor_id != b.anchors[i].anchor_id || a.anchors[i].kind != b.anchors[i].kind ||
        a.anchors[i].status != b.anchors[i].status || a.anchors[i].pubkey != b.anchors[i].pubkey) {
      return false;
    }
  }
  return true;
}

// Sweep fixtures keep the private key behind an opaque handle (location 3)
// so each reboot does not recompute a P-256 public key; the location-1
// consistency check is covered in test_sdkv1_records.
IdentityRecord sweep_identity(const bool strict) {
  IdentityRecord r = identity_record(strict);
  r.key_location = CredentialKeyLocation::SecureElement;
  r.key_material.fill(0xA5);
  return r;
}

template <std::size_t N>
bool same_bytes(const ByteBuffer<N>& a, const ByteBuffer<N>& b) {
  return a.size == b.size && std::memcmp(a.bytes.data(), b.bytes.data(), a.size) == 0;
}

bool same_site(const SiteRecord& a, const SiteRecord& b) {
  return a.state == b.state && a.site_id == b.site_id && a.network == b.network &&
         a.assignment_generation == b.assignment_generation &&
         a.rs_epoch_floor == b.rs_epoch_floor && a.gk_epoch_current == b.gk_epoch_current &&
         a.gk_epoch_next == b.gk_epoch_next && a.gk_current == b.gk_current &&
         a.gk_next == b.gk_next && a.dams == b.dams && a.role == b.role &&
         a.gateway_count == b.gateway_count && a.channel == b.channel &&
         a.channel_epoch == b.channel_epoch && a.boot_witness == b.boot_witness &&
         a.gateways == b.gateways && same_bytes(a.site_cert, b.site_cert) &&
         same_bytes(a.member_cert, b.member_cert);
}

// Rewrite one byte of a stored sealed record and repair its CRC.
void patch(std::vector<std::uint8_t>& slot, const std::size_t offset, const std::uint8_t value) {
  slot[offset] = value;
  const std::size_t used_len = (static_cast<std::size_t>(slot[6]) << 8U) | slot[7];
  const std::uint32_t crc = crc32_iso_hdlc(ByteView{slot.data(), used_len - 4});
  for (std::size_t i = 0; i < 4; ++i) {
    slot[used_len - 4 + i] = static_cast<std::uint8_t>(crc >> (24U - 8U * i));
  }
}

// Outcome of one "cut then reboot" run.
enum class Outcome { Old, New, Fresh, Uncertain, Quarantined };

// --- IdentityStore -------------------------------------------------------------

IdentityRecord identity_variant() {
  IdentityRecord r = sweep_identity(true);
  r.flags = kIdentityFlagStrictAssignment;  // a different, valid record
  return r;
}

void test_identity_basic() {
  FaultyRecordStorage storage(kIdentitySlotBytes);
  {
    IdentityStore store(storage);
    CHECK_OK(store.initialize());
    CHECK(!store.has_identity() && !store.quarantined() && !store.uncertain());
    CHECK_OK(store.commit(identity_record()));
    CHECK(store.has_identity());
    CHECK(std::memcmp(storage.slot(0).data(), storage.slot(1).data(), kIdentitySlotBytes) == 0);
    // Invalid records never reach storage.
    IdentityRecord bad = identity_record();
    bad.kid[0] ^= 1;
    const std::size_t writes = storage.write_calls;
    CHECK(!store.commit(bad).ok());
    CHECK(storage.write_calls == writes);
  }
  IdentityStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.has_identity() && same_identity(reboot.identity(), identity_record()));
  // recover() is only for impaired stores.
  CHECK(reboot.recover(identity_record()).code == StatusCode::InvalidState);
}

void test_identity_power_cuts() {
  // Replace an existing identity (or write the first one) with a cut at every
  // byte of each of the four writes (pending/seal x slot 0/1).
  for (const bool has_old : {false, true}) {
    const IdentityRecord old_record = sweep_identity(false);
    const IdentityRecord new_record = identity_variant();
    ByteBuffer<kIdentitySlotBytes> encoded{};
    CHECK_OK(identity_record_encode(new_record, kIdentitySealCommitted, encoded));
    const std::size_t len = encoded.size;
    for (std::size_t call = 0; call < 4; ++call) {
      for (std::size_t boundary = 0; boundary <= len; ++boundary) {
        FaultyRecordStorage storage(kIdentitySlotBytes);
        std::size_t base = 0;
        {
          IdentityStore store(storage);
          CHECK_OK(store.initialize());
          if (has_old) CHECK_OK(store.commit(old_record));
          base = storage.write_calls;
          storage.cut_call = base + call;
          storage.cut_bytes = boundary;
          CHECK(store.commit(new_record).code == StatusCode::StorageFailure);
        }
        storage.disarm();
        IdentityStore reboot(storage);
        const Status loaded = reboot.initialize();
        Outcome outcome = Outcome::Fresh;
        if (reboot.quarantined()) {
          outcome = Outcome::Quarantined;
        } else if (reboot.uncertain()) {
          outcome = Outcome::Uncertain;
        } else if (reboot.has_identity()) {
          outcome = same_identity(reboot.identity(), new_record) ? Outcome::New : Outcome::Old;
        }
        if (reboot.has_identity()) {
          CHECK(same_identity(reboot.identity(), new_record) ||
                (has_old && same_identity(reboot.identity(), old_record)));
        }
        // The new identity is adopted only once slot 0 fully sealed it.
        const bool slot0_sealed = call > 1 || (call == 1 && boundary == len);
        if (!slot0_sealed && reboot.has_identity()) {
          CHECK(has_old && same_identity(reboot.identity(), old_record));
        }
        CHECK(loaded.ok() == (outcome == Outcome::Old || outcome == Outcome::New ||
                              outcome == Outcome::Fresh));
        // A fully sealed twin pair survives cleanly.
        if (call == 3 && boundary == len) CHECK(outcome == Outcome::New);
        // Progress: impaired -> recover, otherwise commit.
        if (outcome == Outcome::Uncertain || outcome == Outcome::Quarantined) {
          CHECK(reboot.commit(new_record).code != StatusCode::Ok);
          CHECK_OK(reboot.recover(new_record));
        } else {
          CHECK_OK(reboot.commit(new_record));
        }
        IdentityStore again(storage);
        CHECK_OK(again.initialize());
        CHECK(same_identity(again.identity(), new_record));
      }
    }
  }
}

void test_identity_divergent_twins_quarantine() {
  FaultyRecordStorage storage(kIdentitySlotBytes);
  {
    IdentityStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(identity_record()));
  }
  // Slot 1 holds a different valid identity: cannot be ordered.
  FaultyRecordStorage other(kIdentitySlotBytes);
  {
    IdentityStore store(other);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(identity_variant()));
  }
  storage.slot(1) = other.slot(1);
  IdentityStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined() && !reboot.has_identity());
  CHECK(reboot.commit(identity_record()).code == StatusCode::IntegrityError);
  CHECK_OK(reboot.recover(identity_record()));
}

// --- SiteStore -----------------------------------------------------------------

SiteRecord rotated(const SiteRecord& base, const std::uint32_t gk_epoch) {
  SiteRecord r = base;
  r.gk_epoch_current = gk_epoch;
  for (std::size_t i = 0; i < 32; ++i) r.gk_current[i] = static_cast<std::uint8_t>(i + gk_epoch);
  return r;
}

void test_site_monotonicity() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(!store.has_site());
  const SiteRecord base = site_record();
  CHECK_OK(store.commit(base));
  CHECK(store.commit_seq() == 1);
  CHECK_OK(store.commit(rotated(base, 204)));
  CHECK(store.commit_seq() == 2);
  CHECK(store.commit(rotated(base, 203)).code == StatusCode::Conflict);  // gk regress
  SiteRecord r = rotated(base, 205);
  r.rs_epoch_floor = 13;
  CHECK(store.commit(r).code == StatusCode::Conflict);
  r = rotated(base, 205);
  r.boot_witness = 1;
  CHECK(store.commit(r).code == StatusCode::Conflict);
  r = site_record(2, 205);  // assignment generation regress
  CHECK(store.commit(r).code == StatusCode::Conflict);
  r = rotated(site_record(3, 205), 205);
  r.site_id = kSiteId + 1;
  CHECK(!store.commit(r).ok());
  // Same site_epoch, different network: refused; a cutover (epoch+1) with a
  // re-issued MemberCert is accepted; going back is refused.
  const NetworkId same_epoch_other = (NetworkId{kSiteEpoch} << 32U) | (kNetworkLow + 1);
  CHECK(store.commit(site_record(3, 205, same_epoch_other)).code == StatusCode::Conflict);
  const NetworkId cutover = (NetworkId{kSiteEpoch + 1} << 32U) | kNetworkLow;
  CHECK_OK(store.commit(site_record(3, 205, cutover)));
  CHECK(store.commit(site_record(3, 206)).code == StatusCode::Conflict);
  // Tombstone.
  CHECK(store.commit(SiteRecord{}).code == StatusCode::InvalidArgument);
  CHECK_OK(store.clear());
  CHECK(!store.has_site());
  CHECK(storage.slot(0) == storage.slot(1));  // no GK/DAMS copy survives
  SiteStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(!reboot.has_site() && !reboot.uncertain());
  // After removal a fresh (lower-generation, other-site) join is fine.
  SiteRecord fresh = site_record(1, 1);
  CHECK_OK(reboot.commit(fresh));
  SiteStore reboot2(storage);
  CHECK_OK(reboot2.initialize());
  CHECK(reboot2.has_site() && same_site(reboot2.site(), fresh));
}

// Generic cut sweep over a sequenced store operation.
void site_sweep(const char* label, const std::size_t writes,
                const std::function<Status(SiteStore&)>& operation, const bool expect_twin,
                const SiteRecord& old_record, const SiteRecord* new_record) {
  ByteBuffer<kSiteSlotBytes> encoded{};
  CHECK_OK(site_record_encode(new_record != nullptr ? *new_record : SiteRecord{},
                              kSiteSealCommitted, 1, encoded));
  const std::size_t len = encoded.size;
  for (std::size_t call = 0; call < writes; ++call) {
    for (std::size_t boundary = 0; boundary <= len; ++boundary) {
      FaultyRecordStorage storage(kSiteSlotBytes);
      {
        SiteStore store(storage);
        CHECK_OK(store.initialize());
        CHECK_OK(store.commit(old_record));
        CHECK_OK(store.commit(rotated(old_record, old_record.gk_epoch_current + 1)));
        storage.cut_call = storage.write_calls + call;
        storage.cut_bytes = boundary;
        CHECK(operation(store).code == StatusCode::StorageFailure);
      }
      storage.disarm();
      SiteStore reboot(storage);
      const Status loaded = reboot.initialize();
      const SiteRecord previous = rotated(old_record, old_record.gk_epoch_current + 1);
      const bool is_new = reboot.has_site()
                              ? (new_record != nullptr && same_site(reboot.site(), *new_record))
                              : (new_record == nullptr && !reboot.uncertain() &&
                                 !reboot.quarantined() && loaded.ok());
      const bool is_old = reboot.has_site() && same_site(reboot.site(), previous);
      // Never a mixed or foreign record.
      if (reboot.has_site()) CHECK(is_new || is_old);
      // New state requires one fully sealed slot (write 1 of the first slot).
      const bool first_sealed = call > 1 || (call == 1 && boundary == len);
      if (!first_sealed) {
        CHECK(!is_new || new_record == nullptr);
        if (new_record == nullptr) CHECK(is_old || reboot.uncertain());
      }
      if (!reboot.quarantined()) CHECK(reboot.commit_seq() >= 2);
      // Twin writes completed: clean new state.
      if (expect_twin && call == writes - 1 && boundary == len) {
        CHECK(loaded.ok() && is_new);
      }
      // Recovery path always makes progress to a known newer record.
      SiteRecord next = rotated(old_record, old_record.gk_epoch_current + 5);
      if (reboot.uncertain() || reboot.quarantined()) {
        CHECK(reboot.commit(next).code != StatusCode::Ok);
        CHECK_OK(reboot.recover(next));
      } else {
        CHECK_OK(reboot.commit(next));
      }
      SiteStore again(storage);
      if (!again.initialize().ok() || !same_site(again.site(), next)) {
        std::fprintf(stderr, "%s: no progress after cut call=%zu boundary=%zu\n", label, call,
                     boundary);
        ++failures;
      }
    }
  }
}

void test_group_key_durable_rotation() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord base = site_record();
  CHECK_OK(store.commit(base));
  keys::Secret next{};
  next.fill(0xA5);
  CHECK_OK(store.stage_group_key(base.gk_epoch_current + 2, next));
  CHECK(store.site().gk_epoch_next == base.gk_epoch_current + 2);
  CHECK(store.stage_group_key(base.gk_epoch_current + 2, next).ok());
  next[0] ^= 1;
  CHECK(store.stage_group_key(base.gk_epoch_current + 2, next).code == StatusCode::Conflict);
  CHECK(store.stage_group_key(base.gk_epoch_current + 1, next).code == StatusCode::Conflict);
  next[0] ^= 1;
  CHECK_OK(store.activate_group_key(base.gk_epoch_current + 2, base.boot_witness));
  CHECK(storage.slot(0) == storage.slot(1));  // no retired GK in either logical slot
  CHECK(store.site().gk_epoch_next == 0);
  SiteStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(!reboot.group_scrub_needed());
  SiteRecord forged = reboot.site();
  forged.gk_current[0] ^= 1;
  CHECK(reboot.commit(forged).code == StatusCode::Conflict);
  forged = reboot.site();
  forged.gk_epoch_next = base.gk_epoch_current + 1;
  forged.gk_next = next;
  CHECK(reboot.commit(forged).code == StatusCode::Conflict);
}

void test_group_stage_failure_fences_generic_writers() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  keys::Secret next{};
  next.fill(0xA5);
  const auto& slot = storage.slot(0);
  storage.cut_call = storage.write_calls + 1;  // sealed stage write lands, ACK fails
  storage.cut_bytes = (static_cast<std::size_t>(slot[6]) << 8U) | slot[7];
  CHECK(store.stage_group_key(site.gk_epoch_current + 1, next).code ==
        StatusCode::StorageFailure);
  storage.disarm();
  sdkv1::GroupKeyState stale_view(store);
  sdkv1::GroupKeyState::Input start{};
  start.op = sdkv1::GroupKeyState::Op::Start;
  start.boot = site.boot_witness;
  CHECK(stale_view.advance(start, 100).code == StatusCode::RecoveryRequired);
  CHECK(!stale_view.ready());
  CHECK(store.stage_group_key(site.gk_epoch_current, site.gk_current).code ==
        StatusCode::RecoveryRequired);
  CHECK(store.finish_group_scrub().code == StatusCode::RecoveryRequired);
  const auto writes_after_cut = storage.write_calls;
  CHECK(store.commit(store.site()).code == StatusCode::RecoveryRequired);
  CHECK(store.raise_rs_floor(site.rs_epoch_floor + 1).code == StatusCode::RecoveryRequired);
  CHECK(storage.write_calls == writes_after_cut);
  SiteStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.site().gk_epoch_next == site.gk_epoch_current + 1);
  CHECK(reboot.site().gk_next == next);
}

void test_group_activate_cannot_extend_removal_overlap() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState group(store);
  sdkv1::GroupKeyState::Input input{};
  input.op = sdkv1::GroupKeyState::Op::Start;
  input.boot = site.boot_witness;
  CHECK_OK(group.advance(input, 100));
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Stage;
  input.epoch = site.gk_epoch_current + 1;
  input.key.fill(0xA5);
  input.generation = site.assignment_generation;
  input.overlap_s = 10;
  CHECK_OK(group.advance(input, 101));
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Activate;
  input.epoch = site.gk_epoch_current + 1;
  input.boot = site.boot_witness;
  input.generation = site.assignment_generation;
  input.overlap_s = 60;
  CHECK_OK(group.advance(input, 102));
  CHECK(group.accepts(site.gk_epoch_current));
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Tick;
  CHECK_OK(group.advance(input, 10102));
  CHECK(!group.accepts(site.gk_epoch_current));

  FaultyRecordStorage cold_storage(kSiteSlotBytes);
  SiteStore before_boot(cold_storage);
  CHECK_OK(before_boot.initialize());
  CHECK_OK(before_boot.commit(site));
  keys::Secret staged{};
  staged.fill(0xB6);
  CHECK_OK(before_boot.stage_group_key(site.gk_epoch_current + 1, staged));
  SiteStore after_boot(cold_storage);
  CHECK_OK(after_boot.initialize());
  sdkv1::GroupKeyState cold_group(after_boot);
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Start;
  input.boot = site.boot_witness + 1;
  CHECK_OK(cold_group.advance(input, 100));
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Activate;
  input.epoch = site.gk_epoch_current + 1;
  input.boot = site.boot_witness + 1;
  input.generation = site.assignment_generation;
  input.overlap_s = 60;
  CHECK_OK(cold_group.advance(input, 102));
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Tick;
  CHECK_OK(cold_group.advance(input, 10102));
  CHECK(cold_group.accepts(site.gk_epoch_current));
  CHECK_OK(cold_group.advance(input, 60102));
  CHECK(!cold_group.accepts(site.gk_epoch_current));
}

void test_superseded_stage_scrubs_both_slots() {
  const SiteRecord site = site_record();
  keys::Secret first{}, latest{};
  first.fill(0xA5);
  latest.fill(0xB6);
  {
    FaultyRecordStorage storage(kSiteSlotBytes);
    SiteStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(site));
    CHECK_OK(store.stage_group_key(site.gk_epoch_current + 1, first));
    const auto writes = storage.write_calls;
    CHECK_OK(store.stage_group_key(site.gk_epoch_current + 2, latest));
    CHECK(storage.write_calls == writes + 4);
    CHECK(storage.slot(0) == storage.slot(1));
    SiteStore reboot(storage);
    CHECK_OK(reboot.initialize());
    CHECK(reboot.site().gk_epoch_next == site.gk_epoch_current + 2);
    CHECK(!reboot.group_scrub_needed());
  }
  {
    FaultyRecordStorage storage(kSiteSlotBytes);
    SiteStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(site));
    CHECK_OK(store.stage_group_key(site.gk_epoch_current + 1, first));
    storage.cut_call = storage.write_calls + 2;
    storage.cut_bytes = 0;
    CHECK(store.stage_group_key(site.gk_epoch_current + 2, latest).code ==
          StatusCode::StorageFailure);
    storage.disarm();
    SiteStore reboot(storage);
    CHECK_OK(reboot.initialize());
    CHECK(reboot.site().gk_epoch_next == site.gk_epoch_current + 2);
    CHECK(reboot.group_scrub_needed());
    sdkv1::GroupKeyState group(reboot);
    sdkv1::GroupKeyState::Input start{};
    start.op = sdkv1::GroupKeyState::Op::Start;
    start.boot = site.boot_witness;
    CHECK_OK(group.advance(start, 100));
    CHECK(storage.slot(0) == storage.slot(1));
  }
}

void test_pending_sibling_is_scrubbed_before_group_ready() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  keys::Secret next{};
  next.fill(0xA5);
  CHECK_OK(store.stage_group_key(site.gk_epoch_current + 1, next));
  storage.cut_call = storage.write_calls + 2;  // promoted slot sealed
  storage.cut_bytes = kRecordSealOffset + 4;  // sibling seal becomes Pending; old GK stays
  CHECK(store.activate_group_key(site.gk_epoch_current + 1, site.boot_witness).code ==
        StatusCode::StorageFailure);
  storage.disarm();
  SiteStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.site().gk_epoch_current == site.gk_epoch_current + 1);
  CHECK(reboot.group_scrub_needed());
  sdkv1::GroupKeyState group(reboot);
  sdkv1::GroupKeyState::Input start{};
  start.op = sdkv1::GroupKeyState::Op::Start;
  start.boot = site.boot_witness;
  CHECK_OK(group.advance(start, 100));
  CHECK(storage.slot(0) == storage.slot(1));
}

void test_group_twin_byte_cuts() {
  const SiteRecord site = site_record();
  keys::Secret first{}, latest{};
  first.fill(0xA5);
  latest.fill(0xB6);
  const std::size_t length = site_encoded_size(site);
  for (const bool supersede : {false, true}) {
    for (std::size_t call = 0; call < 4; ++call) {
      for (std::size_t boundary = 0; boundary <= length; ++boundary) {
        FaultyRecordStorage storage(kSiteSlotBytes);
        SiteStore before(storage);
        CHECK_OK(before.initialize());
        CHECK_OK(before.commit(site));
        CHECK_OK(before.stage_group_key(site.gk_epoch_current + 1, first));
        storage.cut_call = storage.write_calls + call;
        storage.cut_bytes = boundary;
        const Status cut = supersede
            ? before.stage_group_key(site.gk_epoch_current + 2, latest)
            : before.activate_group_key(site.gk_epoch_current + 1, site.boot_witness);
        CHECK(cut.code == StatusCode::StorageFailure);
        storage.disarm();
        SiteStore reboot(storage);
        const Status loaded = reboot.initialize();
        sdkv1::GroupKeyState group(reboot);
        sdkv1::GroupKeyState::Input start{};
        start.op = sdkv1::GroupKeyState::Op::Start;
        start.boot = site.boot_witness;
        const Status started = group.advance(start, 100);
        if (loaded && reboot.has_site()) {
          CHECK_OK(started);
          CHECK(group.ready());
          CHECK(storage.slot(0) == storage.slot(1));
          if (supersede) {
            CHECK(reboot.site().gk_epoch_current == site.gk_epoch_current);
            CHECK(reboot.site().gk_epoch_next == site.gk_epoch_current + 1 ||
                  reboot.site().gk_epoch_next == site.gk_epoch_current + 2);
          } else {
            CHECK(reboot.site().gk_epoch_current == site.gk_epoch_current ||
                  reboot.site().gk_epoch_current == site.gk_epoch_current + 1);
          }
        } else {
          CHECK(!started && !group.ready());
        }
      }
    }
  }
}

void test_group_state_and_crypto() {
  // V1-K09 (scope-key-change half; the removed-member DISCOVER-drop
  // half has no test). V1-N06 (missing/regressed-rlboot halves; the
  // durability-unknown half has no explicit TX-zero assertion).
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState missing_boot(store);
  sdkv1::GroupKeyState::Input no_boot{};
  no_boot.op = sdkv1::GroupKeyState::Op::Start;
  no_boot.boot = 0;
  CHECK_OK(missing_boot.advance(no_boot, 99));
  CHECK(!missing_boot.tx_ready());  // lost rlboot cannot be guessed from witness
  sdkv1::GroupKeyState exhausted_boot(store);
  no_boot.boot = std::numeric_limits<std::uint32_t>::max();
  CHECK_OK(exhausted_boot.advance(no_boot, 99));
  CHECK(!exhausted_boot.tx_ready());
  sdkv1::GroupKeyState state(store);
  sdkv1::GroupKeyState::Input input{};
  input.op = sdkv1::GroupKeyState::Op::Start;
  input.boot = site.boot_witness + 1;
  CHECK_OK(state.advance(input, 100));
  CHECK(state.tx_ready());
  const ScopeRef scope{1};
  sdkv1::GkMemberScopeProvider discovery(state, scope);
  std::uint32_t generation = 0;
  CHECK(discovery.current_generation(scope, generation));
  CHECK(generation == site.gk_epoch_current);
  ScopeTag old_tag{}, next_tag{};
  const std::uint8_t message[] = {1, 2, 3};
  CHECK_OK(discovery.scope_tag(scope, generation, ByteView{message, 3}, old_tag));
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Stage;
  input.epoch = generation + 2;  // missed an entire rotation: skip is legal
  input.key.fill(0xA5);
  input.generation = site.assignment_generation;
  input.overlap_s = 10;
  CHECK_OK(state.advance(input, 101));
  CHECK(state.current() == generation);
  const auto staged_writes = storage.write_calls;
  input.epoch = generation + 3;
  input.key.fill(0);
  CHECK(state.advance(input, 101).code == StatusCode::Conflict);
  CHECK(state.ready() && storage.write_calls == staged_writes);
  input.epoch = generation + 2;
  input.key.fill(0xA5);
  CHECK(discovery.accepted_generation(scope, generation + 2, 102));
  CHECK_OK(discovery.scope_tag(scope, generation + 2, ByteView{message, 3}, next_tag));
  CHECK(old_tag != next_tag);
  CHECK(state.current() == generation);  // scope verification cannot activate
  input = {};
  input.op = sdkv1::GroupKeyState::Op::AuthenticatedNext;
  input.epoch = generation + 2;
  const auto writes = storage.write_calls;
  CHECK_OK(state.advance(input, 105));
  CHECK(storage.write_calls == writes);  // AEAD callback cannot write flash
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Tick;
  CHECK_OK(state.advance(input, 106));
  CHECK(state.current() == generation + 2);
  CHECK(storage.write_calls == writes + 4);  // twin pending/sealed x2
  CHECK(discovery.accepted_generation(scope, generation, 107));
  CHECK_OK(state.advance(input, 10107));
  CHECK(!state.accepts(generation));
  CHECK(!discovery.accepted_generation(scope, generation, 10108));
  CHECK(storage.slot(0) == storage.slot(1));

  // Crash between the first and second twin seals: reboot may adopt the
  // promoted key, but it cannot transmit until the old sibling is scrubbed.
  FaultyRecordStorage cut(kSiteSlotBytes);
  SiteStore before(cut);
  CHECK_OK(before.initialize());
  CHECK_OK(before.commit(site));
  keys::Secret key{};
  key.fill(0xBB);
  CHECK_OK(before.stage_group_key(generation + 1, key));
  cut.cut_call = cut.write_calls + 2;
  cut.cut_bytes = 0;
  CHECK(before.activate_group_key(generation + 1, site.boot_witness).code ==
        StatusCode::StorageFailure);
  cut.disarm();
  const auto writes_after_cut = cut.write_calls;
  CHECK(before.commit(before.site()).code == StatusCode::RecoveryRequired);
  CHECK(before.raise_rs_floor(site.rs_epoch_floor + 1).code == StatusCode::RecoveryRequired);
  CHECK(cut.write_calls == writes_after_cut);
  SiteStore reboot(cut);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.group_scrub_needed());
  sdkv1::GroupKeyState booted(reboot);
  input = {};
  input.op = sdkv1::GroupKeyState::Op::Start;
  input.boot = site.boot_witness + 2;
  CHECK_OK(booted.advance(input, 200));
  CHECK(!reboot.group_scrub_needed());
  CHECK(reboot.site().gk_epoch_current == generation + 1);
  CHECK(cut.slot(0) == cut.slot(1));

  SiteRecord advanced_witness = store.site();
  advanced_witness.boot_witness = state.boot() + 1;
  CHECK_OK(store.commit(advanced_witness));
  CHECK(!state.tx_ready());
}

void test_group_state_fences_out_of_band_site_change() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState group(store);
  sdkv1::GroupKeyState::Input start{};
  start.op = sdkv1::GroupKeyState::Op::Start;
  start.boot = site.boot_witness;
  CHECK_OK(group.advance(start, 100));
  CHECK(group.tx_ready());
  CHECK_OK(store.commit(rotated(site, site.gk_epoch_current + 1)));
  CHECK(!group.ready());
  sdkv1::GroupKeyState reissued(store);
  CHECK_OK(reissued.advance(start, 101));
  CHECK(reissued.tx_ready());
  CHECK_OK(store.clear());
  const NetworkId new_network = (NetworkId{kSiteEpoch + 1} << 32U) | kNetworkLow;
  CHECK_OK(store.commit(site_record(4, site.gk_epoch_current + 2, new_network)));
  CHECK(!reissued.ready());

  FaultyRecordStorage second_storage(kSiteSlotBytes);
  SiteStore second(second_storage);
  CHECK_OK(second.initialize());
  CHECK_OK(second.commit(site));
  sdkv1::GroupKeyState same_assignment(second);
  CHECK_OK(same_assignment.advance(start, 100));
  CHECK_OK(second.clear());
  SiteRecord replacement = site;
  replacement.gk_current.fill(0xC3);
  CHECK_OK(second.commit(replacement));
  CHECK(!same_assignment.ready());

  FaultyRecordStorage cut_storage(kSiteSlotBytes);
  SiteStore cut_store(cut_storage);
  CHECK_OK(cut_store.initialize());
  CHECK_OK(cut_store.commit(site));
  sdkv1::GroupKeyState during_clear(cut_store);
  CHECK_OK(during_clear.advance(start, 100));
  cut_storage.cut_call = cut_storage.write_calls + 1;
  cut_storage.cut_bytes = site_encoded_size(SiteRecord{});
  CHECK(cut_store.clear().code == StatusCode::StorageFailure);
  CHECK(!during_clear.ready());
  sdkv1::GroupKeyState after_failed_clear(cut_store);
  CHECK(after_failed_clear.advance(start, 101).code == StatusCode::RecoveryRequired);
}

class NoPairwise final : public SecurityProvider {
 public:
  bool ready() const noexcept override { return true; }
  Status next_counter(const SecurityContext&, std::uint64_t&) noexcept override {
    return Status::error(StatusCode::Unsupported, "no pairwise");
  }
  Status seal(const SecurityContext&, std::uint64_t, ByteView, ByteView, MutableByteView,
              std::array<std::uint8_t, kAeadTagSize>&) noexcept override {
    return Status::error(StatusCode::Unsupported, "no pairwise");
  }
  Status open(const SecurityContext&, std::uint64_t, ByteView, ByteView,
              const std::array<std::uint8_t, kAeadTagSize>&, MutableByteView) noexcept override {
    return Status::error(StatusCode::Unsupported, "no pairwise");
  }
};

void test_group_gcm_replay() {
  // V1-K05 (same-boot replay + GroupLink 128-sender-table-full halves;
  // the tx_boot-regress half has no test).
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState keys(store);
  sdkv1::GroupKeyState::Input in{};
  in.op = sdkv1::GroupKeyState::Op::Start;
  in.boot = site.boot_witness + 1;
  CHECK_OK(keys.advance(in, 100));
  NoPairwise pairwise;
  const AeadGcm* aead = builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  sdkv1::GroupSecurityProvider sender(keys, pairwise, *aead, site.gateways[0]);
  sdkv1::GroupSecurityProvider receiver(keys, pairwise, *aead, site.gateways[0]);
  SecurityContext c{SecurityScope::Group, static_cast<std::uint32_t>(site.network),
                    site.gateways[0], kBroadcastNodeId, site.gk_epoch_current,
                    0, site.boot_witness + 1, group_address(1)};
  std::uint64_t counter = 99;
  CHECK_OK(sender.next_counter(c, counter));
  CHECK(counter == 0);
  std::array<std::uint8_t, 3> plain{{1, 2, 3}}, cipher{}, opened{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  const std::uint8_t aad[] = {42};
  CHECK_OK(sender.seal(c, counter, ByteView{aad, 1}, ByteView{plain.data(), plain.size()},
                       MutableByteView{cipher.data(), cipher.size()}, tag));
  auto bad = tag;
  bad[0] ^= 1;
  CHECK(!receiver.open(c, counter, ByteView{aad, 1}, ByteView{cipher.data(), cipher.size()},
                       bad, MutableByteView{opened.data(), opened.size()}).ok());
  CHECK(opened[0] == 0 && opened[1] == 0 && opened[2] == 0);
  std::uint8_t guard = 0xA5;
  const auto huge = std::numeric_limits<std::size_t>::max();
  CHECK(receiver.open(c, counter, ByteView{aad, 1}, ByteView{cipher.data(), huge}, tag,
                      MutableByteView{&guard, huge}).code == StatusCode::ProtocolError);
  CHECK(guard == 0xA5);
  CHECK_OK(receiver.open(c, counter, ByteView{aad, 1}, ByteView{cipher.data(), cipher.size()},
                         tag, MutableByteView{opened.data(), opened.size()}));
  CHECK(opened == plain);
  CHECK(!receiver.open(c, counter, ByteView{aad, 1}, ByteView{cipher.data(), cipher.size()},
                       tag, MutableByteView{opened.data(), opened.size()}).ok());
  CHECK((opened == std::array<std::uint8_t, 3>{}));
  c.group_id = group_address(2);
  CHECK_OK(sender.next_counter(c, counter));
  CHECK(counter == 1);  // all group destinations share a counter
  c.network ^= NetworkId{1} << 32;  // provider only receives low32 wire id
  CHECK(!sender.next_counter(c, counter).ok());
  c.network = static_cast<std::uint32_t>(site.network);

  in = {};
  in.op = sdkv1::GroupKeyState::Op::Stage;
  in.generation = site.assignment_generation;
  in.epoch = site.gk_epoch_current + 1;
  in.key.fill(0xA5);
  in.overlap_s = 10;
  CHECK_OK(keys.advance(in, 101));
  SecurityContext staged_link{SecurityScope::GroupLink,
                              static_cast<std::uint32_t>(site.network), 0x100,
                              kBroadcastNodeId, site.boot_witness + 1,
                              site.gk_epoch_current + 1, 0, 0};
  ScopeDigest staged_prk{};
  keys::TrafficKey staged_traffic{};
  keys::AeadNonce staged_nonce{};
  keys::group_prk(site.network, store.site().gk_next, staged_prk);
  CHECK_OK(keys::group_bcast_key(staged_prk, staged_link.group_epoch,
                                 staged_link.sender, staged_link.epoch,
                                 staged_traffic));
  CHECK_OK(keys::aead_nonce(staged_traffic.iv, 7, staged_nonce));
  const std::uint8_t staged_aad[] = {42};
  const std::uint8_t staged_plain[] = {1, 2, 3};
  std::array<std::uint8_t, 3 + kAeadTagSize> staged_sealed{};
  std::array<std::uint8_t, kAeadTagSize> staged_tag{};
  std::array<std::uint8_t, 3> staged_opened{};
  CHECK(aead->seal(aead->ctx, staged_traffic.key.data(), staged_nonce.data(),
                   ByteView{staged_aad, 1}, ByteView{staged_plain, 3},
                   staged_sealed.data()));
  std::memcpy(staged_tag.data(), staged_sealed.data() + 3, staged_tag.size());
  const auto staged_writes = storage.write_calls;
  CHECK(receiver.open(staged_link, 7, ByteView{staged_aad, 1},
                      ByteView{staged_sealed.data(), 3}, staged_tag,
                      MutableByteView{staged_opened.data(), staged_opened.size()}).code ==
        StatusCode::Busy);
  CHECK((staged_opened == std::array<std::uint8_t, 3>{}));
  CHECK(storage.write_calls == staged_writes && keys.promotion_pending());
  keys::clear(staged_traffic);
  secure_clear(staged_prk);
  secure_clear(staged_nonce);
  // An insider can send under a staged GK. A verified tag schedules the
  // promotion, but cannot reach application plaintext before twin commit.
  NoPairwise no_session;
  sdkv1::GroupSecurityProvider staged_tx(keys, no_session, *aead, site.gateways[0]);
  SecurityContext future = c;
  future.group_id = group_address(1);
  future.epoch = site.gk_epoch_current + 1;
  CHECK(!staged_tx.next_counter(future, counter).ok());  // no early TX
  // Derive a staged frame independently from the frozen KDF, not via TX.
  ScopeDigest prk{};
  keys::TrafficKey traffic{};
  keys::group_prk(site.network, store.site().gk_next, prk);
  CHECK_OK(keys::group_end_key(prk, future.epoch, future.group_id,
                                future.sender, future.sender_boot, traffic));
  keys::AeadNonce nonce{};
  CHECK_OK(keys::aead_nonce(traffic.iv, 9, nonce));
  std::array<std::uint8_t, 3 + kAeadTagSize> sealed{};
  CHECK(aead->seal(aead->ctx, traffic.key.data(), nonce.data(), ByteView{aad, 1},
                   ByteView{plain.data(), plain.size()}, sealed.data()));
  std::memcpy(tag.data(), sealed.data() + 3, tag.size());
  opened.fill(0);
  const auto writes = storage.write_calls;
  CHECK(receiver.open(future, 9, ByteView{aad, 1}, ByteView{sealed.data(), 3}, tag,
                      MutableByteView{opened.data(), opened.size()}).code == StatusCode::Busy);
  CHECK(opened[0] == 0 && storage.write_calls == writes && keys.promotion_pending());
  in = {};
  in.op = sdkv1::GroupKeyState::Op::Tick;
  CHECK_OK(keys.advance(in, 102));
  CHECK(storage.write_calls == writes + 4);
  CHECK_OK(receiver.open(future, 9, ByteView{aad, 1}, ByteView{sealed.data(), 3}, tag,
                         MutableByteView{opened.data(), opened.size()}));
  CHECK(opened == plain);
  keys::clear(traffic);
  secure_clear(prk);

  // GroupLink is bounded by sender, not destination or route count. An
  // unknown 129th peer cannot evict a known sender's boot/replay floor.
  SecurityContext link{SecurityScope::GroupLink, c.network, 0x100,
                       kBroadcastNodeId, keys.boot(), keys.current(), 0, 0};
  keys::group_prk(site.network, store.site().gk_current, prk);
  for (std::size_t i = 0; i < 129; ++i) {
    link.sender = 0x100 + i;
    CHECK_OK(keys::group_bcast_key(prk, link.group_epoch, link.sender, link.epoch, traffic));
    CHECK_OK(keys::aead_nonce(traffic.iv, 0, nonce));
    CHECK(aead->seal(aead->ctx, traffic.key.data(), nonce.data(), ByteView{aad, 1},
                     ByteView{plain.data(), plain.size()}, sealed.data()));
    std::memcpy(tag.data(), sealed.data() + 3, tag.size());
    const Status result = receiver.open(link, 0, ByteView{aad, 1},
                                        ByteView{sealed.data(), 3}, tag,
                                        MutableByteView{opened.data(), opened.size()});
    CHECK(i < 128 ? result.ok() : result.code == StatusCode::NoCapacity);
    keys::clear(traffic);
  }
  link.sender = 0x100;
  CHECK_OK(keys::group_bcast_key(prk, link.group_epoch, link.sender, link.epoch, traffic));
  CHECK_OK(keys::aead_nonce(traffic.iv, 1, nonce));
  CHECK(aead->seal(aead->ctx, traffic.key.data(), nonce.data(), ByteView{aad, 1},
                   ByteView{plain.data(), plain.size()}, sealed.data()));
  std::memcpy(tag.data(), sealed.data() + 3, tag.size());
  CHECK_OK(receiver.open(link, 1, ByteView{aad, 1}, ByteView{sealed.data(), 3}, tag,
                         MutableByteView{opened.data(), opened.size()}));
  keys::clear(traffic);
  secure_clear(prk);

  // Churn across a completed GK overlap must release the old 128 senders.
  in = {};
  in.op = sdkv1::GroupKeyState::Op::Stage;
  in.generation = site.assignment_generation;
  in.epoch = keys.current() + 1;
  in.key.fill(0xBC);
  CHECK_OK(keys.advance(in, 200));
  in.op = sdkv1::GroupKeyState::Op::Activate;
  in.boot = keys.boot();
  CHECK_OK(keys.advance(in, 201));
  in = {};
  in.op = sdkv1::GroupKeyState::Op::Tick;
  CHECK_OK(keys.advance(in, 10202));
  link.sender = 0x1000;
  link.group_epoch = keys.current();
  keys::group_prk(site.network, store.site().gk_current, prk);
  CHECK_OK(keys::group_bcast_key(prk, link.group_epoch, link.sender, link.epoch, traffic));
  CHECK_OK(keys::aead_nonce(traffic.iv, 0, nonce));
  CHECK(aead->seal(aead->ctx, traffic.key.data(), nonce.data(), ByteView{aad, 1},
                   ByteView{plain.data(), plain.size()}, sealed.data()));
  std::memcpy(tag.data(), sealed.data() + 3, tag.size());
  CHECK_OK(receiver.open(link, 0, ByteView{aad, 1}, ByteView{sealed.data(), 3}, tag,
                         MutableByteView{opened.data(), opened.size()}));
  keys::clear(traffic);
  secure_clear(prk);
}

void test_group_end_sender_capacity() {
  // V1-K05 (GroupEnd 8-sender-table-full half).
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState keys(store);
  sdkv1::GroupKeyState::Input start{};
  start.op = sdkv1::GroupKeyState::Op::Start;
  start.boot = site.boot_witness;
  CHECK_OK(keys.advance(start, 100));
  NoPairwise pairwise;
  const AeadGcm* aead = builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  sdkv1::GroupSecurityProvider receiver(keys, pairwise, *aead, site.gateways[0]);
  ScopeDigest prk{};
  keys::group_prk(site.network, site.gk_current, prk);
  const std::uint8_t aad[] = {42};
  const std::uint8_t plain[] = {1, 2, 3};
  const auto receive = [&](const NodeId sender, const std::uint64_t counter) {
    SecurityContext c{SecurityScope::Group, static_cast<std::uint32_t>(site.network),
                      sender, kBroadcastNodeId, site.gk_epoch_current,
                      0, site.boot_witness, group_address(1)};
    keys::TrafficKey key{};
    keys::AeadNonce nonce{};
    std::array<std::uint8_t, 3 + kAeadTagSize> sealed{};
    std::array<std::uint8_t, kAeadTagSize> tag{};
    std::array<std::uint8_t, 3> opened{};
    CHECK_OK(keys::group_end_key(prk, c.epoch, c.group_id, c.sender, c.sender_boot, key));
    CHECK_OK(keys::aead_nonce(key.iv, counter, nonce));
    CHECK(aead->seal(aead->ctx, key.key.data(), nonce.data(), ByteView{aad, 1},
                     ByteView{plain, 3}, sealed.data()));
    std::memcpy(tag.data(), sealed.data() + 3, tag.size());
    const Status result = receiver.open(c, counter, ByteView{aad, 1},
                                        ByteView{sealed.data(), 3}, tag,
                                        MutableByteView{opened.data(), opened.size()});
    keys::clear(key);
    secure_clear(nonce);
    return result;
  };
  for (std::uint8_t batch = 0; batch < 2; ++batch) {
    SiteRecord updated = store.site();
    updated.gateway_count = 4;
    for (std::uint8_t i = 0; i < 4; ++i) updated.gateways[i] = 0x100 + batch * 4 + i;
    CHECK_OK(store.commit(updated));
    for (std::uint8_t i = 0; i < 4; ++i) CHECK_OK(receive(updated.gateways[i], 0));
  }
  SiteRecord updated = store.site();
  updated.gateway_count = 1;
  updated.gateways = {};
  updated.gateways[0] = 0x108;
  CHECK_OK(store.commit(updated));
  CHECK(receive(updated.gateways[0], 0).code == StatusCode::NoCapacity);
  updated.gateways[0] = 0x100;
  CHECK_OK(store.commit(updated));
  CHECK_OK(receive(updated.gateways[0], 1));
  secure_clear(prk);
}

void test_group_provider_reconstruction_preserves_boot_state() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState keys(store);
  sdkv1::GroupKeyState::Input start{};
  start.op = sdkv1::GroupKeyState::Op::Start;
  start.boot = site.boot_witness;
  CHECK_OK(keys.advance(start, 100));
  NoPairwise pairwise;
  const AeadGcm* aead = builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  SecurityContext c{SecurityScope::Group, static_cast<std::uint32_t>(site.network),
                    site.gateways[0], kBroadcastNodeId, site.gk_epoch_current,
                    0, site.boot_witness, group_address(1)};
  const std::uint8_t aad[] = {42};
  const std::uint8_t plain[] = {1, 2, 3};
  std::array<std::uint8_t, 3> cipher{}, opened{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  std::uint64_t counter = 99;
  {
    sdkv1::GroupSecurityProvider first(keys, pairwise, *aead, site.gateways[0]);
    CHECK_OK(first.next_counter(c, counter));
    CHECK(counter == 0);
    CHECK_OK(first.seal(c, counter, ByteView{aad, 1}, ByteView{plain, 3},
                        MutableByteView{cipher.data(), cipher.size()}, tag));
    CHECK_OK(first.open(c, counter, ByteView{aad, 1},
                        ByteView{cipher.data(), cipher.size()}, tag,
                        MutableByteView{opened.data(), opened.size()}));
  }
  sdkv1::GroupKeyState::Input stop{};
  stop.op = sdkv1::GroupKeyState::Op::Stop;
  CHECK_OK(keys.advance(stop, 101));
  CHECK_OK(keys.advance(start, 102));
  sdkv1::GroupSecurityProvider again(keys, pairwise, *aead, site.gateways[0]);
  CHECK_OK(again.next_counter(c, counter));
  CHECK(counter == 1);
  CHECK(again.open(c, 0, ByteView{aad, 1}, ByteView{cipher.data(), cipher.size()}, tag,
                   MutableByteView{opened.data(), opened.size()}).code == StatusCode::Conflict);
}

struct GroupSealReentry {
  const AeadGcm* backend{nullptr};
  sdkv1::GroupSecurityProvider* other{nullptr};
  sdkv1::GroupKeyState* group{nullptr};
  SecurityContext context{};
  Status counter_result{};
  Status group_result{};
};

bool group_seal_reentry(void* opaque, const std::uint8_t* key, const std::uint8_t* nonce,
                        ByteView aad, ByteView plaintext, std::uint8_t* out) noexcept {
  auto& hook = *static_cast<GroupSealReentry*>(opaque);
  std::uint64_t counter = 99;
  hook.counter_result = hook.other->next_counter(hook.context, counter);
  sdkv1::GroupKeyState::Input tick{};
  tick.op = sdkv1::GroupKeyState::Op::Tick;
  hook.group_result = hook.group->advance(tick, 101);
  return hook.backend->seal(hook.backend->ctx, key, nonce, aad, plaintext, out);
}

void test_group_provider_reentry_is_busy_across_views() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  sdkv1::GroupKeyState keys(store);
  sdkv1::GroupKeyState::Input start{};
  start.op = sdkv1::GroupKeyState::Op::Start;
  start.boot = site.boot_witness;
  CHECK_OK(keys.advance(start, 100));
  NoPairwise pairwise;
  const AeadGcm* backend = builtin_aead_gcm();
  CHECK(backend != nullptr);
  if (backend == nullptr) return;
  SecurityContext c{SecurityScope::Group, static_cast<std::uint32_t>(site.network),
                    site.gateways[0], kBroadcastNodeId, site.gk_epoch_current,
                    0, site.boot_witness, group_address(1)};
  sdkv1::GroupSecurityProvider other(keys, pairwise, *backend, site.gateways[0]);
  GroupSealReentry hook{};
  hook.backend = backend;
  hook.other = &other;
  hook.group = &keys;
  hook.context = c;
  AeadGcm wrapped{&group_seal_reentry, backend->open, &hook};
  sdkv1::GroupSecurityProvider first(keys, pairwise, wrapped, site.gateways[0]);
  std::uint64_t counter = 99;
  CHECK_OK(first.next_counter(c, counter));
  const std::uint8_t aad[] = {42}, plain[] = {1, 2, 3};
  std::array<std::uint8_t, 3> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  const auto writes = storage.write_calls;
  CHECK_OK(first.seal(c, counter, ByteView{aad, 1}, ByteView{plain, 3},
                      MutableByteView{cipher.data(), cipher.size()}, tag));
  CHECK(hook.counter_result.code == StatusCode::Busy);
  CHECK(hook.group_result.code == StatusCode::Busy);
  CHECK(storage.write_calls == writes);
  CHECK_OK(first.next_counter(c, counter));
  CHECK(counter == 1);
}

void test_site_power_cuts() {
  const SiteRecord base = site_record();
  const SiteRecord next = rotated(base, base.gk_epoch_current + 2);
  site_sweep("commit", 2, [&](SiteStore& store) { return store.commit(next); }, false, base,
             &next);
  site_sweep("clear", 4, [&](SiteStore& store) { return store.clear(); }, true, base, nullptr);
}

void test_site_recover_power_cuts() {
  // Impaired store (a torn sibling) -> recover() cut at every write.
  const SiteRecord base = site_record();
  const SiteRecord repaired = rotated(base, 250);
  ByteBuffer<kSiteSlotBytes> encoded{};
  CHECK_OK(site_record_encode(repaired, kSiteSealCommitted, 1, encoded));
  for (std::size_t call = 0; call < 4; ++call) {
    for (std::size_t boundary = 0; boundary <= encoded.size; ++boundary) {
      FaultyRecordStorage storage(kSiteSlotBytes);
      {
        SiteStore store(storage);
        CHECK_OK(store.initialize());
        CHECK_OK(store.commit(base));
        storage.slot(1).assign(kSiteSlotBytes, 0x5A);  // noise sibling
      }
      SiteStore impaired(storage);
      CHECK(impaired.initialize().code == StatusCode::IntegrityError);
      CHECK(impaired.uncertain());
      storage.cut_call = storage.write_calls + call;
      storage.cut_bytes = boundary;
      CHECK(!impaired.recover(repaired).ok());
      storage.disarm();
      SiteStore reboot(storage);
      (void)reboot.initialize();
      if (reboot.has_site()) {
        CHECK(same_site(reboot.site(), base) || same_site(reboot.site(), repaired));
      }
      if (reboot.uncertain() || reboot.quarantined()) {
        CHECK_OK(reboot.recover(repaired));
      }
      SiteStore again(storage);
      (void)again.initialize();
      CHECK(again.has_site());
    }
  }
}

void test_site_floors_and_faults() {
  const SiteRecord base = site_record();
  // A committed record whose CRC later fails still proves its sequence.
  FaultyRecordStorage storage(kSiteSlotBytes);
  {
    SiteStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(base));                    // seq 1 -> slot 0
    CHECK_OK(store.commit(rotated(base, 204)));      // seq 2 -> slot 1
  }
  storage.slot(1)[100] ^= 0x01;  // inside the key area: structure intact, CRC fails
  {
    SiteStore reboot(storage);
    CHECK(reboot.initialize().code == StatusCode::IntegrityError);
    CHECK(reboot.uncertain() && reboot.has_site() && reboot.commit_seq() == 1);
    CHECK(reboot.commit(rotated(base, 205)).code == StatusCode::RecoveryRequired);
    CHECK_OK(reboot.recover(rotated(base, 205)));
    CHECK(reboot.commit_seq() == 3);  // above the proven floor of 2
  }
  SiteStore after(storage);
  CHECK_OK(after.initialize());
  CHECK(after.site().gk_epoch_current == 205 && after.commit_seq() == 3);

  // Unsupported schema in the inactive slot: refused as a target.
  FaultyRecordStorage schema(kSiteSlotBytes);
  {
    SiteStore store(schema);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(base));
    CHECK_OK(store.commit(rotated(base, 204)));
  }
  patch(schema.slot(0), 11, 2);  // schema 2, CRC repaired
  {
    SiteStore reboot(schema);
    CHECK(reboot.initialize().code == StatusCode::IntegrityError);
    CHECK(reboot.uncertain() && reboot.site().gk_epoch_current == 204);
    CHECK_OK(reboot.recover(rotated(base, 206)));
  }
  // Both slots Unsupported -> quarantine(Unsupported).
  FaultyRecordStorage both(kSiteSlotBytes);
  {
    SiteStore store(both);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(base));
  }
  patch(both.slot(0), 11, 2);
  {
    SiteStore reboot(both);
    CHECK(reboot.initialize().code == StatusCode::Unsupported);
    CHECK(reboot.quarantined());
    CHECK_OK(reboot.clear());  // the explicit removal path always works
    CHECK(!reboot.quarantined() && !reboot.has_site());
  }
  // Equal sequence, different content -> quarantine.
  FaultyRecordStorage twins(kSiteSlotBytes);
  {
    SiteStore store(twins);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(base));
  }
  ByteBuffer<kSiteSlotBytes> forged{};
  CHECK_OK(site_record_encode(rotated(base, 204), kSiteSealCommitted, 1, forged));
  twins.slot(1).assign(kSiteSlotBytes, 0xFF);
  std::memcpy(twins.slot(1).data(), forged.bytes.data(), forged.size);
  {
    SiteStore reboot(twins);
    CHECK(reboot.initialize().code == StatusCode::IntegrityError);
    CHECK(reboot.quarantined() && !reboot.has_site());
  }
  // Readback mismatch: the commit reports failure; the old record stays.
  FaultyRecordStorage flip(kSiteSlotBytes);
  {
    SiteStore store(flip);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit(base));
    flip.flip_call = flip.write_calls + 1;  // corrupt the sealed write silently
    CHECK(store.commit(rotated(base, 204)).code == StatusCode::StorageFailure);
  }
  flip.disarm();
  {
    SiteStore reboot(flip);
    (void)reboot.initialize();
    CHECK(reboot.has_site() && reboot.site().gk_epoch_current == 203);
  }
  // Read faults are retryable, never quarantine.
  flip.read_error = true;
  {
    SiteStore reboot(flip);
    CHECK(reboot.initialize().code == StatusCode::StorageFailure);
    CHECK(!reboot.quarantined());
  }
  flip.read_error = false;
  flip.read_error_slot = 1;
  {
    SiteStore reboot(flip);
    CHECK(reboot.initialize().code == StatusCode::IntegrityError);
    CHECK(reboot.uncertain() && reboot.has_site());
  }
}

// --- RevocationStore -----------------------------------------------------------

void test_revocation_accept() {
  FaultyRecordStorage storage(kRevocationSlotBytes);
  RevocationStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(!store.has_set());
  const auto first = revocation_object(revocation_set(14));
  CHECK_OK(store.accept(first.view(), sak().pub, kSiteId, kNetwork));
  CHECK(store.rs_epoch() == 14);
  CHECK(store.rejects(0x00A1000000000100ULL, 1, kSiteEpoch));
  CHECK(!store.rejects(kNode, 3, kSiteEpoch));
  // Replay / same epoch / floor regression.
  CHECK(store.accept(first.view(), sak().pub, kSiteId, kNetwork).code == StatusCode::Conflict);
  CHECK(store.accept(revocation_object(revocation_set(15, 1, 1)).view(), sak().pub, kSiteId,
                     kNetwork)
            .code == StatusCode::Conflict);
  // A newer signed set in the same site epoch cannot forget a revocation
  // or lower its minimum generation.
  RevocationSet weaker = revocation_set(15);
  weaker.entries[0].min_generation = 1;
  CHECK(store.accept(revocation_object(weaker).view(), sak().pub, kSiteId, kNetwork).code ==
        StatusCode::Conflict);
  CHECK(store.accept(revocation_object(revocation_set(15, 1)).view(), sak().pub, kSiteId,
                     kNetwork)
            .code == StatusCode::Conflict);
  // Authenticity verdicts.
  CHECK(store.accept(revocation_object(revocation_set(16), other_key()).view(), sak().pub,
                     kSiteId, kNetwork)
            .code == StatusCode::AuthorizationFailed);
  CHECK(store.accept(revocation_object(revocation_set(16)).view(), sak().pub, kSiteId,
                     kNetwork + 1)
            .code == StatusCode::AuthorizationFailed);
  CHECK(store.accept(revocation_object(revocation_set(16)).view(), sak().pub, kSiteId + 1,
                     kNetwork)
            .code == StatusCode::AuthorizationFailed);
  auto garbage = revocation_object(revocation_set(16));
  garbage.bytes[0] = 0xD3;
  CHECK(store.accept(garbage.view(), sak().pub, kSiteId, kNetwork).code ==
        StatusCode::ProtocolError);
  // Raising the floor within the same network does not authorize dropping
  // entries; a replacement that retains them remains valid.
  const auto dropped = revocation_object(revocation_set(16, 0, kSiteEpoch));
  CHECK(store.accept(dropped.view(), sak().pub, kSiteId, kNetwork).code ==
        StatusCode::Conflict);
  const auto retained = revocation_object(revocation_set(16, 2, kSiteEpoch));
  CHECK_OK(store.accept(retained.view(), sak().pub, kSiteId, kNetwork));
  CHECK(store.set().count == 2 && store.rejects(kNode, 3, kSiteEpoch - 1));
  // A new-network set — the cutover adoption shape, where the caller's RLS1
  // expectation moved first — starts its own history.
  const NetworkId next_network =
      (static_cast<NetworkId>(kSiteEpoch + 1) << 32U) | kNetworkLow;
  const auto next_set =
      revocation_object(revocation_set(17, 0, kSiteEpoch + 1, next_network));
  CHECK_OK(store.accept(next_set.view(), sak().pub, kSiteId, next_network));
  CHECK(store.set().count == 0 && store.set().network == next_network &&
        store.rejects(kNode, 3, kSiteEpoch));
  ByteBuffer<kRevocationObjectMax> loaded{};
  CHECK_OK(store.load_object(loaded));
  CHECK(loaded.size == next_set.size &&
        std::memcmp(loaded.bytes.data(), next_set.bytes.data(), next_set.size) == 0);
  RevocationStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.has_set() && reboot.rs_epoch() == 17);
  CHECK_OK(reboot.clear());
  CHECK(!reboot.has_set());
  CHECK(reboot.load_object(loaded).code == StatusCode::NotFound);
  RevocationStore after_clear(storage);
  CHECK_OK(after_clear.initialize());
  CHECK(!after_clear.has_set());
  // After removal a new site's first set (lower epoch) is accepted.
  CHECK_OK(after_clear.accept(first.view(), sak().pub, kSiteId, kNetwork));
}

// P6 PR-A (04 §2): a same-network replacement that drops a past revocation
// or lowers a min_generation is Conflict — history can only be compressed by
// a verified cutover (PR C), never by a plain accept().
void test_revocation_entry_monotonicity() {
  FaultyRecordStorage storage(kRevocationSlotBytes);
  RevocationStore store(storage);
  CHECK_OK(store.initialize());
  RevocationSet first = revocation_set(14);  // 2 entries, min_generation 2,3
  CHECK_OK(store.accept(revocation_object(first).view(), sak().pub, kSiteId, kNetwork));
  // Newer epoch, one old entry silently dropped.
  RevocationSet dropped = first;
  dropped.rs_epoch = 15;
  dropped.count = 1;
  CHECK(store.accept(revocation_object(dropped).view(), sak().pub, kSiteId, kNetwork).code ==
        StatusCode::Conflict);
  // Newer epoch, an old entry's min_generation lowered.
  RevocationSet weakened = first;
  weakened.rs_epoch = 15;
  weakened.entries[0].min_generation = 1;
  CHECK(store.accept(revocation_object(weakened).view(), sak().pub, kSiteId, kNetwork).code ==
        StatusCode::Conflict);
  // Still the old set: nothing was written by the refused replacements.
  CHECK(store.rs_epoch() == 14 && store.set().count == 2);
  // A strict superset (same floor, more entries, raised min_generation) is fine.
  RevocationSet grown = first;
  grown.rs_epoch = 15;
  grown.entries[1].min_generation = 9;
  grown.entries[2] = RevocationEntry{0x00A1000000000200ULL, 4U, RevocationReason::Lost};
  grown.count = 3;
  CHECK_OK(store.accept(revocation_object(grown).view(), sak().pub, kSiteId, kNetwork));
  CHECK(store.rs_epoch() == 15 && store.set().count == 3);
}

// The verification hook is part of the API: the sweep memoizes verdicts so
// ~1300 reboots do not repeat identical P-256 verifications (the first call
// for every distinct input still runs micro-ecc).
class MemoVerifier final : public Es256Verifier {
 public:
  bool verify_digest(const P256PublicKey& pubkey, const Digest256& digest,
                     const Es256Signature& signature) const noexcept override {
    for (std::size_t i = 0; i < used_; ++i) {
      if (entries_[i].pubkey == pubkey && entries_[i].digest == digest &&
          entries_[i].signature == signature) {
        return entries_[i].verdict;
      }
    }
    const bool verdict = default_es256_verifier().verify_digest(pubkey, digest, signature);
    if (used_ < entries_.size()) entries_[used_++] = Entry{pubkey, digest, signature, verdict};
    return verdict;
  }

 private:
  struct Entry {
    P256PublicKey pubkey{};
    Digest256 digest{};
    Es256Signature signature{};
    bool verdict{false};
  };
  mutable std::array<Entry, 8> entries_{};
  mutable std::size_t used_{0};
};

void test_revocation_power_cuts() {
  const MemoVerifier verifier;
  const auto old_object = revocation_object(revocation_set(14, 3));
  const auto new_object = revocation_object(revocation_set(15, 32));
  // Recovery/accept after the cut must keep every adopted entry (04 §2):
  // the same 32 entries at a newer epoch cover either survivor.
  const auto newer = revocation_object(revocation_set(20, 32));
  const auto older = revocation_object(revocation_set(13));
  for (std::size_t call = 0; call < 2; ++call) {
    for (std::size_t boundary = 0; boundary <= kRevocationSlotBytes; ++boundary) {
      FaultyRecordStorage storage(kRevocationSlotBytes);
      {
        RevocationStore store(storage);
        CHECK_OK(store.initialize());
        CHECK_OK(store.accept(old_object.view(), sak().pub, kSiteId, kNetwork, verifier));
        storage.cut_call = storage.write_calls + call;
        storage.cut_bytes = boundary;
        CHECK(store.accept(new_object.view(), sak().pub, kSiteId, kNetwork, verifier).code ==
              StatusCode::StorageFailure);
      }
      storage.disarm();
      RevocationStore reboot(storage);
      const Status loaded = reboot.initialize();
      CHECK(reboot.has_set());
      CHECK(reboot.rs_epoch() == 14 || reboot.rs_epoch() == 15);
      if (call == 0 || boundary < kRevocationSlotBytes) CHECK(reboot.rs_epoch() == 14);
      if (reboot.uncertain()) {
        CHECK(!loaded.ok());
        CHECK(reboot.accept(newer.view(), sak().pub, kSiteId, kNetwork, verifier).code ==
              StatusCode::RecoveryRequired);
        // Recovery never regresses below the adopted epoch.
        CHECK(reboot.recover(older.view(), sak().pub, kSiteId, kNetwork, verifier).code ==
              StatusCode::Conflict);
        CHECK_OK(reboot.recover(newer.view(), sak().pub, kSiteId, kNetwork, verifier));
      } else {
        CHECK_OK(loaded);
        CHECK_OK(reboot.accept(newer.view(), sak().pub, kSiteId, kNetwork, verifier));
      }
      RevocationStore again(storage);
      CHECK_OK(again.initialize());
      CHECK(again.rs_epoch() == 20);
    }
  }
}

void test_revocation_clear_power_cuts() {
  const MemoVerifier verifier;
  const auto object = revocation_object(revocation_set(14, 2));
  ByteBuffer<kRevocationSlotBytes> cleared{};
  CHECK_OK(revocation_record_encode(ByteView{}, kRevocationSealCommitted, 2, cleared));
  for (std::size_t call = 0; call < 4; ++call) {
    for (std::size_t boundary = 0; boundary <= cleared.size; ++boundary) {
      FaultyRecordStorage storage(kRevocationSlotBytes);
      RevocationStore store(storage);
      CHECK_OK(store.initialize());
      CHECK_OK(store.accept(object.view(), sak().pub, kSiteId, kNetwork, verifier));
      storage.cut_call = storage.write_calls + call;
      storage.cut_bytes = boundary;
      CHECK(store.clear().code == StatusCode::StorageFailure);
      storage.disarm();
      RevocationStore reboot(storage);
      (void)reboot.initialize();
      CHECK(!reboot.has_set() || reboot.rs_epoch() == 14);
      CHECK_OK(reboot.clear());
      RevocationStore finished(storage);
      CHECK_OK(finished.initialize());
      CHECK(finished.clean_empty());
      CHECK(storage.slot(0) == storage.slot(1));
    }
  }
}

// --- ResumeCache2 (RLP2) -------------------------------------------------------------

ResumeContext context(const std::uint32_t gk_epoch = 203, const RevocationSet* rrs = nullptr) {
  return ResumeContext{kNetwork, gk_epoch, rrs};
}

void test_resume2_cache_rules() {
  FaultyResumeStorage2 storage(6);  // link 0..2, end 3..5
  ResumeCache2 cache(storage, 3, 3);
  ResumeSlot2 out{};
  std::size_t index = 0;
  CHECK(cache.find_by_peer(ResumePurpose::Link, kPeer, context(), out, index).code ==
        StatusCode::NotFound);
  // A fresh RMS restarts the count: a carried-over high-water is refused.
  ResumeSlot2 carried = resume2_slot(100);
  carried.reserved_uses = 8;
  CHECK(cache.put(carried, context()).code == StatusCode::InvalidArgument);
  CHECK_OK(cache.put(resume2_slot(100, 0, 10), context()));
  CHECK_OK(cache.put(resume2_slot(101, 0, 5), context()));
  CHECK_OK(cache.put(resume2_slot(102, kResumeFlagPinned, 1), context()));
  // The link partition is full (3): LRU eviction stays inside it and never
  // touches the end partition.
  CHECK_OK(cache.put(resume2_slot(103, 0, 20), context()));
  CHECK(cache.find_by_peer(ResumePurpose::Link, 101, context(), out, index).code ==
        StatusCode::NotFound);
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 102, context(), out, index));  // pinned
  CHECK_OK(cache.put(resume2_slot(200, 0, 7, 203, ResumePurpose::End), context()));
  CHECK_OK(cache.find_by_peer(ResumePurpose::End, 200, context(), out, index));
  CHECK(index >= 3);  // end slots live in the end partition
  // Pin budget is per purpose: quota - 2 = 1 pinned end slot at most here.
  CHECK_OK(cache.put(resume2_slot(201, kResumeFlagPinned, 50, 203, ResumePurpose::End), context()));
  CHECK(cache.put(resume2_slot(202, kResumeFlagPinned, 60, 203, ResumePurpose::End), context())
            .code == StatusCode::NoCapacity);
  // Validity: GK window with u64 edges, network, revocation, role.
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(204), out, index));
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, context(205), out, index).code ==
        StatusCode::NotFound);  // created 203 + 2 <= 205
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, context(202), out, index).code ==
        StatusCode::NotFound);  // a regressed GK fails closed
  ResumeSlot2 future = resume2_slot(104, 0, 0, 0xFFFFFFFE);
  CHECK_OK(cache.put(future, context()));  // stored, but never usable here
  CHECK(cache.find_by_peer(ResumePurpose::Link, 104, context(), out, index).code ==
        StatusCode::NotFound);
  ResumeContext other_network = context();
  other_network.network = kNetwork + 1;
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, other_network, out, index).code ==
        StatusCode::NotFound);
  RevocationSet rrs = revocation_set(1, 0);
  rrs.entries[0] = RevocationEntry{100, 2, RevocationReason::Lost};
  rrs.count = 1;
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, context(203, &rrs), out, index).code ==
        StatusCode::NotFound);
  // read_at reports torn slots without failing.
  bool intact = true;
  CHECK_OK(cache.read_at(0, out, intact));
  CHECK(intact);
  storage.slot(0)[40] ^= 0xFF;  // corrupt the generation word, CRC now fails
  CHECK_OK(cache.read_at(0, out, intact));
  CHECK(!intact && !out.valid);
  CHECK(cache.read_at(6, out, intact).code == StatusCode::InvalidArgument);
  // Quota mismatch against the storage refuses lookups loudly.
  ResumeCache2 misconfigured(storage, 3, 4);
  CHECK(misconfigured.find_by_peer(ResumePurpose::Link, 100, context(), out, index).code ==
        StatusCode::InvalidState);
}

void test_resume2_find_by_id() {
  FaultyResumeStorage2 storage(6);
  ResumeCache2 cache(storage, 3, 3);
  CHECK_OK(cache.put(resume2_slot(100), context()));
  CHECK_OK(cache.put(resume2_slot(101), context()));
  ResumeSlot2 out{};
  std::size_t index = 0;
  routeloom::keys::ResumeId rid{};
  {
    ResumeSlot2 slot{};
    CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), slot, index));
    routeloom::keys::resume_id(slot.rms, routeloom::keys::Purpose::Link, rid);
  }
  // Unknown carrier peer: the rid alone still finds the unique slot.
  CHECK_OK(cache.find_by_id(ResumePurpose::Link, rid, kInvalidNodeId, context(), out, index));
  CHECK(out.peer == 100);
  // A claimed peer that matches filters; one that does not refuses.
  CHECK_OK(cache.find_by_id(ResumePurpose::Link, rid, 100, context(), out, index));
  CHECK(cache.find_by_id(ResumePurpose::Link, rid, 101, context(), out, index).code ==
        StatusCode::NotFound);
  // Two slots sharing one RMS are ambiguous even with a claimed peer that
  // both... no: the claimed peer disambiguates, unknown does not.
  ResumeSlot2 twin = resume2_slot(102);
  ResumeSlot2 first{};
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), first, index));
  twin.rms = first.rms;
  CHECK_OK(cache.put(twin, context()));
  CHECK_OK(cache.find_by_id(ResumePurpose::Link, rid, 102, context(), out, index));
  CHECK(out.peer == 102);
  CHECK(cache.find_by_id(ResumePurpose::Link, rid, kInvalidNodeId, context(), out, index).code ==
        StatusCode::NotFound);
  // Wrong purpose or network never matches.
  CHECK(cache.find_by_id(ResumePurpose::End, rid, kInvalidNodeId, context(), out, index).code ==
        StatusCode::NotFound);
  ResumeContext other = context();
  other.network = kNetwork + 1;
  CHECK(cache.find_by_id(ResumePurpose::Link, rid, kInvalidNodeId, other, out, index).code ==
        StatusCode::NotFound);
}

void test_resume2_incremental_lookup() {
  FaultyResumeStorage2 storage(160);
  ResumeCache2 cache(storage, 32, 128);
  ResumeSlot2 slot = resume2_slot(200, 0, 7, 203, ResumePurpose::End);
  std::array<std::uint8_t, kResume2SlotBytes> encoded{};
  CHECK_OK(resume2_slot_encode(slot, encoded));
  storage.slot(159) = encoded;
  ResumeCache2::LookupCursor cursor{};
  bool done = false;
  for (int step = 0; step < 8; ++step) {
    const std::size_t before = storage.read_calls;
    CHECK_OK(cache.find_by_peer_step(ResumePurpose::End, 200, context(), cursor, done));
    CHECK(storage.read_calls - before <= ResumeCache2::kLookupStepSlots);
    if (step < 7) CHECK(!done);
  }
  CHECK(done && cursor.found && cursor.index == 159);
  CHECK(cursor.match.rms == slot.rms);
  routeloom::keys::ResumeId rid{};
  routeloom::keys::resume_id(slot.rms, routeloom::keys::Purpose::End, rid);
  cursor = ResumeCache2::LookupCursor{};
  done = false;
  for (int step = 0; step < 8; ++step) {
    const std::size_t before = storage.read_calls;
    CHECK_OK(cache.find_by_id_step(ResumePurpose::End, rid, kInvalidNodeId,
                                    context(), cursor, done));
    CHECK(storage.read_calls - before <= ResumeCache2::kLookupStepSlots);
    if (step < 7) CHECK(!done);
  }
  CHECK(done && cursor.found && !cursor.ambiguous && cursor.index == 159);
  storage.slot(158) = encoded;
  cursor = ResumeCache2::LookupCursor{};
  done = false;
  while (!done) {
    CHECK_OK(cache.find_by_id_step(ResumePurpose::End, rid, kInvalidNodeId,
                                    context(), cursor, done));
  }
  CHECK(cursor.ambiguous && !cursor.match.valid);
}

void test_resume2_incremental_revocation_and_clear() {
  FaultyResumeStorage2 storage(6);
  ResumeCache2 cache(storage, 3, 3);
  CHECK_OK(cache.put(resume2_slot(100), context()));
  CHECK_OK(cache.put(resume2_slot(101), context()));
  RevocationSet rrs = revocation_set(1, 0);
  rrs.entries[0] = RevocationEntry{100, 2, RevocationReason::Lost};
  rrs.count = 1;
  std::size_t cursor = 0;
  bool done = false;
  storage.cut_call = storage.write_calls;
  CHECK(cache.sweep_revoked(context(203, &rrs), cursor, done).code ==
        StatusCode::StorageFailure);
  CHECK(cursor == 0 && !done);
  storage.disarm();
  while (!done) {
    const std::size_t before = storage.read_calls;
    CHECK_OK(cache.sweep_revoked(context(203, &rrs), cursor, done));
    CHECK(storage.read_calls - before <= 2);
  }
  ResumeSlot2 slot{};
  bool intact = false;
  CHECK_OK(cache.read_at(0, slot, intact));
  CHECK(intact && !slot.valid);
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 101, context(), slot, cursor));
  cursor = 0;
  done = false;
  while (!done) CHECK_OK(cache.clear_step(cursor, done));
  CHECK(cache.find_by_peer(ResumePurpose::Link, 101, context(), slot, cursor).code ==
        StatusCode::NotFound);
}

void test_resume2_uses() {
  // The 64-use ceiling holds across reboots; one RMS generation costs at
  // most 8 durable reservation writes (P4 §6.2, V1-F05). Each boot drops
  // the RAM remainder (safe side), so a use-per-boot pattern serves 8, not
  // 64 — the cap is a ceiling, never a promise.
  FaultyResumeStorage2 storage(16);
  std::size_t index = 0;
  {
    ResumeCache2 cache(storage, 12, 4);
    CHECK_OK(cache.put(resume2_slot(100, 0, 1000), context()));
    ResumeSlot2 slot{};
    CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), slot, index));
    // One boot serves the whole quantum from one grant + RAM.
    for (int i = 0; i < 64; ++i) CHECK_OK(cache.reserve_uses(index, context(), 1000, false));
    CHECK(cache.reserve_uses(index, context(), 1000, false).code ==
          StatusCode::CounterExhausted);
  }
  {
    ResumeCache2 cache(storage, 12, 4);
    ResumeSlot2 slot{};
    bool intact = true;
    CHECK_OK(cache.read_at(index, slot, intact));
    CHECK(intact && slot.reserved_uses == 64);
    CHECK(cache.reserve_uses(index, context(), 1001, false).code ==
          StatusCode::CounterExhausted);
  }
  CHECK(storage.write_calls == 1 + 8);  // put + 8 quanta, no touch double-write
  // A reboot between every use wastes the RAM remainder: 8 serves, then the
  // high-water is spent. Uses served never exceed the durable proof.
  {
    FaultyResumeStorage2 rebooted(16);
    ResumeCache2 seed(rebooted, 12, 4);
    CHECK_OK(seed.put(resume2_slot(100, 0, 5000), context()));
    std::uint32_t served = 0;
    for (std::uint32_t boot = 5000; boot < 5020; ++boot) {
      ResumeCache2 cache(rebooted, 12, 4);
      ResumeSlot2 slot{};
      std::size_t at = 0;
      CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), slot, at));
      if (!cache.reserve_uses(at, context(), boot, false).ok()) break;
      ++served;
    }
    CHECK(served == 8);
    ResumeCache2 cache(rebooted, 12, 4);
    ResumeSlot2 slot{};
    bool intact = true;
    CHECK_OK(cache.read_at(0, slot, intact));
    CHECK(slot.reserved_uses == 64);
  }
  // A rewritten slot invalidates the RAM remainder; failures grant nothing.
  {
    ResumeCache2 cache(storage, 12, 4);
    CHECK(cache.reserve_uses(15, context(), 3000, false).code == StatusCode::NotFound);
    storage.read_error = true;
    CHECK(!cache.reserve_uses(index, context(), 3000, false).ok());
    storage.disarm();
    // Peer 100's slot is spent. Rewriting the same RMS must not reset its
    // durable 64-use high-water; a new RMS may start a new generation.
    ResumeSlot2 fresh = resume2_slot(100, 0, 4000);
    CHECK(cache.put(fresh, context()).code == StatusCode::Conflict);
    fresh.rms[0] ^= 0x5A;
    CHECK_OK(cache.put(fresh, context()));
    ResumeSlot2 slot{};
    CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), slot, index));
    CHECK(slot.reserved_uses == 0);
    CHECK_OK(cache.reserve_uses(index, context(), 4000, false));
  }
}

void test_resume2_power_cuts() {
  // Cut a use-grant at every byte: afterwards the slot grants at most the
  // uses its durable high-water proves — never more (V1-F05).
  const ResumeSlot2 fresh = resume2_slot(100, 0, 1000);
  for (std::size_t boundary = 0; boundary <= kResume2SlotBytes; ++boundary) {
    FaultyResumeStorage2 storage(16);
    std::size_t index = 0;
    {
      ResumeCache2 cache(storage, 12, 4);
      CHECK_OK(cache.put(fresh, context()));
      ResumeSlot2 slot{};
      CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), slot, index));
      storage.cut_call = storage.write_calls;
      storage.cut_bytes = boundary;
      static_cast<void>(cache.reserve_uses(index, context(), 1000, false));
    }
    ResumeCache2 reboot(storage, 12, 4);
    ResumeSlot2 slot{};
    bool intact = true;
    CHECK_OK(reboot.read_at(index, slot, intact));
    if (!slot.valid) continue;  // torn single-copy slot: one full EDHOC
    CHECK(slot.reserved_uses == 0 || slot.reserved_uses == 8);
    // Whatever survived, the lifetime cap still holds end to end: fresh
    // caches serve at most one use per remaining quantum.
    std::uint32_t granted = 0;
    for (std::uint32_t i = 0; i < 70; ++i) {
      ResumeCache2 attempt(storage, 12, 4);
      ResumeSlot2 probe{};
      std::size_t at = 0;
      if (!attempt.find_by_peer(ResumePurpose::Link, 100, context(), probe, at).ok()) break;
      if (!attempt.reserve_uses(at, context(), 1000 + i, false).ok()) break;
      ++granted;
    }
    CHECK(granted <= (64 - slot.reserved_uses) / 8);
    ResumeCache2 tail(storage, 12, 4);
    ResumeSlot2 end{};
    CHECK_OK(tail.read_at(index, end, intact));
    CHECK(end.reserved_uses <= 64);
  }
}

void test_resume2_touch_wear_rule() {
  // V1-F08: the boot stamp rewrites only every 256 boots, so 1-minute
  // wakes for a full day cost a handful of slot writes.
  FaultyResumeStorage2 storage(16);
  ResumeCache2 cache(storage, kResume2NodeLinkQuota, kResume2NodeEndQuota);
  CHECK_OK(cache.put(resume2_slot(100, 0, 1000), context()));
  ResumeSlot2 out{};
  std::size_t index = 0;
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), out, index));
  const std::size_t writes = storage.write_calls;
  for (std::uint32_t boot = 1000; boot < 1000 + 1440; ++boot) {
    CHECK_OK(cache.touch(index, boot, false));
  }
  CHECK(storage.write_calls == writes + 5);  // boots 1256/1512/1768/2024/2280
  CHECK_OK(cache.touch(index, 2440, true));   // GK change forces the update
  CHECK(storage.write_calls == writes + 6);
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 100, context(), out, index));
  CHECK(out.last_used_boot == 2440);
  CHECK(cache.touch(15, 5, true).code == StatusCode::NotFound);  // empty slot
}

// --- LocalRevocationStore (RLV1, P4-M01) ----------------------------------------------

LocalRevocationRecord removal_record() {
  LocalRevocationRecord record{};
  record.state = LocalRevocationState::Blocked;
  record.cause = LocalRevocationCause::Notice;
  record.local_node = 0x00A1000000001234ULL;
  record.site_id = 0x5173000000000042ULL;
  record.network = kNetwork;
  record.removed_generation = 3;
  record.rs_epoch_floor = 11;
  record.site_epoch_floor = kSiteEpoch;
  record.evidence_digest.fill(0xE4);
  record.rls_commit_seq = 41;
  record.boot_witness = 9000;
  return record;
}

void test_local_revocation_basic() {
  FaultyRecordStorage storage(kLocalRevocationSlotBytes);
  {
    LocalRevocationStore store(storage);
    CHECK_OK(store.initialize());
    CHECK(!store.has_record() && !store.blocks_membership(false));
    CHECK_OK(store.check_join(0x5173000000000042ULL, 4, true));
    CHECK_OK(store.commit_blocked(removal_record()));
    CHECK(store.has_record() && store.blocks_membership(false));
    CHECK(store.blocks_membership(true));  // Blocked ignores the holdoff
    CHECK(store.check_join(0x5173000000000042ULL, 9, true).code ==
          StatusCode::AuthorizationFailed);
    // Same-site re-commit with a regressed generation is Conflict.
    LocalRevocationRecord older = removal_record();
    older.removed_generation = 2;
    CHECK(store.commit_blocked(older).code == StatusCode::Conflict);
    // A different site while one stands: finish the cleanup first.
    LocalRevocationRecord foreign = removal_record();
    foreign.site_id = 0x99;
    CHECK(store.commit_blocked(foreign).code == StatusCode::Conflict);
    CHECK_OK(store.commit_cleaned());
    CHECK(store.has_record() && store.blocks_membership(false));
    CHECK(!store.blocks_membership(true));  // Cleaned + elapsed holdoff
    CHECK_OK(store.check_join(0x5173000000000042ULL, 4, true));
    CHECK(store.check_join(0x5173000000000042ULL, 3, true).code ==
          StatusCode::AuthorizationFailed);  // the removed generation never returns
    CHECK(store.check_join(0x5173000000000042ULL, 4, false).code ==
          StatusCode::AuthorizationFailed);  // holdoff still running
    CHECK_OK(store.check_join(0x1234ULL, 1, true));  // another site, full join
    CHECK(store.commit_cleaned().code == StatusCode::InvalidState);  // not Blocked
  }
  // The evidence survives the reboot either way.
  LocalRevocationStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.has_record());
  CHECK(reboot.record().state == LocalRevocationState::Cleaned);
  CHECK(reboot.record().removed_generation == 3);
  // After a full join to another site, its own removal replaces the
  // completed evidence and remains blocking across reboot.
  LocalRevocationRecord next_site = removal_record();
  next_site.site_id = 0x1234;
  next_site.network = (NetworkId{4} << 32U) | 0x1234;
  next_site.evidence_digest.fill(0xAB);
  CHECK_OK(reboot.commit_blocked(next_site));
  LocalRevocationStore second_reboot(storage);
  CHECK_OK(second_reboot.initialize());
  CHECK(second_reboot.blocks_membership(true));
  CHECK(second_reboot.record().site_id == next_site.site_id);
}

void test_local_revocation_power_cuts() {
  // P4-M01: cut the Blocked commit at every byte, then reboot. Either the
  // removal is durably present (and blocks), or nothing landed (and the
  // commit reported an error, so the issuer redelivers) — a reboot never
  // turns an accepted removal back into Member.
  for (const bool has_old : {false, true}) {
    // A sequenced commit is two storage writes (pending + commit marker):
    // cut each of them, at every byte.
    for (const std::size_t cut_write : {0, 1}) {
      for (std::size_t boundary = 0; boundary <= kLocalRevocationSlotBytes; ++boundary) {
        FaultyRecordStorage storage(kLocalRevocationSlotBytes);
        LocalRevocationRecord old_record = removal_record();
        old_record.removed_generation = 2;
        if (has_old) {
          LocalRevocationStore seed(storage);
          CHECK_OK(seed.initialize());
          CHECK_OK(seed.commit_blocked(old_record));
        }
        bool committed = false;
        {
          LocalRevocationStore store(storage);
          CHECK_OK(store.initialize());
          storage.cut_call = storage.write_calls + cut_write;
          storage.cut_bytes = boundary;
          committed = store.commit_blocked(removal_record()).ok();
        }
        LocalRevocationStore reboot(storage);
        const Status booted = reboot.initialize();
        if (!booted.ok()) {
          // Torn sibling states quarantine or report uncertainty: blocking.
          CHECK(reboot.blocks_membership(false));
          continue;
        }
        if (!reboot.has_record()) {
          // Nothing landed: the commit must have said so.
          CHECK(!committed);
          CHECK(!has_old);  // an old record is never lost by a cut
          CHECK(!reboot.blocks_membership(false));
          continue;
        }
        CHECK(reboot.blocks_membership(false));
        CHECK(reboot.blocks_membership(true));
        const LocalRevocationRecord& adopted = reboot.record();
        if (committed) {
          CHECK(adopted.removed_generation == 3);  // read back before reporting
        } else if (adopted.removed_generation == 3) {
          // Only a full commit-marker payload that landed despite the
          // error adopts the new record without a success report.
          CHECK(boundary == kLocalRevocationSlotBytes && cut_write == 1);
        } else {
          CHECK(has_old && adopted.removed_generation == 2);  // the old removal stands
        }
        // Every survivor still verifies as the record it claims to be.
        CHECK_OK(local_revocation_validate(adopted));
      }
    }
  }
}

void test_ram_footprint() {
  static_assert(sizeof(sdkv1::GroupKeyState) + sizeof(sdkv1::GroupSecurityProvider) <= 10 * 1024,
                "P5 GK state and Provider must fit the device RAM budget");
  // None of these is a MeshNode member; each holds one slot-sized scratch
  // plus its decoded record. The resume cache holds one slot buffer
  // whatever the slot count (C3 gateway sizing floor).
  std::printf("sizeof IdentityStore=%zu SiteStore=%zu RevocationStore=%zu ResumeCache2=%zu\n",
              sizeof(IdentityStore), sizeof(SiteStore), sizeof(RevocationStore),
              sizeof(ResumeCache2));
  std::printf("sizeof LocalRevocationStore=%zu\n", sizeof(LocalRevocationStore));
  CHECK(sizeof(ResumeCache2) <= 512);
  CHECK(sizeof(IdentityStore) <= 1408);
  CHECK(sizeof(SiteStore) <= 1536);
  CHECK(sizeof(RevocationStore) <= 2 * kRevocationSlotBytes);
  // The 108 B record is dwarfed by the shared pair machinery; the bound is
  // the record plus one slot buffer plus that fixed overhead.
  CHECK(sizeof(LocalRevocationStore) <=
        sizeof(LocalRevocationRecord) + kLocalRevocationSlotBytes + 128);
}

bool contains_secret(const SiteStore& store, const std::array<std::uint8_t, 32>& secret) {
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(&store);
  for (std::size_t i = 0; i + secret.size() <= sizeof(store); ++i) {
    if (std::memcmp(bytes + i, secret.data(), secret.size()) == 0) return true;
  }
  return false;
}

std::size_t secret_copies(const SiteStore& store, const std::array<std::uint8_t, 32>& secret) {
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(&store);
  std::size_t copies = 0;
  for (std::size_t i = 0; i + secret.size() <= sizeof(store); ++i) {
    if (std::memcmp(bytes + i, secret.data(), secret.size()) == 0) ++copies;
  }
  return copies;
}

void test_rs_floor_wipes_group_key_workspace() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord site = site_record();
  CHECK_OK(store.commit(site));
  CHECK(secret_copies(store, site.gk_current) == 1);
  CHECK_OK(store.raise_rs_floor(site.rs_epoch_floor + 1));
  CHECK(secret_copies(store, site.gk_current) == 1);
}

void test_site_scratch_does_not_retain_uncommitted_keys() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  const SiteRecord candidate = site_record();
  Digest256 digest{};
  CHECK_OK(store.fingerprint(candidate, digest));
  CHECK(!contains_secret(store, candidate.gk_current));
  storage.cut_call = 0;
  storage.cut_bytes = 0;
  CHECK(!store.commit(candidate).ok());
  CHECK(!store.has_site());
  CHECK(!contains_secret(store, candidate.gk_current));
}

void test_site_commit_refuses_failed_active_load() {
  FaultyRecordStorage storage(kSiteSlotBytes);
  SiteStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit(site_record()));
  storage.fail_read_call = storage.read_calls + 3;
  CHECK(store.initialize().code == StatusCode::StorageFailure);
  CHECK(store.health().active_load_failed);
  const std::size_t writes = storage.write_calls;
  CHECK(store.commit(site_record(4, 204)).code == StatusCode::StorageFailure);
  CHECK(storage.write_calls == writes);
}

}  // namespace

int main() {
  test_identity_basic();
  test_identity_power_cuts();
  test_identity_divergent_twins_quarantine();
  test_site_monotonicity();
  test_group_key_durable_rotation();
  test_group_stage_failure_fences_generic_writers();
  test_group_activate_cannot_extend_removal_overlap();
  test_superseded_stage_scrubs_both_slots();
  test_pending_sibling_is_scrubbed_before_group_ready();
  test_group_twin_byte_cuts();
  test_group_state_and_crypto();
  test_group_state_fences_out_of_band_site_change();
  test_group_gcm_replay();
  test_group_end_sender_capacity();
  test_group_provider_reconstruction_preserves_boot_state();
  test_group_provider_reentry_is_busy_across_views();
  test_site_power_cuts();
  test_site_recover_power_cuts();
  test_site_floors_and_faults();
  test_revocation_accept();
  test_revocation_entry_monotonicity();
  test_revocation_power_cuts();
  test_revocation_clear_power_cuts();
  test_resume2_cache_rules();
  test_resume2_find_by_id();
  test_resume2_incremental_lookup();
  test_resume2_incremental_revocation_and_clear();
  test_resume2_uses();
  test_resume2_power_cuts();
  test_resume2_touch_wear_rule();
  test_local_revocation_basic();
  test_local_revocation_power_cuts();
  test_ram_footprint();
  test_site_scratch_does_not_retain_uncommitted_keys();
  test_rs_floor_wipes_group_key_workspace();
  test_site_commit_refuses_failed_active_load();
  if (failures != 0) {
    std::fprintf(stderr, "%d sdkv1 store check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_store_tests: ok");
  return 0;
}
