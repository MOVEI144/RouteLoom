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
//  - ResumeCache LRU/pin/validity rules, the touch wear rule and torn-slot
//    handling at every byte boundary.

#include <cstdio>
#include <functional>

#include "routeloom/key_schedule.hpp"
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
  // Complete replacement: an empty cutover set with a raised floor.
  const auto cutover = revocation_object(revocation_set(16, 0, kSiteEpoch));
  CHECK_OK(store.accept(cutover.view(), sak().pub, kSiteId, kNetwork));
  CHECK(store.set().count == 0 && store.rejects(kNode, 3, kSiteEpoch - 1));
  ByteBuffer<kRevocationObjectMax> loaded{};
  CHECK_OK(store.load_object(loaded));
  CHECK(loaded.size == cutover.size &&
        std::memcmp(loaded.bytes.data(), cutover.bytes.data(), cutover.size) == 0);
  RevocationStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.has_set() && reboot.rs_epoch() == 16);
  CHECK_OK(reboot.clear());
  CHECK(!reboot.has_set());
  CHECK(reboot.load_object(loaded).code == StatusCode::NotFound);
  RevocationStore after_clear(storage);
  CHECK_OK(after_clear.initialize());
  CHECK(!after_clear.has_set());
  // After removal a new site's first set (lower epoch) is accepted.
  CHECK_OK(after_clear.accept(first.view(), sak().pub, kSiteId, kNetwork));
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
  const auto newer = revocation_object(revocation_set(20, 1));
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

// --- ResumeCache -----------------------------------------------------------------

ResumeContext context(const std::uint32_t gk_epoch = 203, const RevocationSet* rrs = nullptr) {
  return ResumeContext{kNetwork, gk_epoch, rrs};
}

ResumeSlot2 resume2_slot(const NodeId peer, const std::uint8_t flags = 0,
                         const std::uint32_t last_used_boot = 0,
                         const std::uint32_t gk_epoch = 203,
                         const ResumePurpose purpose = ResumePurpose::Link) {
  ResumeSlot2 slot{};
  slot.valid = true;
  slot.purpose = purpose;
  slot.flags = flags;
  slot.peer = peer;
  slot.network = kNetwork;
  slot.peer_cert_id = {1, 2, 3, 4, 5, 6, 7, 8};
  slot.local_cert_id = {9, 9, 9, 9, 9, 9, 9, 9};
  slot.peer_generation = 1;
  slot.peer_role = 0b011;
  slot.created_gk_epoch = gk_epoch;
  slot.last_used_boot = last_used_boot;
  for (std::size_t i = 0; i < slot.rms.size(); ++i) {
    slot.rms[i] = static_cast<std::uint8_t>(peer + i + 1);
  }
  return slot;
}

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

void test_resume_cache_rules() {
  FaultyResumeStorage storage(4);
  ResumeCache cache(storage);
  ResumeSlot out{};
  std::size_t index = 0;
  CHECK(cache.find(ResumePurpose::Link, kPeer, context(), out, index).code ==
        StatusCode::NotFound);
  CHECK_OK(cache.put(resume_slot(100, 0, 10), context()));
  CHECK_OK(cache.put(resume_slot(101, 0, 5), context()));
  CHECK_OK(cache.put(resume_slot(102, kResumeFlagPinned, 1), context()));
  CHECK_OK(cache.put(resume_slot(103, 0, 20), context()));
  // Full: the unpinned slot with the smallest last_used_boot (101) goes.
  CHECK_OK(cache.put(resume_slot(104, 0, 30), context()));
  CHECK(cache.find(ResumePurpose::Link, 101, context(), out, index).code == StatusCode::NotFound);
  CHECK_OK(cache.find(ResumePurpose::Link, 102, context(), out, index));  // pinned survived
  // Same peer + purpose replaces in place; another purpose is a new slot.
  ResumeSlot replacement = resume_slot(104, 0, 40);
  replacement.rms[0] ^= 0xFF;
  CHECK_OK(cache.put(replacement, context()));
  CHECK_OK(cache.find(ResumePurpose::Link, 104, context(), out, index));
  CHECK(out.rms == replacement.rms);
  // Pin budget: slots - 2 = 2 pinned at most.
  CHECK_OK(cache.put(resume_slot(105, kResumeFlagPinned, 50), context()));
  CHECK(cache.put(resume_slot(106, kResumeFlagPinned, 60), context()).code ==
        StatusCode::NoCapacity);
  // Validity: GK age, network, revocation.
  CHECK_OK(cache.find(ResumePurpose::Link, 104, context(204), out, index));
  CHECK(cache.find(ResumePurpose::Link, 104, context(205), out, index).code ==
        StatusCode::NotFound);  // created 203 + 2 <= 205
  ResumeContext other_network = context();
  other_network.network = kNetwork + 1;
  CHECK(cache.find(ResumePurpose::Link, 104, other_network, out, index).code ==
        StatusCode::NotFound);
  RevocationSet rrs = revocation_set(1, 0);
  rrs.entries[0] = RevocationEntry{104, 2, RevocationReason::Lost};
  rrs.count = 1;
  const ResumeContext revoked = context(203, &rrs);
  CHECK(cache.find(ResumePurpose::Link, 104, revoked, out, index).code == StatusCode::NotFound);
  // Unusable slots are reused first.
  CHECK_OK(cache.put(resume_slot(107, 0, 0), revoked));
  CHECK_OK(cache.find(ResumePurpose::Link, 107, revoked, out, index));
  // invalidate_peer scrubs the RMS from storage.
  CHECK_OK(cache.find(ResumePurpose::Link, 102, context(), out, index));
  const std::size_t pinned_index = index;
  CHECK_OK(cache.invalidate_peer(102));
  ResumeSlot empty{};
  CHECK_OK(resume_slot_decode(ByteView{storage.slot(pinned_index).data(), kResumeSlotBytes}, empty));
  CHECK(!empty.valid);
  CHECK(cache.find(ResumePurpose::Link, 102, context(), out, index).code == StatusCode::NotFound);
}

void test_resume_touch_wear_rule() {
  FaultyResumeStorage storage(3);
  ResumeCache cache(storage);
  CHECK_OK(cache.put(resume_slot(100, 0, 1000), context()));
  ResumeSlot out{};
  std::size_t index = 0;
  CHECK_OK(cache.find(ResumePurpose::Link, 100, context(), out, index));
  const std::size_t writes = storage.write_calls;
  for (std::uint32_t boot = 1000; boot < 1256; ++boot) CHECK_OK(cache.touch(index, boot, false));
  CHECK(storage.write_calls == writes);  // 1-minute wake-ups for ~4 h: no writes
  CHECK_OK(cache.touch(index, 1256, false));
  CHECK(storage.write_calls == writes + 1);
  CHECK_OK(cache.touch(index, 1257, true));  // GK change forces the update
  CHECK(storage.write_calls == writes + 2);
  CHECK_OK(cache.find(ResumePurpose::Link, 100, context(), out, index));
  CHECK(out.last_used_boot == 1257);
  CHECK(cache.touch(2, 5, true).code == StatusCode::NotFound);
}

void test_resume_power_cuts() {
  // Cut a put() (replacing peer 100's slot) at every byte: the slot then
  // reads either as the old secret, the new one, or unusable — never a mix.
  const ResumeSlot old_slot = resume_slot(100, 0, 1);
  ResumeSlot new_slot = resume_slot(100, 0, 2);
  new_slot.rms.fill(0x77);
  for (std::size_t boundary = 0; boundary <= kResumeSlotBytes; ++boundary) {
    FaultyResumeStorage storage(4);
    {
      ResumeCache cache(storage);
      CHECK_OK(cache.put(old_slot, context()));
      storage.cut_call = storage.write_calls;
      storage.cut_bytes = boundary;
      CHECK(!cache.put(new_slot, context()).ok());
    }
    ResumeCache reboot(storage);
    ResumeSlot out{};
    std::size_t index = 0;
    const Status found = reboot.find(ResumePurpose::Link, 100, context(), out, index);
    if (found.ok()) {
      // A prefix identical to the old record still reads as the old record;
      // anything that decodes is exactly one of the two, never a mix.
      CHECK((out.rms == old_slot.rms && out.last_used_boot == 1) ||
            (out.rms == new_slot.rms && out.last_used_boot == 2 &&
             boundary == kResumeSlotBytes));
    } else {
      CHECK(found.code == StatusCode::NotFound);
    }
    // clear_all scrubs torn slots too.
    CHECK_OK(reboot.clear_all());
    for (std::size_t i = 0; i < storage.slot_count(); ++i) {
      const auto& raw = storage.slot(i);
      bool erased = true;
      for (const auto byte : raw) erased = erased && byte == 0xFF;
      ResumeSlot slot{};
      CHECK(erased || (resume_slot_decode(ByteView{raw.data(), raw.size()}, slot).ok() &&
                       !slot.valid));
    }
  }
}

// --- ResumeCache2 (RLP2) -------------------------------------------------------------

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
    // Peer 100's slot is spent; re-put a fresh RMS and the count restarts.
    ResumeSlot2 fresh = resume2_slot(100, 0, 4000);
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

// --- LocalRevocationStore (RLV1, P4-M01) ----------------------------------------------

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
  // None of these is a MeshNode member; each holds one slot-sized scratch
  // plus its decoded record. The resume caches hold one slot buffer
  // whatever the slot count (C3 gateway sizing floor).
  std::printf("sizeof IdentityStore=%zu SiteStore=%zu RevocationStore=%zu ResumeCache=%zu\n",
              sizeof(IdentityStore), sizeof(SiteStore), sizeof(RevocationStore),
              sizeof(ResumeCache));
  std::printf("sizeof ResumeCache2=%zu LocalRevocationStore=%zu\n", sizeof(ResumeCache2),
              sizeof(LocalRevocationStore));
  CHECK(sizeof(ResumeCache) <= 128);
  CHECK(sizeof(ResumeCache2) <= 512);
  CHECK(sizeof(IdentityStore) <= 2 * kIdentitySlotBytes);
  CHECK(sizeof(SiteStore) <= 2 * kSiteSlotBytes);
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
  test_site_power_cuts();
  test_site_recover_power_cuts();
  test_site_floors_and_faults();
  test_revocation_accept();
  test_revocation_power_cuts();
  test_resume_cache_rules();
  test_resume_touch_wear_rule();
  test_resume_power_cuts();
  test_resume2_cache_rules();
  test_resume2_find_by_id();
  test_resume2_uses();
  test_resume2_power_cuts();
  test_local_revocation_basic();
  test_local_revocation_power_cuts();
  test_ram_footprint();
  test_site_scratch_does_not_retain_uncommitted_keys();
  test_site_commit_refuses_failed_active_load();
  if (failures != 0) {
    std::fprintf(stderr, "%d sdkv1 store check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_store_tests: ok");
  return 0;
}
