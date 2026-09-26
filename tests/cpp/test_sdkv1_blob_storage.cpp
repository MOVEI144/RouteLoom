// SDK v1 stores over the key/blob storage port (sdkv1_blob_storage.hpp) —
// the portable half of the `rlsec` NVS adapter (docs/design/sdk-v1/05 §5,
// 08 P7-1). The ESP-IDF adapter only forwards to nvs_get_blob/nvs_set_blob;
// everything that decides what a slot "is" runs here against a fake NVS
// with NVS's own semantics (a key update is atomic: a power cut leaves the
// old or the new value, never a mix; commit is durable).
//  - read-back contract: missing key = erased, present-but-erased/zeroed/
//    empty = corrupt, oversize or short read = corrupt, backend errors =
//    StorageFailure;
//  - key/namespace mapping (rlident i0/i1, rlsite s0/s1, rlrevo r0/r1,
//    rlres2 s00..s15 / s000..s159) and blobs of exactly used_len bytes;
//  - IdentityStore / SiteStore / RevocationStore / ResumeCache2 end to end,
//    including a manufactured (office-written) twin pair and a power cut at
//    every write of commit/clear with the value either landed or not.

#include <cstdio>
#include <map>
#include <string>

#include "routeloom/sdkv1_blob_storage.hpp"
#include "test_sdkv1.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace sdkv1_test;

constexpr std::size_t kNever = static_cast<std::size_t>(-1);

// One NVS namespace. Key updates are atomic like NVS: an interrupted
// blob_write leaves either the previous value or the new one.
class FakeNvs final : public BlobNamespace {
 public:
  Status blob_size(const char* key, std::size_t& size, bool& found) noexcept override {
    size = 0;
    found = false;
    ++size_calls;
    if (size_error) return Status::error(StatusCode::StorageFailure, "injected size error");
    const auto it = blobs.find(key);
    if (it == blobs.end()) return Status::success();
    size = it->second.size();
    found = true;
    return Status::success();
  }
  Status blob_read(const char* key, const MutableByteView target,
                   std::size_t& read_len) noexcept override {
    read_len = 0;
    if (read_error) return Status::error(StatusCode::StorageFailure, "injected read error");
    const auto it = blobs.find(key);
    if (it == blobs.end() || target.size < it->second.size()) {
      return Status::error(StatusCode::StorageFailure, "fake read arguments");
    }
    std::memcpy(target.data, it->second.data(), it->second.size());
    read_len = it->second.size() - (short_read ? 1U : 0U);
    return Status::success();
  }
  Status blob_write(const char* key, const ByteView data) noexcept override {
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      if (cut_lands) blobs[key].assign(data.data, data.data + data.size);
      return Status::error(StatusCode::StorageFailure, "power cut");
    }
    blobs[key].assign(data.data, data.data + data.size);
    return Status::success();
  }
  Status blob_erase(const char* key) noexcept override {
    blobs.erase(key);
    return Status::success();
  }
  void disarm() {
    cut_call = kNever;
    size_error = read_error = short_read = false;
  }

  std::map<std::string, std::vector<std::uint8_t>> blobs;
  std::size_t write_calls{0};
  std::size_t size_calls{0};
  std::size_t cut_call{kNever};
  bool cut_lands{false};
  bool size_error{false};
  bool read_error{false};
  bool short_read{false};
};

bool all_equal(const std::vector<std::uint8_t>& bytes, const std::uint8_t value) {
  for (const auto byte : bytes) {
    if (byte != value) return false;
  }
  return true;
}

std::vector<std::uint8_t> read_slot(BlobNamespace& nvs, const char* key, const std::size_t size,
                                    Status* status_out = nullptr) {
  std::vector<std::uint8_t> view(size, 0x11);
  const Status status = read_blob_slot(nvs, key, MutableByteView{view.data(), view.size()});
  if (status_out != nullptr) *status_out = status;
  return view;
}

// --- read-back contract ---------------------------------------------------------

void test_read_contract() {
  FakeNvs nvs;
  // Missing key: erased image (Empty to the store).
  CHECK(all_equal(read_slot(nvs, "i0", 64), 0xFF));
  // Present blob: its bytes, erased tail.
  nvs.blobs["i0"] = {1, 2, 3};
  auto view = read_slot(nvs, "i0", 8);
  CHECK(view[0] == 1 && view[1] == 2 && view[2] == 3);
  for (std::size_t i = 3; i < view.size(); ++i) CHECK(view[i] == 0xFF);
  // A blob filling the view exactly has no tail.
  nvs.blobs["i0"].assign(8, 0x42);
  CHECK(all_equal(read_slot(nvs, "i0", 8), 0x42));
  // Present but uniformly erased / zeroed / empty: evidence of a torn
  // write, never Empty.
  for (const std::uint8_t fill : {std::uint8_t{0xFF}, std::uint8_t{0x00}}) {
    nvs.blobs["i0"].assign(8, fill);
    CHECK(all_equal(read_slot(nvs, "i0", 8), kBlobCorruptFill));
  }
  nvs.blobs["i0"].assign(5, 0xFF);  // erased prefix + erased tail
  CHECK(all_equal(read_slot(nvs, "i0", 8), kBlobCorruptFill));
  nvs.blobs["i0"].clear();
  CHECK(all_equal(read_slot(nvs, "i0", 8), kBlobCorruptFill));
  // Mixed content (a zero prefix before the erased tail) is passed through
  // for the store to classify (bad magic -> Corrupt) — the invariant is
  // that a present blob never reads as the uniformly erased Empty image.
  nvs.blobs["i0"].assign(5, 0x00);
  view = read_slot(nvs, "i0", 8);
  CHECK(view[0] == 0x00 && view[7] == 0xFF && !all_equal(view, 0xFF));
  // Oversize: unusable, not erased.
  nvs.blobs["i0"].assign(9, 0x42);
  CHECK(all_equal(read_slot(nvs, "i0", 8), kBlobCorruptFill));
  // Read length disagreeing with the reported size.
  nvs.blobs["i0"].assign(4, 0x42);
  nvs.short_read = true;
  CHECK(all_equal(read_slot(nvs, "i0", 8), kBlobCorruptFill));
  nvs.disarm();
  // Backend faults surface as StorageFailure (the store keeps them retryable).
  Status status = Status::success();
  nvs.size_error = true;
  (void)read_slot(nvs, "i0", 8, &status);
  CHECK(status.code == StatusCode::StorageFailure);
  nvs.disarm();
  nvs.read_error = true;
  (void)read_slot(nvs, "i0", 8, &status);
  CHECK(status.code == StatusCode::StorageFailure);
  nvs.disarm();
  // Argument errors.
  std::uint8_t byte = 0;
  CHECK(read_blob_slot(nvs, nullptr, MutableByteView{&byte, 1}).code ==
        StatusCode::InvalidArgument);
  CHECK(read_blob_slot(nvs, "i0", MutableByteView{&byte, 0}).code == StatusCode::InvalidArgument);
}

void test_record_storage_mapping() {
  FakeNvs nvs;
  auto identity = BlobRecordSlotStorage::identity(nvs);
  auto site = BlobRecordSlotStorage::site(nvs);
  auto revocation = BlobRecordSlotStorage::revocation(nvs);
  auto lifecycle = BlobRecordSlotStorage::lifecycle(nvs);
  const std::uint8_t data[3] = {7, 8, 9};
  CHECK_OK(identity.write(0, ByteView{data, 3}));
  CHECK_OK(identity.write(1, ByteView{data, 2}));
  CHECK_OK(site.write(0, ByteView{data, 1}));
  CHECK_OK(site.write(1, ByteView{data, 1}));
  CHECK_OK(revocation.write(0, ByteView{data, 1}));
  CHECK_OK(revocation.write(1, ByteView{data, 1}));
  CHECK_OK(lifecycle.write(0, ByteView{data, 3}));
  CHECK_OK(lifecycle.write(1, ByteView{data, 2}));
  // Exactly data.size bytes per blob (never slot-padded), fixed key names.
  CHECK(nvs.blobs.size() == 8);
  CHECK(nvs.blobs["i0"].size() == 3 && nvs.blobs["i1"].size() == 2);
  CHECK(nvs.blobs.count("s0") == 1 && nvs.blobs.count("s1") == 1);
  CHECK(nvs.blobs.count("r0") == 1 && nvs.blobs.count("r1") == 1);
  CHECK(nvs.blobs["x0"].size() == 3 && nvs.blobs["x1"].size() == 2);
  // Slot views must be the store's slot size; slot index 0/1 only.
  std::vector<std::uint8_t> view(kIdentitySlotBytes);
  CHECK_OK(identity.read(0, MutableByteView{view.data(), view.size()}));
  CHECK(view[0] == 7 && view[2] == 9 && view[3] == 0xFF);
  CHECK(identity.read(2, MutableByteView{view.data(), view.size()}).code ==
        StatusCode::InvalidArgument);
  CHECK(identity.read(0, MutableByteView{view.data(), view.size() - 1}).code ==
        StatusCode::InvalidArgument);
  CHECK(revocation.read(0, MutableByteView{view.data(), view.size()}).code ==
        StatusCode::InvalidArgument);
  CHECK(lifecycle.read(0, MutableByteView{view.data(), view.size()}).code ==
        StatusCode::InvalidArgument);
  std::vector<std::uint8_t> lifecycle_view(kLifecycleSlotBytes);
  CHECK_OK(lifecycle.read(1, MutableByteView{lifecycle_view.data(), lifecycle_view.size()}));
  CHECK(lifecycle_view[0] == 7 && lifecycle_view[1] == 8 && lifecycle_view[2] == 0xFF);
  std::vector<std::uint8_t> big(kRevocationSlotBytes + 1, 1);
  CHECK(revocation.write(0, ByteView{big.data(), big.size()}).code ==
        StatusCode::InvalidArgument);
  CHECK(identity.write(0, ByteView{data, 0}).code == StatusCode::InvalidArgument);
  CHECK(identity.write(2, ByteView{data, 1}).code == StatusCode::InvalidArgument);
}

void test_resume_keys() {
  char key[kResumeKeyBytes]{};
  CHECK_OK(BlobResumeSlotStorage2::slot_key(0, kResumeNodeSlots, key));
  CHECK(std::string(key) == "s00");
  CHECK_OK(BlobResumeSlotStorage2::slot_key(15, kResumeNodeSlots, key));
  CHECK(std::string(key) == "s15");
  CHECK_OK(BlobResumeSlotStorage2::slot_key(99, 100, key));
  CHECK(std::string(key) == "s99");
  CHECK_OK(BlobResumeSlotStorage2::slot_key(0, kResumeGatewaySlots, key));
  CHECK(std::string(key) == "s000");
  CHECK_OK(BlobResumeSlotStorage2::slot_key(159, kResumeGatewaySlots, key));
  CHECK(std::string(key) == "s159");
  CHECK_OK(BlobResumeSlotStorage2::slot_key(998, kResumeSlotsMax, key));
  CHECK(std::string(key) == "s998");
  CHECK(BlobResumeSlotStorage2::slot_key(16, kResumeNodeSlots, key).code ==
        StatusCode::InvalidArgument);
  CHECK(BlobResumeSlotStorage2::slot_key(0, 0, key).code == StatusCode::InvalidArgument);
  CHECK(BlobResumeSlotStorage2::slot_key(0, kResumeSlotsMax + 1, key).code ==
        StatusCode::InvalidArgument);
  // Every gateway key is distinct and fits NVS's 15-character limit.
  std::map<std::string, int> seen;
  for (std::size_t i = 0; i < kResumeGatewaySlots; ++i) {
    CHECK_OK(BlobResumeSlotStorage2::slot_key(i, kResumeGatewaySlots, key));
    CHECK(std::string(key).size() == 4);
    ++seen[key];
  }
  CHECK(seen.size() == kResumeGatewaySlots);
  FakeNvs nvs;
  BlobResumeSlotStorage2 invalid(nvs, 0);
  CHECK(invalid.slot_count() == 0);
  BlobResumeSlotStorage2 too_many(nvs, kResumeSlotsMax + 1);
  CHECK(too_many.slot_count() == 0);
}

// --- stores end to end ------------------------------------------------------------

std::vector<std::uint8_t> encoded_identity(const IdentityRecord& record) {
  ByteBuffer<kIdentitySlotBytes> encoded{};
  CHECK_OK(identity_record_encode(record, kIdentitySealCommitted, encoded));
  return std::vector<std::uint8_t>(encoded.bytes.data(), encoded.bytes.data() + encoded.size);
}

void test_identity_store_over_nvs() {
  const IdentityRecord record = identity_record();
  {
    FakeNvs nvs;
    auto storage = BlobRecordSlotStorage::identity(nvs);
    IdentityStore store(storage);
    CHECK_OK(store.initialize());
    CHECK(!store.has_identity() && !store.quarantined() && !store.uncertain());
    CHECK_OK(store.commit(record));
    // The twin pair lands as two identical blobs of exactly used_len bytes.
    const auto expected = encoded_identity(record);
    CHECK(nvs.blobs["i0"] == expected && nvs.blobs["i1"] == expected);
    CHECK(nvs.blobs.size() == 2);
    IdentityStore reboot(storage);
    CHECK_OK(reboot.initialize());
    CHECK(reboot.has_identity() && reboot.identity().node_id == kNode);
  }
  {
    // The office-manufactured `rlsec` image (routeloomctl
    // provision-identity): the same committed record in i0 and i1, never
    // written by the device. It adopts cleanly.
    FakeNvs nvs;
    nvs.blobs["i0"] = encoded_identity(record);
    nvs.blobs["i1"] = nvs.blobs["i0"];
    auto storage = BlobRecordSlotStorage::identity(nvs);
    IdentityStore store(storage);
    CHECK_OK(store.initialize());
    CHECK(store.has_identity() && !store.uncertain());
    CHECK(store.identity().devcert.size == record.devcert.size);
    // One slot only (the other key missing) still adopts cleanly: a missing
    // key is provably "never written".
    nvs.blobs.erase("i1");
    IdentityStore single(storage);
    CHECK_OK(single.initialize());
    CHECK(single.has_identity() && !single.uncertain());
    // A PRESENT-but-erased sibling is not proof of absence: the known value
    // is kept but commits are refused until recover().
    nvs.blobs["i1"].assign(64, 0xFF);
    IdentityStore torn(storage);
    CHECK(torn.initialize().code == StatusCode::IntegrityError);
    CHECK(torn.has_identity() && torn.uncertain());
    CHECK(torn.commit(record).code == StatusCode::RecoveryRequired);
    CHECK_OK(torn.recover(record));
    CHECK(nvs.blobs["i1"] == nvs.blobs["i0"]);
    // Both present-but-zeroed: quarantine, never a fresh unprovisioned store.
    nvs.blobs["i0"].assign(16, 0x00);
    nvs.blobs["i1"].assign(16, 0x00);
    IdentityStore wiped(storage);
    CHECK(wiped.initialize().code == StatusCode::IntegrityError);
    CHECK(wiped.quarantined() && !wiped.has_identity());
  }
}

void test_erase_restores_factory_empty() {
  // The deprovision primitive: both keys erased, the store re-observes
  // factory-empty (missing keys, never present-but-erased), and a fresh
  // provision commits cleanly.
  FakeNvs nvs;
  auto storage = BlobRecordSlotStorage::identity(nvs);
  IdentityStore store(storage);
  CHECK_OK(store.initialize());
  CHECK_OK(store.commit(identity_record()));
  CHECK(nvs.blobs.size() == 2);
  CHECK_OK(store.clear());
  CHECK(nvs.blobs.empty());
  CHECK(!store.has_identity() && !store.quarantined() && !store.uncertain());
  IdentityStore reboot(storage);
  CHECK_OK(reboot.initialize());
  CHECK(!reboot.has_identity() && !reboot.quarantined() && !reboot.uncertain());
  CHECK_OK(reboot.commit(identity_record()));
  CHECK(reboot.has_identity());
  // Erasing an already-empty slot and an out-of-range slot.
  CHECK_OK(storage.erase(0));
  CHECK_OK(store.clear());
  CHECK(storage.erase(2).code == StatusCode::InvalidArgument);
}

void test_identity_power_cuts_over_nvs() {
  // Replace an identity with a cut at each of the four blob writes (pending
  // and sealed for i0 then i1), the interrupted update landing or not.
  const IdentityRecord old_record = identity_record(false);
  const IdentityRecord new_record = identity_record(true);
  for (const bool lands : {false, true}) {
    for (std::size_t call = 0; call < 4; ++call) {
      FakeNvs nvs;
      auto storage = BlobRecordSlotStorage::identity(nvs);
      {
        IdentityStore store(storage);
        CHECK_OK(store.initialize());
        CHECK_OK(store.commit(old_record));
        nvs.cut_call = nvs.write_calls + call;
        nvs.cut_lands = lands;
        CHECK(store.commit(new_record).code == StatusCode::StorageFailure);
      }
      nvs.disarm();
      IdentityStore reboot(storage);
      const Status status = reboot.initialize();
      // Twin pair: the new identity exists only once i0 was sealed (call 1
      // landed, or any later call); i0 new + i1 old is a divergent pair and
      // quarantines (office re-provisioning is an explicit recover()).
      const bool i0_sealed = call > 1 || (call == 1 && lands);
      if (reboot.has_identity()) {
        const std::uint8_t flags = reboot.identity().flags;
        CHECK(flags == old_record.flags || (i0_sealed && flags == new_record.flags));
      }
      if (!i0_sealed) CHECK(status.ok() && reboot.identity().flags == old_record.flags);
      if (call == 1 && lands) CHECK(reboot.quarantined());
      if (call == 3 && lands) CHECK(status.ok() && reboot.identity().flags == new_record.flags);
      if (reboot.quarantined() || reboot.uncertain()) {
        CHECK(!status.ok());
        CHECK(reboot.commit(new_record).code != StatusCode::Ok);
        CHECK_OK(reboot.recover(new_record));
      } else {
        CHECK_OK(status);
        CHECK_OK(reboot.commit(new_record));
      }
      IdentityStore again(storage);
      CHECK_OK(again.initialize());
      CHECK(again.has_identity() && again.identity().flags == new_record.flags);
    }
  }
}

void test_site_and_revocation_over_nvs() {
  FakeNvs site_nvs;
  FakeNvs revo_nvs;
  auto site_storage = BlobRecordSlotStorage::site(site_nvs);
  auto revo_storage = BlobRecordSlotStorage::revocation(revo_nvs);
  {
    SiteStore site(site_storage);
    CHECK_OK(site.initialize());
    CHECK_OK(site.commit(site_record(3, 203)));
    CHECK_OK(site.commit(site_record(3, 204)));  // A/B: the other key
    CHECK(site_nvs.blobs.count("s0") == 1 && site_nvs.blobs.count("s1") == 1);
    CHECK(site_nvs.blobs["s0"] != site_nvs.blobs["s1"]);
    RevocationStore revocations(revo_storage);
    CHECK_OK(revocations.initialize());
    const auto object = revocation_object(revocation_set(1));
    CHECK_OK(revocations.accept(object.view(), sak().pub, kSiteId, kNetwork));
    CHECK(revo_nvs.blobs.size() == 1);
    const auto newer = revocation_object(revocation_set(2, 3));
    CHECK_OK(revocations.accept(newer.view(), sak().pub, kSiteId, kNetwork));
    CHECK(revo_nvs.blobs.size() == 2);
  }
  SiteStore site(site_storage);
  CHECK_OK(site.initialize());
  CHECK(site.has_site() && site.site().gk_epoch_current == 204);
  RevocationStore revocations(revo_storage);
  CHECK_OK(revocations.initialize());
  CHECK(revocations.has_set() && revocations.rs_epoch() == 2);
  // Removal: the tombstone lands in both keys; no GK/DAMS copy survives.
  CHECK_OK(site.clear());
  CHECK(site_nvs.blobs["s0"] == site_nvs.blobs["s1"]);
  CHECK(site_nvs.blobs["s0"].size() == 200);
  SiteStore removed(site_storage);
  CHECK_OK(removed.initialize());
  CHECK(!removed.has_site());
  // A cut GK update (either landed or not) adopts the old or the new record.
  for (const bool lands : {false, true}) {
    for (std::size_t call = 0; call < 2; ++call) {
      FakeNvs nvs;
      auto storage = BlobRecordSlotStorage::site(nvs);
      {
        SiteStore store(storage);
        CHECK_OK(store.initialize());
        CHECK_OK(store.commit(site_record(3, 203)));
        nvs.cut_call = nvs.write_calls + call;
        nvs.cut_lands = lands;
        CHECK(store.commit(site_record(3, 204)).code == StatusCode::StorageFailure);
      }
      nvs.disarm();
      SiteStore reboot(storage);
      CHECK_OK(reboot.initialize());
      CHECK(reboot.has_site());
      const std::uint32_t gk = reboot.site().gk_epoch_current;
      CHECK(gk == 203 || (gk == 204 && lands && call == 1));
    }
  }
}

void test_resume_cache_over_nvs() {
  FakeNvs nvs;
  BlobResumeSlotStorage2 storage(nvs, kResumeNodeSlots);
  CHECK(storage.slot_count() == kResumeNodeSlots);
  ResumeCache2 cache(storage, kResume2NodeLinkQuota, kResume2NodeEndQuota);
  const ResumeContext context{kNetwork, 203, nullptr};
  ResumeSlot2 out{};
  std::size_t index = 0;
  // Nothing written: every key missing = every slot empty.
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, context, out, index).code ==
        StatusCode::NotFound);
  CHECK(nvs.blobs.empty());
  CHECK_OK(cache.put(resume2_slot(100), context));
  CHECK_OK(cache.put(resume2_slot(101), context));
  CHECK(nvs.blobs.size() == 2 && nvs.blobs["s00"].size() == kResume2SlotBytes &&
        nvs.blobs.count("s01") == 1);
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 101, context, out, index));
  CHECK(index == 1 && out.rms == resume2_slot(101).rms);
  // A wrong-size or present-but-erased blob is an unusable slot (full
  // EDHOC), and is the first reused.
  nvs.blobs["s00"].resize(kResume2SlotBytes - 1);
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, context, out, index).code ==
        StatusCode::NotFound);
  nvs.blobs["s00"].assign(kResume2SlotBytes, 0xFF);
  CHECK(cache.find_by_peer(ResumePurpose::Link, 100, context, out, index).code ==
        StatusCode::NotFound);
  CHECK_OK(cache.put(resume2_slot(102), context));
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 102, context, out, index));
  CHECK(index == 0);
  // The revocation sweep scrubs the RMS from the stored blob (peer 102
  // is not revoked and survives the same two sweep steps).
  RevocationSet rrs{};
  rrs.entries[0] = RevocationEntry{101, 2, RevocationReason::Removed};
  rrs.count = 1;
  const ResumeContext guarded{kNetwork, 203, &rrs};
  std::size_t cursor = 0;
  bool done = true;
  CHECK_OK(cache.sweep_revoked(guarded, cursor, done));
  CHECK(!done);
  CHECK_OK(cache.sweep_revoked(guarded, cursor, done));
  ResumeSlot2 scrubbed{};
  CHECK_OK(resume2_slot_decode(ByteView{nvs.blobs["s01"].data(), nvs.blobs["s01"].size()},
                               scrubbed));
  CHECK(!scrubbed.valid);
  CHECK(all_equal(std::vector<std::uint8_t>(nvs.blobs["s01"].begin() + 60,
                                            nvs.blobs["s01"].begin() + 92),
                  0x00));
  CHECK_OK(cache.find_by_peer(ResumePurpose::Link, 102, context, out, index));
  // Gateway sizing: 160 fixed keys (32 link + 128 end), same RAM.
  FakeNvs gateway_nvs;
  BlobResumeSlotStorage2 gateway(gateway_nvs, kResumeGatewaySlots);
  ResumeCache2 gateway_cache(gateway, kResume2GatewayLinkQuota, kResume2GatewayEndQuota);
  for (NodeId peer = 200; peer < 200 + kResume2GatewayLinkQuota; ++peer) {
    CHECK_OK(gateway_cache.put(
        resume2_slot(peer, 0, static_cast<std::uint32_t>(peer), 203, ResumePurpose::Link),
        context));
  }
  for (NodeId peer = 300; peer < 300 + kResume2GatewayEndQuota; ++peer) {
    CHECK_OK(gateway_cache.put(
        resume2_slot(peer, 0, static_cast<std::uint32_t>(peer), 203, ResumePurpose::End),
        context));
  }
  CHECK(gateway_nvs.blobs.size() == kResumeGatewaySlots);
  CHECK(gateway_nvs.blobs.count("s000") == 1 && gateway_nvs.blobs.count("s159") == 1);
  // Backend faults propagate.
  nvs.read_error = true;
  CHECK(cache.find_by_peer(ResumePurpose::Link, 102, context, out, index).code ==
        StatusCode::StorageFailure);
  nvs.disarm();
}

void test_ram_footprint() {
  // The storage ports are two pointers and a size; wiring the stores
  // adds nothing beyond the stores' own scratch buffers (C3 floor).
  std::printf("sizeof BlobRecordSlotStorage=%zu BlobResumeSlotStorage2=%zu\n",
              sizeof(BlobRecordSlotStorage), sizeof(BlobResumeSlotStorage2));
  CHECK(sizeof(BlobRecordSlotStorage) <= 6 * sizeof(void*));
  CHECK(sizeof(BlobResumeSlotStorage2) <= 4 * sizeof(void*));
}

}  // namespace

int main() {
  test_read_contract();
  test_record_storage_mapping();
  test_resume_keys();
  test_identity_store_over_nvs();
  test_erase_restores_factory_empty();
  test_identity_power_cuts_over_nvs();
  test_site_and_revocation_over_nvs();
  test_resume_cache_over_nvs();
  test_ram_footprint();
  if (failures != 0) {
    std::fprintf(stderr, "%d sdkv1 blob storage check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_blob_storage_tests: ok");
  return 0;
}
