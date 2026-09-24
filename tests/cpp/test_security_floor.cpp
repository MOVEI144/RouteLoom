// RLF1 security floor tests: the 136-byte codec and the
// SecurityFloorStore reservation rules — encode/decode roundtrip, CRC and
// header rejection, the no-auto-create missing-floor rule, forward-only
// advance, the expected-image conflict, idempotent resume, and the
// explicit provision_seed path.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/security_floor.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;

constexpr std::uint64_t kNet = 0xC0FFEE;
constexpr std::uint64_t kTarget = 0x30;

class FakeFloorStore final : public SecurityFloorStorage {
 public:
  Status read(const MutableByteView target) noexcept override {
    if (target.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor read");
    }
    if (!provisioned) return Status::error(StatusCode::NotFound, "floor missing");
    std::memcpy(target.data, blob_.data(), kSecurityFloorBlobBytes);
    return Status::success();
  }
  Status write(const ByteView data) noexcept override {
    if (data.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor write");
    }
    ++write_calls;
    if (fail_writes) {
      return Status::error(StatusCode::StorageFailure, "injected write error");
    }
    std::memcpy(blob_.data(), data.data, data.size);
    provisioned = true;
    return Status::success();
  }
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob_{};
  bool provisioned{false};
  bool fail_writes{false};
  std::size_t write_calls{0};
};

SecurityFloorState make_state() {
  SecurityFloorState state{};
  state.network = kNet;
  state.target = kTarget;
  state.trust_epoch_floor = 7;
  state.min_authority_generation = 2;
  state.last_manifest_hash[0] = 0xAB;
  state.namespace_count = 2;
  state.flags = kSecurityFloorTrustManaged;
  state.entries[0].config_namespace = 1;
  state.entries[0].schema = 1;
  state.entries[0].store_floor = 40;
  state.entries[0].decision_floor = 9;
  state.entries[1].config_namespace = 0x8001;
  state.entries[1].schema = 4;
  state.entries[1].store_floor = 41;
  state.entries[1].decision_floor = 11;
  return state;
}

bool state_equal(const SecurityFloorState& a, const SecurityFloorState& b) {
  if (a.network != b.network || a.target != b.target ||
      a.trust_epoch_floor != b.trust_epoch_floor ||
      a.min_authority_generation != b.min_authority_generation ||
      a.namespace_count != b.namespace_count || a.flags != b.flags) {
    return false;
  }
  for (std::size_t i = 0; i < a.last_manifest_hash.size(); ++i) {
    if (a.last_manifest_hash[i] != b.last_manifest_hash[i]) return false;
  }
  for (std::size_t i = 0; i < kSecurityFloorMaxNamespaces; ++i) {
    const SecurityFloorEntry& x = a.entries[i];
    const SecurityFloorEntry& y = b.entries[i];
    if (x.config_namespace != y.config_namespace || x.schema != y.schema ||
        x.store_floor != y.store_floor || x.decision_floor != y.decision_floor) {
      return false;
    }
  }
  return true;
}

void test_codec_roundtrip() {
  const SecurityFloorState state = make_state();
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob{};
  CHECK_OK(security_floor_encode(
      state, MutableByteView{blob.data(), blob.size()}));
  // Magic "RLF1", format 1, length 136.
  CHECK(blob[0] == 0x52 && blob[1] == 0x4C && blob[2] == 0x46 &&
        blob[3] == 0x31);
  CHECK(blob[4] == 0 && blob[5] == 1 && blob[6] == 0 && blob[7] == 136);
  SecurityFloorState decoded{};
  CHECK_OK(security_floor_decode(ByteView{blob.data(), blob.size()}, decoded));
  CHECK(state_equal(decoded, state));
}

void test_codec_rejections() {
  const SecurityFloorState state = make_state();
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob{};
  CHECK_OK(security_floor_encode(
      state, MutableByteView{blob.data(), blob.size()}));
  SecurityFloorState decoded{};
  // Any torn byte breaks the CRC.
  for (const std::size_t offset : {0u, 10u, 67u, 100u, 131u}) {
    auto torn = blob;
    torn[offset] ^= 0xFFU;
    CHECK(security_floor_decode(ByteView{torn.data(), torn.size()}, decoded)
              .code == StatusCode::IntegrityError);
  }
  // Wrong size never decodes.
  CHECK(security_floor_decode(ByteView{blob.data(), 135}, decoded).code ==
        StatusCode::InvalidArgument);
  // Unknown flags / bad namespace count / duplicate namespaces are
  // refused at encode time (never written).
  SecurityFloorState bad = state;
  bad.flags = 0x02;
  CHECK(security_floor_encode(
            bad, MutableByteView{blob.data(), blob.size()})
            .code == StatusCode::InvalidArgument);
  bad = state;
  bad.namespace_count = 0;
  CHECK(security_floor_encode(
            bad, MutableByteView{blob.data(), blob.size()})
            .code == StatusCode::InvalidArgument);
  bad = state;
  bad.entries[1].config_namespace = 1;
  CHECK(security_floor_encode(
            bad, MutableByteView{blob.data(), blob.size()})
            .code == StatusCode::InvalidArgument);
  bad = state;
  bad.entries[2].store_floor = 1;  // padding past namespace_count
  CHECK(security_floor_encode(
            bad, MutableByteView{blob.data(), blob.size()})
            .code == StatusCode::InvalidArgument);
}

void test_missing_floor_never_autocreated() {
  FakeFloorStore storage;
  SecurityFloorStore floor(storage);
  CHECK(floor.initialize().code == StatusCode::RecoveryRequired);
  CHECK(!floor.usable());
  SecurityFloorState state{};
  CHECK(floor.read(state).code == StatusCode::RecoveryRequired);
  SecurityFloorState seed = make_state();
  CHECK_OK(floor.provision_seed(seed));
  CHECK(floor.usable());
  CHECK_OK(floor.read(state));
  CHECK(state_equal(state, seed));
  // A fresh cache over the same bytes re-reads them.
  SecurityFloorStore floor2(storage);
  CHECK_OK(floor2.initialize());
  CHECK_OK(floor2.read(state));
  CHECK(state_equal(state, seed));
}

void test_advance_rules() {
  FakeFloorStore storage;
  SecurityFloorStore floor(storage);
  const SecurityFloorState seed = make_state();
  CHECK_OK(floor.provision_seed(seed));
  const std::size_t seeded_writes = storage.write_calls;

  // Forward-only: J/R/E/G rise, identity and table stay.
  SecurityFloorState next = seed;
  next.trust_epoch_floor = 8;
  next.min_authority_generation = 3;
  next.last_manifest_hash[1] = 0xCD;
  next.entries[0].store_floor = 41;
  next.entries[0].decision_floor = 10;
  CHECK_OK(floor.advance(seed, next));
  SecurityFloorState current{};
  CHECK_OK(floor.read(current));
  CHECK(state_equal(current, next));

  // Idempotent resume: advancing to the held image is a no-op success
  // that costs no flash write.
  CHECK_OK(floor.advance(next, next));
  CHECK(storage.write_calls == seeded_writes + 1);

  // A stale expected image conflicts — the caller decided against old
  // floors.
  SecurityFloorState newer = next;
  newer.entries[0].store_floor = 42;
  CHECK(floor.advance(seed, newer).code == StatusCode::Conflict);

  // Regression in any counter is refused.
  SecurityFloorState lower = next;
  lower.entries[1].store_floor = 40;
  CHECK(floor.advance(next, lower).code == StatusCode::InvalidArgument);
  lower = next;
  lower.min_authority_generation = 2;
  CHECK(floor.advance(next, lower).code == StatusCode::InvalidArgument);

  // Identity, namespace table and flags are provisioning facts.
  SecurityFloorState moved = next;
  moved.target = kTarget + 1;
  CHECK(floor.advance(next, moved).code == StatusCode::InvalidArgument);
  moved = next;
  moved.entries[0].config_namespace = 2;
  CHECK(floor.advance(next, moved).code == StatusCode::InvalidArgument);
  moved = next;
  moved.flags = 0;
  CHECK(floor.advance(next, moved).code == StatusCode::InvalidArgument);

  // A failed write invalidates the cache: intake stops until refresh.
  storage.fail_writes = true;
  CHECK(floor.advance(next, newer).code == StatusCode::StorageFailure);
  CHECK(!floor.usable());
  storage.fail_writes = false;
  CHECK_OK(floor.refresh());
  CHECK(floor.usable());
  CHECK_OK(floor.read(current));
  CHECK(state_equal(current, next));  // the failed advance never landed
  CHECK_OK(floor.advance(next, newer));
}

void test_entry_lookup() {
  const SecurityFloorState state = make_state();
  const SecurityFloorEntry* entry = SecurityFloorStore::entry_for(state, 1);
  CHECK(entry != nullptr && entry->store_floor == 40);
  CHECK(SecurityFloorStore::entry_for(state, 2) == nullptr);
}

}  // namespace

int main() {
  test_codec_roundtrip();
  test_codec_rejections();
  test_missing_floor_never_autocreated();
  test_advance_rules();
  test_entry_lookup();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom security-floor tests passed");
  return 0;
}
