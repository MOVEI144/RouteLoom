// Authority ledger persistence tests: double-slot commit protocol, power-cut
// injection at every write boundary, quarantine and operator recovery, schema
// and identity handling, and the CRC-32/ISO-HDLC primitive.

#include <array>
#include <cstdint>
#include <cstdio>

#include "routeloom/authority.hpp"
#include "routeloom/crc32.hpp"

#include "test_ledger.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::FaultyLedgerStorage;

constexpr std::size_t kRecord = kAuthorityLedgerRecordSize;
constexpr std::size_t kCrcOffset = kRecord - 4;
constexpr std::size_t kSchemaOffset = 8;
constexpr std::size_t kStateHashOffset = 56;

AuthorityOperation make_op(const SingleAuthority& authority, const std::uint64_t sequence,
                           const AuthorityOperationKind kind = AuthorityOperationKind::Generic) {
  AuthorityOperation op{};
  op.network = authority.state().network;
  op.authority = authority.state().authority;
  op.generation = authority.state().generation;
  op.sequence = sequence;
  op.kind = kind;
  op.previous_state_hash = authority.state().state_hash;
  const std::array<std::uint8_t, 8> payload{{
      static_cast<std::uint8_t>(sequence), 1, 2, 3, 4, 5, 6, 7}};
  op.operation_hash = bind_operation_payload(kind, ByteView{payload.data(), payload.size()});
  return op;
}

Digest256 hash_with(const std::uint8_t tag) {
  Digest256 hash{};
  hash[0] = tag;
  return hash;
}

// Rewrites a stored slot field and repairs the record CRC so the slot stays
// structurally intact (used to fabricate schema/chain variations a plain
// corruption test cannot produce).
void patch_slot(FaultyLedgerStorage& storage, const std::uint8_t slot,
                const std::size_t offset, const std::uint8_t value) {
  auto& bytes = storage.slot_bytes(slot);
  bytes[offset] = value;
  const std::uint32_t crc = crc32_iso_hdlc(ByteView{bytes.data(), kCrcOffset});
  bytes[kCrcOffset] = static_cast<std::uint8_t>(crc >> 24U);
  bytes[kCrcOffset + 1] = static_cast<std::uint8_t>(crc >> 16U);
  bytes[kCrcOffset + 2] = static_cast<std::uint8_t>(crc >> 8U);
  bytes[kCrcOffset + 3] = static_cast<std::uint8_t>(crc);
}

void commit_two(FaultyLedgerStorage& storage) {
  SingleAuthority authority(1, 99, storage);
  CHECK_OK(authority.initialize());
  CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
  CHECK_OK(authority.commit(make_op(authority, 2), hash_with(0x22), true));
}

void test_crc32_vector() {
  const char* known = "123456789";
  CHECK(crc32_iso_hdlc(ByteView{reinterpret_cast<const std::uint8_t*>(known), 9}) == 0xCBF43926U);
  CHECK(crc32_iso_hdlc(ByteView{nullptr, 0}) == 0U);
}

void test_ledger_persistence_roundtrip() {
  FaultyLedgerStorage storage;
  {
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
    CHECK_OK(authority.commit(make_op(authority, 2), hash_with(0x22), true));
    CHECK(authority.revision() == 2);
    CHECK(storage.write_calls == 4);  // pending body + commit seal per commit
  }
  {
    SingleAuthority reboot(1, 99, storage);
    CHECK_OK(reboot.initialize());
    CHECK(reboot.state().applied_sequence == 2);
    CHECK(reboot.state().state_hash == hash_with(0x22));
    CHECK(reboot.revision() == 2);
    // Replaying the committed operation is Conflict, not re-applied.
    CHECK(reboot.commit(make_op(reboot, 2), hash_with(0x33), true).code == StatusCode::Conflict);
    CHECK(reboot.state().applied_sequence == 2);
    CHECK(reboot.validate(make_op(reboot, 4), true).code == StatusCode::InvalidState);
  }
}

void test_ledger_pending_write_boundaries() {
  // Power cut at every byte boundary of the pending-record write: the previous
  // committed state must always survive.
  for (std::size_t boundary = 0; boundary <= kRecord; ++boundary) {
    FaultyLedgerStorage storage;
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
    storage.cut_call = storage.write_calls;
    storage.cut_bytes = boundary;
    CHECK(!authority.commit(make_op(authority, 2), hash_with(0x22), true));
    SingleAuthority reboot(1, 99, storage);
    CHECK_OK(reboot.initialize());
    CHECK(!reboot.quarantined());
    CHECK(reboot.state().applied_sequence == 1);
    CHECK(reboot.state().state_hash == hash_with(0x11));
    CHECK(reboot.revision() == 1);
  }
}

void test_ledger_commit_seal_boundaries() {
  // Power cut at every byte boundary of the commit-marker write: only a fully
  // landed seal may activate the new record.
  for (std::size_t boundary = 0; boundary <= kRecord; ++boundary) {
    FaultyLedgerStorage storage;
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
    storage.cut_call = storage.write_calls + 1;  // the seal write of commit 2
    storage.cut_bytes = boundary;
    CHECK(!authority.commit(make_op(authority, 2), hash_with(0x22), true));
    SingleAuthority reboot(1, 99, storage);
    CHECK_OK(reboot.initialize());
    if (boundary == kRecord) {
      CHECK(reboot.state().applied_sequence == 2);
      CHECK(reboot.state().state_hash == hash_with(0x22));
    } else {
      CHECK(reboot.state().applied_sequence == 1);
      CHECK(reboot.state().state_hash == hash_with(0x11));
    }
  }
}

void test_ledger_cut_between_phases() {
  FaultyLedgerStorage storage;
  SingleAuthority authority(1, 99, storage);
  CHECK_OK(authority.initialize());
  CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
  // Pending body lands; power dies before the commit-marker write starts.
  storage.drop_call = storage.write_calls + 1;
  CHECK(!authority.commit(make_op(authority, 2), hash_with(0x22), true));
  SingleAuthority reboot(1, 99, storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.state().applied_sequence == 1);
  CHECK(reboot.state().state_hash == hash_with(0x11));
}

void test_ledger_first_commit_torn() {
  // A cut inside the very first pending write never produces a half-applied
  // record: a discardable pending fragment restores genesis, unverifiable
  // bytes quarantine instead of silently resetting.
  for (std::size_t boundary = 0; boundary <= kRecord; ++boundary) {
    FaultyLedgerStorage storage;
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    storage.cut_call = 0;
    storage.cut_bytes = boundary;
    CHECK(!authority.commit(make_op(authority, 1), hash_with(0x11), true));
    SingleAuthority reboot(1, 99, storage);
    const Status loaded = reboot.initialize();
    if (boundary == 0 || boundary >= 8) {
      // Nothing landed, or the fragment is a provably-uncommitted pending
      // record (seal reads 0 on erased storage): genesis is the safe state.
      CHECK_OK(loaded);
      CHECK(reboot.state().applied_sequence == 0);
    } else {
      // A partial header is unverifiable: quarantine, never a silent reset.
      CHECK(loaded.code == StatusCode::IntegrityError);
      CHECK(reboot.quarantined());
    }
  }
}

void test_ledger_corrupt_one_slot() {
  FaultyLedgerStorage storage;
  commit_two(storage);
  storage.corrupt(0, 100);  // the older revision
  SingleAuthority reboot(1, 99, storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.state().applied_sequence == 2);
  CHECK(reboot.state().state_hash == hash_with(0x22));
  // The corrupt slot is reclaimed by the next commit.
  CHECK_OK(reboot.commit(make_op(reboot, 3), hash_with(0x33), true));
  SingleAuthority again(1, 99, storage);
  CHECK_OK(again.initialize());
  CHECK(again.state().applied_sequence == 3);
}

void test_ledger_corrupt_both_quarantine() {
  FaultyLedgerStorage storage;
  commit_two(storage);
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  SingleAuthority reboot(1, 99, storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
  // Quarantine is terminal: validate/commit fail with a distinct code and the
  // state is not silently reset to revision 0 for continued use.
  CHECK(reboot.validate(make_op(reboot, 3), true).code == StatusCode::IntegrityError);
  CHECK(reboot.commit(make_op(reboot, 3), hash_with(0x33), true).code == StatusCode::IntegrityError);
  // Only an explicit operator recovery rewrites the ledger.
  CHECK_OK(reboot.recover(2));
  CHECK(!reboot.quarantined());
  CHECK(reboot.state().applied_sequence == 0);
  CHECK_OK(reboot.commit(make_op(reboot, 1), hash_with(0x44), true));
  SingleAuthority again(1, 99, storage);
  CHECK_OK(again.initialize());
  CHECK(again.state().applied_sequence == 1);
  CHECK(again.state().state_hash == hash_with(0x44));
}

void test_ledger_broken_chain_quarantine() {
  FaultyLedgerStorage storage;
  commit_two(storage);
  // Both records stay individually valid but the hash chain no longer links:
  // the ledger cannot prove which revision is authoritative.
  patch_slot(storage, 0, kStateHashOffset, 0xEE);
  SingleAuthority reboot(1, 99, storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
  CHECK(reboot.revision() == 2);  // provenance of the lost state stays visible
  CHECK_OK(reboot.recover(2));
  CHECK(reboot.revision() == 3);  // recovery never regresses the ledger index
  SingleAuthority again(1, 99, storage);
  CHECK_OK(again.initialize());
  CHECK(again.state().applied_sequence == 0);
}

void test_ledger_schema_mismatch() {
  // Sole committed record carries an unsupported schema_version: reject and
  // quarantine rather than interpret or reset.
  FaultyLedgerStorage storage;
  {
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
  }
  patch_slot(storage, 0, kSchemaOffset + 3, 2);
  SingleAuthority reboot(1, 99, storage);
  CHECK(reboot.initialize().code == StatusCode::Unsupported);
  CHECK(reboot.quarantined());
  CHECK(reboot.commit(make_op(reboot, 1), hash_with(0x22), true).code ==
        StatusCode::IntegrityError);

  // A valid sibling still boots, but the unsupported slot is never overwritten.
  FaultyLedgerStorage storage2;
  commit_two(storage2);
  patch_slot(storage2, 0, kSchemaOffset + 3, 2);  // the older revision
  SingleAuthority mixed(1, 99, storage2);
  CHECK_OK(mixed.initialize());
  CHECK(mixed.state().applied_sequence == 2);
  CHECK(mixed.commit(make_op(mixed, 3), hash_with(0x33), true).code == StatusCode::Unsupported);
}

void test_ledger_foreign_identity() {
  FaultyLedgerStorage storage;
  {
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    CHECK_OK(authority.commit(make_op(authority, 1), hash_with(0x11), true));
  }
  SingleAuthority wrong_network(2, 99, storage);
  CHECK(wrong_network.initialize().code == StatusCode::Conflict);
  SingleAuthority wrong_authority(1, 7, storage);
  CHECK(wrong_authority.initialize().code == StatusCode::Conflict);
}

void test_ledger_recovery_new_generation() {
  // Both records stay CRC-intact but the chain breaks: boot sees proven
  // generation 1, quarantines, and recovery must start a NEW generation so
  // operations signed for the pre-loss generation can never be applied.
  FaultyLedgerStorage storage;
  commit_two(storage);
  patch_slot(storage, 0, kStateHashOffset, 0xEE);
  SingleAuthority reboot(1, 99, storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.quarantined());
  CHECK_OK(reboot.recover(2));
  CHECK(reboot.state().generation == 2);
  // An operation carrying the pre-recovery generation is rejected even when
  // its sequence/hash would otherwise be valid.
  AuthorityOperation stale = make_op(reboot, 1);
  stale.generation = 1;
  CHECK(reboot.commit(stale, hash_with(0x55), true).code ==
        StatusCode::AuthorizationFailed);
  CHECK_OK(reboot.commit(make_op(reboot, 1), hash_with(0x66), true));
}

void test_ledger_recovery_never_reuses_generation() {
  // gen 1 -> recover to gen 2 -> BOTH slots corrupt -> reinit must refuse to
  // recover into generation 2 again. The corrupt records still carry a
  // committed seal so their generation fields bound the recovery floor; an
  // old gen-2 operation must stay rejected after recovery to generation 3.
  FaultyLedgerStorage storage;
  commit_two(storage);  // generation 1
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  {
    SingleAuthority reboot(1, 99, storage);
    CHECK(reboot.initialize().code == StatusCode::IntegrityError);
    CHECK_OK(reboot.recover(2));
    CHECK_OK(reboot.commit(make_op(reboot, 1), hash_with(0x77), true));
  }
  // Second total loss: one byte inside the hash region of each slot. CRC
  // fails but the committed generation fields survive and bound recovery.
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  SingleAuthority lost(1, 99, storage);
  CHECK(lost.initialize().code == StatusCode::IntegrityError);
  CHECK(lost.quarantined());
  CHECK(lost.recover(2).code == StatusCode::InvalidArgument);
  CHECK(lost.recover(1).code == StatusCode::InvalidArgument);
  CHECK_OK(lost.recover(3));
  CHECK(lost.state().generation == 3);
  AuthorityOperation stale = make_op(lost, 1);
  stale.generation = 2;
  CHECK(lost.commit(stale, hash_with(0x55), true).code ==
        StatusCode::AuthorizationFailed);
}

void test_ledger_unreadable_sibling_blocks_boot() {
  // One slot reads fine but its sibling faults: the unreadable slot might
  // hold a NEWER committed record, so booting the stale readable one — or
  // clobbering the unreadable slot with a commit — is unsafe.
  FaultyLedgerStorage storage;
  commit_two(storage);
  storage.read_error_slot = 1;  // slot 1 holds the newer record
  SingleAuthority reboot(1, 99, storage);
  CHECK(reboot.initialize().code == StatusCode::StorageFailure);
  CHECK(!reboot.quarantined());
}

void test_ledger_read_error_not_quarantine() {
  FaultyLedgerStorage storage;
  commit_two(storage);
  storage.read_error = true;
  SingleAuthority reboot(1, 99, storage);
  // An unreadable slot is a storage fault, not proven corruption: report the
  // failure instead of quarantining or resetting.
  CHECK(reboot.initialize().code == StatusCode::StorageFailure);
  CHECK(!reboot.quarantined());
  CHECK(reboot.validate(make_op(reboot, 3), true).code == StatusCode::InvalidState);
}

void test_ledger_operation_kinds() {
  FaultyLedgerStorage storage;
  SingleAuthority authority(1, 99, storage);
  CHECK_OK(authority.initialize());
  const std::array<std::uint8_t, 8> member{{0xAA, 1, 2, 3, 4, 5, 6, 7}};
  CHECK(bind_operation_payload(AuthorityOperationKind::MembershipApproval,
                               ByteView{member.data(), member.size()}) !=
        bind_operation_payload(AuthorityOperationKind::MembershipRevocation,
                               ByteView{member.data(), member.size()}));

  auto approve = make_op(authority, 1, AuthorityOperationKind::MembershipApproval);
  approve.operation_hash = bind_operation_payload(AuthorityOperationKind::MembershipApproval,
                                                  ByteView{member.data(), member.size()});
  CHECK(authority.apply_remote_config(approve, hash_with(0x44), true).code ==
        StatusCode::InvalidArgument);
  CHECK_OK(authority.apply_membership_approval(approve, hash_with(0x44), true));
  CHECK(authority.state().applied_sequence == 1);

  CHECK_OK(authority.apply_membership_revocation(
      make_op(authority, 2, AuthorityOperationKind::MembershipRevocation), hash_with(0x55), true));
  CHECK_OK(authority.apply_remote_config(
      make_op(authority, 3, AuthorityOperationKind::RemoteConfig), hash_with(0x66), true));

  // Operation kinds persist through the ledger; replay stays Conflict.
  SingleAuthority reboot(1, 99, storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.state().applied_sequence == 3);
  CHECK(reboot.apply_membership_revocation(
      make_op(reboot, 2, AuthorityOperationKind::MembershipRevocation), hash_with(0x55), true)
            .code == StatusCode::Conflict);
}

void test_ledger_storage_contract() {
  // Storage faults never trigger automatic erase: an interrupted write leaves
  // the unwritten tail byte-identical and the sibling slot untouched.
  FaultyLedgerStorage storage;
  commit_two(storage);
  const auto before0 = storage.slot_bytes(0);
  const auto before1 = storage.slot_bytes(1);
  {
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    storage.cut_call = storage.write_calls;
    storage.cut_bytes = 40;
    CHECK(authority.commit(make_op(authority, 3), hash_with(0x33), true).code ==
          StatusCode::StorageFailure);
  }
  CHECK(std::memcmp(storage.slot_bytes(0).data() + 40, before0.data() + 40,
                    kRecord - 40) == 0);
  CHECK(storage.slot_bytes(1) == before1);

  // A commit whose readback cannot be verified reports failure even though
  // the record may have landed; the next boot recovers whatever persisted.
  {
    SingleAuthority authority(1, 99, storage);
    CHECK_OK(authority.initialize());
    storage.read_error = true;
    CHECK(authority.commit(make_op(authority, 3), hash_with(0x33), true).code ==
          StatusCode::StorageFailure);
    CHECK(authority.state().applied_sequence == 2);
    storage.read_error = false;
  }
  SingleAuthority reboot(1, 99, storage);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.state().applied_sequence == 3);
  CHECK(reboot.commit(make_op(reboot, 3), hash_with(0x33), true).code == StatusCode::Conflict);
}

}  // namespace

int main() {
  test_crc32_vector();
  test_ledger_persistence_roundtrip();
  test_ledger_pending_write_boundaries();
  test_ledger_commit_seal_boundaries();
  test_ledger_cut_between_phases();
  test_ledger_first_commit_torn();
  test_ledger_corrupt_one_slot();
  test_ledger_corrupt_both_quarantine();
  test_ledger_broken_chain_quarantine();
  test_ledger_schema_mismatch();
  test_ledger_foreign_identity();
  test_ledger_recovery_new_generation();
  test_ledger_recovery_never_reuses_generation();
  test_ledger_unreadable_sibling_blocks_boot();
  test_ledger_read_error_not_quarantine();
  test_ledger_operation_kinds();
  test_ledger_storage_contract();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom authority ledger tests passed");
  return 0;
}
