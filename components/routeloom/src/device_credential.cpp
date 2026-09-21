#include "routeloom/device_credential.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom {
namespace {

// RLC1 record byte layout (big-endian via ByteWriter; ≤1024-byte slot):
//   0   u32  magic "RLC1"
//   4   u16  format version (1)
//   6   u16  used_len (bytes incl. CRC)
//   8   u32  schema_version (1)
//   12  u32  commit seal (0 pending / kCredSealCommitted committed)
//   16  u64  network (FULL NetworkId — §4.8 deployment-generation split)
//   24  u64  node_id
//   32  u32  generation_base_session
//   36  u8   key_location | u8 cred_status | u16 grant_len
//   40  32B  kid = SHA-256(canonical COSE_Key(pubkey))
//   72  64B  pubkey X||Y
//   136 32B  private_key (location 1) | opaque handle (location >=2) | zero
//   168 grant bytes (≤256)
//   len-4 u32 crc32_iso_hdlc over [0, used_len-4)
constexpr std::uint32_t kCredMagic = 0x524C4331U;  // "RLC1"
constexpr std::uint16_t kCredFormat = 1;
constexpr std::uint32_t kCredSealPending = 0U;
// New seal constant for this record family (proposed; pending registry
// landing like every number in the design document).
constexpr std::uint32_t kCredSealCommitted = 0xC0ED1CE5U;
constexpr std::size_t kCredMinRecord = kCredentialHeaderSize + kCredentialFixedBody + 4;

bool is_erased(const std::uint8_t* data, const std::size_t size) noexcept {
  const std::uint8_t fill = data[0];
  if (fill != 0x00U && fill != 0xFFU) return false;
  for (std::size_t i = 1; i < size; ++i) {
    if (data[i] != fill) return false;
  }
  return true;
}

bool all_zero(const std::uint8_t* data, const std::size_t size) noexcept {
  for (std::size_t i = 0; i < size; ++i) {
    if (data[i] != 0) return false;
  }
  return true;
}

// --- Minimal canonical-CBOR readers (grant field extraction) -----------------
// Same restricted shape family as config_cose.cpp: definite lengths and
// minimal encodings only. Duplicated file-locally because the permit
// profile's helpers are private to that TU — the alternative (a shared
// cbor unit) is a broader refactor left out of this slice.

Status cbor_expect_u8(ByteView body, std::size_t& pos,
                      const std::uint8_t value, const char* what) noexcept {
  if (pos >= body.size || body.data[pos] != value) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  ++pos;
  return Status::success();
}

Status cbor_read_bstr(ByteView body, std::size_t& pos, ByteView& out,
                      const char* what) noexcept {
  out = ByteView{};
  if (pos >= body.size) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  const std::uint8_t ib = body.data[pos++];
  std::size_t len = 0;
  if (ib >= 0x40 && ib <= 0x57) {
    len = ib - 0x40;
  } else if (ib == 0x58) {
    if (pos >= body.size) return Status::error(StatusCode::ProtocolError, what);
    len = body.data[pos++];
    if (len <= 23) return Status::error(StatusCode::ProtocolError, what);
  } else if (ib == 0x59) {
    if (pos + 2 > body.size) {
      return Status::error(StatusCode::ProtocolError, what);
    }
    len = (static_cast<std::size_t>(body.data[pos]) << 8U) | body.data[pos + 1];
    pos += 2;
    if (len <= 255) return Status::error(StatusCode::ProtocolError, what);
  } else {
    return Status::error(StatusCode::ProtocolError, what);
  }
  if (pos + len > body.size) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  out = ByteView{body.data + pos, len};
  pos += len;
  return Status::success();
}

// Canonical unsigned integer: shortest-form only (0x18 requires >=24,
// 0x19 >0xFF, 0x1A >0xFFFF, 0x1B >0xFFFFFFFF), matching the deterministic
// CBOR rule the grant payload profile uses.
Status cbor_read_uint(ByteView body, std::size_t& pos, std::uint64_t& out,
                      const char* what) noexcept {
  out = 0;
  if (pos >= body.size) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  const std::uint8_t ib = body.data[pos++];
  auto read_be = [&](const std::size_t bytes, std::uint64_t& value) -> bool {
    if (pos + bytes > body.size) return false;
    value = 0;
    for (std::size_t i = 0; i < bytes; ++i) {
      value = (value << 8U) | body.data[pos + i];
    }
    pos += bytes;
    return true;
  };
  if (ib <= 0x17) {
    out = ib;
    return Status::success();
  }
  std::uint64_t value = 0;
  std::uint64_t minimum = 0;
  std::size_t bytes = 0;
  switch (ib) {
    case 0x18: bytes = 1; minimum = 24; break;
    case 0x19: bytes = 2; minimum = 0x100; break;
    case 0x1A: bytes = 4; minimum = 0x10000; break;
    case 0x1B: bytes = 8; minimum = 0x100000000ULL; break;
    default:
      return Status::error(StatusCode::ProtocolError, what);
  }
  if (!read_be(bytes, value) || value < minimum) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  out = value;
  return Status::success();
}

// The fields the §4.3.2 boot check compares against the record, pulled out
// of the MembershipGrant's signed payload (host-security §3:
// [1, network_u32, node_u64, kid_bstr32, role_bits_u32,
//  authority_generation_u64, membership_revision_u64, not_before_u64,
//  not_after_u64]).
struct GrantFields {
  std::uint32_t network{0};
  NodeId node_id{0};
  Digest256 kid{};
};

// Parse the grant's restricted COSE_Sign1 envelope far enough to reach the
// signed payload: tag 18, array(4), protected bstr, empty unprotected map,
// payload bstr, 64-byte signature bstr, no trailing data. The signature
// itself is NOT verified here — the boot check is field consistency, and
// grant verification belongs to the membership workstream that owns the
// signing-key resolution.
Status grant_envelope_payload(ByteView grant, ByteView& payload) noexcept {
  payload = ByteView{};
  if (grant.size < 8 || grant.size > kCredentialGrantMax) {
    return Status::error(StatusCode::ProtocolError, "grant size");
  }
  std::size_t pos = 0;
  Status status = cbor_expect_u8(grant, pos, 0xD2, "grant tag18");
  if (status) status = cbor_expect_u8(grant, pos, 0x84, "grant array4");
  ByteView protected_bstr{};
  if (status) status = cbor_read_bstr(grant, pos, protected_bstr, "grant protected");
  if (status) status = cbor_expect_u8(grant, pos, 0xA0, "grant unprotected");
  if (status) status = cbor_read_bstr(grant, pos, payload, "grant payload");
  ByteView signature{};
  if (status) status = cbor_read_bstr(grant, pos, signature, "grant signature");
  if (!status) return status;
  if (protected_bstr.size == 0 || payload.size == 0 ||
      signature.size != 64 || pos != grant.size) {
    return Status::error(StatusCode::ProtocolError, "grant envelope shape");
  }
  return Status::success();
}

Status grant_fields_parse(ByteView grant, GrantFields& out) noexcept {
  out = GrantFields{};
  ByteView payload{};
  Status status = grant_envelope_payload(grant, payload);
  if (!status) return status;
  std::size_t pos = 0;
  status = cbor_expect_u8(payload, pos, 0x89, "grant payload array9");
  std::uint64_t version = 0, network = 0, node = 0, role_bits = 0;
  std::uint64_t generation = 0, revision = 0, not_before = 0, not_after = 0;
  ByteView kid{};
  if (status) status = cbor_read_uint(payload, pos, version, "grant version");
  if (status) status = cbor_read_uint(payload, pos, network, "grant network");
  if (status) status = cbor_read_uint(payload, pos, node, "grant node");
  if (status) status = cbor_read_bstr(payload, pos, kid, "grant kid");
  if (status) status = cbor_read_uint(payload, pos, role_bits, "grant roles");
  if (status) status = cbor_read_uint(payload, pos, generation, "grant generation");
  if (status) status = cbor_read_uint(payload, pos, revision, "grant revision");
  if (status) status = cbor_read_uint(payload, pos, not_before, "grant not_before");
  if (status) status = cbor_read_uint(payload, pos, not_after, "grant not_after");
  if (!status) return status;
  if (pos != payload.size || version != 1 || network > 0xFFFFFFFFULL ||
      role_bits > 0xFFFFFFFFULL || kid.size != 32) {
    return Status::error(StatusCode::ProtocolError, "grant payload fields");
  }
  out.network = static_cast<std::uint32_t>(network);
  out.node_id = node;
  std::memcpy(out.kid.data(), kid.data, kid.size);
  return Status::success();
}

// Credential equality over the semantic content: two valid records with
// identical fields encode byte-identically (deterministic codec, reserved
// bytes proven zero at decode), so field equality is byte equality.
bool same_credential(const DeviceCredential& a, const DeviceCredential& b) noexcept {
  return a.network == b.network && a.node_id == b.node_id &&
         a.generation_base_session == b.generation_base_session &&
         a.key_location == b.key_location && a.cred_status == b.cred_status &&
         a.kid == b.kid && a.pubkey == b.pubkey &&
         a.key_material == b.key_material && a.grant.size == b.grant.size &&
         (a.grant.size == 0 ||
          std::memcmp(a.grant.bytes.data(), b.grant.bytes.data(), a.grant.size) == 0);
}

Status encode_record(const DeviceCredential& credential,
                     const std::uint32_t seal, const std::size_t used_len,
                     const MutableByteView target) noexcept {
  ByteWriter writer(target);
  Status status = writer.write_u32(kCredMagic);
  if (status) status = writer.write_u16(kCredFormat);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(used_len));
  if (status) status = writer.write_u32(kCredentialSchemaVersion);
  if (status) status = writer.write_u32(seal);
  if (status) status = writer.write_u64(credential.network);
  if (status) status = writer.write_u64(credential.node_id);
  if (status) status = writer.write_u32(credential.generation_base_session);
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(credential.key_location));
  }
  if (status) {
    status = writer.write_u8(static_cast<std::uint8_t>(credential.cred_status));
  }
  if (status) {
    status = writer.write_u16(static_cast<std::uint16_t>(credential.grant.size));
  }
  if (status) {
    status = writer.write_bytes(ByteView{credential.kid.data(), credential.kid.size()});
  }
  if (status) {
    status = writer.write_bytes(
        ByteView{credential.pubkey.data(), credential.pubkey.size()});
  }
  if (status) {
    status = writer.write_bytes(
        ByteView{credential.key_material.data(), credential.key_material.size()});
  }
  if (status) status = writer.write_bytes(credential.grant.view());
  if (!status) return status;
  if (writer.size() != used_len - 4) {
    return Status::error(StatusCode::InternalError, "credential size drift");
  }
  return writer.write_u32(crc32_iso_hdlc(ByteView{target.data, used_len - 4}));
}

}  // namespace

Status credential_cose_key_encode(const ByteView pubkey,
                                  ByteBuffer<80>& out) noexcept {
  out.clear();
  if (pubkey.size != kCredentialPubkeySize || pubkey.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "credential pubkey size");
  }
  // a5 01 02 | 03 26 | 20 01 | 21 58 20 <x:32> | 22 58 20 <y:32> — 75 B.
  static constexpr std::array<std::uint8_t, 10> kHead{{
      0xA5, 0x01, 0x02,        // map(5): kty(1) = EC2(2)
      0x03, 0x26,              // alg(3) = ES256(-7)
      0x20, 0x01,              // crv(-1) = P-256(1)
      0x21, 0x58, 0x20}};      // x(-2) = bstr(32)
  ByteWriter writer(out.writable());
  Status status = writer.write_bytes(ByteView{kHead.data(), kHead.size()});
  if (status) status = writer.write_bytes(ByteView{pubkey.data, 32});
  if (status) status = writer.write_u8(0x22);  // y(-3)
  if (status) status = writer.write_u8(0x58);
  if (status) status = writer.write_u8(0x20);
  if (status) status = writer.write_bytes(ByteView{pubkey.data + 32, 32});
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status credential_kid(const ByteView pubkey, Digest256& out) noexcept {
  ByteBuffer<80> cose_key{};
  const Status status = credential_cose_key_encode(pubkey, cose_key);
  if (!status) return status;
  sha256(cose_key.view(), out);
  return Status::success();
}

Status credential_validate(const DeviceCredential& credential) noexcept {
  if (credential.network == 0 || credential.node_id == kInvalidNodeId ||
      credential.node_id == kBroadcastNodeId) {
    return Status::error(StatusCode::InvalidArgument, "credential identity");
  }
  if (credential.key_location > CredentialKeyLocation::SecureElement ||
      credential.cred_status < CredentialStatus::PendingRegistration ||
      credential.cred_status > CredentialStatus::SuspendedLocal) {
    return Status::error(StatusCode::InvalidArgument, "credential fields");
  }
  if (uECC_valid_public_key(credential.pubkey.data(), uECC_secp256r1()) == 0) {
    return Status::error(StatusCode::InvalidArgument, "credential pubkey off curve");
  }
  Digest256 computed_kid{};
  const Status kid_status =
      credential_kid(ByteView{credential.pubkey.data(), credential.pubkey.size()},
                     computed_kid);
  if (!kid_status) return kid_status;
  if (computed_kid != credential.kid) {
    return Status::error(StatusCode::IntegrityError, "credential kid mismatch");
  }
  switch (credential.key_location) {
    case CredentialKeyLocation::None:
      if (!all_zero(credential.key_material.data(), credential.key_material.size())) {
        return Status::error(StatusCode::InvalidArgument, "credential key residue");
      }
      break;
    case CredentialKeyLocation::NvsPlaintext: {
      std::array<std::uint8_t, kCredentialPubkeySize> computed_pub{};
      if (uECC_compute_public_key(credential.key_material.data(),
                                  computed_pub.data(), uECC_secp256r1()) == 0 ||
          computed_pub != credential.pubkey) {
        // Corruption, never a cue to "re-derive" a credential (§4.3.2).
        return Status::error(StatusCode::IntegrityError, "credential keypair mismatch");
      }
      break;
    }
    default:
      // eFuse/DS-bound and secure-element locations carry an opaque handle
      // the portable core cannot interpret — no local check exists.
      break;
  }
  if (credential.grant.size > 0) {
    GrantFields fields{};
    const Status parsed = grant_fields_parse(credential.grant.view(), fields);
    if (!parsed) return parsed;
    // The grant's network_u32 names the wire-visible low32 of the full
    // NetworkId (§4.8); node and kid bind the whole record.
    if (fields.network != static_cast<std::uint32_t>(credential.network & 0xFFFFFFFFULL) ||
        fields.node_id != credential.node_id || fields.kid != credential.kid) {
      return Status::error(StatusCode::IntegrityError, "credential grant mismatch");
    }
  }
  return Status::success();
}

Status credential_record_encode(const DeviceCredential& credential,
                                const std::uint32_t seal,
                                ByteBuffer<kCredentialSlotBytes>& out) noexcept {
  const Status valid = credential_validate(credential);
  if (!valid) return valid;
  if (seal != kCredSealPending && seal != kCredSealCommitted) {
    return Status::error(StatusCode::InvalidArgument, "credential seal value");
  }
  const std::size_t used_len =
      kCredentialHeaderSize + kCredentialFixedBody + credential.grant.size + 4;
  if (used_len > kCredentialSlotBytes || credential.grant.size > kCredentialGrantMax) {
    return Status::error(StatusCode::InvalidArgument, "credential oversize");
  }
  const Status status = encode_record(
      credential, seal, used_len, MutableByteView{out.bytes.data(), out.bytes.size()});
  if (!status) return status;
  out.size = used_len;
  return Status::success();
}

Status credential_record_decode(const ByteView record, DeviceCredential& out) noexcept {
  out = DeviceCredential{};
  if (record.data == nullptr || record.size < kCredMinRecord ||
      record.size > kCredentialSlotBytes) {
    return Status::error(StatusCode::ProtocolError, "credential record bounds");
  }
  ByteReader reader(record);
  std::uint32_t magic = 0, schema = 0, seal = 0;
  std::uint16_t format = 0, used_len = 0, grant_len = 0;
  std::uint8_t key_location = 0, cred_status = 0;
  Status status = reader.read_u32(magic);
  if (status) status = reader.read_u16(format);
  if (status) status = reader.read_u16(used_len);
  if (status) status = reader.read_u32(schema);
  if (status) status = reader.read_u32(seal);
  if (!status || magic != kCredMagic || format != kCredFormat ||
      used_len < kCredMinRecord || used_len > record.size) {
    return Status::error(StatusCode::ProtocolError, "credential record head");
  }
  if (seal != kCredSealCommitted) {
    return Status::error(StatusCode::ProtocolError, "credential uncommitted");
  }
  status = reader.read_u64(out.network);
  if (status) status = reader.read_u64(out.node_id);
  if (status) status = reader.read_u32(out.generation_base_session);
  if (status) status = reader.read_u8(key_location);
  if (status) status = reader.read_u8(cred_status);
  if (status) status = reader.read_u16(grant_len);
  if (!status || grant_len > kCredentialGrantMax ||
      kCredentialHeaderSize + kCredentialFixedBody + grant_len + 4 != used_len) {
    return Status::error(StatusCode::ProtocolError, "credential record length");
  }
  out.key_location = static_cast<CredentialKeyLocation>(key_location);
  out.cred_status = static_cast<CredentialStatus>(cred_status);
  status = reader.read_bytes(MutableByteView{out.kid.data(), out.kid.size()});
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.pubkey.data(), out.pubkey.size()});
  }
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.key_material.data(), out.key_material.size()});
  }
  if (status) {
    status = reader.read_bytes(
        MutableByteView{out.grant.bytes.data(), grant_len});
  }
  std::uint32_t crc = 0;
  if (status) status = reader.read_u32(crc);
  if (!status || reader.consumed() != used_len) {
    return Status::error(StatusCode::ProtocolError, "credential record truncated");
  }
  out.grant.size = grant_len;
  if (crc32_iso_hdlc(ByteView{record.data, static_cast<std::size_t>(used_len) - 4}) != crc) {
    return Status::error(StatusCode::IntegrityError, "credential record crc");
  }
  if (schema != kCredentialSchemaVersion) {
    return Status::error(StatusCode::Unsupported, "credential record schema");
  }
  return credential_validate(out);
}

Status credential_epoch_for_session(const std::uint32_t session,
                                    const std::uint32_t generation_base_session,
                                    std::uint16_t& epoch_out) noexcept {
  epoch_out = 0;
  if (session == 0 || session <= generation_base_session) {
    // A session at or before the generation base predates the window the
    // base defines — there is no epoch to derive.
    return Status::error(StatusCode::InvalidArgument, "epoch session before base");
  }
  const std::uint32_t elapsed = session - generation_base_session;
  if (elapsed >= kCredentialEpochWindowMax) {
    // The next boots would wrap the u16 epoch and silently reuse epoch 1
    // under peer floors that can never accept it: refuse bring-up with the
    // design's REPROVISION_REQUIRED wedge (§4.8) — RecoveryRequired in the
    // portable status set.
    return Status::error(StatusCode::RecoveryRequired,
                        "epoch window exhausted; re-provision required");
  }
  epoch_out = static_cast<std::uint16_t>(((elapsed - 1U) % 0xFFFFU) + 1U);
  return Status::success();
}

// --- DeviceCredentialStore -----------------------------------------------------

DeviceCredentialStore::DeviceCredentialStore(CredentialStorage& storage) noexcept
    : storage_(storage) {}

Status DeviceCredentialStore::decode_slot(const std::uint8_t slot,
                                          DeviceCredential& credential,
                                          std::size_t& used_len,
                                          SlotContent& content) noexcept {
  used_len = 0;
  auto& raw = scratch_a_;
  const Status status = storage_.read(slot, MutableByteView{raw.data(), raw.size()});
  if (!status) return status;
  if (is_erased(raw.data(), raw.size())) {
    content = SlotContent::Empty;
    return Status::success();
  }
  ByteReader reader(ByteView{raw.data(), raw.size()});
  std::uint32_t magic = 0, schema = 0, seal = 0;
  std::uint16_t format = 0, length = 0;
  Status st = reader.read_u32(magic);
  if (st) st = reader.read_u16(format);
  if (st) st = reader.read_u16(length);
  if (st) st = reader.read_u32(schema);
  if (st) st = reader.read_u32(seal);
  if (!st || magic != kCredMagic || format != kCredFormat ||
      length < kCredMinRecord || length > kCredentialRecordMax) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (seal != kCredSealCommitted) {
    // A well-formed pending record was never committed — safe to discard;
    // any other seal value is corruption.
    content = seal == kCredSealPending ? SlotContent::Pending : SlotContent::Corrupt;
    return Status::success();
  }
  std::uint8_t key_location = 0, cred_status = 0;
  std::uint16_t grant_len = 0;
  st = reader.read_u64(credential.network);
  if (st) st = reader.read_u64(credential.node_id);
  if (st) st = reader.read_u32(credential.generation_base_session);
  if (st) st = reader.read_u8(key_location);
  if (st) st = reader.read_u8(cred_status);
  if (st) st = reader.read_u16(grant_len);
  if (!st || grant_len > kCredentialGrantMax ||
      kCredentialHeaderSize + kCredentialFixedBody + grant_len + 4 != length) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  credential.key_location = static_cast<CredentialKeyLocation>(key_location);
  credential.cred_status = static_cast<CredentialStatus>(cred_status);
  st = reader.read_bytes(MutableByteView{credential.kid.data(), credential.kid.size()});
  if (st) {
    st = reader.read_bytes(
        MutableByteView{credential.pubkey.data(), credential.pubkey.size()});
  }
  if (st) {
    st = reader.read_bytes(
        MutableByteView{credential.key_material.data(), credential.key_material.size()});
  }
  if (st) {
    st = reader.read_bytes(MutableByteView{credential.grant.bytes.data(), grant_len});
  }
  std::uint32_t crc = 0;
  if (st) st = reader.read_u32(crc);
  if (!st || reader.consumed() != length) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  credential.grant.size = grant_len;
  used_len = length;
  if (crc32_iso_hdlc(ByteView{raw.data(), static_cast<std::size_t>(length) - 4}) != crc) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (schema != kCredentialSchemaVersion) {
    content = SlotContent::Unsupported;
    return Status::success();
  }
  // CRC + schema prove a real committed record; the consistency checks
  // (kid recompute, keypair, grant fields) decide whether it can serve as
  // this node's credential. A failure is corruption, never a re-derive.
  if (!credential_validate(credential).ok()) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  content = SlotContent::Valid;
  return Status::success();
}

Status DeviceCredentialStore::initialize() noexcept {
  std::array<SlotContent, kCredentialSlots> content{};
  std::array<std::size_t, kCredentialSlots> used_len{};
  std::array<bool, kCredentialSlots> unreadable{};
  Status read_error = Status::success();
  int valid = 0, corrupt = 0, unsupported = 0;
  for (std::uint8_t slot = 0; slot < kCredentialSlots; ++slot) {
    slot_reserved_[slot] = StatusCode::Ok;
    parsed_[slot] = DeviceCredential{};
    const Status status =
        decode_slot(slot, parsed_[slot], used_len[slot], content[slot]);
    if (!status) {
      unreadable[slot] = true;
      if (read_error.ok()) read_error = status;
      continue;
    }
    switch (content[slot]) {
      case SlotContent::Valid:
        ++valid;
        break;
      case SlotContent::Unsupported:
        ++unsupported;
        slot_reserved_[slot] = StatusCode::Unsupported;
        break;
      case SlotContent::Corrupt:
        ++corrupt;
        break;
      default:
        break;
    }
  }

  auto quarantine = [&](const StatusCode code, const char* detail) {
    quarantined_ = true;
    initialized_ = true;
    has_active_ = false;
    credential_ = DeviceCredential{};
    return Status::error(code, detail);
  };

  const auto provably_absent = [&](const std::uint8_t slot) {
    return !unreadable[slot] &&
           (content[slot] == SlotContent::Empty || content[slot] == SlotContent::Pending);
  };

  const auto adopt = [&](const std::uint8_t slot) {
    credential_ = parsed_[slot];
    active_slot_ = slot;
    has_active_ = true;
  };

  if (unreadable[0] && unreadable[1]) {
    return read_error.ok()
               ? Status::error(StatusCode::StorageFailure, "credential store unreadable")
               : read_error;
  }

  if (valid == 2) {
    // RLC1 has no ordinal: a commit writes the same record to both slots,
    // so two valid survivors must be identical. Different-but-valid
    // siblings cannot be ordered — quarantine rather than guess which
    // credential the last interrupted commit intended.
    if (!same_credential(parsed_[0], parsed_[1])) {
      return quarantine(StatusCode::IntegrityError, "credential records diverge");
    }
    adopt(0);
    initialized_ = true;
    return Status::success();
  }

  if (valid == 1) {
    const std::uint8_t slot = content[0] == SlotContent::Valid ? 0 : 1;
    adopt(slot);
    initialized_ = true;
    if (!provably_absent(static_cast<std::uint8_t>(slot ^ 1U))) {
      // The sibling may hold a different committed credential: known value
      // only — commits refuse until recover() (the journal's uncertain
      // posture, §4.3.1/06 §6.3).
      uncertain_ = true;
      return Status::error(StatusCode::IntegrityError,
                         "credential sibling state unproven");
    }
    return Status::success();
  }

  if (unreadable[0] || unreadable[1]) {
    return read_error;  // a storage fault, not proven corruption — retryable
  }
  if (unsupported > 0) {
    return quarantine(StatusCode::Unsupported, "credential schema unsupported");
  }
  if (corrupt > 0) {
    return quarantine(StatusCode::IntegrityError, "credential store corrupt");
  }

  // Fresh: all slots empty or pending-only — the device simply has no
  // credential yet (pre-provisioning), not an impairment.
  initialized_ = true;
  return Status::success();
}

Status DeviceCredentialStore::store_record(const std::uint8_t slot,
                                           const DeviceCredential& credential,
                                           const std::size_t used_len) noexcept {
  auto& buffer = scratch_a_;
  // Phase 1: unsealed record; a power cut leaves discardable pending bytes.
  Status status =
      encode_record(credential, kCredSealPending, used_len,
                    MutableByteView{buffer.data(), buffer.size()});
  if (!status) return status;
  status = storage_.write(slot, ByteView{buffer.data(), used_len});
  if (!status) return status;
  // Phase 2: commit seal.
  status = encode_record(credential, kCredSealCommitted, used_len,
                         MutableByteView{buffer.data(), buffer.size()});
  if (!status) return status;
  status = storage_.write(slot, ByteView{buffer.data(), used_len});
  if (!status) return status;
  // Phase 3: readback before the record counts as landed.
  auto& verify = scratch_b_;
  status = storage_.read(slot, MutableByteView{verify.data(), verify.size()});
  if (!status) return status;
  if (std::memcmp(verify.data(), buffer.data(), used_len) != 0) {
    return Status::error(StatusCode::StorageFailure, "credential readback mismatch");
  }
  return Status::success();
}

Status DeviceCredentialStore::commit_record(const DeviceCredential& credential) noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "credential store not initialized");
  }
  if (quarantined_) {
    return Status::error(StatusCode::IntegrityError, "credential store quarantined");
  }
  if (uncertain_) {
    return Status::error(StatusCode::RecoveryRequired,
                        "credential sibling state unproven");
  }
  if (slot_reserved_[0] != StatusCode::Ok) {
    return Status::error(slot_reserved_[0], "credential slot owned by other data");
  }
  if (slot_reserved_[1] != StatusCode::Ok) {
    return Status::error(slot_reserved_[1], "credential slot owned by other data");
  }
  const Status valid = credential_validate(credential);
  if (!valid) return valid;
  const std::size_t used_len =
      kCredentialHeaderSize + kCredentialFixedBody + credential.grant.size + 4;
  // RLC1 carries no ordinal, so both slots take the identical record —
  // that is what makes "two valid survivors must be identical" the correct
  // boot rule (§4.9 budgets the 2-slot × 2-phase write).
  Status status = store_record(0, credential, used_len);
  if (!status) return status;
  status = store_record(1, credential, used_len);
  if (!status) return status;
  credential_ = credential;
  active_slot_ = 0;
  has_active_ = true;
  return Status::success();
}

Status DeviceCredentialStore::recover(const DeviceCredential& credential) noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "credential store not initialized");
  }
  if (!quarantined_ && !uncertain_) {
    return Status::error(StatusCode::InvalidState, "credential store not impaired");
  }
  const Status valid = credential_validate(credential);
  if (!valid) return valid;
  const std::size_t used_len =
      kCredentialHeaderSize + kCredentialFixedBody + credential.grant.size + 4;
  Status status = store_record(0, credential, used_len);
  if (!status) return status;
  status = store_record(1, credential, used_len);
  if (!status) return status;
  slot_reserved_[0] = StatusCode::Ok;
  slot_reserved_[1] = StatusCode::Ok;
  credential_ = credential;
  active_slot_ = 0;
  has_active_ = true;
  quarantined_ = false;
  uncertain_ = false;
  return Status::success();
}

}  // namespace routeloom
