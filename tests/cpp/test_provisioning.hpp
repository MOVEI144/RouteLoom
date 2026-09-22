#pragma once

// Shared fixtures for the provisioning-lifecycle portable-core tests
// (sdk-completion/04-provisioning-lifecycle.md): in-memory dual-slot storage
// with byte-granular power-cut injection in the same style as
// test_ledger.hpp's FaultyLedgerStorage, plus the crypto helpers the trust
// image format needs — real P-256 keypairs (uECC_compute_public_key over
// fixed scalars, no RNG required) and RFC-6979 deterministic signing
// normalized to the low-S rule the RTM1 envelope enforces.

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

#include "routeloom/byte_io.hpp"
#include "routeloom/config_cose.hpp"  // kSecp256r1Order/HalfOrder, cose_be32_cmp
#include "routeloom/crc32.hpp"
#include "routeloom/device_credential.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256, Sha256
#include "routeloom/trust_manifest.hpp"
#include "routeloom/trust_store.hpp"

extern "C" {
#include "uECC.h"
}

namespace routeloom_test {

// --- Wire constants mirrored from the codecs (they are the format contract; the
// symbols themselves are file-local to the .cpp units) -------------------------
constexpr std::uint32_t kTrustSealPendingWire = 0U;
constexpr std::uint32_t kTrustSealCommittedWire = 0x7A51C9E2U;  // §4.3.1
constexpr std::uint32_t kCredSealPendingWire = 0U;
constexpr std::uint32_t kCredSealCommittedWire = 0xC0ED1CE5U;  // §4.3.2

// --- P-256 key fixtures -------------------------------------------------------
// Private scalars are fixed test constants (any value in [1, n)); the public
// halves are derived with the same micro-ecc the codecs run on.

struct TestKeyPair {
  std::array<std::uint8_t, 32> priv{};
  std::array<std::uint8_t, 64> pub{};  // X || Y
};

inline TestKeyPair test_keypair(const std::uint8_t seed) {
  TestKeyPair pair;
  pair.priv.fill(seed);
  // uECC_compute_public_key has no range gate; these patterns are all < n.
  const int ok =
      uECC_compute_public_key(pair.priv.data(), pair.pub.data(), uECC_secp256r1());
  (void)ok;  // fixed scalars are valid by construction
  return pair;
}

// SHA-256-backed uECC_HashContext for uECC_sign_deterministic (RFC 6979 — no
// RNG needed on the host test path either).
struct DetSha256Context {
  uECC_HashContext base;
  routeloom::Sha256 sha;
  std::array<std::uint8_t, 32 + 32 + 64> tmp{};
};

inline void det_sha256_init(const uECC_HashContext* context) {
  const_cast<routeloom::Sha256&>(
      reinterpret_cast<const DetSha256Context*>(context)->sha)
      .reset();
}
inline void det_sha256_update(const uECC_HashContext* context,
                              const std::uint8_t* message,
                              const unsigned message_size) {
  const_cast<routeloom::Sha256&>(
      reinterpret_cast<const DetSha256Context*>(context)->sha)
      .update(routeloom::ByteView{message, message_size});
}
inline void det_sha256_finish(const uECC_HashContext* context,
                              std::uint8_t* hash_result) {
  routeloom::ScopeDigest digest{};
  const_cast<routeloom::Sha256&>(
      reinterpret_cast<const DetSha256Context*>(context)->sha)
      .finish(digest);
  std::memcpy(hash_result, digest.data(), digest.size());
}

// Big-endian 32-byte subtraction: out = a - b (test-local, a >= b assumed).
inline void be32_sub(std::array<std::uint8_t, 32>& a,
                     const std::array<std::uint8_t, 32>& b) {
  int borrow = 0;
  for (int i = 31; i >= 0; --i) {
    const int diff = static_cast<int>(a[i]) - static_cast<int>(b[i]) - borrow;
    a[i] = static_cast<std::uint8_t>(diff);
    borrow = diff < 0 ? 1 : 0;
  }
}

// Sign a 32-byte digest; normalizes S to the low-S canonical form the RTM1
// verifier requires (mirroring what a production RootSigner must emit).
inline bool sign_digest_low_s(const std::array<std::uint8_t, 32>& priv,
                              const routeloom::ScopeDigest& digest,
                              std::array<std::uint8_t, 64>& signature) {
  DetSha256Context context{};
  context.base = {&det_sha256_init, &det_sha256_update, &det_sha256_finish,
                  64, 32, context.tmp.data()};
  if (uECC_sign_deterministic(priv.data(), digest.data(),
                              static_cast<unsigned>(digest.size()),
                              &context.base, signature.data(),
                              uECC_secp256r1()) == 0) {
    return false;
  }
  std::array<std::uint8_t, 32> s{};
  std::memcpy(s.data(), signature.data() + 32, 32);
  if (routeloom::cose_be32_cmp(s, routeloom::kSecp256r1HalfOrder) > 0) {
    // (r, n - s) is the same signature in canonical form.
    std::array<std::uint8_t, 32> flipped = routeloom::kSecp256r1Order;
    be32_sub(flipped, s);
    std::memcpy(signature.data() + 32, flipped.data(), 32);
  }
  return true;
}

// --- RLT1 image builders ------------------------------------------------------

inline routeloom::TrustAnchor test_anchor(const std::uint64_t root_id,
                                          const std::array<std::uint8_t, 64>& pubkey,
                                          const routeloom::TrustAnchorStatus status =
                                              routeloom::TrustAnchorStatus::Active) {
  routeloom::TrustAnchor anchor{};
  anchor.root_id = root_id;
  anchor.pubkey = pubkey;
  anchor.status = status;
  return anchor;
}

inline routeloom::TrustKeyRecord test_key_record(
    const std::uint64_t authority_id, const std::uint32_t generation,
    const std::array<std::uint8_t, 64>& pubkey,
    const routeloom::TrustKeyStatus status = routeloom::TrustKeyStatus::Active) {
  routeloom::TrustKeyRecord key{};
  key.authority_id = authority_id;
  key.generation = generation;
  key.status = status;
  key.pubkey = pubkey;
  return key;
}

inline routeloom::TrustRevocation test_revocation(
    const routeloom::NodeId node, const routeloom::Digest256& kid,
    const std::uint32_t at_epoch) {
  routeloom::TrustRevocation revocation{};
  revocation.node_id = node;
  revocation.kid_fingerprint = kid;
  revocation.revoked_at_epoch = at_epoch;
  return revocation;
}

// Minimal valid image: one active anchor, given epoch/network.
inline routeloom::TrustImage test_image(const std::uint32_t epoch,
                                        const routeloom::NetworkId network,
                                        const TestKeyPair& anchor_key,
                                        const std::uint64_t root_id = 0x100) {
  routeloom::TrustImage image{};
  image.store_epoch = epoch;
  image.min_authority_generation = 1;
  image.network = network;
  image.deployment_id = 0xDE9L;
  image.anchors[0] = test_anchor(root_id, anchor_key.pub);
  image.anchor_count = 1;
  return image;
}

// Rewrite `offset` inside a stored RLT1/RLC1 record and repair the CRC so the
// slot stays structurally intact (used_len lives at bytes 6-7, CRC at
// used_len-4). Mirrors patch_slot() in test_ledger.cpp.
template <std::size_t SlotBytes>
inline void patch_record(std::array<std::uint8_t, SlotBytes>& slot,
                         const std::size_t offset, const std::uint8_t value) {
  slot[offset] = value;
  const std::size_t used_len =
      (static_cast<std::size_t>(slot[6]) << 8U) | slot[7];
  const std::uint32_t crc = routeloom::crc32_iso_hdlc(
      routeloom::ByteView{slot.data(), used_len - 4});
  slot[used_len - 4] = static_cast<std::uint8_t>(crc >> 24U);
  slot[used_len - 3] = static_cast<std::uint8_t>(crc >> 16U);
  slot[used_len - 2] = static_cast<std::uint8_t>(crc >> 8U);
  slot[used_len - 1] = static_cast<std::uint8_t>(crc);
}

template <std::size_t SlotBytes>
inline std::size_t record_used_len(
    const std::array<std::uint8_t, SlotBytes>& slot) {
  return (static_cast<std::size_t>(slot[6]) << 8U) | slot[7];
}

// --- Fault-injection dual-slot storage -----------------------------------------
// Same discipline as FaultyLedgerStorage: slots read back uniformly erased
// (0xFF, the NVS-missing-blob convention) until written; each write() either
// lands fully, lands a byte prefix then reports failure (mid-write cut), or
// lands nothing (power lost between phases).

class FaultyTrustStorage final : public routeloom::TrustStoreStorage {
 public:
  FaultyTrustStorage() noexcept {
    for (auto& slot : slots_) slot.fill(0xFF);
  }
  routeloom::Status read(const std::uint8_t slot,
                         const routeloom::MutableByteView target) noexcept override {
    if (slot >= routeloom::kTrustStoreSlots || target.data == nullptr ||
        target.size != routeloom::kTrustStoreSlotBytes) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument,
                                    "bad trust read");
    }
    if (read_error || slot == read_error_slot) {
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "injected read error");
    }
    std::memcpy(target.data, slots_[slot].data(), target.size);
    return routeloom::Status::success();
  }

  routeloom::Status write(const std::uint8_t slot,
                          const routeloom::ByteView data) noexcept override {
    if (slot >= routeloom::kTrustStoreSlots || data.data == nullptr ||
        data.size > routeloom::kTrustStoreSlotBytes) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument,
                                    "bad trust write");
    }
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      std::memcpy(slots_[slot].data(), data.data, cut_bytes);
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "power cut mid write");
    }
    if (call == drop_call) {
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    // A blob shorter than the slot view reads an erased tail.
    std::memset(slots_[slot].data() + data.size, 0xFF,
                slots_[slot].size() - data.size);
    return routeloom::Status::success();
  }

  std::array<std::uint8_t, routeloom::kTrustStoreSlotBytes>& slot_bytes(
      const std::uint8_t slot) noexcept {
    return slots_[slot];
  }
  void corrupt(const std::uint8_t slot, const std::size_t offset) noexcept {
    slots_[slot][offset] ^= 0xFFU;
  }
  void fill(const std::uint8_t slot, const std::uint8_t value) noexcept {
    slots_[slot].fill(value);
  }

  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
  bool read_error{false};
  std::uint8_t read_error_slot{0xFF};

 private:
  std::array<std::array<std::uint8_t, routeloom::kTrustStoreSlotBytes>,
             routeloom::kTrustStoreSlots>
      slots_{};
};

class FaultyCredentialStorage final : public routeloom::CredentialStorage {
 public:
  FaultyCredentialStorage() noexcept {
    for (auto& slot : slots_) slot.fill(0xFF);
  }
  routeloom::Status read(const std::uint8_t slot,
                         const routeloom::MutableByteView target) noexcept override {
    if (slot >= routeloom::kCredentialSlots || target.data == nullptr ||
        target.size != routeloom::kCredentialSlotBytes) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument,
                                    "bad credential read");
    }
    if (read_error || slot == read_error_slot) {
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "injected read error");
    }
    std::memcpy(target.data, slots_[slot].data(), target.size);
    return routeloom::Status::success();
  }

  routeloom::Status write(const std::uint8_t slot,
                          const routeloom::ByteView data) noexcept override {
    if (slot >= routeloom::kCredentialSlots || data.data == nullptr ||
        data.size > routeloom::kCredentialSlotBytes) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument,
                                    "bad credential write");
    }
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      std::memcpy(slots_[slot].data(), data.data, cut_bytes);
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "power cut mid write");
    }
    if (call == drop_call) {
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    std::memset(slots_[slot].data() + data.size, 0xFF,
                slots_[slot].size() - data.size);
    return routeloom::Status::success();
  }

  std::array<std::uint8_t, routeloom::kCredentialSlotBytes>& slot_bytes(
      const std::uint8_t slot) noexcept {
    return slots_[slot];
  }
  void corrupt(const std::uint8_t slot, const std::size_t offset) noexcept {
    slots_[slot][offset] ^= 0xFFU;
  }
  void fill(const std::uint8_t slot, const std::uint8_t value) noexcept {
    slots_[slot].fill(value);
  }

  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
  bool read_error{false};
  std::uint8_t read_error_slot{0xFF};

 private:
  std::array<std::array<std::uint8_t, routeloom::kCredentialSlotBytes>,
             routeloom::kCredentialSlots>
      slots_{};
};

// --- RLC1 credential builders --------------------------------------------------

// Canonical (minimal-form) CBOR unsigned integer — the grant payload profile
// admits nothing else.
inline routeloom::Status cbor_put_uint(routeloom::ByteWriter& writer,
                                       const std::uint64_t value) {
  routeloom::Status status = routeloom::Status::success();
  if (value <= 0x17U) {
    status = writer.write_u8(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFU) {
    status = writer.write_u8(0x18);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFFFU) {
    status = writer.write_u8(0x19);
    if (status) status = writer.write_u16(static_cast<std::uint16_t>(value));
  } else if (value <= 0xFFFFFFFFULL) {
    status = writer.write_u8(0x1A);
    if (status) status = writer.write_u32(static_cast<std::uint32_t>(value));
  } else {
    status = writer.write_u8(0x1B);
    if (status) status = writer.write_u64(value);
  }
  return status;
}

inline routeloom::Status cbor_put_bstr(routeloom::ByteWriter& writer,
                                       const routeloom::ByteView data) {
  routeloom::Status status = routeloom::Status::success();
  if (data.size <= 23) {
    status = writer.write_u8(static_cast<std::uint8_t>(0x40 + data.size));
  } else if (data.size <= 255) {
    status = writer.write_u8(0x58);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(data.size));
  } else {
    status = writer.write_u8(0x59);
    if (status) status = writer.write_u16(static_cast<std::uint16_t>(data.size));
  }
  if (!status) return status;
  return writer.write_bytes(data);
}

// A field-consistent MembershipGrant in the restricted envelope the RLC1 boot
// check parses (the signature bytes are arbitrary — grant signature
// verification belongs to the membership workstream, not this codec).
// Payload: [1, network_low32, node_id, kid bstr32, role_bits, generation,
//           revision, not_before, not_after].
inline routeloom::Status test_grant(const routeloom::NetworkId network,
                                    const routeloom::NodeId node_id,
                                    const routeloom::Digest256& kid,
                                    routeloom::ByteBuffer<routeloom::kCredentialGrantMax>& out) {
  out.clear();
  routeloom::ByteBuffer<200> payload{};
  routeloom::ByteWriter payload_writer(payload.writable());
  routeloom::Status status = payload_writer.write_u8(0x89);  // array(9)
  if (status) status = cbor_put_uint(payload_writer, 1);     // version
  if (status) {
    status =
        cbor_put_uint(payload_writer, network & 0xFFFFFFFFULL);  // low32
  }
  if (status) status = cbor_put_uint(payload_writer, node_id);
  if (status) status = cbor_put_bstr(payload_writer, routeloom::ByteView{kid.data(), kid.size()});
  if (status) status = cbor_put_uint(payload_writer, 3);       // role_bits
  if (status) status = cbor_put_uint(payload_writer, 7);       // generation
  if (status) status = cbor_put_uint(payload_writer, 11);      // revision
  if (status) status = cbor_put_uint(payload_writer, 1000);    // not_before
  if (status) status = cbor_put_uint(payload_writer, 2000);    // not_after
  if (!status) return status;
  payload.size = payload_writer.size();

  routeloom::ByteWriter writer(out.writable());
  const std::array<std::uint8_t, 1> protected_bytes{{0xA0}};  // nonempty per profile
  const std::array<std::uint8_t, 64> signature{};
  status = writer.write_u8(0xD2);  // tag 18
  if (status) status = writer.write_u8(0x84);  // array(4)
  if (status) status = cbor_put_bstr(writer, routeloom::ByteView{protected_bytes.data(), protected_bytes.size()});
  if (status) status = writer.write_u8(0xA0);  // empty unprotected map
  if (status) status = cbor_put_bstr(writer, payload.view());
  if (status) status = cbor_put_bstr(writer, routeloom::ByteView{signature.data(), signature.size()});
  if (!status) return status;
  out.size = writer.size();
  return routeloom::Status::success();
}

// Valid credential fixture: real keypair (key_location NvsPlaintext carries
// the private scalar), kid computed by the codec itself.
inline routeloom::DeviceCredential test_credential(
    const routeloom::NetworkId network, const routeloom::NodeId node,
    const TestKeyPair& keys, const bool with_grant = true) {
  routeloom::DeviceCredential credential{};
  credential.network = network;
  credential.node_id = node;
  credential.generation_base_session = 500;
  credential.key_location = routeloom::CredentialKeyLocation::NvsPlaintext;
  credential.cred_status = routeloom::CredentialStatus::Active;
  credential.pubkey = keys.pub;
  credential.key_material = keys.priv;
  routeloom::credential_kid(
      routeloom::ByteView{keys.pub.data(), keys.pub.size()}, credential.kid);
  if (with_grant) {
    routeloom::ByteBuffer<routeloom::kCredentialGrantMax> grant{};
    const routeloom::Status made =
        test_grant(network, node, credential.kid, grant);
    (void)made;
    credential.grant = grant;
  }
  return credential;
}

}  // namespace routeloom_test
