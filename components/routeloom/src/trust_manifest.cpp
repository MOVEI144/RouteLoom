#include "routeloom/trust_manifest.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom {
namespace {

// --- Minimal canonical-CBOR helpers ------------------------------------------
// The same restricted-CBOR rules as config_cose.cpp's file-local helpers
// (definite/minimal lengths only); duplicated rather than shared because
// that TU owns its copies and a shared cbor unit is a broader refactor —
// documented, small, and identical in behavior.

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

Status cbor_write_bstr(ByteWriter& writer, const ByteView data) noexcept {
  Status status;
  if (data.size <= 23) {
    status = writer.write_u8(static_cast<std::uint8_t>(0x40 + data.size));
  } else if (data.size <= 255) {
    status = writer.write_u8(0x58);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(data.size));
  } else {
    status = writer.write_u8(0x59);
    if (status) {
      status = writer.write_u16(static_cast<std::uint16_t>(data.size));
    }
  }
  if (!status) return status;
  return writer.write_bytes(data);
}

// The protected header is byte-exact by profile: a2 {1:-9, 4:h'kid8'} —
// the same 13-byte shape as the permit envelope, but the kid names a root
// anchor, not a config authority.
constexpr std::array<std::uint8_t, 5> kProtectedHead{{0xa2, 0x01, 0x28, 0x04, 0x48}};

}  // namespace

Status trust_manifest_aad(const NetworkId network,
                          ByteBuffer<kTrustManifestAadSize>& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status = writer.write_bytes(ByteView{
      reinterpret_cast<const std::uint8_t*>(kTrustManifestDomain),
      sizeof(kTrustManifestDomain)});  // includes the NUL terminator
  if (status) status = writer.write_u64(network);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status trust_manifest_protected(
    const std::uint64_t root_id,
    ByteBuffer<kTrustManifestProtectedSize>& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status =
      writer.write_bytes(ByteView{kProtectedHead.data(), kProtectedHead.size()});
  if (status) status = writer.write_u64(root_id);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status trust_manifest_parse(const ByteView object, TrustManifestParts& out) noexcept {
  out = TrustManifestParts{};
  // 84 bytes of fixed envelope overhead + the smallest legal payload.
  if (object.size < 86 || object.size > kTrustManifestObjectMax) {
    return Status::error(StatusCode::ProtocolError, "manifest object size");
  }
  std::size_t pos = 0;
  Status status = cbor_expect_u8(object, pos, 0xD2, "manifest tag18");
  if (status) status = cbor_expect_u8(object, pos, 0x84, "manifest array4");
  ByteView protected_bstr{};
  if (status) {
    status = cbor_read_bstr(object, pos, protected_bstr, "manifest protected");
  }
  if (!status) return status;
  // Byte-exact protected header: map2 {alg:-9, kid:bstr8} canonical order.
  if (protected_bstr.size != kTrustManifestProtectedSize ||
      std::memcmp(protected_bstr.data, kProtectedHead.data(),
                  kProtectedHead.size()) != 0) {
    return Status::error(StatusCode::ProtocolError, "manifest protected shape");
  }
  std::uint64_t root_id = 0;
  for (int i = 0; i < 8; ++i) {
    root_id = (root_id << 8U) | protected_bstr.data[5 + i];
  }
  status = cbor_expect_u8(object, pos, 0xA0, "manifest unprotected empty");
  if (!status) return status;
  ByteView payload{};
  status = cbor_read_bstr(object, pos, payload, "manifest payload");
  if (!status) return status;
  if (payload.size == 0 || payload.size > kTrustImageContentMax) {
    return Status::error(StatusCode::ProtocolError, "manifest payload bounds");
  }
  ByteView signature{};
  status = cbor_read_bstr(object, pos, signature, "manifest signature");
  if (!status) return status;
  if (signature.size != kCoseSignatureSize || pos != object.size) {
    return Status::error(StatusCode::ProtocolError, "manifest signature/trailer");
  }
  out.protected_bytes = protected_bstr;
  out.root_id = root_id;
  out.payload = payload;
  out.signature = signature;
  return Status::success();
}

Status trust_manifest_sig_structure(
    const ByteView protected_bytes, const ByteView external_aad,
    const ByteView payload, ByteBuffer<kTrustManifestSigMax>& out) noexcept {
  out.clear();
  if (protected_bytes.size != kTrustManifestProtectedSize ||
      external_aad.size != kTrustManifestAadSize ||
      payload.size == 0 || payload.size > kTrustImageContentMax) {
    return Status::error(StatusCode::InvalidArgument, "manifest sig_structure fields");
  }
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(0x84);  // array(4)
  if (status) {
    status = writer.write_u8(0x60 + 10);  // "Signature1" text(10)
  }
  if (status) {
    status = writer.write_bytes(ByteView{
        reinterpret_cast<const std::uint8_t*>("Signature1"), 10});
  }
  if (status) status = cbor_write_bstr(writer, protected_bytes);
  if (status) status = cbor_write_bstr(writer, external_aad);
  if (status) status = cbor_write_bstr(writer, payload);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status trust_manifest_assemble(
    const ByteView content, const std::uint64_t root_id,
    const ByteView signature, ByteBuffer<kTrustManifestObjectMax>& out) noexcept {
  out.clear();
  if (content.size == 0 || content.size > kTrustImageContentMax ||
      signature.size != kCoseSignatureSize || signature.data == nullptr ||
      content.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "manifest assemble fields");
  }
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(0xD2);  // tag 18
  if (status) status = writer.write_u8(0x84);  // array(4)
  ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
  if (status) status = trust_manifest_protected(root_id, protected_bytes);
  if (status) status = cbor_write_bstr(writer, protected_bytes.view());
  if (status) status = writer.write_u8(0xA0);  // empty unprotected map
  if (status) status = cbor_write_bstr(writer, content);
  if (status) status = cbor_write_bstr(writer, signature);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status trust_manifest_accept(TrustStore& store, const ByteView object) noexcept {
  // Store-state gates first — a manifest is never the first install (there
  // is no anchor to verify against; §4.4 first install is physical).
  if (!store.initialized()) {
    return Status::error(StatusCode::InvalidState, "trust store not initialized");
  }
  if (store.quarantined()) {
    return Status::error(StatusCode::IntegrityError, "trust store quarantined");
  }
  if (store.uncertain()) {
    return Status::error(StatusCode::RecoveryRequired,
                        "trust store storage uncertain");
  }
  if (!store.has_active()) {
    return Status::error(StatusCode::AuthorizationFailed,
                        "no trust anchor base installed");
  }

  // 1. Envelope shape (cheap parse; §4.5.1 rule 1).
  TrustManifestParts parts{};
  Status status = trust_manifest_parse(object, parts);
  if (!status) return status;

  // 2. Content head: structural decode, then the cheap semantic gates the
  //    design lists before any signature work (network equality, nonzero
  //    epoch, counts/tables — enforced inside the codec).
  TrustImage candidate{};
  status = trust_image_body_decode(parts.payload, candidate);
  if (!status) return status;
  if (candidate.network != store.network()) {
    return Status::error(StatusCode::AuthorizationFailed, "manifest foreign network");
  }
  if (candidate.store_epoch == 0) {
    return Status::error(StatusCode::ProtocolError, "manifest epoch zero");
  }

  // 3. Ordinal epoch compare — a manifest at or below the committed epoch
  //    is a harmless stale replay, denied without spending the verify.
  if (candidate.store_epoch <= store.store_epoch()) {
    return Status::error(StatusCode::Conflict, "manifest epoch not newer");
  }

  // 4. kid names an anchor ACTIVE in the CURRENT image (a manifest signed
  //    under a disabled anchor fails even with a valid signature).
  const TrustAnchor* anchor = store.find_anchor(parts.root_id);
  if (anchor == nullptr || anchor->status != TrustAnchorStatus::Active) {
    return Status::error(StatusCode::AuthorizationFailed, "manifest anchor unusable");
  }

  // R/S range + low-S canonicality before the expensive point multiply —
  // the same rules the permit verifier applies.
  std::array<std::uint8_t, 32> r{}, s{};
  std::memcpy(r.data(), parts.signature.data, 32);
  std::memcpy(s.data(), parts.signature.data + 32, 32);
  if (cose_be32_is_zero(r) || cose_be32_is_zero(s) ||
      cose_be32_cmp(r, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1HalfOrder) > 0) {
    return Status::error(StatusCode::AuthorizationFailed, "manifest signature range");
  }

  // The AAD binds the device's own committed network — never a transport
  // claim (§4.3.3).
  ByteBuffer<kTrustManifestAadSize> aad{};
  status = trust_manifest_aad(store.network(), aad);
  if (!status) return status;
  ByteBuffer<kTrustManifestSigMax> to_verify{};
  status = trust_manifest_sig_structure(parts.protected_bytes, aad.view(),
                                        parts.payload, to_verify);
  if (!status) return status;
  ScopeDigest digest{};
  sha256(to_verify.view(), digest);
  if (uECC_verify(anchor->pubkey.data(), digest.data(),
                  static_cast<unsigned>(digest.size()), parts.signature.data,
                  uECC_secp256r1()) == 0) {
    return Status::error(StatusCode::AuthorizationFailed, "manifest signature invalid");
  }

  // 5-6. Semantic floor + retention invariants + the two-phase dual-slot
  //      commit with readback live in commit_image: it re-checks
  //      store_epoch against the proven epoch floor (not just the active
  //      epoch), refuses a min_authority_generation regression, and
  //      requires the new image to keep >=1 active anchor. A storage fault
  //      leaves the old image authoritative.
  return store.commit_image(candidate);
}

}  // namespace routeloom
