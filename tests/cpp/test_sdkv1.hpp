#pragma once

// Shared fixtures for the SDK v1 record/certificate tests: fault-injecting
// dual-slot and resume-slot storage (byte-granular power cuts, dropped
// writes, read errors, silent write corruption — the FaultyTrustStorage
// discipline) and builders for real, signed RLCW1 certificates, RLI1/RLS1
// records and RRS1 objects. Keys are test_keypair(seed) fixtures; the C++
// signer is micro-ecc's deterministic mode normalized to low-S (valid
// signatures, not RFC 6979 byte-identical — the golden vectors pin those).

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"

#include "test_provisioning.hpp"

namespace sdkv1_test {

using namespace routeloom;
using namespace routeloom::sdkv1;

// --- Storage ---------------------------------------------------------------------

class FaultyRecordStorage final : public RecordSlotStorage {
 public:
  explicit FaultyRecordStorage(const std::size_t slot_bytes) : slot_bytes_(slot_bytes) {
    for (auto& slot : slots_) slot.assign(slot_bytes_, 0xFF);
  }
  Status read(const std::uint8_t slot, const MutableByteView target) noexcept override {
    if (slot >= 2 || target.data == nullptr || target.size != slot_bytes_) {
      return Status::error(StatusCode::InvalidArgument, "bad read");
    }
    ++read_calls;
    if (read_error || slot == read_error_slot || read_calls == fail_read_call) {
      return Status::error(StatusCode::StorageFailure, "injected read error");
    }
    std::memcpy(target.data, slots_[slot].data(), slot_bytes_);
    return Status::success();
  }
  Status write(const std::uint8_t slot, const ByteView data) noexcept override {
    if (slot >= 2 || data.data == nullptr || data.size > slot_bytes_) {
      return Status::error(StatusCode::InvalidArgument, "bad write");
    }
    if (fail_writes) return Status::error(StatusCode::StorageFailure, "injected write failure");
    const std::size_t call = write_calls++;
    if (call == substitute_call) {
      if (substitute_record.size() > slot_bytes_) {
        return Status::error(StatusCode::InvalidArgument, "substitute too long");
      }
      std::memcpy(slots_[slot].data(), substitute_record.data(), substitute_record.size());
      std::memset(slots_[slot].data() + substitute_record.size(), 0xFF,
                  slot_bytes_ - substitute_record.size());
      return Status::error(StatusCode::StorageFailure, "power lost after different commit");
    }
    if (call == cut_call) {
      std::memcpy(slots_[slot].data(), data.data, cut_bytes);
      return Status::error(StatusCode::StorageFailure, "power cut mid write");
    }
    if (call == drop_call) return Status::error(StatusCode::StorageFailure, "power lost");
    std::memcpy(slots_[slot].data(), data.data, data.size);
    std::memset(slots_[slot].data() + data.size, 0xFF, slot_bytes_ - data.size);
    if (call == flip_call) slots_[slot][data.size / 2] ^= 0x01;  // silent corruption
    return Status::success();
  }
  std::vector<std::uint8_t>& slot(const std::uint8_t index) { return slots_[index]; }
  void disarm() {
    cut_call = drop_call = flip_call = substitute_call = std::numeric_limits<std::size_t>::max();
    substitute_record.clear();
    read_error = false;
    read_error_slot = 0xFF;
    fail_writes = false;
  }

  std::size_t write_calls{0};
  std::size_t read_calls{0};
  std::size_t fail_read_call{0};  // 1-based call, once
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
  std::size_t flip_call{std::numeric_limits<std::size_t>::max()};
  std::size_t substitute_call{std::numeric_limits<std::size_t>::max()};
  std::vector<std::uint8_t> substitute_record{};
  bool read_error{false};
  std::uint8_t read_error_slot{0xFF};
  bool fail_writes{false};

 private:
  std::size_t slot_bytes_;
  std::array<std::vector<std::uint8_t>, 2> slots_{};
};

class FaultyResumeStorage2 final : public ResumeSlotStorage2 {
 public:
  explicit FaultyResumeStorage2(const std::size_t count) : slots_(count) {
    for (auto& slot : slots_) slot.fill(0xFF);
  }
  std::size_t slot_count() const noexcept override { return slots_.size(); }
  Status read(const std::size_t index, const MutableByteView target) noexcept override {
    if (index >= slots_.size() || target.size != kResume2SlotBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad resume2 read");
    }
    if (read_error) return Status::error(StatusCode::StorageFailure, "injected read error");
    std::memcpy(target.data, slots_[index].data(), kResume2SlotBytes);
    return Status::success();
  }
  Status write(const std::size_t index, const ByteView data) noexcept override {
    if (index >= slots_.size() || data.size != kResume2SlotBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad resume2 write");
    }
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      std::memcpy(slots_[index].data(), data.data, cut_bytes);
      return Status::error(StatusCode::StorageFailure, "power cut mid write");
    }
    std::memcpy(slots_[index].data(), data.data, kResume2SlotBytes);
    return Status::success();
  }
  std::array<std::uint8_t, kResume2SlotBytes>& slot(const std::size_t index) {
    return slots_[index];
  }
  void disarm() {
    cut_call = std::numeric_limits<std::size_t>::max();
    read_error = false;
  }

  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  bool read_error{false};

 private:
  std::vector<std::array<std::uint8_t, kResume2SlotBytes>> slots_{};
};

class FaultyResumeStorage final : public ResumeSlotStorage {
 public:
  explicit FaultyResumeStorage(const std::size_t count) : slots_(count) {
    for (auto& slot : slots_) slot.fill(0xFF);
  }
  std::size_t slot_count() const noexcept override { return slots_.size(); }
  Status read(const std::size_t index, const MutableByteView target) noexcept override {
    if (index >= slots_.size() || target.size != kResumeSlotBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad resume read");
    }
    std::memcpy(target.data, slots_[index].data(), kResumeSlotBytes);
    return Status::success();
  }
  Status write(const std::size_t index, const ByteView data) noexcept override {
    if (index >= slots_.size() || data.size != kResumeSlotBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad resume write");
    }
    if (fail_writes) return Status::error(StatusCode::StorageFailure, "injected write failure");
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      std::memcpy(slots_[index].data(), data.data, cut_bytes);
      return Status::error(StatusCode::StorageFailure, "power cut mid write");
    }
    std::memcpy(slots_[index].data(), data.data, kResumeSlotBytes);
    return Status::success();
  }
  std::array<std::uint8_t, kResumeSlotBytes>& slot(const std::size_t index) {
    return slots_[index];
  }
  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  bool fail_writes{false};

 private:
  std::vector<std::array<std::uint8_t, kResumeSlotBytes>> slots_;
};

// --- Keys / ids ----------------------------------------------------------------------

inline const routeloom_test::TestKeyPair& device_ca() {
  static const auto key = routeloom_test::test_keypair(0x51);
  return key;
}
inline const routeloom_test::TestKeyPair& site_ca() {
  static const auto key = routeloom_test::test_keypair(0x52);
  return key;
}
inline const routeloom_test::TestKeyPair& sak() {
  static const auto key = routeloom_test::test_keypair(0x53);
  return key;
}
inline const routeloom_test::TestKeyPair& device_key() {
  static const auto key = routeloom_test::test_keypair(0x54);
  return key;
}
inline const routeloom_test::TestKeyPair& verifier_key() {
  static const auto key = routeloom_test::test_keypair(0x55);
  return key;
}
inline const routeloom_test::TestKeyPair& other_key() {
  static const auto key = routeloom_test::test_keypair(0x56);
  return key;
}

constexpr std::uint64_t kDeviceCaId = 0x0DCA000000000001ULL;
constexpr std::uint64_t kSiteCaId = 0x05CA000000000001ULL;
constexpr std::uint64_t kVerifierId = 0x0A55000000000001ULL;
constexpr std::uint64_t kSiteId = 0x5173000000000042ULL;
constexpr NodeId kNode = 0x00A1000000001234ULL;
constexpr NodeId kPeer = 0x00A1000000000777ULL;
constexpr std::uint32_t kSiteEpoch = 3;
constexpr std::uint32_t kNetworkLow = 0x0A1B2C3DU;
constexpr NetworkId kNetwork = (static_cast<NetworkId>(kSiteEpoch) << 32U) | kNetworkLow;

// --- Builders ------------------------------------------------------------------------

inline void sign_payload(const routeloom_test::TestKeyPair& key, const ByteView payload,
                         const ByteView aad, Es256Signature& signature) {
  Digest256 digest{};
  cose_es256_digest(payload, aad, digest);
  routeloom_test::sign_digest_low_s(key.priv, digest, signature);
}

inline ByteBuffer<kRlcw1CertMax> issue(const CertClaims& claims,
                                       const routeloom_test::TestKeyPair& key) {
  ByteBuffer<kRlcw1PayloadMax> payload{};
  ByteBuffer<kRlcw1CertMax> cert{};
  if (!cert_payload_encode(claims, payload).ok()) return cert;
  Es256Signature signature{};
  sign_payload(key, payload.view(), ByteView{}, signature);
  (void)cert_assemble(payload.view(), ByteView{signature.data(), signature.size()}, cert);
  return cert;
}

inline CertClaims devcert_claims(const NodeId node = kNode) {
  CertClaims c{};
  c.type = CertType::Device;
  c.issuer = kDeviceCaId;
  c.subject = node;
  c.pubkey = device_key().pub;
  c.model = 17;
  c.hw_rev = 2;
  c.serial = 90211;
  return c;
}

inline CertClaims sitecert_claims(const NetworkId network = kNetwork) {
  CertClaims c{};
  c.type = CertType::Site;
  c.issuer = kSiteCaId;
  c.subject = kSiteId;
  c.pubkey = sak().pub;
  c.network_low32 = static_cast<std::uint32_t>(network & 0xFFFFFFFFULL);
  c.site_epoch = static_cast<std::uint32_t>(network >> 32U);
  c.usage = kSiteUsageAuthority;
  c.serial = 7;
  return c;
}

inline CertClaims membercert_claims(const std::uint32_t generation = 3,
                                    const NetworkId network = kNetwork,
                                    const NodeId node = kNode,
                                    const P256PublicKey& pubkey = device_key().pub) {
  CertClaims c{};
  c.type = CertType::Member;
  c.issuer = kSiteId;
  c.subject = node;
  c.pubkey = pubkey;
  c.network = network;
  c.role = kMemberRoleEndpoint;
  c.assignment_generation = generation;
  c.site_epoch = static_cast<std::uint32_t>(network >> 32U);
  c.serial = 4412;
  return c;
}

inline IdentityRecord identity_record(const bool strict = false) {
  IdentityRecord r{};
  r.node_id = kNode;
  r.key_location = CredentialKeyLocation::NvsPlaintext;
  r.flags = strict ? (kIdentityFlagConsoleLocked | kIdentityFlagStrictAssignment) : 0;
  (void)credential_kid(ByteView{device_key().pub.data(), device_key().pub.size()}, r.kid);
  r.pubkey = device_key().pub;
  r.key_material = device_key().priv;
  r.anchors[0] = IdentityAnchor{kSiteCaId, AnchorKind::SiteCa, AnchorStatus::Active, site_ca().pub};
  r.anchor_count = 1;
  if (strict) {
    r.anchors[1] = IdentityAnchor{kVerifierId, AnchorKind::AssignmentVerifier,
                                  AnchorStatus::Active, verifier_key().pub};
    r.anchor_count = 2;
  }
  r.devcert = issue(devcert_claims(), device_ca());
  return r;
}

inline SiteRecord site_record(const std::uint32_t generation = 3,
                              const std::uint32_t gk_epoch = 203,
                              const NetworkId network = kNetwork) {
  SiteRecord r{};
  r.state = SiteState::Member;
  r.site_id = kSiteId;
  r.network = network;
  r.assignment_generation = generation;
  r.rs_epoch_floor = 14;
  r.gk_epoch_current = gk_epoch;
  for (std::size_t i = 0; i < 32; ++i) {
    r.gk_current[i] = static_cast<std::uint8_t>(0x20 + i + gk_epoch);
    r.dams[i] = static_cast<std::uint8_t>(0x60 + i);
  }
  r.role = static_cast<std::uint8_t>(kMemberRoleEndpoint);
  r.gateway_count = 2;
  r.channel = 6;
  r.channel_epoch = 9;
  r.boot_witness = 1234;
  r.gateways[0] = 0x00A1000000000001ULL;
  r.gateways[1] = 0x00A1000000000002ULL;
  r.site_cert = issue(sitecert_claims(network), site_ca());
  r.member_cert = issue(membercert_claims(generation, network), sak());
  return r;
}

inline RevocationSet revocation_set(const std::uint32_t rs_epoch, const std::uint8_t count = 2,
                                    const std::uint32_t floor = 2,
                                    const NetworkId network = kNetwork) {
  RevocationSet set{};
  set.site_id = kSiteId;
  set.network = network;
  set.rs_epoch = rs_epoch;
  set.site_epoch_floor = floor;
  for (std::uint8_t i = 0; i < count; ++i) {
    set.entries[i] = RevocationEntry{0x00A1000000000100ULL + i * 7U, 2U + i,
                                     RevocationReason::Removed};
  }
  set.count = count;
  return set;
}

inline ByteBuffer<kRevocationObjectMax> revocation_object(
    const RevocationSet& set, const routeloom_test::TestKeyPair& key = sak(),
    const NetworkId aad_network = 0) {
  ByteBuffer<kRevocationPayloadMax> payload{};
  ByteBuffer<kRevocationObjectMax> object{};
  if (!revocation_payload_encode(set, payload).ok()) return object;
  ByteBuffer<kRevocationAadSize> aad{};
  (void)revocation_aad(aad_network != 0 ? aad_network : set.network, aad);
  Es256Signature signature{};
  sign_payload(key, payload.view(), aad.view(), signature);
  (void)revocation_object_assemble(payload.view(), ByteView{signature.data(), signature.size()},
                                   object);
  return object;
}

inline ResumeSlot resume_slot(const NodeId peer, const std::uint8_t flags = 0,
                              const std::uint32_t last_used_boot = 0,
                              const std::uint32_t gk_epoch = 203,
                              const ResumePurpose purpose = ResumePurpose::Link) {
  ResumeSlot slot{};
  slot.valid = true;
  slot.purpose = purpose;
  slot.flags = flags;
  slot.peer = peer;
  slot.network = kNetwork;
  slot.peer_cert_id = {1, 2, 3, 4, 5, 6, 7, 8};
  slot.peer_generation = 1;
  slot.created_gk_epoch = gk_epoch;
  slot.last_used_boot = last_used_boot;
  for (std::size_t i = 0; i < slot.rms.size(); ++i) {
    slot.rms[i] = static_cast<std::uint8_t>(peer + i + 1);
  }
  return slot;
}

}  // namespace sdkv1_test
