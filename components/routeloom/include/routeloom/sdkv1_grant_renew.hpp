#pragma once

// Authority type 7: fixed, bounded cutover messages. Decode never treats
// transport authentication as a substitute for the SAK-signed commit/RRS1.
#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_records.hpp"

namespace routeloom::sdkv1 {

constexpr std::size_t kGrantRenewHeadSize = 24;
constexpr std::size_t kGrantPrepareMax = 700;
constexpr std::size_t kGrantCommitMax = 799;
constexpr std::size_t kGrantReceiptSize = 76;
constexpr std::size_t kCutoverPayloadSize = 80;
constexpr std::size_t kCutoverObjectSize = 155;
constexpr std::size_t kCutoverAadSize = sizeof("RouteLoom/site-cutover/v1") + 8;

enum class GrantRenewPhase : std::uint8_t { Prepare = 1, Commit = 2, Prepared = 3, Applied = 4 };
struct GrantRenewHead {
  GrantRenewPhase phase{GrantRenewPhase::Prepare};
  std::uint64_t cutover_id{0};
  std::uint32_t revision{0};
  NetworkId old_network{0};
};
struct GrantPrepare {
  GrantRenewHead head{};
  NetworkId new_network{0};
  ByteBuffer<kRlcw1CertMax> site_cert{};
  ByteBuffer<kRlcw1CertMax> member_cert{};
  SitePackage package{};
  std::array<std::uint8_t, 32> dams{};
};
struct GrantCommit {
  GrantRenewHead head{};
  ByteBuffer<kCutoverObjectSize> proof{};
  ByteBuffer<kRevocationObjectMax> revocations{};
};
struct GrantReceipt {
  GrantRenewHead head{};
  NetworkId new_network{0};
  std::uint32_t gk_epoch{0};
  std::uint32_t rs_epoch{0};
  Digest256 digest{};
  std::uint8_t status{0};
};
struct CutoverCommit {
  std::uint64_t site_id{0};
  NetworkId old_network{0};
  NetworkId new_network{0};
  std::uint64_t cutover_id{0};
  std::uint32_t revision{0};
  std::uint32_t gk_epoch{0};
  std::uint32_t rs_epoch{0};
  Digest256 rrs_sha256{};
};

Status grant_renew_head_encode(const GrantRenewHead& head,
                               std::array<std::uint8_t, kGrantRenewHeadSize>& out) noexcept;
Status grant_renew_head_decode(ByteView bytes, GrantRenewHead& out) noexcept;
Status grant_prepare_decode(ByteView bytes, GrantPrepare& out) noexcept;
Status grant_commit_decode(ByteView bytes, GrantCommit& out) noexcept;
Status grant_receipt_encode(const GrantReceipt& receipt,
                            std::array<std::uint8_t, kGrantReceiptSize>& out) noexcept;
Status grant_receipt_decode(ByteView bytes, GrantReceipt& out) noexcept;
Status cutover_commit_aad(NetworkId old_network,
                          std::array<std::uint8_t, kCutoverAadSize>& out) noexcept;
Status cutover_commit_verify(ByteView object, const P256PublicKey& sak,
                             NetworkId expected_old, CutoverCommit& out, bool& verified,
                             const Es256Verifier& verifier = default_es256_verifier()) noexcept;

}  // namespace routeloom::sdkv1
