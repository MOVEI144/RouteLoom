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
constexpr std::size_t kGrantReceiptSize = 76;
constexpr std::size_t kGrantRouteStateSize = 60;
constexpr std::size_t kCutoverPayloadSize = 80;
constexpr std::size_t kCutoverObjectSize = 155;
constexpr std::size_t kGrantCommitMax = 28 + kCutoverObjectSize + kRevocationObjectMax;
constexpr std::size_t kCutoverAadSize = sizeof("RouteLoom/site-cutover/v1") + 8;

enum class GrantRenewPhase : std::uint8_t {
  Prepare = 1,
  Commit = 2,
  Prepared = 3,
  Applied = 4,
  CommitStored = 5,
  RouteState = 6
};
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
// RouteState (phase 6, 60 B): the Host's view of one target's uplink
// path for leaf-first COMMIT dispatch (04 §7). A query (mode 0) names
// only the cutover binding and a query id; a report (mode 1) names
// the mesh root, the committed next hop toward it, the boot
// incarnation, a local route stamp (change detector), the echoed
// query id and the remaining route lease. A report with
// status 1 (unavailable) carries no parent and no lease.
struct GrantRouteState {
  GrantRenewHead head{};
  std::uint8_t mode{0};  // 0 = query, 1 = report
  std::uint8_t status{0};  // report only: 0 = ok, 1 = unavailable
  std::uint64_t root{0};
  std::uint64_t parent{0};  // committed next hop (0 = self is the root)
  std::uint32_t boot{0};
  std::uint32_t route_stamp{0};
  std::uint32_t query_id{0};
  std::uint32_t valid_for_ms{0};
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
Status grant_route_state_encode(const GrantRouteState& state,
                                std::array<std::uint8_t, kGrantRouteStateSize>& out) noexcept;
Status grant_route_state_decode(ByteView bytes, GrantRouteState& out) noexcept;
Status cutover_commit_aad(NetworkId old_network,
                          std::array<std::uint8_t, kCutoverAadSize>& out) noexcept;
Status cutover_commit_verify(ByteView object, const P256PublicKey& sak,
                             NetworkId expected_old, CutoverCommit& out, bool& verified,
                             const Es256Verifier& verifier = default_es256_verifier()) noexcept;

}  // namespace routeloom::sdkv1
