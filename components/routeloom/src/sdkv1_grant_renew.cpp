#include "routeloom/sdkv1_grant_renew.hpp"

#include <cstring>

namespace routeloom::sdkv1 {
namespace {
std::uint16_t u16(const std::uint8_t* p) noexcept { return static_cast<std::uint16_t>((p[0] << 8U) | p[1]); }
std::uint32_t u32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}
std::uint64_t u64(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint64_t>(u32(p)) << 32U) | u32(p + 4);
}
void put32(std::uint8_t* p, std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 24U); p[1] = static_cast<std::uint8_t>(v >> 16U);
  p[2] = static_cast<std::uint8_t>(v >> 8U); p[3] = static_cast<std::uint8_t>(v);
}
void put64(std::uint8_t* p, std::uint64_t v) noexcept {
  put32(p, static_cast<std::uint32_t>(v >> 32U)); put32(p + 4, static_cast<std::uint32_t>(v));
}
bool nonzero(const std::array<std::uint8_t, 32>& value) noexcept {
  for (const auto byte : value) if (byte != 0) return true;
  return false;
}
Status bad(const char* reason) noexcept { return Status::error(StatusCode::ProtocolError, reason); }
}  // namespace

Status grant_renew_head_encode(const GrantRenewHead& head,
                               std::array<std::uint8_t, kGrantRenewHeadSize>& out) noexcept {
  if (head.phase < GrantRenewPhase::Prepare || head.phase > GrantRenewPhase::Applied ||
      head.cutover_id == 0 || head.revision == 0 || head.old_network == 0) return bad("renew head");
  out.fill(0);
  out[0] = 1; out[1] = static_cast<std::uint8_t>(head.phase);
  put64(out.data() + 4, head.cutover_id);
  put32(out.data() + 12, head.revision);
  put64(out.data() + 16, head.old_network);
  return Status::success();
}
Status grant_renew_head_decode(ByteView bytes, GrantRenewHead& out) noexcept {
  if (bytes.data == nullptr || bytes.size < kGrantRenewHeadSize || bytes.data[0] != 1 ||
      bytes.data[1] < 1 || bytes.data[1] > 4 || u16(bytes.data + 2) != 0 ||
      u64(bytes.data + 4) == 0 || u32(bytes.data + 12) == 0 || u64(bytes.data + 16) == 0)
    return bad("renew head");
  out.phase = static_cast<GrantRenewPhase>(bytes.data[1]);
  out.cutover_id = u64(bytes.data + 4);
  out.revision = u32(bytes.data + 12);
  out.old_network = u64(bytes.data + 16);
  return Status::success();
}
Status grant_prepare_decode(ByteView bytes, GrantPrepare& out) noexcept {
  out = GrantPrepare{};
  GrantRenewHead head{};
  Status st = grant_renew_head_decode(bytes, head);
  if (!st) return st;
  if (head.phase != GrantRenewPhase::Prepare || bytes.size < 24 + 12 + kSitePackageSize + 32 ||
      bytes.size > kGrantPrepareMax) return bad("renew prepare length");
  const auto* p = bytes.data + 24;
  const auto network = u64(p);
  const std::size_t site_len = u16(p + 8), member_len = u16(p + 10);
  if (site_len == 0 || member_len == 0 || site_len > kRlcw1CertMax ||
      member_len > kRlcw1CertMax ||
      bytes.size != 24 + 12 + site_len + member_len + kSitePackageSize + 32 ||
      network == 0 || network == head.old_network ||
      static_cast<std::uint32_t>(network) != static_cast<std::uint32_t>(head.old_network) ||
      static_cast<std::uint32_t>(head.old_network >> 32U) == 0xFFFFFFFFU ||
      static_cast<std::uint32_t>(network >> 32U) !=
          static_cast<std::uint32_t>(head.old_network >> 32U) + 1U) return bad("renew prepare binding");
  p += 12;
  out.site_cert.size = site_len;
  std::memcpy(out.site_cert.bytes.data(), p, site_len); p += site_len;
  out.member_cert.size = member_len;
  std::memcpy(out.member_cert.bytes.data(), p, member_len); p += member_len;
  st = site_package_decode(ByteView{p, kSitePackageSize}, out.package);
  if (!st) return st;
  p += kSitePackageSize;
  std::memcpy(out.dams.data(), p, out.dams.size());
  if (!nonzero(out.dams) || out.package.network != network || out.package.rs_epoch != 0)
    return bad("renew prepare package");
  out.head = head;
  out.new_network = network;
  return Status::success();
}
Status grant_commit_decode(ByteView bytes, GrantCommit& out) noexcept {
  out = GrantCommit{};
  GrantRenewHead head{};
  Status st = grant_renew_head_decode(bytes, head);
  if (!st) return st;
  if (head.phase != GrantRenewPhase::Commit || bytes.size < 28 || bytes.size > kGrantCommitMax)
    return bad("renew commit length");
  const std::size_t commit_len = u16(bytes.data + 24), rrs_len = u16(bytes.data + 26);
  if (commit_len != kCutoverObjectSize || rrs_len == 0 || rrs_len > kRevocationObjectMax ||
      bytes.size != 28 + commit_len + rrs_len) return bad("renew commit lengths");
  out.head = head;
  out.proof.size = commit_len;
  out.revocations.size = rrs_len;
  std::memcpy(out.proof.bytes.data(), bytes.data + 28, commit_len);
  std::memcpy(out.revocations.bytes.data(), bytes.data + 28 + commit_len, rrs_len);
  return Status::success();
}
Status grant_receipt_encode(const GrantReceipt& receipt,
                            std::array<std::uint8_t, kGrantReceiptSize>& out) noexcept {
  if (receipt.head.phase != GrantRenewPhase::Prepared && receipt.head.phase != GrantRenewPhase::Applied)
    return bad("renew receipt phase");
  std::array<std::uint8_t, kGrantRenewHeadSize> head{};
  Status st = grant_renew_head_encode(receipt.head, head);
  if (!st) return st;
  std::memcpy(out.data(), head.data(), head.size());
  if (receipt.new_network == 0 || receipt.status > 4 ||
      (receipt.head.phase == GrantRenewPhase::Prepared && receipt.rs_epoch != 0)) return bad("renew receipt");
  put64(out.data() + 24, receipt.new_network);
  put32(out.data() + 32, receipt.gk_epoch);
  put32(out.data() + 36, receipt.rs_epoch);
  std::memcpy(out.data() + 40, receipt.digest.data(), 32);
  out[72] = receipt.status;
  out[73] = out[74] = out[75] = 0;
  return Status::success();
}
Status grant_receipt_decode(ByteView bytes, GrantReceipt& out) noexcept {
  if (bytes.data == nullptr || bytes.size != kGrantReceiptSize) return bad("renew receipt length");
  GrantRenewHead head{};
  Status st = grant_renew_head_decode(bytes, head);
  if (!st) return st;
  if ((head.phase != GrantRenewPhase::Prepared && head.phase != GrantRenewPhase::Applied) ||
      u64(bytes.data + 24) == 0 || bytes.data[72] > 4 || bytes.data[73] != 0 ||
      bytes.data[74] != 0 || bytes.data[75] != 0 ||
      (head.phase == GrantRenewPhase::Prepared && u32(bytes.data + 36) != 0))
    return bad("renew receipt");
  out.head = head;
  out.new_network = u64(bytes.data + 24);
  out.gk_epoch = u32(bytes.data + 32);
  out.rs_epoch = u32(bytes.data + 36);
  std::memcpy(out.digest.data(), bytes.data + 40, 32);
  out.status = bytes.data[72];
  return Status::success();
}
Status cutover_commit_aad(NetworkId old_network,
                          std::array<std::uint8_t, kCutoverAadSize>& out) noexcept {
  if (old_network == 0) return bad("cutover old network");
  constexpr char domain[] = "RouteLoom/site-cutover/v1";
  std::memcpy(out.data(), domain, sizeof(domain));
  put64(out.data() + sizeof(domain), old_network);
  return Status::success();
}
Status cutover_commit_verify(ByteView object, const P256PublicKey& sak,
                             NetworkId expected_old, CutoverCommit& out, bool& verified,
                             const Es256Verifier& verifier) noexcept {
  out = CutoverCommit{};
  verified = false;
  CoseEs256Parts parts{};
  Status st = cose_es256_parse(object, kCutoverPayloadSize, kCutoverPayloadSize,
                               kCutoverObjectSize, parts);
  if (!st) return st;
  const auto* p = parts.payload.data;
  if (object.size != kCutoverObjectSize || p[0] != 1 || p[1] != 0 || u16(p + 2) != 0 ||
      u64(p + 4) == 0 || u64(p + 12) != expected_old || u64(p + 20) == 0 ||
      u64(p + 28) == 0 || u32(p + 36) == 0 || u32(p + 40) == 0 || u32(p + 44) == 0)
    return bad("cutover proof binding");
  std::array<std::uint8_t, kCutoverAadSize> aad{};
  st = cutover_commit_aad(expected_old, aad);
  if (!st) return st;
  st = cose_es256_verify(parts.payload, ByteView{aad.data(), aad.size()},
                         parts.signature, sak, verifier, verified);
  if (!st || !verified) return st;
  out.site_id = u64(p + 4);
  out.old_network = u64(p + 12);
  out.new_network = u64(p + 20);
  out.cutover_id = u64(p + 28);
  out.revision = u32(p + 36);
  out.gk_epoch = u32(p + 40);
  out.rs_epoch = u32(p + 44);
  std::memcpy(out.rrs_sha256.data(), p + 48, 32);
  return Status::success();
}
}  // namespace routeloom::sdkv1
