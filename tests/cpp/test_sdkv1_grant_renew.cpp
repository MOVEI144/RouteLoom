#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/sdkv1_grant_renew.hpp"

using namespace routeloom;
using namespace routeloom::sdkv1;

int main() {
  GrantRenewHead head{};
  head.phase = GrantRenewPhase::Prepare;
  head.cutover_id = 9;
  head.revision = 1;
  head.old_network = 0x10000002aULL;
  std::array<std::uint8_t, kGrantRenewHeadSize> bytes{};
  if (!grant_renew_head_encode(head, bytes)) return 1;
  GrantRenewHead parsed{};
  if (!grant_renew_head_decode(ByteView{bytes.data(), bytes.size()}, parsed) ||
      parsed.phase != head.phase || parsed.cutover_id != 9) return 2;
  bytes[2] = 1;
  if (grant_renew_head_decode(ByteView{bytes.data(), bytes.size()}, parsed)) return 3;
  bytes[2] = 0;
  bytes[1] = 5;
  if (!grant_renew_head_decode(ByteView{bytes.data(), bytes.size()}, parsed) ||
      parsed.phase != GrantRenewPhase::CommitStored) return 4;
  bytes[1] = 6;
  if (!grant_renew_head_decode(ByteView{bytes.data(), bytes.size()}, parsed) ||
      parsed.phase != GrantRenewPhase::RouteState) return 5;
  bytes[1] = 7;
  if (grant_renew_head_decode(ByteView{bytes.data(), bytes.size()}, parsed)) return 6;
  // COMMIT_STORED is a receipt phase (76 B, same layout as APPLIED).
  GrantReceipt stored{};
  stored.head = {GrantRenewPhase::CommitStored, 9, 1, 0x10000002aULL};
  stored.new_network = 0x20000002aULL;
  stored.gk_epoch = 19;
  stored.rs_epoch = 22;
  stored.digest.fill(0xab);
  std::array<std::uint8_t, kGrantReceiptSize> receipt_bytes{};
  if (!grant_receipt_encode(stored, receipt_bytes)) return 7;
  GrantReceipt receipt_parsed{};
  if (!grant_receipt_decode(ByteView{receipt_bytes.data(), receipt_bytes.size()},
                            receipt_parsed) ||
      receipt_parsed.head.phase != GrantRenewPhase::CommitStored ||
      receipt_parsed.rs_epoch != 22) return 8;
  // RouteState query/report round-trip plus strict rejections.
  GrantRouteState query{};
  query.head = {GrantRenewPhase::RouteState, 9, 1, 0x10000002aULL};
  query.mode = 0;
  query.query_id = 41;
  std::array<std::uint8_t, kGrantRouteStateSize> route_bytes{};
  if (!grant_route_state_encode(query, route_bytes)) return 9;
  GrantRouteState route_parsed{};
  if (!grant_route_state_decode(ByteView{route_bytes.data(), route_bytes.size()},
                                route_parsed) ||
      route_parsed.mode != 0 || route_parsed.query_id != 41) return 10;
  GrantRouteState report{};
  report.head = query.head;
  report.mode = 1;
  report.status = 0;
  report.root = 0x00A100000000A101ULL;
  report.parent = 0x00A100000000A102ULL;
  report.boot = 7;
  report.route_stamp = 4242;
  report.query_id = 41;
  report.valid_for_ms = 30000;
  if (!grant_route_state_encode(report, route_bytes)) return 11;
  if (!grant_route_state_decode(ByteView{route_bytes.data(), route_bytes.size()},
                                route_parsed) ||
      route_parsed.parent != report.parent || route_parsed.valid_for_ms != 30000) return 12;
  GrantRouteState unavailable{};
  unavailable.head = query.head;
  unavailable.mode = 1;
  unavailable.status = 1;
  unavailable.query_id = 41;
  if (!grant_route_state_encode(unavailable, route_bytes)) return 13;
  if (!grant_route_state_decode(ByteView{route_bytes.data(), route_bytes.size()},
                                route_parsed) ||
      route_parsed.status != 1) return 14;
  // Rejections: bad mode/status, query with payload, unavailable with
  // parent/lease, ok without root, short/long/reserved corruption.
  GrantRouteState bad = report;
  bad.mode = 2;
  if (grant_route_state_encode(bad, route_bytes)) return 15;
  bad = report;
  bad.status = 2;
  if (grant_route_state_encode(bad, route_bytes)) return 16;
  bad = query;
  bad.root = 1;
  if (grant_route_state_encode(bad, route_bytes)) return 17;
  bad = unavailable;
  bad.parent = 1;
  if (grant_route_state_encode(bad, route_bytes)) return 18;
  bad = unavailable;
  bad.valid_for_ms = 1;
  if (grant_route_state_encode(bad, route_bytes)) return 19;
  bad = report;
  bad.root = 0;
  if (grant_route_state_encode(bad, route_bytes)) return 20;
  bad = query;
  bad.query_id = 0;
  if (grant_route_state_encode(bad, route_bytes)) return 21;
  if (!grant_route_state_encode(report, route_bytes)) return 22;
  if (grant_route_state_decode(ByteView{route_bytes.data(), route_bytes.size() - 1},
                               route_parsed)) return 23;
  std::array<std::uint8_t, kGrantRouteStateSize + 1> trailing{};
  std::memcpy(trailing.data(), route_bytes.data(), route_bytes.size());
  if (grant_route_state_decode(ByteView{trailing.data(), trailing.size()}, route_parsed))
    return 24;
  route_bytes[26] = 1;
  if (grant_route_state_decode(ByteView{route_bytes.data(), route_bytes.size()}, route_parsed))
    return 25;
  std::puts("grant renew head ok");
  return 0;
}
