#include <array>
#include <cstdint>
#include <cstdio>

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
  if (grant_renew_head_decode(ByteView{bytes.data(), bytes.size()}, parsed)) return 4;
  std::puts("grant renew head ok");
  return 0;
}
