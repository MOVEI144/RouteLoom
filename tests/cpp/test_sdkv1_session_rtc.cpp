#include <array>
#include <cstdint>
#include <cstdio>

#include "routeloom/sdkv1_session_rtc.hpp"

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
int failures = 0;
void check(bool ok, int line) {
  if (!ok) { std::fprintf(stderr, "RTC check failed: %d\n", line); ++failures; }
}
#define CHECK(x) check(static_cast<bool>(x), __LINE__)
}

int main() {
  RtcSessionImage saved{};
  saved.source_boot = 42;
  saved.network = 0x1234567800000001ULL;
  saved.local_generation = 3;
  saved.site_commit = 5;
  saved.gk_epoch = 7;
  saved.rs_floor = 4;
  saved.kid_digest[0] = 0xaa;
  saved.parent_mac[0] = 0x22;
  saved.parent_binding = 8;
  saved.count = 2;
  saved.contexts[0].scope = SecurityScope::Link;
  saved.contexts[1].scope = SecurityScope::EndToEnd;
  for (auto& c : saved.contexts) {
    c.entry.peer = 11;
    c.entry.tx_cid = 17;
    c.entry.rx_cid = 19;
    c.entry.tx_next = 20;
    c.entry.rx_max = 10;
    c.entry.rx_bitmap = 1;
    c.entry.remaining_ms = 10000;
    c.entry.created_gk = 7;
    c.entry.tx_key[0] = 0x61;
  }
  std::array<std::uint8_t, kRtcSessionRecordSize> raw{};
  CHECK(encode_rtc_session(saved, MutableByteView{raw.data(), raw.size()}).ok());
  RtcSessionImage result{};
  RtcWakeCheck wake{};
  wake.deep_sleep = true;
  wake.sleep_marker = true;
  wake.trusted_elapsed_ms = 100;
  wake.next_boot = 43;
  wake.network = saved.network;
  wake.local_generation = saved.local_generation;
  wake.site_commit = saved.site_commit;
  wake.gk_epoch = saved.gk_epoch;
  wake.rs_floor = saved.rs_floor;
  wake.kid_digest = saved.kid_digest;
  CHECK(decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
  CHECK(result.count == 2 && result.contexts[0].entry.tx_next == 20 &&
        result.contexts[1].entry.remaining_ms == 9900);
  // Every corrupt byte, including keys, counters and commitment, rejects.
  for (std::size_t i = 0; i < raw.size(); ++i) {
    raw[i] ^= 1;
    CHECK(!decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
    raw[i] ^= 1;
  }
  wake.deep_sleep = false;
  CHECK(!decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
  wake.deep_sleep = true;
  wake.sleep_marker = false;
  CHECK(!decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
  wake.sleep_marker = true;
  wake.next_boot = 44;
  CHECK(!decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
  wake.next_boot = 43;
  wake.trusted_elapsed_ms = 0;
  CHECK(!decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
  wake.trusted_elapsed_ms = 10000;
  CHECK(!decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
  return failures ? 1 : 0;
}
