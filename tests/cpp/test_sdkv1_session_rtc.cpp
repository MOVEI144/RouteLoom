#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/sdkv1_session_rtc.hpp"
#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"

using namespace routeloom;
using namespace routeloom::sdkv1;

// The write-ahead guard borrows its retained image from caller-stable
// storage: a second by-value copy would not fit bridge DRAM next to the
// coordinator's held restore image.
static_assert(sizeof(RtcWriteAheadProvider) <= 48, "guard must borrow the image");

namespace {
// Keyed test cipher (NOT an AEAD): XOR stream plus a tag over key, nonce,
// AAD and body. Cross-key confusion fails the tag; the bank suite proves the
// same logic against real AES-GCM.
struct RtcAead {
  static bool xform(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                    const ByteView aad, const ByteView input, std::uint8_t* out,
                    std::uint8_t tag[16], const bool sealing) noexcept {
    (void)ctx;
    std::uint64_t state = 0x5254436165616400ULL;
    auto mix = [&state](std::uint64_t v) {
      state ^= v + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
      state *= 0xbf58476d1ce4e5b9ULL;
    };
    for (int i = 0; i < 16; ++i) mix(key[i]);
    for (int i = 0; i < 12; ++i) mix(nonce[i]);
    for (std::size_t i = 0; i < aad.size; ++i) mix(aad.data[i]);
    const std::uint64_t stream = state;
    for (std::size_t i = 0; i < input.size; ++i) {
      std::uint64_t s = stream ^ (i + 1);
      s ^= s + 0x9e3779b97f4a7c15ULL;
      out[i] = input.data[i] ^ static_cast<std::uint8_t>(s >> 56U);
    }
    const ByteView tagged = sealing ? ByteView{out, input.size} : input;
    std::uint64_t left = stream, right = stream ^ 0x746167ULL;
    for (std::size_t i = 0; i < aad.size; ++i) {
      left ^= aad.data[i];
      left *= 0xbf58476d1ce4e5b9ULL;
    }
    for (std::size_t i = 0; i < tagged.size; ++i) {
      right ^= tagged.data[i];
      right *= 0xbf58476d1ce4e5b9ULL;
    }
    std::uint8_t expect[16];
    for (int i = 0; i < 8; ++i) {
      expect[i] = static_cast<std::uint8_t>(left >> (56 - i * 8));
      expect[8 + i] = static_cast<std::uint8_t>(right >> (56 - i * 8));
    }
    if (sealing) {
      std::memcpy(tag, expect, 16);
      return true;
    }
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<std::uint8_t>(expect[i] ^ tag[i]);
    return diff == 0;
  }
  static bool seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out,
                   std::uint8_t tag[16]) noexcept {
    return xform(ctx, key, nonce, aad, plaintext, out, tag, true);
  }
  static bool open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out) noexcept {
    std::uint8_t copy[16];
    std::memcpy(copy, tag, 16);
    return xform(ctx, key, nonce, aad, ciphertext, out, copy, false);
  }
};

struct RtcRandom {
  std::uint64_t state{0xC10C5EED5EED1ULL};
  static bool fill(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
    auto& self = *static_cast<RtcRandom*>(ctx);
    for (std::size_t i = 0; i < size; ++i) {
      self.state = self.state * 6364136223846793005ULL + 1442695040888963407ULL;
      out[i] = static_cast<std::uint8_t>(self.state >> 56U);
    }
    return true;
  }
};

struct RtcMemory final : RtcSessionPort {
  std::array<std::uint8_t, kRtcSessionRecordSize> bytes{};
  bool fail_clear{false};
  bool fail_write{false};
  bool stale_clear{false};
  Status read(MutableByteView out) noexcept override {
    std::copy(bytes.begin(), bytes.end(), out.data);
    return Status::success();
  }
  Status invalidate() noexcept override {
    if (fail_clear) return Status::error(StatusCode::StorageFailure, "clear");
    if (!stale_clear) bytes[8] = 0; // committed marker, invalid before publishing keys
    return Status::success();
  }
  Status write(ByteView in) noexcept override {
    if (fail_write) return Status::error(StatusCode::StorageFailure, "write");
    std::copy(in.data, in.data + in.size, bytes.begin());
    return Status::success();
  }
};
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
  RtcSessionImage no_parent = saved;
  no_parent.parent_mac = {};
  CHECK(!encode_rtc_session(no_parent, MutableByteView{raw.data(), raw.size()}).ok());
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
    CHECK(result.count == 0 && result.contexts[0].entry.tx_key[0] == 0);
    raw[i] ^= 1;
    CHECK(decode_rtc_session(ByteView{raw.data(), raw.size()}, wake, result).ok());
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
  wake.trusted_elapsed_ms = 100;

  // F07: a wake may consume the image only once, and a failed marker
  // invalidation must never publish keys or counters.
  RtcMemory rtc;
  rtc.bytes = raw;
  RtcSessionImage restored{};
  rtc.fail_clear = true;
  CHECK(!consume_rtc_session(rtc, wake, restored).ok());
  CHECK(restored.count == 0);
  rtc.fail_clear = false;
  rtc.stale_clear = true;
  CHECK(!consume_rtc_session(rtc, wake, restored).ok());
  CHECK(restored.count == 0);
  rtc.stale_clear = false;
  CHECK(consume_rtc_session(rtc, wake, restored).ok());
  CHECK(restored.count == 2 && restored.contexts[0].entry.tx_next == 20);
  CHECK(!consume_rtc_session(rtc, wake, result).ok());

  // A rejected wake image must not leave old key bytes in retained RAM.
  std::array<std::uint8_t, kRtcSessionRecordSize> retained = raw;
  retained[80] ^= 1;  // key/body corruption with a committed marker
  BufferRtcSessionPort retained_port(MutableByteView{retained.data(), retained.size()});
  CHECK(!consume_rtc_session(retained_port, wake, result).ok());
  CHECK(std::all_of(retained.begin(), retained.end(), [](std::uint8_t byte) {
    return byte == 0;
  }));

  // F07 write-ahead: no radio TX with an old retained counter. An
  // interrupted write leaves the marker invalid and forces a new handshake.
  rtc.bytes = raw;
  std::uint64_t issued = 123;
  rtc.fail_write = true;
  CHECK(!advance_rtc_tx(rtc, saved, 0, issued).ok());
  CHECK(issued == 123 && saved.contexts[0].entry.tx_next == 20);
  CHECK(!decode_rtc_session(ByteView{rtc.bytes.data(), rtc.bytes.size()}, wake, result).ok());
  rtc.fail_write = false;
  rtc.bytes = raw;
  CHECK(advance_rtc_tx(rtc, saved, 0, issued).ok());
  CHECK(issued == 20 && saved.contexts[0].entry.tx_next == 21);
  CHECK(decode_rtc_session(ByteView{rtc.bytes.data(), rtc.bytes.size()}, wake, result).ok());
  CHECK(result.contexts[0].entry.tx_next == 21);
  // Stale copies cannot overwrite a later retained counter.
  RtcSessionImage stale = saved;
  stale.contexts[0].entry.tx_next = 20;
  CHECK(!advance_rtc_tx(rtc, stale, 0, issued).ok());
  CHECK(stale.contexts[0].entry.tx_next == 20);
  rtc.stale_clear = true;
  CHECK(!advance_rtc_tx(rtc, saved, 0, issued).ok());
  CHECK(saved.contexts[0].entry.tx_next == 21);

  // F07 restore: a consumed image returns its key, TX counter, RX window and
  // lifetime to a cold bank as one unit — never counter 0 under the old key.
  // The radio peer must also be live: the parent MAC/binding gate below
  // refuses a context without its neighbor.
  RtcRandom random_a;
  RtcRandom random_b;
  AeadGcm aead{RtcAead::seal, RtcAead::open, nullptr};
  NodeSessionBank bank_a;
  NodeSessionBank::LocalView local{};
  local.self = 0x00A1000000000001ULL;
  local.network = 0x1234567800000001ULL;
  local.gk_epoch = 7;
  CHECK(bank_a.configure(local, aead, {RtcRandom::fill, &random_a}, 1000).ok());
  ContextKeys keys{};
  keys.scope = SecurityScope::Link;
  keys.network = local.network;
  keys.peer = 11;
  keys.tx_context_id = 17;
  keys.rx_context_id = 19;
  for (std::size_t i = 0; i < keys.tx_key.size(); ++i) {
    keys.tx_key[i] = static_cast<std::uint8_t>(0x10 + i);
    keys.rx_key[i] = static_cast<std::uint8_t>(0x50 + i);
  }
  for (std::size_t i = 0; i < keys.tx_iv.size(); ++i) {
    keys.tx_iv[i] = static_cast<std::uint8_t>(0x90 + i);
    keys.rx_iv[i] = static_cast<std::uint8_t>(0xD0 + i);
  }
  keys.peer_cert_id = {1, 2, 3, 4, 5, 6, 7, 8};
  keys.peer_generation = 3;
  InstallAttestation att{};
  att.peer_role = 0b011;
  att.created_gk_epoch = 7;
  CHECK(bank_a.install_verified(keys, att).ok());
  SecurityContext tx{};
  tx.scope = SecurityScope::Link;
  tx.network = local.network;
  tx.sender = local.self;
  tx.receiver = 11;
  tx.epoch = 17;
  std::uint64_t pre_sleep = 0;
  CHECK(bank_a.next_counter(tx, pre_sleep).ok());
  CHECK(pre_sleep == 0);
  const std::uint8_t aad[] = {0xAA};
  const std::uint8_t plain[] = {1, 2, 3, 4};
  std::array<std::uint8_t, 4> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK(bank_a.seal(tx, pre_sleep, ByteView{aad, sizeof(aad)},
                    ByteView{plain, sizeof(plain)},
                    MutableByteView{cipher.data(), cipher.size()}, tag).ok());
  SessionBankEntry exported{};
  CHECK(bank_a.export_entry(SecurityScope::Link, 11, exported).ok());
  CHECK(exported.tx_next == 1 && exported.flags == 0);
  // The image below carries a post-RX window; encode/consume/restore must
  // keep it with the key instead of reopening old counters.
  exported.rx_max = 9;
  exported.rx_bitmap = 0x1D;
  exported.install_serial = 41;  // stale pre-sleep serial: never trusted post-wake
  RtcSessionImage sleep{};
  sleep.source_boot = 42;
  sleep.network = local.network;
  sleep.local_generation = 3;
  sleep.site_commit = 5;
  sleep.gk_epoch = 7;
  sleep.rs_floor = 4;
  sleep.kid_digest[0] = 0xAA;
  sleep.parent_mac = {0x02, 0, 0, 0, 0, 0x0B};
  sleep.parent_binding = 8;
  sleep.count = 1;
  sleep.contexts[0].scope = SecurityScope::Link;
  sleep.contexts[0].entry = exported;
  RtcMemory sleep_rtc;
  CHECK(encode_rtc_session(sleep, MutableByteView{sleep_rtc.bytes.data(),
                                                 sleep_rtc.bytes.size()}).ok());
  RtcWakeCheck sleep_wake{};
  sleep_wake.deep_sleep = true;
  sleep_wake.sleep_marker = true;
  sleep_wake.trusted_elapsed_ms = 100;
  sleep_wake.next_boot = 43;
  sleep_wake.network = local.network;
  sleep_wake.local_generation = 3;
  sleep_wake.site_commit = 5;
  sleep_wake.gk_epoch = 7;
  sleep_wake.rs_floor = 4;
  sleep_wake.kid_digest = sleep.kid_digest;
  RtcSessionImage woken{};
  CHECK(consume_rtc_session(sleep_rtc, sleep_wake, woken).ok());
  CHECK(!consume_rtc_session(sleep_rtc, sleep_wake, result).ok());
  CHECK(rtc_parent_binding_ok(woken, sleep.parent_mac, 8));
  CHECK(!rtc_parent_binding_ok(woken, MacAddress{0x02, 0, 0, 0, 0, 0x0C}, 8));
  CHECK(!rtc_parent_binding_ok(woken, sleep.parent_mac, 9));
  CHECK(!rtc_parent_binding_ok(woken, sleep.parent_mac, 0));
  NodeSessionBank bank_b;
  CHECK(bank_b.configure(local, aead, {RtcRandom::fill, &random_b}, 2000).ok());
  CHECK(bank_b.restore_entry(SecurityScope::Link, 11, woken.contexts[0].entry).ok());
  SessionBankEntry round_trip{};
  CHECK(bank_b.export_entry(SecurityScope::Link, 11, round_trip).ok());
  CHECK(round_trip.tx_next == 1 && round_trip.rx_max == 9 &&
        round_trip.rx_bitmap == 0x1D);
  CHECK(round_trip.tx_key == exported.tx_key && round_trip.rx_key == exported.rx_key);
  CHECK(round_trip.tx_cid == 17 && round_trip.rx_cid == 19);
  CHECK(round_trip.peer_generation == 3 && round_trip.peer_role == 0b011);
  CHECK(round_trip.created_gk == 7 && round_trip.remaining_ms == 24U * 3600U * 1000U - 100);
  CHECK(round_trip.install_serial != exported.install_serial);
  std::uint64_t post_wake = 0;
  CHECK(bank_b.next_counter(tx, post_wake).ok());
  CHECK(post_wake == 1);  // continues — the pre-sleep counter is never reused
  CHECK(bank_b.restore_entry(SecurityScope::Link, 11, woken.contexts[0].entry).code ==
        StatusCode::Conflict);  // occupied: never overwrite live keys with old counters

  // Restore refusals: exhausted counters, dead lifetimes, in-flight
  // reservations, stale GK birthdays, id collisions and empty tables.
  NodeSessionBank bank_c;
  CHECK(bank_c.configure(local, aead, {RtcRandom::fill, &random_b}, 3000).ok());
  SessionBankEntry bad = woken.contexts[0].entry;
  bad.tx_next = std::uint64_t{1} << 32;
  CHECK(bank_c.restore_entry(SecurityScope::Link, 11, bad).code ==
        StatusCode::CounterExhausted);
  bad = woken.contexts[0].entry;
  bad.rx_max = std::uint64_t{1} << 32;
  CHECK(!bank_c.restore_entry(SecurityScope::Link, 11, bad).ok());
  bad = woken.contexts[0].entry;
  bad.remaining_ms = 0;
  CHECK(bank_c.restore_entry(SecurityScope::Link, 11, bad).code == StatusCode::Conflict);
  bad = woken.contexts[0].entry;
  bad.flags = 1;
  CHECK(bank_c.restore_entry(SecurityScope::Link, 11, bad).code ==
        StatusCode::InvalidArgument);
  bad = woken.contexts[0].entry;
  bad.created_gk = 5;
  CHECK(bank_c.restore_entry(SecurityScope::Link, 11, bad).code == StatusCode::Conflict);
  bad = woken.contexts[0].entry;
  bad.tx_cid = 0;
  CHECK(!bank_c.restore_entry(SecurityScope::Link, 11, bad).ok());
  CHECK(bank_c.restore_entry(SecurityScope::Link, 12, woken.contexts[0].entry).code ==
        StatusCode::InvalidArgument);  // entry peer must match the slot
  ContextKeys other = keys;
  other.peer = 12;
  other.tx_context_id = 23;
  CHECK(bank_c.install_verified(other, att).ok());  // holds rx_cid 19
  CHECK(bank_c.restore_entry(SecurityScope::Link, 11, woken.contexts[0].entry).code ==
        StatusCode::Conflict);
  SessionBankEntry missing{};
  CHECK(bank_c.export_entry(SecurityScope::Link, 99, missing).code == StatusCode::NotFound);
  NodeSessionBank cold;
  CHECK(cold.export_entry(SecurityScope::Link, 11, missing).code == StatusCode::InvalidState);
  CHECK(cold.restore_entry(SecurityScope::Link, 11, woken.contexts[0].entry).code ==
        StatusCode::InvalidState);

  // P4 wiring: the buffer-backed port is what firmware binds to RTC slow
  // memory. Exact-size reads/writes only; invalidate clears the committed
  // marker AND any retained key material (no stale keys linger in RTC).
  std::array<std::uint8_t, kRtcSessionRecordSize> backing{};
  BufferRtcSessionPort backing_port{MutableByteView{backing.data(), backing.size()}};
  CHECK(backing_port.write(ByteView{raw.data(), raw.size()}).ok());
  CHECK(backing == raw);
  CHECK(backing_port.write(ByteView{backing.data(), backing.size()}).code ==
        StatusCode::InvalidArgument);
  CHECK(backing == raw);
  std::array<std::uint8_t, kRtcSessionRecordSize> seen{};
  CHECK(backing_port.read(MutableByteView{seen.data(), seen.size()}).ok());
  CHECK(seen == raw);
  std::array<std::uint8_t, kRtcSessionRecordSize - 1> short_buf{};
  CHECK(!backing_port.read(MutableByteView{short_buf.data(), short_buf.size()}).ok());
  CHECK(!backing_port
             .write(ByteView{short_buf.data(), short_buf.size()})
             .ok());
  CHECK(backing == raw);  // refused sizes leave the backing untouched
  RtcSessionImage via_port{};
  CHECK(consume_rtc_session(backing_port, wake, via_port).ok());
  CHECK(via_port.count == 2 && via_port.contexts[0].entry.tx_next == 20);
  CHECK(!consume_rtc_session(backing_port, wake, result).ok());  // one-shot
  bool all_zero = true;
  for (const auto byte : backing) all_zero = all_zero && (byte == 0);
  CHECK(all_zero);  // invalidate wiped the retained keys, not just the marker
  RtcSessionImage live = saved;  // tx_next already 21 from the cycle above
  CHECK(encode_rtc_session(live, MutableByteView{raw.data(), raw.size()}).ok());
  CHECK(backing_port.write(ByteView{raw.data(), raw.size()}).ok());
  CHECK(advance_rtc_tx(backing_port, live, 0, issued).ok());
  CHECK(issued == 21 && live.contexts[0].entry.tx_next == 22);
  CHECK(backing_port.read(MutableByteView{seen.data(), seen.size()}).ok());
  CHECK(decode_rtc_session(ByteView{seen.data(), seen.size()}, wake, result).ok());
  CHECK(result.contexts[0].entry.tx_next == 22);

  // P4 wiring: dev-resume contexts never RTC-restore (fresh RLRES1 after
  // every boot instead); the provenance flag fails the shape gate.
  bad = woken.contexts[0].entry;
  bad.flags = NodeSessionBank::kFlagDevResume;
  CHECK(bank_c.restore_entry(SecurityScope::Link, 11, bad).code ==
        StatusCode::InvalidArgument);

  // Deep-sleep warm gate (P4 §9.3): the restored parent MAC must equal
  // the re-observed radio peer and a live post-wake binding must exist
  // for the parent. Binding ids are re-minted every boot, so id equality
  // is NOT part of this gate — rtc_parent_binding_ok above stays the
  // RAM-continuity check for retained wakes.
  CHECK(rtc_parent_warm_ok(woken, sleep.parent_mac, true));
  CHECK(!rtc_parent_warm_ok(woken, MacAddress{0x02, 0, 0, 0, 0, 0x0C}, true));
  CHECK(!rtc_parent_warm_ok(woken, sleep.parent_mac, false));
  RtcSessionImage empty_image{};
  CHECK(!rtc_parent_warm_ok(empty_image, sleep.parent_mac, true));

  // Write-ahead guard: restored contexts issue TX counters from the RTC
  // image first, so a power cut between radio TX and the next save can
  // never rewind to an issued counter. Unarmed it purely delegates.
  NodeSessionBank bank_d;
  RtcRandom random_d;
  CHECK(bank_d.configure(local, aead, {RtcRandom::fill, &random_d}, 4000).ok());
  CHECK(bank_d.restore_entry(SecurityScope::Link, 11, woken.contexts[0].entry).ok());
  RamSessionProvider<32, 8> inner(bank_d);
  // The guard borrows this image: it must outlive the guard.
  RtcSessionImage guard_image = sleep;
  guard_image.count = 1;
  guard_image.contexts[0].entry.tx_next = 2;
  RtcWriteAheadProvider guard(inner, inner);
  CHECK(!guard.armed());
  CHECK(guard.ready());
  CHECK(guard.security_profile() == SecurityProfile::Development);
  CHECK(guard.context_state(SecurityScope::Link, 11) == ContextState::Ready);
  std::uint32_t guard_epoch = 0;
  CHECK(guard.tx_epoch(SecurityScope::Link, 11, guard_epoch).ok());
  CHECK(guard_epoch == 17);
  std::uint64_t unarmed_first = 0;
  CHECK(guard.next_counter(tx, unarmed_first).ok());
  CHECK(unarmed_first == 1);
  std::array<std::uint8_t, 4> guard_cipher{};
  std::array<std::uint8_t, kAeadTagSize> guard_tag{};
  CHECK(guard.seal(tx, unarmed_first, ByteView{aad, sizeof(aad)},
                  ByteView{plain, sizeof(plain)},
                  MutableByteView{guard_cipher.data(), guard_cipher.size()}, guard_tag).ok());
  // Arm over the live entry: the port commits the image first, then bank
  // and RTC advance in lockstep (bank tx_next is 2 after the issue above).
  RtcMemory guard_rtc;
  CHECK(guard.arm(guard_rtc, guard_image).ok());
  CHECK(guard.armed());
  CHECK(guard.arm(guard_rtc, guard_image).code == StatusCode::InvalidState);
  std::uint64_t issued_two = 0, issued_three = 0;
  CHECK(guard.next_counter(tx, issued_two).ok());
  CHECK(guard.next_counter(tx, issued_three).ok());
  CHECK(issued_two == 2 && issued_three == 3);
  CHECK(decode_rtc_session(ByteView{guard_rtc.bytes.data(), guard_rtc.bytes.size()}, sleep_wake,
                           result).ok());
  CHECK(result.contexts[0].entry.tx_next == 4);  // retained >= issued + 1, always
  SessionBankEntry lockstep{};
  CHECK(bank_d.export_entry(SecurityScope::Link, 11, lockstep).ok());
  CHECK(lockstep.tx_next == 4);  // the bank advanced with the image
  // A reinstalled context stops the write-ahead: the live tx id no
  // longer matches the armed one, so the guard disarms and delegates
  // fresh bank counters — and the dead image is wiped from the port.
  ContextKeys rekeys = keys;
  rekeys.tx_context_id = 0x5555;
  rekeys.rx_context_id = 0x6666;
  rekeys.tx_key.fill(0xC0);  // a real re-handshake mints fresh keys, not just ids
  rekeys.rx_key.fill(0xC1);
  rekeys.tx_iv.fill(0xC2);
  rekeys.rx_iv.fill(0xC3);
  CHECK(bank_d.install_verified(rekeys, att).ok());
  tx.epoch = 0x5555;  // the wire layer re-stamps after tx_epoch, as always
  std::uint64_t fresh = 0;
  CHECK(guard.next_counter(tx, fresh).ok());
  CHECK(fresh == 0);
  CHECK(!guard.armed());
  CHECK(guard_image.count == 0);  // disarm wiped the borrowed image, not a copy
  CHECK(!decode_rtc_session(ByteView{guard_rtc.bytes.data(), guard_rtc.bytes.size()}, sleep_wake,
                            result).ok());
  // An invalid image never arms and leaves the port untouched.
  RtcMemory untouched_rtc;
  CHECK(guard.arm(untouched_rtc, empty_image).code == StatusCode::InvalidArgument);
  CHECK(!guard.armed());
  bool untouched_zero = true;
  for (const auto byte : untouched_rtc.bytes) untouched_zero = untouched_zero && (byte == 0);
  CHECK(untouched_zero);
  // A failed RTC update retires the bank entry and refuses: no counter
  // may fall back to RAM-only issue after durability is lost.
  NodeSessionBank bank_f;
  RtcRandom random_f;
  CHECK(bank_f.configure(local, aead, {RtcRandom::fill, &random_f}, 5000).ok());
  CHECK(bank_f.restore_entry(SecurityScope::Link, 11, woken.contexts[0].entry).ok());
  RamSessionProvider<32, 8> inner_f(bank_f);
  RtcWriteAheadProvider failing(inner_f, inner_f);
  RtcMemory failing_rtc;
  CHECK(failing.arm(failing_rtc, woken).ok());
  tx.epoch = 17;  // re-stamp for this bank's live tx id
  failing_rtc.fail_write = true;
  std::uint64_t refused = 0;
  CHECK(!failing.next_counter(tx, refused).ok());
  CHECK(failing.tx_epoch(SecurityScope::Link, 11, guard_epoch).code == StatusCode::AuthRequired);
  CHECK(!failing.next_counter(tx, refused).ok());  // still refused: no RAM fallback
  CHECK(woken.count == 0);  // the failed update disarmed and wiped the borrowed image
  return failures ? 1 : 0;
}
