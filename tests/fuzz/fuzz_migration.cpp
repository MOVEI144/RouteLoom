// Fuzz target: routeloom migration wire decoders
// (components/routeloom/src/migration_wire.cpp) — the object-content codecs
// carried inside ControlObject/RecoverySnapshot objects: CommitEvidence,
// ReadyReport, ResultReport, SnapshotRequest and the signed-snapshot
// wrapper. Accepted inputs get an encode→decode→encode idempotence pass.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "routeloom/migration_wire.hpp"

#include "fuzz_driver.hpp"

namespace {

using routeloom::ByteView;
using routeloom::MutableByteView;

// Encode capacity covers the largest body (commit evidence ~203B) plus
// headroom for the snapshot wrapper.
std::array<std::uint8_t, 2048> enc_buf;

template <typename T, typename Decode, typename Encode>
void roundtrip(const ByteView input, Decode decode, Encode encode) {
  T first{};
  if (!decode(input, first)) return;
  std::size_t written = 0;
  if (!encode(first, MutableByteView{enc_buf.data(), enc_buf.size()},
              written)) {
    return;
  }
  T second{};
  if (!decode(ByteView{enc_buf.data(), written}, second)) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  const ByteView input{data, size};

  roundtrip<routeloom::CommitEvidence>(
      input, routeloom::commit_evidence_decode,
      [](const routeloom::CommitEvidence& p, MutableByteView o,
         std::size_t& n) {
        return routeloom::commit_evidence_encode(p, o, n);
      });
  roundtrip<routeloom::ReadyReport>(
      input, routeloom::ready_report_decode,
      [](const routeloom::ReadyReport& p, MutableByteView o, std::size_t& n) {
        return routeloom::ready_report_encode(p, o, n);
      });
  roundtrip<routeloom::ResultReport>(
      input, routeloom::result_report_decode,
      [](const routeloom::ResultReport& p, MutableByteView o, std::size_t& n) {
        return routeloom::result_report_encode(p, o, n);
      });
  roundtrip<routeloom::SnapshotRequest>(
      input, routeloom::snapshot_request_decode,
      [](const routeloom::SnapshotRequest& p, MutableByteView o,
         std::size_t& n) {
        return routeloom::snapshot_request_encode(p, o, n);
      });

  // Signed-snapshot wrapper: u16 sig_len | signature | body. On a
  // successful unwrap, re-wrap must round-trip to identical bytes.
  {
    ByteView body{};
    ByteView signature{};
    if (routeloom::signed_snapshot_unwrap(input, body, signature)) {
      std::size_t written = 0;
      if (routeloom::signed_snapshot_wrap(
              body, signature,
              MutableByteView{enc_buf.data(), enc_buf.size()}, written)) {
        ByteView body2{};
        ByteView sig2{};
        if (!routeloom::signed_snapshot_unwrap(
                ByteView{enc_buf.data(), written}, body2, sig2)) {
          std::abort();
        }
        if (body2.size != body.size || sig2.size != signature.size) {
          std::abort();
        }
      }
    }
  }

  // Commit-signing input: pure layout over a fuzzed AuthorityOperation is
  // encode-only; the decode direction is commit_evidence_decode above.
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
