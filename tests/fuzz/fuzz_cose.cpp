// Fuzz target: routeloom COSE permit envelope parse
// (components/routeloom/src/config_cose.cpp) — the fixed RLCP1 CBOR
// envelope (COSE_Sign1 tag 18, protected bstr, payload bstr, signature)
// feeding cose_permit_parse, with the decoded payload passed into
// endpoint::config_command_decode (the RCC1 parser the verifier runs next).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "routeloom/config_cose.hpp"
#include "routeloom/endpoint_wire.hpp"

#include "fuzz_driver.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  if (size > routeloom::kCosePermitMax * 2) return 0;
  const routeloom::ByteView permit{data, size};

  routeloom::CosePermitParts parts{};
  if (routeloom::cose_permit_parse(permit, parts)) {
    // The payload alias must stay inside the input — touch every byte.
    volatile std::uint8_t sink = 0;
    for (std::size_t i = 0; i < parts.payload.size; ++i) {
      sink ^= parts.payload.data[i];
    }
    for (std::size_t i = 0; i < parts.signature.size; ++i) {
      sink ^= parts.signature.data[i];
    }
    (void)sink;

    // The next parser stage the real verifier runs on a parsed envelope.
    routeloom::endpoint::ConfigCommand command{};
    (void)routeloom::endpoint::config_command_decode(parts.payload, command);

    // Sig_structure rebuild: caller-supplied external_aad — feed a bounded
    // slice of the input as the AAD (wrong size is a plain error).
    const std::size_t aad_len = size < 64 ? size : 64;
    routeloom::ByteBuffer<routeloom::kCosePermitMax + 64> sig_structure{};
    (void)routeloom::cose_sig_structure(
        parts.protected_bytes, routeloom::ByteView{data, aad_len},
        parts.payload, sig_structure);
  } else {
    // Also probe the inner command parser on raw input — COSE payloads are
    // attacker-controlled once the envelope shape parses.
    routeloom::endpoint::ConfigCommand command{};
    (void)routeloom::endpoint::config_command_decode(permit, command);
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
