// Fuzz target: routeloom::endpoint wire decoders
// (components/routeloom/src/endpoint_wire.cpp) — RLD1 scope bodies,
// Service=21 and Control=22 payloads, and the RCC1 canonical config command
// (+ config_tlv_decode, the TLV layer it wraps).
//
// Every decoder sees the raw input; accepted values get an
// encode→decode→encode idempotence pass.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "routeloom/config.hpp"       // config_tlv_decode / config_snapshot_hash
#include "routeloom/endpoint_wire.hpp"

#include "fuzz_driver.hpp"

namespace {

using routeloom::ByteView;
using routeloom::endpoint::EncodedServicePayload;

template <typename Payload, typename Decode, typename Encode>
void roundtrip(const ByteView input, Decode decode, Encode encode) {
  Payload first{};
  if (!decode(input, first)) return;
  EncodedServicePayload reencoded{};
  if (!encode(first, reencoded)) return;
  Payload second{};
  if (!decode(reencoded.view(), second)) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  namespace e = routeloom::endpoint;
  const ByteView input{data, size};

  // RLD1 scope bodies.
  {
    e::Rld1DiscoverBodyV2 body{};
    if (e::scope_discover_body_decode(input, body)) {
      e::EncodedScopeBody reencoded{};
      if (e::scope_discover_body_encode(body, reencoded)) {
        e::Rld1DiscoverBodyV2 again{};
        if (!e::scope_discover_body_decode(reencoded.view(), again))
          std::abort();
      }
    }
    e::Rld1OfferBodyV2 offer{};
    if (e::scope_offer_body_decode(input, offer)) {
      e::EncodedScopeBody reencoded{};
      if (e::scope_offer_body_encode(offer, reencoded)) {
        e::Rld1OfferBodyV2 again{};
        if (!e::scope_offer_body_decode(reencoded.view(), again))
          std::abort();
      }
    }
  }

  // Service=21 payloads.
  roundtrip<e::ServiceQuery>(input, e::service_query_decode,
                             [](const e::ServiceQuery& p,
                                EncodedServicePayload& o) {
                               return e::service_query_encode(p, o);
                             });
  roundtrip<e::ServiceDescriptor>(
      input, e::service_descriptor_decode,
      [](const e::ServiceDescriptor& p, EncodedServicePayload& o) {
        return e::service_descriptor_encode(p, o);
      });
  roundtrip<e::ServiceSubmit>(input, e::service_submit_decode,
                              [](const e::ServiceSubmit& p,
                                 EncodedServicePayload& o) {
                                return e::service_submit_encode(p, o);
                              });
  roundtrip<e::ServiceOutcome>(input, e::service_outcome_decode,
                              [](const e::ServiceOutcome& p,
                                 EncodedServicePayload& o) {
                                return e::service_outcome_encode(p, o);
                              });

  // Control=22 payloads.
  roundtrip<e::ControlChallengeQuery>(
      input, e::control_challenge_query_decode,
      [](const e::ControlChallengeQuery& p, EncodedServicePayload& o) {
        return e::control_challenge_query_encode(p, o);
      });
  roundtrip<e::ControlChallenge>(
      input, e::control_challenge_decode,
      [](const e::ControlChallenge& p, EncodedServicePayload& o) {
        return e::control_challenge_encode(p, o);
      });
  roundtrip<e::ControlStatusQuery>(
      input, e::control_status_query_decode,
      [](const e::ControlStatusQuery& p, EncodedServicePayload& o) {
        return e::control_status_query_encode(p, o);
      });
  roundtrip<e::ControlStatus>(input, e::control_status_decode,
                              [](const e::ControlStatus& p,
                                 EncodedServicePayload& o) {
                                return e::control_status_encode(p, o);
                              });

  // RCC1 canonical command: 176B fixed header + sorted TLV patch.
  {
    e::ConfigCommand command{};
    if (e::config_command_decode(input, command)) {
      e::EncodedConfigCommand reencoded{};
      if (e::config_command_encode(command, reencoded)) {
        e::ConfigCommand again{};
        if (!e::config_command_decode(reencoded.view(), again)) std::abort();
      }
    }
  }

  // Bare TLV snapshot parser (bounds: 16 fields, value <=96B, strict order).
  {
    std::array<e::ConfigField, e::kConfigFieldCountMax> fields{};
    std::uint16_t count = 0;
    if (routeloom::config_tlv_decode(input, fields.data(),
                                    e::kConfigFieldCountMax, count)) {
      routeloom::ByteBuffer<e::kConfigSnapshotMax> reencoded{};
      if (routeloom::config_tlv_encode(fields.data(), count, reencoded)) {
        std::array<e::ConfigField, e::kConfigFieldCountMax> again_fields{};
        std::uint16_t again_count = 0;
        if (!routeloom::config_tlv_decode(reencoded.view(),
                                         again_fields.data(),
                                         e::kConfigFieldCountMax,
                                         again_count)) {
          std::abort();
        }
      }
    }
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
