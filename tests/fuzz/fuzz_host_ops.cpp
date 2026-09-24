// Fuzz target: routeloom::usb host-operations inner-body decoders
// (components/routeloom/src/usb_host_ops.cpp) — the payload layer carried
// inside FrameKind::HostOps USB frames, plus parse_canonical_request (the
// canonical send-request parser the bridge runs per submit).
//
// All decoders run over the raw input; the `sub` byte where required is
// taken from the input itself. Accepted structures are re-encoded where an
// encoder exists (idempotence), and decoders that borrow `inner` are checked
// for view safety by touching the borrowed bytes after the call.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "routeloom/usb_host_ops.hpp"

#include "fuzz_driver.hpp"

namespace {

using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::usb::HostOpsSub;

HostOpsSub sub_of(const std::uint8_t* data, std::size_t size) {
  return static_cast<HostOpsSub>(size > 1 ? data[1] : 0);
}

void touch(const ByteView view) {
  volatile std::uint8_t sink = 0;
  for (std::size_t i = 0; i < view.size; ++i) sink ^= view.data[i];
  (void)sink;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace routeloom::usb;
  const ByteView inner{data, size};
  const HostOpsSub sub = sub_of(data, size);
  std::array<std::uint8_t, 8192> enc{};
  std::size_t written = 0;

  {
    SubmitRequest out{};
    if (decode_submit(inner, out)) {
      touch(out.canonical);
      written = 0;
      if (encode_submit(out, MutableByteView{enc.data(), enc.size()},
                        written)) {
        SubmitRequest again{};
        if (!decode_submit(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    LaneRequest out{};
    if (decode_lane_request(inner, sub, out)) {
      written = 0;
      if (encode_lane_request(sub, out,
                              MutableByteView{enc.data(), enc.size()},
                              written)) {
        LaneRequest again{};
        if (!decode_lane_request(ByteView{enc.data(), written}, sub, again))
          std::abort();
      }
    }
  }
  {
    TimeSampleRequest out{};
    if (decode_time_sample_request(inner, out)) {
      written = 0;
      if (encode_time_sample_request(
              out, MutableByteView{enc.data(), enc.size()}, written)) {
        TimeSampleRequest again{};
        if (!decode_time_sample_request(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    DispatchReceipt out{};
    if (decode_receipt(inner, sub, out)) {
      written = 0;
      if (encode_receipt(out, MutableByteView{enc.data(), enc.size()},
                         written)) {
        DispatchReceipt again{};
        if (!decode_receipt(ByteView{enc.data(), written}, sub, again))
          std::abort();
      }
    }
  }
  {
    QueryResponse out{};
    if (decode_query_response(inner, out)) {
      written = 0;
      if (encode_query_response(out, MutableByteView{enc.data(), enc.size()},
                                written)) {
        QueryResponse again{};
        if (!decode_query_response(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    RetireResponse out{};
    if (decode_retire_response(inner, out)) {
      written = 0;
      if (encode_retire_response(out,
                                 MutableByteView{enc.data(), enc.size()},
                                 written)) {
        RetireResponse again{};
        if (!decode_retire_response(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    TimeSampleResponse out{};
    if (decode_time_sample_response(inner, out)) {
      written = 0;
      if (encode_time_sample_response(
              out, MutableByteView{enc.data(), enc.size()}, written)) {
        TimeSampleResponse again{};
        if (!decode_time_sample_response(ByteView{enc.data(), written},
                                         again))
          std::abort();
      }
    }
  }
  {
    HostRegisterRequest out{};
    if (decode_host_register(inner, out)) {
      written = 0;
      if (encode_host_register(out, MutableByteView{enc.data(), enc.size()},
                               written)) {
        HostRegisterRequest again{};
        if (!decode_host_register(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    HostRegisterResponse out{};
    if (decode_host_register_response(inner, out)) {
      written = 0;
      if (encode_host_register_response(
              out, MutableByteView{enc.data(), enc.size()}, written)) {
        HostRegisterResponse again{};
        if (!decode_host_register_response(ByteView{enc.data(), written},
                                           again))
          std::abort();
      }
    }
  }
  {
    GatewayIngress out{};
    if (decode_gateway_ingress(inner, out)) {
      touch(out.payload);
      written = 0;
      if (encode_gateway_ingress(out, MutableByteView{enc.data(), enc.size()},
                                 written)) {
        GatewayIngress again{};
        if (!decode_gateway_ingress(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    GatewayIngressAck out{};
    if (decode_gateway_ingress_ack(inner, out)) {
      written = 0;
      if (encode_gateway_ingress_ack(
              out, MutableByteView{enc.data(), enc.size()}, written)) {
        GatewayIngressAck again{};
        if (!decode_gateway_ingress_ack(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    HostUnregisterRequest out{};
    if (decode_host_unregister(inner, out)) {
      written = 0;
      if (encode_host_unregister(out,
                                 MutableByteView{enc.data(), enc.size()},
                                 written)) {
        HostUnregisterRequest again{};
        if (!decode_host_unregister(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    HostUnregisterResponse out{};
    if (decode_host_unregister_response(inner, out)) {
      written = 0;
      if (encode_host_unregister_response(
              out, MutableByteView{enc.data(), enc.size()}, written)) {
        HostUnregisterResponse again{};
        if (!decode_host_unregister_response(ByteView{enc.data(), written},
                                             again))
          std::abort();
      }
    }
  }
  {
    ConfigQueryRequest out{};
    if (decode_config_query(inner, out)) {
      written = 0;
      if (encode_config_query(out, MutableByteView{enc.data(), enc.size()},
                              written)) {
        ConfigQueryRequest again{};
        if (!decode_config_query(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    ConfigChallengeRequest out{};
    if (decode_config_challenge(inner, out)) {
      written = 0;
      if (encode_config_challenge(out,
                                  MutableByteView{enc.data(), enc.size()},
                                  written)) {
        ConfigChallengeRequest again{};
        if (!decode_config_challenge(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    ConfigPermitRequest out{};
    if (decode_config_permit(inner, out)) {
      touch(out.permit);
      written = 0;
      if (encode_config_permit(out, MutableByteView{enc.data(), enc.size()},
                               written)) {
        ConfigPermitRequest again{};
        if (!decode_config_permit(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    ConfigTrustRequest out{};
    if (decode_config_trust(inner, out)) {
      touch(out.object);
      written = 0;
      if (encode_config_trust(out, MutableByteView{enc.data(), enc.size()},
                              written)) {
        ConfigTrustRequest again{};
        if (!decode_config_trust(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    TrustStatusRequest out{};
    if (decode_trust_status(inner, out)) {
      written = 0;
      if (encode_trust_status(out, MutableByteView{enc.data(), enc.size()},
                              written)) {
        TrustStatusRequest again{};
        if (!decode_trust_status(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    RecoveryInfoRequest out{};
    if (decode_recovery_info(inner, out)) {
      written = 0;
      if (encode_recovery_info(out, MutableByteView{enc.data(), enc.size()},
                               written)) {
        RecoveryInfoRequest again{};
        if (!decode_recovery_info(ByteView{enc.data(), written}, again))
          std::abort();
      }
    }
  }
  {
    ConfigReply out{};
    if (decode_config_reply(inner, sub, out)) {
      touch(out.body);
      written = 0;
      if (encode_config_reply(sub, out,
                              MutableByteView{enc.data(), enc.size()},
                              written)) {
        ConfigReply again{};
        if (!decode_config_reply(ByteView{enc.data(), written}, sub, again))
          std::abort();
      }
    }
  }
  {
    DiagnosticRequestView out{};
    if (decode_diagnostic_request(inner, out)) touch(out.body);
  }
  {
    CanonicalFields out{};
    if (parse_canonical_request(inner, out)) touch(out.payload);
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
