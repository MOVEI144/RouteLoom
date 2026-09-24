#include "routeloom/endpoint_wire.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"

namespace routeloom::endpoint {
namespace {

Status reject() noexcept {
  return Status::error(StatusCode::ProtocolError, "endpoint payload rejected");
}

Status invalid(const char* detail) noexcept {
  return Status::error(StatusCode::InvalidArgument, detail);
}

bool all_zero(const ByteView view) noexcept {
  for (std::size_t i = 0; i < view.size; ++i) {
    if (view.data[i] != 0) return false;
  }
  return true;
}

bool any_nonzero(const ByteView view) noexcept { return !all_zero(view); }

// Shared 4-byte Service prelude: version u8 | subtype u8 | scope u8 | flags u8.
Status service_preamble_write(ByteWriter& writer, const std::uint8_t subtype,
                              const GatewayScope scope) noexcept {
  Status status = writer.write_u8(kServicePayloadVersion);
  if (!status) return status;
  status = writer.write_u8(subtype);
  if (!status) return status;
  status = writer.write_u8(static_cast<std::uint8_t>(scope));
  if (!status) return status;
  return writer.write_u8(0);
}

// Reads and validates the prelude; returns the scope on success.
Status service_preamble_read(ByteReader& reader, const std::uint8_t subtype,
                             GatewayScope& scope) noexcept {
  std::uint8_t version = 0;
  std::uint8_t found_subtype = 0;
  std::uint8_t raw_scope = 0;
  std::uint8_t flags = 0;
  Status status = reader.read_u8(version);
  if (!status) return status;
  status = reader.read_u8(found_subtype);
  if (!status) return status;
  status = reader.read_u8(raw_scope);
  if (!status) return status;
  status = reader.read_u8(flags);
  if (!status) return status;
  if (version != kServicePayloadVersion || found_subtype != subtype || flags != 0 ||
      !gateway_scope_valid(raw_scope)) {
    return reject();
  }
  scope = static_cast<GatewayScope>(raw_scope);
  return Status::success();
}

// The host-digest rule (§5.3): scope 1 (GATEWAY_SDK_RAM) carries an all-zero
// digest; scope 2 (HOST_RECEIVE_RAM) requires the authenticated principal's
// nonzero SHA-256 digest — an any-host wildcard is forbidden.
Status host_digest_scope_check(const GatewayScope scope, const ByteView digest) noexcept {
  if (scope == GatewayScope::GatewaySdkRam) {
    return all_zero(digest) ? Status::success() : reject();
  }
  return any_nonzero(digest) ? Status::success() : reject();
}

Status control_preamble_read(ByteReader& reader, const std::uint8_t subtype) noexcept {
  std::uint8_t version = 0;
  std::uint8_t found_subtype = 0;
  Status status = reader.read_u8(version);
  if (!status) return status;
  status = reader.read_u8(found_subtype);
  if (!status) return status;
  if (version != kControlPayloadVersion || found_subtype != subtype) {
    return reject();
  }
  return Status::success();
}

// Expected value length for a TLV field type; SIZE_MAX marks "reject".
constexpr std::size_t tlv_value_length(const std::uint8_t type,
                                       const std::uint16_t declared) noexcept {
  switch (type) {
    case 1:  // bool
      return declared == 1 ? 1 : static_cast<std::size_t>(-1);
    case 2:  // u8
      return declared == 1 ? 1 : static_cast<std::size_t>(-1);
    case 3:  // u32
      return declared == 4 ? 4 : static_cast<std::size_t>(-1);
    case 4:  // bytes
      return declared <= kConfigFieldValueMax ? declared : static_cast<std::size_t>(-1);
    default:
      return static_cast<std::size_t>(-1);
  }
}

}  // namespace

// --- RLD1 body v2 -------------------------------------------------------------

Status scope_discover_body_encode(const Rld1DiscoverBodyV2& body,
                                  EncodedScopeBody& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kScopeBodyVersion));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(body.scope_class)));
  RL_WRITE(writer.write_u8(kScopeScheme));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u32(body.generation));
  RL_WRITE(writer.write_bytes(ByteView{body.tag.data(), body.tag.size()}));
#undef RL_WRITE
  if (writer.size() != kRld1DiscoverBodyV2Size) {
    return Status::error(StatusCode::InternalError, "discover v2 body size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status scope_discover_body_decode(const ByteView encoded, Rld1DiscoverBodyV2& out) noexcept {
  if (encoded.size != kRld1DiscoverBodyV2Size) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint8_t version = 0;
  std::uint8_t scope_class = 0;
  std::uint8_t scheme = 0;
  std::uint8_t flags = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u8(version));
  RL_READ(reader.read_u8(scope_class));
  RL_READ(reader.read_u8(scheme));
  RL_READ(reader.read_u8(flags));
  RL_READ(reader.read_u32(out.generation));
  RL_READ(reader.read_bytes(MutableByteView{out.tag.data(), out.tag.size()}));
#undef RL_READ
  if (version != kScopeBodyVersion || scheme != kScopeScheme || flags != 0 ||
      !scope_class_valid(scope_class)) {
    return reject();
  }
  out.scope_class = static_cast<ScopeClass>(scope_class);
  return Status::success();
}

Status scope_offer_body_encode(const Rld1OfferBodyV2& body, EncodedScopeBody& out) noexcept {
  if (all_zero(ByteView{body.cookie.data(), body.cookie.size()}) ||
      all_zero(ByteView{body.responder_nonce.data(), body.responder_nonce.size()})) {
    return invalid("offer v2 cookie/responder nonce must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kScopeBodyVersion));
  RL_WRITE(writer.write_u8(body.density));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(ByteView{body.cookie.data(), body.cookie.size()}));
  RL_WRITE(writer.write_bytes(
      ByteView{body.responder_nonce.data(), body.responder_nonce.size()}));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(body.scope_class)));
  RL_WRITE(writer.write_u8(kScopeScheme));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_u32(body.generation));
  RL_WRITE(writer.write_bytes(ByteView{body.tag.data(), body.tag.size()}));
#undef RL_WRITE
  if (writer.size() != kRld1OfferBodyV2Size) {
    return Status::error(StatusCode::InternalError, "offer v2 body size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status scope_offer_body_decode(const ByteView encoded, Rld1OfferBodyV2& out) noexcept {
  if (encoded.size != kRld1OfferBodyV2Size) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint8_t version = 0;
  std::uint8_t scope_class = 0;
  std::uint8_t scheme = 0;
  std::uint16_t reserved = 0;
  std::uint16_t flags = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u8(version));
  RL_READ(reader.read_u8(out.density));
  RL_READ(reader.read_u16(reserved));
  RL_READ(reader.read_bytes(MutableByteView{out.cookie.data(), out.cookie.size()}));
  RL_READ(reader.read_bytes(
      MutableByteView{out.responder_nonce.data(), out.responder_nonce.size()}));
  RL_READ(reader.read_u8(scope_class));
  RL_READ(reader.read_u8(scheme));
  RL_READ(reader.read_u16(flags));
  RL_READ(reader.read_u32(out.generation));
  RL_READ(reader.read_bytes(MutableByteView{out.tag.data(), out.tag.size()}));
#undef RL_READ
  if (version != kScopeBodyVersion || scheme != kScopeScheme || reserved != 0 ||
      flags != 0 || !scope_class_valid(scope_class) ||
      all_zero(ByteView{out.cookie.data(), out.cookie.size()}) ||
      all_zero(ByteView{out.responder_nonce.data(), out.responder_nonce.size()})) {
    return reject();
  }
  out.scope_class = static_cast<ScopeClass>(scope_class);
  return Status::success();
}

Status scope_binding_encode(const ScopeBindingInput& input,
                            std::array<std::uint8_t, kScopeBindingSize>& out) noexcept {
  std::size_t offset = 0;
  out.fill(0);
  out[offset++] = static_cast<std::uint8_t>(input.scope_class);
  out[offset++] = static_cast<std::uint8_t>(input.generation >> 24);
  out[offset++] = static_cast<std::uint8_t>(input.generation >> 16);
  out[offset++] = static_cast<std::uint8_t>(input.generation >> 8);
  out[offset++] = static_cast<std::uint8_t>(input.generation);
  out[offset++] = kScopeScheme;
  out[offset++] = input.scoped;
  std::memcpy(out.data() + offset, input.discover_digest.data(), input.discover_digest.size());
  offset += input.discover_digest.size();
  std::memcpy(out.data() + offset, input.offer_digest.data(), input.offer_digest.size());
  offset += input.offer_digest.size();
  if (offset != kScopeBindingSize) {
    return Status::error(StatusCode::InternalError, "scope binding size mismatch");
  }
  return Status::success();
}

Status scope_discover_mac_input(const NetworkId network, const MacAddress requester,
                                const MacAddress destination, const ByteView rld1_header,
                                const ByteView body_prefix,
                                ByteBuffer<kScopeDiscoverMacInputSize>& out) noexcept {
  if (rld1_header.size != 44 || body_prefix.size != 8) {
    return invalid("discover MAC input needs the 44B header and 8B body prefix");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>(kScopeDiscoverDomain),
               sizeof(kScopeDiscoverDomain)}));
  RL_WRITE(writer.write_u64(network));
  RL_WRITE(writer.write_bytes(ByteView{requester.data(), requester.size()}));
  RL_WRITE(writer.write_bytes(ByteView{destination.data(), destination.size()}));
  RL_WRITE(writer.write_bytes(rld1_header));
  RL_WRITE(writer.write_bytes(body_prefix));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status scope_offer_mac_input(const NetworkId network, const MacAddress requester,
                             const MacAddress responder, const ByteView discover_digest,
                             const ByteView rld1_header, const ByteView body_prefix,
                             ByteBuffer<kScopeOfferMacInputSize>& out) noexcept {
  if (discover_digest.size != 32 || rld1_header.size != 44 || body_prefix.size != 44) {
    return invalid("offer MAC input needs digest32/header44/prefix44");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>(kScopeOfferDomain),
               sizeof(kScopeOfferDomain)}));
  RL_WRITE(writer.write_u64(network));
  RL_WRITE(writer.write_bytes(ByteView{requester.data(), requester.size()}));
  RL_WRITE(writer.write_bytes(ByteView{responder.data(), responder.size()}));
  RL_WRITE(writer.write_bytes(discover_digest));
  RL_WRITE(writer.write_bytes(rld1_header));
  RL_WRITE(writer.write_bytes(body_prefix));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

// --- Service=21 payloads --------------------------------------------------------

Status service_query_encode(const ServiceQuery& payload, EncodedServicePayload& out) noexcept {
  if (all_zero(ByteView{payload.nonce.data(), payload.nonce.size()})) {
    return invalid("service query nonce must be nonzero");
  }
  const Status digest =
      host_digest_scope_check(payload.scope,
                              ByteView{payload.expected_host_digest.data(),
                                       payload.expected_host_digest.size()});
  if (!digest) return invalid("service query host digest violates scope rule");
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(service_preamble_write(writer, static_cast<std::uint8_t>(ServiceSubtype::Query),
                                  payload.scope));
  RL_WRITE(writer.write_bytes(ByteView{payload.nonce.data(), payload.nonce.size()}));
  RL_WRITE(writer.write_bytes(ByteView{payload.expected_host_digest.data(),
                                     payload.expected_host_digest.size()}));
#undef RL_WRITE
  if (writer.size() != kServiceQuerySize) {
    return Status::error(StatusCode::InternalError, "service query size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status service_query_decode(const ByteView encoded, ServiceQuery& out) noexcept {
  if (encoded.size != kServiceQuerySize) return reject();
  ByteReader reader(encoded);
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(service_preamble_read(reader, static_cast<std::uint8_t>(ServiceSubtype::Query),
                                out.scope));
  RL_READ(reader.read_bytes(MutableByteView{out.nonce.data(), out.nonce.size()}));
  RL_READ(reader.read_bytes(MutableByteView{out.expected_host_digest.data(),
                                            out.expected_host_digest.size()}));
#undef RL_READ
  if (all_zero(ByteView{out.nonce.data(), out.nonce.size()})) return reject();
  return host_digest_scope_check(out.scope, ByteView{out.expected_host_digest.data(),
                                                     out.expected_host_digest.size()});
}

Status service_descriptor_encode(const ServiceDescriptor& payload,
                                 EncodedServicePayload& out) noexcept {
  if (all_zero(ByteView{payload.echo_nonce.data(), payload.echo_nonce.size()}) ||
      all_zero(ByteView{payload.token.data(), payload.token.size()}) ||
      payload.gateway_boot == 0) {
    return invalid("service descriptor nonce/token/boot must be nonzero");
  }
  if (payload.max_payload > kGatewayPayloadMax) {
    return invalid("service descriptor max_payload exceeds registry bound");
  }
  const Status digest =
      host_digest_scope_check(payload.scope, ByteView{payload.host_digest.data(),
                                                      payload.host_digest.size()});
  if (!digest) return invalid("service descriptor host digest violates scope rule");
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(service_preamble_write(writer,
                                  static_cast<std::uint8_t>(ServiceSubtype::Descriptor),
                                  payload.scope));
  RL_WRITE(writer.write_bytes(ByteView{payload.echo_nonce.data(), payload.echo_nonce.size()}));
  RL_WRITE(writer.write_bytes(ByteView{payload.token.data(), payload.token.size()}));
  RL_WRITE(writer.write_u64(payload.gateway_boot));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.host_digest.data(), payload.host_digest.size()}));
  RL_WRITE(writer.write_u32(payload.capabilities));
  RL_WRITE(writer.write_u16(payload.max_payload));
  RL_WRITE(writer.write_u32(payload.lease_ms));
#undef RL_WRITE
  if (writer.size() != kServiceDescriptorSize) {
    return Status::error(StatusCode::InternalError, "service descriptor size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status service_descriptor_decode(const ByteView encoded, ServiceDescriptor& out) noexcept {
  if (encoded.size != kServiceDescriptorSize) return reject();
  ByteReader reader(encoded);
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(service_preamble_read(reader,
                                static_cast<std::uint8_t>(ServiceSubtype::Descriptor),
                                out.scope));
  RL_READ(reader.read_bytes(MutableByteView{out.echo_nonce.data(), out.echo_nonce.size()}));
  RL_READ(reader.read_bytes(MutableByteView{out.token.data(), out.token.size()}));
  RL_READ(reader.read_u64(out.gateway_boot));
  RL_READ(reader.read_bytes(MutableByteView{out.host_digest.data(), out.host_digest.size()}));
  RL_READ(reader.read_u32(out.capabilities));
  RL_READ(reader.read_u16(out.max_payload));
  RL_READ(reader.read_u32(out.lease_ms));
#undef RL_READ
  if (all_zero(ByteView{out.echo_nonce.data(), out.echo_nonce.size()}) ||
      all_zero(ByteView{out.token.data(), out.token.size()}) ||
      out.gateway_boot == 0 || out.max_payload > kGatewayPayloadMax) {
    return reject();
  }
  return host_digest_scope_check(out.scope,
                                 ByteView{out.host_digest.data(), out.host_digest.size()});
}

Status service_submit_encode(const ServiceSubmit& payload, EncodedServicePayload& out) noexcept {
  if (all_zero(ByteView{payload.token.data(), payload.token.size()}) ||
      payload.gateway_boot == 0) {
        return invalid("service submit token/boot must be nonzero");
  }
  if (payload.payload_size > kGatewayPayloadMax) {
    return invalid("service submit payload exceeds 96 bytes");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(service_preamble_write(writer, static_cast<std::uint8_t>(ServiceSubtype::Submit),
                                  payload.scope));
  RL_WRITE(writer.write_bytes(ByteView{payload.token.data(), payload.token.size()}));
  RL_WRITE(writer.write_u64(payload.gateway_boot));
  RL_WRITE(writer.write_u16(payload.payload_size));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(ByteView{payload.payload.data(), payload.payload_size}));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status service_submit_decode(const ByteView encoded, ServiceSubmit& out) noexcept {
  if (encoded.size < kServiceSubmitHeaderSize ||
      encoded.size > kServiceSubmitHeaderSize + kGatewayPayloadMax) {
    return reject();
  }
  ByteReader reader(encoded);
  Status status;
  std::uint16_t payload_len = 0;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(service_preamble_read(reader, static_cast<std::uint8_t>(ServiceSubtype::Submit),
                                out.scope));
  RL_READ(reader.read_bytes(MutableByteView{out.token.data(), out.token.size()}));
  RL_READ(reader.read_u64(out.gateway_boot));
  RL_READ(reader.read_u16(payload_len));
  RL_READ(reader.read_u16(reserved));
#undef RL_READ
  if (reserved != 0 || payload_len > kGatewayPayloadMax ||
      reader.remaining() != payload_len ||
      all_zero(ByteView{out.token.data(), out.token.size()}) || out.gateway_boot == 0) {
    return reject();
  }
  status = reader.read_bytes(MutableByteView{out.payload.data(), payload_len});
  if (!status) return status;
  out.payload_size = payload_len;
  return Status::success();
}

Status service_outcome_encode(const ServiceOutcome& payload,
                              EncodedServicePayload& out) noexcept {
  const std::uint8_t subtype = static_cast<std::uint8_t>(payload.subtype);
  if (subtype < static_cast<std::uint8_t>(ServiceSubtype::Receipt) ||
      subtype > static_cast<std::uint8_t>(ServiceSubtype::Reject)) {
    return invalid("service outcome subtype must be receipt/pending/reject");
  }
  const std::uint16_t reason = static_cast<std::uint16_t>(payload.reason);
  const bool reason_ok =
      (payload.subtype == ServiceSubtype::Receipt && reason == 0) ||
      (payload.subtype == ServiceSubtype::Pending && reason == 1) ||
      (payload.subtype == ServiceSubtype::Reject && reason >= 2 && reason <= 8);
  if (!reason_ok) {
    return invalid("service outcome reason does not match its subtype");
  }
  // ref_origin is a logical unicast node id: 0 (invalid) and u64::MAX
  // (broadcast) are both reserved, never a real origin.
  if (all_zero(ByteView{payload.token.data(), payload.token.size()}) ||
      payload.gateway_boot == 0 || payload.ref_origin == kInvalidNodeId ||
      payload.ref_origin == kBroadcastNodeId) {
    return invalid("service outcome token/boot/origin must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(service_preamble_write(writer, subtype, payload.scope));
  RL_WRITE(writer.write_bytes(ByteView{payload.token.data(), payload.token.size()}));
  RL_WRITE(writer.write_u64(payload.gateway_boot));
  RL_WRITE(writer.write_u64(payload.ref_origin));
  RL_WRITE(writer.write_u32(payload.ref_session));
  RL_WRITE(writer.write_u64(payload.ref_sequence));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.request_digest.data(), payload.request_digest.size()}));
  RL_WRITE(writer.write_u16(reason));
  RL_WRITE(writer.write_u16(0));
#undef RL_WRITE
  if (writer.size() != kServiceOutcomeSize) {
    return Status::error(StatusCode::InternalError, "service outcome size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status service_outcome_decode(const ByteView encoded, ServiceOutcome& out) noexcept {
  if (encoded.size != kServiceOutcomeSize || encoded.data[0] != kServicePayloadVersion) {
    return reject();
  }
  const std::uint8_t subtype = encoded.data[1];
  if (subtype < static_cast<std::uint8_t>(ServiceSubtype::Receipt) ||
      subtype > static_cast<std::uint8_t>(ServiceSubtype::Reject)) {
    return reject();
  }
  ByteReader reader(ByteView{encoded.data + 2, encoded.size - 2});
  Status status;
  std::uint8_t raw_scope = 0;
  std::uint8_t flags = 0;
  std::uint16_t reason = 0;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  // The subtype byte is already consumed; read scope/flags then the body.
  RL_READ(reader.read_u8(raw_scope));
  RL_READ(reader.read_u8(flags));
  RL_READ(reader.read_bytes(MutableByteView{out.token.data(), out.token.size()}));
  RL_READ(reader.read_u64(out.gateway_boot));
  RL_READ(reader.read_u64(out.ref_origin));
  RL_READ(reader.read_u32(out.ref_session));
  RL_READ(reader.read_u64(out.ref_sequence));
  RL_READ(reader.read_bytes(
      MutableByteView{out.request_digest.data(), out.request_digest.size()}));
  RL_READ(reader.read_u16(reason));
  RL_READ(reader.read_u16(reserved));
#undef RL_READ
  const bool reason_ok =
      (subtype == static_cast<std::uint8_t>(ServiceSubtype::Receipt) && reason == 0) ||
      (subtype == static_cast<std::uint8_t>(ServiceSubtype::Pending) && reason == 1) ||
      (subtype == static_cast<std::uint8_t>(ServiceSubtype::Reject) && reason >= 2 &&
       reason <= 8);
  if (flags != 0 || reserved != 0 || !gateway_scope_valid(raw_scope) || !reason_ok ||
      all_zero(ByteView{out.token.data(), out.token.size()}) || out.gateway_boot == 0 ||
      out.ref_origin == kInvalidNodeId || out.ref_origin == kBroadcastNodeId) {
    return reject();
  }
  out.subtype = static_cast<ServiceSubtype>(subtype);
  out.scope = static_cast<GatewayScope>(raw_scope);
  out.reason = static_cast<ServiceReason>(reason);
  return Status::success();
}

// --- Control=22 payloads --------------------------------------------------------

Status control_challenge_query_encode(const ControlChallengeQuery& payload,
                                      EncodedServicePayload& out) noexcept {
  if (!config_namespace_valid(payload.config_namespace)) {
    return invalid("control namespace is not registered");
  }
  if (all_zero(ByteView{payload.client_nonce.data(), payload.client_nonce.size()})) {
    return invalid("challenge query client nonce must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(1));
  RL_WRITE(writer.write_u16(payload.config_namespace));
  RL_WRITE(writer.write_u16(payload.schema));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.client_nonce.data(), payload.client_nonce.size()}));
#undef RL_WRITE
  if (writer.size() != kControlChallengeQuerySize) {
    return Status::error(StatusCode::InternalError, "challenge query size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status control_challenge_query_decode(const ByteView encoded,
                                      ControlChallengeQuery& out) noexcept {
  if (encoded.size != kControlChallengeQuerySize) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 1));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_u16(out.schema));
  RL_READ(reader.read_u16(reserved));
  RL_READ(reader.read_bytes(
      MutableByteView{out.client_nonce.data(), out.client_nonce.size()}));
#undef RL_READ
  if (reserved != 0 || !config_namespace_valid(out.config_namespace) ||
      all_zero(ByteView{out.client_nonce.data(), out.client_nonce.size()})) {
    return reject();
  }
  return Status::success();
}

Status control_challenge_encode(const ControlChallenge& payload,
                                EncodedServicePayload& out) noexcept {
  if (!config_namespace_valid(payload.config_namespace)) {
    return invalid("control namespace is not registered");
  }
  if (all_zero(ByteView{payload.client_nonce.data(), payload.client_nonce.size()}) ||
      all_zero(ByteView{payload.challenge_nonce.data(), payload.challenge_nonce.size()}) ||
      payload.target_boot == 0) {
    return invalid("challenge nonce/boot fields must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(2));
  RL_WRITE(writer.write_u16(payload.config_namespace));
  RL_WRITE(writer.write_u16(payload.schema));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.client_nonce.data(), payload.client_nonce.size()}));
  RL_WRITE(writer.write_u64(payload.target_boot));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.challenge_nonce.data(), payload.challenge_nonce.size()}));
  RL_WRITE(writer.write_u64(payload.revision));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.active_hash.data(), payload.active_hash.size()}));
  RL_WRITE(writer.write_u32(payload.valid_for_ms));
#undef RL_WRITE
  if (writer.size() != kControlChallengeSize) {
    return Status::error(StatusCode::InternalError, "challenge size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status control_challenge_decode(const ByteView encoded, ControlChallenge& out) noexcept {
  if (encoded.size != kControlChallengeSize) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 2));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_u16(out.schema));
  RL_READ(reader.read_u16(reserved));
  RL_READ(reader.read_bytes(
      MutableByteView{out.client_nonce.data(), out.client_nonce.size()}));
  RL_READ(reader.read_u64(out.target_boot));
  RL_READ(reader.read_bytes(
      MutableByteView{out.challenge_nonce.data(), out.challenge_nonce.size()}));
  RL_READ(reader.read_u64(out.revision));
  RL_READ(reader.read_bytes(
      MutableByteView{out.active_hash.data(), out.active_hash.size()}));
  RL_READ(reader.read_u32(out.valid_for_ms));
#undef RL_READ
  if (reserved != 0 || !config_namespace_valid(out.config_namespace) ||
      all_zero(ByteView{out.client_nonce.data(), out.client_nonce.size()}) ||
      all_zero(ByteView{out.challenge_nonce.data(), out.challenge_nonce.size()}) ||
      out.target_boot == 0) {
    return reject();
  }
  return Status::success();
}

Status control_status_query_encode(const ControlStatusQuery& payload,
                                   EncodedServicePayload& out) noexcept {
  if (!config_namespace_valid(payload.config_namespace)) {
    return invalid("control namespace is not registered");
  }
  if (all_zero(ByteView{payload.operation_id.data(), payload.operation_id.size()})) {
    return invalid("status query operation id must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(3));
  RL_WRITE(writer.write_u16(payload.config_namespace));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.operation_id.data(), payload.operation_id.size()}));
#undef RL_WRITE
  if (writer.size() != kControlStatusQuerySize) {
    return Status::error(StatusCode::InternalError, "status query size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status control_status_query_decode(const ByteView encoded, ControlStatusQuery& out) noexcept {
  if (encoded.size != kControlStatusQuerySize) return reject();
  ByteReader reader(encoded);
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 3));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_bytes(
      MutableByteView{out.operation_id.data(), out.operation_id.size()}));
#undef RL_READ
  if (!config_namespace_valid(out.config_namespace) ||
      all_zero(ByteView{out.operation_id.data(), out.operation_id.size()})) {
    return reject();
  }
  return Status::success();
}

Status control_status_encode(const ControlStatus& payload, EncodedServicePayload& out) noexcept {
  if (!config_namespace_valid(payload.config_namespace)) {
    return invalid("control namespace is not registered");
  }
  if (all_zero(ByteView{payload.operation_id.data(), payload.operation_id.size()})) {
    return invalid("status operation id must be nonzero");
  }
  if (static_cast<std::uint8_t>(payload.phase) >
          static_cast<std::uint8_t>(ConfigPhase::Quarantined) ||
      static_cast<std::uint16_t>(payload.reason) >
          static_cast<std::uint16_t>(ConfigReason::ResultExpired)) {
    return invalid("control status phase/reason out of range");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(4));
  RL_WRITE(writer.write_u16(payload.config_namespace));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.operation_id.data(), payload.operation_id.size()}));
  RL_WRITE(writer.write_u64(payload.decision_revision));
  RL_WRITE(writer.write_u64(payload.active_revision));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(payload.phase)));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u16(static_cast<std::uint16_t>(payload.reason)));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.active_hash.data(), payload.active_hash.size()}));
#undef RL_WRITE
  if (writer.size() != kControlStatusSize) {
    return Status::error(StatusCode::InternalError, "status size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status control_status_decode(const ByteView encoded, ControlStatus& out) noexcept {
  if (encoded.size != kControlStatusSize) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint8_t phase = 0;
  std::uint8_t reserved = 0;
  std::uint16_t reason = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 4));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_bytes(
      MutableByteView{out.operation_id.data(), out.operation_id.size()}));
  RL_READ(reader.read_u64(out.decision_revision));
  RL_READ(reader.read_u64(out.active_revision));
  RL_READ(reader.read_u8(phase));
  RL_READ(reader.read_u8(reserved));
  RL_READ(reader.read_u16(reason));
  RL_READ(reader.read_bytes(
      MutableByteView{out.active_hash.data(), out.active_hash.size()}));
#undef RL_READ
  if (reserved != 0 || !config_namespace_valid(out.config_namespace) ||
      all_zero(ByteView{out.operation_id.data(), out.operation_id.size()}) ||
      phase > static_cast<std::uint8_t>(ConfigPhase::Quarantined) ||
      reason > static_cast<std::uint16_t>(ConfigReason::ResultExpired)) {
    return reject();
  }
  out.phase = static_cast<ConfigPhase>(phase);
  out.reason = static_cast<ConfigReason>(reason);
  return Status::success();
}

Status trust_status_query_encode(const TrustStatusQuery& payload,
                                 EncodedServicePayload& out) noexcept {
  if (all_zero(ByteView{payload.nonce.data(), payload.nonce.size()})) {
    return invalid("trust query nonce must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(5));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.nonce.data(), payload.nonce.size()}));
#undef RL_WRITE
  if (writer.size() != kTrustStatusQuerySize) {
    return Status::error(StatusCode::InternalError, "trust query size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status trust_status_query_decode(const ByteView encoded, TrustStatusQuery& out) noexcept {
  if (encoded.size != kTrustStatusQuerySize) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 5));
  RL_READ(reader.read_u16(reserved));
  RL_READ(reader.read_bytes(
      MutableByteView{out.nonce.data(), out.nonce.size()}));
#undef RL_READ
  if (reserved != 0 ||
      all_zero(ByteView{out.nonce.data(), out.nonce.size()})) {
    return reject();
  }
  return Status::success();
}

Status trust_status_encode(const TrustStatus& payload,
                           EncodedServicePayload& out) noexcept {
  if (all_zero(ByteView{payload.nonce_echo.data(), payload.nonce_echo.size()})) {
    return invalid("trust status nonce echo must be nonzero");
  }
  if ((payload.flags & ~kTrustStatusFlagMask) != 0) {
    return invalid("trust status flags out of range");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(6));
  RL_WRITE(writer.write_u16(0));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.nonce_echo.data(), payload.nonce_echo.size()}));
  RL_WRITE(writer.write_u32(payload.store_epoch));
  RL_WRITE(writer.write_u32(payload.min_authority_generation));
  RL_WRITE(writer.write_u64(payload.network));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.image_fingerprint.data(), payload.image_fingerprint.size()}));
  RL_WRITE(writer.write_u8(payload.anchor_count));
  RL_WRITE(writer.write_u8(payload.key_count));
  RL_WRITE(writer.write_u8(payload.revocation_count));
  RL_WRITE(writer.write_u8(payload.flags));
#undef RL_WRITE
  if (writer.size() != kTrustStatusSize) {
    return Status::error(StatusCode::InternalError, "trust status size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status trust_status_decode(const ByteView encoded, TrustStatus& out) noexcept {
  if (encoded.size != kTrustStatusSize) return reject();
  ByteReader reader(encoded);
  Status status;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 6));
  RL_READ(reader.read_u16(reserved));
  RL_READ(reader.read_bytes(
      MutableByteView{out.nonce_echo.data(), out.nonce_echo.size()}));
  RL_READ(reader.read_u32(out.store_epoch));
  RL_READ(reader.read_u32(out.min_authority_generation));
  RL_READ(reader.read_u64(out.network));
  RL_READ(reader.read_bytes(
      MutableByteView{out.image_fingerprint.data(), out.image_fingerprint.size()}));
  RL_READ(reader.read_u8(out.anchor_count));
  RL_READ(reader.read_u8(out.key_count));
  RL_READ(reader.read_u8(out.revocation_count));
  RL_READ(reader.read_u8(out.flags));
#undef RL_READ
  if (reserved != 0 ||
      all_zero(ByteView{out.nonce_echo.data(), out.nonce_echo.size()}) ||
      (out.flags & ~kTrustStatusFlagMask) != 0) {
    return reject();
  }
  return Status::success();
}

Status recovery_info_query_encode(const RecoveryInfoQuery& payload,
                                  EncodedServicePayload& out) noexcept {
  if (!config_namespace_valid(payload.config_namespace)) {
    return invalid("control namespace is not registered");
  }
  if (all_zero(ByteView{payload.nonce.data(), payload.nonce.size()})) {
    return invalid("recovery query nonce must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(7));
  RL_WRITE(writer.write_u16(payload.config_namespace));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.nonce.data(), payload.nonce.size()}));
#undef RL_WRITE
  if (writer.size() != kRecoveryInfoQuerySize) {
    return Status::error(StatusCode::InternalError, "recovery query size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status recovery_info_query_decode(const ByteView encoded, RecoveryInfoQuery& out) noexcept {
  if (encoded.size != kRecoveryInfoQuerySize) return reject();
  ByteReader reader(encoded);
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 7));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_bytes(
      MutableByteView{out.nonce.data(), out.nonce.size()}));
#undef RL_READ
  if (!config_namespace_valid(out.config_namespace) ||
      all_zero(ByteView{out.nonce.data(), out.nonce.size()})) {
    return reject();
  }
  return Status::success();
}

Status recovery_info_encode(const RecoveryInfo& payload,
                            EncodedServicePayload& out) noexcept {
  if (!config_namespace_valid(payload.config_namespace)) {
    return invalid("control namespace is not registered");
  }
  if (all_zero(ByteView{payload.nonce_echo.data(), payload.nonce_echo.size()})) {
    return invalid("recovery info nonce echo must be nonzero");
  }
  if ((payload.flags & ~kRecoveryInfoFlagMask) != 0) {
    return invalid("recovery info flags out of range");
  }
  if (payload.recovery_version == 0) {
    return invalid("recovery info version must be nonzero");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kControlPayloadVersion));
  RL_WRITE(writer.write_u8(8));
  RL_WRITE(writer.write_u16(payload.config_namespace));
  RL_WRITE(writer.write_u16(payload.schema));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.nonce_echo.data(), payload.nonce_echo.size()}));
  RL_WRITE(writer.write_u64(payload.network));
  RL_WRITE(writer.write_u32(payload.store_floor));
  RL_WRITE(writer.write_u64(payload.decision_floor));
  RL_WRITE(writer.write_u8(payload.flags));
  RL_WRITE(writer.write_u8(payload.recovery_version));
  RL_WRITE(writer.write_u32(payload.profile_bits));
  RL_WRITE(writer.write_bytes(
      ByteView{payload.snapshot_hash.data(), payload.snapshot_hash.size()}));
#undef RL_WRITE
  if (writer.size() != kRecoveryInfoSize) {
    return Status::error(StatusCode::InternalError, "recovery info size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status recovery_info_decode(const ByteView encoded, RecoveryInfo& out) noexcept {
  if (encoded.size != kRecoveryInfoSize) return reject();
  ByteReader reader(encoded);
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(control_preamble_read(reader, 8));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_u16(out.schema));
  RL_READ(reader.read_bytes(
      MutableByteView{out.nonce_echo.data(), out.nonce_echo.size()}));
  RL_READ(reader.read_u64(out.network));
  RL_READ(reader.read_u32(out.store_floor));
  RL_READ(reader.read_u64(out.decision_floor));
  RL_READ(reader.read_u8(out.flags));
  RL_READ(reader.read_u8(out.recovery_version));
  RL_READ(reader.read_u32(out.profile_bits));
  RL_READ(reader.read_bytes(
      MutableByteView{out.snapshot_hash.data(), out.snapshot_hash.size()}));
#undef RL_READ
  if (!config_namespace_valid(out.config_namespace) ||
      all_zero(ByteView{out.nonce_echo.data(), out.nonce_echo.size()}) ||
      (out.flags & ~kRecoveryInfoFlagMask) != 0 ||
      out.recovery_version == 0) {
    return reject();
  }
  return Status::success();
}

// --- RCC1 canonical config command ----------------------------------------------

Status config_command_encode(const ConfigCommand& command,
                             EncodedConfigCommand& out) noexcept {
  if (!config_namespace_valid(command.config_namespace)) {
    return invalid("config namespace is not registered");
  }
  // target/authority are logical unicast node ids: 0 (invalid) and
  // u64::MAX (broadcast) are both reserved and can never be a peer.
  if (command.network == 0 || command.target == kInvalidNodeId ||
      command.target == kBroadcastNodeId || command.authority == kInvalidNodeId ||
      command.authority == kBroadcastNodeId ||
      all_zero(ByteView{command.operation_id.data(), command.operation_id.size()}) ||
      command.target_boot == 0 ||
      all_zero(ByteView{command.challenge_nonce.data(), command.challenge_nonce.size()})) {
    return invalid("config command identity/nonce fields must be nonzero");
  }
  // The u64 axis reserves its top value: next == MAX can never be a
  // decision (nothing could follow it), and the authority sequence shares
  // the same reservation so both counters fail closed at the bound.
  if (command.expected_revision == UINT64_MAX ||
      command.next_revision != command.expected_revision + 1 ||
      command.next_revision == UINT64_MAX ||
      command.authority_sequence == UINT64_MAX) {
    return invalid("config revision must satisfy next = expected + 1");
  }
  if (command.field_count == 0 || command.field_count > kConfigFieldCountMax) {
    return invalid("config field_count out of range");
  }
  std::uint16_t patch_len = 0;
  std::uint16_t previous_id = 0;
  for (std::uint16_t i = 0; i < command.field_count; ++i) {
    const ConfigField& field = command.fields[i];
    const std::size_t value_len =
        tlv_value_length(static_cast<std::uint8_t>(field.type), field.value_size);
    if (value_len == static_cast<std::size_t>(-1)) {
      return invalid("config field type/length invalid");
    }
    if (field.type == ConfigFieldType::Bool && field.value_size == 1 &&
        field.value[0] > 1) {
      return invalid("config bool field must be 0 or 1");
    }
    if (i > 0 && field.field_id <= previous_id) {
      return invalid("config field ids must be strictly ascending");
    }
    previous_id = field.field_id;
    const std::uint32_t field_bytes = 5 + value_len;
    if (static_cast<std::uint32_t>(patch_len) + field_bytes > kConfigPatchMax) {
      return invalid("config patch exceeds 512 bytes");
    }
    patch_len = static_cast<std::uint16_t>(patch_len + field_bytes);
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u32(kRcc1Magic));
  RL_WRITE(writer.write_u8(kRcc1Version));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u16(command.config_namespace));
  RL_WRITE(writer.write_u16(command.schema));
  RL_WRITE(writer.write_u16(command.field_count));
  RL_WRITE(writer.write_u64(command.network));
  RL_WRITE(writer.write_u64(command.target));
  RL_WRITE(writer.write_u64(command.authority));
  RL_WRITE(writer.write_u32(command.authority_generation));
  RL_WRITE(writer.write_u64(command.authority_sequence));
  RL_WRITE(writer.write_bytes(
      ByteView{command.operation_id.data(), command.operation_id.size()}));
  RL_WRITE(writer.write_u64(command.expected_revision));
  RL_WRITE(writer.write_u64(command.next_revision));
  RL_WRITE(writer.write_bytes(
      ByteView{command.base_snapshot_hash.data(), command.base_snapshot_hash.size()}));
  RL_WRITE(writer.write_bytes(
      ByteView{command.next_snapshot_hash.data(), command.next_snapshot_hash.size()}));
  RL_WRITE(writer.write_u64(command.target_boot));
  RL_WRITE(writer.write_bytes(
      ByteView{command.challenge_nonce.data(), command.challenge_nonce.size()}));
  RL_WRITE(writer.write_u32(command.apply_within_ms));
  RL_WRITE(writer.write_u16(patch_len));
  RL_WRITE(writer.write_u16(0));
  for (std::uint16_t i = 0; i < command.field_count; ++i) {
    const ConfigField& field = command.fields[i];
    RL_WRITE(writer.write_u16(field.field_id));
    RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(field.type)));
    RL_WRITE(writer.write_u16(field.value_size));
    RL_WRITE(writer.write_bytes(ByteView{field.value.data(), field.value_size}));
  }
#undef RL_WRITE
  if (writer.size() != kRcc1HeaderSize + patch_len) {
    return Status::error(StatusCode::InternalError, "config command size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status config_command_decode(const ByteView encoded, ConfigCommand& out) noexcept {
  if (encoded.size < kRcc1HeaderSize || encoded.size > kRcc1MaxTotal) {
    return reject();
  }
  ByteReader reader(encoded);
  Status status;
  std::uint32_t magic = 0;
  std::uint8_t version = 0;
  std::uint8_t flags = 0;
  std::uint16_t field_count = 0;
  std::uint16_t patch_len = 0;
  std::uint16_t reserved = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u32(magic));
  RL_READ(reader.read_u8(version));
  RL_READ(reader.read_u8(flags));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_u16(out.schema));
  RL_READ(reader.read_u16(field_count));
  RL_READ(reader.read_u64(out.network));
  RL_READ(reader.read_u64(out.target));
  RL_READ(reader.read_u64(out.authority));
  RL_READ(reader.read_u32(out.authority_generation));
  RL_READ(reader.read_u64(out.authority_sequence));
  RL_READ(reader.read_bytes(
      MutableByteView{out.operation_id.data(), out.operation_id.size()}));
  RL_READ(reader.read_u64(out.expected_revision));
  RL_READ(reader.read_u64(out.next_revision));
  RL_READ(reader.read_bytes(
      MutableByteView{out.base_snapshot_hash.data(), out.base_snapshot_hash.size()}));
  RL_READ(reader.read_bytes(
      MutableByteView{out.next_snapshot_hash.data(), out.next_snapshot_hash.size()}));
  RL_READ(reader.read_u64(out.target_boot));
  RL_READ(reader.read_bytes(
      MutableByteView{out.challenge_nonce.data(), out.challenge_nonce.size()}));
  RL_READ(reader.read_u32(out.apply_within_ms));
  RL_READ(reader.read_u16(patch_len));
  RL_READ(reader.read_u16(reserved));
#undef RL_READ
  if (magic != kRcc1Magic || version != kRcc1Version || flags != 0 || reserved != 0 ||
      !config_namespace_valid(out.config_namespace) ||
      field_count == 0 || field_count > kConfigFieldCountMax ||
      reader.remaining() != patch_len ||
      out.expected_revision == UINT64_MAX ||
      out.next_revision != out.expected_revision + 1 ||
      out.next_revision == UINT64_MAX || out.authority_sequence == UINT64_MAX ||
      out.network == 0 || out.target == kInvalidNodeId ||
      out.target == kBroadcastNodeId || out.authority == kInvalidNodeId ||
      out.authority == kBroadcastNodeId || out.target_boot == 0 ||
      all_zero(ByteView{out.operation_id.data(), out.operation_id.size()}) ||
      all_zero(ByteView{out.challenge_nonce.data(), out.challenge_nonce.size()})) {
    return reject();
  }
  // Sorted TLV patch: strict ascending ids, known types, exact lengths.
  std::uint16_t previous_id = 0;
  for (std::uint16_t i = 0; i < field_count; ++i) {
    ConfigField& field = out.fields[i];
    std::uint8_t type = 0;
    std::uint16_t declared = 0;
    status = reader.read_u16(field.field_id);
    if (!status) return status;
    status = reader.read_u8(type);
    if (!status) return status;
    status = reader.read_u16(declared);
    if (!status) return status;
    const std::size_t value_len = tlv_value_length(type, declared);
    if (value_len == static_cast<std::size_t>(-1) || reader.remaining() < value_len) {
      return reject();
    }
    if (i > 0 && field.field_id <= previous_id) {
      return reject();
    }
    previous_id = field.field_id;
    status = reader.read_bytes(MutableByteView{field.value.data(), value_len});
    if (!status) return status;
    field.value_size = static_cast<std::uint16_t>(value_len);
    field.type = static_cast<ConfigFieldType>(type);
    if (type == static_cast<std::uint8_t>(ConfigFieldType::Bool) && field.value[0] > 1) {
      return reject();
    }
  }
  if (reader.remaining() != 0) return reject();
  out.field_count = field_count;
  return Status::success();
}

Status config_recovery_encode(const ConfigRecoveryCommand& command,
                              EncodedRecoveryCommand& out) noexcept {
  // target/authority are logical unicast node ids (same reservation rule as
  // RCC1); the operation id must be nonzero so dedup can never collide with
  // an unset record.
  if (!config_namespace_valid(command.config_namespace) ||
      command.network == 0 || command.target == kInvalidNodeId ||
      command.target == kBroadcastNodeId || command.authority == kInvalidNodeId ||
      command.authority == kBroadcastNodeId ||
      all_zero(ByteView{command.operation_id.data(), command.operation_id.size()})) {
    return invalid("config recovery identity fields invalid");
  }
  if (command.recovery_class != ConfigRecoveryClass::StoreRecover) {
    return invalid("config recovery class unknown");
  }
  // A store recovery attests a fresh generation (attest 0|1); the
  // authority-generation field is reserved and stays 0. The authority
  // sequence shares the u64 top-value reservation with RCC1.
  if (command.attest > kRcr1AttestReprovision ||
      command.new_store_generation == 0 ||
      command.new_authority_generation != 0 ||
      command.authority_sequence == UINT64_MAX) {
    return invalid("config recovery store fields invalid");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u32(kRcr1Magic));
  RL_WRITE(writer.write_u8(kRcr1Version));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(command.recovery_class)));
  RL_WRITE(writer.write_u8(command.attest));
  RL_WRITE(writer.write_u16(command.config_namespace));
  RL_WRITE(writer.write_u16(command.schema));
  RL_WRITE(writer.write_u64(command.network));
  RL_WRITE(writer.write_u64(command.target));
  RL_WRITE(writer.write_u64(command.authority));
  RL_WRITE(writer.write_u32(command.authority_generation));
  RL_WRITE(writer.write_u64(command.authority_sequence));
  RL_WRITE(writer.write_bytes(
      ByteView{command.operation_id.data(), command.operation_id.size()}));
  RL_WRITE(writer.write_u32(command.new_store_generation));
  RL_WRITE(writer.write_u32(command.new_authority_generation));
  RL_WRITE(writer.write_u32(0));
#undef RL_WRITE
  if (writer.size() != kRcr1Size) {
    return Status::error(StatusCode::InternalError, "config recovery size mismatch");
  }
  out.size = writer.size();
  return Status::success();
}

Status config_recovery_decode(const ByteView encoded,
                              ConfigRecoveryCommand& out) noexcept {
  if (encoded.size != kRcr1Size) {
    return reject();
  }
  ByteReader reader(encoded);
  Status status;
  std::uint32_t magic = 0;
  std::uint32_t reserved = 0;
  std::uint8_t version = 0;
  std::uint8_t flags = 0;
  std::uint8_t recovery_class = 0;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u32(magic));
  RL_READ(reader.read_u8(version));
  RL_READ(reader.read_u8(flags));
  RL_READ(reader.read_u8(recovery_class));
  RL_READ(reader.read_u8(out.attest));
  RL_READ(reader.read_u16(out.config_namespace));
  RL_READ(reader.read_u16(out.schema));
  RL_READ(reader.read_u64(out.network));
  RL_READ(reader.read_u64(out.target));
  RL_READ(reader.read_u64(out.authority));
  RL_READ(reader.read_u32(out.authority_generation));
  RL_READ(reader.read_u64(out.authority_sequence));
  RL_READ(reader.read_bytes(
      MutableByteView{out.operation_id.data(), out.operation_id.size()}));
  RL_READ(reader.read_u32(out.new_store_generation));
  RL_READ(reader.read_u32(out.new_authority_generation));
  RL_READ(reader.read_u32(reserved));
#undef RL_READ
  out.recovery_class = static_cast<ConfigRecoveryClass>(recovery_class);
  if (magic != kRcr1Magic || version != kRcr1Version || flags != 0 ||
      reserved != 0 || reader.remaining() != 0 ||
      out.recovery_class != ConfigRecoveryClass::StoreRecover ||
      !config_namespace_valid(out.config_namespace) ||
      out.network == 0 || out.target == kInvalidNodeId ||
      out.target == kBroadcastNodeId || out.authority == kInvalidNodeId ||
      out.authority == kBroadcastNodeId ||
      all_zero(ByteView{out.operation_id.data(), out.operation_id.size()}) ||
      out.attest > kRcr1AttestReprovision ||
      out.new_store_generation == 0 || out.new_authority_generation != 0 ||
      out.authority_sequence == UINT64_MAX) {
    return reject();
  }
  return Status::success();
}

Status config_snapshot_hash_input(const std::uint16_t config_namespace,
                                  const std::uint16_t schema, const ByteView snapshot_tlv,
                                  ByteBuffer<kConfigSnapshotInputMax>& out) noexcept {
  if (!config_namespace_valid(config_namespace)) {
    return invalid("config namespace is not registered");
  }
  if (snapshot_tlv.size > kConfigSnapshotMax ||
      (snapshot_tlv.size > 0 && snapshot_tlv.data == nullptr)) {
    return invalid("config snapshot exceeds the 512-byte bound");
  }
  out.clear();
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>(kConfigSnapshotDomain),
               sizeof(kConfigSnapshotDomain)}));
  RL_WRITE(writer.write_u16(config_namespace));
  RL_WRITE(writer.write_u16(schema));
  RL_WRITE(writer.write_bytes(snapshot_tlv));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

// --- AppResult=19 bodies (sdk-completion/01-applied-delivery.md §1.2) ---------

namespace {

bool app_result_subtype_valid(const std::uint8_t value) noexcept {
  return value >= static_cast<std::uint8_t>(AppResultSubtype::Result) &&
         value <= static_cast<std::uint8_t>(AppResultSubtype::Status);
}

Status app_result_head_write(const AppResultHead& head, ByteWriter& writer) noexcept {
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kAppResultBodyVersion));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(head.subtype)));
  RL_WRITE(writer.write_u8(head.outcome));
  RL_WRITE(writer.write_u8(0));  // flags
  RL_WRITE(writer.write_u32(head.network));
  RL_WRITE(writer.write_u64(head.original_origin));
  RL_WRITE(writer.write_u32(head.original_session));
  RL_WRITE(writer.write_u64(head.original_sequence));
  RL_WRITE(writer.write_u64(head.original_destination));
  RL_WRITE(writer.write_bytes(ByteView{head.request_digest.data(), head.request_digest.size()}));
#undef RL_WRITE
  return Status::success();
}

// Shared strict checks for the 68B head. `expected_subtype` is verified by the
// caller after this returns; outcome validity is subtype-scoped and also
// checked by the caller.
Status app_result_head_read(ByteReader& reader, AppResultHead& out) noexcept {
  std::uint8_t version = 0;
  std::uint8_t subtype = 0;
  std::uint8_t flags = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return reject(); } while (false)
  RL_READ(reader.read_u8(version));
  RL_READ(reader.read_u8(subtype));
  RL_READ(reader.read_u8(out.outcome));
  RL_READ(reader.read_u8(flags));
  RL_READ(reader.read_u32(out.network));
  RL_READ(reader.read_u64(out.original_origin));
  RL_READ(reader.read_u32(out.original_session));
  RL_READ(reader.read_u64(out.original_sequence));
  RL_READ(reader.read_u64(out.original_destination));
  RL_READ(reader.read_bytes(
      MutableByteView{out.request_digest.data(), out.request_digest.size()}));
#undef RL_READ
  if (version != kAppResultBodyVersion || flags != 0 ||
      !app_result_subtype_valid(subtype) || out.network == 0 ||
      out.original_origin == kInvalidNodeId ||
      out.original_destination == kInvalidNodeId || out.original_sequence == 0) {
    return reject();
  }
  out.subtype = static_cast<AppResultSubtype>(subtype);
  return Status::success();
}

bool app_result_head_encodable(const AppResultHead& head) noexcept {
  return app_result_subtype_valid(static_cast<std::uint8_t>(head.subtype)) &&
         head.network != 0 && head.original_origin != kInvalidNodeId &&
         head.original_destination != kInvalidNodeId && head.original_sequence != 0;
}

}  // namespace

Status app_result_encode(const AppResultBody& body, EncodedServicePayload& out) noexcept {
  if (body.head.subtype != AppResultSubtype::Result ||
      body.head.outcome > static_cast<std::uint8_t>(AppResultOutcome::Failure) ||
      body.data_size > kAppResultDataMax || !app_result_head_encodable(body.head)) {
    return invalid("app_result_encode: invalid field");
  }
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(app_result_head_write(body.head, writer));
  RL_WRITE(writer.write_u32(body.application_code));
  RL_WRITE(writer.write_u16(body.data_size));
  RL_WRITE(writer.write_bytes(ByteView{body.data.data(), body.data_size}));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status app_result_decode(ByteView encoded, AppResultBody& out) noexcept {
  if (encoded.size < kAppResultBodyMinSize || encoded.size > kAppResultBodyMaxSize) {
    return reject();
  }
  ByteReader reader(encoded);
  AppResultHead head;
  if (!app_result_head_read(reader, head)) return reject();
  if (head.subtype != AppResultSubtype::Result ||
      head.outcome > static_cast<std::uint8_t>(AppResultOutcome::Failure)) {
    return reject();
  }
  std::uint32_t code = 0;
  std::uint16_t data_size = 0;
  if (!reader.read_u32(code) || !reader.read_u16(data_size) ||
      data_size > kAppResultDataMax || reader.remaining() != data_size) {
    return reject();
  }
  out.head = head;
  out.application_code = code;
  out.data_size = data_size;
  if (!reader.read_bytes(MutableByteView{out.data.data(), data_size})) {
    return reject();
  }
  return Status::success();
}

Status app_result_query_encode(const AppResultQuery& query, EncodedServicePayload& out) noexcept {
  if (query.head.subtype != AppResultSubtype::Query || query.head.outcome != 0 ||
      query.query_nonce == 0 || !app_result_head_encodable(query.head)) {
    return invalid("app_result_query_encode: invalid field");
  }
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(app_result_head_write(query.head, writer));
  RL_WRITE(writer.write_u64(query.query_nonce));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status app_result_query_decode(ByteView encoded, AppResultQuery& out) noexcept {
  if (encoded.size != kAppResultQuerySize) return reject();
  ByteReader reader(encoded);
  AppResultHead head;
  if (!app_result_head_read(reader, head)) return reject();
  std::uint64_t nonce = 0;
  if (!reader.read_u64(nonce) || head.subtype != AppResultSubtype::Query ||
      head.outcome != 0 || nonce == 0) {
    return reject();
  }
  out.head = head;
  out.query_nonce = nonce;
  return Status::success();
}

Status app_result_ack_encode(const AppResultAck& ack, EncodedServicePayload& out) noexcept {
  if (ack.head.subtype != AppResultSubtype::ResultAck || ack.head.outcome != 0 ||
      !app_result_head_encodable(ack.head)) {
    return invalid("app_result_ack_encode: invalid field");
  }
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(app_result_head_write(ack.head, writer));
  RL_WRITE(writer.write_bytes(ByteView{ack.result_digest.data(), ack.result_digest.size()}));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status app_result_ack_decode(ByteView encoded, AppResultAck& out) noexcept {
  if (encoded.size != kAppResultAckSize) return reject();
  ByteReader reader(encoded);
  AppResultHead head;
  if (!app_result_head_read(reader, head)) return reject();
  if (head.subtype != AppResultSubtype::ResultAck || head.outcome != 0) {
    return reject();
  }
  out.head = head;
  if (!reader.read_bytes(
          MutableByteView{out.result_digest.data(), out.result_digest.size()})) {
    return reject();
  }
  return Status::success();
}

Status app_result_status_encode(const AppResultStatus& status_body,
                                EncodedServicePayload& out) noexcept {
  const auto outcome = status_body.head.outcome;
  if (status_body.head.subtype != AppResultSubtype::Status ||
      outcome < static_cast<std::uint8_t>(AppResultStatusCode::Pending) ||
      outcome > static_cast<std::uint8_t>(AppResultStatusCode::NotRetained) ||
      status_body.query_nonce == 0 || !app_result_head_encodable(status_body.head)) {
    return invalid("app_result_status_encode: invalid field");
  }
  ByteWriter writer(out.writable());
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(app_result_head_write(status_body.head, writer));
  RL_WRITE(writer.write_u64(status_body.query_nonce));
#undef RL_WRITE
  out.size = writer.size();
  return Status::success();
}

Status app_result_status_decode(ByteView encoded, AppResultStatus& out) noexcept {
  if (encoded.size != kAppResultStatusSize) return reject();
  ByteReader reader(encoded);
  AppResultHead head;
  if (!app_result_head_read(reader, head)) return reject();
  std::uint64_t nonce = 0;
  if (!reader.read_u64(nonce) || head.subtype != AppResultSubtype::Status ||
      head.outcome < static_cast<std::uint8_t>(AppResultStatusCode::Pending) ||
      head.outcome > static_cast<std::uint8_t>(AppResultStatusCode::NotRetained) ||
      nonce == 0) {
    return reject();
  }
  out.head = head;
  out.query_nonce = nonce;
  return Status::success();
}

void applied_request_digest(const NetworkId network, const NodeId origin,
                            const NodeId destination, const std::uint32_t session,
                            const std::uint64_t sequence, const DeliveryClass delivery,
                            const std::uint32_t original_lifetime_ms,
                            const ByteView payload,
                            std::array<std::uint8_t, 32>& out) noexcept {
  // 43B of fixed fields then the payload — streaming update avoids a
  // contiguous staging buffer so a 128B payload never needs a second copy.
  Sha256 hash;
  hash.update(ByteView{reinterpret_cast<const std::uint8_t*>("RouteLoom/app-request/v1"), 24});
  const std::uint8_t nul = 0;
  hash.update(ByteView{&nul, 1});
  std::array<std::uint8_t, 43> fixed{};
  ByteWriter writer(MutableByteView{fixed.data(), fixed.size()});
  (void)writer.write_u64(network);
  (void)writer.write_u64(origin);
  (void)writer.write_u64(destination);
  (void)writer.write_u32(session);
  (void)writer.write_u64(sequence);
  (void)writer.write_u8(static_cast<std::uint8_t>(delivery));
  (void)writer.write_u32(original_lifetime_ms);
  (void)writer.write_u16(static_cast<std::uint16_t>(payload.size));
  hash.update(ByteView{fixed.data(), writer.size()});
  hash.update(payload);
  hash.finish(out);
}

void applied_result_digest(const ByteView canonical_result_body,
                           std::array<std::uint8_t, 32>& out) noexcept {
  Sha256 hash;
  hash.update(ByteView{reinterpret_cast<const std::uint8_t*>("RouteLoom/app-result/v1"), 23});
  const std::uint8_t nul = 0;
  hash.update(ByteView{&nul, 1});
  hash.update(canonical_result_body);
  hash.finish(out);
}

}  // namespace routeloom::endpoint
