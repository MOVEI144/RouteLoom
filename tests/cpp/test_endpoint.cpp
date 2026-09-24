// Scope-gateway-config codec contract tests: the endpoint_wire codecs against
// the shared vectors in protocol/endpoint-golden/ (byte-for-byte encode and
// decode equivalence with the Rust harness in
// host/routeloom-wire/tests/endpoint.rs), plus direct codec round-trips.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "routeloom/endpoint_wire.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
namespace ep = routeloom::endpoint;

#ifndef ROUTELOOM_ENDPOINT_GOLDEN_DIR
#define ROUTELOOM_ENDPOINT_GOLDEN_DIR "protocol/endpoint-golden"
#endif

using Fields = std::map<std::string, std::string>;

// Same flat "key": value subset as the other golden harnesses.
Fields parse_flat_json(const std::string& text) {
  Fields fields;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t key_begin = text.find('"', pos);
    if (key_begin == std::string::npos) break;
    const std::size_t key_end = text.find('"', key_begin + 1);
    if (key_end == std::string::npos) break;
    const std::size_t colon = text.find(':', key_end + 1);
    if (colon == std::string::npos) break;
    std::size_t cursor = colon + 1;
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) ++cursor;
    std::string value;
    if (cursor < text.size() && text[cursor] == '"') {
      const std::size_t value_end = text.find('"', cursor + 1);
      if (value_end == std::string::npos) break;
      value = text.substr(cursor + 1, value_end - cursor - 1);
      pos = value_end + 1;
    } else {
      std::size_t value_end = cursor;
      while (value_end < text.size() &&
             (std::isdigit(static_cast<unsigned char>(text[value_end])) || text[value_end] == '-')) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::uint64_t field_u64(const Fields& fields, const char* key, bool& present) {
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.empty()) {
    present = false;
    return 0;
  }
  return std::strtoull(it->second.c_str(), nullptr, 10);
}

int hex_value(const char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hex_decode(const std::string& hex, std::vector<std::uint8_t>& out) {
  if (hex.size() % 2 != 0) return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int high = hex_value(hex[i]);
    const int low = hex_value(hex[i + 1]);
    if (high < 0 || low < 0) return false;
    out.push_back(static_cast<std::uint8_t>(high * 16 + low));
  }
  return true;
}

std::string read_file(const std::filesystem::path& path, bool& ok) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  ok = input.good() || input.eof();
  return contents.str();
}

std::vector<std::filesystem::path> list_json(const std::filesystem::path& dir) {
  std::vector<std::filesystem::path> files;
  if (!std::filesystem::is_directory(dir)) return files;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() == ".json") files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  return files;
}

ByteView to_view(const std::vector<std::uint8_t>& bytes) {
  return ByteView{bytes.data(), bytes.size()};
}

template <std::size_t N>
bool hex_field(const Fields& fields, const char* key, std::array<std::uint8_t, N>& out) {
  const auto it = fields.find(key);
  if (it == fields.end()) return false;
  std::vector<std::uint8_t> bytes;
  if (!hex_decode(it->second, bytes) || bytes.size() != N) return false;
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return true;
}

bool mac_field(const Fields& fields, const char* key, MacAddress& out) {
  return hex_field(fields, key, out);
}

// The config_command "fields" spec: "id:type:valuehex,id:type:valuehex,...".
bool parse_fields_spec(const std::string& spec, ep::ConfigCommand& command) {
  std::size_t count = 0;
  std::size_t pos = 0;
  while (pos <= spec.size()) {
    const std::size_t comma = spec.find(',', pos);
    const std::string entry = spec.substr(pos, comma == std::string::npos
                                               ? std::string::npos : comma - pos);
    const std::size_t colon1 = entry.find(':');
    const std::size_t colon2 = entry.find(':', colon1 + 1);
    if (colon1 == std::string::npos || colon2 == std::string::npos ||
        count >= ep::kConfigFieldCountMax) {
      return false;
    }
    ep::ConfigField& field = command.fields[count];
    field.field_id = static_cast<std::uint16_t>(
        std::strtoul(entry.substr(0, colon1).c_str(), nullptr, 10));
    field.type = static_cast<ep::ConfigFieldType>(static_cast<std::uint8_t>(
        std::strtoul(entry.substr(colon1 + 1, colon2 - colon1 - 1).c_str(),
                     nullptr, 10)));
    std::vector<std::uint8_t> value;
    if (!hex_decode(entry.substr(colon2 + 1), value) ||
        value.size() > field.value.size()) {
      return false;
    }
    std::copy(value.begin(), value.end(), field.value.begin());
    field.value_size = static_cast<std::uint16_t>(value.size());
    ++count;
    if (comma == std::string::npos) break;
    pos = comma + 1;
  }
  command.field_count = static_cast<std::uint16_t>(count);
  return count > 0;
}

bool encode_vector(const std::string& codec, const Fields& fields,
                   std::vector<std::uint8_t>& out) {
  bool present = true;
  const auto at = [&](const char* key) { return field_u64(fields, key, present); };
  if (codec == "scope_discover") {
    ep::Rld1DiscoverBodyV2 body{};
    body.scope_class = static_cast<ep::ScopeClass>(at("scope_class"));
    body.generation = static_cast<std::uint32_t>(at("generation"));
    if (!hex_field(fields, "tag_hex", body.tag)) return false;
    ep::EncodedScopeBody enc{};
    if (!ep::scope_discover_body_encode(body, enc) || !present) return false;
    out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    return true;
  }
  if (codec == "scope_offer") {
    ep::Rld1OfferBodyV2 body{};
    body.density = static_cast<std::uint8_t>(at("density"));
    body.scope_class = static_cast<ep::ScopeClass>(at("scope_class"));
    body.generation = static_cast<std::uint32_t>(at("generation"));
    if (!hex_field(fields, "cookie_hex", body.cookie) ||
        !hex_field(fields, "responder_nonce_hex", body.responder_nonce) ||
        !hex_field(fields, "tag_hex", body.tag)) return false;
    ep::EncodedScopeBody enc{};
    if (!ep::scope_offer_body_encode(body, enc) || !present) return false;
    out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    return true;
  }
  if (codec == "scope_binding") {
    ep::ScopeBindingInput input{};
    input.scope_class = static_cast<ep::ScopeClass>(at("scope_class"));
    input.generation = static_cast<std::uint32_t>(at("generation"));
    input.scoped = static_cast<std::uint8_t>(at("scoped"));
    if (!hex_field(fields, "discover_digest_hex", input.discover_digest) ||
        !hex_field(fields, "offer_digest_hex", input.offer_digest)) return false;
    std::array<std::uint8_t, ep::kScopeBindingSize> enc{};
    if (!ep::scope_binding_encode(input, enc) || !present) return false;
    out.assign(enc.begin(), enc.end());
    return true;
  }
  if (codec == "scope_discover_mac_input" || codec == "scope_offer_mac_input") {
    const NetworkId network = at("network");
    MacAddress requester{};
    std::vector<std::uint8_t> header;
    std::vector<std::uint8_t> prefix;
    if (!mac_field(fields, "requester_mac_hex", requester) ||
        !hex_decode(fields.at("header_hex"), header) ||
        !hex_decode(fields.at("body_prefix_hex"), prefix) || !present) return false;
    if (codec == "scope_discover_mac_input") {
      MacAddress destination{};
      if (!mac_field(fields, "destination_mac_hex", destination)) return false;
      ByteBuffer<ep::kScopeDiscoverMacInputSize> enc{};
      if (!ep::scope_discover_mac_input(network, requester, destination,
                                        to_view(header), to_view(prefix), enc)) {
        return false;
      }
      out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
      return true;
    }
    MacAddress responder{};
    std::array<std::uint8_t, 32> digest{};
    if (!mac_field(fields, "responder_mac_hex", responder) ||
        !hex_field(fields, "discover_digest_hex", digest)) return false;
    ByteBuffer<ep::kScopeOfferMacInputSize> enc{};
    if (!ep::scope_offer_mac_input(network, requester, responder,
                                   ByteView{digest.data(), digest.size()},
                                   to_view(header), to_view(prefix), enc)) {
      return false;
    }
    out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    return true;
  }
  ep::EncodedServicePayload payload{};
  Status status = Status::error(StatusCode::InternalError, "unset");
  if (codec == "service_query") {
    ep::ServiceQuery p{};
    p.scope = static_cast<ep::GatewayScope>(at("scope"));
    if (!hex_field(fields, "nonce_hex", p.nonce) ||
        !hex_field(fields, "expected_host_digest_hex", p.expected_host_digest)) {
      return false;
    }
    status = ep::service_query_encode(p, payload);
  } else if (codec == "service_descriptor") {
    ep::ServiceDescriptor p{};
    p.scope = static_cast<ep::GatewayScope>(at("scope"));
    p.gateway_boot = at("gateway_boot");
    p.capabilities = static_cast<std::uint32_t>(at("capabilities"));
    p.max_payload = static_cast<std::uint16_t>(at("max_payload"));
    p.lease_ms = static_cast<std::uint32_t>(at("lease_ms"));
    if (!hex_field(fields, "echo_nonce_hex", p.echo_nonce) ||
        !hex_field(fields, "token_hex", p.token) ||
        !hex_field(fields, "host_digest_hex", p.host_digest)) return false;
    status = ep::service_descriptor_encode(p, payload);
  } else if (codec == "service_submit") {
    ep::ServiceSubmit p{};
    p.scope = static_cast<ep::GatewayScope>(at("scope"));
    p.gateway_boot = at("gateway_boot");
    std::vector<std::uint8_t> data;
    if (!hex_field(fields, "token_hex", p.token) ||
        !hex_decode(fields.at("payload_hex"), data) ||
        data.size() > p.payload.size()) return false;
    std::copy(data.begin(), data.end(), p.payload.begin());
    p.payload_size = static_cast<std::uint16_t>(data.size());
    status = ep::service_submit_encode(p, payload);
  } else if (codec == "service_outcome") {
    ep::ServiceOutcome p{};
    p.subtype = static_cast<ep::ServiceSubtype>(at("subtype"));
    p.scope = static_cast<ep::GatewayScope>(at("scope"));
    p.gateway_boot = at("gateway_boot");
    p.ref_origin = at("ref_origin");
    p.ref_session = static_cast<std::uint32_t>(at("ref_session"));
    p.ref_sequence = at("ref_sequence");
    p.reason = static_cast<ep::ServiceReason>(at("reason"));
    if (!hex_field(fields, "token_hex", p.token) ||
        !hex_field(fields, "request_digest_hex", p.request_digest)) return false;
    status = ep::service_outcome_encode(p, payload);
  } else if (codec == "control_challenge_query") {
    ep::ControlChallengeQuery p{};
    p.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    p.schema = static_cast<std::uint16_t>(at("schema"));
    if (!hex_field(fields, "client_nonce_hex", p.client_nonce)) return false;
    status = ep::control_challenge_query_encode(p, payload);
  } else if (codec == "control_challenge") {
    ep::ControlChallenge p{};
    p.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    p.schema = static_cast<std::uint16_t>(at("schema"));
    p.target_boot = at("target_boot");
    p.revision = at("revision");
    p.valid_for_ms = static_cast<std::uint32_t>(at("valid_for_ms"));
    if (!hex_field(fields, "client_nonce_hex", p.client_nonce) ||
        !hex_field(fields, "challenge_nonce_hex", p.challenge_nonce) ||
        !hex_field(fields, "active_hash_hex", p.active_hash)) return false;
    status = ep::control_challenge_encode(p, payload);
  } else if (codec == "control_status_query") {
    ep::ControlStatusQuery p{};
    p.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    if (!hex_field(fields, "operation_id_hex", p.operation_id)) return false;
    status = ep::control_status_query_encode(p, payload);
  } else if (codec == "control_status") {
    ep::ControlStatus p{};
    p.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    p.decision_revision = at("decision_revision");
    p.active_revision = at("active_revision");
    p.phase = static_cast<ep::ConfigPhase>(at("phase"));
    p.reason = static_cast<ep::ConfigReason>(at("reason"));
    if (!hex_field(fields, "operation_id_hex", p.operation_id) ||
        !hex_field(fields, "active_hash_hex", p.active_hash)) return false;
    status = ep::control_status_encode(p, payload);
  } else if (codec == "control_trust_status_query") {
    ep::TrustStatusQuery p{};
    if (!hex_field(fields, "nonce_hex", p.nonce)) return false;
    status = ep::trust_status_query_encode(p, payload);
  } else if (codec == "control_trust_status") {
    ep::TrustStatus p{};
    p.store_epoch = static_cast<std::uint32_t>(at("store_epoch"));
    p.min_authority_generation =
        static_cast<std::uint32_t>(at("min_authority_generation"));
    p.network = at("network");
    p.anchor_count = static_cast<std::uint8_t>(at("anchor_count"));
    p.key_count = static_cast<std::uint8_t>(at("key_count"));
    p.revocation_count = static_cast<std::uint8_t>(at("revocation_count"));
    p.flags = static_cast<std::uint8_t>(at("flags"));
    if (!hex_field(fields, "nonce_echo_hex", p.nonce_echo) ||
        !hex_field(fields, "image_fingerprint_hex", p.image_fingerprint)) {
      return false;
    }
    status = ep::trust_status_encode(p, payload);
  } else if (codec == "control_recovery_info_query") {
    ep::RecoveryInfoQuery p{};
    p.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    if (!hex_field(fields, "nonce_hex", p.nonce)) return false;
    status = ep::recovery_info_query_encode(p, payload);
  } else if (codec == "control_recovery_info") {
    ep::RecoveryInfo p{};
    p.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    p.schema = static_cast<std::uint16_t>(at("schema"));
    p.network = at("network");
    p.store_floor = static_cast<std::uint32_t>(at("store_floor"));
    p.decision_floor = at("decision_floor");
    p.flags = static_cast<std::uint8_t>(at("flags"));
    p.recovery_version = static_cast<std::uint8_t>(at("recovery_version"));
    p.profile_bits = static_cast<std::uint32_t>(at("profile_bits"));
    if (!hex_field(fields, "nonce_echo_hex", p.nonce_echo) ||
        !hex_field(fields, "snapshot_hash_hex", p.snapshot_hash)) {
      return false;
    }
    status = ep::recovery_info_encode(p, payload);
  } else if (codec == "config_command") {
    ep::ConfigCommand command{};
    command.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    command.schema = static_cast<std::uint16_t>(at("schema"));
    command.network = at("network");
    command.target = at("target");
    command.authority = at("authority");
    command.authority_generation =
        static_cast<std::uint32_t>(at("authority_generation"));
    command.authority_sequence = at("authority_sequence");
    command.expected_revision = at("expected_revision");
    command.next_revision = at("next_revision");
    command.target_boot = at("target_boot");
    command.apply_within_ms = static_cast<std::uint32_t>(at("apply_within_ms"));
    const auto fields_it = fields.find("fields");
    if (!hex_field(fields, "operation_id_hex", command.operation_id) ||
        !hex_field(fields, "base_snapshot_hash_hex", command.base_snapshot_hash) ||
        !hex_field(fields, "next_snapshot_hash_hex", command.next_snapshot_hash) ||
        !hex_field(fields, "challenge_nonce_hex", command.challenge_nonce) ||
        fields_it == fields.end() ||
        !parse_fields_spec(fields_it->second, command) || !present) {
      return false;
    }
    ep::EncodedConfigCommand enc{};
    status = ep::config_command_encode(command, enc);
    if (!status) return false;
    out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    return true;
  } else if (codec == "config_recovery") {
    ep::ConfigRecoveryIntent intent{};
    intent.config_namespace = static_cast<std::uint16_t>(at("config_namespace"));
    intent.schema = static_cast<std::uint16_t>(at("schema"));
    intent.network = at("network");
    intent.target = at("target");
    intent.authority = at("authority");
    intent.authority_generation =
        static_cast<std::uint32_t>(at("authority_generation"));
    intent.authority_sequence = at("authority_sequence");
    intent.mode = static_cast<std::uint8_t>(at("mode"));
    intent.new_store_generation =
        static_cast<std::uint32_t>(at("new_store_generation"));
    intent.new_revision = at("new_revision");
    std::vector<std::uint8_t> snapshot;
    if (!hex_field(fields, "operation_id_hex", intent.operation_id) ||
        !hex_field(fields, "snapshot_hash_hex", intent.snapshot_hash) ||
        !hex_decode(fields.at("snapshot_hex"), snapshot) || !present) {
      return false;
    }
    if (snapshot.size() > intent.baseline.bytes.size()) return false;
    intent.baseline.size = snapshot.size();
    if (!snapshot.empty()) {
      std::memcpy(intent.baseline.bytes.data(), snapshot.data(), snapshot.size());
    }
    ep::EncodedRecoveryIntent enc{};
    status = ep::config_recovery_encode(intent, enc);
    if (!status) return false;
    out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    return true;
  } else if (codec == "config_snapshot_input") {
    std::vector<std::uint8_t> snapshot;
    if (!hex_decode(fields.at("snapshot_hex"), snapshot)) return false;
    ByteBuffer<ep::kConfigSnapshotInputMax> enc{};
    status = ep::config_snapshot_hash_input(
        static_cast<std::uint16_t>(at("config_namespace")),
        static_cast<std::uint16_t>(at("schema")), to_view(snapshot), enc);
    if (!status || !present) return false;
    out.assign(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    return true;
  } else {
    return false;
  }
  if (!status || !present) return false;
  out.assign(payload.bytes.begin(), payload.bytes.begin() + payload.size);
  return true;
}

bool decode_and_reencode(const std::string& codec, const std::vector<std::uint8_t>& encoded) {
  if (codec == "scope_discover") {
    ep::Rld1DiscoverBodyV2 body{};
    ep::EncodedScopeBody reenc{};
    return ep::scope_discover_body_decode(to_view(encoded), body).ok() &&
           ep::scope_discover_body_encode(body, reenc).ok() &&
           std::equal(reenc.bytes.begin(), reenc.bytes.begin() + reenc.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "scope_offer") {
    ep::Rld1OfferBodyV2 body{};
    ep::EncodedScopeBody reenc{};
    return ep::scope_offer_body_decode(to_view(encoded), body).ok() &&
           ep::scope_offer_body_encode(body, reenc).ok() &&
           std::equal(reenc.bytes.begin(), reenc.bytes.begin() + reenc.size,
                      encoded.begin(), encoded.end());
  }
  // Encode-only canonical helpers have no decoder to round-trip.
  if (codec == "scope_binding" || codec == "scope_discover_mac_input" ||
      codec == "scope_offer_mac_input" || codec == "config_snapshot_input") {
    return true;
  }
  ep::EncodedServicePayload out{};
  if (codec == "service_query") {
    ep::ServiceQuery p{};
    return ep::service_query_decode(to_view(encoded), p).ok() &&
           ep::service_query_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "service_descriptor") {
    ep::ServiceDescriptor p{};
    return ep::service_descriptor_decode(to_view(encoded), p).ok() &&
           ep::service_descriptor_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "service_submit") {
    ep::ServiceSubmit p{};
    return ep::service_submit_decode(to_view(encoded), p).ok() &&
           ep::service_submit_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "service_outcome") {
    ep::ServiceOutcome p{};
    return ep::service_outcome_decode(to_view(encoded), p).ok() &&
           ep::service_outcome_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_challenge_query") {
    ep::ControlChallengeQuery p{};
    return ep::control_challenge_query_decode(to_view(encoded), p).ok() &&
           ep::control_challenge_query_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_challenge") {
    ep::ControlChallenge p{};
    return ep::control_challenge_decode(to_view(encoded), p).ok() &&
           ep::control_challenge_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_status_query") {
    ep::ControlStatusQuery p{};
    return ep::control_status_query_decode(to_view(encoded), p).ok() &&
           ep::control_status_query_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_status") {
    ep::ControlStatus p{};
    return ep::control_status_decode(to_view(encoded), p).ok() &&
           ep::control_status_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_trust_status_query") {
    ep::TrustStatusQuery p{};
    return ep::trust_status_query_decode(to_view(encoded), p).ok() &&
           ep::trust_status_query_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_trust_status") {
    ep::TrustStatus p{};
    return ep::trust_status_decode(to_view(encoded), p).ok() &&
           ep::trust_status_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_recovery_info_query") {
    ep::RecoveryInfoQuery p{};
    return ep::recovery_info_query_decode(to_view(encoded), p).ok() &&
           ep::recovery_info_query_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "control_recovery_info") {
    ep::RecoveryInfo p{};
    return ep::recovery_info_decode(to_view(encoded), p).ok() &&
           ep::recovery_info_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "config_command") {
    ep::ConfigCommand command{};
    ep::EncodedConfigCommand reenc{};
    return ep::config_command_decode(to_view(encoded), command).ok() &&
           ep::config_command_encode(command, reenc).ok() &&
           std::equal(reenc.bytes.begin(), reenc.bytes.begin() + reenc.size,
                      encoded.begin(), encoded.end());
  }
  if (codec == "config_recovery") {
    ep::ConfigRecoveryIntent intent{};
    ep::EncodedRecoveryIntent reenc{};
    return ep::config_recovery_decode(to_view(encoded), intent).ok() &&
           ep::config_recovery_encode(intent, reenc).ok() &&
           std::equal(reenc.bytes.begin(), reenc.bytes.begin() + reenc.size,
                      encoded.begin(), encoded.end());
  }
  return false;
}

bool decode_expect_error(const std::string& codec, const std::vector<std::uint8_t>& encoded) {
  const ByteView view = to_view(encoded);
  if (codec == "scope_discover") {
    ep::Rld1DiscoverBodyV2 p{};
    return !ep::scope_discover_body_decode(view, p).ok();
  }
  if (codec == "scope_offer") {
    ep::Rld1OfferBodyV2 p{};
    return !ep::scope_offer_body_decode(view, p).ok();
  }
  if (codec == "service_query") {
    ep::ServiceQuery p{};
    return !ep::service_query_decode(view, p).ok();
  }
  if (codec == "service_descriptor") {
    ep::ServiceDescriptor p{};
    return !ep::service_descriptor_decode(view, p).ok();
  }
  if (codec == "service_submit") {
    ep::ServiceSubmit p{};
    return !ep::service_submit_decode(view, p).ok();
  }
  if (codec == "service_outcome") {
    ep::ServiceOutcome p{};
    return !ep::service_outcome_decode(view, p).ok();
  }
  if (codec == "control_challenge_query") {
    ep::ControlChallengeQuery p{};
    return !ep::control_challenge_query_decode(view, p).ok();
  }
  if (codec == "control_challenge") {
    ep::ControlChallenge p{};
    return !ep::control_challenge_decode(view, p).ok();
  }
  if (codec == "control_status_query") {
    ep::ControlStatusQuery p{};
    return !ep::control_status_query_decode(view, p).ok();
  }
  if (codec == "control_status") {
    ep::ControlStatus p{};
    return !ep::control_status_decode(view, p).ok();
  }
  if (codec == "control_trust_status_query") {
    ep::TrustStatusQuery p{};
    return !ep::trust_status_query_decode(view, p).ok();
  }
  if (codec == "control_trust_status") {
    ep::TrustStatus p{};
    return !ep::trust_status_decode(view, p).ok();
  }
  if (codec == "control_recovery_info_query") {
    ep::RecoveryInfoQuery p{};
    return !ep::recovery_info_query_decode(view, p).ok();
  }
  if (codec == "control_recovery_info") {
    ep::RecoveryInfo p{};
    return !ep::recovery_info_decode(view, p).ok();
  }
  if (codec == "config_command") {
    ep::ConfigCommand p{};
    return !ep::config_command_decode(view, p).ok();
  }
  if (codec == "config_recovery") {
    ep::ConfigRecoveryIntent p{};
    return !ep::config_recovery_decode(view, p).ok();
  }
  return false;
}

void test_endpoint_golden() {
  const std::filesystem::path dir(ROUTELOOM_ENDPOINT_GOLDEN_DIR);
  const auto valid_files = list_json(dir / "valid");
  const auto invalid_files = list_json(dir / "invalid");
  CHECK(valid_files.size() >= 15);
  CHECK(invalid_files.size() >= 15);

  for (const auto& path : valid_files) {
    bool ok = false;
    const Fields fields = parse_flat_json(read_file(path, ok));
    CHECK(ok);
    const std::string name = fields.count("name") != 0U ? fields.at("name") : path.filename().string();
    const std::string codec = fields.count("codec") != 0U ? fields.at("codec") : "";
    std::vector<std::uint8_t> expected;
    CHECK(fields.count("encoded_hex") != 0U && hex_decode(fields.at("encoded_hex"), expected));

    std::vector<std::uint8_t> produced;
    if (!encode_vector(codec, fields, produced)) {
      std::fprintf(stderr, "valid vector %s failed to encode\n", name.c_str());
      ++failures;
      continue;
    }
    if (produced != expected) {
      std::fprintf(stderr, "valid vector %s: encode bytes differ\n  produced: ", name.c_str());
      for (const auto b : produced) std::fprintf(stderr, "%02x", b);
      std::fprintf(stderr, "\n  expected: ");
      for (const auto b : expected) std::fprintf(stderr, "%02x", b);
      std::fprintf(stderr, "\n");
      ++failures;
      continue;
    }
    if (!decode_and_reencode(codec, expected)) {
      std::fprintf(stderr, "valid vector %s: decode/re-encode failed\n", name.c_str());
      ++failures;
    }
  }

  for (const auto& path : invalid_files) {
    bool ok = false;
    const Fields fields = parse_flat_json(read_file(path, ok));
    CHECK(ok);
    const std::string name = fields.count("name") != 0U ? fields.at("name") : path.filename().string();
    const std::string codec = fields.count("codec") != 0U ? fields.at("codec") : "";
    std::vector<std::uint8_t> encoded;
    CHECK(fields.count("encoded_hex") != 0U && hex_decode(fields.at("encoded_hex"), encoded));
    if (!decode_expect_error(codec, encoded)) {
      std::fprintf(stderr, "invalid vector %s unexpectedly decoded\n", name.c_str());
      ++failures;
    }
  }
}

// Every valid vector must still reject with one trailing byte appended:
// decoders consume exactly their frame — leftover bytes are a framing
// violation, never ignorable padding.
void test_trailing_byte_rejected() {
  const std::filesystem::path dir(ROUTELOOM_ENDPOINT_GOLDEN_DIR);
  for (const auto& path : list_json(dir / "valid")) {
    bool ok = false;
    const Fields fields = parse_flat_json(read_file(path, ok));
    CHECK(ok);
    const std::string codec = fields.count("codec") != 0U ? fields.at("codec") : "";
    // Encode-only canonical helpers have no decoder to feed.
    if (codec == "scope_binding" || codec == "scope_discover_mac_input" ||
        codec == "scope_offer_mac_input" || codec == "config_snapshot_input") {
      continue;
    }
    std::vector<std::uint8_t> encoded;
    CHECK(fields.count("encoded_hex") != 0U &&
          hex_decode(fields.at("encoded_hex"), encoded));
    encoded.push_back(0x00);
    const std::string name = fields.count("name") != 0U ? fields.at("name")
                                                      : path.filename().string();
    if (!decode_expect_error(codec, encoded)) {
      std::fprintf(stderr, "valid vector %s accepted a trailing 0x00\n",
                   name.c_str());
      ++failures;
    }
  }
}

// Direct codec round-trips covering shapes the vectors do not pin.
void test_codec_roundtrip() {
  ep::Rld1DiscoverBodyV2 discover{};
  discover.scope_class = ep::ScopeClass::Commissioning;
  discover.generation = 42;
  for (std::size_t i = 0; i < discover.tag.size(); ++i) discover.tag[i] = i;
  ep::EncodedScopeBody body{};
  CHECK_OK(ep::scope_discover_body_encode(discover, body));
  CHECK(body.size == ep::kRld1DiscoverBodyV2Size);
  ep::Rld1DiscoverBodyV2 discover_back{};
  CHECK_OK(ep::scope_discover_body_decode(body.view(), discover_back));
  CHECK(discover_back.scope_class == ep::ScopeClass::Commissioning);
  CHECK(discover_back.generation == 42);

  ep::Rld1OfferBodyV2 offer{};
  offer.density = 200;
  for (std::size_t i = 0; i < 16; ++i) {
    offer.cookie[i] = i + 1;
    offer.responder_nonce[i] = i + 17;
  }
  offer.generation = 42;
  CHECK_OK(ep::scope_offer_body_encode(offer, body));
  CHECK(body.size == ep::kRld1OfferBodyV2Size);
  ep::Rld1OfferBodyV2 offer_back{};
  CHECK_OK(ep::scope_offer_body_decode(body.view(), offer_back));
  CHECK(offer_back.density == 200 && offer_back.generation == 42);
  // A zero responder nonce fails at both ends.
  offer.responder_nonce.fill(0);
  CHECK(!ep::scope_offer_body_encode(offer, body));

  ep::EncodedServicePayload payload{};
  ep::ServiceSubmit submit{};
  submit.scope = ep::GatewayScope::HostReceiveRam;
  for (std::size_t i = 0; i < 16; ++i) submit.token[i] = i + 1;
  submit.gateway_boot = 7;
  submit.payload_size = 0;  // legal empty message
  CHECK_OK(ep::service_submit_encode(submit, payload));
  CHECK(payload.size == ep::kServiceSubmitHeaderSize);
  ep::ServiceSubmit submit_back{};
  CHECK_OK(ep::service_submit_decode(payload.view(), submit_back));
  CHECK(submit_back.payload_size == 0);
  submit.payload_size = ep::kGatewayPayloadMax + 1;
  CHECK(!ep::service_submit_encode(submit, payload));

  ep::ConfigCommand command{};
  command.config_namespace = 1;
  command.schema = 1;
  command.network = 1;
  command.target = 0x30;
  command.authority = 0x10;
  command.authority_sequence = 13;
  command.operation_id.fill(0x55);
  command.expected_revision = 7;
  command.next_revision = 8;
  command.target_boot = 9;
  command.challenge_nonce.fill(0x66);
  command.apply_within_ms = 5000;
  command.fields[0].field_id = 1;
  command.fields[0].type = ep::ConfigFieldType::U8;
  command.fields[0].value[0] = 1;
  command.fields[0].value_size = 1;
  command.field_count = 1;
  ep::EncodedConfigCommand rcc{};
  CHECK_OK(ep::config_command_encode(command, rcc));
  CHECK(rcc.size == ep::kRcc1HeaderSize + 6);
  ep::ConfigCommand back{};
  CHECK_OK(ep::config_command_decode(rcc.view(), back));
  CHECK(back.field_count == 1 && back.fields[0].field_id == 1);
  CHECK(back.expected_revision == 7 && back.next_revision == 8);
  // Encode-side contract checks.
  command.next_revision = 9;
  CHECK(!ep::config_command_encode(command, rcc));
  command.next_revision = 8;
  command.fields[0].field_id = 0;
  command.field_count = 2;
  command.fields[1] = command.fields[0];  // duplicate id 0, and not ascending
  CHECK(!ep::config_command_encode(command, rcc));
}

// Reserved node ids (0 = invalid, u64::MAX = broadcast) can never appear in
// a logical node-id field — both directions, encode and decode.
void test_reserved_node_ids() {
  ep::ConfigCommand command{};
  command.config_namespace = 1;
  command.schema = 1;
  command.network = 1;
  command.target = 0x30;
  command.authority = 0x10;
  command.authority_sequence = 1;
  command.operation_id.fill(0x55);
  command.expected_revision = 7;
  command.next_revision = 8;
  command.target_boot = 9;
  command.challenge_nonce.fill(0x66);
  command.apply_within_ms = 5000;
  command.fields[0].field_id = 1;
  command.fields[0].type = ep::ConfigFieldType::U8;
  command.fields[0].value[0] = 1;
  command.fields[0].value_size = 1;
  command.field_count = 1;
  ep::EncodedConfigCommand rcc{};
  CHECK_OK(ep::config_command_encode(command, rcc));

  // Encode side: broadcast is refused the same way node id 0 is.
  const NodeId good_target = command.target;
  command.target = kBroadcastNodeId;
  CHECK(!ep::config_command_encode(command, rcc));
  command.target = good_target;
  command.authority = kBroadcastNodeId;
  CHECK(!ep::config_command_encode(command, rcc));
  command.authority = 0x10;
  CHECK_OK(ep::config_command_encode(command, rcc));

  // Decode side: patch the wire bytes to u64::MAX (target at offset 20,
  // authority at offset 28 in the RCC1 header) — both must reject.
  ep::EncodedConfigCommand forged = rcc;
  std::memset(forged.bytes.data() + 20, 0xFF, 8);
  ep::ConfigCommand back{};
  CHECK(!ep::config_command_decode(forged.view(), back));
  forged = rcc;
  std::memset(forged.bytes.data() + 28, 0xFF, 8);
  CHECK(!ep::config_command_decode(forged.view(), back));

  // Service outcome ref_origin: encode and decode both refuse broadcast.
  ep::ServiceOutcome outcome{};
  outcome.subtype = ep::ServiceSubtype::Reject;
  outcome.scope = ep::GatewayScope::GatewaySdkRam;
  outcome.token.fill(0x11);
  outcome.gateway_boot = 7;
  outcome.ref_origin = 0x30;
  outcome.ref_session = 1;
  outcome.ref_sequence = 2;
  outcome.request_digest.fill(0x22);
  outcome.reason = ep::ServiceReason::Capacity;
  ep::EncodedServicePayload encoded{};
  CHECK_OK(ep::service_outcome_encode(outcome, encoded));
  outcome.ref_origin = kBroadcastNodeId;
  CHECK(!ep::service_outcome_encode(outcome, encoded));
  // ref_origin sits at offset 28 in the outcome layout.
  ep::EncodedServicePayload bad = encoded;
  std::memset(bad.bytes.data() + 28, 0xFF, 8);
  ep::ServiceOutcome out_back{};
  CHECK(!ep::service_outcome_decode(bad.view(), out_back));
}

// RCR2 error-code mapping (the golden vectors assert ok/err only): the
// retired RCR1 wire is Unsupported, truncations are ProtocolError, and
// the encoder refuses unnameable counters and mode/shape mismatches.
void test_recovery_codec() {
  ep::ConfigRecoveryIntent intent{};
  intent.config_namespace = 1;
  intent.schema = 1;
  intent.network = 7;
  intent.target = 0x30;
  intent.authority = 0x10;
  intent.authority_generation = 2;
  intent.authority_sequence = 15;
  intent.operation_id.fill(0x35);
  intent.mode = ep::kRcr2ModeReprovision;
  intent.new_store_generation = 42;
  intent.new_revision = 7;
  const std::uint8_t field[] = {0x00, 0x01, 0x02, 0x00, 0x01, 0x02};
  intent.baseline.size = sizeof(field);
  std::memcpy(intent.baseline.bytes.data(), field, sizeof(field));
  ep::EncodedRecoveryIntent encoded{};
  CHECK_OK(ep::config_recovery_encode(intent, encoded));
  CHECK(encoded.size == ep::kRcr2HeaderSize + sizeof(field));
  ep::ConfigRecoveryIntent back{};
  CHECK_OK(ep::config_recovery_decode(encoded.view(), back));
  CHECK(back.mode == ep::kRcr2ModeReprovision);
  CHECK(back.new_store_generation == 42);
  CHECK(back.new_revision == 7);
  CHECK(back.baseline.size == sizeof(field));

  // The retired 76 B RCR1 body is Unsupported — never parsed, even
  // though it is shorter than the RCR2 header.
  std::array<std::uint8_t, 76> rcr1{};
  rcr1[0] = 'R';
  rcr1[1] = 'C';
  rcr1[2] = 'R';
  rcr1[3] = '1';
  rcr1[4] = 1;
  CHECK(ep::config_recovery_decode(ByteView{rcr1.data(), rcr1.size()}, back).code ==
        StatusCode::Unsupported);
  // Unknown magic/version on an RCR2-sized frame: Unsupported too.
  ep::EncodedRecoveryIntent wrong_magic = encoded;
  wrong_magic.bytes[0] = 'X';
  CHECK(ep::config_recovery_decode(wrong_magic.view(), back).code ==
        StatusCode::Unsupported);
  ep::EncodedRecoveryIntent wrong_version = encoded;
  wrong_version.bytes[4] = 1;
  CHECK(ep::config_recovery_decode(wrong_version.view(), back).code ==
        StatusCode::Unsupported);
  // A truncated RCR2 body (right magic/version) is a framing error.
  CHECK(ep::config_recovery_decode(
            ByteView{encoded.bytes.data(), ep::kRcr2HeaderSize - 1}, back)
            .code == StatusCode::ProtocolError);

  // Encoder refusals: adopt-known with bytes, unnameable counters.
  ep::ConfigRecoveryIntent adopt = intent;
  adopt.mode = ep::kRcr2ModeAdoptKnown;
  CHECK(!ep::config_recovery_encode(adopt, encoded));
  adopt.baseline.size = 0;
  CHECK_OK(ep::config_recovery_encode(adopt, encoded));
  CHECK(encoded.size == ep::kRcr2HeaderSize);
  ep::ConfigRecoveryIntent bad_counters = intent;
  bad_counters.new_store_generation = 0;
  CHECK(!ep::config_recovery_encode(bad_counters, encoded));
  bad_counters.new_store_generation = UINT32_MAX;
  CHECK(!ep::config_recovery_encode(bad_counters, encoded));
  bad_counters.new_store_generation = 42;
  bad_counters.new_revision = 0;
  CHECK(!ep::config_recovery_encode(bad_counters, encoded));
  bad_counters.new_revision = UINT64_MAX;
  CHECK(!ep::config_recovery_encode(bad_counters, encoded));
}

}  // namespace

int main() {
  test_codec_roundtrip();
  test_reserved_node_ids();
  test_recovery_codec();
  test_endpoint_golden();
  test_trailing_byte_rejected();

  if (failures != 0) {
    std::fprintf(stderr, "%d endpoint checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom endpoint codec contract tests passed");
  return 0;
}
