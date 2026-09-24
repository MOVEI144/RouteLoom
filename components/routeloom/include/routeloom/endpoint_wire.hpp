#pragma once

// Wire codec contract for the scope-gateway-config feature set
// (docs/design/scope-gateway-config/05-wire-api.md §5.2–§5.5 and
// contracts.json). This is the BYTE LAYOUT layer only: no state machines,
// no providers, no dispatch. Downstream phases build the Scope/Gateway/
// Config logic on top of these codecs.
//
// Carriers are unchanged: RLD1 keeps its existing envelope and gains body
// version 2 payloads for Discover/Offer; Service=21 and Control=22 payloads
// ride inside the existing Wire v1 envelope; RCC1 is the canonical command
// carried as the COSE_Sign1 payload (and inside manifest kind 3 objects).
//
// All integers are fixed-width big-endian; reserved bytes are 0. Decoders
// reject wrong versions, wrong lengths, nonzero reserved/flags, zero
// nonce/token/boot/ID fields, duplicate or out-of-order TLV fields and any
// trailing bytes — they never guess at a layout.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::endpoint {

// --- RLD1 body v2: scoped Discover/Offer (§5.2) ------------------------------
// BODY payloads only — they sit inside the existing autonomy::Rld1Envelope,
// they are not new envelope kinds. Legacy bodies (Discover empty, Offer
// 36B/version1) are rejected by these decoders; mode decisions such as
// Optional/Required fallback belong to the discovery logic phase.

constexpr std::uint8_t kScopeBodyVersion = 2;
constexpr std::uint8_t kScopeScheme = 1;

// 02-discovery-scope.md §2.2: the only registered scope classes.
enum class ScopeClass : std::uint8_t {
  Member = 1,
  Commissioning = 2,
};

constexpr bool scope_class_valid(const std::uint8_t value) noexcept {
  return value == static_cast<std::uint8_t>(ScopeClass::Member) ||
         value == static_cast<std::uint8_t>(ScopeClass::Commissioning);
}

// MAC domains and the auth-binding domain (contracts.json scope.*). Each is
// the ASCII string followed by exactly one NUL, as hashed.
inline constexpr char kScopeHintDomain[] = "RouteLoom/DSK/v1/hint";
inline constexpr char kScopeDiscoverDomain[] = "RouteLoom/DSK/v1/discover";
inline constexpr char kScopeOfferDomain[] = "RouteLoom/DSK/v1/offer";
inline constexpr char kScopeBindingDomain[] = "RouteLoom/DSK/v1/auth-binding";
inline constexpr char kConfigSnapshotDomain[] = "RouteLoom/config-snapshot/v1";

// DiscoverV2 body (24B): version u8=2 | class u8 | scheme u8=1 | flags u8=0 |
// generation u32 | tag 16B.
struct Rld1DiscoverBodyV2 {
  ScopeClass scope_class{ScopeClass::Member};
  std::uint32_t generation{0};
  std::array<std::uint8_t, 16> tag{};
};
constexpr std::size_t kRld1DiscoverBodyV2Size = 24;

// OfferV2 body (60B): version u8=2 | density u8 | reserved u16=0 |
// cookie 16B | responder_nonce 16B | class u8 | scheme u8=1 | flags u16=0 |
// generation u32 | tag 16B.
struct Rld1OfferBodyV2 {
  std::uint8_t density{0};
  std::array<std::uint8_t, 16> cookie{};
  std::array<std::uint8_t, 16> responder_nonce{};
  ScopeClass scope_class{ScopeClass::Member};
  std::uint32_t generation{0};
  std::array<std::uint8_t, 16> tag{};
};
constexpr std::size_t kRld1OfferBodyV2Size = 60;

using EncodedScopeBody = ByteBuffer<kRld1OfferBodyV2Size>;

Status scope_discover_body_encode(const Rld1DiscoverBodyV2& body,
                                  EncodedScopeBody& out) noexcept;
Status scope_discover_body_decode(ByteView encoded, Rld1DiscoverBodyV2& out) noexcept;
Status scope_offer_body_encode(const Rld1OfferBodyV2& body, EncodedScopeBody& out) noexcept;
Status scope_offer_body_decode(ByteView encoded, Rld1OfferBodyV2& out) noexcept;

// Canonical MAC-context inputs (02-discovery-scope.md §2.4). These assemble
// the exact byte sequences the scope HMAC and the auth-binding SHA-256 hash
// are computed over — pure layout helpers, the crypto itself lives elsewhere.
//
// scope_binding (71B): class u8 | generation u32 | scheme u8 | scoped u8 |
// discover_digest 32B | offer_digest 32B. The domain prefix is NOT included;
// callers hash domain_binding+NUL || these bytes.
struct ScopeBindingInput {
  ScopeClass scope_class{ScopeClass::Member};  // legacy exchange: all zeros
  std::uint32_t generation{0};                 // legacy: 0
  std::uint8_t scoped{0};                      // 1 scoped, 0 legacy
  std::array<std::uint8_t, 32> discover_digest{};
  std::array<std::uint8_t, 32> offer_digest{};
};
constexpr std::size_t kScopeBindingSize = 71;
Status scope_binding_encode(const ScopeBindingInput& input,
                            std::array<std::uint8_t, kScopeBindingSize>& out) noexcept;

// DISCOVER tag input (§2.4): domain_discover || Network u64 | observed
// requester MAC 6B | broadcast MAC 6B | RLD1 header 44B | body prefix 8B.
// OFFER tag input: domain_offer || Network u64 | requester MAC 6B | observed
// responder MAC 6B | SHA256(discover) 32B | RLD1 header 44B | body prefix 44B.
// The domain string (with trailing NUL) is prepended by the helpers.
constexpr std::size_t kScopeDiscoverMacInputSize =
    sizeof(kScopeDiscoverDomain) + 8 + 6 + 6 + 44 + 8;   // 98
constexpr std::size_t kScopeOfferMacInputSize =
    sizeof(kScopeOfferDomain) + 8 + 6 + 6 + 32 + 44 + 44;  // 163
Status scope_discover_mac_input(NetworkId network, MacAddress requester,
                                MacAddress destination, ByteView rld1_header,
                                ByteView body_prefix,
                                ByteBuffer<kScopeDiscoverMacInputSize>& out) noexcept;
Status scope_offer_mac_input(NetworkId network, MacAddress requester,
                             MacAddress responder, ByteView discover_digest,
                             ByteView rld1_header, ByteView body_prefix,
                             ByteBuffer<kScopeOfferMacInputSize>& out) noexcept;

// --- Service=21 payloads (§5.3) ---------------------------------------------
// All Service payloads start with ver u8=1 | subtype u8 | scope u8 | flags
// u8=0. nonce/token/boot/ID fields are never zero; a scope-1 endpoint carries
// an all-zero host digest while scope-2 requires the authenticated
// principal's SHA-256 digest (any-host is forbidden).

constexpr std::uint8_t kServicePayloadVersion = 1;
constexpr std::size_t kGatewayPayloadMax = 96;

enum class GatewayScope : std::uint8_t {
  GatewaySdkRam = 1,
  HostReceiveRam = 2,
};

constexpr bool gateway_scope_valid(const std::uint8_t value) noexcept {
  return value == static_cast<std::uint8_t>(GatewayScope::GatewaySdkRam) ||
         value == static_cast<std::uint8_t>(GatewayScope::HostReceiveRam);
}

enum class ServiceSubtype : std::uint8_t {
  Query = 1,
  Descriptor = 2,
  Submit = 3,
  Receipt = 4,
  Pending = 5,
  Reject = 6,
};

// Service-local reasons (§5.3) — distinct from the Config table and never
// renumbering existing Status codes. Receipt is only ever reason 0, Pending
// only reason 1; Reject carries 2..8.
enum class ServiceReason : std::uint16_t {
  Ok = 0,
  PendingWait = 1,
  TokenStale = 2,
  HostUnavailable = 3,
  Capacity = 4,
  RoleDenied = 5,
  Unsupported = 6,
  Deadline = 7,
  Conflict = 8,
};

using EncodedServicePayload = ByteBuffer<kMaxApplicationPayload>;

// Query1 (52B): ver/sub1/scope/flags | nonce 16B | expected_host_digest 32B.
struct ServiceQuery {
  GatewayScope scope{GatewayScope::GatewaySdkRam};
  std::array<std::uint8_t, 16> nonce{};
  std::array<std::uint8_t, 32> expected_host_digest{};
};
constexpr std::size_t kServiceQuerySize = 52;
Status service_query_encode(const ServiceQuery& payload, EncodedServicePayload& out) noexcept;
Status service_query_decode(ByteView encoded, ServiceQuery& out) noexcept;

// Descriptor2 (86B): ver/sub2/scope/flags | echo_nonce 16B | token 16B |
// gateway_boot u64 | host_digest 32B | caps u32 | max_payload u16 | lease u32.
struct ServiceDescriptor {
  GatewayScope scope{GatewayScope::GatewaySdkRam};
  std::array<std::uint8_t, 16> echo_nonce{};
  std::array<std::uint8_t, 16> token{};
  std::uint64_t gateway_boot{0};
  std::array<std::uint8_t, 32> host_digest{};
  std::uint32_t capabilities{0};
  std::uint16_t max_payload{0};  // 0..kGatewayPayloadMax
  std::uint32_t lease_ms{0};
};
constexpr std::size_t kServiceDescriptorSize = 86;
Status service_descriptor_encode(const ServiceDescriptor& payload,
                                 EncodedServicePayload& out) noexcept;
Status service_descriptor_decode(ByteView encoded, ServiceDescriptor& out) noexcept;

// Submit3 (32..128B): ver/sub3/scope/flags | token 16B | gateway_boot u64 |
// payload_len u16 | reserved u16=0 | payload 0..96B.
struct ServiceSubmit {
  GatewayScope scope{GatewayScope::GatewaySdkRam};
  std::array<std::uint8_t, 16> token{};
  std::uint64_t gateway_boot{0};
  std::array<std::uint8_t, kGatewayPayloadMax> payload{};
  std::uint16_t payload_size{0};  // 0..96; a 0B payload is a legal empty message
};
constexpr std::size_t kServiceSubmitHeaderSize = 32;
Status service_submit_encode(const ServiceSubmit& payload, EncodedServicePayload& out) noexcept;
Status service_submit_decode(ByteView encoded, ServiceSubmit& out) noexcept;

// Receipt4 / Pending5 / Reject6 (84B shared): ver/sub/scope/flags | token 16B
// | gateway_boot u64 | ref_origin u64 | ref_session u32 | ref_sequence u64 |
// request_digest 32B | reason u16 | reserved u16=0.
struct ServiceOutcome {
  ServiceSubtype subtype{ServiceSubtype::Receipt};  // Receipt/Pending/Reject only
  GatewayScope scope{GatewayScope::GatewaySdkRam};
  std::array<std::uint8_t, 16> token{};
  std::uint64_t gateway_boot{0};
  NodeId ref_origin{kInvalidNodeId};
  std::uint32_t ref_session{0};
  std::uint64_t ref_sequence{0};
  std::array<std::uint8_t, 32> request_digest{};
  ServiceReason reason{ServiceReason::Ok};
};
constexpr std::size_t kServiceOutcomeSize = 84;
Status service_outcome_encode(const ServiceOutcome& payload,
                              EncodedServicePayload& out) noexcept;
Status service_outcome_decode(ByteView encoded, ServiceOutcome& out) noexcept;

// --- Control=22 payloads (§5.5) ---------------------------------------------
// All Control payloads start with ver u8=1 | subtype u8. Namespaces follow
// 04-remote-config.md §4.2: SDK namespace 1 plus app-registered
// 0x8000..0xfffe; every other value is rejected by the codec.

constexpr std::uint8_t kControlPayloadVersion = 1;
constexpr std::uint16_t kConfigNamespaceSdk = 1;
constexpr std::uint16_t kConfigNamespaceAppMin = 0x8000;
constexpr std::uint16_t kConfigNamespaceAppMax = 0xfffe;

constexpr bool config_namespace_valid(const std::uint16_t value) noexcept {
  return value == kConfigNamespaceSdk ||
         (value >= kConfigNamespaceAppMin && value <= kConfigNamespaceAppMax);
}

enum class ConfigPhase : std::uint8_t {
  Idle = 0,
  Prepared = 1,
  Decided = 2,
  ApplyIntent = 3,
  Applying = 4,
  Verifying = 5,
  Active = 6,
  Interrupted = 7,
  Quarantined = 8,
};

// Config-local reason table (§5.5) — details ride in this u16 while the
// coarse C Status maps onto existing names.
enum class ConfigReason : std::uint16_t {
  Ok = 0,
  InProgress = 1,
  StaleRevision = 2,
  BaseHashMismatch = 3,
  InvalidPatch = 4,
  Deadline = 5,
  AuthorityDenied = 6,
  Unsupported = 7,
  Capacity = 8,
  StorageFailure = 9,
  ApplyInterrupted = 10,
  VerifyFailed = 11,
  RecoveryRequired = 12,
  MaintenanceBusy = 13,
  NoChange = 14,
  ResultExpired = 15,
};

// ChallengeQuery1 (24B): ver/sub1 | ns u16 | schema u16 | reserved u16=0 |
// client_nonce 16B.
struct ControlChallengeQuery {
  std::uint16_t config_namespace{0};
  std::uint16_t schema{0};
  std::array<std::uint8_t, 16> client_nonce{};
};
constexpr std::size_t kControlChallengeQuerySize = 24;
Status control_challenge_query_encode(const ControlChallengeQuery& payload,
                                      EncodedServicePayload& out) noexcept;
Status control_challenge_query_decode(ByteView encoded, ControlChallengeQuery& out) noexcept;

// Challenge2 (92B): the ChallengeQuery 24B head with sub2 (client_nonce is the
// echo) | target_boot u64 | challenge_nonce 16B | revision u64 |
// active_hash 32B | valid_for_ms u32.
struct ControlChallenge {
  std::uint16_t config_namespace{0};
  std::uint16_t schema{0};
  std::array<std::uint8_t, 16> client_nonce{};
  std::uint64_t target_boot{0};
  std::array<std::uint8_t, 16> challenge_nonce{};
  std::uint64_t revision{0};
  std::array<std::uint8_t, 32> active_hash{};
  std::uint32_t valid_for_ms{0};
};
constexpr std::size_t kControlChallengeSize = 92;
Status control_challenge_encode(const ControlChallenge& payload,
                                EncodedServicePayload& out) noexcept;
Status control_challenge_decode(ByteView encoded, ControlChallenge& out) noexcept;

// StatusQuery3 (20B): ver/sub3 | ns u16 | opid 16B.
struct ControlStatusQuery {
  std::uint16_t config_namespace{0};
  std::array<std::uint8_t, 16> operation_id{};
};
constexpr std::size_t kControlStatusQuerySize = 20;
Status control_status_query_encode(const ControlStatusQuery& payload,
                                   EncodedServicePayload& out) noexcept;
Status control_status_query_decode(ByteView encoded, ControlStatusQuery& out) noexcept;

// Status4 (72B): ver/sub4 | ns u16 | opid 16B | decision_rev u64 |
// active_rev u64 | phase u8 | reserved u8=0 | reason u16 | active_hash 32B.
struct ControlStatus {
  std::uint16_t config_namespace{0};
  std::array<std::uint8_t, 16> operation_id{};
  std::uint64_t decision_revision{0};
  std::uint64_t active_revision{0};
  ConfigPhase phase{ConfigPhase::Idle};
  ConfigReason reason{ConfigReason::Ok};
  std::array<std::uint8_t, 32> active_hash{};
};
constexpr std::size_t kControlStatusSize = 72;
Status control_status_encode(const ControlStatus& payload, EncodedServicePayload& out) noexcept;
Status control_status_decode(ByteView encoded, ControlStatus& out) noexcept;

// --- RCC1 canonical config command (§5.4) ------------------------------------
// 176B fixed header + sorted TLV patch (max 512B) = max 688B. Carried as the
// COSE_Sign1 payload inside manifest kind 3 objects — this codec covers the
// canonical bytes only, not the COSE wrapper or signature validation.

constexpr std::uint32_t kRcc1Magic = 0x52434331;  // "RCC1"
constexpr std::uint8_t kRcc1Version = 1;
constexpr std::size_t kRcc1HeaderSize = 176;
constexpr std::size_t kConfigPatchMax = 512;
constexpr std::size_t kConfigFieldCountMax = 16;
constexpr std::size_t kConfigFieldValueMax = 96;
constexpr std::size_t kRcc1MaxTotal = kRcc1HeaderSize + kConfigPatchMax;  // 688

enum class ConfigFieldType : std::uint8_t {
  Bool = 1,   // length 1, value 0/1
  U8 = 2,     // length 1
  U32 = 3,    // length 4
  Bytes = 4,  // length 0..96
};

struct ConfigField {
  std::uint16_t field_id{0};
  ConfigFieldType type{ConfigFieldType::U8};
  std::array<std::uint8_t, kConfigFieldValueMax> value{};
  std::uint16_t value_size{0};
};

// Header layout (176B): magic "RCC1" 4 | version u8 | flags u8=0 |
// namespace u16 | schema u16 | field_count u16 | Network u64 | target u64 |
// authority u64 | authority_generation u32 | authority_sequence u64 |
// config_operation_id 16B | expected_revision u64 | next_revision u64 |
// base_snapshot_hash 32B | next_snapshot_hash 32B | target_boot u64 |
// challenge_nonce 16B | apply_within_ms u32 | patch_len u16 | reserved u16=0.
struct ConfigCommand {
  std::uint16_t config_namespace{0};
  std::uint16_t schema{0};
  NetworkId network{0};
  NodeId target{kInvalidNodeId};
  NodeId authority{kInvalidNodeId};
  std::uint32_t authority_generation{0};
  std::uint64_t authority_sequence{0};
  std::array<std::uint8_t, 16> operation_id{};
  std::uint64_t expected_revision{0};
  std::uint64_t next_revision{0};  // must equal expected_revision + 1
  std::array<std::uint8_t, 32> base_snapshot_hash{};
  std::array<std::uint8_t, 32> next_snapshot_hash{};
  std::uint64_t target_boot{0};
  std::array<std::uint8_t, 16> challenge_nonce{};
  std::uint32_t apply_within_ms{0};
  std::array<ConfigField, kConfigFieldCountMax> fields{};
  std::uint16_t field_count{0};  // 1..16; field ids strictly ascending
};

using EncodedConfigCommand = ByteBuffer<kRcc1MaxTotal>;

Status config_command_encode(const ConfigCommand& command,
                             EncodedConfigCommand& out) noexcept;
Status config_command_decode(ByteView encoded, ConfigCommand& out) noexcept;

// --- RCR1 canonical recovery command (04 §4.7, 06 §6.3) ----------------------
// Fixed 76B body carried as the signed payload of a kind-4 recovery object —
// never an RCC1 extension and never a kind-3 permit. Two classes share the
// header: StoreRecover attests a fresh store generation for a quarantined/
// uncertain journal (the signed RECOVER evidence §6.3 requires); the
// AuthorityGeneration countersign installs a newer authority generation on a
// healthy journal so post-disaster permits verify (03-signing trust update).
//
// Header layout (76B): magic "RCR1" 4 | version u8 | flags u8=0 |
// class u8 | attest u8 | namespace u16 | schema u16 | network u64 |
// target u64 | authority u64 | authority_generation u32 (the generation the
// signature verifies under) | authority_sequence u64 | operation_id 16B |
// new_store_generation u32 | new_authority_generation u32 | reserved u32=0.
// Class rules: StoreRecover carries attest 0|1 and a nonzero
// new_store_generation with new_authority_generation == 0;
// AuthorityGeneration carries attest 0, new_store_generation == 0 and a
// nonzero new_authority_generation.

constexpr std::uint32_t kRcr1Magic = 0x52435231;  // "RCR1"
constexpr std::uint8_t kRcr1Version = 1;
constexpr std::size_t kRcr1Size = 76;

enum class ConfigRecoveryClass : std::uint8_t {
  StoreRecover = 1,         // quarantine/uncertain -> fresh store generation
  AuthorityGeneration = 2,  // countersign: install a newer authority generation
};

// `attest` values for ConfigRecoveryClass::StoreRecover — the signed
// attestation recover() requires before fabricating a base when no
// verifiable record survives (04 §4.7).
constexpr std::uint8_t kRcr1AttestAdopt = 0;        // adopt a proven survivor only
constexpr std::uint8_t kRcr1AttestReprovision = 1;  // attested re-provisioning

struct ConfigRecoveryCommand {
  ConfigRecoveryClass recovery_class{ConfigRecoveryClass::StoreRecover};
  std::uint8_t attest{kRcr1AttestAdopt};
  std::uint16_t config_namespace{0};
  std::uint16_t schema{0};
  NetworkId network{0};
  NodeId target{kInvalidNodeId};
  NodeId authority{kInvalidNodeId};
  // The generation the permit's signature verifies under — the journal's
  // currently accepted generation, NOT the generation being installed.
  std::uint32_t authority_generation{0};
  std::uint64_t authority_sequence{0};
  std::array<std::uint8_t, 16> operation_id{};
  std::uint32_t new_store_generation{0};        // StoreRecover only
  std::uint32_t new_authority_generation{0};    // AuthorityGeneration only
};

using EncodedRecoveryCommand = ByteBuffer<kRcr1Size>;

Status config_recovery_encode(const ConfigRecoveryCommand& command,
                              EncodedRecoveryCommand& out) noexcept;
Status config_recovery_decode(ByteView encoded, ConfigRecoveryCommand& out) noexcept;

// Snapshot-hash input (§5.4): domain_snapshot || namespace u16 | schema u16 |
// complete sorted TLV snapshot bytes. Layout helper only — SHA-256 lives in
// the crypto phase.
constexpr std::size_t kConfigSnapshotMax = 512;
constexpr std::size_t kConfigSnapshotInputMax =
    sizeof(kConfigSnapshotDomain) + 2 + 2 + kConfigSnapshotMax;  // 547
Status config_snapshot_hash_input(std::uint16_t config_namespace, std::uint16_t schema,
                                  ByteView snapshot_tlv,
                                  ByteBuffer<kConfigSnapshotInputMax>& out) noexcept;

// --- AppResult=19 bodies (sdk-completion/01-applied-delivery.md §1.2) ---------
// Four subtypes share one 68B head: ver u8=1 | subtype u8 | outcome u8 |
// flags u8=0 | network u32 | original_origin u64 | original_session u32 |
// original_sequence u64 | original_destination u64 | request_digest 32B.
// APP_RESULT frames ride the end-protected routed lane as Reliable management
// traffic; the bodies below are the plaintext of that lane.

constexpr std::uint8_t kAppResultBodyVersion = 1;
constexpr std::size_t kAppResultHeadSize = 68;
constexpr std::size_t kAppResultDataMax = 48;

enum class AppResultSubtype : std::uint8_t {
  Result = 1,
  Query = 2,
  ResultAck = 3,
  Status = 4,
};

// RESULT outcome byte values.
enum class AppResultOutcome : std::uint8_t {
  Success = 0,
  Failure = 1,
};

// STATUS outcome byte values (an answer to a QUERY).
enum class AppResultStatusCode : std::uint8_t {
  Pending = 1,
  Indeterminate = 2,
  Expired = 3,
  NotRetained = 4,
};

// SDK-reserved application_code band. The node generates these refusal
// verdicts itself; an endpoint reply carrying a code inside the band is
// rewritten to InternalError so app bytes can never impersonate the SDK.
constexpr std::uint32_t kAppResultSdkCodeBase = 0xffff0000u;
enum class AppResultRefusal : std::uint32_t {
  InternalError = 0xffff0000u,
  StaleLease = 0xffff0001u,
  NoEndpoint = 0xffff0002u,
  Capacity = 0xffff0003u,
  MalformedRequest = 0xffff0004u,
};

struct AppResultHead {
  AppResultSubtype subtype{AppResultSubtype::Result};
  std::uint8_t outcome{0};  // AppResultOutcome / AppResultStatusCode per subtype
  std::uint32_t network{0};
  NodeId original_origin{kInvalidNodeId};
  std::uint32_t original_session{0};
  std::uint64_t original_sequence{0};
  NodeId original_destination{kInvalidNodeId};
  std::array<std::uint8_t, 32> request_digest{};
};

// RESULT1 (74..122B): head | application_code u32 | result_len u16 |
// result[0..48].
struct AppResultBody {
  AppResultHead head;
  std::uint32_t application_code{0};
  std::array<std::uint8_t, kAppResultDataMax> data{};
  std::uint16_t data_size{0};  // 0..48
};
constexpr std::size_t kAppResultBodyMinSize = kAppResultHeadSize + 6;  // 74
constexpr std::size_t kAppResultBodyMaxSize = kAppResultBodyMinSize + kAppResultDataMax;  // 122
Status app_result_encode(const AppResultBody& body, EncodedServicePayload& out) noexcept;
Status app_result_decode(ByteView encoded, AppResultBody& out) noexcept;

// QUERY2 (76B): head(outcome=0) | query_nonce u64.
struct AppResultQuery {
  AppResultHead head;
  std::uint64_t query_nonce{0};
};
constexpr std::size_t kAppResultQuerySize = kAppResultHeadSize + 8;  // 76
Status app_result_query_encode(const AppResultQuery& query, EncodedServicePayload& out) noexcept;
Status app_result_query_decode(ByteView encoded, AppResultQuery& out) noexcept;

// RESULT_ACK3 (100B): head(outcome=0) | result_digest 32B.
struct AppResultAck {
  AppResultHead head;
  std::array<std::uint8_t, 32> result_digest{};
};
constexpr std::size_t kAppResultAckSize = kAppResultHeadSize + 32;  // 100
Status app_result_ack_encode(const AppResultAck& ack, EncodedServicePayload& out) noexcept;
Status app_result_ack_decode(ByteView encoded, AppResultAck& out) noexcept;

// STATUS4 (76B): head(outcome=AppResultStatusCode) | query_nonce u64 (echo).
struct AppResultStatus {
  AppResultHead head;
  std::uint64_t query_nonce{0};
};
constexpr std::size_t kAppResultStatusSize = kAppResultHeadSize + 8;  // 76
Status app_result_status_encode(const AppResultStatus& status, EncodedServicePayload& out) noexcept;
Status app_result_status_decode(ByteView encoded, AppResultStatus& out) noexcept;

// APPLIED request body shape inside an end-protected DATA frame:
// execution_lease 16B || user payload (0..kAppliedUserPayloadMax).
// Lease (Wire v2): message_session u32 | end_epoch u32 | boot_incarnation u64.
// message_session is never zero (NodeConfig validation), so a computed lease
// is never all-zero and an all-zero lease on the wire is unambiguously "no
// assertion" and refuses.
constexpr std::size_t kAppliedLeaseBytes = 16;
constexpr std::size_t kAppliedUserPayloadMax = kMaxApplicationPayload - kAppliedLeaseBytes;  // 112

// request_digest (§1.2): SHA-256 over
// "RouteLoom/app-request/v1" || NUL || network u64 | origin u64 |
// destination u64 | session u32 | sequence u64 | delivery u8 |
// original_lifetime u32 | payload_len u16 | payload — every end-immutable
// field of the request, so origin and destination compute identical digests.
void applied_request_digest(NetworkId network, NodeId origin, NodeId destination,
                            std::uint32_t session, std::uint64_t sequence,
                            DeliveryClass delivery, std::uint32_t original_lifetime_ms,
                            ByteView payload,
                            std::array<std::uint8_t, 32>& out) noexcept;

// result_digest (§1.2): SHA-256 over "RouteLoom/app-result/v1" || NUL || the
// canonical RESULT body bytes — deterministic encoding lets the destination
// validate a RESULT_ACK against its stored record.
void applied_result_digest(ByteView canonical_result_body,
                           std::array<std::uint8_t, 32>& out) noexcept;

}  // namespace routeloom::endpoint
