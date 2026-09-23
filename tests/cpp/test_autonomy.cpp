// Autonomous-mesh P0 tests: contract types, the semantics.json-synchronized
// coarse admission matrix, the new payload/RLD1 codecs against the shared
// vectors in protocol/autonomy-golden/, and self-tests for the fake radio /
// entropy fixtures.

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

#include "routeloom/admission.hpp"
#include "routeloom/autonomy.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

#include "test_autonomy.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom::autonomy::EncodedPayload;
using routeloom_test::FakeRadioPort;
using routeloom_test::ScriptedEntropy;

#ifndef ROUTELOOM_AUTONOMY_GOLDEN_DIR
#define ROUTELOOM_AUTONOMY_GOLDEN_DIR "protocol/autonomy-golden"
#endif

// --- Contract types -----------------------------------------------------------

void test_contract_types() {
  // RawRxEnvelope is bounded and self-contained.
  RawRxEnvelope rx{};
  rx.body_size = 7;
  rx.rssi_valid = false;
  CHECK(rx.body.size() == kMaxEspNowBody);
  CHECK(rx.bytes().size == 7);
  CHECK(rx.lane == RxLane::Bootstrap);

  // Distinct id/generation types do not silently convert.
  static_assert(!std::is_convertible<CandidateId, BindingId>::value, "candidate->binding");
  static_assert(!std::is_convertible<CandidateId, NodeId>::value, "candidate->node id");
  static_assert(!std::is_convertible<BindingId, NodeId>::value, "binding->node id");
  static_assert(!std::is_convertible<BindingGeneration, RadioGeneration>::value, "gen mix");
  static_assert(!std::is_convertible<ChannelEpoch, FeedbackSequence>::value, "gen mix");
  static_assert(!std::is_convertible<QueueDelayMs, DriverServiceUs>::value, "unit mix");
  static_assert(!std::is_convertible<EstimatedAirtimeUs, TxPowerQuarterDbm>::value, "unit mix");
  static_assert(!std::is_convertible<RouteMetric, QueueDelayMs>::value, "metric/unit mix");

  // Candidate ids cannot reach Core delivery APIs at all (compile-time).
  static_assert(!std::is_convertible<CandidateId, NodeId>::value, "candidate id to core");

  PeerLease lease{};
  lease.expires_at_ms = 100;
  CHECK(!lease.expired(99));
  CHECK(lease.expired(100));
  lease.refcount = 2;
  lease.purpose = PeerLeasePurpose::AuthExchange;

  // TxIntent: the only recipient arms are a verified binding or a limited
  // bootstrap address — there is no arbitrary-MAC arm for DATA.
  const TxRecipient bound = TxRecipient::for_binding(BindingId{42});
  CHECK(bound.kind == TxRecipient::Kind::VerifiedBinding);
  CHECK(bound.binding == BindingId{42});
  const TxRecipient boot = TxRecipient::for_bootstrap(MacAddress{1, 2, 3, 4, 5, 6}, 7);
  CHECK(boot.kind == TxRecipient::Kind::Bootstrap);
  CHECK(boot.bootstrap.mac[5] == 6);
  TxIntent intent{};
  intent.recipient = bound;
  intent.purpose = TxPurpose::Data;
  CHECK(intent.required_lease == kInvalidBindingId);

  OperationResult result{};
  CHECK(result.token == kInvalidOperationToken);
  CHECK(result.outcome == OperationOutcome::Pending);

  CHECK(autonomy::payload_budget(FrameType::Busy) == 64);
  CHECK(autonomy::payload_budget(FrameType::NeighborProbe) == kMaxApplicationPayload);
  CHECK(autonomy::payload_budget(FrameType::Data) == 0);
  CHECK(autonomy::kRld1HeaderSize + autonomy::kRld1MaxBody == autonomy::kRld1MaxTotal);
}

// --- Status codes --------------------------------------------------------------

void test_status_names() {
  // New reason codes resolve to their protocol names without renumbering.
  CHECK(std::strcmp(status_code_name(StatusCode::Ok), "OK") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::DiscoveryBudgetExhausted),
                    "DISCOVERY_BUDGET_EXHAUSTED") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::AuthRequired), "AUTH_REQUIRED") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::ApprovalRequired), "APPROVAL_REQUIRED") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::BindingConflict), "BINDING_CONFLICT") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::PeerCapacity), "PEER_CAPACITY") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::Congested), "CONGESTED") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::RemoteBusy), "REMOTE_BUSY") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::NoFeasibleAlternative),
                    "NO_FEASIBLE_ALTERNATIVE") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::SurveyRequiresOutagePermission),
                    "SURVEY_REQUIRES_OUTAGE_PERMISSION") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::LegacyParticipant), "LEGACY_PARTICIPANT") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::ClockUncertain), "CLOCK_UNCERTAIN") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::PlanNotCommitted), "PLAN_NOT_COMMITTED") == 0);
  CHECK(std::strcmp(status_code_name(StatusCode::RecoveryRequired), "RECOVERY_REQUIRED") == 0);
  // Existing values keep their numbers: Ok=0, InternalError=22.
  CHECK(static_cast<std::uint16_t>(StatusCode::Ok) == 0);
  CHECK(static_cast<std::uint16_t>(StatusCode::InternalError) == 22);
}

// --- Coarse admission matrix ---------------------------------------------------

constexpr FrameType kAllTypes[] = {
    FrameType::Discover, FrameType::Offer, FrameType::BootstrapAuth,
    FrameType::MembershipResult, FrameType::BootstrapChunk, FrameType::BootstrapReply,
    FrameType::MembershipQuery, FrameType::Data, FrameType::HopAccept,
    FrameType::EndReceipt, FrameType::AppResult, FrameType::Busy, FrameType::Service,
    FrameType::Control, FrameType::TimeSync, FrameType::ChannelNotice,
    FrameType::GroupData, FrameType::GroupReport, FrameType::RouteUpdate, FrameType::RouteWithdraw, FrameType::SeqnoRequest,
    FrameType::RouteRequest, FrameType::NeighborProbe, FrameType::NeighborResult,
    FrameType::Diagnostic, FrameType::ControlObject, FrameType::ObjectChunk,
    FrameType::ObjectAck,
};
static_assert(sizeof(kAllTypes) / sizeof(kAllTypes[0]) == 28, "28 assigned type ids");

// Expected matrix derived from protocol/semantics.json membership_allowlist —
// the normative source. Do not "fix" this table to match the code.
bool semantics_allows(const MembershipState state, const FrameType type) {
  switch (state) {
    case MembershipState::Unprovisioned:
    case MembershipState::Discovering:
      return type == FrameType::Discover || type == FrameType::Offer;
    case MembershipState::Authenticating:
      return type == FrameType::Discover || type == FrameType::Offer ||
             type == FrameType::BootstrapAuth || type == FrameType::BootstrapChunk ||
             type == FrameType::BootstrapReply;
    case MembershipState::AuthorizedPendingCommit:
      return type == FrameType::MembershipQuery || type == FrameType::MembershipResult ||
             type == FrameType::BootstrapChunk || type == FrameType::BootstrapReply;
    case MembershipState::Member:
      // JSON MEMBER = bootstrap set + member_only set = all 28 assigned type
      // ids; `type` here always comes from the kAllTypes list of exactly
      // those ids. Unknown raw ids are checked separately for every state.
      return true;
    case MembershipState::Revoked:
      return false;
  }
  return false;
}

void test_frame_allowed_matrix() {
  constexpr MembershipState kStates[] = {
      MembershipState::Unprovisioned, MembershipState::Discovering,
      MembershipState::Authenticating, MembershipState::AuthorizedPendingCommit,
      MembershipState::Member, MembershipState::Revoked,
  };
  for (const MembershipState state : kStates) {
    for (const FrameType type : kAllTypes) {
      if (frame_allowed(state, type) != semantics_allows(state, type)) {
        std::fprintf(stderr, "frame_allowed mismatch: state=%d type=%d\n",
                     static_cast<int>(state), static_cast<int>(type));
        ++failures;
      }
    }
    // Unknown FrameType ids must be denied for every state — including
    // Member, where the old code let `type != Discover && type != Offer`
    // pass anything.
    for (const std::uint8_t raw : {0, 8, 15, 27, 31, 52, 0xEE, 0xFF}) {
      CHECK(!frame_allowed(state, static_cast<FrameType>(raw)));
    }
  }
  // Out-of-range membership states default-deny.
  for (const std::uint8_t raw : {6, 7, 200, 0xFF}) {
    for (const FrameType type : kAllTypes) {
      CHECK(!frame_allowed(static_cast<MembershipState>(raw), type));
    }
  }
  // The specific corrections vs. the old helper: Member answers discovery and
  // Revoked answers nothing.
  CHECK(frame_allowed(MembershipState::Member, FrameType::Discover));
  CHECK(frame_allowed(MembershipState::Member, FrameType::Offer));
  CHECK(!frame_allowed(MembershipState::Revoked, FrameType::Discover));
  CHECK(frame_allowed(MembershipState::Authenticating, FrameType::BootstrapChunk));
  CHECK(frame_allowed(MembershipState::AuthorizedPendingCommit, FrameType::MembershipQuery));
}

void test_admission_decision() {
  AdmissionContext context{};
  context.local_membership = MembershipState::Authenticating;
  context.carrier = AdmissionCarrier::Rld1;

  // RLD1 carries only kinds {1,2,3,5,6}.
  for (const FrameType type : {FrameType::Discover, FrameType::Offer,
                               FrameType::BootstrapAuth, FrameType::BootstrapChunk,
                               FrameType::BootstrapReply}) {
    const AdmissionDecision d = admission_decision(context, type);
    CHECK(d.verdict == AdmissionVerdict::CoarseAllow);
    CHECK(d.scope == AdmissionScope::Bootstrap);
  }
  for (const FrameType type : {FrameType::MembershipResult, FrameType::MembershipQuery,
                               FrameType::Data, FrameType::Busy,
                               FrameType::RouteUpdate}) {
    const AdmissionDecision d = admission_decision(context, type);
    CHECK(d.verdict == AdmissionVerdict::Denied);
    CHECK(d.reason == StatusCode::ProtocolError);
  }
  // Unknown type id on RLD1 is denied.
  CHECK(admission_decision(context, static_cast<FrameType>(0xEE)).verdict ==
        AdmissionVerdict::Denied);

  // Wire v1 carrier + Member: DATA passes the coarse screen with Member
  // scope (still subject to the full context gate).
  context.carrier = AdmissionCarrier::WireV1;
  context.local_membership = MembershipState::Member;
  const AdmissionDecision data = admission_decision(context, FrameType::Data);
  CHECK(data.verdict == AdmissionVerdict::CoarseAllow);
  CHECK(data.scope == AdmissionScope::Member);
  // And bootstrap types remain Bootstrap-scoped even for a Member.
  CHECK(admission_decision(context, FrameType::Offer).scope == AdmissionScope::Bootstrap);

  // Coarse allowlist denial: pre-member state cannot take member traffic.
  context.local_membership = MembershipState::Authenticating;
  const AdmissionDecision denied = admission_decision(context, FrameType::Data);
  CHECK(denied.verdict == AdmissionVerdict::Denied);
  CHECK(denied.reason == StatusCode::AuthorizationFailed);

  context.local_membership = MembershipState::Revoked;
  CHECK(admission_decision(context, FrameType::Discover).verdict ==
        AdmissionVerdict::Denied);
}

// --- Payload codec round-trips ---------------------------------------------------

void test_payload_roundtrip() {
  EncodedPayload enc{};

  autonomy::BusyPayload busy{};
  busy.subtype = autonomy::BusySubtype::Reject;
  busy.reason = autonomy::BusyReason::QueueFull;
  busy.referenced_type = FrameType::Data;
  busy.referenced_origin = 0xDEAD;
  busy.referenced_session = 3;
  busy.referenced_sequence = 55;
  busy.referenced_round = 1;
  busy.binding_generation = BindingGeneration{7};
  busy.feedback_sequence = FeedbackSequence{9};
  busy.retry_after_ms = 250;
  busy.pressure = 200;
  CHECK_OK(autonomy::busy_encode(busy, enc));
  CHECK(enc.size == autonomy::kBusyPayloadSize);
  autonomy::BusyPayload busy_back{};
  CHECK_OK(autonomy::busy_decode(enc.view(), busy_back));
  CHECK(busy_back.reason == autonomy::BusyReason::QueueFull);
  CHECK(busy_back.referenced_origin == 0xDEAD);
  CHECK(busy_back.binding_generation == BindingGeneration{7});

  autonomy::TimeSyncPayload sync{};
  sync.source = 5;
  sync.sequence = 1;
  sync.reference_ms = 999;
  sync.uncertainty_ms = 20;
  CHECK_OK(autonomy::time_sync_encode(sync, enc));
  autonomy::TimeSyncPayload sync_back{};
  CHECK_OK(autonomy::time_sync_decode(enc.view(), sync_back));
  CHECK(sync_back.reference_ms == 999);

  autonomy::ChannelNoticePayload notice{};
  notice.subject = 8;
  notice.channel_epoch = ChannelEpoch{2};
  notice.starts_in_ms = 50;
  notice.duration_ms = 200;
  notice.reason = autonomy::AbsenceReason::SurveyVisit;
  notice.protected_cut_id = 7;
  CHECK_OK(autonomy::channel_notice_encode(notice, enc));
  autonomy::ChannelNoticePayload notice_back{};
  CHECK_OK(autonomy::channel_notice_decode(enc.view(), notice_back));
  CHECK(notice_back.channel_epoch == ChannelEpoch{2});
  CHECK(notice_back.protected_cut_id == 7);

  autonomy::NeighborProbePayload probe{};
  probe.binding_generation = BindingGeneration{4};
  probe.probe_sequence = 77;
  probe.sent_ms = 1234;
  probe.requested_lease_ms = 30000;
  CHECK_OK(autonomy::neighbor_probe_encode(probe, enc));
  autonomy::NeighborProbePayload probe_back{};
  CHECK_OK(autonomy::neighbor_probe_decode(enc.view(), probe_back));
  CHECK(probe_back.probe_sequence == 77);

  autonomy::NeighborResultPayload nres{};
  nres.binding_generation = BindingGeneration{4};
  nres.probe_sequence = 77;
  nres.result = autonomy::NeighborResultCode::Reachable;
  nres.queue_delay_ms = 12;
  CHECK_OK(autonomy::neighbor_result_encode(nres, enc));
  autonomy::NeighborResultPayload nres_back{};
  CHECK_OK(autonomy::neighbor_result_decode(enc.view(), nres_back));
  CHECK(nres_back.result == autonomy::NeighborResultCode::Reachable);

  autonomy::ControlObjectPayload object{};
  object.kind = autonomy::ControlObjectKind::ChannelPlan;
  object.total_len = 2048;
  for (std::size_t i = 0; i < object.object_hash.size(); ++i) object.object_hash[i] = i;
  CHECK_OK(autonomy::control_object_encode(object, enc));
  autonomy::ControlObjectPayload object_back{};
  CHECK_OK(autonomy::control_object_decode(enc.view(), object_back));
  CHECK(object_back.total_len == 2048);
  // Objects beyond the authenticated limit are refused.
  object.total_len = 2049;
  CHECK(!autonomy::control_object_encode(object, enc));

  autonomy::ObjectChunkPayload chunk{};
  for (std::size_t i = 0; i < chunk.object_hash.size(); ++i) chunk.object_hash[i] = 0xA0 + i;
  chunk.offset = 90;
  chunk.data_size = 90;  // fills the 128-byte payload exactly
  for (std::size_t i = 0; i < chunk.data_size; ++i) chunk.data[i] = i;
  CHECK_OK(autonomy::object_chunk_encode(chunk, enc));
  CHECK(enc.size == kMaxApplicationPayload);
  autonomy::ObjectChunkPayload chunk_back{};
  CHECK_OK(autonomy::object_chunk_decode(enc.view(), chunk_back));
  CHECK(chunk_back.offset == 90 && chunk_back.data_size == 90);
  chunk.offset = 2040;  // 2040 + 90 > 2048 object limit
  CHECK(!autonomy::object_chunk_encode(chunk, enc));

  autonomy::ObjectAckPayload ack{};
  ack.received_len = 512;
  ack.status = autonomy::ObjectAckStatus::Incomplete;
  CHECK_OK(autonomy::object_ack_encode(ack, enc));
  autonomy::ObjectAckPayload ack_back{};
  CHECK_OK(autonomy::object_ack_decode(enc.view(), ack_back));
  CHECK(ack_back.status == autonomy::ObjectAckStatus::Incomplete);

  autonomy::BootstrapAuthBody auth{};
  auth.phase = autonomy::AuthPhase::Confirm;
  auth.step_index = 2;
  auth.body_size = 5;
  std::memcpy(auth.body.data(), "proof", 5);
  CHECK_OK(autonomy::bootstrap_auth_encode(auth, enc));
  autonomy::BootstrapAuthBody auth_back{};
  CHECK_OK(autonomy::bootstrap_auth_decode(enc.view(), auth_back));
  CHECK(auth_back.phase == autonomy::AuthPhase::Confirm);
  CHECK(auth_back.step_index == 2);
  CHECK(auth_back.body_size == 5);
}

void test_rld1_codec() {
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Discover;
  env.network_hint = 0xC0FFEE01;
  env.claimed_node = 0x0102030405060708;
  env.capability_bits = 3;
  for (std::size_t i = 0; i < env.transaction_nonce.size(); ++i) {
    env.transaction_nonce[i] = static_cast<std::uint8_t>(i * 7);
  }
  env.body_size = 9;
  std::memcpy(env.body.data(), "disc-hint", 9);

  autonomy::Rld1Encoded enc{};
  CHECK_OK(autonomy::rld1_encode(env, enc));
  CHECK(enc.size == autonomy::kRld1HeaderSize + 9);
  CHECK(autonomy::rld1_probe(enc.view()));

  autonomy::Rld1Envelope back{};
  CHECK_OK(autonomy::rld1_decode(enc.view(), back));
  CHECK(back.kind == FrameType::Discover);
  CHECK(back.claimed_node == 0x0102030405060708);
  CHECK(back.network_hint == 0xC0FFEE01);
  CHECK(back.body_size == 9);
  CHECK(std::memcmp(back.body.data(), "disc-hint", 9) == 0);
  CHECK(back.transaction_nonce == env.transaction_nonce);

  // A Wire v1 frame must not classify as RLD1 — carrier selection happens
  // once, on the full magic.
  std::uint8_t wire_prefix[4] = {0x52, 0x4C, 0x01, 0x00};
  CHECK(!autonomy::rld1_probe(ByteView{wire_prefix, sizeof(wire_prefix)}));

  // Encode-side validation: forbidden kinds, reserved flags, oversize body.
  env.kind = FrameType::MembershipResult;
  CHECK(autonomy::rld1_encode(env, enc).code == StatusCode::InvalidArgument);
  env.kind = FrameType::MembershipQuery;
  CHECK(!autonomy::rld1_encode(env, enc));
  env.kind = FrameType::Data;
  CHECK(!autonomy::rld1_encode(env, enc));
  env.kind = FrameType::Discover;
  env.flags = 1;
  CHECK(!autonomy::rld1_encode(env, enc));
  env.flags = 0;
  env.body_size = autonomy::kRld1MaxBody + 1;
  CHECK(autonomy::rld1_encode(env, enc).code == StatusCode::NoCapacity);
}

// --- Shared golden vectors ------------------------------------------------------

using Fields = std::map<std::string, std::string>;

// Minimal extractor for the flat "key": value objects used by the golden
// files. Same subset as test_golden.cpp: strings or unsigned integers.
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

// Rebuild the payload for a valid vector from its decoded fields and confirm
// byte-exact encoding; decode() alone returning the fields is covered by the
// per-codec round-trip above plus the re-encode here.
bool encode_vector(const std::string& codec, const Fields& fields,
                   std::vector<std::uint8_t>& out) {
  bool present = true;
  const auto at = [&](const char* key) { return field_u64(fields, key, present); };
  EncodedPayload payload{};
  Status status = Status::error(StatusCode::InternalError, "unset");
  if (codec == "busy") {
    autonomy::BusyPayload p{};
    p.subtype = static_cast<autonomy::BusySubtype>(at("subtype"));
    p.reason = static_cast<autonomy::BusyReason>(at("reason"));
    p.referenced_type = static_cast<FrameType>(at("referenced_type"));
    p.referenced_origin = at("referenced_origin");
    p.referenced_session = static_cast<std::uint32_t>(at("referenced_session"));
    p.referenced_sequence = at("referenced_sequence");
    p.referenced_round = static_cast<std::uint8_t>(at("referenced_round"));
    p.binding_generation = BindingGeneration{static_cast<std::uint32_t>(at("binding_generation"))};
    p.feedback_sequence = FeedbackSequence{static_cast<std::uint32_t>(at("feedback_sequence"))};
    p.retry_after_ms = static_cast<std::uint32_t>(at("retry_after_ms"));
    p.pressure = static_cast<std::uint8_t>(at("pressure"));
    status = autonomy::busy_encode(p, payload);
  } else if (codec == "time_sync") {
    autonomy::TimeSyncPayload p{};
    p.source = at("source");
    p.sequence = static_cast<std::uint32_t>(at("sequence"));
    p.reference_ms = at("reference_ms");
    p.uncertainty_ms = static_cast<std::uint32_t>(at("uncertainty_ms"));
    status = autonomy::time_sync_encode(p, payload);
  } else if (codec == "channel_notice") {
    autonomy::ChannelNoticePayload p{};
    p.subject = at("subject");
    p.channel_epoch = ChannelEpoch{static_cast<std::uint32_t>(at("channel_epoch"))};
    p.starts_in_ms = static_cast<std::uint32_t>(at("starts_in_ms"));
    p.duration_ms = static_cast<std::uint32_t>(at("duration_ms"));
    p.reason = static_cast<autonomy::AbsenceReason>(at("reason"));
    p.protected_cut_id =
        static_cast<std::uint16_t>(at("protected_cut_id"));
    status = autonomy::channel_notice_encode(p, payload);
  } else if (codec == "neighbor_probe") {
    autonomy::NeighborProbePayload p{};
    p.binding_generation = BindingGeneration{static_cast<std::uint32_t>(at("binding_generation"))};
    p.probe_sequence = static_cast<std::uint32_t>(at("probe_sequence"));
    p.sent_ms = at("sent_ms");
    p.requested_lease_ms = static_cast<std::uint32_t>(at("requested_lease_ms"));
    status = autonomy::neighbor_probe_encode(p, payload);
  } else if (codec == "neighbor_result") {
    autonomy::NeighborResultPayload p{};
    p.binding_generation = BindingGeneration{static_cast<std::uint32_t>(at("binding_generation"))};
    p.probe_sequence = static_cast<std::uint32_t>(at("probe_sequence"));
    p.result = static_cast<autonomy::NeighborResultCode>(at("result"));
    p.pressure = static_cast<std::uint8_t>(at("pressure"));
    p.queue_delay_ms = static_cast<std::uint32_t>(at("queue_delay_ms"));
    p.est_airtime_us = static_cast<std::uint32_t>(at("est_airtime_us"));
    p.lease_granted_ms = static_cast<std::uint32_t>(at("lease_granted_ms"));
    status = autonomy::neighbor_result_encode(p, payload);
  } else if (codec == "control_object") {
    autonomy::ControlObjectPayload p{};
    p.kind = static_cast<autonomy::ControlObjectKind>(at("kind"));
    p.total_len = static_cast<std::uint16_t>(at("total_len"));
    std::vector<std::uint8_t> hash;
    if (!hex_decode(fields.at("object_hash_hex"), hash) || hash.size() != 32) return false;
    std::copy(hash.begin(), hash.end(), p.object_hash.begin());
    status = autonomy::control_object_encode(p, payload);
  } else if (codec == "object_chunk") {
    autonomy::ObjectChunkPayload p{};
    std::vector<std::uint8_t> hash;
    std::vector<std::uint8_t> data;
    if (!hex_decode(fields.at("object_hash_hex"), hash) || hash.size() != 32) return false;
    if (!hex_decode(fields.at("data_hex"), data)) return false;
    std::copy(hash.begin(), hash.end(), p.object_hash.begin());
    p.offset = static_cast<std::uint16_t>(at("offset"));
    if (data.size() > p.data.size()) return false;
    std::copy(data.begin(), data.end(), p.data.begin());
    p.data_size = static_cast<std::uint16_t>(data.size());
    status = autonomy::object_chunk_encode(p, payload);
  } else if (codec == "object_ack") {
    autonomy::ObjectAckPayload p{};
    std::vector<std::uint8_t> hash;
    if (!hex_decode(fields.at("object_hash_hex"), hash) || hash.size() != 32) return false;
    std::copy(hash.begin(), hash.end(), p.object_hash.begin());
    p.received_len = static_cast<std::uint16_t>(at("received_len"));
    p.status = static_cast<autonomy::ObjectAckStatus>(at("status"));
    status = autonomy::object_ack_encode(p, payload);
  } else if (codec == "bootstrap_auth") {
    autonomy::BootstrapAuthBody p{};
    p.phase = static_cast<autonomy::AuthPhase>(at("phase"));
    p.step_index = static_cast<std::uint8_t>(at("step_index"));
    std::vector<std::uint8_t> body;
    if (!hex_decode(fields.at("body_hex"), body) || body.size() > p.body.size()) return false;
    std::copy(body.begin(), body.end(), p.body.begin());
    p.body_size = body.size();
    status = autonomy::bootstrap_auth_encode(p, payload);
  } else if (codec == "rld1") {
    autonomy::Rld1Envelope env{};
    env.kind = static_cast<FrameType>(at("kind"));
    env.flags = static_cast<std::uint16_t>(at("flags"));
    env.network_hint = static_cast<std::uint32_t>(at("network_hint"));
    env.claimed_node = at("claimed_node");
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> body;
    if (!hex_decode(fields.at("nonce_hex"), nonce) || nonce.size() != 16) return false;
    if (!hex_decode(fields.at("body_hex"), body) || body.size() > env.body.size()) return false;
    std::copy(nonce.begin(), nonce.end(), env.transaction_nonce.begin());
    std::copy(body.begin(), body.end(), env.body.begin());
    env.body_size = body.size();
    env.capability_bits = static_cast<std::uint32_t>(at("capability_bits"));
    autonomy::Rld1Encoded encoded{};
    status = autonomy::rld1_encode(env, encoded);
    if (status.ok()) {
      out.assign(encoded.bytes.begin(), encoded.bytes.begin() + encoded.size);
      return present;
    }
    return false;
  } else {
    return false;
  }
  if (!status || !present) return false;
  out.assign(payload.bytes.begin(), payload.bytes.begin() + payload.size);
  return true;
}

// decode -> re-encode round trip for a byte buffer; the decoded fields must
// reproduce the exact input bytes.
bool decode_and_reencode(const std::string& codec, const std::vector<std::uint8_t>& encoded) {
  EncodedPayload out{};
  if (codec == "busy") {
    autonomy::BusyPayload p{};
    return autonomy::busy_decode(to_view(encoded), p).ok() &&
           autonomy::busy_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "time_sync") {
    autonomy::TimeSyncPayload p{};
    return autonomy::time_sync_decode(to_view(encoded), p).ok() &&
           autonomy::time_sync_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "channel_notice") {
    autonomy::ChannelNoticePayload p{};
    return autonomy::channel_notice_decode(to_view(encoded), p).ok() &&
           autonomy::channel_notice_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "neighbor_probe") {
    autonomy::NeighborProbePayload p{};
    return autonomy::neighbor_probe_decode(to_view(encoded), p).ok() &&
           autonomy::neighbor_probe_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "neighbor_result") {
    autonomy::NeighborResultPayload p{};
    return autonomy::neighbor_result_decode(to_view(encoded), p).ok() &&
           autonomy::neighbor_result_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "control_object") {
    autonomy::ControlObjectPayload p{};
    return autonomy::control_object_decode(to_view(encoded), p).ok() &&
           autonomy::control_object_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "object_chunk") {
    autonomy::ObjectChunkPayload p{};
    return autonomy::object_chunk_decode(to_view(encoded), p).ok() &&
           autonomy::object_chunk_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "object_ack") {
    autonomy::ObjectAckPayload p{};
    return autonomy::object_ack_decode(to_view(encoded), p).ok() &&
           autonomy::object_ack_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "bootstrap_auth") {
    autonomy::BootstrapAuthBody p{};
    return autonomy::bootstrap_auth_decode(to_view(encoded), p).ok() &&
           autonomy::bootstrap_auth_encode(p, out).ok() &&
           std::equal(out.bytes.begin(), out.bytes.begin() + out.size, encoded.begin(),
                      encoded.end());
  }
  if (codec == "rld1") {
    autonomy::Rld1Envelope env{};
    autonomy::Rld1Encoded reenc{};
    return autonomy::rld1_decode(to_view(encoded), env).ok() &&
           autonomy::rld1_encode(env, reenc).ok() &&
           std::equal(reenc.bytes.begin(), reenc.bytes.begin() + reenc.size, encoded.begin(),
                      encoded.end());
  }
  return false;
}

bool decode_expect_error(const std::string& codec, const std::vector<std::uint8_t>& encoded) {
  const ByteView view = to_view(encoded);
  if (codec == "busy") {
    autonomy::BusyPayload p{};
    return !autonomy::busy_decode(view, p).ok();
  }
  if (codec == "time_sync") {
    autonomy::TimeSyncPayload p{};
    return !autonomy::time_sync_decode(view, p).ok();
  }
  if (codec == "channel_notice") {
    autonomy::ChannelNoticePayload p{};
    return !autonomy::channel_notice_decode(view, p).ok();
  }
  if (codec == "neighbor_probe") {
    autonomy::NeighborProbePayload p{};
    return !autonomy::neighbor_probe_decode(view, p).ok();
  }
  if (codec == "neighbor_result") {
    autonomy::NeighborResultPayload p{};
    return !autonomy::neighbor_result_decode(view, p).ok();
  }
  if (codec == "control_object") {
    autonomy::ControlObjectPayload p{};
    return !autonomy::control_object_decode(view, p).ok();
  }
  if (codec == "object_chunk") {
    autonomy::ObjectChunkPayload p{};
    return !autonomy::object_chunk_decode(view, p).ok();
  }
  if (codec == "object_ack") {
    autonomy::ObjectAckPayload p{};
    return !autonomy::object_ack_decode(view, p).ok();
  }
  if (codec == "bootstrap_auth") {
    autonomy::BootstrapAuthBody p{};
    return !autonomy::bootstrap_auth_decode(view, p).ok();
  }
  if (codec == "rld1") {
    autonomy::Rld1Envelope env{};
    return !autonomy::rld1_decode(view, env).ok();
  }
  return false;
}

void test_autonomy_golden() {
  const std::filesystem::path dir(ROUTELOOM_AUTONOMY_GOLDEN_DIR);
  const auto valid_files = list_json(dir / "valid");
  const auto invalid_files = list_json(dir / "invalid");
  CHECK(valid_files.size() >= 10);
  CHECK(invalid_files.size() >= 10);

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
    if (codec == "rld1") {
      CHECK(autonomy::rld1_probe(to_view(expected)));
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
    if (codec == "rld1" && fields.count("probe") != 0U && fields.at("probe") == "false") {
      CHECK(!autonomy::rld1_probe(to_view(encoded)));
    }
    if (!decode_expect_error(codec, encoded)) {
      std::fprintf(stderr, "invalid vector %s unexpectedly decoded\n", name.c_str());
      ++failures;
    }
  }
}

// --- Fixture self-tests --------------------------------------------------------

void test_fake_radio() {
  routeloom_test::TestSecurity security;
  routeloom_test::CapturingObserver observer;
  FakeRadioPort radio;
  NodeConfig config{};
  config.network = 1;
  config.node = 1;
  config.message_session = 7;
  config.route_advertisement_period_ms = 100;
  config.route_lifetime_ms = 1000;
  MeshNode node(config, radio, security, observer);
  CHECK_OK(node.start(0));

  // Scripted driver-level rejection is returned immediately and recorded.
  radio.script_send_status(Status::error(StatusCode::NoCapacity, "busy"));
  const std::uint8_t bytes[4] = {1, 2, 3, 4};
  CHECK(radio.send(2, 10, ByteView{bytes, 4}).code == StatusCode::NoCapacity);
  CHECK(radio.sent.size() == 1);
  CHECK(radio.sent[0].peer == 2 && radio.sent[0].token == 10);

  // Default path: accepted, success reported at the scripted delay.
  radio.script_tx_result(false, 50);
  CHECK_OK(radio.send(2, 11, ByteView{bytes, 4}));
  CHECK(radio.pump(0, node) == 0);   // not due yet
  radio.script_tx_result(true, 5);
  CHECK_OK(radio.send(2, 12, ByteView{bytes, 4}));
  CHECK(radio.pump(40, node) == 0);  // 50ms result still pending; 5ms fires at 45
  // pump delivers in FIFO order only when the front is due.
  CHECK(radio.pump(60, node) == 2);

  // Dropped TX results never arrive.
  radio.drop_tx_results(1);
  CHECK_OK(radio.send(2, 13, ByteView{bytes, 4}));
  CHECK(radio.pump(10000, node) == 0);

  // Scripted recover.
  radio.script_recover(Status::error(StatusCode::RadioFailure, "dead"));
  CHECK(radio.recover().code == StatusCode::RadioFailure);
  CHECK_OK(radio.recover());
  CHECK(radio.recover_calls == 2);

  // Single-radio model: while visiting channel 6, home-channel RX is dropped.
  radio.set_home_channel(1);
  radio.visit_channel(6, 500);
  const bool delivered = radio.inject_rx(1, 2, ByteView{bytes, 4},
                                         RadioRxMetadata{-60}, 100, node);
  CHECK(!delivered);
  CHECK(radio.missed_rx == 1);
  // ...but the visited channel can receive, and after the visit ends the
  // home channel works again.
  CHECK(radio.inject_rx(6, 2, ByteView{bytes, 4}, RadioRxMetadata{-60}, 100, node));
  radio.return_home();
  CHECK(radio.on_channel(1, 100));
  CHECK(radio.inject_rx(1, 2, ByteView{bytes, 4}, RadioRxMetadata{-60}, 600, node));
  // Visit expiry also returns to home.
  radio.visit_channel(6, 500);
  CHECK(radio.on_channel(1, 600));

  // Deterministic entropy.
  ScriptedEntropy entropy_a(7);
  ScriptedEntropy entropy_b(7);
  CHECK(entropy_a.next_u64() == entropy_b.next_u64());
  std::uint8_t nonce[16];
  CHECK_OK(entropy_a.fill(MutableByteView{nonce, sizeof(nonce)}));
  entropy_b.fail_next(1);
  CHECK(!entropy_b.fill(MutableByteView{nonce, sizeof(nonce)}));
  CHECK_OK(entropy_b.fill(MutableByteView{nonce, sizeof(nonce)}));
}

}  // namespace

int main() {
  test_contract_types();
  test_status_names();
  test_frame_allowed_matrix();
  test_admission_decision();
  test_payload_roundtrip();
  test_rld1_codec();
  test_autonomy_golden();
  test_fake_radio();

  if (failures != 0) {
    std::fprintf(stderr, "%d autonomy checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom autonomy contract tests passed");
  return 0;
}
