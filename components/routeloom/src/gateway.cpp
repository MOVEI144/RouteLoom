// Explicit Gateway delivery component (docs/design/scope-gateway-config/
// 03-explicit-gateway.md, 05-wire-api.md §5.3, contracts.json gateway.*).
//
// ORIGIN role: resolve() runs the authenticated Query/Descriptor exchange
// against a designated gateway and issues an opaque GatewayEndpoint; send()
// validates the endpoint + lease, reserves a result slot, then carries the
// canonical Service Submit on the node's end-protected Service=21 lane.
// GATEWAY role: enable_gateway() arms the responder — Query mints a
// lease-bound token, Submit faces dedup (32 records/60s), rate (20/min+8)
// and capacity (8 pending) admission before any state exists, scope 1
// completes into the bounded mailbox, scope 2 completes only on a real
// host-ingress ACK through the injected GatewayHostSink.
//
// Completion is a verified Service Receipt bound to the designated
// gateway + original MessageKey + request digest + token + boot + scope.
// Nothing here reports through the node's DATA/DeliveryResult path.

#include "routeloom/gateway.hpp"

#include <cstring>

namespace routeloom {

namespace {

// Bounded retry pacing for origin resolve/send rounds and outcome re-emit.
constexpr MonotonicMs kRetryBackoffMs = 250;
constexpr std::uint32_t kOutcomeLifetimeMs = 5000;
constexpr std::uint8_t kEmitMaxRetries = 3;

bool all_zero(const std::uint8_t* data, const std::size_t size) noexcept {
  for (std::size_t i = 0; i < size; ++i) {
    if (data[i] != 0) return false;
  }
  return true;
}

}  // namespace

GatewayDelivery::GatewayDelivery(MeshNode& node) noexcept : node_(node) {
  observer_ = &null_observer_;
}

void GatewayDelivery::attach() noexcept { node_.set_gateway_sink(this); }

// --- Small helpers -------------------------------------------------------------

bool GatewayDelivery::token_nonzero(const GatewayToken& token) noexcept {
  return !all_zero(token.data(), token.size());
}

// Tokens/nonces are opaque endpoint references, not cryptographic keys: a
// monotonic issue counter folded with the node id and gateway boot keeps
// them nonzero and collision-free inside this boot incarnation.
void GatewayDelivery::make_nonce(GatewayToken& out) noexcept {
  const std::uint64_t counter = ++nonce_counter_;
  const std::uint64_t node = node_.node_id();
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((counter >> (i * 8)) & 0xFF);
    out[8 + i] = static_cast<std::uint8_t>((node >> (i * 8)) & 0xFF);
  }
}

void GatewayDelivery::mint_token(GatewayToken& out) noexcept {
  const std::uint64_t counter = ++role_.issue_counter;
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((role_.gateway_boot >> (i * 8)) & 0xFF);
    out[8 + i] = static_cast<std::uint8_t>((counter >> (i * 8)) & 0xFF);
  }
}

// The request digest binds the exact canonical Submit bytes — version,
// subtype, scope, flags, token, gateway boot and payload (03 §3.3).
RequestDigest GatewayDelivery::submit_digest(const ByteView canonical_submit) noexcept {
  RequestDigest digest{};
  sha256(canonical_submit, digest);
  return digest;
}

// --- Bounded lookups -------------------------------------------------------------

GatewayDelivery::IssuedToken* GatewayDelivery::find_issued(
    const GatewayToken& token) noexcept {
  return issued_.find([&](const IssuedToken& record) {
    return constant_time_equal(
        ByteView{record.token.data(), record.token.size()},
        ByteView{token.data(), token.size()});
  });
}

const GatewayDelivery::IssuedToken* GatewayDelivery::find_issued(
    const GatewayToken& token) const noexcept {
  return issued_.find([&](const IssuedToken& record) {
    return constant_time_equal(
        ByteView{record.token.data(), record.token.size()},
        ByteView{token.data(), token.size()});
  });
}

GatewayDelivery::DedupRecord* GatewayDelivery::find_dedup(
    const MessageKey& key) noexcept {
  return receipts_.find([&](const DedupRecord& record) { return record.key == key; });
}

GatewayDelivery::OriginSend* GatewayDelivery::find_send(
    const MessageId& id) noexcept {
  return sends_.find([&](const OriginSend& send) { return send.id == id; });
}

const GatewayDelivery::OriginSend* GatewayDelivery::find_send(
    const MessageId& id) const noexcept {
  return sends_.find([&](const OriginSend& send) { return send.id == id; });
}

// A handle is only ever (slot, generation); both must match the live record,
// so a fabricated or stale handle can never mint authority (03 §3.2).
GatewayDelivery::EndpointRecord* GatewayDelivery::endpoint_record(
    const GatewayEndpoint& endpoint) noexcept {
  if (endpoint.slot_ >= kGatewayEndpointRecords) return nullptr;
  EndpointRecord& record = endpoints_[endpoint.slot_];
  if (!record.used || record.generation != endpoint.generation_) return nullptr;
  return &record;
}

const GatewayDelivery::EndpointRecord* GatewayDelivery::endpoint_record(
    const GatewayEndpoint& endpoint) const noexcept {
  if (endpoint.slot_ >= kGatewayEndpointRecords) return nullptr;
  const EndpointRecord& record = endpoints_[endpoint.slot_];
  if (!record.used || record.generation != endpoint.generation_) return nullptr;
  return &record;
}

std::uint8_t GatewayDelivery::endpoint_index(
    const EndpointRecord* record) const noexcept {
  const std::ptrdiff_t index = record - endpoints_.data();
  return (index >= 0 && index < static_cast<std::ptrdiff_t>(kGatewayEndpointRecords))
             ? static_cast<std::uint8_t>(index)
             : static_cast<std::uint8_t>(0xFF);
}

void GatewayDelivery::fail_resolve(const std::size_t slot,
                                   const Status result) noexcept {
  EndpointRecord& record = endpoints_[slot];
  const NodeId gateway = record.gateway;
  const std::uint32_t generation = record.generation;
  ++stats_.resolves_failed;
  record = EndpointRecord{};          // frees the slot and every reference
  record.generation = generation;     // slot tag keeps climbing — a stale
  observer_->on_gateway_resolved(GatewayEndpoint{}, gateway, result);
}                                     // handle can never match a new record

std::size_t GatewayDelivery::endpoint_records_used() const noexcept {
  std::size_t count = 0;
  for (const EndpointRecord& record : endpoints_) count += record.used ? 1U : 0U;
  return count;
}

// --- Origin: resolve --------------------------------------------------------------

Status GatewayDelivery::resolve(const NodeId gateway,
                                const endpoint::GatewayScope scope,
                                const HostDigest& expected_host_digest,
                                const std::uint32_t resolve_deadline_ms,
                                const MonotonicMs now_ms,
                                GatewayEndpoint& out) noexcept {
  if (gateway == kInvalidNodeId || gateway == node_.node_id() ||
      !endpoint::gateway_scope_valid(static_cast<std::uint8_t>(scope)) ||
      resolve_deadline_ms == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid gateway resolve");
  }
  // §5.3: scope 1 carries an all-zero host digest; scope 2 requires a real
  // authenticated principal pin — any-host is forbidden.
  const bool expected_zero = all_zero(expected_host_digest.data(), 32);
  if (scope == endpoint::GatewayScope::GatewaySdkRam && !expected_zero) {
    return Status::error(StatusCode::InvalidArgument,
                         "SDK_RAM scope carries no host digest");
  }
  if (scope == endpoint::GatewayScope::HostReceiveRam && expected_zero) {
    return Status::error(StatusCode::InvalidArgument,
                         "HOST_RECEIVE_RAM requires a host principal digest");
  }
  std::size_t slot = kGatewayEndpointRecords;
  for (std::size_t i = 0; i < kGatewayEndpointRecords; ++i) {
    if (!endpoints_[i].used) {
      slot = i;
      break;
    }
  }
  if (slot == kGatewayEndpointRecords) {
    return Status::error(StatusCode::NoCapacity, "endpoint records full");
  }

  EndpointRecord& record = endpoints_[slot];
  const std::uint32_t generation = record.generation + 1;
  record = EndpointRecord{};   // reset everything except the slot tag
  record.generation = generation;
  record.used = true;
  record.refs = 1;             // the app's reference
  record.state = EndpointState::Resolving;
  record.gateway = gateway;
  record.scope = scope;
  record.expected_host = expected_host_digest;
  make_nonce(record.query_nonce);
  record.resolve_deadline_ms = now_ms + resolve_deadline_ms;
  record.query_sent_ms = now_ms;
  record.round = 0;
  record.next_round_ms = 0;

  endpoint::ServiceQuery query{};
  query.scope = scope;
  query.nonce = record.query_nonce;
  query.expected_host_digest = expected_host_digest;
  endpoint::EncodedServicePayload encoded_query{};
  const Status encoded = endpoint::service_query_encode(query, encoded_query);
  if (!encoded) {
    record = EndpointRecord{};
    record.generation = generation;
    return Status::error(StatusCode::InternalError, "query encode failed");
  }
  // The resolve deadline bounds the whole exchange; the Query job itself
  // never outlives the descriptor lease it is racing against.
  const std::uint32_t lifetime = resolve_deadline_ms < kGatewayDescriptorLeaseMs
                                     ? resolve_deadline_ms
                                     : kGatewayDescriptorLeaseMs;
  const Status sent = node_.send_service(gateway, encoded_query.view(), lifetime,
                                         now_ms, record.query_id);
  if (!sent) {
    record = EndpointRecord{};
    record.generation = generation;
    return sent;
  }
  out = GatewayEndpoint{static_cast<std::uint8_t>(slot), generation};
  return Status::success();
}

EndpointState GatewayDelivery::endpoint_state(
    const GatewayEndpoint& endpoint) const noexcept {
  const EndpointRecord* record = endpoint_record(endpoint);
  return record == nullptr ? EndpointState::Failed : record->state;
}

bool GatewayDelivery::endpoint_info(const GatewayEndpoint& endpoint,
                                    GatewayEndpointInfo& info) const noexcept {
  const EndpointRecord* record = endpoint_record(endpoint);
  if (record == nullptr) return false;
  info.gateway = record->gateway;
  info.scope = record->scope;
  info.token = record->token;
  info.gateway_boot = record->gateway_boot;
  info.host_digest = record->host_digest;
  info.max_payload = record->max_payload;
  info.state = record->state;
  info.lease_deadline_ms = record->lease_deadline_ms;
  return true;
}

Status GatewayDelivery::endpoint_retain(const GatewayEndpoint& endpoint) noexcept {
  EndpointRecord* record = endpoint_record(endpoint);
  if (record == nullptr || record->refs == 0xFFFF) {
    return Status::error(StatusCode::NotFound, "endpoint not found");
  }
  ++record->refs;
  return Status::success();
}

void GatewayDelivery::endpoint_release(const GatewayEndpoint& endpoint) noexcept {
  EndpointRecord* record = endpoint_record(endpoint);
  if (record == nullptr || record->refs == 0) return;
  if (--record->refs == 0) {
    // refs covers the app AND every in-flight send, so reaching zero means
    // nothing can still produce an outcome from this record.
    record->used = false;
  }
}

// --- Origin: send ------------------------------------------------------------------

Status GatewayDelivery::send(const GatewayEndpoint& endpoint,
                             const ByteView payload,
                             const std::uint32_t lifetime_ms,
                             const MonotonicMs now_ms, MessageId& out) noexcept {
  EndpointRecord* record = endpoint_record(endpoint);
  if (record == nullptr) {
    return Status::error(StatusCode::NotFound, "endpoint not found");
  }
  if (record->state != EndpointState::Ready) {
    return Status::error(StatusCode::InvalidState, "ENDPOINT_NOT_READY");
  }
  // §3.5: 97..128B is rejected before acceptance, never truncated; 0B is a
  // legal empty message.
  if (payload.size > kGatewayPayloadMaxBytes ||
      (payload.size > 0 && payload.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "payload over gateway max");
  }
  if (payload.size > record->max_payload) {
    return Status::error(StatusCode::InvalidArgument, "PAYLOAD_OVER_MAX");
  }
  if (lifetime_ms == 0 || lifetime_ms > kGatewayLifetimeMaxMs) {
    return Status::error(StatusCode::InvalidArgument, "lifetime over 30s max");
  }
  // §5.3: the requested lifetime must fit STRICTLY inside the remaining
  // descriptor lease — equality already ends at a dead token, so the
  // boundary case is refused too (never shortened, never extended).
  if (now_ms >= record->lease_deadline_ms ||
      lifetime_ms >= record->lease_deadline_ms - now_ms) {
    return Status::error(StatusCode::InvalidState, "ENDPOINT_LEASE_TOO_SHORT");
  }
  // Reserve the result slot BEFORE any transmit — acceptance failure leaves
  // nothing half-queued (03 §3.3/§3.4).
  OriginSend* send = sends_.allocate();
  if (send == nullptr) {
    return Status::error(StatusCode::NoCapacity, "send records full");
  }

  endpoint::ServiceSubmit submit{};
  submit.scope = record->scope;
  submit.token = record->token;
  submit.gateway_boot = record->gateway_boot;
  submit.payload_size = static_cast<std::uint16_t>(payload.size);
  if (payload.size > 0) {
    std::memcpy(submit.payload.data(), payload.data, payload.size);
  }
  endpoint::EncodedServicePayload canonical{};
  const Status encoded = endpoint::service_submit_encode(submit, canonical);
  if (!encoded) {
    sends_.release(send);
    return Status::error(StatusCode::InternalError, "submit encode failed");
  }

  MessageId id{};
  const Status sent = node_.send_service(record->gateway, canonical.view(),
                                         lifetime_ms, now_ms, id);
  if (!sent) {
    sends_.release(send);
    return sent;
  }
  send->id = id;
  send->endpoint_slot = endpoint_index(record);
  send->gateway = record->gateway;
  send->scope = record->scope;
  send->token = record->token;          // the send keeps its own copy —
  send->gateway_boot = record->gateway_boot;  // endpoint release can't touch it
  send->payload_size = payload.size;
  if (payload.size > 0) {
    std::memcpy(send->payload.data(), payload.data, payload.size);
  }
  send->request_digest = submit_digest(canonical.view());
  send->state = GatewaySendState::Queued;
  send->reason = endpoint::ServiceReason::Ok;
  send->detail = "NONE";
  send->hop_accepted = false;
  send->expires_at_ms = now_ms + lifetime_ms;
  send->next_round_ms = 0;
  send->round = 0;
  ++record->refs;   // the send holds its own endpoint reference until done
  out = id;
  return Status::success();
}

GatewaySendResult GatewayDelivery::send_result(const MessageId& id) const noexcept {
  const OriginSend* send = find_send(id);
  if (send == nullptr) {
    return GatewaySendResult{id, GatewaySendState::Failed,
                             endpoint::ServiceReason::Unsupported, "SEND_NOT_FOUND"};
  }
  return GatewaySendResult{send->id, send->state, send->reason, send->detail};
}

void GatewayDelivery::finish_send(OriginSend& send, const GatewaySendState state,
                                  const endpoint::ServiceReason reason,
                                  const char* detail) noexcept {
  send.state = state;
  send.reason = reason;
  send.detail = detail;
  // Completion is reported exactly once; the record frees immediately after
  // the callback so finished work can never exhaust the pool.
  observer_->on_gateway_result(
      GatewaySendResult{send.id, state, reason, detail});
  if (send.endpoint_slot < kGatewayEndpointRecords) {
    EndpointRecord& record = endpoints_[send.endpoint_slot];
    if (record.used && record.refs > 0 && --record.refs == 0) {
      record.used = false;
    }
  }
  sends_.release(&send);
}

void GatewayDelivery::retry_send(OriginSend& send, const MonotonicMs now_ms) noexcept {
  if (now_ms >= send.expires_at_ms) {
    finish_send(send, send.hop_accepted ? GatewaySendState::Indeterminate
                                        : GatewaySendState::Expired,
                endpoint::ServiceReason::Deadline, "LIFETIME_EXPIRED");
    return;
  }
  const std::uint8_t round = static_cast<std::uint8_t>(send.round + 1);
  send.next_round_ms = 0;
  const std::uint32_t remaining =
      static_cast<std::uint32_t>(send.expires_at_ms - now_ms);
  // Same logical MessageKey every round (03 §3.3); the round field separates
  // hop-ACK correlation and relay dedup. Re-encoding the canonical Submit
  // from the stored fields is byte-identical to round 0's bytes.
  endpoint::ServiceSubmit submit{};
  submit.scope = send.scope;
  submit.token = send.token;
  submit.gateway_boot = send.gateway_boot;
  submit.payload_size = static_cast<std::uint16_t>(send.payload_size);
  if (send.payload_size > 0) {
    std::memcpy(submit.payload.data(), send.payload.data(), send.payload_size);
  }
  endpoint::EncodedServicePayload canonical{};
  const Status encoded = endpoint::service_submit_encode(submit, canonical);
  if (!encoded) {
    finish_send(send, GatewaySendState::Failed,
                endpoint::ServiceReason::Unsupported, "SUBMIT_ENCODE_FAILED");
    return;
  }
  const Status resent = node_.resend_service(send.id, send.gateway,
                                             canonical.view(), round,
                                             remaining, now_ms);
  if (!resent) {
    // A synchronous refusal (no route yet, TX pool full, node paused) is
    // TRANSIENT — it spent no airtime, so it spends no round and never
    // finishes the send. Re-arm on the tick; expires_at still bounds the
    // whole effort.
    send.next_round_ms = now_ms + kRetryBackoffMs;
    return;
  }
  send.round = round;   // a round is spent only once its frame is queued
}

// --- Gateway role --------------------------------------------------------------------

Status GatewayDelivery::enable_gateway(const GatewayRoleConfig& config) noexcept {
  if (config.gateway_boot == 0) {
    return Status::error(StatusCode::InvalidArgument, "gateway boot must be nonzero");
  }
  if ((config.capabilities & kGatewayCapHostReceive) != 0 &&
      config.host_sink == nullptr) {
    return Status::error(StatusCode::InvalidArgument,
                         "HOST_RECEIVE capability requires a host sink");
  }
  // A boot CHANGE re-issues every token from scratch; a same-boot re-enable
  // keeps issued records so stored evidence stays resendable (03 §3.4).
  if (role_.gateway_boot != config.gateway_boot) {
    issued_.clear();
    receipts_.clear();
    pending_.clear();
  }
  role_.enabled = true;
  role_.gateway_boot = config.gateway_boot;
  role_.capabilities = config.capabilities;
  role_.host_sink = config.host_sink;
  return Status::success();
}

void GatewayDelivery::disable_gateway() noexcept {
  role_.enabled = false;
  role_.host_sink = nullptr;
}

// --- Service frame dispatch ----------------------------------------------------------

void GatewayDelivery::on_service_payload(const NodeId peer,
                                         const wire::PlainFrame& frame,
                                         const MonotonicMs now_ms) noexcept {
  if (frame.payload_size < 2 ||
      frame.payload[0] != endpoint::kServicePayloadVersion) {
    ++stats_.malformed_frames;
    return;
  }
  switch (static_cast<endpoint::ServiceSubtype>(frame.payload[1])) {
    case endpoint::ServiceSubtype::Query:
      handle_query(peer, frame, now_ms);
      break;
    case endpoint::ServiceSubtype::Descriptor:
      handle_descriptor(peer, frame, now_ms);
      break;
    case endpoint::ServiceSubtype::Submit:
      handle_submit(peer, frame, now_ms);
      break;
    case endpoint::ServiceSubtype::Receipt:
    case endpoint::ServiceSubtype::Pending:
    case endpoint::ServiceSubtype::Reject:
      handle_outcome(peer, frame, now_ms);
      break;
    default:
      ++stats_.malformed_frames;
      break;
  }
}

// --- Gateway responder: Query ---------------------------------------------------------

void GatewayDelivery::handle_query(const NodeId peer,
                                   const wire::PlainFrame& frame,
                                   const MonotonicMs now_ms) noexcept {
  (void)peer;   // replies address the logical origin, not the previous hop
  endpoint::ServiceQuery query{};
  const Status decoded = endpoint::service_query_decode(
      ByteView{frame.payload.data(), frame.payload_size}, query);
  if (!decoded) {
    ++stats_.malformed_frames;
    return;
  }
  if (!role_.enabled) {
    // Without the role there is no token context to reject against; silence
    // lets the origin's resolve expire honestly (03 §3.4).
    ++stats_.queries_dropped;
    return;
  }
  if (node_.tx_free_slots() < 1) {
    ++stats_.queries_dropped;
    return;
  }
  // Queries share the submit admission discipline: a bounded token bucket
  // keeps a query flood from churning answers and (below) from exhausting
  // the 4-slot issued pool with refusals (03 §3.4).
  if (!query_rate_.consume(now_ms)) {
    ++stats_.queries_dropped;
    return;
  }
  // Scope-2 readiness: the descriptor is only issued when the authenticated
  // host registration is live AND matches the pinned principal (03 §3.2).
  HostBinding binding{};
  bool host_bound = false;
  if (query.scope == endpoint::GatewayScope::HostReceiveRam) {
    host_bound = role_.host_sink != nullptr && role_.host_sink->host_ready(binding) &&
                 constant_time_equal(
                     ByteView{binding.principal_digest.data(), 32},
                     ByteView{query.expected_host_digest.data(), 32});
  }

  // Replies address the logical ORIGIN, not the previous hop — over a
  // multi-hop path routing picks the next hop from the destination.
  const NodeId origin = frame.header.origin;
  const MessageKey query_key{origin, frame.header.message};

  // A refusal never stores an IssuedToken: it mints an ephemeral token that
  // only binds this Reject to the exchange (the codec requires nonzero).
  // The origin correlates Rejects by request digest + MessageKey, never by
  // token validity — so refused Queries can never exhaust the issue pool.
  const auto reject_query = [&](const endpoint::ServiceReason reason) {
    endpoint::ServiceOutcome reject{};
    reject.subtype = endpoint::ServiceSubtype::Reject;
    reject.scope = query.scope;
    mint_token(reject.token);
    reject.gateway_boot = role_.gateway_boot;
    reject.ref_origin = query_key.origin;
    reject.ref_session = query_key.id.session;
    reject.ref_sequence = query_key.id.sequence;
    reject.request_digest =
        submit_digest(ByteView{frame.payload.data(), frame.payload_size});
    reject.reason = reason;
    endpoint::EncodedServicePayload encoded{};
    if (endpoint::service_outcome_encode(reject, encoded)) {
      MessageId emit_id{};
      (void)node_.send_service(origin, encoded.view(), kOutcomeLifetimeMs,
                               Priority::Management, now_ms, emit_id);
    }
  };

  if (query.scope == endpoint::GatewayScope::HostReceiveRam && !host_bound) {
    // Explicit refusal instead of an unverifiable descriptor (G02-style):
    // the Reject references the Query's own MessageKey for correlation.
    ++stats_.submits_host_unavailable;
    reject_query(endpoint::ServiceReason::HostUnavailable);
    return;
  }

  IssuedToken* issued = issued_.allocate();
  if (issued == nullptr) {
    // Issue pool full: an explicit capacity refusal beats silence — the
    // origin's resolve fails fast instead of expiring.
    ++stats_.queries_dropped;
    reject_query(endpoint::ServiceReason::Capacity);
    return;
  }
  mint_token(issued->token);
  issued->client = origin;
  issued->scope = query.scope;
  issued->binding = host_bound ? binding : HostBinding{};
  issued->lease_deadline_ms = now_ms + kGatewayDescriptorLeaseMs;

  endpoint::ServiceDescriptor descriptor{};
  descriptor.scope = query.scope;
  descriptor.echo_nonce = query.nonce;
  descriptor.token = issued->token;
  descriptor.gateway_boot = role_.gateway_boot;
  descriptor.host_digest = host_bound ? binding.principal_digest : HostDigest{};
  descriptor.capabilities = role_.capabilities;
  descriptor.max_payload = static_cast<std::uint16_t>(kGatewayPayloadMaxBytes);
  descriptor.lease_ms = kGatewayDescriptorLeaseMs;
  endpoint::EncodedServicePayload encoded{};
  if (!endpoint::service_descriptor_encode(descriptor, encoded)) {
    issued_.release(issued);
    return;
  }
  MessageId emit_id{};
  const Status sent = node_.send_service(origin, encoded.view(), kOutcomeLifetimeMs,
                                         Priority::Management, now_ms, emit_id);
  if (!sent) {
    issued_.release(issued);
    ++stats_.outcomes_emit_failed;
    return;
  }
  ++stats_.queries_answered;
  ++stats_.descriptors_issued;
}

// --- Gateway responder: Submit ----------------------------------------------------------

void GatewayDelivery::handle_submit(const NodeId peer,
                                    const wire::PlainFrame& frame,
                                    const MonotonicMs now_ms) noexcept {
  (void)peer;   // replies address the logical origin, not the previous hop
  const ByteView canonical{frame.payload.data(), frame.payload_size};
  endpoint::ServiceSubmit submit{};
  const Status decoded = endpoint::service_submit_decode(canonical, submit);
  if (!decoded) {
    ++stats_.malformed_frames;
    return;
  }
  const MessageKey key{frame.header.origin, frame.header.message};
  const RequestDigest digest = submit_digest(canonical);

  // Dedup BEFORE any validation: a re-seen key returns the stored decision
  // verbatim — even after the token's lease expired (03 §3.4). New work is
  // never executed twice and never extends the 60s hold.
  DedupRecord* existing = find_dedup(key);
  if (existing != nullptr) {
    if (!constant_time_equal(ByteView{existing->request_digest.data(), 32},
                             ByteView{digest.data(), 32})) {
      // Same MessageKey, different content — CONFLICT names the collision;
      // the stored record keeps the ORIGINAL outcome.
      ++stats_.submits_conflict;
      endpoint::ServiceOutcome reject{};
      reject.subtype = endpoint::ServiceSubtype::Reject;
      reject.scope = submit.scope;
      reject.token = submit.token;
      reject.gateway_boot = submit.gateway_boot;
      reject.ref_origin = key.origin;
      reject.ref_session = key.id.session;
      reject.ref_sequence = key.id.sequence;
      reject.request_digest = digest;
      reject.reason = endpoint::ServiceReason::Conflict;
      endpoint::EncodedServicePayload encoded{};
      if (node_.tx_free_slots() >= 1 &&
          endpoint::service_outcome_encode(reject, encoded)) {
        MessageId emit_id{};
        (void)node_.send_service(key.origin, encoded.view(), kOutcomeLifetimeMs,
                                 Priority::Management, now_ms, emit_id);
      }
      return;
    }
    ++stats_.submits_duplicate;
    if (existing->state == DedupState::Completed) {
      ++stats_.outcomes_resend;
      (void)emit_outcome(*existing, now_ms);
    } else {
      // Still executing: answer PENDING (reason PendingWait) — never a
      // second ingress, never a fabricated final receipt.
      endpoint::ServiceOutcome pending{};
      pending.subtype = endpoint::ServiceSubtype::Pending;
      pending.scope = existing->scope;
      pending.token = existing->token;
      pending.gateway_boot = existing->gateway_boot;
      pending.ref_origin = key.origin;
      pending.ref_session = key.id.session;
      pending.ref_sequence = key.id.sequence;
      pending.request_digest = existing->request_digest;
      pending.reason = endpoint::ServiceReason::PendingWait;
      endpoint::EncodedServicePayload encoded{};
      if (node_.tx_free_slots() >= 1 &&
          endpoint::service_outcome_encode(pending, encoded)) {
        MessageId emit_id{};
        (void)node_.send_service(key.origin, encoded.view(), kOutcomeLifetimeMs,
                                 Priority::Management, now_ms, emit_id);
      }
    }
    return;
  }

  // VALIDATING — nothing exists yet; every failure below is a pre-acceptance
  // refusal with no state created (03 §3.4).
  const auto reject_new = [&](const endpoint::ServiceReason reason) {
    endpoint::ServiceOutcome reject{};
    reject.subtype = endpoint::ServiceSubtype::Reject;
    reject.scope = submit.scope;
    reject.token = submit.token;   // echo the presented token — the codec
    reject.gateway_boot = submit.gateway_boot;  // binds the rejection to it
    reject.ref_origin = key.origin;
    reject.ref_session = key.id.session;
    reject.ref_sequence = key.id.sequence;
    reject.request_digest = digest;
    reject.reason = reason;
    endpoint::EncodedServicePayload encoded{};
    if (node_.tx_free_slots() >= 1 &&
        endpoint::service_outcome_encode(reject, encoded)) {
      MessageId emit_id{};
      (void)node_.send_service(key.origin, encoded.view(), kOutcomeLifetimeMs,
                               Priority::Management, now_ms, emit_id);
    }
  };

  if (!role_.enabled) {
    ++stats_.submits_stale_token;
    reject_new(endpoint::ServiceReason::TokenStale);
    return;
  }
  // Token must be issued by THIS boot to THIS client for THIS scope, and its
  // lease must still be live — an expired token may never start new work.
  const IssuedToken* issued = find_issued(submit.token);
  if (issued == nullptr || issued->client != key.origin ||
      issued->scope != submit.scope ||
      submit.gateway_boot != role_.gateway_boot ||
      now_ms >= issued->lease_deadline_ms) {
    ++stats_.submits_stale_token;
    reject_new(endpoint::ServiceReason::TokenStale);
    return;
  }
  HostBinding binding{};
  if (submit.scope == endpoint::GatewayScope::HostReceiveRam) {
    if (role_.host_sink == nullptr || !role_.host_sink->host_ready(binding)) {
      ++stats_.submits_host_unavailable;
      reject_new(endpoint::ServiceReason::HostUnavailable);
      return;
    }
    // The token binds principal + host boot + USB session: a reconnect never
    // re-validates an old token (03 §3.4) — the binding must still be exact.
    if (!constant_time_equal(
            ByteView{binding.principal_digest.data(), 32},
            ByteView{issued->binding.principal_digest.data(), 32}) ||
        binding.host_boot != issued->binding.host_boot ||
        binding.usb_session != issued->binding.usb_session) {
      ++stats_.submits_stale_token;
      reject_new(endpoint::ServiceReason::TokenStale);
      return;
    }
  }
  // Admission: a rate token AND every slot must exist before the record is
  // born — pending + dedup/receipt + reply budget reserved atomically.
  if (node_.tx_free_slots() < 1 || pending_.size() >= kGatewayPendingMax ||
      receipts_.size() >= kGatewayReceiptRecords || !rate_.consume(now_ms)) {
    ++stats_.submits_capacity;
    reject_new(endpoint::ServiceReason::Capacity);
    return;
  }
  DedupRecord* record = receipts_.allocate();
  PendingRecord* pending = pending_.allocate();
  if (record == nullptr || pending == nullptr) {
    if (record != nullptr) receipts_.release(record);
    if (pending != nullptr) pending_.release(pending);
    ++stats_.submits_capacity;
    reject_new(endpoint::ServiceReason::Capacity);
    return;
  }
  record->key = key;
  record->request_digest = digest;
  record->token = submit.token;
  record->gateway_boot = submit.gateway_boot;
  record->scope = submit.scope;
  record->state = DedupState::Pending;
  record->pending_index =
      static_cast<std::uint8_t>(pending_.index_of(pending));
  record->first_seen_ms = now_ms;
  pending->key = key;
  pending->payload_size = submit.payload_size;
  if (submit.payload_size > 0) {
    std::memcpy(pending->payload.data(), submit.payload.data(), submit.payload_size);
  }
  ++stats_.submits_accepted;

  if (submit.scope == endpoint::GatewayScope::GatewaySdkRam) {
    // Scope 1 completes on bounded mailbox storage — the pending record IS
    // the mailbox slot, held until the app drains or the dedup hold ends.
    pending->state = PendingState::Received;
    pending->mailbox_held = true;
    ++stats_.mailbox_stored;
    ++stats_.sdk_ram_receipts;
    complete_pending(*record, endpoint::ServiceSubtype::Receipt,
                     endpoint::ServiceReason::Ok, now_ms);
    return;
  }

  // Scope 2: success requires the host-ingress ACK — queue the ReceiveLog
  // store through the bridge seam; a pre-acceptance refusal drops the whole
  // reservation and answers CAPACITY (03 §3.4). The record is armed for the
  // ACK BEFORE the seam is entered so a synchronous ACK inside host_ingress
  // still lands on WaitHost state instead of being dropped as stale.
  pending->state = PendingState::WaitHost;
  const std::uint32_t frame_remaining = frame.header.remaining_deadline_ms;
  const std::uint32_t ack_window = frame_remaining < kGatewayHostAckMs
                                     ? frame_remaining
                                     : kGatewayHostAckMs;
  pending->host_ack_deadline_ms = now_ms + ack_window;
  // The 32B canonical head rides the ingress frame so the host recomputes
  // the request digest over prefix+payload before storing (05 §5.6).
  const Status ingressed = role_.host_sink->host_ingress(
      key, digest, ByteView{canonical.data, endpoint::kServiceSubmitHeaderSize},
      ByteView{pending->payload.data(), pending->payload_size}, now_ms);
  if (!ingressed) {
    if (record->state == DedupState::Pending) {
      // No synchronous ACK consumed the reservation — unwind it fully.
      release_pending(pending);
      receipts_.release(record);
      ++stats_.submits_capacity;
      reject_new(endpoint::ServiceReason::Capacity);
    }
    // else: a synchronous ACK already produced the stored final outcome —
    // real evidence supersedes the failed return; nothing to unwind.
    return;
  }
  ++stats_.host_ingress_sent;
}

// --- Origin: descriptor / outcome ---------------------------------------------------------

void GatewayDelivery::handle_descriptor(const NodeId peer,
                                        const wire::PlainFrame& frame,
                                        const MonotonicMs now_ms) noexcept {
  (void)peer;
  endpoint::ServiceDescriptor descriptor{};
  const Status decoded = endpoint::service_descriptor_decode(
      ByteView{frame.payload.data(), frame.payload_size}, descriptor);
  if (!decoded) {
    ++stats_.malformed_frames;
    return;
  }
  EndpointRecord* record = nullptr;
  for (std::size_t i = 0; i < kGatewayEndpointRecords; ++i) {
    EndpointRecord& candidate = endpoints_[i];
    if (candidate.used && candidate.state == EndpointState::Resolving &&
        candidate.gateway == frame.header.origin &&
        constant_time_equal(
            ByteView{candidate.query_nonce.data(), 16},
            ByteView{descriptor.echo_nonce.data(), 16})) {
      record = &candidate;
      break;
    }
  }
  if (record == nullptr) {
    ++stats_.outcomes_rejected;   // unsolicited/foreign descriptor
    return;
  }
  // Full binding check: designated gateway (frame origin == record->gateway,
  // already end-verified), scope match, nonce echo, nonzero token/boot and —
  // for scope 2 — the pinned host principal (03 §3.2).
  const bool fields_ok =
      descriptor.scope == record->scope &&
      token_nonzero(descriptor.token) && descriptor.gateway_boot != 0 &&
      (record->scope != endpoint::GatewayScope::HostReceiveRam ||
       constant_time_equal(ByteView{descriptor.host_digest.data(), 32},
                           ByteView{record->expected_host.data(), 32}));
  if (!fields_ok) {
    ++stats_.outcomes_rejected;
    return;   // not our descriptor — keep waiting for the real one
  }
  // The claimed lease is clamped to the contract bound — a descriptor
  // advertising a longer lease (up to u32::MAX, ~136 years) can never pin
  // an origin endpoint past the gateway's own issued-token lease (03 §3.2).
  const std::uint32_t lease_ms = descriptor.lease_ms < kGatewayDescriptorLeaseMs
                                   ? descriptor.lease_ms
                                   : kGatewayDescriptorLeaseMs;
  // The lease is measured from when the Query left, so the whole RTT is
  // uncertainty the origin never trusts (03 §3.2).
  const MonotonicMs rtt = now_ms - record->query_sent_ms;
  if (lease_ms <= rtt) {
    fail_resolve(endpoint_index(record),
                 Status::error(StatusCode::Expired, "LEASE_EXPIRED_ON_ARRIVAL"));
    return;
  }
  record->token = descriptor.token;
  record->gateway_boot = descriptor.gateway_boot;
  record->host_digest = descriptor.host_digest;
  record->max_payload = descriptor.max_payload;
  record->lease_deadline_ms = record->query_sent_ms + lease_ms;
  record->state = EndpointState::Ready;
  ++stats_.resolves_succeeded;
  observer_->on_gateway_resolved(
      GatewayEndpoint{endpoint_index(record), record->generation},
      record->gateway, Status::success());
}

void GatewayDelivery::handle_outcome(const NodeId peer,
                                     const wire::PlainFrame& frame,
                                     const MonotonicMs now_ms) noexcept {
  (void)peer;
  (void)now_ms;
  endpoint::ServiceOutcome outcome{};
  const Status decoded = endpoint::service_outcome_decode(
      ByteView{frame.payload.data(), frame.payload_size}, outcome);
  if (!decoded) {
    ++stats_.malformed_frames;
    return;
  }
  const MessageId ref_id{outcome.ref_session, outcome.ref_sequence};

  // A Reject can also terminate a RESOLVE (e.g. HOST_UNAVAILABLE at Query
  // time): correlate against in-flight queries first. The request digest
  // must match our canonical Query bytes — a forged refusal that only
  // guesses the MessageKey gets dropped, not believed.
  for (std::size_t i = 0; i < kGatewayEndpointRecords; ++i) {
    EndpointRecord& record = endpoints_[i];
    if (!record.used || record.state != EndpointState::Resolving ||
        record.gateway != frame.header.origin || record.query_id != ref_id ||
        outcome.ref_origin != node_.node_id()) {
      continue;
    }
    // Re-encode the canonical Query from the record's fields — identical
    // bytes to what was sent, so the digest binds the forged answer to the
    // real exchange.
    endpoint::ServiceQuery query{};
    query.scope = record.scope;
    query.nonce = record.query_nonce;
    query.expected_host_digest = record.expected_host;
    endpoint::EncodedServicePayload canonical{};
    if (!endpoint::service_query_encode(query, canonical)) {
      ++stats_.outcomes_rejected;
      return;
    }
    const RequestDigest expected = submit_digest(canonical.view());
    if (!constant_time_equal(ByteView{outcome.request_digest.data(), 32},
                             ByteView{expected.data(), 32})) {
      ++stats_.outcomes_rejected;
      return;
    }
    if (outcome.subtype == endpoint::ServiceSubtype::Reject) {
      fail_resolve(i, Status::error(StatusCode::InvalidState,
                                    "RESOLVE_REJECTED"));
    }
    return;   // an outcome for a live query is consumed either way
  }

  OriginSend* send = find_send(ref_id);
  if (send == nullptr) {
    ++stats_.outcomes_rejected;   // not our MessageKey — forged or stale
    return;
  }
  // Full receipt binding (03 §3.3, G01/G08): designated gateway, original
  // MessageKey (ref fields matched the send), token, boot, scope and the
  // request digest — every field must verify before success exists.
  const bool bound =
      frame.header.origin == send->gateway &&
      outcome.ref_origin == node_.node_id() &&
      outcome.scope == send->scope &&
      outcome.gateway_boot == send->gateway_boot &&
      constant_time_equal(ByteView{outcome.token.data(), 16},
                          ByteView{send->token.data(), 16}) &&
      constant_time_equal(ByteView{outcome.request_digest.data(), 32},
                          ByteView{send->request_digest.data(), 32});
  if (!bound) {
    ++stats_.outcomes_rejected;
    return;
  }
  switch (outcome.subtype) {
    case endpoint::ServiceSubtype::Receipt:
      ++stats_.receipts_verified;
      finish_send(*send, GatewaySendState::EndpointReceived,
                  endpoint::ServiceReason::Ok, "ENDPOINT_RECEIVED");
      break;
    case endpoint::ServiceSubtype::Pending:
      if (send->state == GatewaySendState::Queued ||
          send->state == GatewaySendState::HopAccepted) {
        send->state = GatewaySendState::WaitingEndpoint;
      }
      break;
    case endpoint::ServiceSubtype::Reject:
      finish_send(*send, GatewaySendState::Failed, outcome.reason, "REJECTED");
      break;
    default:
      ++stats_.outcomes_rejected;
      break;
  }
}

// --- Job completion + tick ------------------------------------------------------------

void GatewayDelivery::on_service_job_done(const MessageId& id,
                                          const bool hop_accepted,
                                          const char* reason,
                                          const MonotonicMs now_ms) noexcept {
  OriginSend* send = find_send(id);
  if (send != nullptr) {
    if (hop_accepted) {
      send->hop_accepted = true;
      if (send->state == GatewaySendState::Queued) {
        send->state = GatewaySendState::HopAccepted;
      }
      return;
    }
    // Bounded retry: ≤3 E2E rounds total, next round scheduled on the poll
    // tick so nothing re-enters the scheduler mid-callback.
    if (send->round + 1 < kGatewayMaxRounds && now_ms < send->expires_at_ms) {
      send->next_round_ms = now_ms + kRetryBackoffMs;
      return;
    }
    finish_send(*send, send->hop_accepted ? GatewaySendState::Indeterminate
                                          : GatewaySendState::Expired,
                endpoint::ServiceReason::Deadline, reason);
    return;
  }
  // Resolve retries ride the same bounded-round discipline: an accepted
  // Query is done (the Descriptor is now owed); only a job failure spends
  // another round.
  for (std::size_t i = 0; i < kGatewayEndpointRecords; ++i) {
    EndpointRecord& record = endpoints_[i];
    if (!record.used || record.state != EndpointState::Resolving ||
        record.query_id != id) {
      continue;
    }
    if (hop_accepted) return;
    if (record.round + 1 < kGatewayMaxRounds &&
        now_ms < record.resolve_deadline_ms) {
      record.next_round_ms = now_ms + kRetryBackoffMs;
    } else {
      fail_resolve(i, Status::error(StatusCode::Expired, reason));
    }
    return;
  }
  // Outcome emit jobs: failure re-queues a bounded re-emit on the poll tick.
  // Only the sequence half is tracked — every emit job's session is this
  // node's own, so the match is exact and a stale notice can't be misread.
  DedupRecord* record = receipts_.find(
      [&](const DedupRecord& value) {
        return value.emit_sequence != 0 && value.emit_sequence == id.sequence;
      });
  if (record != nullptr && !hop_accepted &&
      record->emit_retries < kEmitMaxRetries) {
    ++record->emit_retries;
    record->emit_pending = true;
    record->next_emit_ms = now_ms + kRetryBackoffMs;
  }
}

void GatewayDelivery::poll(const MonotonicMs now_ms) noexcept {
  // Origin endpoints: bounded query rounds, lease staleness, resolve timeout.
  for (std::size_t i = 0; i < kGatewayEndpointRecords; ++i) {
    EndpointRecord& record = endpoints_[i];
    if (!record.used) continue;
    if (record.state == EndpointState::Ready &&
        now_ms >= record.lease_deadline_ms) {
      record.state = EndpointState::Stale;   // new work stops; sends keep
    }                                        // their own token copies
    if (record.state != EndpointState::Resolving) continue;
    if (now_ms >= record.resolve_deadline_ms) {
      fail_resolve(i, Status::error(StatusCode::Expired, "RESOLVE_TIMEOUT"));
      continue;
    }
    if (record.next_round_ms != 0 && now_ms >= record.next_round_ms) {
      const std::uint8_t round = static_cast<std::uint8_t>(record.round + 1);
      record.next_round_ms = 0;
      const std::uint32_t remaining = static_cast<std::uint32_t>(
          record.resolve_deadline_ms - now_ms);
      // Byte-identical canonical Query — re-encoded from the stored fields.
      endpoint::ServiceQuery query{};
      query.scope = record.scope;
      query.nonce = record.query_nonce;
      query.expected_host_digest = record.expected_host;
      endpoint::EncodedServicePayload canonical{};
      if (!endpoint::service_query_encode(query, canonical)) {
        fail_resolve(i, Status::error(StatusCode::InternalError,
                                      "QUERY_ENCODE_FAILED"));
        continue;
      }
      const Status resent =
          node_.resend_service(record.query_id, record.gateway,
                               canonical.view(), round, remaining,
                               now_ms);
      if (!resent) {
        // Same transient-refusal rule as sends: no airtime was spent, so no
        // round is spent — re-arm on the tick inside the resolve deadline.
        record.next_round_ms = now_ms + kRetryBackoffMs;
        continue;
      }
      record.round = round;
    }
  }

  // Origin sends: bounded rounds, then Expired/Indeterminate by hop evidence.
  sends_.for_each([&](OriginSend& send) {
    if (now_ms >= send.expires_at_ms) {
      finish_send(send, send.hop_accepted ? GatewaySendState::Indeterminate
                                          : GatewaySendState::Expired,
                  endpoint::ServiceReason::Deadline, "LIFETIME_EXPIRED");
      return;
    }
    if (send.next_round_ms != 0 && now_ms >= send.next_round_ms) {
      retry_send(send, now_ms);
    }
  });

  // Issued tokens age out at their lease — stale tokens stay recognizable
  // only as "not found", which is the same TOKEN_STALE answer.
  issued_.for_each([&](IssuedToken& issued) {
    if (now_ms >= issued.lease_deadline_ms) {
      issued_.release(&issued);   // safe: for_each revisits used_ flags
    }                             // only through the pool's own scan
  });

  // Dedup/receipt records: 60s from first sight, never extended (03 §3.4).
  // A live mailbox entry ages out WITH its record — protected records are
  // never evicted early to look better under load.
  receipts_.for_each([&](DedupRecord& record) {
    if (now_ms - record.first_seen_ms <= kGatewayReceiptHoldMs) {
      if (record.emit_pending && now_ms >= record.next_emit_ms) {
        record.emit_pending = false;
        (void)emit_outcome(record, now_ms);
      }
      return;
    }
    PendingRecord* pending = pending_.at(record.pending_index);
    if (pending != nullptr) {
      if (pending->mailbox_held) ++stats_.mailbox_dropped;
      pending_.release(pending);
      record.pending_index = kNoPending;
    }
    receipts_.release(&record);
  });

  // Host ACK timeout: evidence is RETAINED (the store may have happened);
  // the origin's own deadline expires into an honest INDETERMINATE while a
  // late ACK can still complete the record (03 §3.4, G03). But the wait is
  // bounded — once a timed-out record also exhausts its grace window it
  // concludes as a stored non-success and the pending slot frees, so a dead
  // host can never pin all 8 slots for the whole 60s hold.
  PendingRecord* conclude[kGatewayPendingMax]{};
  std::size_t conclude_count = 0;
  pending_.for_each([&](PendingRecord& pending) {
    if (pending.state != PendingState::WaitHost ||
        pending.host_ack_deadline_ms == 0 ||
        now_ms < pending.host_ack_deadline_ms) {
      return;
    }
    if (!pending.host_timed_out) {
      pending.host_timed_out = true;
      ++stats_.host_ingress_timeouts;
    }
    if (now_ms >= pending.host_ack_deadline_ms + kGatewayHostAckGraceMs &&
        conclude_count < kGatewayPendingMax) {
      conclude[conclude_count++] = &pending;
    }
  });
  for (std::size_t i = 0; i < conclude_count; ++i) {
    PendingRecord* pending = conclude[i];
    const std::size_t index = pending_.index_of(pending);
    DedupRecord* record = receipts_.find(
        [&](const DedupRecord& value) {
          return value.pending_index == index;
        });
    if (record == nullptr || record->state != DedupState::Pending) {
      release_pending(pending);   // orphaned slot — free it regardless
      continue;
    }
    // Deadline is the honest stored outcome: no success evidence arrived
    // inside the bounded window. The dedup record keeps answering
    // duplicates for its full hold; only the pending slot frees early.
    complete_pending(*record, endpoint::ServiceSubtype::Reject,
                     endpoint::ServiceReason::Deadline, now_ms);
  }
}

// --- Host seam --------------------------------------------------------------------------

void GatewayDelivery::on_host_ingress_ack(const MessageKey& key,
                                          const bool stored,
                                          const MonotonicMs now_ms) noexcept {
  DedupRecord* record = find_dedup(key);
  PendingRecord* pending =
      record != nullptr ? pending_.at(record->pending_index) : nullptr;
  if (record == nullptr || record->state != DedupState::Pending ||
      pending == nullptr || pending->state != PendingState::WaitHost) {
    return;   // stale/foreign ACK — never completes twice, never starts work
  }
  if (stored) {
    ++stats_.host_ingress_acked;
    ++stats_.host_ram_receipts;
    pending->state = PendingState::Received;
    complete_pending(*record, endpoint::ServiceSubtype::Receipt,
                     endpoint::ServiceReason::Ok, now_ms);
  } else {
    // A real storage failure is a final answer for this MessageKey — never
    // a second ingress attempt (03 §3.4).
    pending->state = PendingState::Received;
    complete_pending(*record, endpoint::ServiceSubtype::Reject,
                     endpoint::ServiceReason::HostUnavailable, now_ms);
  }
}

// --- Outcome assembly/emit -----------------------------------------------------------------

void GatewayDelivery::set_outcome(DedupRecord& record,
                                  const endpoint::ServiceSubtype subtype,
                                  const endpoint::ServiceReason reason) noexcept {
  record.outcome_subtype = subtype;
  record.outcome_reason = reason;
}

// Re-encodes from the stored decision fields every time, so a resend is
// byte-identical to the original outcome — the wire bytes are the evidence.
Status GatewayDelivery::emit_outcome(DedupRecord& record,
                                     const MonotonicMs now_ms) noexcept {
  endpoint::ServiceOutcome outcome{};
  outcome.subtype = record.outcome_subtype;
  outcome.scope = record.scope;
  outcome.token = record.token;
  outcome.gateway_boot = record.gateway_boot;
  outcome.ref_origin = record.key.origin;
  outcome.ref_session = record.key.id.session;
  outcome.ref_sequence = record.key.id.sequence;
  outcome.request_digest = record.request_digest;
  outcome.reason = record.outcome_reason;
  endpoint::EncodedServicePayload encoded{};
  const Status ok = endpoint::service_outcome_encode(outcome, encoded);
  if (!ok) return ok;
  MessageId emit_id{};
  const Status sent =
      node_.send_service(record.key.origin, encoded.view(), kOutcomeLifetimeMs,
                         Priority::Management, now_ms, emit_id);
  if (!sent) {
    ++stats_.outcomes_emit_failed;
    // A synchronous emit failure (queue pressure, route flap) schedules a
    // bounded re-emit on the poll tick — the stored outcome is the
    // evidence, retries are best-effort delivery of it.
    if (record.emit_retries < kEmitMaxRetries) {
      ++record.emit_retries;
      record.emit_pending = true;
      record.next_emit_ms = now_ms + kRetryBackoffMs;
    }
    return sent;
  }
  ++stats_.outcomes_emitted;
  record.emit_sequence = emit_id.sequence;
  return Status::success();
}

// Terminal completion for accepted work: store the final outcome on the
// dedup record (the resendable evidence), emit it, and release the pending
// slot unless the payload still lives in the mailbox.
void GatewayDelivery::complete_pending(DedupRecord& record,
                                       const endpoint::ServiceSubtype subtype,
                                       const endpoint::ServiceReason reason,
                                       const MonotonicMs now_ms) noexcept {
  set_outcome(record, subtype, reason);
  record.state = DedupState::Completed;
  (void)emit_outcome(record, now_ms);
  PendingRecord* pending = pending_.at(record.pending_index);
  if (pending != nullptr && !pending->mailbox_held) {
    release_pending(pending);
  }
}

void GatewayDelivery::release_pending(PendingRecord* pending) noexcept {
  if (pending == nullptr) return;
  const std::size_t index = pending_.index_of(pending);
  DedupRecord* owner = receipts_.find(
      [&](const DedupRecord& record) {
        return record.pending_index == index;
      });
  if (owner != nullptr) owner->pending_index = kNoPending;
  pending_.release(pending);
}

// --- Mailbox (GATEWAY_SDK_RAM evidence) --------------------------------------------------

std::size_t GatewayDelivery::mailbox_size() const noexcept {
  std::size_t count = 0;
  pending_.for_each([&](const PendingRecord& pending) {
    count += pending.mailbox_held ? 1U : 0U;
  });
  return count;
}

bool GatewayDelivery::mailbox_take(
    MessageKey& key, std::array<std::uint8_t, kGatewayPayloadMaxBytes>& payload,
    std::size_t& payload_size) noexcept {
  PendingRecord* entry = pending_.find(
      [](const PendingRecord& pending) { return pending.mailbox_held; });
  if (entry == nullptr) return false;
  key = entry->key;
  payload_size = entry->payload_size;
  if (payload_size > 0) {
    std::memcpy(payload.data(), entry->payload.data(), payload_size);
  }
  entry->mailbox_held = false;
  release_pending(entry);   // drained — the dedup record still holds the
  return true;              // outcome evidence for late duplicates
}

}  // namespace routeloom
