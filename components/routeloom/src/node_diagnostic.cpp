#include "node_internal.hpp"

namespace routeloom {

// ---------------------------------------------------------------------------
// D1c Diagnostic (48) dispatch (02-telemetry §4.2)
// ---------------------------------------------------------------------------

Status MeshNode::send_telemetry_query(const NodeId observer,
                                      const TelemetryQuery& query,
                                      const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "node not started");
  }
  if (observer == kInvalidNodeId || observer == kBroadcastNodeId ||
      observer == config_.node) {
    return Status::error(StatusCode::InvalidArgument, "invalid observer");
  }
  std::array<std::uint8_t, kTelemetryQueryBodySize> body{};
  const Status status =
      telemetry_query_encode(query, MutableByteView{body.data(), body.size()});
  if (!status) return status;
  // Bounded reply path: the query's own lifetime (capped at the 5 s design
  // bound) limits how long the exchange may occupy the routed lane.
  const MessageId id{config_.message_session, next_control_sequence_++};
  return queue_typed_job(FrameType::Diagnostic, JobOwner::Diagnostic, id,
                         observer, ByteView{body.data(), body.size()}, 0,
                         kTelemetryQueryLifetimeMs, Priority::Normal, now_ms);
}

Status MeshNode::send_observation_query(const NodeId observer,
                                        const RemoteObservationQuery& query,
                                        const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "node not started");
  }
  if (observer == kInvalidNodeId || observer == kBroadcastNodeId ||
      observer == config_.node) {
    return Status::error(StatusCode::InvalidArgument, "invalid observer");
  }
  std::array<std::uint8_t, kRemoteObservationQueryBodySize> body{};
  const Status status =
      remote_observation_query_encode(query, MutableByteView{body.data(), body.size()});
  if (!status) return status;
  // Same 5 s routed-lane bound as the telemetry query: the reply borrows
  // the query's own remaining deadline and never extends it.
  const MessageId id{config_.message_session, next_control_sequence_++};
  return queue_typed_job(FrameType::Diagnostic, JobOwner::Diagnostic, id,
                         observer, ByteView{body.data(), body.size()}, 0,
                         kTelemetryQueryLifetimeMs, Priority::Normal, now_ms);
}

Status MeshNode::send_capabilities_query(
    const NodeId peer,
    const std::array<std::uint8_t, kCapabilitiesNonceSize>& nonce,
    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "node not started");
  }
  auto* const neighbor = find_neighbor(peer);
  if (peer == kInvalidNodeId || peer == kBroadcastNodeId ||
      peer == config_.node || neighbor == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "invalid peer");
  }
  // Renewal bound (04 §capabilities): a completed or granted exchange may
  // not be restarted for the same peer inside kCapQueryRenewalMs —
  // capability probing is bounded airtime, not a polling primitive.
  if (neighbor->last_cap_exchange_ms != 0 &&
      now_ms - neighbor->last_cap_exchange_ms < kCapQueryRenewalMs) {
    return Status::error(StatusCode::Busy, "capability query renewal bound");
  }
  // One outstanding query per peer; replies beyond their lifetime are
  // never matched (04 §capabilities).
  PendingCapQuery* free_slot = nullptr;
  for (auto& p : pending_caps_) {
    if (p.peer == kInvalidNodeId) {
      if (free_slot == nullptr) free_slot = &p;
      continue;
    }
    if (p.expires_at_ms <= now_ms) {
      if (free_slot == nullptr) free_slot = &p;
      continue;
    }
    if (p.peer == peer) {
      return Status::error(StatusCode::Busy, "capability query outstanding");
    }
  }
  if (free_slot == nullptr) {
    return Status::error(StatusCode::NoCapacity, "capability query table full");
  }
  CapabilitiesQuery query{};
  query.nonce = nonce;
  std::array<std::uint8_t, kCapabilitiesQueryBodySize> body{};
  Status status =
      capabilities_query_encode(query, MutableByteView{body.data(), body.size()});
  if (!status) return status;
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::Diagnostic;
  job.peer = peer;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::Diagnostic;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = peer;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = peer;
  job.plain.header.message =
      MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  std::memcpy(job.plain.payload.data(), body.data(), body.size());
  job.plain.payload_size = body.size();
  if (!scheduler_.enqueue(std::move(job), config_.node, now_ms)) {
    return Status::error(StatusCode::NoCapacity, "tx queue full");
  }
  free_slot->peer = peer;
  free_slot->nonce = nonce;
  free_slot->expires_at_ms = now_ms + kCapQueryLifetimeMs;
  // Pin the peer's binding generation at query time: a reply that arrives
  // after a rebind is stale evidence and must not grant capability.
  if (const auto* summary = telemetry_peers_.find(peer);
      summary != nullptr && summary->occupied) {
    free_slot->binding = summary->binding;
  } else {
    free_slot->binding = BindingGeneration{0};
  }
  return Status::success();
}

Status MeshNode::queue_diagnostic_reply(const NodeId destination,
                                        const ByteView body,
                                        const std::uint32_t lifetime_ms,
                                        const MonotonicMs now_ms) noexcept {
  const MessageId id{config_.message_session, next_control_sequence_++};
  return queue_typed_job(FrameType::Diagnostic, JobOwner::Diagnostic, id,
                         destination, body, 0, lifetime_ms, Priority::Normal,
                         now_ms);
}

Status MeshNode::build_telemetry_snapshot(
    const TelemetryQuery& query, const MonotonicMs now_ms,
    TelemetrySnapshot& out, DiagnosticRejectReason& reject_reason) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  return build_telemetry_snapshot_impl(query, now_ms, out, reject_reason);
}

Status MeshNode::build_telemetry_snapshot_impl(
    const TelemetryQuery& query, const MonotonicMs now_ms,
    TelemetrySnapshot& out, DiagnosticRejectReason& reject_reason) noexcept {
  const PeerTelemetrySummary* summary = telemetry_peers_.find(query.peer);
  if (summary == nullptr) {
    reject_reason = DiagnosticRejectReason::NoPeer;
    return Status::error(StatusCode::NotFound, "no telemetry for peer");
  }
  if (summary->stale) {
    reject_reason = DiagnosticRejectReason::Stale;
    return Status::error(StatusCode::InvalidState, "telemetry stale");
  }

  // Freshness is judged ONLY from the measurements that contribute each
  // field group (02 §2.4): an unrelated recent frame can never relabel an
  // old RSSI aggregate as fresh, bookkeeping timestamps never freshen a
  // bucket, and a bound the contributing measurements cannot meet rejects
  // the whole snapshot as STALE instead of returning stale data with
  // cleared bits.
  const ObservationBucket* bucket = nullptr;
  if (query.length_class != kTelemetryPeerSummaryClass) {
    const ObservationKey key{summary->binding, query.direction,
                             summary->radio, summary->channel,
                             query.length_class, query.peer};
    bucket = telemetry_bucket(key);
  }
  // Contributing measurement stamps: RSSI group → last_rssi_ms; bucket
  // group → the current window's OLDEST contributing sample
  // (first_sample_ms — never last_update_ms bookkeeping, and never the
  // newest sample which would overstate freshness).
  MonotonicMs oldest_contributing = 0;
  const bool rssi_contributes = summary->rssi_present;
  const bool bucket_contributes =
      bucket != nullptr && bucket->current.present &&
      bucket->current.first_sample_ms != 0;
  if (rssi_contributes) oldest_contributing = summary->last_rssi_ms;
  if (bucket_contributes &&
      (oldest_contributing == 0 ||
       bucket->current.first_sample_ms < oldest_contributing)) {
    oldest_contributing = bucket->current.first_sample_ms;
  }
  const auto within_bound = [&](const MonotonicMs stamp) {
    return stamp != 0 && now_ms - stamp <= query.max_age_ms;
  };
  // A nonzero bound must be satisfiable by at least one contributing
  // measurement; max_age_ms == 0 means "no bound requested".
  if (query.max_age_ms != 0 &&
      !(rssi_contributes && within_bound(summary->last_rssi_ms)) &&
      !(bucket_contributes &&
        within_bound(bucket->current.first_sample_ms))) {
    reject_reason = DiagnosticRejectReason::Stale;
    return Status::error(StatusCode::Expired,
                         "no contributing measurement within bound");
  }

  out = TelemetrySnapshot{};
  out.request_id = query.request_id;
  out.observer = config_.node;
  out.observer_boot = config_.boot_incarnation;
  out.peer = query.peer;
  out.binding = summary->binding;
  out.radio = summary->radio;
  out.channel_epoch = summary->channel;
  out.channel = summary->channel_present ? summary->last_channel : 0;
  out.direction = query.direction;
  out.length_class = query.length_class;
  out.sampled_at_ms = oldest_contributing;
  // sample_age is the age of the OLDEST contributing measurement — a
  // conservative freshness claim that never rides on unrelated activity.
  out.sample_age_ms =
      oldest_contributing != 0 && now_ms > oldest_contributing
          ? static_cast<std::uint32_t>(now_ms - oldest_contributing)
          : 0;
  out.event_drops = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(telemetry_event_drops_, UINT32_MAX));

  const bool rssi_fresh =
      summary->rssi_present &&
      (query.max_age_ms == 0 || within_bound(summary->last_rssi_ms));
  if (summary->rssi_present) {
    if (rssi_fresh) out.validity |= kTelemetryValidRssi;
    out.rssi_last = summary->rssi_last;
    out.rssi_min = summary->rssi_min;
    out.rssi_max = summary->rssi_max;
    out.rssi_ewma_q8_8 = summary->rssi_ewma_q8_8;
    out.rssi_samples = summary->rssi_samples;
    if (summary->rssi_saturated) out.saturation_mask |= kSatRssiSamples;
  }
  // Source bits reflect EVERY contributing group: the peer summary's own
  // provenance plus the detailed bucket's window source mask — an injected
  // TX measurement is never serialized as driver-derived evidence.
  out.validity |= summary->provenance == ObservationProvenance::LocalDriver
                      ? kTelemetrySourceLocalDriver
                      : kTelemetrySourceInjectedTest;
  if (bucket != nullptr) {
    const std::uint8_t src = bucket->current.sources;
    if (src & (1u << static_cast<unsigned>(ObservationProvenance::LocalDriver))) {
      out.validity |= kTelemetrySourceLocalDriver;
    }
    if (src & (1u << static_cast<unsigned>(ObservationProvenance::InjectedTest))) {
      out.validity |= kTelemetrySourceInjectedTest;
    }
  }
  if (summary->stale || (summary->rssi_present && !rssi_fresh)) {
    out.validity |= kTelemetryStale;
  }

  // A peer-summary-class query stops at the RSSI record; a bucket class
  // additionally fills the counters for that exact observation key.
  if (query.length_class != kTelemetryPeerSummaryClass) {
    if (bucket != nullptr) {
      const auto clamp = [](const std::uint64_t v) {
        return static_cast<std::uint32_t>(std::min<std::uint64_t>(v, UINT32_MAX));
      };
      // Lifetime counters are reported as lifetime values regardless of
      // freshness; the bucket-validity bit asserts a contributing sample
      // inside the requested bound — bookkeeping stamps never count.
      const bool bucket_fresh =
          query.max_age_ms == 0
              ? bucket_contributes
              : within_bound(bucket->current.first_sample_ms);
      if (bucket_fresh) out.validity |= kTelemetryValidBucket;
      out.window_ms = static_cast<std::uint32_t>(
          std::min<std::uint64_t>(now_ms - bucket->window_start_ms, UINT32_MAX));
      out.tx_submitted = clamp(bucket->tx_submitted);
      out.tx_mac_success = bucket->tx_mac_success;
      out.tx_mac_fail = bucket->tx_mac_fail;
      out.tx_unknown = clamp(bucket->unknown_results);
      out.sdk_retries = bucket->sdk_retries;
      out.hop_accepts = clamp(bucket->hop_accepted);
      out.hop_timeouts = bucket->hop_timeouts;
      out.busy = clamp(bucket->busy_deferrals);
      // Queue EWMA is a current-window measurement like the driver EWMA —
      // only reported when the window contributed queue samples.
      if (bucket->current.queue_samples > 0 && bucket_fresh) {
        out.queue_us_ewma = bucket->current.queue_us_ewma;
      }
      // The driver-service EWMA is only fresh evidence when the CURRENT
      // window actually contributed a driver measurement — a lifetime
      // aggregate freshened by an unrelated observation would misreport
      // stale data as current (02 §2.4).
      if (bucket->current.driver_samples > 0 && bucket_fresh) {
        out.validity |= kTelemetryValidDriverEwma;
        out.driver_us_ewma = bucket->current.driver_us_ewma;
      }
      // Same window-freshness rule for the HOP_ACCEPT RTT EWMA (radio.md §8).
      if (bucket->current.hop_rtt_samples > 0 && bucket_fresh) {
        out.validity |= kTelemetryValidHopRttEwma;
        out.hop_rtt_us_ewma = bucket->current.hop_rtt_us_ewma;
      }
      out.saturation_mask |= bucket->saturation_mask;
      if (bucket->stale || !bucket_fresh) out.validity |= kTelemetryStale;
      if (bucket->current.incomplete) out.validity |= kTelemetryWindowIncomplete;
    }
    // No matching bucket is not an error: the summary stands alone with the
    // bucket-validity bit clear (04 §4.2 — never invent a zero measurement).
  }
  return Status::success();
}

// CapabilitiesReply (04 §capabilities): advertises only what is wired AND
// currently permitted — forward_v1 requires the live relay gate, not just
// build support; permit_profiles lists only profiles with a ready endpoint.
MeshNode::DiagBudget* MeshNode::diag_budget(const NodeId peer,
                                            const MonotonicMs now_ms) noexcept {
  DiagBudget* free_slot = nullptr;
  DiagBudget* reclaimable = nullptr;
  for (auto& entry : diag_budget_) {
    if (entry.peer == peer) {
      // Single window-reset point: every pacing counter tied to this
      // window resets together — callers only test/increment, never
      // re-check the elapsed condition (it is already consumed here).
      if (now_ms - entry.window_start_ms >= kDiagBudgetWindowMs) {
        entry.window_start_ms = now_ms;
        entry.window_used = 0;
        entry.failure_window_used = 0;
      }
      return &entry;
    }
    if (entry.peer == kInvalidNodeId) {
      if (free_slot == nullptr) free_slot = &entry;
      continue;
    }
    // A slot whose every pacing restriction has expired carries no live
    // state — reclaiming it is not eviction, it is reuse of an entry that
    // enforces nothing. This bounds residency without ever losing live
    // pacing history.
    const bool expired =
        now_ms - entry.window_start_ms >= kDiagBudgetWindowMs &&
        (entry.last_cap_reply_ms == 0 ||
         now_ms - entry.last_cap_reply_ms >= kCapReplyMinIntervalMs) &&
        (entry.last_query_ms == 0 ||
         now_ms - entry.last_query_ms >= kDiagQueryMinIntervalMs);
    if (expired &&
        (reclaimable == nullptr ||
         entry.window_start_ms < reclaimable->window_start_ms)) {
      reclaimable = &entry;
    }
  }
  // A full table NEVER evicts a live budget — eviction would silently
  // reset that peer's pacing state. nullptr is a refusal: callers drop and
  // count, they do not admit unbounded work.
  if (free_slot == nullptr) free_slot = reclaimable;
  if (free_slot == nullptr) return nullptr;
  *free_slot = DiagBudget{};
  free_slot->peer = peer;
  free_slot->window_start_ms = now_ms;
  return free_slot;
}

CapabilitiesReply MeshNode::build_capabilities_reply(
    const std::array<std::uint8_t, kCapabilitiesNonceSize>& echo_nonce)
    const noexcept {
  CapabilitiesReply reply{};
  reply.echo_nonce = echo_nonce;
  reply.node_boot = config_.boot_incarnation;
  reply.features = kCapLocalTelemetryV1 | kCapTransitFailureV1 | kCapBusyV1;
  // forward_v1 additionally requires the live relay gate (04 §capabilities).
  if (transit_permitted()) reply.features |= kCapForwardV1;
  if (telemetry_remote_) reply.features |= kCapRemoteTelemetryV1;
  // The broadcast bit names a wired receiver: scoped opt-in only, so a
  // legacy or flat peer never grants it (routing-scale.md §8).
  if (config_.route_broadcast) reply.features |= kCapRouteBroadcastV1;
  // Only the configured+ready verifier's bit — never every compiled profile.
  if (config_sink_ != nullptr) {
    ExternalCallbackScope scope(in_external_callback_);
    reply.permit_profiles = config_sink_->permit_profile_bits();
  }
  reply.valid_for_ms = kCapabilitiesValidityMs;
  return reply;
}

void MeshNode::handle_diagnostic(const wire::PlainFrame& frame,
                                 const NodeId peer,
                                 const MonotonicMs now_ms) noexcept {
  const ByteView body{frame.payload.data(), frame.payload_size};
  // Subtype dispatch happens on the end-verified body only — a malformed or
  // unversioned body is a drop, never a fallthrough to a link-only parser.
  if (body.size < kDiagnosticPrefixSize || body.data[0] != kDiagnosticBodyVersion ||
      body.data[2] != 0 || body.data[3] != 0) {
    observer_.on_diagnostic("DIAGNOSTIC_BODY_REJECTED", peer,
                            &frame.header.message);
    return;
  }
  const auto subtype = static_cast<DiagnosticSubtype>(body.data[1]);
  const auto origin = frame.header.origin;
  const std::uint32_t lifetime_ms = frame.header.remaining_deadline_ms;

  auto reply_reject = [&](const DiagnosticRejectReason reason,
                          const std::uint32_t request_id) {
    DiagnosticReject reject{};
    reject.request_id = request_id;
    reject.reason = reason;
    reject.observer = config_.node;
    std::array<std::uint8_t, kDiagnosticRejectBodySize> out{};
    if (!diagnostic_reject_encode(reject,
                                  MutableByteView{out.data(), out.size()})) {
      return;
    }
    if (!queue_diagnostic_reply(origin, ByteView{out.data(), out.size()},
                                lifetime_ms, now_ms)) {
      // A reject that cannot be queued is a counted loss, never a spin.
      ++telemetry_event_drops_;
    }
  };

  switch (subtype) {
    case DiagnosticSubtype::TelemetryQuery: {
      TelemetryQuery query{};
      if (!telemetry_query_decode(body, query).ok()) {
        observer_.on_diagnostic("DIAGNOSTIC_QUERY_REJECTED", peer,
                                &frame.header.message);
        return;
      }
      // Bounded intake: at most one diagnostic query per origin per
      // interval — a requester cannot convert authenticated queries into
      // airtime floods (telemetry §2.7; queries are costly: 644 B/edge).
      // The telemetry and observation subtypes share the one pacing
      // stamp per origin. Budget-table exhaustion refuses rather than
      // admitting untracked work.
      DiagBudget* const qbudget = diag_budget(origin, now_ms);
      if (qbudget == nullptr ||
          (qbudget->last_query_ms != 0 &&
           now_ms - qbudget->last_query_ms < kDiagQueryMinIntervalMs)) {
        ++telemetry_event_drops_;
        return;
      }
      qbudget->last_query_ms = now_ms;
      if (!telemetry_remote_) {
        reply_reject(DiagnosticRejectReason::Denied, query.request_id);
        return;
      }
      TelemetrySnapshot snapshot{};
      DiagnosticRejectReason reason{};
      if (!build_telemetry_snapshot_impl(query, now_ms, snapshot, reason)) {
        reply_reject(reason, query.request_id);
        return;
      }
      std::array<std::uint8_t, kTelemetrySnapshotBodySize> out{};
      if (!telemetry_snapshot_encode(snapshot,
                                     MutableByteView{out.data(), out.size()})) {
        ++telemetry_event_drops_;
        return;
      }
      if (!queue_diagnostic_reply(origin, ByteView{out.data(), out.size()},
                                  lifetime_ms, now_ms)) {
        ++telemetry_event_drops_;
      }
      return;
    }
    case DiagnosticSubtype::RemoteObservationQuery: {
      RemoteObservationQuery query{};
      if (!remote_observation_query_decode(body, query).ok()) {
        observer_.on_diagnostic("DIAGNOSTIC_QUERY_REJECTED", peer,
                                &frame.header.message);
        return;
      }
      // Same shared pacing stamp as the telemetry query above: one
      // diagnostic query per origin per interval, whatever the subtype.
      DiagBudget* const qbudget = diag_budget(origin, now_ms);
      if (qbudget == nullptr ||
          (qbudget->last_query_ms != 0 &&
           now_ms - qbudget->last_query_ms < kDiagQueryMinIntervalMs)) {
        ++telemetry_event_drops_;
        return;
      }
      qbudget->last_query_ms = now_ms;
      if (!observation_remote_) {
        reply_reject(DiagnosticRejectReason::Denied, query.request_id);
        return;
      }
      RemoteObservationSnapshot snapshot{};
      DiagnosticRejectReason reason{};
      if (!build_observation_snapshot_impl(query, now_ms, snapshot, reason)) {
        reply_reject(reason, query.request_id);
        return;
      }
      std::array<std::uint8_t, kRemoteObservationSnapshotBodyMax> out{};
      if (!remote_observation_snapshot_encode(snapshot,
                                       MutableByteView{out.data(), out.size()})) {
        ++telemetry_event_drops_;
        return;
      }
      const std::size_t total = kRemoteObservationSnapshotHeadSize + snapshot.body_size;
      if (!queue_diagnostic_reply(origin, ByteView{out.data(), total},
                                  lifetime_ms, now_ms)) {
        ++telemetry_event_drops_;
      }
      return;
    }
    case DiagnosticSubtype::TelemetrySnapshot:
    case DiagnosticSubtype::RemoteObservationSnapshot:
    case DiagnosticSubtype::DiagnosticReject:
      if (diagnostic_sink_ != nullptr) {
        ExternalCallbackScope scope(in_external_callback_);
        diagnostic_sink_->on_diagnostic_body(origin, body, now_ms);
      } else {
        observer_.on_diagnostic("DIAGNOSTIC_NO_ENDPOINT", peer,
                                &frame.header.message);
      }
      return;
    default:
      // Unknown/unsupported subtype on an authenticated body: honest reject
      // when a request_id is present, otherwise a counted drop (04 §4.2).
      if (body.size >= 8) {
        std::uint32_t request_id = 0;
        for (int i = 0; i < 4; ++i) {
          request_id = (request_id << 8U) | body.data[4 + i];
        }
        reply_reject(DiagnosticRejectReason::Unsupported, request_id);
      } else {
        ++telemetry_event_drops_;
      }
      return;
  }
}

void MeshNode::handle_diagnostic_link(const NodeId peer,
                                      const wire::LinkOpenedFrame& frame,
                                      const RxBinding& rx,
                                      const MonotonicMs now_ms) noexcept {
  // Link-only Diagnostic subtypes (CapabilitiesQuery/Reply, TransitFailure):
  // link-authenticated hop-1 traffic — surfaced to the sink for correlation,
  // never forwarded and never answered on a routed lane.
  const ByteView body{frame.protected_payload.data(),
                      frame.header.payload_length};
  if (body.size < kDiagnosticPrefixSize ||
      body.data[0] != kDiagnosticBodyVersion) {
    observer_.on_diagnostic("DIAGNOSTIC_BODY_REJECTED", peer,
                            &frame.header.message);
    return;
  }
  const auto subtype = static_cast<DiagnosticSubtype>(body.data[1]);
  if (subtype == DiagnosticSubtype::TransitFailure) {
    // Bounded intake (01 §evidence): a peer cannot convert reports into
    // unbounded dedup/seen-table scans — at most kTransitFailurePerWindow
    // decodable bodies per peer per second.
    DiagBudget* budget = diag_budget(peer, now_ms);
    if (budget == nullptr ||
        budget->failure_window_used >= kTransitFailurePerWindow) {
      ++telemetry_event_drops_;
      return;
    }
    TransitFailure report{};
    if (transit_failure_decode(body, report).ok()) {
      ++budget->failure_window_used;
      // Node-internal correlation/propagation first; the sink still sees
      // the body so a host can surface upstream failure evidence.
      handle_transit_failure_report(peer, report, now_ms);
      if (diagnostic_sink_ != nullptr) {
        ExternalCallbackScope scope(in_external_callback_);
        diagnostic_sink_->on_diagnostic_body(peer, body, now_ms);
      }
    } else {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("TRANSIT_FAILURE_REJECTED", peer,
                              &frame.header.message);
    }
    return;
  }
  if (subtype == DiagnosticSubtype::CapabilitiesQuery) {
    CapabilitiesQuery query{};
    if (!capabilities_query_decode(body, query).ok()) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_QUERY_REJECTED", peer,
                              &frame.header.message);
      return;
    }
    // Bounded reply pacing: one capability reply per peer per second —
    // a querier cannot convert link-only probes into airtime floods.
    DiagBudget* budget = diag_budget(peer, now_ms);
    // last_*_ms == 0 means "never used": the first query is always admitted
    // even when the node clock starts near zero. A full budget table
    // refuses — unbounded replies are never emitted.
    if (budget == nullptr || (budget->last_cap_reply_ms != 0 &&
        now_ms - budget->last_cap_reply_ms < kCapReplyMinIntervalMs)) {
      ++telemetry_event_drops_;
      return;
    }
    CapabilitiesReply reply = build_capabilities_reply(query.nonce);
    std::array<std::uint8_t, kCapabilitiesReplyBodySize> out{};
    if (!capabilities_reply_encode(reply,
                                   MutableByteView{out.data(), out.size()})) {
      ++telemetry_event_drops_;
      return;
    }
    TxJob job{};
    job.form = JobForm::Plain;
    job.owner = JobOwner::Diagnostic;
    job.peer = peer;
    job.requires_hop_accept = false;
    job.max_attempts = 1;
    job.deadline_ms = now_ms + kControlLifetimeMs;
    job.plain.header.type = FrameType::Diagnostic;
    job.plain.header.delivery = DeliveryClass::BestEffort;
    job.plain.header.hop_remaining = 1;
    job.plain.header.network = config_.network;
    job.plain.header.origin = config_.node;
    job.plain.header.destination = peer;
    job.plain.header.previous_hop = config_.node;
    job.plain.header.next_hop = peer;
    job.plain.header.message =
        MessageId{config_.message_session, next_control_sequence_++};
    job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
    job.plain.header.original_lifetime_ms = kControlLifetimeMs;
    job.plain.header.link_epoch = config_.link_epoch;
    job.plain.header.end_epoch = config_.end_epoch;
    std::memcpy(job.plain.payload.data(), out.data(), out.size());
    job.plain.payload_size = out.size();
    // Link-local replies hold a short transaction on the receive's
    // evidence, like every other reply — unaffordable answers are counted
    // drops, and only an actually queued answer spends the rate budget.
    AdmissionReservation res{};
    if (!rx.valid ||
        !reserve_rx_reply(rx, /*needs_control_slot=*/false, 1, now_ms,
                          res)) {
      ++telemetry_event_drops_;
      return;
    }
    job.txn = res.txn;
    if (scheduler_.enqueue(std::move(job), config_.node, now_ms)) {
      join_txn(res.txn);
      res.committed = true;
      budget->last_cap_reply_ms = now_ms;
    } else {
      ++telemetry_event_drops_;
    }
    return;
  }
  if (subtype == DiagnosticSubtype::CapabilitiesReply) {
    CapabilitiesReply reply{};
    if (!capabilities_reply_decode(body, reply).ok()) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_REJECTED", peer,
                              &frame.header.message);
      return;
    }
    // The reply must echo a nonce from OUR outstanding query to this peer
    // (04 §capabilities): unsolicited or stale replies never grant
    // capability. Consume the pending entry on match.
    auto* pending = std::find_if(
        pending_caps_.begin(), pending_caps_.end(),
        [&](const PendingCapQuery& p) {
          return p.peer == peer && p.expires_at_ms > now_ms &&
                 p.nonce == reply.echo_nonce;
        });
    if (pending == pending_caps_.end()) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_UNSOLICITED", peer,
                              &frame.header.message);
      return;
    }
    // The reply must answer under the SAME binding generation the query
    // was issued in — a post-rebind reply is stale evidence. A summary
    // already marked stale proves the rebind happened; binding 0 recorded
    // at query time means no binding was known, so the reply's own
    // (fresh) binding establishes the baseline rather than violating it.
    const auto* summary = telemetry_peers_.find(peer);
    const bool summary_current = summary != nullptr && !summary->stale;
    const BindingGeneration current_binding =
        summary_current ? summary->binding : BindingGeneration{0};
    const bool binding_violated =
        summary != nullptr && summary->stale
            ? true  // stale summary = a rebind happened after the query
            : pending->binding != BindingGeneration{0} &&
                  current_binding != pending->binding;
    // Consuming a pending entry — matched or not — still paces renewal:
    // otherwise a rejected reply would permit an immediate reprobe storm.
    if (auto* neighbor = find_neighbor(peer)) {
      neighbor->last_cap_exchange_ms = now_ms;
    }
    *pending = PendingCapQuery{};
    if (binding_violated) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_STALE_BINDING", peer,
                              &frame.header.message);
      return;
    }
    // A reply must name a concrete responder boot — node_boot==0 means the
    // peer never initialized an incarnation, so the grant cannot be bound
    // to any identity (04 §capabilities).
    if (reply.node_boot == 0) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_NO_BOOT", peer,
                              &frame.header.message);
      return;
    }
    // The grant is bounded by the reply's own valid_for_ms under the
    // responder's boot identity — clamped to the protocol's validity bound
    // so a reply cannot mint an unbounded grant, and valid_for_ms==0 is
    // an explicit no-grant rather than a silent default (04 §capabilities).
    if (auto* neighbor = find_neighbor(peer)) {
      const std::uint32_t grant_ms =
          reply.valid_for_ms < kCapabilitiesValidityMs
              ? reply.valid_for_ms
              : kCapabilitiesValidityMs;
      neighbor->cap_node_boot = reply.node_boot;
      neighbor->cap_valid_until_ms = grant_ms != 0 ? now_ms + grant_ms : 0;
      neighbor->last_cap_exchange_ms = now_ms;
      // The whole granted bitmask is retained per recipient under the same
      // validity window — a grant without the broadcast bit authorizes no
      // broadcast, and valid_for_ms==0 clears every permission at once.
      neighbor->cap_features = grant_ms != 0 ? reply.features : 0;
      neighbor->busy_capable =
          grant_ms != 0 && (reply.features & kCapBusyV1) != 0;
    }
    if (diagnostic_sink_ != nullptr) {
      ExternalCallbackScope scope(in_external_callback_);
      diagnostic_sink_->on_diagnostic_body(peer, body, now_ms);
    }
    return;
  }
  // Routed subtypes (TelemetryQuery/Snapshot/Reject) on the link-only lane
  // are a protocol violation: they lack end protection and can never be
  // authenticated as their claimed origin. Never feed them to a sink that
  // would resolve pending end-authenticated queries (04 §4.2).
  ++telemetry_event_drops_;
  observer_.on_diagnostic("DIAGNOSTIC_LINK_SCOPE_VIOLATION", peer,
                          &frame.header.message);
}

}  // namespace routeloom
