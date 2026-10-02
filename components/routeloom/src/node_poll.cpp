#include "node_internal.hpp"

namespace routeloom {

void MeshNode::process_awaiting_hop(const MonotonicMs now_ms) noexcept {
  saturating_add(work_stats_.expiry_slots_scanned, awaiting_hop_.capacity());
  awaiting_hop_.erase_if(
      [&](const AwaitingHop& value) { return value.expires_at_ms <= now_ms; },
      [&](AwaitingHop& expired) {
        TxJob& job = expired.job;
        if (expired.busy_deferred) {
          // BUSY deferral expiry re-admits the job under its BUSY readmission
          // budget — it is not an RF-loss retry (03 §5 separate accounting).
          readmit_after_busy(job, now_ms);
          return;
        }
        obs_hop_result(job, false, now_ms);
        // Hop-level timeout is its own counter — folded into rf_failures too,
        // but never reported under the wrong name (02 §counter identity).
        // Saturates with its flag set rather than wrapping silently.
        if (auto* bucket = job_bucket(job, now_ms)) {
          if (bucket->hop_timeouts != UINT32_MAX) {
            ++bucket->hop_timeouts;
          } else {
            bucket->saturation_mask |= kSatHopTimeouts;
          }
        }
        saturating_inc(work_stats_.hop_accept_expired);
        retry_or_fail(job, "HOP_ACCEPT_TIMEOUT", now_ms);
      });
}

void MeshNode::process_delivery_timeouts(const MonotonicMs now_ms) noexcept {
  deliveries_.for_each([&](Delivery& delivery) {
    if (delivery.state == DeliveryState::Delivered || delivery.state == DeliveryState::Failed ||
        delivery.state == DeliveryState::Expired ||
        delivery.state == DeliveryState::CancelledBeforeTx ||
        delivery.state == DeliveryState::Indeterminate) {
      return;
    }
    if (now_ms >= delivery.expires_at_ms) {
      // APPLIED (01 §1.3): a transmitted APPLIED request may already have
      // executed at the destination — post-TX expiry is Indeterminate,
      // never the unproven Failed and never END_RECEIVED-promoted.
      if (delivery.options.delivery == DeliveryClass::Applied && delivery.transmitted) {
        set_delivery_state(delivery, DeliveryState::Indeterminate,
                           "APP_RESULT_TIMEOUT");
        return;
      }
      set_delivery_state(delivery, DeliveryState::Expired, "DEADLINE_EXPIRED");
      return;
    }
    // While retry rounds are paused (sleep drain or an operational pause),
    // the deliveries wait for their disposition instead of making new work.
    if (delivery.order_wait) {
      // Held behind its ordered predecessor: released once the predecessor
      // is Delivered (or gone as never-sent) or its deadline passed — the
      // head-of-line wait never outlives the predecessor's lifetime.
      const Delivery* predecessor = find_delivery(delivery.order_after);
      const bool settled =
          predecessor != nullptr &&
          (predecessor->state == DeliveryState::Delivered ||
           predecessor->state == DeliveryState::CancelledBeforeTx);
      if (!settled && now_ms < delivery.order_hold_until_ms) return;
      if (paused(pause::kRetryRounds)) return;
      delivery.order_wait = false;
      delivery.next_round_at_ms = now_ms;
    }
    if (!paused(pause::kRetryRounds) &&
        (delivery.state == DeliveryState::WaitingForRoute ||
         delivery.state == DeliveryState::WaitingForEndReceipt) &&
        now_ms >= delivery.next_round_at_ms) {
      if (delivery.state == DeliveryState::WaitingForEndReceipt) {
        if (delivery.options.delivery == DeliveryClass::Applied &&
            delivery.app_phase != 0) {
          // Application-pending window elapsed: bounded QUERY recovery
          // (<=kAppliedMaxQueries), then the delivery simply waits out its
          // deadline — a late RESULT still resolves it (01 §1.3).
          if (delivery.app_queries < kAppliedMaxQueries) {
            delivery.app_query_nonce = next_app_nonce_++;
            if (emit_app_query(delivery, now_ms)) {
              ++delivery.app_queries;
            }
            delivery.next_round_at_ms = std::min(
                delivery.expires_at_ms,
                now_ms + applied_window_ms(delivery.options.hop_limit,
                                           config_.hop_accept_timeout_ms));
          } else {
            delivery.next_round_at_ms = delivery.expires_at_ms;
          }
          return;
        }
        if (static_cast<std::uint8_t>(delivery.round + 1U) >=
            config_.max_end_to_end_rounds) {
          // For APPLIED the last round's DATA may have landed and executed —
          // Indeterminate, not the unproven Failed (01 §1.9).
          set_delivery_state(
              delivery,
              delivery.options.delivery == DeliveryClass::Applied
                  ? DeliveryState::Indeterminate
                  : DeliveryState::Failed,
              delivery.options.delivery == DeliveryClass::Applied
                  ? "APP_RESULT_TIMEOUT"
                  : "END_RECEIPT_TIMEOUT");
          return;
        }
        ++delivery.round;
      }
      const auto status = queue_origin_data(delivery, now_ms);
      if (!status) {
        delivery.next_round_at_ms = now_ms + 100;
        set_delivery_state(delivery, DeliveryState::WaitingForRoute, status.detail);
      }
    }
  });
}

void MeshNode::expire_dedup(const MonotonicMs now_ms) noexcept {
  saturating_add(work_stats_.expiry_slots_scanned, dedup_.capacity());
  const std::size_t expired = dedup_.erase_if(
      [&](const DedupEntry& value) { return value.expires_at_ms <= now_ms; });
  saturating_add(dedup_stats_.expired, expired);
}

Status MeshNode::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) return Status::success();
  last_clock_ms_ = now_ms;
  // Expired/revoked admission transactions close before anything else may
  // transmit: no new TX leaves on a dead transaction (design-q116 §7.2).
  sweep_transactions(now_ms);
  saturating_add(work_stats_.expiry_slots_scanned, routes_.expire(now_ms));
  // P3 (03 §6/§7): decay the per-peer observation windows, release stale
  // busy feedback at its TTL, refresh effective link costs and advance the
  // route-switch hysteresis before any selection change is advertised.
  refresh_neighbor_load(now_ms);
  expire_dedup(now_ms);
  expire_sequence_requests(now_ms);
  process_awaiting_hop(now_ms);
  process_delivery_timeouts(now_ms);
  // APPLIED terminal bookkeeping: result-record retention expiry and the
  // bounded RESULT emit retry pass (sdk-completion/01 §1.4/§1.6).
  process_applied(now_ms);
  // Group delivery (group-delivery.md): report deadlines, source rounds and
  // admission, ordered-hold release, retention expiry.
  process_group(now_ms);
  scan_selection_changes(now_ms);
  if (gateway_scoped()) expire_route_requests(now_ms);
  if (!paused(pause::kBackgroundWork)) {
    // Background work stops while paused/draining; in-flight queue entries
    // still dispatch below so the TX path can settle.
    run_triggered_advertisement(now_ms);
    schedule_sequence_requests(now_ms);
    schedule_route_advertisements(now_ms);
    if (!gateway_scoped()) schedule_route_discovery(now_ms);
    if (gateway_scoped()) {
      // Scoped profile repair/bootstrap and on-demand paths (routing-scale
      // §3.3/§4): answers to pulls, pulls for a lost gateway route and
      // bounded discovery for waiting deliveries.
      flush_pull_answers(now_ms);
      schedule_parent_releases(now_ms);
      schedule_gateway_pulls(now_ms);
      schedule_route_discovery(now_ms);
    }
  }
  // The Service/config components are driven by the Owner outside node
  // calls (design-q116 §8.3): their poll() no longer runs here, and their
  // payloads/completions wait in the component event queue for take/complete.
  dispatch_next(now_ms);
  return Status::success();
}

}  // namespace routeloom
