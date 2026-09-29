#include "node_internal.hpp"

namespace routeloom {

// ---------------------------------------------------------------------------
// Congestion observation + stats surface (03 §3 groundwork for P3)
// ---------------------------------------------------------------------------

ObservationBucket* MeshNode::observation_bucket(
    const ObservationKey& key, const MonotonicMs now_ms) noexcept {
  auto* existing = observations_.find(
      [&](const ObservationBucket& value) { return value.key == key; });
  if (existing != nullptr) {
    // Window rotation (02 §2.4): a live bucket finalizes its current window
    // into `previous` every kObservationWindowMs — freshness is then judged
    // from contributing measurements, never from allocation age.
    if (now_ms - existing->window_start_ms >= kObservationWindowMs) {
      existing->previous = existing->current;
      existing->current = ObservationWindow{};
      existing->window_start_ms = now_ms;
    }
    existing->last_update_ms = now_ms;
    return existing;
  }
  auto* created = observations_.allocate();
  if (created == nullptr) {
    // Bounded reclaim (02 §bounded state): only a bucket whose evidence
    // validity has fully expired (kFeedbackTtlMs, not the shorter
    // aggregation window) AND that holds no pins or pending completions
    // may be released — live evidence and in-flight work are never
    // evicted into a silent counter reset.
    ObservationBucket* oldest_expired = nullptr;
    observations_.for_each([&](ObservationBucket& value) {
      if (value.pins != 0 || value.pending_completions != 0) return;
      if (now_ms - value.last_update_ms < kFeedbackTtlMs) return;
      if (oldest_expired == nullptr ||
          value.last_update_ms < oldest_expired->last_update_ms) {
        oldest_expired = &value;
      }
    });
    if (oldest_expired == nullptr ||
        !observations_.release(oldest_expired)) {
      ++busy_stats_.observation_overflow;  // bounded memory: overflow counts, never grows
      return nullptr;
    }
    created = observations_.allocate();
    if (created == nullptr) {
      ++busy_stats_.observation_overflow;
      return nullptr;
    }
  }
  created->key = key;
  created->window_start_ms = now_ms;
  created->last_update_ms = now_ms;
  return created;
}

ObservationBucket* MeshNode::observation_bucket(
    const NodeId peer, const std::uint8_t length_class,
    const MonotonicMs now_ms) noexcept {
  // Align submission-side accounting with the completion-side identity
  // (02 §2.3): one observation key spans the whole attempt, so a snapshot
  // can never report MAC successes against zero submissions. The peer's
  // current summary supplies the identity tuple; when none exists the
  // zero-generation key is the honest "unattributed" record.
  ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                     RadioGeneration{0}, ChannelEpoch{0}, length_class, peer};
  if (const auto* summary = telemetry_peers_.find(peer);
      summary != nullptr && !summary->stale) {
    key.binding = summary->binding;
    key.radio = summary->radio;
    key.channel = summary->channel;
  }
  return observation_bucket(key, now_ms);
}

void MeshNode::obs_tx_submitted(TxJob& job, const std::uint64_t token,
                                const MonotonicMs now_ms) noexcept {
  // One immutable observation identity per PHYSICAL ATTEMPT (02 §2.3):
  // every accepted submission re-stamps the key the runtime froze for
  // THIS token — a retry after a rebind/channel change must not inherit
  // the first attempt's identity. Only when the runtime did not stamp one
  // (host simulation harness) fall back to the peer summary.
  if (submit_identity_.valid && submit_identity_.token == token) {
    job.obs_key = submit_identity_.key;
    job.obs_key_set = true;
    submit_identity_.valid = false;
  } else if (!job.obs_key_set) {
    ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                       RadioGeneration{0}, ChannelEpoch{0},
                       frame_length_class(job.tx_cost), job.peer};
    if (const auto* summary = telemetry_peers_.find(job.peer);
        summary != nullptr && !summary->stale) {
      key.binding = summary->binding;
      key.radio = summary->radio;
      key.channel = summary->channel;
    }
    job.obs_key = key;
    job.obs_key_set = true;
  }
  auto* bucket = observation_bucket(job.obs_key, now_ms);
  if (bucket != nullptr) {
    ++bucket->tx_submitted;
    // The attempt pins its bucket until the completion-side observation
    // lands — in-flight work can never be reclaimed (02 §bounded state).
    if (bucket->pending_completions != UINT32_MAX) {
      ++bucket->pending_completions;
    }
    if (job.physical_attempts > 1) {
      // A re-submission after MAC failure/timeout is the only SDK-visible
      // retry the driver reports — never claimed as ESP-NOW-internal (02).
      // Saturates with its flag set rather than wrapping silently.
      if (bucket->sdk_retries != UINT32_MAX) {
        ++bucket->sdk_retries;
      } else {
        bucket->saturation_mask |= kSatSdkRetries;
      }
    }
    ++bucket->sojourn_samples;
    // Queue sojourn: enqueue -> handed to radio (03 §3). Lifetime EWMA
    // plus the current window's own measurement — window fields are what
    // snapshot freshness is judged against.
    ewma_add(bucket->queue_sojourn_ms_ewma, now_ms - job.enqueued_at_ms,
             bucket->sojourn_samples);
    ++bucket->current.queue_samples;
    ewma_add(bucket->current.queue_us_ewma,
             (now_ms - job.enqueued_at_ms) * 1000,
             bucket->current.queue_samples);
    ++bucket->current.tx_submitted;
    bucket->current.present = true;
    if (bucket->current.first_sample_ms == 0) {
      bucket->current.first_sample_ms = now_ms;
    }
    bucket->current.last_sample_ms = now_ms;
  }
  // Per-peer mirror (03 §6): the A->B queue picture and the exchange ratio
  // are per-next-hop, so the global bucket is mirrored into the neighbor
  // record even when the bounded bucket pool overflows.
  if (auto* neighbor = find_neighbor(job.peer)) {
    ++neighbor->sojourn_samples;
    ewma_add(neighbor->queue_sojourn_ewma_ms, now_ms - job.enqueued_at_ms,
             neighbor->sojourn_samples);
    neighbor->last_sojourn_ms = now_ms;
    neighbor->metric_sources |= Neighbor::kMetricSourceLocalSojourn;
    if (neighbor->sojourn_window_ms == 0) neighbor->sojourn_window_ms = now_ms;
    if (job.requires_hop_accept) {
      // Eligible attempt work for the exchange-cost ratio: every physical
      // submission counts, including submissions that later fail (§6.1).
      if (neighbor->exchange_window_ms == 0) neighbor->exchange_window_ms = now_ms;
      ++neighbor->exchange_work;
      neighbor->metric_sources |= Neighbor::kMetricSourceLocalExchange;
    }
  }
}

ObservationBucket* MeshNode::job_bucket(const TxJob& job,
                                        const MonotonicMs now_ms) noexcept {
  // The attempt's own stamped identity when it exists — never re-derive it
  // from a summary that may have re-bound mid-attempt (02 §2.3).
  if (job.obs_key_set) return observation_bucket(job.obs_key, now_ms);
  return observation_bucket(job.peer, frame_length_class(job.tx_cost), now_ms);
}

void MeshNode::obs_driver_service(const TxJob& job, const std::uint32_t service_us,
                                  const MonotonicMs now_ms) noexcept {
  auto* bucket = job_bucket(job, now_ms);
  if (bucket == nullptr) return;
  ++bucket->service_samples;
  // Driver service: driver acceptance -> TX callback (03 §3). May include
  // CCA/MAC retries — it is not airtime.
  ewma_add(bucket->driver_service_us_ewma, service_us, bucket->service_samples);
}

void MeshNode::obs_hop_result(const TxJob& job, const bool accepted,
                              const MonotonicMs now_ms) noexcept {
  auto* bucket = job_bucket(job, now_ms);
  if (bucket != nullptr) {
    if (accepted) {
      ++bucket->hop_accepted;
      // Hop exchange attempts until authenticated HOP_ACCEPT (03 §3), counted
      // by the physical attempt index that finally got through.
      const std::uint8_t index =
          job.physical_attempts == 0
              ? 0
              : static_cast<std::uint8_t>(job.physical_attempts - 1);
      ++bucket->accepted_at_attempt[std::min<std::uint8_t>(
          index, kCombinedPhysicalAttemptsMax - 1)];
    } else {
      ++bucket->rf_failures;  // HOP_ACCEPT timeout folds into RF-loss accounting
    }
  }
  if (accepted) {
    if (auto* neighbor = find_neighbor(job.peer)) {
      ++neighbor->exchange_accepts;  // authenticated-accept success (03 §6.1)
      neighbor->metric_sources |= Neighbor::kMetricSourceLocalExchange;
    }
  }
}

void MeshNode::obs_count(const TxJob& job,
                         std::uint64_t ObservationBucket::*counter,
                         const MonotonicMs now_ms) noexcept {
  auto* bucket = job_bucket(job, now_ms);
  if (bucket != nullptr) ++(bucket->*counter);
}

void MeshNode::obs_final(const Delivery& delivery, const DeliveryState state,
                         const MonotonicMs now_ms) noexcept {
  std::uint64_t ObservationBucket::*counter = nullptr;
  switch (state) {
    case DeliveryState::Delivered:
      // Only RELIABLE completion is an END_RECEIPT result; a BestEffort
      // "delivered" means TX_MAC_DONE and counts as a plain completion.
      counter = delivery.options.delivery == DeliveryClass::Reliable
                    ? &ObservationBucket::end_receipts
                    : &ObservationBucket::completions;
      break;
    case DeliveryState::Expired:
      counter = &ObservationBucket::expiries;
      break;
    case DeliveryState::Failed:
      counter = &ObservationBucket::failures;
      break;
    default:
      counter = &ObservationBucket::indeterminate;
      break;
  }
  // Final results aggregate under the default length class — a delivery has
  // no single on-air frame size.
  auto* bucket = observation_bucket(delivery.destination, 0, now_ms);
  if (bucket != nullptr) ++(bucket->*counter);
}

// ---------------------------------------------------------------------------
// M1 telemetry entry points (02-telemetry.md §2.3)
// ---------------------------------------------------------------------------

Status MeshNode::note_radio_tx(const RadioTxObservation& observation,
                               const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_ || observation.peer == kInvalidNodeId) return Status::success();
  const std::uint64_t service_us =
      observation.completed_us > observation.submitted_us
          ? observation.completed_us - observation.submitted_us
          : 0;
  if (service_us > 0) {
    // §14 airtime ledger: debit the measured driver service before any
    // bucket bookkeeping — the ledger is a fixed accumulator and must
    // record even when the bounded bucket pool cannot. A token that
    // matches the in-flight submission attributes to that job's domain;
    // anything else (raw lane, bootstrap, stale callback) lands in Misc.
    AirtimeDomain domain = AirtimeDomain::Misc;
    if (observation.token != 0 && physical_.active &&
        observation.token == physical_.token) {
      domain = TxScheduler::airtime_domain(physical_.job);
    }
    switch (domain) {
      case AirtimeDomain::Ack:
        saturating_add(budget_stats_.service_us_ack, service_us);
        break;
      case AirtimeDomain::Work:
        saturating_add(budget_stats_.service_us_work, service_us);
        break;
      case AirtimeDomain::Control:
        saturating_add(budget_stats_.service_us_control, service_us);
        // §14 charges the gated domain at completion: measured service
        // debits the bucket and may run it negative — the deficit is
        // repaid through the wait computed for the next management
        // emission, never by queueing on debt. The same sample calibrates
        // the demand the gate charges per emission.
        control_budget_balance(now_ms);
        control_budget_tokens_us_ -= static_cast<std::int64_t>(service_us);
        ++control_service_samples_;
        ewma_add(control_service_ewma_us_,
                 static_cast<std::uint32_t>(
                     std::min<std::uint64_t>(service_us, UINT32_MAX)),
                 control_service_samples_);
        break;
      case AirtimeDomain::Optimization:
        saturating_add(budget_stats_.service_us_optimization, service_us);
        break;
      case AirtimeDomain::Misc:
        saturating_add(budget_stats_.service_us_misc, service_us);
        break;
    }
  }
  // RF broadcast consumes management airtime but has no neighbor MAC ACK.
  // Keep the ledger debit above and omit every per-peer completion sample.
  if (observation.peer == kBroadcastNodeId) return Status::success();
  auto* bucket = observation_bucket(
      ObservationKey{observation.binding_generation,
                     ObservationDirection::Egress, observation.radio_generation,
                     observation.channel_epoch, observation.frame_length_class,
                     observation.peer},
      now_ms);
  if (bucket == nullptr) {
    // observation_bucket already counted overflow
    return Status::success();
  }
  bucket->observer_boot = config_.boot_incarnation;
  switch (observation.outcome) {
    case RadioTxOutcome::Success:
      ++bucket->tx_mac_success;
      break;
    case RadioTxOutcome::Failure:
      ++bucket->tx_mac_fail;
      break;
    case RadioTxOutcome::Unknown:
      ++bucket->unknown_results;
      // §3.3 evidence gate: an Unknown resolution taints the peer's metric
      // window — it may worsen but never improve until the next roll.
      if (Neighbor* neighbor = find_neighbor(observation.peer)) {
        neighbor->metric_window_dirty = true;
      }
      break;
  }
  if (service_us > 0) {
    const std::uint32_t service_us32 = static_cast<std::uint32_t>(service_us);
    ++bucket->service_samples;
    ++bucket->current.driver_samples;
    ewma_add(bucket->driver_service_us_ewma, service_us32,
             bucket->service_samples);
    ewma_add(bucket->current.driver_us_ewma, service_us32,
             bucket->current.driver_samples);
  }
  bucket->current.present = true;
  bucket->current.sources |= static_cast<std::uint8_t>(
      1u << static_cast<unsigned>(observation.provenance));
  bucket->current.last_sample_ms = now_ms;
  if (bucket->current.first_sample_ms == 0) {
    bucket->current.first_sample_ms = now_ms;
  }
  return Status::success();
}

const PeerTelemetrySummary* MeshNode::telemetry_peer(const NodeId peer) const noexcept {
  return telemetry_peers_.find(peer);
}

const ObservationBucket* MeshNode::telemetry_bucket(
    const ObservationKey& key) const noexcept {
  return observations_.find(
      [&](const ObservationBucket& value) { return value.key == key; });
}

}  // namespace routeloom
