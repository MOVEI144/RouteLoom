#include "node_internal.hpp"

namespace routeloom {

// --- BUSY emission (03-congestion.md §5) ----------------------------------------

std::uint32_t MeshNode::busy_retry_hint() const noexcept {
  // Occupancy-scaled retry hint, kept inside the contract clamp interval.
  const std::uint32_t hint =
      kBusyRetryAfterMinMs + scheduler_.occupancy_percent() * 4;
  return std::min(hint, kBusyRetryAfterMaxMs);
}

Status MeshNode::queue_busy(const NodeId peer, const wire::Header& rejected,
                            const std::uint8_t reason, const TxnHandle txn,
                            const MonotonicMs now_ms) noexcept {
  autonomy::BusyPayload payload{};
  payload.subtype = autonomy::BusySubtype::Reject;
  payload.reason = static_cast<autonomy::BusyReason>(reason);
  payload.referenced_type = rejected.type;
  payload.referenced_origin = rejected.origin;
  payload.referenced_session = rejected.message.session;
  payload.referenced_sequence = rejected.message.sequence;
  payload.referenced_round = rejected.delivery_round;
  // binding generation belongs to the radio Owner's binding table, which is
  // not wired into the portable core yet — 0 means "no binding context".
  payload.feedback_sequence = FeedbackSequence{next_feedback_sequence_++};
  payload.retry_after_ms = busy_retry_hint();
  payload.pressure = static_cast<std::uint8_t>(
      std::min<std::uint32_t>(255, scheduler_.occupancy_percent() * 255 / 100));
  autonomy::EncodedPayload encoded{};
  auto status = autonomy::busy_encode(payload, encoded);
  if (!status) return status;

  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::Transit;
  job.peer = peer;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::Busy;
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
  std::memcpy(job.plain.payload.data(), encoded.bytes.data(), encoded.size);
  job.plain.payload_size = encoded.size;
  job.txn = txn;
  status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (status) join_txn(txn);
  return status;
}

void MeshNode::emit_busy_or_drop(const NodeId peer, const wire::Header& rejected,
                                 const std::uint8_t reason, const RxBinding& rx,
                                 const MonotonicMs now_ms) noexcept {
  const auto* neighbor = find_neighbor(peer);
  // Never emit the new payload toward a peer that has not proven or been
  // configured for BUSY (03 §5; the D4-09 legacy fallback is the sender's
  // own timeout). A BUSY itself needs a reply slot: without one the frame
  // is dropped and counted, never fabricated.
  if (neighbor == nullptr || !neighbor->busy_capable ||
      neighbor->cap_valid_until_ms <= now_ms ||
      scheduler_.free_slots() < 1) {
    ++busy_stats_.busy_send_failed;
    return;
  }
  if (!rx.valid) {
    refuse_without_binding(peer, rejected, "BUSY_NO_BINDING", now_ms);
    return;
  }
  // The BUSY rides its own short reply reservation on the receive's
  // evidence — when the lease itself is unaffordable the refusal degrades
  // to the counted local drop the sender's timeout already covers.
  AdmissionReservation reply{};
  if (!reserve_rx_reply(rx, true, 1, now_ms, reply)) {
    ++busy_stats_.busy_send_failed;
    return;
  }
  if (queue_busy(peer, rejected, reason, reply.txn, now_ms)) {
    reply.committed = true;
    ++busy_stats_.busy_sent;
  } else {
    ++busy_stats_.busy_send_failed;
  }
}

Status MeshNode::encode_job(TxJob& job, const MonotonicMs now_ms) noexcept {
#if ROUTELOOM_APP_OBJECT_TRANSFER
  if (job.owner == JobOwner::AppObject) {
    const auto& header = job.form == JobForm::Plain ? job.plain.header : job.forwarded.header;
    std::uint32_t epoch = 0;
    // Object jobs belong to the boot and End context admitted at enqueue;
    // session repair must not seal an old operation under a new context.
    if (header.network != config_.network || header.origin != config_.node ||
        header.message.session != config_.message_session ||
        !security_.tx_epoch(SecurityScope::EndToEnd, header.destination, epoch) ||
        epoch != header.end_epoch) {
      return Status::error(StatusCode::Expired, "OBJECT_CONTEXT_RETIRED");
    }
  }
#endif
  // tx_encoded_ still holds this job's sealed frame (the driver refused it
  // and nothing else was sealed since): hand the same bytes over again.
  if (job.encoded_tag != 0 && job.encoded_tag == tx_encoded_tag_) return Status::success();
  job.encoded_tag = 0;
  if (now_ms >= job.deadline_ms) {
    if (job.session_deferred) {
      // The job waited for a provider-owned session that never became
      // usable (sdk-v1/03 §9): say so instead of a generic expiry.
      if (session_stats_.tx_unavailable != UINT32_MAX) ++session_stats_.tx_unavailable;
      return Status::error(StatusCode::Expired, "SESSION_UNAVAILABLE");
    }
    return Status::error(StatusCode::Expired, "JOB_EXPIRED");
  }
  const auto remaining = static_cast<std::uint32_t>(job.deadline_ms - now_ms);
  // Sealing overwrites the shared buffer: whichever job it held loses its
  // encoding (tags never repeat within a job's lifetime).
  tx_encoded_tag_ = 0;
  Status status;
  if (job.form == JobForm::Plain) {
    job.plain.header.previous_hop = config_.node;
    job.plain.header.next_hop = job.peer;
    job.plain.header.remaining_deadline_ms = std::min(job.plain.header.remaining_deadline_ms,
                                                      remaining);
    if ((job.plain.header.flags & wire::kFlagEndProtected) != 0) {
      wire::LinkOpenedFrame sealed{};
      status = wire::encode_new(job.plain, security_, tx_encoded_, &sealed);
      if (status) {
        // Preserve the End counter/ciphertext across hop retries. Only the
        // Link wrapper and its deadline are re-created on retransmission.
        job.set_forwarded(sealed);
        job.form = JobForm::Sealed;
      }
    } else {
      status = wire::encode_new(job.plain, security_, tx_encoded_);
    }
  } else if (job.form == JobForm::Sealed) {
    status = wire::retry_local(job.forwarded, job.peer, remaining, security_, tx_encoded_);
  } else {
    status = wire::forward(job.forwarded, config_.node, job.peer, config_.link_epoch,
                           remaining, security_, tx_encoded_);
  }
  if (status) {
    if (++last_encoded_tag_ == 0) last_encoded_tag_ = 1;
    tx_encoded_tag_ = last_encoded_tag_;
    job.encoded_tag = last_encoded_tag_;
    job.session_deferred = false;
  }
  return status;
}

bool MeshNode::defer_for_session(TxJob& job) noexcept {
  // encode refused with AuthRequired. Which context is missing? The link to
  // the next hop first, then the end layer a fresh frame would seal (a
  // forwarded frame's end layer is already sealed by its origin).
  NodeId subject = job.peer;
  // A broadcast job seals under GroupLink, not the pairwise Link: ask about
  // the context the encode actually refused on, or a missing GK would fail
  // the job instead of holding it for the key.
  const SecurityScope link_scope = job.peer == kBroadcastNodeId
                                       ? SecurityScope::GroupLink
                                       : SecurityScope::Link;
  ContextState state = security_.context_state(link_scope, job.peer);
  if (context_usable(state) && job.form == JobForm::Plain &&
      (job.plain.header.flags & wire::kFlagEndProtected) != 0) {
    const SecurityContext end = wire::end_context(job.plain.header);
    subject = end.receiver;
    state = security_.context_state(end.scope, end.receiver);
  }
  // Every involved context is usable: the refusal is an ordinary
  // authentication failure and the job fails exactly as before.
  if (context_usable(state)) return false;
  if (!job.session_deferred) {
    // Once per job: the provider already knows (it answered None or
    // Establishing) and owns establishment (the handshake engine, P4-2);
    // the node only holds the frame, deadline-bounded, without spending a
    // counter on it.
    job.session_deferred = true;
    if (session_stats_.tx_deferred != UINT32_MAX) ++session_stats_.tx_deferred;
    observer_.on_diagnostic(
        state == ContextState::None ? "SESSION_REQUIRED" : "SESSION_PENDING",
        subject, &job.ack.key.id);
  }
  return true;
}

void MeshNode::note_rx_refusal(const Status& status, const NodeId peer,
                               const MessageId* message) noexcept {
  // Receive-side refusals keep the provider's detail as the diagnostic; an
  // unknown context (AuthRequired, sdk-v1/03 §9) is additionally counted —
  // it is never a replay and never falls back to another key.
  if (status.code == StatusCode::AuthRequired &&
      session_stats_.rx_auth_required != UINT32_MAX) {
    ++session_stats_.rx_auth_required;
  }
  observer_.on_diagnostic(status.detail, peer, message);
}

void MeshNode::note_end_rx_refusal(const Status& status,
                                   const wire::LinkOpenedFrame& frame,
                                   const NodeId peer) noexcept {
  // The link layer already authenticated this frame from `peer`. When the
  // end layer finds no context for its stamped id, the origin still seals
  // under a context this node lost (a reboot, sdk-v1/03 §4.3) and nothing
  // on the wire tells it: the provider records the rate-limited
  // re-handshake demand (03 §9) and the refusal is counted as before.
  if (status.code == StatusCode::AuthRequired &&
      (frame.header.flags & wire::kFlagEndProtected) != 0) {
    security_.note_rx_unknown_context(wire::end_context(frame.header));
  }
  note_rx_refusal(status, peer, &frame.header.message);
}

void MeshNode::dispatch_next(const MonotonicMs now_ms) noexcept {
  if (physical_.active) {
    if (now_ms - physical_.submitted_at_ms >= config_.callback_watchdog_ms) {
      TxJob job = physical_.job;
      const bool early_hop_accept = physical_.early_hop_accept;
      physical_ = PhysicalInflight{};
      observer_.on_diagnostic("DRIVER_RESULT_UNKNOWN", job.peer, &job.ack.key.id);
      // Callback-uncertain results are accounted separately from RF loss
      // and BUSY — the job still retries within its bounded attempt budget.
      obs_count(job, &ObservationBucket::unknown_results, now_ms);
      // §3.3 evidence gate: an Unknown resolution taints the peer's metric
      // window — it may worsen but never improve until the next roll.
      if (Neighbor* neighbor = find_neighbor(job.peer)) {
        neighbor->metric_window_dirty = true;
      }
      // No driver observation will ever land for this attempt — release
      // its bucket pin here or the evidence could never be reclaimed.
      if (auto* bucket = job_bucket(job, now_ms);
          bucket != nullptr && bucket->pending_completions != 0) {
        --bucket->pending_completions;
      }
      (void)radio_.recover();
      if (early_hop_accept) {
        if (auto* neighbor = find_neighbor(job.peer)) neighbor->consecutive_failures = 0;
        finish_hop_accept(job, false, 0, now_ms);
      } else {
        retry_or_fail(job, "DRIVER_RESULT_UNKNOWN", now_ms);
      }
    }
    return;
  }

  std::size_t route_defers = 0;
  while (TxJob* queued = scheduler_.select(now_ms, *this)) {
    if (queued->owner == JobOwner::OriginDelivery) {
      auto* delivery = find_delivery(queued->ack.key.id);
      // A queued retry for an already-terminal delivery is stale work:
      // dispatching it would burn airtime on a duplicate the receiver's
      // dedup pin suppresses anyway, and its outcome must never touch the
      // settled verdict. Delivered/Indeterminate are terminal too.
      if (delivery == nullptr || sleep_terminal(delivery->state)) {
        TxJob discarded{};
        scheduler_.take_selected(discarded);
        // The slot `queued` points at is released above: diagnose from the
        // taken job, not the dead slot.
        observer_.on_diagnostic("STALE_JOB_DROPPED", discarded.peer,
                                &discarded.ack.key.id);
        continue;
      }
    } else if (queued->owner == JobOwner::Group &&
               group_origin_job_stale(*queued)) {
      // A queued retry for an already-settled group origin: same rule as
      // above — never dispatch airtime for a verdict that already landed.
      TxJob discarded{};
      scheduler_.take_selected(discarded);
      observer_.on_diagnostic("STALE_JOB_DROPPED", discarded.peer,
                              &discarded.ack.key.id);
      continue;
    }
    // Combined physical-attempt budget (03 §5): a job that already consumed
    // its six transmissions fails here instead of occupying the driver.
    if (queued->physical_attempts >= kCombinedPhysicalAttemptsMax) {
      TxJob exhausted{};
      scheduler_.take_selected(exhausted);
      fail_job(exhausted, "ATTEMPT_BUDGET_EXHAUSTED", now_ms);
      continue;
    }
    // Route re-verification (03 §7): the route reserved at enqueue is
    // re-checked against the LIVE selected snapshot before the driver sees
    // the frame. A switched route retargets the job under the SAME
    // MessageId, original deadline and consumed round; a destination with
    // no feasible route holds the job (deadline-bounded) instead of
    // launching it on a next hop the table no longer selects — a frame
    // sent down an infeasible route can close a forwarding loop (D4-02).
    NodeId routed = kInvalidNodeId;
    const wire::Header& route_header = queued->form == JobForm::Plain
                                           ? queued->plain.header
                                           : queued->forwarded.header;
    if (queued->form == JobForm::Forwarded &&
        route_header.type != FrameType::GroupData) {
      // Group copies target a tree child chosen at round start; their
      // destination is a group address, never a unicast route.
      routed = route_header.destination;
    } else if (queued->form != JobForm::Forwarded &&
               (route_header.type == FrameType::Data ||
                route_header.type == FrameType::Service ||
                route_header.type == FrameType::EndReceipt)) {
      routed = route_header.destination;
    }
    if (routed != kInvalidNodeId) {
      const auto live = routes_.best(routed);
      if (!live.valid || find_neighbor(live.next_hop) == nullptr) {
        if (queued->form != JobForm::Forwarded &&
            route_header.type == FrameType::EndReceipt &&
            queued->peer == kInvalidNodeId) {
          TxJob failed{};
          scheduler_.take_selected(failed);
          fail_job(failed, "NO_RETURN_ROUTE", now_ms);
          continue;
        }
        if (now_ms >= work_deadline(*queued)) {
          TxJob stale{};
          scheduler_.take_selected(stale);
          fail_job(stale, "NO_ROUTE", now_ms);
          continue;
        }
        scheduler_.defer_selected();
        // A queue of only route-blocked jobs must not spin this pass; the
        // bound lets each job be re-checked on a later poll.
        if (++route_defers >= kTxQueueCapacity) return;
        continue;
      }
      if (live.next_hop != queued->peer) {
        queued->peer = live.next_hop;
        queued->encoded_tag = 0;  // re-stamp next_hop at encode
      }
    }
    if (next_physical_token_ == 0) {
      TxJob exhausted{};
      scheduler_.take_selected(exhausted);
      fail_job(exhausted, "TX_TOKEN_EXHAUSTED", now_ms);
      continue;
    }
    if (queued->txn != kInvalidTxnHandle) {
      // Admission work re-validates its lease use immediately before the
      // send (design-q116 §6.3): a use the Owner revoked or retired since
      // admission must never reach the air on a recycled binding.
      if (reply_peer_port_ == nullptr) {
        TxJob revoked{};
        scheduler_.take_selected(revoked);
        fail_job(revoked, "TXN_NO_PORT", now_ms);
        continue;
      }
      const TxnSlot* slot = resolve_txn(queued->txn);
      if (slot == nullptr) {
        // A live job always references a live transaction — a stale handle
        // fails closed instead of transmitting off-account.
        TxJob revoked{};
        scheduler_.take_selected(revoked);
        fail_job(revoked, "TXN_REVOKED", now_ms);
        continue;
      }
      const Status lease = reply_peer_port_->validate(slot->use, now_ms);
      if (lease.code == StatusCode::TimeUncertain) {
        // A regressed clock stops new TX this pass; the sweep already
        // suspended time-based closes, and callbacks still drain.
        scheduler_.requeue_selected();
        return;
      }
      if (!lease) {
        TxJob revoked{};
        scheduler_.take_selected(revoked);
        fail_job(revoked,
                 lease.code == StatusCode::Expired ? "TXN_EXPIRED"
                                                   : "TXN_REVOKED",
                 now_ms);
        continue;
      }
      if (now_ms >= work_deadline(*queued)) {
        TxJob expired{};
        scheduler_.take_selected(expired);
        fail_job(expired, "TXN_EXPIRED", now_ms);
        continue;
      }
    }
    auto status = encode_job(*queued, now_ms);
    if (!status) {
      if (status.code == StatusCode::AuthRequired && defer_for_session(*queued)) {
        // No session with the peer yet (sdk-v1/03 §9): hold the job like a
        // route-blocked one; its deadline still bounds the wait.
        scheduler_.defer_selected();
        if (++route_defers >= kTxQueueCapacity) return;
        continue;
      }
      TxJob failed{};
      scheduler_.take_selected(failed);
      fail_job(failed, status.detail, now_ms);
      continue;
    }
    if (queued->requires_hop_accept && reply_peer_port_ != nullptr) {
      // ACK-awaiting TX pins the submitted binding (design-q116 §6.2): the
      // snapshot, the encode above and the bound send below are one serial
      // operation, so the HOP_ACCEPT match later compares like with like.
      ReplyBinding snapshot{};
      status = reply_peer_port_->snapshot_binding(queued->peer, snapshot);
      if (!status) {
        TxJob unbound{};
        scheduler_.take_selected(unbound);
        retry_or_fail(unbound, status.detail, now_ms);
        continue;
      }
      queued->submitted_binding = snapshot.id;
      queued->submitted_generation = snapshot.generation;
      queued->submitted_rx_context = snapshot.rx_context_id;
      queued->submitted_binding_set = true;
    }
    std::uint64_t token = 0;
    (void)mint_physical_token(next_physical_token_, token);
    if (reply_peer_port_ != nullptr && queued->requires_hop_accept &&
        queued->submitted_binding_set) {
      ReplyBinding submitted{};
      submitted.peer = queued->peer;
      submitted.id = queued->submitted_binding;
      submitted.generation = queued->submitted_generation;
      submitted.rx_context_id = queued->submitted_rx_context;
      status = reply_peer_port_->send_bound(submitted, token,
                                            tx_encoded_.view());
    } else if (reply_peer_port_ != nullptr &&
               queued->txn != kInvalidTxnHandle &&
               resolve_txn(queued->txn) != nullptr) {
      // Lease-protected reply without a hop exchange (HOP_ACCEPT, BUSY,
      // refusals, receipts that need no accept): the Owner rechecks the use
      // against the live mapping, then submits.
      const TxnSlot* slot = resolve_txn(queued->txn);
      status = reply_peer_port_->send_reply(slot->use, token,
                                            tx_encoded_.view(), now_ms);
    } else {
      status = radio_.send(queued->peer, token, tx_encoded_.view());
    }
    if (status.code == StatusCode::WouldBlock || status.code == StatusCode::Busy) {
      // The driver could not take the frame: no attempt was made. Restore
      // the job at the head of its lane and stop dispatching this pass.
      scheduler_.requeue_selected();
      return;
    }
    TxJob submitted{};
    scheduler_.take_selected(submitted);
    if (!status) {
      retry_or_fail(submitted, status.detail, now_ms);
      continue;
    }
    const auto& submitted_header = submitted.form == JobForm::Plain ? submitted.plain.header : submitted.forwarded.header;
    if (submitted_header.type == FrameType::AppObjectStart ||
        submitted_header.type == FrameType::AppObjectChunk || submitted_header.type == FrameType::AppObjectAck) {
      // 50,000 us/s with one frame of burst. Charge each physical attempt
      // using encoded length and fixed PHY cost, independently of service time.
      const auto cost_us = (tx_encoded_.size + kTxFrameFixedCostBytes) * 32;
      object_send_after_ms_ = now_ms + (cost_us + 49) / 50;
    } else if ((submitted_header.type == FrameType::Data ||
                submitted_header.type == FrameType::Service ||
                submitted_header.type == FrameType::EndReceipt ||
                submitted_header.type == FrameType::AppResult) &&
               (submitted_header.traffic & wire::kTrafficPriorityMask) != wire::kTrafficBulk) {
      // Leave the following airtime turn for the foreground exchange's
      // forwarded data and receipt, which may not be queued here yet.
      const auto cost_us = (tx_encoded_.size + kTxFrameFixedCostBytes) * 32;
      object_send_after_ms_ = std::max(object_send_after_ms_, now_ms + (cost_us + 49) / 50);
    }
    ++submitted.physical_attempts;
    obs_tx_submitted(submitted, token, now_ms);
    physical_.job = std::move(submitted);
    physical_.token = token;
    physical_.submitted_at_ms = now_ms;
    physical_.active = true;
    if (physical_.job.owner == JobOwner::Transit) {
      // Bind the retained transit record to the attempt actually
      // submitted — dispatch may have retargeted next_hop after admission
      // (route repair), so the stored downstream/binding must reflect the
      // real attempt, not the enqueue-time route. The job's ack key holds
      // the transit record's identity; forwarded jobs keep no plain
      // header.
      if (auto* entry = find_dedup(physical_.job.ack.key,
                                   physical_.job.ack.accepted_type,
                                   physical_.job.ack.round)) {
        entry->downstream_peer = physical_.job.peer;
        entry->downstream_binding = BindingGeneration{0};
        if (const auto* s = telemetry_peers_.find(physical_.job.peer);
            s != nullptr && s->occupied) {
          entry->downstream_binding = s->binding;
        }
      }
    }
    if (physical_.job.owner == JobOwner::OriginDelivery) {
      if (auto* delivery = find_delivery(physical_.job.ack.key.id)) {
        set_delivery_state(*delivery, DeliveryState::WaitingForMac, "TX_MAC_PENDING");
      }
    }
    return;
  }
}

Status MeshNode::on_radio_tx_result(const std::uint64_t token, const bool success,
                                    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  ++work_generation_;
  if (!physical_.active || physical_.token != token) {
    observer_.on_diagnostic("STALE_TX_CALLBACK", kInvalidNodeId, nullptr);
    return Status::success();
  }
  TxJob job = physical_.job;
  const bool busy_deferred = physical_.busy_deferred;
  const std::uint32_t busy_retry_ms = physical_.busy_retry_ms;
  const bool early_hop_accept = physical_.early_hop_accept;
  // Driver service time is recorded ONLY by note_radio_tx from the
  // runtime's own submitted/completed timestamps — a second measurement
  // here would double-record and inflate it with Owner/RX backlog (03 §3).
  physical_ = PhysicalInflight{};
  // The attempt resolved: release the bucket pin its submission took.
  // (Driver-side note_radio_tx never touches pins — raw-lane completions
  // must not consume a pin belonging to an in-flight job under the same
  // observation key.)
  if (auto* bucket = job_bucket(job, now_ms);
      bucket != nullptr && bucket->pending_completions != 0) {
    --bucket->pending_completions;
  }
  // A broadcast has no per-neighbor MAC ACK. Resolve the one-shot driver
  // attempt without fabricating reachability, RF loss or HopAccept evidence.
  if (job.peer == kBroadcastNodeId) {
    complete_job(job, false, now_ms);
    return Status::success();
  }
  auto* neighbor = find_neighbor(job.peer);
  if (early_hop_accept) {
    // A binding-matched accept is stronger evidence than the MAC callback;
    // keep the physical fence until now even if the callback reports loss.
    // The accept preceded MAC completion, so there is no MAC-to-ACK RTT.
    if (neighbor != nullptr) neighbor->consecutive_failures = 0;
    finish_hop_accept(job, false, 0, now_ms);
    return Status::success();
  }
  if (!success) {
    if (neighbor != nullptr && neighbor->consecutive_failures < UINT8_MAX) {
      ++neighbor->consecutive_failures;
      if (neighbor->consecutive_failures >= 2) {
        routes_.invalidate_next_hop(job.peer, now_ms);
        trigger_route_advertisement(now_ms);
      }
    }
    obs_count(job, &ObservationBucket::rf_failures, now_ms);
    retry_or_fail(job, "MAC_SEND_FAILED", now_ms);
    return Status::success();
  }
  if (neighbor != nullptr) neighbor->consecutive_failures = 0;
  if (!job.requires_hop_accept) {
    complete_job(job, false, now_ms);
    return Status::success();
  }
  auto* awaiting = awaiting_hop_.allocate();
  if (awaiting == nullptr) {
    // A full hop-wait table is a capacity shortfall, not RF loss (issue
    // #50): defer without consuming the retry budget. The frame did reach
    // the air so physical_attempts stays counted; tx_admitted_now re-gates
    // capacity before the next send.
    if (now_ms >= work_deadline(job)) {
      fail_job(job, "DEADLINE_EXPIRED", now_ms);
      return Status::success();
    }
    observer_.on_diagnostic("HOP_WAIT_TABLE_FULL", job.peer, &job.ack.key.id);
    job.encoded_tag = 0;
    TxJob pending = std::move(job);
    if (!scheduler_.enqueue(std::move(pending), config_.node, now_ms)) {
      fail_job(pending, "TX_QUEUE_FULL", now_ms);
    }
    return Status::success();
  }
  awaiting->job = std::move(job);
  // An authenticated BUSY that arrived while the frame was with the driver
  // takes effect now: the exchange is deferred, not retried as RF loss.
  awaiting->busy_deferred = busy_deferred;
  awaiting->sent_at_ms = now_ms;
  awaiting->expires_at_ms =
      now_ms + (busy_deferred
                    ? busy_retry_ms
                    : effective_hop_timeout_ms(awaiting->job.peer));
  if (awaiting->job.owner == JobOwner::OriginDelivery) {
    if (auto* delivery = find_delivery(awaiting->job.ack.key.id);
        delivery != nullptr && !sleep_terminal(delivery->state)) {
      // A receipt/RESULT may have settled the verdict while this frame was
      // with the driver — the hop-accept wait of its stale job must not
      // demote a terminal state.
      set_delivery_state(*delivery, DeliveryState::WaitingForHopAccept, "HOP_ACCEPT_PENDING");
    }
  }
  return Status::success();
}

void MeshNode::complete_job(TxJob& job, const bool hop_accepted,
                            const MonotonicMs now_ms) noexcept {
  // The transaction work item ends here — before any component effect, so
  // the lease releases exactly once however this fans out.
  finish_txn_work(job.txn);
  if (job.owner == JobOwner::Group) {
    group_job_done(job, true, now_ms);
    return;
  }
  if (job.owner == JobOwner::GatewayService || job.owner == JobOwner::Config ||
      job.owner == JobOwner::AppObject) {
    // Completion stays deferred for the Owner's outside drive.
    if (component_jobs_outstanding_ > 0) --component_jobs_outstanding_;
    const bool service = job.owner == JobOwner::GatewayService;
    if (service ? gateway_sink_ != nullptr : config_sink_ != nullptr) {
      if (component_event_available()) {
        publish_component_event(service ? ComponentEventTarget::ServiceJobDone
                                        : ComponentEventTarget::ConfigJobDone,
                                job.peer, kInvalidTxnHandle, job.deadline_ms, nullptr,
                                &job.ack.key.id, true, "HOP_ACCEPTED");
      } else {
        observer_.on_diagnostic("COMPONENT_EVENT_LOST", job.peer,
                                &job.ack.key.id);
      }
    }
    return;
  }
  (void)hop_accepted;
  if (job.owner == JobOwner::Transit) {
    // sdk-completion/02 §2.6: a completed forward demotes its dedup record to
    // residual re-ACK/report-relay duty — Resolved is the evictable class.
    resolve_dedup_for_job(job);
    return;
  }
  if (job.owner != JobOwner::OriginDelivery) return;
  auto* delivery = find_delivery(job.ack.key.id);
  if (delivery == nullptr) return;
  if (job.plain.header.type != FrameType::Data) return;
  if (delivery->options.delivery == DeliveryClass::BestEffort) {
    // Same stale-job rule as below: a BestEffort frame that was still in
    // flight when its delivery settled (e.g. SLEEP_SAVED) must not overwrite
    // the settled verdict with a late TX_MAC_DONE.
    if (sleep_terminal(delivery->state)) {
      return;
    }
    set_delivery_state(*delivery, DeliveryState::Delivered, "TX_MAC_DONE");
    return;
  }
  // A verified RESULT/END_RECEIPT may have resolved the delivery while its
  // DATA job was still completing — for EVERY class the receipt wait must
  // never demote a terminal verdict (sdk-completion/01 §1.3).
  if (sleep_terminal(delivery->state)) {
    return;
  }
  delivery->next_round_at_ms = std::min(
      delivery->expires_at_ms,
      now_ms + applied_window_ms(delivery->options.hop_limit,
                                 config_.hop_accept_timeout_ms));
  set_delivery_state(*delivery, DeliveryState::WaitingForEndReceipt, "END_RECEIPT_PENDING");
}

void MeshNode::fail_job(TxJob& job, const char* reason,
                        const MonotonicMs now_ms, const bool terminal) noexcept {
  // A route update that failed after enqueue never refreshed its peer's
  // lease. Re-arm a bounded burst instead of waiting for the next period.
  if (job.form == JobForm::Plain && job.plain.header.type == FrameType::RouteUpdate &&
      job.peer != kBroadcastNodeId) {
    const auto* neighbor = find_neighbor(job.peer);
    if (neighbor != nullptr && neighbor->active) trigger_route_advertisement(now_ms + 50);
  }
  // Terminate the transaction work item first: the failure report below
  // reserves a fresh short transaction, which must see the freed capacity.
  finish_txn_work(job.txn);
  if (job.owner == JobOwner::Group) {
    (void)reason;
    group_job_done(job, false, now_ms);
    return;
  }
  if (job.owner == JobOwner::GatewayService || job.owner == JobOwner::Config ||
      job.owner == JobOwner::AppObject) {
    if (component_jobs_outstanding_ > 0) --component_jobs_outstanding_;
    const bool service = job.owner == JobOwner::GatewayService;
    if (service ? gateway_sink_ != nullptr : config_sink_ != nullptr) {
      if (component_event_available()) {
        publish_component_event(service ? ComponentEventTarget::ServiceJobDone
                                        : ComponentEventTarget::ConfigJobDone,
                                job.peer, kInvalidTxnHandle, job.deadline_ms, nullptr,
                                &job.ack.key.id, false, reason);
      } else {
        observer_.on_diagnostic("COMPONENT_EVENT_LOST", job.peer,
                                &job.ack.key.id);
      }
    }
    return;
  }
  // Accepted transit work that failed post-acceptance reports a bounded
  // TransitFailure to its retained upstream — BUSY is pre-acceptance only
  // and must never retract an earlier HOP_ACCEPT.
  if (job.owner == JobOwner::Transit) {
    report_transit_failure(job, reason, now_ms);
    return;
  }
  if (job.owner != JobOwner::OriginDelivery) return;
  auto* delivery = find_delivery(job.ack.key.id);
  if (delivery == nullptr) return;
  // A stale DATA job (queued/dispatched before the verdict landed — e.g. a
  // retry round in flight when a late END_RECEIPT resolved the delivery)
  // must never demote a terminal verdict: Delivered cannot fall back to
  // WaitingForRoute/Failed on evidence that predates the resolution.
  if (sleep_terminal(delivery->state)) {
    return;
  }
  // APPLIED: a stale DATA job failure must not cancel a result wait already
  // in progress, and must never demote a stored verdict (01 §1.5).
  if (delivery->options.delivery == DeliveryClass::Applied &&
      delivery->app_phase != 0) {
    return;
  }
  if (!terminal &&
      (delivery->options.delivery == DeliveryClass::Reliable ||
       delivery->options.delivery == DeliveryClass::Applied) &&
      now_ms < delivery->expires_at_ms &&
      static_cast<std::uint8_t>(delivery->round + 1U) < config_.max_end_to_end_rounds) {
    ++delivery->round;
    // Keep the last bounded round for recovery after receiver admission pressure.
    // Earlier hop/round retries stay fast; neither attempts nor lifetime increase.
    delivery->next_round_at_ms = std::min(delivery->expires_at_ms, now_ms + 50);
    if (delivery->round + 1U == config_.max_end_to_end_rounds &&
        delivery->expires_at_ms - delivery->next_round_at_ms > 5000) {
      delivery->next_round_at_ms = delivery->expires_at_ms - 5000;
    }
    set_delivery_state(*delivery, DeliveryState::WaitingForRoute, reason);
    return;
  }
  if (delivery->options.delivery == DeliveryClass::Applied &&
      (!terminal || job.physical_attempts != 0)) {
    // Rounds exhausted on a transmitted request — the destination may have
    // executed it; Indeterminate is the honest verdict (01 §1.9).
    set_delivery_state(*delivery, DeliveryState::Indeterminate, "APP_RESULT_TIMEOUT");
    return;
  }
  set_delivery_state(*delivery, DeliveryState::Failed, reason);
}

void MeshNode::retry_or_fail(TxJob& job, const char* reason,
                             const MonotonicMs now_ms) noexcept {
  if (group_origin_job_stale(job)) {
    // Settled while in flight: drop instead of re-queueing — a retry must
    // not resurrect a terminal origin verdict.
    observer_.on_diagnostic("STALE_JOB_DROPPED", job.peer, &job.ack.key.id);
    return;
  }
  if (now_ms >= work_deadline(job)) {
    fail_job(job, "DEADLINE_EXPIRED", now_ms);
    return;
  }
  ++job.attempts;
  if (job.attempts < job.max_attempts &&
      job.physical_attempts < kCombinedPhysicalAttemptsMax) {
    // Each SDK retry receives a fresh link counter. Reusing a captured frame would
    // make strict anti-replay incompatible with reliable delivery.
    job.encoded_tag = 0;
    // Link-retry decorrelation (radio.md §8): the re-queued job is not
    // select-eligible until the jittered delay elapses.
    job.not_before_ms = link_retry_not_before_ms(job, now_ms);
    TxJob pending = std::move(job);
    if (!scheduler_.enqueue(std::move(pending), config_.node, now_ms)) {
      fail_job(pending, "TX_QUEUE_FULL", now_ms);
    }
    return;
  }
  fail_job(job, reason, now_ms);
}

}  // namespace routeloom
