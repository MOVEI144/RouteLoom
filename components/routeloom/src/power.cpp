#include "routeloom/power.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kImageMagic = 0x524c5057;  // "RLPW"
constexpr std::size_t kImageHeaderSize = 32;
constexpr std::size_t kImagePeerSize = 20;
constexpr std::size_t kImagePendingSize = 157;
constexpr std::size_t kImageCrcOffset = kPowerImageRecordSize - 4;

static_assert(kImageHeaderSize +
                      kPowerPeerCacheCapacity * kImagePeerSize +
                      kPowerPendingCapacity * kImagePendingSize + 4 ==
                  kPowerImageRecordSize,
              "sleep image record layout must stay fixed-size");

Status encode_image(const PowerImage& image,
                    std::array<std::uint8_t, kPowerImageRecordSize>& out) noexcept {
  out.fill(0);
  ByteWriter writer(MutableByteView{out.data(), out.size()});
  Status status;
#define RL_WRITE(expr)            \
  do {                            \
    status = (expr);              \
    if (!status) return status;   \
  } while (false)
  RL_WRITE(writer.write_u32(kImageMagic));
  RL_WRITE(writer.write_u16(static_cast<std::uint16_t>(kPowerImageSchemaVersion)));
  RL_WRITE(writer.write_u32(image.sequence));
  RL_WRITE(writer.write_u64(image.network));
  RL_WRITE(writer.write_u64(image.node));
  RL_WRITE(writer.write_u32(image.config_revision));
  RL_WRITE(writer.write_u8(image.channel));
  RL_WRITE(writer.write_u8(0));
  for (const auto& peer : image.peers) {
    RL_WRITE(writer.write_u64(peer.node));
    RL_WRITE(writer.write_bytes(ByteView{peer.address.data(), peer.address.size()}));
    RL_WRITE(writer.write_u8(peer.address_size));
    RL_WRITE(writer.write_u16(peer.metric));
    RL_WRITE(writer.write_u8(peer.used ? 1 : 0));
  }
  for (const auto& pending : image.pending) {
    RL_WRITE(writer.write_u32(pending.original_id.session));
    RL_WRITE(writer.write_u64(pending.original_id.sequence));
    RL_WRITE(writer.write_u64(pending.destination));
    RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(pending.delivery)));
    RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(pending.priority)));
    RL_WRITE(writer.write_u8(pending.hop_limit));
    RL_WRITE(writer.write_u8(pending.payload_size));
    RL_WRITE(writer.write_u32(pending.stored_remaining_ms));
    RL_WRITE(writer.write_u8(pending.used ? 1 : 0));
    RL_WRITE(writer.write_bytes(ByteView{pending.payload.data(), pending.payload.size()}));
  }
#undef RL_WRITE
  if (writer.size() != kImageCrcOffset) {
    return Status::error(StatusCode::InternalError, "sleep image encode size");
  }
  const std::uint32_t crc =
      crc32_iso_hdlc(ByteView{out.data(), kImageCrcOffset});
  status = writer.write_u32(crc);
  if (!status) return status;
  return writer.size() == kPowerImageRecordSize
             ? Status::success()
             : Status::error(StatusCode::InternalError, "sleep image encode size");
}

Status decode_image(const ByteView record, PowerImage& image) noexcept {
  if (record.data == nullptr || record.size != kPowerImageRecordSize) {
    return Status::error(StatusCode::IntegrityError, "sleep image size");
  }
  const std::uint32_t expected =
      crc32_iso_hdlc(ByteView{record.data, kImageCrcOffset});
  ByteReader reader(record);
  std::uint32_t magic = 0;
  std::uint16_t schema = 0;
  Status status;
#define RL_READ(expr)             \
  do {                            \
    status = (expr);              \
    if (!status) return status;   \
  } while (false)
  RL_READ(reader.read_u32(magic));
  RL_READ(reader.read_u16(schema));
  if (magic != kImageMagic || schema != kPowerImageSchemaVersion) {
    return Status::error(StatusCode::IntegrityError, "sleep image magic/schema");
  }
  RL_READ(reader.read_u32(image.sequence));
  RL_READ(reader.read_u64(image.network));
  RL_READ(reader.read_u64(image.node));
  RL_READ(reader.read_u32(image.config_revision));
  RL_READ(reader.read_u8(image.channel));
  std::uint8_t scratch = 0;
  RL_READ(reader.read_u8(scratch));
  for (auto& peer : image.peers) {
    std::uint8_t used = 0;
    RL_READ(reader.read_u64(peer.node));
    RL_READ(reader.read_bytes(
        MutableByteView{peer.address.data(), peer.address.size()}));
    RL_READ(reader.read_u8(peer.address_size));
    RL_READ(reader.read_u16(peer.metric));
    RL_READ(reader.read_u8(used));
    peer.used = used != 0;
  }
  for (auto& pending : image.pending) {
    std::uint8_t delivery = 0;
    std::uint8_t priority = 0;
    std::uint8_t used = 0;
    RL_READ(reader.read_u32(pending.original_id.session));
    RL_READ(reader.read_u64(pending.original_id.sequence));
    RL_READ(reader.read_u64(pending.destination));
    RL_READ(reader.read_u8(delivery));
    RL_READ(reader.read_u8(priority));
    RL_READ(reader.read_u8(pending.hop_limit));
    RL_READ(reader.read_u8(pending.payload_size));
    RL_READ(reader.read_u32(pending.stored_remaining_ms));
    RL_READ(reader.read_u8(used));
    RL_READ(reader.read_bytes(
        MutableByteView{pending.payload.data(), pending.payload.size()}));
    if (delivery > static_cast<std::uint8_t>(DeliveryClass::Applied) ||
        priority > static_cast<std::uint8_t>(Priority::Urgent)) {
      return Status::error(StatusCode::IntegrityError, "sleep image enum range");
    }
    pending.delivery = static_cast<DeliveryClass>(delivery);
    pending.priority = static_cast<Priority>(priority);
    pending.used = used != 0;
    if (pending.payload_size > kMaxApplicationPayload) {
      return Status::error(StatusCode::IntegrityError, "sleep image payload size");
    }
  }
  std::uint32_t crc = 0;
  RL_READ(reader.read_u32(crc));
#undef RL_READ
  if (reader.remaining() != 0 || crc != expected) {
    return Status::error(StatusCode::IntegrityError, "sleep image crc");
  }
  return Status::success();
}

std::size_t peer_count(const PowerImage& image) noexcept {
  std::size_t count = 0;
  for (const auto& peer : image.peers) count += peer.used ? 1U : 0U;
  return count;
}

bool has_pending(const PowerImage& image) noexcept {
  for (const auto& pending : image.pending) {
    if (pending.used) return true;
  }
  return false;
}

}  // namespace

const char* power_state_name(const PowerState state) noexcept {
  switch (state) {
    case PowerState::Running: return "RUNNING";
    case PowerState::Draining: return "DRAINING";
    case PowerState::Persisting: return "PERSISTING";
    case PowerState::ReadyToSleep: return "READY_TO_SLEEP";
    case PowerState::Sleeping: return "SLEEPING";
    case PowerState::Resuming: return "RESUMING";
  }
  return "UNKNOWN";
}

const char* resume_outcome_name(const ResumeOutcome outcome) noexcept {
  switch (outcome) {
    case ResumeOutcome::None: return "NONE";
    case ResumeOutcome::ColdStart: return "COLD_START";
    case ResumeOutcome::FastResume: return "FAST_RESUME";
    case ResumeOutcome::DiscoveryRequired: return "DISCOVERY_REQUIRED";
    case ResumeOutcome::CacheLost: return "CACHE_LOST";
  }
  return "UNKNOWN";
}

PowerCoordinator::PowerCoordinator(const PowerConfig& config, MeshNode& node,
                                   PowerPort& port, PowerStorage& storage,
                                   PowerEvents& events) noexcept
    : config_(config), node_(node), port_(port), storage_(storage),
      events_(events) {}

void PowerCoordinator::transition(const PowerState next,
                                  const char* reason) noexcept {
  if (state_ == next) return;
  const PowerState from = state_;
  const std::uint32_t attempt = attempt_;
  events_.on_transition(from, next, reason);
  // The notification runs application code: a veto inside it (sleep_abort,
  // which bumps attempt_ and lands in RUNNING) already drove the machine.
  // Never overwrite that outcome with this transition's stale target.
  if (state_ != from || attempt_ != attempt) return;
  state_ = next;
}

std::uint32_t PowerCoordinator::pending_generation() const noexcept {
  return node_.work_generation() + app_events_;
}

bool PowerCoordinator::ticket_valid(const SleepTicket& ticket) const noexcept {
  return ticket.issued && ticket_.issued && ticket.id == ticket_.id &&
         ticket.radio_generation == radio_generation_ &&
         ticket.config_revision == node_.config_revision() &&
         ticket.pending_generation == pending_generation();
}

void PowerCoordinator::issue_ticket() noexcept {
  ticket_ = SleepTicket{next_ticket_id_++, radio_generation_,
                        node_.config_revision(), pending_generation(), true};
}

Status PowerCoordinator::begin(const ResetCause cause,
                               const ElapsedInterval elapsed,
                               const MonotonicMs now_ms) noexcept {
  if (begun_) {
    return Status::error(StatusCode::AlreadyExists, "coordinator already begun");
  }
  begun_ = true;
  cause_ = cause;
  transition(PowerState::Resuming,
             cause == ResetCause::DeepSleepWake ? "WAKE_DEEP_SLEEP" : "BOOT");
  resume_flow(cause, elapsed, now_ms);
  return Status::success();
}

Status PowerCoordinator::sleep_prepare(const SleepRequest& request,
                                       const MonotonicMs now_ms) noexcept {
  if (!begun_ || state_ != PowerState::Running || !node_.started()) {
    return Status::error(StatusCode::InvalidState, "not running");
  }
  request_ = request;
  node_.set_draining(true);
  drain_deadline_ms_ = now_ms + config_.drain_timeout_ms;
  // New attempt: every callback site from here on pins this generation so
  // re-entrant aborts/prepares cannot resume stale work on its behalf.
  ++attempt_;
  transition(PowerState::Draining, "SLEEP_PREPARE");
  return Status::success();
}

Status PowerCoordinator::sleep_abort(const char* reason) noexcept {
  // PERSISTING is the settlement window inside finish_drain: an application
  // callback fired by a disposition may veto the sleep before the ticket
  // exists. Work already settled stays settled — the same contract as an
  // abort from READY_TO_SLEEP, where the durable image is already committed.
  if (state_ != PowerState::Draining && state_ != PowerState::Persisting &&
      state_ != PowerState::ReadyToSleep) {
    return Status::error(StatusCode::InvalidState, "no sleep in progress");
  }
  abort_to_running(reason == nullptr ? "SLEEP_ABORT_REQUEST" : reason);
  return Status::success();
}

Status PowerCoordinator::sleep_enter(const SleepTicket& ticket,
                                     const MonotonicMs now_ms) noexcept {
  if (state_ != PowerState::ReadyToSleep) {
    return Status::error(StatusCode::InvalidState, "not ready to sleep");
  }
  if (!image_valid_) {
    // READY_TO_SLEEP is only reachable after commit_image() succeeded, but
    // re-check the durable flag: entering deep sleep without a committed
    // image would silently lose the resume context.
    return Status::error(StatusCode::InvalidState, "SLEEP_IMAGE_MISSING");
  }
  if (!ticket_valid(ticket)) {
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  // Time spent waiting in READY_TO_SLEEP is real elapsed lifetime: re-derive
  // every pending's remaining budget against its absolute deadline and
  // re-commit the image so work that expired while waiting is not
  // resurrected after the wake.
  bool pending_changed = false;
  for (auto& record : image_.pending) {
    if (!record.used) continue;
    if (record.expires_at_ms <= now_ms) {
      events_.on_pending_result(record, StatusCode::Expired);
      record.used = false;
      pending_changed = true;
      continue;
    }
    const auto remaining =
        static_cast<std::uint32_t>(record.expires_at_ms - now_ms);
    if (remaining != record.stored_remaining_ms) {
      record.stored_remaining_ms = remaining;
      pending_changed = true;
    }
  }
  if (pending_changed) {
    // Write the refreshed image to BOTH slots: if a power cut tears one
    // commit, the other still carries the corrected lifetimes rather than an
    // older image whose longer budgets would resurrect expired work.
    for (std::uint8_t copy = 0; copy < kPowerImageSlots; ++copy) {
      image_.sequence = image_sequence_ + 1;
      const auto refresh = commit_image(image_);
      if (!refresh) {
        // Abort instead of sleeping on a stale image. The durable records
        // are not lost; they survive for a later resume.
        abort_to_running(refresh.detail);
        return refresh;
      }
    }
  }
  // The on_pending_result notifications above are app callbacks: one may
  // have vetoed the sleep. Never consume the ticket on an aborted attempt.
  if (state_ != PowerState::ReadyToSleep) {
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  ticket_ = SleepTicket{};  // consume: no other ticket can re-enter
  transition(PowerState::Sleeping, "SLEEP_ENTER");
  if (state_ != PowerState::Sleeping) {
    // The transition notification vetoed the entry — the abort already
    // landed the coordinator in RUNNING; do not enter sleep behind it.
    return Status::error(StatusCode::InvalidState, "SLEEP_ABORTED");
  }
  auto status = port_.configure_wake(request_.wake);
  if (status) status = port_.enter_sleep();
  if (!status) {
    abort_to_running("SLEEP_ENTER_FAILED");
    return status;
  }
  return Status::success();
}

Status PowerCoordinator::wake(const ResetCause cause,
                              const ElapsedInterval elapsed,
                              const MonotonicMs now_ms) noexcept {
  if (state_ != PowerState::Sleeping) {
    return Status::error(StatusCode::InvalidState, "not sleeping");
  }
  cause_ = cause;
  transition(PowerState::Resuming, "WAKE");
  resume_flow(cause, elapsed, now_ms);
  return Status::success();
}

void PowerCoordinator::poll(const MonotonicMs now_ms) noexcept {
  switch (state_) {
    case PowerState::Running:
      node_.poll(now_ms);
      break;
    case PowerState::Draining: {
      // node_.poll() runs app callbacks (delivery/group terminal events):
      // an abort or re-prepare inside one ends this attempt — the stale
      // attempt must not roll into finish_drain on its old deadline.
      const std::uint32_t attempt = attempt_;
      node_.poll(now_ms);
      if (attempt_ != attempt || state_ != PowerState::Draining) break;
      if (node_.quiesced() || now_ms >= drain_deadline_ms_) {
        finish_drain(attempt, now_ms);
      }
      break;
    }
    case PowerState::ReadyToSleep:
      // Radio is quiesced; a ticket invalidated by late activity aborts the
      // sleep attempt instead of entering on a stale snapshot.
      if (!ticket_valid(ticket_)) {
        abort_to_running("SLEEP_TICKET_INVALID");
      }
      break;
    case PowerState::Resuming:
      node_.poll(now_ms);
      // Only inbound peer traffic confirms a fast resume: a failed TX
      // callback or an app send must not count as peers answering.
      if (node_.rx_generation() != confirm_baseline_) {
        outcome_ = ResumeOutcome::FastResume;
        transition(PowerState::Running, "RESUME_CONFIRMED");
      } else if (now_ms >= resume_deadline_ms_) {
        if (!discovery_started_) {
          discovery_started_ = true;
          const auto discovery = port_.start_discovery(image_);
          events_.on_diagnostic(discovery ? "RESUME_DISCOVERY_STARTED"
                                        : discovery.detail);
        }
        outcome_ = ResumeOutcome::DiscoveryRequired;
        transition(PowerState::Running, "RESUME_UNCONFIRMED");
      }
      break;
    case PowerState::Persisting:
    case PowerState::Sleeping:
      break;
  }
}

void PowerCoordinator::finish_drain(const std::uint32_t attempt,
                                    const MonotonicMs now_ms) noexcept {
  // Pinned attempt only: an abort or a re-prepare seen between poll() and
  // here means a different sleep attempt owns the machine now.
  if (attempt_ != attempt || state_ != PowerState::Draining) return;
  transition(PowerState::Persisting,
             node_.quiesced() ? "DRAIN_SETTLED" : "DRAIN_DEADLINE");
  // The transition notification itself is application code — it may have
  // vetoed the attempt (sleep_abort) or replaced it (sleep_prepare).
  if (attempt_ != attempt || state_ != PowerState::Persisting) return;
  // Records already durable in the previous image — e.g. a pending retained
  // when its resume re-inject failed — are invisible to the node snapshot
  // below: the live delivery is no longer offerable. They are carried over
  // explicitly once the fresh snapshot has landed. The whole image is kept
  // for rollback: while the deliveries it references are still live (i.e.
  // until apply_sleep_dispositions runs), image_ must only ever describe
  // durable-bound pendings. An abort before then restores this image so the
  // uncommitted snapshot cannot leak into the next drain's carry-over set
  // and resurrect work that completed while the node stayed awake.
  const auto previous_image = image_;
  image_ = PowerImage{};
  image_.network = node_.config().network;
  image_.node = node_.config().node;
  // Phase 1: snapshot durable work into the image WITHOUT changing delivery
  // state. If the commit below fails, abort_to_running leaves every delivery
  // live so the work can retry instead of being marked SLEEP_SAVED and lost.
  node_.snapshot_for_sleep(request_.pending_policy,
                           [&](const DeliverySnapshot& snapshot) {
                             if (snapshot.expires_at_ms <= now_ms) return false;
                             for (auto& record : image_.pending) {
                               if (record.used) continue;
                               record.used = true;
                               record.original_id = snapshot.id;
                               record.destination = snapshot.destination;
                               record.delivery = snapshot.options.delivery;
                               record.priority = snapshot.options.priority;
                               record.hop_limit = snapshot.options.hop_limit;
                               record.expires_at_ms = snapshot.expires_at_ms;
                               record.stored_remaining_ms = static_cast<std::uint32_t>(
                                   snapshot.expires_at_ms - now_ms);
                               record.payload_size = static_cast<std::uint8_t>(
                                   snapshot.payload.size);
                               if (snapshot.payload.size != 0) {
                                 std::memcpy(record.payload.data(), snapshot.payload.data,
                                             snapshot.payload.size);
                               }
                               return true;
                             }
                             return false;
                           });
  // Carry over still-live records the snapshot did not cover. A record the
  // snapshot re-persisted under the same logical id is superseded by it;
  // one that outlived its deadline while awake terminates loudly here; one
  // that cannot fit reports NoCapacity rather than vanishing silently.
  bool previous_had_pending = false;
  for (const auto& record : previous_image.pending) {
    if (!record.used) continue;
    previous_had_pending = true;
    bool covered = false;
    for (const auto& fresh : image_.pending) {
      if (fresh.used && fresh.original_id == record.original_id) {
        covered = true;
        break;
      }
    }
    if (covered) continue;
    if (record.expires_at_ms <= now_ms) {
      events_.on_pending_result(record, StatusCode::Expired);
      continue;
    }
    bool placed = false;
    for (auto& slot : image_.pending) {
      if (slot.used) continue;
      slot = record;
      slot.stored_remaining_ms =
          static_cast<std::uint32_t>(record.expires_at_ms - now_ms);
      placed = true;
      break;
    }
    if (!placed) {
      events_.on_pending_result(record, StatusCode::NoCapacity);
    }
  }
  // on_pending_result() is an app callback too: a veto inside it ends this
  // attempt — keep the uncommitted snapshot out of the next drain's
  // carry-over set, exactly like the commit-failure rollback below.
  if (attempt_ != attempt || state_ != PowerState::Persisting) {
    image_ = previous_image;
    return;
  }
  const auto status = persist_image();
  if (!status) {
    // Abort before dispositions ran: the rebuilt image was never persisted
    // and every delivery it captured is still live. Roll back so its
    // records do not become holdover input for the next drain.
    image_ = previous_image;
    abort_to_running(status.detail);
    return;
  }
  if (previous_had_pending) {
    // The slot this commit did not touch still holds the previous image,
    // whose copies of these records carry a longer, pre-decay stored
    // budget. Overwrite it too so a torn commit cannot resurrect that
    // budget — same dual-write pattern sleep_enter uses for its refresh.
    image_.sequence = image_sequence_ + 1;
    const auto second = commit_image(image_);
    if (!second) {
      image_ = previous_image;
      abort_to_running(second.detail);
      return;
    }
  }
  // Phase 2: the image is durable — only now apply dispositions. Every
  // callback this runs (delivery terminal, group settled, released holds)
  // still sees the coordinator in PERSISTING with the node draining: a
  // send()/send_group() inside one is refused by the drain pause, and a
  // sleep_abort() lands in RUNNING instead of racing a ticket that does not
  // exist yet. `still_current` pins the settlement to this attempt — an
  // abort or a re-prepare inside any callback stops it item-by-item, so the
  // old attempt can never settle work belonging to a new one.
  const std::uint32_t app_events = app_events_;
  node_.apply_sleep_dispositions(
      request_.pending_policy, [&](const MessageId& id) {
        for (const auto& record : image_.pending) {
          if (record.used && record.original_id == id) return true;
        }
        return false;
      },
      [&] {
        return attempt_ == attempt && state_ == PowerState::Persisting;
      });
  // A disposition callback aborted the sleep: the node is already back in
  // RUNNING with its queues live — no teardown, no radio quiesce, no ticket.
  if (attempt_ != attempt || state_ != PowerState::Persisting) return;
  node_.quiesce_for_sleep();
  const auto radio = port_.quiesce_radio();
  if (!radio) {
    abort_to_running(radio.detail);
    return;
  }
  radio_quiesced_ = true;
  ++radio_generation_;
  // A notify_app_event() inside any callback above must invalidate the
  // sleep exactly like late activity does in READY_TO_SLEEP — a ticket
  // issued now would bake the event in and be born valid. Refused sends
  // are NOT vetoed here: their work_generation bump is already covered by
  // the deterministic NODE_DRAINING error returned to the caller.
  if (app_events_ != app_events) {
    abort_to_running("SLEEP_TICKET_INVALID");
    return;
  }
  issue_ticket();
  transition(PowerState::ReadyToSleep, "SLEEP_READY");
}

Status PowerCoordinator::persist_image() noexcept {
  // Durable commit only: capture the platform cache and write the image.
  // Radio quiesce, the ticket and the READY_TO_SLEEP transition belong to
  // finish_drain AFTER the settlement — issuing them here would let a
  // disposition callback observe READY_TO_SLEEP while its own work is
  // still being torn down.
  image_.sequence = image_sequence_ + 1;
  image_.config_revision = node_.config_revision();
  auto status = port_.capture_cache(image_);
  if (!status) return status;
  return commit_image(image_);
}

Status PowerCoordinator::commit_image(const PowerImage& image) noexcept {
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  auto status = encode_image(image, record);
  if (!status) return status;
  status = storage_.write(static_cast<std::uint8_t>(image.sequence & 1U),
                          ByteView{record.data(), record.size()});
  if (!status) return status;
  image_sequence_ = image.sequence;
  image_valid_ = true;
  return Status::success();
}

Status PowerCoordinator::load_image(PowerImage& image, bool& found) noexcept {
  found = false;
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  bool any = false;
  std::uint32_t best_sequence = 0;
  for (std::uint8_t slot = 0; slot < kPowerImageSlots; ++slot) {
    const auto status =
        storage_.read(slot, MutableByteView{record.data(), record.size()});
    if (!status) {
      events_.on_diagnostic(status.detail);
      continue;
    }
    PowerImage candidate{};
    if (!decode_image(ByteView{record.data(), record.size()}, candidate)) {
      continue;  // torn/corrupt slot: discard, never erase
    }
    if (!any || candidate.sequence > best_sequence) {
      image = candidate;
      best_sequence = candidate.sequence;
      any = true;
    }
  }
  if (any) {
    found = true;
    image_sequence_ = best_sequence;
  }
  return Status::success();
}

bool PowerCoordinator::image_usable(const PowerImage& image) const noexcept {
  // Identity binding only. config_revision is persisted in the image for
  // diagnostics but deliberately not compared here: MeshNode::config_revision
  // also bumps on runtime peer add/remove, so a freshly-booted node would
  // never match a stored image and every resume would degrade to cold start.
  return image.network == node_.config().network &&
         image.node == node_.config().node;
}

void PowerCoordinator::resume_flow(const ResetCause cause,
                                   const ElapsedInterval elapsed,
                                   const MonotonicMs now_ms) noexcept {
  outcome_ = ResumeOutcome::None;
  discovery_started_ = false;
  radio_quiesced_ = false;
  image_valid_ = false;

  PowerImage stored{};
  bool found = false;
  (void)load_image(stored, found);
  const bool usable = found && image_usable(stored);
  if (found && !usable) {
    events_.on_diagnostic("SLEEP_IMAGE_CONTEXT_MISMATCH");
  }

  // Saved peers first, then the platform's current peer table (static config
  // covers the cold path). Duplicates keep the platform record — it is the
  // authoritative current configuration.
  PowerImage platform{};
  (void)port_.capture_cache(platform);
  PowerImage merged = usable ? stored : PowerImage{};
  for (const auto& peer : platform.peers) {
    if (!peer.used) continue;
    bool placed = false;
    for (auto& slot : merged.peers) {
      if (slot.used && slot.node == peer.node) {
        slot = peer;
        placed = true;
      }
    }
    if (placed) continue;
    for (auto& slot : merged.peers) {
      if (!slot.used) {
        slot = peer;
        break;
      }
    }
  }
  merged.channel = usable && stored.channel != 0 ? stored.channel
                                                 : platform.channel;

  ++radio_generation_;
  const auto radio = port_.start_radio(&merged);
  if (!radio) events_.on_diagnostic(radio.detail);

  if (!node_.started()) {
    (void)node_.start(now_ms);
  }
  node_.set_draining(false);
  for (const auto& peer : merged.peers) {
    if (peer.used) {
      (void)node_.add_neighbor(peer.node, peer.metric, now_ms);
    }
  }

  if (usable) {
    restore_pending(stored, elapsed, now_ms, merged);
    if (has_pending(stored)) {
      // Consume only the pendings that were re-injected; records whose send
      // failed stay in `merged.pending` so the next sleep image retains them
      // instead of silently dropping durable work.
      merged.sequence = image_sequence_ + 1;
      (void)commit_image(merged);
    }
  }
  image_ = merged;

  if (peer_count(merged) == 0) {
    const bool expected = cause == ResetCause::DeepSleepWake;
    outcome_ = usable ? ResumeOutcome::ColdStart
                      : (expected || found) ? ResumeOutcome::CacheLost
                                            : ResumeOutcome::ColdStart;
    transition(PowerState::Running, "COLD_START");
    return;
  }
  confirm_baseline_ = node_.rx_generation();
  resume_deadline_ms_ = now_ms + config_.resume_confirm_ms;
  // Stay RESUMING: poll() confirms saved peers inside the window or starts
  // bounded discovery on expiry.
}

void PowerCoordinator::restore_pending(const PowerImage& image,
                                       const ElapsedInterval elapsed,
                                       const MonotonicMs now_ms,
                                       PowerImage& retained) noexcept {
  for (std::size_t i = 0; i < image.pending.size(); ++i) {
    const PendingDeliveryRecord& record = image.pending[i];
    if (!record.used) continue;
    // Same-index slot in `retained` tracks what survives this resume. The
    // default below is "consumed": mark the retained copy unused unless the
    // re-inject fails and the record must outlive this boot.
    PendingDeliveryRecord* keep =
        i < retained.pending.size() ? &retained.pending[i] : nullptr;
    if (keep != nullptr) keep->used = false;
    std::uint32_t remaining = 0;
    const auto resumed = resume_remaining_lifetime(
        config_.deadline_policy, record.stored_remaining_ms, elapsed, remaining);
    if (!resumed) {
      // TIME_UNCERTAIN/EXPIRED: never auto-resend on a fabricated clock.
      events_.on_pending_result(record, resumed.code);
      continue;
    }
    const SendOptions options{record.delivery, record.priority, remaining,
                              record.hop_limit, true};
    // Resume under the ORIGINAL logical id, not a fresh send() allocation:
    // the destination may already have delivered the payload and lost only
    // the end receipt — terminal dedup keyed on this id must still suppress
    // the retransmission so the application never sees it twice. Fresh link
    // counters are fine; logical identity is what dedup tracks.
    const auto sent = node_.resume_delivery(
        record.original_id, record.destination,
        ByteView{record.payload.data(), record.payload_size}, options, now_ms);
    events_.on_pending_result(record, sent.ok() ? StatusCode::Ok : sent.code);
    if (!sent.ok() && keep != nullptr) {
      // Re-injection failed (queue full, draining, ...): keep the durable
      // record — with the decayed lifetime — so a later sleep image retries
      // it instead of dropping it at the storage layer. expires_at_ms is
      // RAM-only bookkeeping, so it is re-anchored on this boot's clock and
      // awake time still counts against the deadline.
      *keep = record;
      keep->used = true;
      keep->stored_remaining_ms = remaining;
      keep->expires_at_ms = now_ms + remaining;
    }
  }
}

void PowerCoordinator::abort_to_running(const char* reason) noexcept {
  // Bump BEFORE any callback: the attempt is over the moment we commit to
  // aborting, so every pinned check — including re-entrant ones fired from
  // the notifications below — sees it as stale.
  ++attempt_;
  events_.on_diagnostic(reason);
  ticket_ = SleepTicket{};
  if (radio_quiesced_) {
    ++radio_generation_;
    (void)port_.start_radio(&image_);
    radio_quiesced_ = false;
  }
  node_.set_draining(false);
  transition(PowerState::Running, "SLEEP_ABORTED");
}

}  // namespace routeloom
