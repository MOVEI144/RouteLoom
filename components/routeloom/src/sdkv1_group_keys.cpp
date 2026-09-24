#include "routeloom/sdkv1_group_keys.hpp"

#include <limits>

#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {
MonotonicMs deadline(const MonotonicMs now, const std::uint16_t seconds) noexcept {
  const auto span = static_cast<MonotonicMs>(seconds) * 1000;
  return now > std::numeric_limits<MonotonicMs>::max() - span
             ? std::numeric_limits<MonotonicMs>::max() : now + span;
}
}  // namespace

GroupKeyState::~GroupKeyState() { expire(); }

void GroupKeyState::expire() noexcept {
  secure_clear(previous_);
  previous_epoch_ = 0;
  previous_deadline_ = 0;
  previous_started_ = 0;
}

bool GroupKeyState::accepts(const std::uint32_t epoch) const noexcept {
  return ready() && epoch != 0 &&
         (epoch == store_.site().gk_epoch_current ||
          epoch == store_.site().gk_epoch_next || epoch == previous_epoch_);
}

Status GroupKeyState::derive(const std::uint32_t epoch, ScopeDigest& prk) const noexcept {
  prk.fill(0);
  if (!ready() || in_call_ || epoch == 0) {
    return Status::error(StatusCode::AuthRequired, "group key unavailable");
  }
  const SiteRecord& site = store_.site();
  const keys::Secret* key = nullptr;
  if (epoch == site.gk_epoch_current) key = &site.gk_current;
  else if (epoch == site.gk_epoch_next) key = &site.gk_next;
  else if (epoch == previous_epoch_) key = &previous_;
  if (key == nullptr) return Status::error(StatusCode::AuthRequired, "group epoch retired");
  keys::group_prk(site.network, *key, prk);
  return Status::success();
}

Status GroupKeyState::promote(const std::uint32_t epoch, const std::uint32_t witness,
                              const MonotonicMs now) noexcept {
  if (epoch != store_.site().gk_epoch_next) {
    return Status::error(StatusCode::Conflict, "next group epoch changed");
  }
  keys::Secret old = store_.site().gk_current;
  const std::uint32_t old_epoch = store_.site().gk_epoch_current;
  const Status status = store_.activate_group_key(epoch, witness);
  if (!status) {
    blocked_ = true;  // the first write might have committed: never fall back
    expire();
    return status;
  }
  expire();
  previous_ = old;
  previous_epoch_ = old_epoch;
  previous_deadline_ = deadline(now, overlap_s_);
  previous_started_ = now;
  secure_clear(old);
  pending_ = false;
  return Status::success();
}

Status GroupKeyState::advance(const Input& input, const MonotonicMs now) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "group operation re-entry");
  in_call_ = true;
  Status status = Status::success();
  switch (input.op) {
    case Op::Start: {
      // Restart is Owner-controlled: it never resets counters in an active
      // boot. A new instance may start only after rlboot is durable.
      if (started_) { status = Status::error(StatusCode::InvalidState, "group already started"); break; }
      if (!store_.initialized() || !store_.has_site() || store_.quarantined() ||
          store_.uncertain() || store_.health().active_load_failed) {
        status = Status::error(StatusCode::RecoveryRequired, "site record unavailable");
        break;
      }
      if (store_.group_scrub_needed()) {
        status = store_.finish_group_scrub();
        if (!status) break;
      }
      boot_ = input.boot;
      boot_ok_ = boot_ != 0 && boot_ >= store_.site().boot_witness;
      started_ = true;
      blocked_ = false;
      break;
    }
    case Op::Stage:
      if (!ready() || input.generation != store_.site().assignment_generation ||
          (input.overlap_s != 10 && input.overlap_s != 60)) {
        status = Status::error(StatusCode::Conflict, "group update binding"); break;
      }
      // A newer stage retires the RAM-only old generation; at most two
      // generations can be used for receive after the durable write.
      {
        const std::uint32_t prior_next = store_.site().gk_epoch_next;
        status = store_.stage_group_key(input.epoch, input.key);
        if (status && input.epoch == store_.site().gk_epoch_next) {
          if (input.epoch != prior_next) {
            expire();
            overlap_s_ = input.overlap_s;
            pending_ = false;
          } else if (input.overlap_s < overlap_s_) {
            overlap_s_ = input.overlap_s;
          }
        }
      }
      if (!status && status.code != StatusCode::Conflict) {
        blocked_ = true;
        expire();
      }
      break;
    case Op::Activate:
      if (!ready() || input.generation != store_.site().assignment_generation ||
          (input.overlap_s != 10 && input.overlap_s != 60)) {
        status = Status::error(StatusCode::Conflict, "group activation binding"); break;
      }
      if (input.epoch == current() && store_.site().gk_epoch_next == 0) break;
      overlap_s_ = input.overlap_s;
      status = promote(input.epoch, input.boot, now);
      break;
    case Op::AuthenticatedNext:
      if (!ready() || input.epoch == 0 || input.epoch != store_.site().gk_epoch_next) {
        status = Status::error(StatusCode::Conflict, "not a staged group frame"); break;
      }
      pending_ = true;  // never write flash in the AEAD callback
      break;
    case Op::Tick:
      if (!ready()) { status = Status::error(StatusCode::RecoveryRequired, "group blocked"); break; }
      if (previous_epoch_ && (now >= previous_deadline_ || now < previous_started_)) expire();
      if (pending_) status = promote(store_.site().gk_epoch_next, boot_, now);
      break;
    case Op::Stop:
      expire();
      started_ = false;
      blocked_ = true;
      pending_ = false;
      boot_ok_ = false;
      break;
  }
  in_call_ = false;
  return status;
}

bool GkMemberScopeProvider::current_generation(const ScopeRef scope,
                                                 std::uint32_t& out) noexcept {
  out = 0;
  if (scope != member_ || member_ == kInvalidScopeRef || !keys_.ready() || keys_.in_call())
    return false;
  out = keys_.current();
  return out != 0;
}

bool GkMemberScopeProvider::accepted_generation(const ScopeRef scope,
                                                   const std::uint32_t generation,
                                                   const MonotonicMs now) noexcept {
  if (scope != member_ || keys_.in_call()) return false;
  // Expiry is advanced by the Owner tick, never by an untrusted DISCOVER.
  return keys_.accepts(generation) &&
         (generation != keys_.previous_epoch_ || now < keys_.previous_deadline_);
}

Status GkMemberScopeProvider::scope_tag(const ScopeRef scope,
                                         const std::uint32_t generation,
                                         const ByteView input, ScopeTag& out) noexcept {
  out.fill(0);
  if (scope != member_ || !keys_.accepts(generation) || keys_.in_call()) {
    return Status::error(StatusCode::AuthRequired, "member scope unavailable");
  }
  ScopeDigest prk{};
  keys::Secret dsk{};
  Status status = keys_.derive(generation, prk);
  if (status) status = keys::group_dsk_key(prk, generation, dsk);
  if (status) {
    ScopeDigest digest{};
    hmac_sha256(ByteView{dsk.data(), dsk.size()}, input, digest);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = digest[i];
    secure_clear(digest);
  }
  secure_clear(dsk);
  secure_clear(prk);
  return status;
}

}  // namespace routeloom::sdkv1
