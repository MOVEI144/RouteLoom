#include "routeloom/sdkv1_group_security.hpp"

#include <cstring>

#include "routeloom/group.hpp"
#include "routeloom/secure_clear.hpp"
#include "routeloom/sdkv1_store.hpp"

namespace routeloom::sdkv1 {
namespace {
bool group_scope(const SecurityScope scope) noexcept {
  return scope == SecurityScope::Group || scope == SecurityScope::GroupLink;
}
std::uint32_t gk_epoch(const SecurityContext& c) noexcept {
  return c.scope == SecurityScope::Group ? c.epoch : c.group_epoch;
}
std::uint32_t sender_boot(const SecurityContext& c) noexcept {
  return c.scope == SecurityScope::Group ? c.sender_boot : c.epoch;
}
}  // namespace

GroupSecurityProvider::~GroupSecurityProvider() {
  secure_clear(staging_);
}

bool GroupSecurityProvider::revoked_group_sender(const NodeId sender) const noexcept {
  if (revocations_ == nullptr || !revocations_->has_set() ||
      !keys_.store_.has_site()) return false;
  const RevocationSet& set = revocations_->set();
  const SiteRecord& site = keys_.store_.site();
  if (set.site_id != site.site_id || set.network != site.network) return false;
  for (std::size_t i = 0; i < set.count; ++i) {
    if (set.entries[i].node_id == sender) return true;
  }
  return false;
}

Status GroupSecurityProvider::tx_epoch(const SecurityScope scope, const NodeId peer,
                                        std::uint32_t& epoch) noexcept {
  if (!group_scope(scope)) return pairwise_.tx_epoch(scope, peer, epoch);
  if (in_call_) return Status::error(StatusCode::Busy, "group provider re-entry");
  if (scope != SecurityScope::Group || peer != kBroadcastNodeId || !keys_.tx_ready())
    return Status::error(StatusCode::AuthRequired, "group TX unavailable");
  epoch = keys_.current();
  return Status::success();
}

ContextState GroupSecurityProvider::context_state(const SecurityScope scope,
                                                    const NodeId peer) const noexcept {
  if (!group_scope(scope)) return pairwise_.context_state(scope, peer);
  return keys_.tx_ready() ? ContextState::Ready : ContextState::None;
}

Status GroupSecurityProvider::tx_group_link_epochs(std::uint32_t& boot,
                                                     std::uint32_t& g) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "group provider re-entry");
  if (!keys_.tx_ready()) return Status::error(StatusCode::AuthRequired, "group TX unavailable");
  boot = keys_.boot();
  g = keys_.current();
  return Status::success();
}

bool GroupSecurityProvider::allowed_sender(const SecurityContext& c) const noexcept {
  if (c.scope != SecurityScope::Group) return true;
  const SiteRecord& site = keys_.store_.site();
  for (std::size_t i = 0; i < site.gateway_count; ++i) {
    if (site.gateways[i] == c.sender) return true;
  }
  return false;
}

Status GroupSecurityProvider::material(const SecurityContext& c, keys::TrafficKey& out,
                                        const bool transmit) noexcept {
  if (c.network == 0 || c.network != static_cast<std::uint32_t>(keys_.network()) ||
      c.sender == kInvalidNodeId || c.sender == kBroadcastNodeId ||
      c.receiver != kBroadcastNodeId || sender_boot(c) == 0 || gk_epoch(c) == 0 ||
      (transmit && (c.sender != self_ || !keys_.tx_ready() ||
                    gk_epoch(c) != keys_.current() || sender_boot(c) != keys_.boot()))) {
    return Status::error(StatusCode::AuthorizationFailed, "group context binding");
  }
  if (c.scope == SecurityScope::Group &&
      (!is_group_address(c.group_id) || c.group_epoch != 0 || !allowed_sender(c))) {
    return Status::error(StatusCode::AuthorizationFailed, "group end binding");
  }
  if (c.scope == SecurityScope::GroupLink && (c.sender_boot || c.group_id)) {
    return Status::error(StatusCode::AuthorizationFailed, "group link binding");
  }
  if (transmit && revoked_group_sender(c.sender)) {
    return Status::error(StatusCode::AuthorizationFailed, "group sender revoked");
  }
  ScopeDigest prk{};
  Status status = keys_.derive(gk_epoch(c), prk);
  if (status) {
    status = c.scope == SecurityScope::Group
                 ? keys::group_end_key(prk, c.epoch, c.group_id, c.sender,
                                       c.sender_boot, out)
                 : keys::group_bcast_key(prk, c.group_epoch, c.sender, c.epoch, out);
  }
  secure_clear(prk);
  return status;
}

GroupReplaySender* GroupSecurityProvider::sender(const SecurityContext& c) noexcept {
  if (c.scope == SecurityScope::Group) {
    for (auto& s : keys_.end_rx_) if (s.sender == c.sender) return &s;
  } else {
    for (auto& s : keys_.link_rx_) if (s.sender == c.sender) return &s;
  }
  return nullptr;
}

GroupReplaySender* GroupSecurityProvider::free_sender(const SecurityScope scope) noexcept {
  if (scope == SecurityScope::Group) {
    for (auto& s : keys_.end_rx_) if (s.sender == 0) return &s;
  } else {
    for (auto& s : keys_.link_rx_) if (s.sender == 0) return &s;
  }
  return nullptr;  // never evict an authenticated sender: its boot floor matters
}

bool GroupSecurityProvider::replay_ok(const GroupReplaySender& s, const std::uint32_t epoch,
                                      const std::uint32_t boot,
                                      const std::uint64_t counter) noexcept {
  if (boot < s.boot) return false;
  if (boot > s.boot) return true;
  for (std::size_t i = 0; i < keys_.replay_epochs_.size(); ++i) {
    if (keys_.replay_epochs_[i] != epoch) continue;
    const auto& bank = s.banks[i];
    if (counter > bank.max) return true;
    const std::uint64_t distance = bank.max - counter;
    return distance < 64 && (bank.bitmap & (std::uint64_t{1} << distance)) == 0;
  }
  return true;
}

void GroupSecurityProvider::replay_commit(GroupReplaySender& s, const NodeId peer,
                                          const std::uint32_t epoch, const std::uint32_t boot,
                                          const std::uint64_t counter) noexcept {
  if (boot > s.boot || s.sender == 0) {
    s.banks[0] = {};
    s.banks[1] = {};
    s.boot = boot;
  }
  s.sender = peer;
  std::size_t index = 0;
  if (keys_.replay_epochs_[0] == epoch) {
    index = 0;
  } else if (keys_.replay_epochs_[1] == epoch) {
    index = 1;
  } else {
    // Only an authenticated frame may relabel a bank. Clear every sender's
    // retired bank together; a delayed old epoch cannot evict a live one.
    index = !keys_.accepts(keys_.replay_epochs_[0]) ? 0 : 1;
    for (auto& entry : keys_.link_rx_) entry.banks[index] = {};
    for (auto& entry : keys_.end_rx_) entry.banks[index] = {};
    keys_.replay_epochs_[index] = epoch;
  }
  GroupReplayBank* bank = &s.banks[index];
  if (counter > bank->max) {
    const std::uint64_t delta = counter - bank->max;
    bank->bitmap = (delta >= 64 ? 0 : bank->bitmap << delta) | 1;
    bank->max = counter;
  } else {
    bank->bitmap |= std::uint64_t{1} << (bank->max - counter);
  }
}

Status GroupSecurityProvider::next_counter(const SecurityContext& c,
                                            std::uint64_t& counter) noexcept {
  if (!group_scope(c.scope)) return pairwise_.next_counter(c, counter);
  if (in_call_ || keys_.provider_in_call_)
    return Status::error(StatusCode::Busy, "group provider re-entry");
  in_call_ = true;
  keys_.provider_in_call_ = true;
  keys::TrafficKey material_key{};
  Status status = material(c, material_key, true);
  keys::clear(material_key);
  if (status) {
    auto& next = c.scope == SecurityScope::Group ? keys_.end_tx_ : keys_.link_tx_;
    if (next > kMaxCryptoCounter)
      status = Status::error(StatusCode::RecoveryRequired, "group counter exhausted");
    else counter = next++;  // consumed even if seal/transport later fails
  }
  keys_.provider_in_call_ = false;
  in_call_ = false;
  return status;
}

Status GroupSecurityProvider::seal(const SecurityContext& c, const std::uint64_t counter,
                                   const ByteView aad, const ByteView plaintext,
                                   const MutableByteView ciphertext,
                                   std::array<std::uint8_t, kAeadTagSize>& tag) noexcept {
  if (!group_scope(c.scope)) return pairwise_.seal(c, counter, aad, plaintext, ciphertext, tag);
  if (in_call_ || keys_.provider_in_call_)
    return Status::error(StatusCode::Busy, "group provider re-entry");
  const bool end = c.scope == SecurityScope::Group;
  if (counter >= (end ? keys_.end_tx_ : keys_.link_tx_) ||
      (end ? keys_.end_has_sealed_ && counter <= keys_.end_sealed_ :
             keys_.link_has_sealed_ && counter <= keys_.link_sealed_) ||
      counter > kMaxCryptoCounter || ciphertext.size != plaintext.size ||
      plaintext.size > staging_.size() - kAeadTagSize || !aead_.seal ||
      (aad.size != 0 && aad.data == nullptr) ||
      (plaintext.size != 0 && (plaintext.data == nullptr || ciphertext.data == nullptr))) {
    return Status::error(StatusCode::InvalidArgument, "group seal bounds");
  }
  in_call_ = true;
  keys_.provider_in_call_ = true;
  // A failed seal also burns the counter: no second plaintext can use the
  // same key/nonce even if the backend wrote partial ciphertext.
  if (end) { keys_.end_sealed_ = counter; keys_.end_has_sealed_ = true; }
  else { keys_.link_sealed_ = counter; keys_.link_has_sealed_ = true; }
  keys::TrafficKey key{};
  keys::AeadNonce nonce{};
  Status status = material(c, key, true);
  if (status) status = keys::aead_nonce(key.iv, counter, nonce);
  if (status && !aead_.seal(aead_.ctx, key.key.data(), nonce.data(), aad, plaintext,
                            staging_.data())) {
    status = Status::error(StatusCode::IntegrityError, "group seal failed");
  }
  if (status) {
    std::memcpy(ciphertext.data, staging_.data(), plaintext.size);
    std::memcpy(tag.data(), staging_.data() + plaintext.size, tag.size());
  }
  secure_clear(staging_);
  keys::clear(key);
  secure_clear(nonce);
  keys_.provider_in_call_ = false;
  in_call_ = false;
  return status;
}

Status GroupSecurityProvider::open(const SecurityContext& c, const std::uint64_t counter,
                                   const ByteView aad, const ByteView ciphertext,
                                   const std::array<std::uint8_t, kAeadTagSize>& tag,
                                   const MutableByteView plaintext) noexcept {
  if (!group_scope(c.scope)) return pairwise_.open(c, counter, aad, ciphertext, tag, plaintext);
  if (in_call_ || keys_.provider_in_call_)
    return Status::error(StatusCode::Busy, "group provider re-entry");
  if (counter > kMaxCryptoCounter || plaintext.size != ciphertext.size ||
      ciphertext.size > staging_.size() - kAeadTagSize || !aead_.open ||
      (aad.size != 0 && aad.data == nullptr) ||
      (ciphertext.size != 0 && (ciphertext.data == nullptr || plaintext.data == nullptr))) {
    if (plaintext.data != nullptr && plaintext.size <= staging_.size())
      secure_clear(plaintext.data, plaintext.size);
    return Status::error(StatusCode::ProtocolError, "group open bounds");
  }
  in_call_ = true;
  keys_.provider_in_call_ = true;
  keys::TrafficKey key{};
  keys::AeadNonce nonce{};
  Status status = material(c, key, false);
  GroupReplaySender* entry = sender(c);
  if (status && entry && !replay_ok(*entry, gk_epoch(c), sender_boot(c), counter)) {
    status = Status::error(StatusCode::Conflict, "group replay");
  }
  if (status && !entry && !(entry = free_sender(c.scope))) {
    status = Status::error(StatusCode::NoCapacity, "group sender table full");
  }
  if (status) status = keys::aead_nonce(key.iv, counter, nonce);
  if (status) {
    std::memcpy(staging_.data(), ciphertext.data, ciphertext.size);
    std::memcpy(staging_.data() + ciphertext.size, tag.data(), tag.size());
    if (!aead_.open(aead_.ctx, key.key.data(), nonce.data(), aad,
                    ByteView{staging_.data(), ciphertext.size + tag.size()}, staging_.data())) {
      status = Status::error(StatusCode::AuthorizationFailed, "group tag invalid");
    }
  }
  if (status && revoked_group_sender(c.sender)) {
    status = Status::error(StatusCode::AuthorizationFailed, "group sender revoked");
  }
  const bool next_end = status && c.scope == SecurityScope::Group &&
                        gk_epoch(c) == keys_.store_.site().gk_epoch_next;
  if (status && !next_end) {
    std::memcpy(plaintext.data, staging_.data(), ciphertext.size);
    replay_commit(*entry, c.sender, gk_epoch(c), sender_boot(c), counter);
  } else if (plaintext.data != nullptr) {
    secure_clear(plaintext.data, plaintext.size);
  }
  secure_clear(staging_);
  keys::clear(key);
  secure_clear(nonce);
  keys_.provider_in_call_ = false;
  in_call_ = false;
  // Do not deliver, replay-commit or forward a next-GK frame before the
  // Owner's next Tick durably promotes. The sender's repair can resend it.
  if (next_end) {
    GroupKeyState::Input event{};
    event.op = GroupKeyState::Op::AuthenticatedNext;
    event.epoch = gk_epoch(c);
    status = keys_.advance(event, 0);
    return status ? Status::error(StatusCode::Busy, "group promotion pending") : status;
  }
  return status;
}

}  // namespace routeloom::sdkv1
