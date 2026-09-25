#include "routeloom/sdkv1_session_rtc.hpp"

#include <atomic>
#include <cstring>

#include "routeloom/crc32.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {
constexpr std::uint32_t kMagic = 0x524C5443;  // RLTC, distinct from durable RLT1
constexpr std::uint32_t kCommitted = 0x52544331;  // RTC1
constexpr std::uint32_t kLifetime = 24U * 3600U * 1000U;
constexpr std::uint64_t kUseLimit = 1ULL << 32;
constexpr std::size_t kHeader = 70;
constexpr std::size_t kContext = 136;
static_assert(kHeader + 2 * kContext + 4 == kRtcSessionRecordSize);

struct Scratch {
  std::array<std::uint8_t, kRtcSessionRecordSize> raw{};
  RtcSessionImage image{};
  ~Scratch() noexcept {
    secure_clear(raw);
    secure_clear(&image, sizeof(image));
  }
};

struct Cursor {
  std::uint8_t* bytes;
  std::size_t pos{0};
  void put(std::uint64_t v, std::size_t n) noexcept {
    for (std::size_t i = n; i != 0; --i) bytes[pos++] = static_cast<std::uint8_t>(v >> (8 * (i - 1)));
  }
  std::uint64_t get(std::size_t n) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v = (v << 8) | bytes[pos++];
    return v;
  }
  template <std::size_t N> void put_bytes(const std::array<std::uint8_t, N>& a) noexcept {
    for (auto b : a) bytes[pos++] = b;
  }
  template <std::size_t N> void get_bytes(std::array<std::uint8_t, N>& a) noexcept {
    for (auto& b : a) b = bytes[pos++];
  }
};

bool valid(const RtcSessionImage& image) noexcept {
  if (image.source_boot == 0 || image.network == 0 || image.local_generation == 0 ||
      image.site_commit == 0 || image.gk_epoch == 0 || image.parent_binding == 0 ||
      image.parent_mac == MacAddress{} ||
      image.parent_mac == MacAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} ||
      image.count == 0 || image.count > 2) return false;
  for (std::size_t i = 0; i < image.count; ++i) {
    const auto& c = image.contexts[i];
    const auto& e = c.entry;
    if (c.scope != (i == 0 ? SecurityScope::Link : SecurityScope::EndToEnd) ||
        e.peer == kInvalidNodeId || e.peer == kBroadcastNodeId ||
        e.tx_cid == 0 || e.rx_cid == 0 || e.flags != 0 ||
        e.remaining_ms == 0 || e.remaining_ms > kLifetime ||
        e.created_gk == 0 || e.created_gk > image.gk_epoch ||
        static_cast<std::uint64_t>(image.gk_epoch) - e.created_gk >= 2 ||
        e.tx_next >= kUseLimit || e.rx_max >= kUseLimit) return false;
  }
  return true;
}

void context(Cursor& c, RtcSessionContext& image, bool writing) noexcept {
  auto& e = image.entry;
  if (writing) {
    c.put(static_cast<std::uint8_t>(image.scope), 1);
    c.put(0, 7);
    c.put(e.peer, 8); c.put(e.tx_next, 8); c.put(e.rx_max, 8); c.put(e.rx_bitmap, 8);
    c.put_bytes(e.tx_key); c.put_bytes(e.rx_key); c.put_bytes(e.tx_iv); c.put_bytes(e.rx_iv);
    c.put_bytes(e.peer_cert_id);
    c.put(e.tx_cid, 4); c.put(e.rx_cid, 4); c.put(e.peer_generation, 4); c.put(e.peer_role, 4);
    c.put(e.created_gk, 4); c.put(e.remaining_ms, 4); c.put(e.install_serial, 4);
    c.put(e.flags, 4);
  } else {
    image.scope = static_cast<SecurityScope>(c.get(1));
    c.get(7);
    e.peer = c.get(8); e.tx_next = c.get(8); e.rx_max = c.get(8); e.rx_bitmap = c.get(8);
    c.get_bytes(e.tx_key); c.get_bytes(e.rx_key); c.get_bytes(e.tx_iv); c.get_bytes(e.rx_iv);
    c.get_bytes(e.peer_cert_id);
    e.tx_cid = c.get(4); e.rx_cid = c.get(4); e.peer_generation = c.get(4); e.peer_role = c.get(4);
    e.created_gk = c.get(4); e.remaining_ms = c.get(4); e.install_serial = c.get(4);
    e.flags = c.get(4);
  }
}

Status invalid() noexcept { return Status::error(StatusCode::IntegrityError, "RTC session invalid"); }
}  // namespace

Status encode_rtc_session(const RtcSessionImage& image, MutableByteView out) noexcept {
  if (out.data == nullptr || out.size != kRtcSessionRecordSize || !valid(image)) return invalid();
  Scratch scratch;
  auto& raw = scratch.raw;
  Cursor c{raw.data()};
  c.put(kMagic, 4); c.put(1, 2); c.put(kRtcSessionRecordSize, 2); c.put(kCommitted, 4);
  c.put(image.source_boot, 4); c.put(image.network, 8);
  c.put(image.local_generation, 4); c.put(image.site_commit, 4);
  c.put(image.gk_epoch, 4); c.put(image.rs_floor, 4);
  c.put_bytes(image.kid_digest); c.put_bytes(image.parent_mac);
  c.put(image.parent_binding, 4); c.put(image.count, 1); c.put(0, 3);
  for (std::size_t i = 0; i < image.count; ++i) {
    scratch.image.contexts[i] = image.contexts[i];
    context(c, scratch.image.contexts[i], true);
  }
  c.pos = kRtcSessionRecordSize - 4;
  c.put(crc32_iso_hdlc(ByteView{raw.data(), raw.size() - 4}), 4);
  std::memcpy(out.data, raw.data(), raw.size());
  return Status::success();
}

Status decode_rtc_session(ByteView bytes, const RtcWakeCheck& wake,
                          RtcSessionImage& out) noexcept {
  secure_clear(&out, sizeof(out));
  if (bytes.data == nullptr || bytes.size != kRtcSessionRecordSize || !wake.deep_sleep ||
      !wake.sleep_marker || wake.trusted_elapsed_ms == 0) return invalid();
  Scratch scratch;
  auto& raw = scratch.raw;
  std::memcpy(raw.data(), bytes.data, raw.size());
  Cursor c{raw.data()};
  if (c.get(4) != kMagic || c.get(2) != 1 || c.get(2) != kRtcSessionRecordSize ||
      c.get(4) != kCommitted) return invalid();
  c.pos = raw.size() - 4;
  if (c.get(4) != crc32_iso_hdlc(ByteView{raw.data(), raw.size() - 4})) return invalid();
  c.pos = 12;
  auto& candidate = scratch.image;
  candidate.source_boot = c.get(4); candidate.network = c.get(8);
  candidate.local_generation = c.get(4); candidate.site_commit = c.get(4);
  candidate.gk_epoch = c.get(4); candidate.rs_floor = c.get(4);
  c.get_bytes(candidate.kid_digest); c.get_bytes(candidate.parent_mac);
  candidate.parent_binding = c.get(4); candidate.count = c.get(1);
  if (c.get(3) != 0 || candidate.count == 0 || candidate.count > 2) return invalid();
  for (auto& entry : candidate.contexts) context(c, entry, false);
  for (std::size_t i = 0; i < candidate.count; ++i) {
    for (std::size_t j = kHeader + i * kContext + 1; j < kHeader + i * kContext + 8; ++j) {
      if (raw[j] != 0) return invalid();
    }
  }
  // Unused bytes must be zero: an ambiguous second key is never silently accepted.
  if (candidate.count == 1) {
    for (std::size_t i = kHeader + kContext; i < raw.size() - 4; ++i) {
      if (raw[i] != 0) return invalid();
    }
  }
  if (!valid(candidate) || wake.next_boot == 0 ||
      static_cast<std::uint64_t>(candidate.source_boot) + 1 != wake.next_boot ||
      candidate.network != wake.network || candidate.local_generation != wake.local_generation ||
      candidate.site_commit != wake.site_commit || candidate.gk_epoch != wake.gk_epoch ||
      candidate.rs_floor != wake.rs_floor || candidate.kid_digest != wake.kid_digest) return invalid();
  for (std::size_t i = 0; i < candidate.count; ++i) {
    auto& e = candidate.contexts[i].entry;
    if (wake.trusted_elapsed_ms >= e.remaining_ms) return invalid();
    e.remaining_ms -= wake.trusted_elapsed_ms;
  }
  out = candidate;
  return Status::success();
}

Status consume_rtc_session(RtcSessionPort& port, const RtcWakeCheck& wake,
                           RtcSessionImage& out) noexcept {
  secure_clear(&out, sizeof(out));
  Scratch scratch;
  Status status = port.read(MutableByteView{scratch.raw.data(), scratch.raw.size()});
  if (!status) {
    const Status cleared = port.invalidate();
    return cleared ? status : cleared;
  }
  status = decode_rtc_session(ByteView{scratch.raw.data(), scratch.raw.size()}, wake,
                              scratch.image);
  if (!status) {
    const Status cleared = port.invalidate();
    return cleared ? status : cleared;
  }
  status = port.invalidate();
  if (!status) return status;
  status = port.read(MutableByteView{scratch.raw.data(), scratch.raw.size()});
  if (!status) return status;
  // An adapter that acknowledges the clear but leaves the marker committed
  // cannot publish the old key/window: a second wake could use it again.
  Cursor marker{scratch.raw.data(), 8};
  if (marker.get(4) == kCommitted) {
    return Status::error(StatusCode::StorageFailure, "RTC marker not cleared");
  }
  out = scratch.image;
  return Status::success();
}

bool rtc_parent_binding_ok(const RtcSessionImage& image, const MacAddress& observed_parent,
                           const std::uint32_t live_binding) noexcept {
  if (image.count == 0 || image.count > 2 || live_binding == 0 ||
      image.parent_binding != live_binding) return false;
  return image.parent_mac == observed_parent;
}

bool rtc_parent_warm_ok(const RtcSessionImage& image, const MacAddress& observed_parent,
                        const bool parent_bound) noexcept {
  if (image.count == 0 || image.count > kRtcSessionMaxContexts || !parent_bound) return false;
  return image.parent_mac == observed_parent;
}

RtcWriteAheadProvider::RtcWriteAheadProvider(SecurityProvider& inner,
                                             SessionInstaller& installer) noexcept
    : inner_(inner), installer_(installer) {}

RtcWriteAheadProvider::~RtcWriteAheadProvider() noexcept {
  // Borrowed image only: the port and the image may already be gone (both
  // must merely outlive the armed period, and disarm() is the call that
  // retires them).
  for (bool& armed : slot_armed_) armed = false;
  if (image_ != nullptr) {
    secure_clear(image_, sizeof(*image_));
    image_ = nullptr;
  }
  port_ = nullptr;
}

Status RtcWriteAheadProvider::arm(RtcSessionPort& port, RtcSessionImage& image) noexcept {
  if (armed()) return Status::error(StatusCode::InvalidState, "write-ahead already armed");
  std::array<std::uint8_t, kRtcSessionRecordSize> encoded{};
  const Status shaped =
      encode_rtc_session(image, MutableByteView{encoded.data(), encoded.size()});
  if (!shaped) {
    secure_clear(encoded);
    return Status::error(StatusCode::InvalidArgument, "write-ahead image shape");
  }
  const Status written = port.write(ByteView{encoded.data(), encoded.size()});
  if (!written) {
    secure_clear(encoded);
    return written;
  }
  std::array<std::uint8_t, kRtcSessionRecordSize> back{};
  const Status seen = port.read(MutableByteView{back.data(), back.size()});
  const bool match = seen.ok() && back == encoded;
  secure_clear(encoded);
  secure_clear(back);
  if (!match) {
    (void)port.invalidate();
    return Status::error(StatusCode::StorageFailure, "write-ahead commit unverified");
  }
  image_ = &image;
  port_ = &port;
  for (std::size_t i = 0; i < image.count; ++i) slot_armed_[i] = true;
  return Status::success();
}

void RtcWriteAheadProvider::disarm() noexcept {
  for (bool& armed : slot_armed_) armed = false;
  if (image_ != nullptr) {
    secure_clear(image_, sizeof(*image_));
    image_ = nullptr;
  }
  if (port_ != nullptr) {
    (void)port_->invalidate();
    port_ = nullptr;
  }
}

bool RtcWriteAheadProvider::armed() const noexcept {
  return slot_armed_[0] || slot_armed_[1];
}

void RtcWriteAheadProvider::disarm_slot(const std::size_t index) noexcept {
  if (index < kRtcSessionMaxContexts) slot_armed_[index] = false;
  if (!armed()) disarm();
}

SecurityProfile RtcWriteAheadProvider::security_profile() const noexcept {
  return inner_.security_profile();
}

bool RtcWriteAheadProvider::ready() const noexcept { return inner_.ready(); }

ContextState RtcWriteAheadProvider::context_state(const SecurityScope scope,
                                                  const NodeId peer) const noexcept {
  return inner_.context_state(scope, peer);
}

Status RtcWriteAheadProvider::tx_epoch(const SecurityScope scope, const NodeId peer,
                                       std::uint32_t& epoch) noexcept {
  return inner_.tx_epoch(scope, peer, epoch);
}

Status RtcWriteAheadProvider::current_rx_epoch(const SecurityScope scope, const NodeId peer,
                                               std::uint32_t& epoch) const noexcept {
  return inner_.current_rx_epoch(scope, peer, epoch);
}

Status RtcWriteAheadProvider::tx_group_link_epochs(std::uint32_t& boot, std::uint32_t& g) noexcept {
  return inner_.tx_group_link_epochs(boot, g);
}

bool RtcWriteAheadProvider::accepts_group_epoch(const std::uint32_t g) const noexcept {
  return inner_.accepts_group_epoch(g);
}

bool RtcWriteAheadProvider::revoked_group_sender(const NodeId sender) const noexcept {
  return inner_.revoked_group_sender(sender);
}

Status RtcWriteAheadProvider::next_counter(const SecurityContext& context,
                                           std::uint64_t& counter) noexcept {
  std::size_t slot = kRtcSessionMaxContexts;
  if (armed() && image_ != nullptr) {
    for (std::size_t i = 0; i < image_->count; ++i) {
      if (slot_armed_[i] && image_->contexts[i].scope == context.scope &&
          image_->contexts[i].entry.peer == context.receiver) {
        slot = i;
        break;
      }
    }
  }
  if (slot == kRtcSessionMaxContexts) return inner_.next_counter(context, counter);
  // The live context must still be the restored one: a reinstall (fresh
  // handshake under a new tx id) ends write-ahead for the slot and the
  // bank issues its own counters from here on.
  std::uint32_t live_cid = 0;
  const Status epoch_status = inner_.tx_epoch(context.scope, context.receiver, live_cid);
  if (!epoch_status || live_cid != image_->contexts[slot].entry.tx_cid) {
    disarm_slot(slot);
    return inner_.next_counter(context, counter);
  }
  // Lockstep: the bank counter first, then the retained counter, and the
  // two must agree. The RTC write completes before the counter returns,
  // so radio only ever sees counters the retained image already leads.
  std::uint64_t bank_counter = 0;
  const Status bank_status = inner_.next_counter(context, bank_counter);
  if (!bank_status) return bank_status;
  std::uint64_t retained_counter = 0;
  const Status retained_status = advance_rtc_tx(*port_, *image_, slot, retained_counter);
  if (!retained_status || retained_counter != bank_counter) {
    // Durability lost (or diverged): retire the entry and refuse. The
    // counter never reached radio, so the demand-driven re-handshake
    // starts clean — no RAM fallback may issue past this point.
    (void)installer_.retire(context.scope, context.receiver);
    disarm_slot(slot);
    if (retained_status) {
      return Status::error(StatusCode::InternalError, "write-ahead diverged");
    }
    return retained_status;
  }
  counter = retained_counter;
  return Status::success();
}

Status RtcWriteAheadProvider::seal(const SecurityContext& context, const std::uint64_t counter,
                                   const ByteView aad, const ByteView plaintext,
                                   const MutableByteView ciphertext,
                                   std::array<std::uint8_t, kAeadTagSize>& tag) noexcept {
  return inner_.seal(context, counter, aad, plaintext, ciphertext, tag);
}

Status RtcWriteAheadProvider::open(const SecurityContext& context, const std::uint64_t counter,
                                   const ByteView aad, const ByteView ciphertext,
                                   const std::array<std::uint8_t, kAeadTagSize>& tag,
                                   const MutableByteView plaintext) noexcept {
  return inner_.open(context, counter, aad, ciphertext, tag, plaintext);
}

Status advance_rtc_tx(RtcSessionPort& port, RtcSessionImage& current,
                      const std::size_t context_index, std::uint64_t& counter) noexcept {
  if (!valid(current) || context_index >= current.count ||
      current.contexts[context_index].entry.tx_next >= kUseLimit - 1) {
    return Status::error(StatusCode::CounterExhausted, "RTC TX counter exhausted");
  }
  Scratch scratch;
  Status status = encode_rtc_session(current,
                                     MutableByteView{scratch.raw.data(), scratch.raw.size()});
  if (!status) return status;
  // Refuse stale in-memory images; in particular a failed readback must not
  // allow a retry that overwrites a newer counter with an older one.
  std::array<std::uint8_t, kRtcSessionRecordSize> observed{};
  status = port.read(MutableByteView{observed.data(), observed.size()});
  if (!status) { secure_clear(observed); return status; }
  const bool matches = observed == scratch.raw;
  secure_clear(observed);
  if (!matches) return Status::error(StatusCode::Conflict, "RTC image changed");
  status = port.invalidate();
  if (!status) return status;
  status = port.read(MutableByteView{scratch.raw.data(), scratch.raw.size()});
  if (!status) return status;
  Cursor marker{scratch.raw.data(), 8};
  if (marker.get(4) == kCommitted) {
    return Status::error(StatusCode::StorageFailure, "RTC marker not cleared");
  }
  scratch.image = current;
  const std::uint64_t issued = scratch.image.contexts[context_index].entry.tx_next++;
  status = encode_rtc_session(scratch.image,
                              MutableByteView{scratch.raw.data(), scratch.raw.size()});
  if (!status) return status;
  status = port.write(ByteView{scratch.raw.data(), scratch.raw.size()});
  if (!status) return status;
  observed = {};
  status = port.read(MutableByteView{observed.data(), observed.size()});
  if (!status) { secure_clear(observed); return status; }
  const bool durable = observed == scratch.raw;
  secure_clear(observed);
  if (!durable) return Status::error(StatusCode::StorageFailure, "RTC TX readback");
  current = scratch.image;
  counter = issued;
  return Status::success();
}

Status BufferRtcSessionPort::read(const MutableByteView out) noexcept {
  if (backing_.data == nullptr || backing_.size != kRtcSessionRecordSize ||
      out.data == nullptr || out.size != kRtcSessionRecordSize) {
    return Status::error(StatusCode::InvalidArgument, "RTC buffer size");
  }
  std::memcpy(out.data, backing_.data, kRtcSessionRecordSize);
  return Status::success();
}

Status BufferRtcSessionPort::invalidate() noexcept {
  if (backing_.data == nullptr || backing_.size != kRtcSessionRecordSize) {
    return Status::error(StatusCode::InvalidArgument, "RTC buffer size");
  }
  secure_clear(backing_.data, backing_.size);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  return Status::success();
}

Status BufferRtcSessionPort::write(const ByteView image) noexcept {
  if (backing_.data == nullptr || backing_.size != kRtcSessionRecordSize ||
      image.data == nullptr || image.size != kRtcSessionRecordSize) {
    return Status::error(StatusCode::InvalidArgument, "RTC buffer size");
  }
  if (image.data == backing_.data) {
    return Status::error(StatusCode::InvalidArgument, "RTC image aliases backing");
  }
  // The commit word at bytes 8..11 is the last write. An interrupted
  // update leaves an uncommitted record, never a partly advanced key/window.
  secure_clear(backing_.data, backing_.size);
  std::memcpy(backing_.data, image.data, 8);
  std::memcpy(backing_.data + 12, image.data + 12, kRtcSessionRecordSize - 12);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  auto* commit = static_cast<volatile std::uint8_t*>(backing_.data + 8);
  for (std::size_t i = 0; i < 4; ++i) commit[i] = image.data[8 + i];
  std::atomic_thread_fence(std::memory_order_seq_cst);
  return Status::success();
}

}  // namespace routeloom::sdkv1
