// Live E2E peer (design P3-4 §10.2, P5 §10.4, P6 §11.4): the C++ end of
// the Rust Site Authority interop. A real Joiner + ZtJoinerLink +
// Identity/Site stores runs on a fake channel-switching radio and fake
// slot flash; each site runs a real JoinProxy + JoinRelayGateway whose
// host sink is the pipe to the Rust driver
// (host/routeloom-host/src/site/joiner_interop.rs) — there is
// deliberately no scripted authority on this side.
//
// Once the Joiner commits a SiteRecord, the same process also runs the
// real member security leg over the pipe: AuthorityClient +
// GroupKeyState over the committed SiteStore, and MembershipLifecycle
// over Revocation/Lifecycle/Resume stores, with the verified type 5..7
// plaintext crossing between them exactly like the firmware Owner
// (EspNowSecurityOwner): the full envelope body is stripped of its 16 B
// P5 head before the lifecycle sees it, and lifecycle reports leave via
// SendTyped. Gossip has no peer in this single-device harness, so RRS1
// arrives over the authority channel only.
//
// Framing: u16le length (1..4096) + payload over stdin/stdout; stderr is
// diagnostics only and never carries key material. First payload byte is
// the tag. Rust -> C++:
//
//   T <now u64le>                    advance virtual time, run the pump
//   W <site u8><to_proxy u64le><relay object>   host down (queued, applied
//                                        at the next round, never in a callback)
//   B <site u8><proxy u64le><relay_id u32le><gateway_epoch u32le>
//     <proxy_epoch u32le> host abort (queued likewise)
//   F <site u8><proxy u8><muted u8>   power a proxy off/on
//   C <kind u8><carrier bytes>       authority down (queued likewise;
//                                    kind 1..5, envelope <= 2048 B)
//   V <reason u8>                    request a GK pull (reason 1..3)
//   J <RRS1 object bytes>            inject a gossip-completed RRS1 object
//                                    (single-device harness: no mesh peer
//                                    exists, so the bytes cross the pipe and
//                                    the lifecycle verifies them for real)
//   P                              dump the flash image (4 slot replies)
//   X                              dump the extended image: RRS slots 0/1
//                                  (store 2, 640 B) then journal 0/1
//                                  (store 3, 1609 B)
//   Q                              quit (exit 0)
//
// C++ -> Rust, emitted after each T in this order:
//
//   U <site u8><proxy u64le><hops u8><relay object>   one relayed up
//   A <site u8><proxy u64le><relay_id u32le><gateway_epoch u32le>
//     <proxy_epoch u32le><reason u8> gateway/proxy abort
//   O <kind u8><carrier bytes>       one authority up (R1/R3/envelope)
//   S <46 B snapshot>               state/action/store/counter observation
//   M <site cert><member cert><dams sha256>  member material (digests, no keys)
//   G <45 B owner snapshot>         authority/GK/lifecycle observation
//   P <store u8><slot u8><1024 B>    flash slot image (power-cut handover)
//   X <store u8><slot u8><bytes>     extended slot image (RRS/journal)
//   D                              end of the TICK response
//   E <text>                        fatal error; the peer exits nonzero after it
//
// S payload: state u8 | action_pending u8 | pending_action u8 |
// store_site u64le | store_generation u32le | site_writes u16le |
// last_site_write_at u64le | last_site_read_at u64le | zt_sends u32le |
// terminal_at u64le (0 = none) | terminal_kind u8.
//
// M payload: sitecert_len u16le | sitecert | membercert_len u16le |
// membercert | sha256(dams) 32 B (zeros when no member row).
//
// G frame (45 B incl. tag, all le): auth_state u8 | join_confirmed u8 |
// gk_current u32 | gk_next u32 | lifecycle_phase u8 |
// lifecycle_action u8 | applied_rs u32 | applied_gk u32 |
// holdoff_remaining_ms u64 | authority_ready u8 | adopted_network u64 |
// own_generation u32 | lifecycle_booted u8 | runtime_enforce_count u8 |
// runtime_flags u8 (removed=1, trust_erased=2, retired=4, installed=8).
//
// Setup arrives on argv (all integers accept 0x hex; blobs are hex):
//
//   --node <u64> --mac <12hex> --dev-priv <64hex> --dev-pub <128hex>
//   --dev-cert <hex> --site-ca-id <u64> --site-ca-pub <128hex>
//   --fw <u32> --cap <u32> --role <u8> --t0 <ms> --seed <u64>
//   --site <id,network,gateway,proxymac,proxynode,channel,rssi,hops>
//   --flash <file>   (optional 4096 B preload: identity slots, site slots)
//   --flash-ext <file> (optional 4498 B preload: RRS slots, journal slots)
//   --verify         boot the Joiner in VerifyExistingMembership mode (a
//                    retained RLS1 re-proves over ZT instead of adopting
//                    silently — the removal-recovery / cutover-reissue leg)
//
// Test keys only; every byte on argv is test material.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/aead_gcm.hpp"
#include "routeloom/device_credential.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/sdkv1_authority.hpp"
#include "routeloom/sdkv1_group_keys.hpp"
#include "routeloom/sdkv1_lifecycle_store.hpp"
#include "routeloom/sdkv1_revocation.hpp"

#include "join_sim_network.hpp"

namespace {

using namespace join_sim;
using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kRpcMax = 4096;  // P5 §10.4: envelopes ride the same pipe
constexpr std::size_t kFlashSlots = 4;  // identity 0/1, site 0/1
constexpr std::size_t kFlashSlotBytes = 1024;  // pipe fixture layout
constexpr std::size_t kFlashBytes = kFlashSlots * kFlashSlotBytes;
constexpr std::uint64_t kBootWitness = 0x0A11CE;
constexpr std::uint64_t kTickStepMs = 5;
constexpr std::size_t kAuthorityUpsMax = 8;  // bounded pipe queue per tick
constexpr std::size_t kAuthorityQueueMax = 8;
constexpr std::size_t kPassthroughMax = 4;
constexpr std::size_t kRrsSlotBytes = 640;
constexpr std::size_t kJournalSlotBytes = 88 + 1521;
constexpr std::size_t kFlashExtBytes = 2 * kRrsSlotBytes + 2 * kJournalSlotBytes;
constexpr NodeId kGossipPeer = 0x00A1000000000301ULL;  // fixed fake mesh peer

bool from_hex(const std::string& text, Bytes& out) {
  out.clear();
  if (text.empty() || text.size() % 2 != 0) return false;
  for (std::size_t i = 0; i < text.size(); i += 2) {
    char* end = nullptr;
    const std::string pair = text.substr(i, 2);
    const unsigned long value = std::strtoul(pair.c_str(), &end, 16);
    if (end != pair.c_str() + 2) return false;
    out.push_back(static_cast<std::uint8_t>(value));
  }
  return true;
}

bool parse_u64(const std::string& text, std::uint64_t& out) {
  char* end = nullptr;
  out = std::strtoull(text.c_str(), &end, 0);
  return end != nullptr && *end == '\0';
}

void put_u16(Bytes& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value));
  out.push_back(static_cast<std::uint8_t>(value >> 8));
}

void put_u32(Bytes& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

void put_u64(Bytes& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

bool read_exact(void* data, std::size_t size) {
  return std::fread(data, 1, size, stdin) == size;
}

bool read_frame(Bytes& payload) {
  std::uint8_t head[2];
  if (!read_exact(head, sizeof(head))) return false;
  const std::size_t length = static_cast<std::size_t>(head[0] | (head[1] << 8));
  if (length == 0 || length > kRpcMax) return false;
  payload.resize(length);
  return read_exact(payload.data(), length);
}

bool write_frame(const Bytes& payload) {
  if (payload.empty() || payload.size() > kRpcMax) return false;
  const std::uint8_t head[2] = {static_cast<std::uint8_t>(payload.size()),
                                static_cast<std::uint8_t>(payload.size() >> 8)};
  return std::fwrite(head, 1, 2, stdout) == 2 &&
         std::fwrite(payload.data(), 1, payload.size(), stdout) == payload.size();
}

[[noreturn]] void fatal(const std::string& detail) {
  Bytes payload;
  payload.push_back('E');
  payload.insert(payload.end(), detail.begin(), detail.end());
  if (payload.size() > kRpcMax) payload.resize(kRpcMax);
  (void)write_frame(payload);
  (void)std::fflush(stdout);
  std::fprintf(stderr, "joiner_interop_peer: %s\n", detail.c_str());
  std::exit(1);
}

// --- Peer sites ------------------------------------------------------------------
// One proxy + gateway per site; the gateway host sink feeds the pipe
// instead of a scripted authority.

struct PeerUp {
  NodeId proxy{kInvalidNodeId};
  std::uint8_t hops{0};
  Bytes object;
};

struct PeerAbort {
  NodeId proxy{kInvalidNodeId};
  RelayToken token{};
  std::uint8_t reason{0};
};

class PipeSink final : public JoinRelayHostSink {
 public:
  Status relay_up(const NodeId proxy, const std::uint8_t hops,
                  const ByteView object) noexcept override {
    ups.push_back(PeerUp{proxy, hops, Bytes(object.data, object.data + object.size)});
    return Status::success();
  }
  Status relay_abort(const NodeId proxy, const RelayToken token,
                     const RelayAbortReason reason) noexcept override {
    aborts.push_back(PeerAbort{proxy, token, static_cast<std::uint8_t>(reason)});
    return Status::success();
  }
  std::deque<PeerUp> ups;
  std::deque<PeerAbort> aborts;
};

class PeerSite {
 public:
  PeerSite(const SimSiteParams& params, std::deque<RadioFrame>& air, std::deque<WireFrame>& mesh,
           std::uint64_t& now, RadioFaults& faults, std::uint64_t rng_seed)
      : params_(params),
        gateway_wire_(mesh, params.gateway, now),
        gateway_(gateway_config(params), gateway_wire_),
        cookie_(cookie_key_),
        proxy_entropy_(rng_seed ^ 0x9E3779B9ULL) {
    gateway_.set_host_sink(&sink_);
    gateway_.set_membership(MembershipState::Member);
    for (const auto& proxy : params.proxies) {
      proxies_.emplace_back(
          new ProxyEnds(proxy, params, air, mesh, now, faults, cookie_, proxy_entropy_));
    }
  }

  void set_proxy_muted(std::size_t index, bool muted) {
    if (index < proxies_.size()) proxies_[index]->muted = muted;
  }
  void on_radio(const RadioFrame& frame, std::uint64_t now) {
    for (auto& proxy : proxies_) {
      if (proxy->muted) continue;
      if (frame.channel != proxy->params.channel) continue;
      proxy->engine.on_rld1_rx(frame.from, frame.to, proxy->params.rssi, view(frame.bytes), now);
    }
  }
  void on_wire(const WireFrame& frame, std::uint64_t now) {
    if (frame.to == params_.gateway) {
      gateway_.on_relay_rx(frame.from, /*hops=*/1, frame.type, view(frame.payload), now);
      return;
    }
    for (auto& proxy : proxies_) {
      if (frame.to == proxy->params.node) {
        proxy->engine.on_relay_rx(frame.from, frame.type, view(frame.payload), now);
      }
    }
  }
  void poll(std::uint64_t now) {
    for (auto& proxy : proxies_) proxy->engine.poll(now);
    gateway_.poll(now);
  }
  Status apply_down(NodeId to_proxy, const Bytes& object, std::uint64_t now) {
    return gateway_.host_down(to_proxy, view(object), now);
  }
  Status apply_abort(NodeId proxy, RelayToken token, std::uint64_t now) {
    return gateway_.host_abort(proxy, token, now);
  }
  PipeSink sink_;

 private:
  struct ProxyEnds {
    ProxyEnds(const SimProxyParams& proxy, const SimSiteParams& site, std::deque<RadioFrame>& air,
              std::deque<WireFrame>& mesh, std::uint64_t& now, RadioFaults& faults,
              JoinCookieSealer& cookie, EntropySource& entropy)
        : params(proxy),
          radio(air, proxy.mac, proxy.channel, now, faults, &muted),
          wire(mesh, proxy.node, now),
          engine(proxy_config(proxy, site), radio, wire, cookie, entropy) {
      engine.set_policy(true);
      engine.set_authority(proxy.reachable, proxy.hops, 0);
      engine.set_membership(MembershipState::Member, 0);
    }
    SimProxyParams params;
    bool muted{false};
    SiteRadioPort radio;
    SimWirePort wire;
    JoinProxy engine;
  };

  static JoinRelayGatewayConfig gateway_config(const SimSiteParams& params) {
    JoinRelayGatewayConfig config{};
    config.node = params.gateway;
    config.gateway_epoch = 7;
    return config;
  }
  static JoinProxyConfig proxy_config(const SimProxyParams& proxy, const SimSiteParams& site) {
    JoinProxyConfig config{};
    config.node = proxy.node;
    config.mac = proxy.mac;
    config.network_low32 = static_cast<std::uint32_t>(site.network);
    config.org_hint = join_org_hint(site.site_ca->pub);
    config.site_hint = join_site_hint(site.site_id);
    config.gateway = site.gateway;
    config.proxy_epoch = 3;
    return config;
  }

  SimSiteParams params_;
  SimWirePort gateway_wire_;
  JoinRelayGateway gateway_;
  std::vector<std::unique_ptr<ProxyEnds>> proxies_;
  std::array<std::uint8_t, 32> cookie_key_{{0xC0, 0x01, 0x5E, 0xED}};
  HmacJoinCookie cookie_;
  SimEntropy proxy_entropy_;
};

// --- Member security leg -----------------------------------------------------------
// Real AuthorityClient + GroupKeyState + MembershipLifecycle over the pipe.
// Queues are bounded; nothing sends from inside a callback — the pump
// drains staged work between rounds, mirroring the firmware Owner.

struct AuthorityCarrier {
  std::uint8_t kind{0};  // 1..5, AuthorityCarrierKind
  Bytes bytes;
};

struct PassthroughItem {
  std::uint8_t type{0};  // 5..7
  Bytes body;            // full verified body (head + tail)
};

class PipeAuthorityPort final : public routeloom::sdkv1::AuthorityPort {
 public:
  bool try_send(NodeId gateway, routeloom::sdkv1::AuthorityCarrierKind kind, ByteView carrier,
                std::uint64_t& token) noexcept override {
    (void)gateway;
    if (carrier.data == nullptr || carrier.size == 0 ||
        carrier.size > routeloom::keys::kAuthorityEnvelopeMax || ups.size() >= kAuthorityUpsMax) {
      return false;
    }
    AuthorityCarrier up{};
    up.kind = static_cast<std::uint8_t>(kind);
    up.bytes.assign(carrier.data, carrier.data + carrier.size);
    ups.push_back(std::move(up));
    token = ++next_token_;
    return true;
  }
  std::deque<AuthorityCarrier> ups;

 private:
  std::uint64_t next_token_{0};
};

class PipeAuthorityObserver final : public routeloom::sdkv1::AuthorityObserver {
 public:
  void on_event(const routeloom::sdkv1::AuthorityEvent& event) noexcept override {
    switch (event.kind) {
      case routeloom::sdkv1::AuthorityEvent::Kind::ChannelReady:
        ++ready;
        break;
      case routeloom::sdkv1::AuthorityEvent::Kind::ChannelLost:
        ++lost;
        break;
      case routeloom::sdkv1::AuthorityEvent::Kind::JoinConfirmAck:
        ++confirmed;
        break;
      case routeloom::sdkv1::AuthorityEvent::Kind::UpdateReceived:
        ++updates;
        break;
      case routeloom::sdkv1::AuthorityEvent::Kind::ActivateReceived:
        ++activates;
        break;
      case routeloom::sdkv1::AuthorityEvent::Kind::Passthrough:
        ++passthroughs;
        if (event.envelope_type >= 5 && event.envelope_type <= 7 &&
            event.passthrough.data != nullptr && event.passthrough.size != 0 &&
            event.passthrough.size <= routeloom::keys::kAuthorityEnvelopeMax &&
            staged.size() < kPassthroughMax) {
          PassthroughItem item{};
          item.type = event.envelope_type;
          item.body.assign(event.passthrough.data,
                           event.passthrough.data + event.passthrough.size);
          staged.push_back(std::move(item));
        }
        break;
    }
  }
  std::uint64_t ready{0};
  std::uint64_t lost{0};
  std::uint64_t confirmed{0};
  std::uint64_t updates{0};
  std::uint64_t activates{0};
  std::uint64_t passthroughs{0};
  std::deque<PassthroughItem> staged;
};

class PeerRlres1Env final : public routeloom::rlres1::Environment {
 public:
  void bind(EntropySource* entropy) noexcept { entropy_ = entropy; }
  bool random(MutableByteView out) noexcept override {
    return entropy_ != nullptr && entropy_->fill(out).ok();
  }
  bool find_slot(routeloom::rlres1::Purpose purpose, const routeloom::rlres1::ResumeId& rid,
                 routeloom::rlres1::Slot& out) noexcept override {
    (void)purpose;
    (void)rid;
    (void)out;
    return false;  // initiator-only: never answers R1
  }
  bool revoked(NodeId peer, std::uint32_t generation) noexcept override {
    (void)peer;
    (void)generation;
    return false;
  }
  bool allocate_context_id(routeloom::rlres1::Purpose purpose, NodeId peer,
                           std::uint32_t& cid) noexcept override {
    (void)purpose;
    (void)peer;
    if (++next_cid_ == 0) next_cid_ = 1;
    cid = next_cid_;
    return true;
  }
  bool reserve_resume_use(routeloom::rlres1::Purpose purpose,
                          const routeloom::rlres1::ResumeId& rid) noexcept override {
    (void)purpose;
    (void)rid;
    return false;
  }

 private:
  EntropySource* entropy_{nullptr};
  std::uint32_t next_cid_{0};
};

// Lifecycle ports. The authority port stages SendTyped work for the pump
// (never drives the channel from the callback); the peer port records
// gossip attempts (no peer exists in this harness); the runtime port
// records enforcement so the G snapshot can observe it.
struct LifecycleTyped {
  std::uint8_t type{0};
  Bytes body;
};

class PeerLifecycleAuthorityPort final : public routeloom::sdkv1::LifecycleAuthorityPort {
 public:
  Status authority_send(const std::uint8_t type, const ByteView body) noexcept override {
    if (body.data == nullptr || body.size == 0 || body.size > 1024 ||
        queued.size() >= kAuthorityQueueMax) {
      return Status::error(StatusCode::WouldBlock, "lifecycle authority busy");
    }
    LifecycleTyped item{};
    item.type = type;
    item.body.assign(body.data, body.data + body.size);
    queued.push_back(std::move(item));
    ++staged;
    return Status::success();
  }
  std::deque<LifecycleTyped> queued;
  std::uint64_t staged{0};
};

class PeerLifecyclePeerPort final : public routeloom::sdkv1::LifecyclePeerPort {
 public:
  Status peer_send(const NodeId peer, const FrameType carrier,
                   const ByteView body) noexcept override {
    (void)carrier;
    if (body.data == nullptr) return Status::error(StatusCode::InvalidArgument, "peer body");
    ++attempts;
    last_peer = peer;
    return Status::success();  // single-device harness: no gossip peer
  }
  std::uint64_t attempts{0};
  NodeId last_peer{kInvalidNodeId};
};

class PeerLifecycleRuntimePort final : public routeloom::sdkv1::LifecycleRuntimePort {
 public:
  Status retire_network() noexcept override {
    network_retired = true;
    return Status::success();
  }
  Status install_site_trust(const SiteRecord& next) noexcept override {
    (void)next;
    trust_installed = true;
    return Status::success();
  }
  Status remove_member_runtime() noexcept override {
    runtime_erased = true;
    return Status::success();
  }
  Status erase_site_trust() noexcept override {
    trust_erased = true;
    return Status::success();
  }
  Status enforce_revocation(const RevocationSet& set, const std::uint32_t site_epoch,
                            const MonotonicMs now) noexcept override {
    (void)now;
    ++enforced;
    last_rs = set.rs_epoch;
    last_site_epoch = site_epoch;
    return Status::success();
  }
  std::uint64_t enforced{0};
  std::uint32_t last_rs{0};
  std::uint32_t last_site_epoch{0};
  bool network_retired{false};
  bool trust_installed{false};
  bool runtime_erased{false};
  bool trust_erased{false};
};

class PeerRrsObjectSink final : public routeloom::sdkv1::RrsObjectSink {
 public:
  void on_rrs_object(const NodeId peer, const ByteView object,
                     const MonotonicMs now_ms) noexcept override {
    (void)now_ms;
    (void)peer;
    (void)object;
    ++completed;
  }
  std::uint64_t completed{0};
};

class PeerLifecycleObserver final : public routeloom::sdkv1::LifecycleObserver {
 public:
  void on_lifecycle_event(const routeloom::sdkv1::LifecycleEvent& event,
                          const MonotonicMs now_ms) noexcept override {
    (void)event;
    (void)now_ms;
    ++events;
  }
  std::uint64_t events{0};
};

// --- Setup -----------------------------------------------------------------------

struct PeerSetup {
  JoinerConfig config{};
  IdentityRecord identity{};
  std::uint64_t t0{0};
  std::uint64_t seed{0x5EED1234ULL};
  std::vector<SimSiteParams> sites;
  Bytes flash;      // empty, or exactly kFlashBytes
  Bytes flash_ext;  // empty, or exactly kFlashExtBytes
  bool verify{false};
};

bool take_arg(int argc, char** argv, int& i, std::string& out) {
  if (i + 1 >= argc) return false;
  out = argv[++i];
  return true;
}

bool parse_site(const std::string& text, const routeloom_test::TestKeyPair& site_ca,
                SimSiteParams& out) {
  // id,network,gateway,proxymac,proxynode,channel,rssi,hops
  std::vector<std::string> fields;
  std::string field;
  for (char c : text + ",") {
    if (c == ',') {
      fields.push_back(field);
      field.clear();
    } else {
      field.push_back(c);
    }
  }
  if (fields.size() != 8) return false;
  std::uint64_t id = 0, network = 0, gateway = 0, node = 0, channel = 0;
  std::int64_t rssi = 0, hops = 0;
  Bytes mac;
  char* end = nullptr;
  if (!parse_u64(fields[0], id) || !parse_u64(fields[1], network) || !parse_u64(fields[2], gateway) ||
      !from_hex(fields[3], mac) || mac.size() != 6 || !parse_u64(fields[4], node) ||
      !parse_u64(fields[5], channel) || channel < 1 || channel > 14) {
    return false;
  }
  rssi = std::strtoll(fields[6].c_str(), &end, 0);
  if (end == nullptr || *end != '\0' || rssi > 0 || rssi < -120) return false;
  hops = std::strtoll(fields[7].c_str(), &end, 0);
  if (end == nullptr || *end != '\0' || hops < 0 || hops > 8) return false;
  SimSiteParams params{};
  params.site_id = id;
  params.network = static_cast<NetworkId>(network);
  params.site_ca = &site_ca;
  params.gateway = gateway;
  SimProxyParams proxy{};
  std::memcpy(proxy.mac.data(), mac.data(), 6);
  proxy.node = node;
  proxy.channel = static_cast<std::uint8_t>(channel);
  proxy.rssi = static_cast<std::int16_t>(rssi);
  proxy.hops = static_cast<std::uint8_t>(hops);
  params.proxies.push_back(proxy);
  out = params;
  return true;
}

void usage() {
  std::fprintf(stderr,
               "usage: joiner_interop_peer --node <u64> --mac <12hex> --dev-priv <64hex> "
               "--dev-pub <128hex> --dev-cert <hex> --site-ca-id <u64> --site-ca-pub <128hex> "
               "--fw <u32> --cap <u32> --role <u8> --t0 <ms> --seed <u64> "
               "--site <id,network,gateway,proxymac,proxynode,channel,rssi,hops>... "
               "[--flash <file>] [--flash-ext <file>] [--verify]\n");
}

// The site CA keypair outlives the setup (SimSiteParams only borrows it).
routeloom_test::TestKeyPair g_site_ca{};

bool parse_setup(int argc, char** argv, PeerSetup& setup) {
  Bytes dev_priv, dev_pub, dev_cert, site_ca_pub, mac;
  std::uint64_t node = 0, site_ca_id = 0, fw = 0, cap = 0, role = 0;
  bool have_node = false, have_mac = false, have_priv = false, have_pub = false,
       have_cert = false, have_ca_id = false, have_ca_pub = false, have_t0 = false;
  std::string flash_path;
  std::string flash_ext_path;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i], value;
    if (arg == "--node" && take_arg(argc, argv, i, value)) {
      have_node = parse_u64(value, node);
    } else if (arg == "--mac" && take_arg(argc, argv, i, value)) {
      have_mac = from_hex(value, mac) && mac.size() == 6;
    } else if (arg == "--dev-priv" && take_arg(argc, argv, i, value)) {
      have_priv = from_hex(value, dev_priv) && dev_priv.size() == 32;
    } else if (arg == "--dev-pub" && take_arg(argc, argv, i, value)) {
      have_pub = from_hex(value, dev_pub) && dev_pub.size() == 64;
    } else if (arg == "--dev-cert" && take_arg(argc, argv, i, value)) {
      have_cert = from_hex(value, dev_cert) && !dev_cert.empty() &&
                  dev_cert.size() <= kRlcw1CertMax;
    } else if (arg == "--site-ca-id" && take_arg(argc, argv, i, value)) {
      have_ca_id = parse_u64(value, site_ca_id);
    } else if (arg == "--site-ca-pub" && take_arg(argc, argv, i, value)) {
      have_ca_pub = from_hex(value, site_ca_pub) && site_ca_pub.size() == 64;
    } else if (arg == "--fw" && take_arg(argc, argv, i, value)) {
      if (!parse_u64(value, fw)) return false;
    } else if (arg == "--cap" && take_arg(argc, argv, i, value)) {
      if (!parse_u64(value, cap)) return false;
    } else if (arg == "--role" && take_arg(argc, argv, i, value)) {
      if (!parse_u64(value, role)) return false;
    } else if (arg == "--t0" && take_arg(argc, argv, i, value)) {
      have_t0 = parse_u64(value, setup.t0);
    } else if (arg == "--seed" && take_arg(argc, argv, i, value)) {
      if (!parse_u64(value, setup.seed)) return false;
    } else if (arg == "--site" && take_arg(argc, argv, i, value)) {
      SimSiteParams params{};
      if (setup.sites.size() >= 2 || !parse_site(value, g_site_ca, params)) return false;
      setup.sites.push_back(params);
    } else if (arg == "--flash" && take_arg(argc, argv, i, value)) {
      flash_path = value;
    } else if (arg == "--flash-ext" && take_arg(argc, argv, i, value)) {
      flash_ext_path = value;
    } else if (arg == "--verify") {
      setup.verify = true;
    } else {
      return false;
    }
  }
  if (!have_node || !have_mac || !have_priv || !have_pub || !have_cert || !have_ca_id ||
      !have_ca_pub || !have_t0 || setup.sites.empty()) {
    return false;
  }
  // Site CA before the sites borrow it (argv order requires a second pass).
  std::memcpy(g_site_ca.pub.data(), site_ca_pub.data(), 64);
  g_site_ca.priv.fill(0);
  for (auto& site : setup.sites) site.site_ca = &g_site_ca;
  JoinerConfig config{};
  config.node = node;
  std::memcpy(config.mac.data(), mac.data(), 6);
  config.fw_version = static_cast<std::uint32_t>(fw);
  config.capability = static_cast<std::uint32_t>(cap);
  config.requested_role = static_cast<std::uint8_t>(role);
  setup.config = config;
  IdentityRecord identity{};
  identity.node_id = node;
  identity.key_location = CredentialKeyLocation::NvsPlaintext;
  std::memcpy(identity.pubkey.data(), dev_pub.data(), 64);
  std::memcpy(identity.key_material.data(), dev_priv.data(), 32);
  if (!credential_kid(ByteView{identity.pubkey.data(), identity.pubkey.size()}, identity.kid)
           .ok()) {
    return false;
  }
  identity.anchors[0] =
      IdentityAnchor{site_ca_id, AnchorKind::SiteCa, AnchorStatus::Active, P256PublicKey{}};
  std::memcpy(identity.anchors[0].pubkey.data(), site_ca_pub.data(), 64);
  identity.anchor_count = 1;
  identity.devcert.size = dev_cert.size();
  std::memcpy(identity.devcert.bytes.data(), dev_cert.data(), dev_cert.size());
  setup.identity = identity;
  if (!flash_path.empty()) {
    std::FILE* file = std::fopen(flash_path.c_str(), "rb");
    if (file == nullptr) return false;
    setup.flash.resize(kFlashBytes);
    const bool ok = std::fread(setup.flash.data(), 1, kFlashBytes, file) == kFlashBytes;
    std::fclose(file);
    if (!ok) return false;
  }
  if (!flash_ext_path.empty()) {
    std::FILE* file = std::fopen(flash_ext_path.c_str(), "rb");
    if (file == nullptr) return false;
    setup.flash_ext.resize(kFlashExtBytes);
    const bool ok =
        std::fread(setup.flash_ext.data(), 1, kFlashExtBytes, file) == kFlashExtBytes;
    std::fclose(file);
    if (!ok) return false;
  }
  return true;
}

// --- The owner leg -----------------------------------------------------------------
// Starts once the Joiner commits a SiteRecord and then runs every round:
// the GroupKeyState tick, the AuthorityClient tick, the lifecycle poll,
// and the staged handoffs between them (observer passthroughs into the
// lifecycle with the 16 B P5 head stripped, lifecycle reports out via
// SendTyped) plus the lifecycle action drain. A changed SiteRecord
// (cutover adoption) restarts the channel and the group binding; a
// cleared one (removal) suspends them while the lifecycle runs the
// erasure and the holdoff. Recovery/rejoin legs are driven by the Rust
// side respawning this peer (power-cut handover), never by restarting
// the Joiner in place.

class OwnerLeg {
 public:
  OwnerLeg(DeviceEnds& device, NodeId self, NodeId gateway_fallback, std::uint64_t seed)
      : device_(device),
        self_(self),
        gateway_fallback_(gateway_fallback),
        auth_entropy_(seed ^ 0xA07E1E9ULL),
        group_(device.site_store),
        client_(aead_or_die(), port_, observer_, env_, &group_),
        rrs_storage_(routeloom::sdkv1::kRevocationSlotBytes),
        journal_storage_(routeloom::sdkv1::kLifecycleSlotBytes),
        resume_storage_(16),
        revocations_(rrs_storage_),
        resume_(resume_storage_),
        journal_(journal_storage_),
        ports_{lauth_, lpeer_, lruntime_, auth_entropy_, lobject_, &lobs_},
        config_(make_config(self)),
        lifecycle_(config_, device.identity_store, device.site_store, revocations_, resume_,
                   ports_, default_es256_verifier(), &journal_) {
    env_.bind(&auth_entropy_);
  }

  void queue_down(std::uint8_t kind, Bytes bytes) {
    if (kind < 1 || kind > 5 || bytes.empty() ||
        bytes.size() > routeloom::keys::kAuthorityEnvelopeMax ||
        downs_.size() >= kAuthorityQueueMax) {
      fatal("bad authority down");
    }
    AuthorityCarrier down{};
    down.kind = kind;
    down.bytes = std::move(bytes);
    downs_.push_back(std::move(down));
  }

  void request_pull(std::uint8_t reason) {
    if (reason < 1 || reason > 3) fatal("bad pull reason");
    pulls_.push_back(reason);
  }

  void inject_gossip(Bytes object) {
    if (object.empty() || object.size() > 640 || gossip_.size() >= 4) {
      fatal("bad gossip object");
    }
    gossip_.push_back(std::move(object));
  }

  void preload_extended(const Bytes& image) {
    if (image.size() != kFlashExtBytes) fatal("bad extended flash image");
    if (rrs_storage_.slot(0).size() != kRrsSlotBytes ||
        journal_storage_.slot(0).size() != kJournalSlotBytes) {
      fatal("extended slot size mismatch");
    }
    std::memcpy(rrs_storage_.slot(0).data(), image.data(), kRrsSlotBytes);
    std::memcpy(rrs_storage_.slot(1).data(), image.data() + kRrsSlotBytes, kRrsSlotBytes);
    std::memcpy(journal_storage_.slot(0).data(), image.data() + 2 * kRrsSlotBytes,
                kJournalSlotBytes);
    std::memcpy(journal_storage_.slot(1).data(), image.data() + 2 * kRrsSlotBytes + kJournalSlotBytes,
                kJournalSlotBytes);
  }

  void emit_extended() {
    const std::uint8_t stores[4] = {2, 2, 3, 3};
    for (int i = 0; i < 4; ++i) {
      const std::vector<std::uint8_t>& slot =
          (i < 2) ? rrs_storage_.slot(static_cast<std::uint8_t>(i))
                  : journal_storage_.slot(static_cast<std::uint8_t>(i - 2));
      Bytes payload;
      payload.push_back('X');
      payload.push_back(stores[i]);
      payload.push_back(static_cast<std::uint8_t>(i % 2));
      payload.insert(payload.end(), slot.begin(), slot.end());
      if (!write_frame(payload)) fatal("X exceeds the RPC bound");
    }
  }

  void round(std::uint64_t now) {
    // The lifecycle runs with or without a site once booted: removal,
    // the holdoff and recovery all happen on a cleared store. But the
    // boot itself needs a site or a journal record — booting pointlessly
    // on empty stores parks the lifecycle in StorageBlocked, and only
    // the channel and the group binding need the committed SiteRecord.
    if (!lifecycle_ready_) {
      if (!revocations_.initialize()) fatal("lifecycle RRS store init failed");
      if (!journal_.initialize()) fatal("lifecycle journal init failed");
      const bool has_site = device_.site_store.has_site();
      if (has_site || journal_.has_record()) {
        if (!lifecycle_.dispatch(routeloom::sdkv1::LifecycleInput::Boot(true), now))
          fatal("lifecycle boot failed");
        lifecycle_ready_ = true;
        lifecycle_booted_ = true;
      }
    }
    maybe_start(now);
    if (started_) track_site(now);
    // Queued host carriers first: the client is idle here, never inside
    // a port callback, so RxCarrier cannot report Busy.
    while (!downs_.empty()) {
      const AuthorityCarrier down = downs_.front();
      downs_.pop_front();
      if (!channel_live_) continue;  // suspended across removal; drop
      routeloom::sdkv1::AuthorityInput in{};
      in.kind = routeloom::sdkv1::AuthorityInputKind::RxCarrier;
      in.rx.kind = static_cast<routeloom::sdkv1::AuthorityCarrierKind>(down.kind);
      in.rx.bytes = ByteView{down.bytes.data(), down.bytes.size()};
      const Status status = client_.advance(in, now);
      if (!status.ok()) fatal("authority RxCarrier failed");
    }
    if (channel_live_) {
      while (!pulls_.empty()) {
        const std::uint8_t reason = pulls_.front();
        routeloom::sdkv1::AuthorityInput pull{};
        pull.kind = routeloom::sdkv1::AuthorityInputKind::RequestPull;
        pull.pull.reason = static_cast<routeloom::sdkv1::PullReason>(reason);
        const Status status = client_.advance(pull, now);
        if (status.code == StatusCode::Busy) break;  // retry next round
        if (!status.ok()) fatal("authority pull failed");
        pulls_.pop_front();
      }
      routeloom::sdkv1::GroupKeyState::Input tick{};
      tick.op = routeloom::sdkv1::GroupKeyState::Op::Tick;
      (void)group_.advance(tick, now);
      routeloom::sdkv1::AuthorityInput poll{};
      poll.kind = routeloom::sdkv1::AuthorityInputKind::Tick;
      const Status status = client_.advance(poll, now);
      if (!status.ok()) fatal("authority Tick failed");
    }
    (void)lifecycle_.dispatch(routeloom::sdkv1::LifecycleInput::Poll(), now);
    // Injected gossip objects dispatch as completed reassemblies from a
    // fixed mesh peer; the lifecycle verifies them like any gossip.
    while (!gossip_.empty() && lifecycle_ready_) {
      const Bytes object = gossip_.front();
      gossip_.pop_front();
      (void)lifecycle_.dispatch(
          routeloom::sdkv1::LifecycleInput::Completed(
              kGossipPeer, ByteView{object.data(), object.size()}),
          now);
    }
    drain_passthroughs(now);
    drain_lifecycle_reports(now);
    drain_actions(now);
  }

  void emit_ups() {
    while (!port_.ups.empty()) {
      const AuthorityCarrier up = port_.ups.front();
      port_.ups.pop_front();
      Bytes payload;
      payload.push_back('O');
      payload.push_back(up.kind);
      payload.insert(payload.end(), up.bytes.begin(), up.bytes.end());
      if (!write_frame(payload)) fatal("O exceeds the RPC bound");
    }
  }

  void emit_snapshot() {
    const routeloom::sdkv1::AuthoritySnapshot auth = client_.snapshot();
    const routeloom::sdkv1::LifecycleSnapshot life = lifecycle_.snapshot();
    Bytes payload;
    payload.push_back('G');
    payload.push_back(static_cast<std::uint8_t>(auth.state));
    payload.push_back(auth.join_confirmed ? 1 : 0);
    put_u32(payload, group_.current());
    std::uint32_t next = 0;
    if (device_.site_store.has_site()) next = device_.site_store.site().gk_epoch_next;
    put_u32(payload, next);
    payload.push_back(static_cast<std::uint8_t>(life.phase));
    payload.push_back(last_action_);
    put_u32(payload, life.applied_rs_epoch);
    put_u32(payload, life.applied_gk_epoch);
    put_u64(payload, life.holdoff_remaining_ms);
    payload.push_back(auth.state == routeloom::sdkv1::AuthoritySnapshot::State::Ready ? 1 : 0);
    put_u64(payload, life.adopted_network);
    put_u32(payload, life.own_generation);
    payload.push_back(lifecycle_booted_ ? 1 : 0);
    payload.push_back(static_cast<std::uint8_t>(lruntime_.enforced > 255 ? 255 : lruntime_.enforced));
    payload.push_back(static_cast<std::uint8_t>((lruntime_.runtime_erased ? 1 : 0) |
                                                (lruntime_.trust_erased ? 2 : 0) |
                                                (lruntime_.network_retired ? 4 : 0) |
                                                (lruntime_.trust_installed ? 8 : 0)));
    if (!write_frame(payload)) fatal("G write failed");
  }

  bool channel_ready() const {
    return channel_live_ &&
           client_.snapshot().state == routeloom::sdkv1::AuthoritySnapshot::State::Ready;
  }

 private:
  static const routeloom::AeadGcm& aead_or_die() {
    const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
    if (aead == nullptr) fatal("no host AEAD backend");
    return *aead;
  }

  static routeloom::sdkv1::LifecycleConfig make_config(NodeId self) {
    routeloom::sdkv1::LifecycleConfig config{};
    config.self = self;
    config.profile = routeloom::sdkv1::LifecycleProfile::Node;
    config.enabled_features = 0;  // authority-only harness: gossip stays silent
    return config;
  }

  void maybe_start(std::uint64_t now) {
    const bool has_site =
        device_.site_store.has_site() && device_.site_store.site().state == SiteState::Member;
    if (!has_site) {
      had_site_ = false;
      return;
    }
    const SiteRecord& site = device_.site_store.site();
    bool dams_zero = true;
    for (const auto b : site.dams) dams_zero = dams_zero && (b == 0);
    if (dams_zero) return;
    // A fresh site under a running lifecycle (first join, or a rejoin
    // after the removal holdoff) adopts it; a cutover adoption keeps
    // the lifecycle's own switch instead.
    if (!had_site_) {
      if (!lifecycle_.dispatch(routeloom::sdkv1::LifecycleInput::MemberReady(
              device_.site_store.commit_seq(), site.rs_epoch_floor),
                                   now))
        fatal("lifecycle member-ready failed");
      had_site_ = true;
    }
    if (started_) return;
    routeloom::sdkv1::GroupKeyState::Input begin{};
    begin.op = routeloom::sdkv1::GroupKeyState::Op::Start;
    begin.boot = static_cast<std::uint32_t>(kBootWitness);
    if (!group_.advance(begin, now)) fatal("group start failed");
    routeloom::sdkv1::AuthorityStart start{};
    if (!build_start(site, start)) fatal("authority start build failed");
    routeloom::sdkv1::AuthorityInput input{};
    input.kind = routeloom::sdkv1::AuthorityInputKind::Start;
    input.start = start;
    if (!client_.advance(input, now)) fatal("authority start failed");
    bound_ = site;
    bound_valid_ = true;
    started_ = true;
    channel_live_ = true;
  }

  // Cutover adoption changes the SiteRecord under us; removal clears it.
  // The lifecycle drives both — here only the channel and the group
  // binding follow, exactly once per change.
  void track_site(std::uint64_t now) {
    if (!device_.site_store.has_site()) {
      if (channel_live_) {
        routeloom::sdkv1::AuthorityInput suspend{};
        suspend.kind = routeloom::sdkv1::AuthorityInputKind::Suspend;
        (void)client_.advance(suspend, now);
        routeloom::sdkv1::GroupKeyState::Input stop{};
        stop.op = routeloom::sdkv1::GroupKeyState::Op::Stop;
        (void)group_.advance(stop, now);
        channel_live_ = false;
      }
      return;
    }
    const SiteRecord& site = device_.site_store.site();
    if (!bound_valid_ || site_changed(site)) {
      routeloom::sdkv1::GroupKeyState::Input stop{};
      stop.op = routeloom::sdkv1::GroupKeyState::Op::Stop;
      (void)group_.advance(stop, now);
      routeloom::sdkv1::GroupKeyState::Input begin{};
      begin.op = routeloom::sdkv1::GroupKeyState::Op::Start;
      begin.boot = static_cast<std::uint32_t>(kBootWitness);
      if (!group_.advance(begin, now)) fatal("group restart failed");
      routeloom::sdkv1::AuthorityInput suspend{};
      suspend.kind = routeloom::sdkv1::AuthorityInputKind::Suspend;
      (void)client_.advance(suspend, now);
      routeloom::sdkv1::AuthorityStart start{};
      if (!build_start(site, start)) fatal("authority restart build failed");
      routeloom::sdkv1::AuthorityInput input{};
      input.kind = routeloom::sdkv1::AuthorityInputKind::Start;
      input.start = start;
      if (!client_.advance(input, now)) fatal("authority restart failed");
      bound_ = site;
      bound_valid_ = true;
      channel_live_ = true;
    }
  }

  bool site_changed(const SiteRecord& site) const {
    if (site.site_id != bound_.site_id || site.network != bound_.network ||
        site.assignment_generation != bound_.assignment_generation || site.role != bound_.role) {
      return true;
    }
    return site.dams != bound_.dams;
  }

  bool build_start(const SiteRecord& site, routeloom::sdkv1::AuthorityStart& out) const {
    out.network = site.network;
    out.self = self_;
    out.site_id = site.site_id;
    out.gateway = site.gateway_count != 0 ? site.gateways[0] : gateway_fallback_;
    out.dams = site.dams;
    out.generation = site.assignment_generation;
    out.epochs.site_epoch = static_cast<std::uint32_t>(site.network >> 32U);
    out.epochs.rs_epoch = site.rs_epoch_floor;
    out.epochs.gk_epoch = site.gk_epoch_current;
    ScopeDigest digest{};
    sha256(ByteView{site.member_cert.bytes.data(), site.member_cert.size}, digest);
    std::memcpy(out.member_cert_hash.data(), digest.data(), digest.size());
    out.boot = static_cast<std::uint32_t>(kBootWitness);
    out.gk_current = site.gk_epoch_current;
    out.gk_next = site.gk_epoch_next;
    return true;
  }

  void drain_passthroughs(std::uint64_t now) {
    if (!device_.site_store.has_site()) {
      observer_.staged.clear();
      return;
    }
    const SiteRecord& site = device_.site_store.site();
    while (!observer_.staged.empty()) {
      const PassthroughItem item = observer_.staged.front();
      observer_.staged.pop_front();
      if (item.body.size() <= routeloom::sdkv1::kAuthorityBodyHeadSize) continue;
      routeloom::sdkv1::AuthorityBodyHead head{};
      if (!routeloom::sdkv1::authority_head_decode(
              ByteView{item.body.data(), routeloom::sdkv1::kAuthorityBodyHeadSize}, head))
        continue;
      if (head.op != 1 || head.generation != site.assignment_generation ||
          site.network == 0) {
        continue;  // the client already fenced this; never feed the lifecycle
      }
      routeloom::sdkv1::PeerCredentialStamp stamp{};
      stamp.network = site.network;
      stamp.peer = site.gateway_count != 0 ? site.gateways[0] : gateway_fallback_;
      stamp.assignment_generation = head.generation;
      stamp.role = site.role;
      (void)lifecycle_.dispatch(
          routeloom::sdkv1::LifecycleInput::Authority(
              stamp, item.type,
              ByteView{item.body.data() + routeloom::sdkv1::kAuthorityBodyHeadSize,
                       item.body.size() - routeloom::sdkv1::kAuthorityBodyHeadSize}),
          now);
    }
  }

  void drain_lifecycle_reports(std::uint64_t now) {
    while (!lauth_.queued.empty()) {
      if (!channel_live_) return;  // keep queued across the suspension
      const LifecycleTyped item = lauth_.queued.front();
      routeloom::sdkv1::AuthorityInput in{};
      in.kind = routeloom::sdkv1::AuthorityInputKind::SendTyped;
      in.typed.type = item.type;
      in.typed.body = ByteView{item.body.data(), item.body.size()};
      const Status status = client_.advance(in, now);
      if (status.code == StatusCode::Busy || status.code == StatusCode::InvalidState) {
        return;  // TX staged or handshaking: retry next round
      }
      if (!status.ok()) fatal("authority SendTyped failed");
      lauth_.queued.pop_front();
    }
  }

  void drain_actions(std::uint64_t now) {
    for (;;) {
      routeloom::sdkv1::LifecycleAction action{};
      const Status taken = lifecycle_.take_action(action);
      if (taken.code == StatusCode::NotFound) return;
      if (!taken.ok()) fatal("lifecycle take_action failed");
      last_action_ = static_cast<std::uint8_t>(action.tag);
      // The harness owns no radio/discovery to reinit: completing with
      // success records the order. Process-spawning legs (recovery and
      // rejoin) are driven by the Rust side respawning this peer.
      (void)lifecycle_.dispatch(
          routeloom::sdkv1::LifecycleInput::ActionDone(action.token, Status::success()), now);
    }
  }

  DeviceEnds& device_;
  NodeId self_{kInvalidNodeId};
  NodeId gateway_fallback_{kInvalidNodeId};
  SimEntropy auth_entropy_;
  PeerRlres1Env env_;
  PipeAuthorityPort port_;
  PipeAuthorityObserver observer_;
  routeloom::sdkv1::GroupKeyState group_;
  routeloom::sdkv1::AuthorityClient client_;
  sdkv1_test::FaultyRecordStorage rrs_storage_;
  sdkv1_test::FaultyRecordStorage journal_storage_;
  sdkv1_test::FaultyResumeStorage resume_storage_;
  RevocationStore revocations_;
  ResumeCache resume_;
  routeloom::sdkv1::LifecycleStore journal_;
  PeerLifecycleAuthorityPort lauth_;
  PeerLifecyclePeerPort lpeer_;
  PeerLifecycleRuntimePort lruntime_;
  PeerRrsObjectSink lobject_;
  PeerLifecycleObserver lobs_;
  routeloom::sdkv1::LifecyclePorts ports_;
  routeloom::sdkv1::LifecycleConfig config_;
  routeloom::sdkv1::MembershipLifecycle lifecycle_;
  std::deque<AuthorityCarrier> downs_;
  std::deque<std::uint8_t> pulls_;
  std::deque<Bytes> gossip_;
  SiteRecord bound_{};
  bool bound_valid_{false};
  bool started_{false};
  bool channel_live_{false};
  bool lifecycle_ready_{false};
  bool lifecycle_booted_{false};
  bool had_site_{false};
  std::uint8_t last_action_{0};
};

// --- The pump --------------------------------------------------------------------
// Mirrors JoinSimNetwork::round, but gateway ups drain to the pipe and host
// downs/aborts arrive queued between rounds — never inside a callback.

struct QueuedDown {
  std::uint8_t site{0};
  NodeId to_proxy{kInvalidNodeId};
  Bytes object;
};

struct QueuedAbort {
  std::uint8_t site{0};
  NodeId proxy{kInvalidNodeId};
  RelayToken token{};
};

class PeerWorld {
 public:
  explicit PeerWorld(const PeerSetup& setup)
      : device_(new DeviceEnds(setup.config, setup.identity, setup.seed, faults_,
                               setup.flash.empty())),
        seed_(setup.seed),
        now_(setup.t0) {
    if (!setup.flash.empty()) {
      auto& dev = *device_;
      std::memcpy(dev.identity_storage.inner_.slot(0).data(), setup.flash.data(),
                  kIdentitySlotBytes);
      std::memcpy(dev.identity_storage.inner_.slot(1).data(),
                  setup.flash.data() + kFlashSlotBytes, kIdentitySlotBytes);
      std::memcpy(dev.site_storage.inner_.slot(0).data(), setup.flash.data() + 2 * kFlashSlotBytes,
                  kSiteSlotBytes);
      std::memcpy(dev.site_storage.inner_.slot(1).data(), setup.flash.data() + 3 * kFlashSlotBytes,
                  kSiteSlotBytes);
    }
    for (const auto& site : setup.sites) add_site(site);
    JoinBootInput boot{};
    boot.boot_witness = static_cast<std::uint32_t>(kBootWitness);
    boot.prepared = true;
    if (setup.verify) boot.mode = JoinBootMode::VerifyExistingMembership;
    const Status started = device_->joiner.start(boot, now_);
    if (!started.ok()) fatal("joiner start failed");
    owner_.reset(new OwnerLeg(*device_, setup.config.node, setup.sites[0].gateway, setup.seed));
    if (!setup.flash_ext.empty()) owner_->preload_extended(setup.flash_ext);
  }

  void add_site(const SimSiteParams& params) {
    sites_.emplace_back(new PeerSite(params, air_, mesh_, now_, faults_,
                                     seed_ ^ (0x1000U * (sites_.size() + 1))));
    for (const auto& proxy : params.proxies) {
      rssi_map_.push_back({proxy.mac, proxy.rssi});
    }
  }

  void queue_down(std::uint8_t site, NodeId to_proxy, Bytes object) {
    downs_.push_back(QueuedDown{site, to_proxy, std::move(object)});
  }
  void queue_abort(std::uint8_t site, NodeId proxy, RelayToken token) {
    aborts_.push_back(QueuedAbort{site, proxy, token});
  }
  void queue_authority_down(std::uint8_t kind, Bytes carrier) {
    owner_->queue_down(kind, std::move(carrier));
  }
  void request_pull(std::uint8_t reason) { owner_->request_pull(reason); }
  void inject_gossip(Bytes object) { owner_->inject_gossip(std::move(object)); }
  void emit_extended() { owner_->emit_extended(); }
  void set_proxy_muted(std::uint8_t site, std::uint8_t proxy, bool muted) {
    if (site < sites_.size()) sites_[site]->set_proxy_muted(proxy, muted);
  }

  // Advances to `target` in 5 ms rounds. Fatal (E + exit) on any pump
  // error: the interop run must fail loudly, never limp along.
  void tick(std::uint64_t target) {
    if (target < now_) fatal("time went backwards");
    std::uint64_t rounds = 0;
    while (now_ < target) {
      round();
      now_ += kTickStepMs;
      if (++rounds > 20000) fatal("tick overran the round budget");
    }
    round();
  }

  void emit_ups_and_aborts() {
    for (std::size_t i = 0; i < sites_.size(); ++i) {
      auto& sink = sites_[i]->sink_;
      while (!sink.ups.empty()) {
        const PeerUp up = sink.ups.front();
        sink.ups.pop_front();
        Bytes payload;
        payload.push_back('U');
        payload.push_back(static_cast<std::uint8_t>(i));
        put_u64(payload, up.proxy);
        payload.push_back(up.hops);
        payload.insert(payload.end(), up.object.begin(), up.object.end());
        if (!write_frame(payload)) fatal("U exceeds the RPC bound");
      }
      while (!sink.aborts.empty()) {
        const PeerAbort abort = sink.aborts.front();
        sink.aborts.pop_front();
        Bytes payload;
        payload.push_back('A');
        payload.push_back(static_cast<std::uint8_t>(i));
        put_u64(payload, abort.proxy);
        put_u32(payload, abort.token.relay_id);
        put_u32(payload, abort.token.gateway_epoch);
        put_u32(payload, abort.token.proxy_epoch);
        payload.push_back(abort.reason);
        if (!write_frame(payload)) fatal("A write failed");
      }
    }
    owner_->emit_ups();
  }

  void emit_owner() { owner_->emit_snapshot(); }

  void emit_snapshot() {
    DeviceEnds& dev = *device_;
    const JoinSnapshot snap = dev.joiner.snapshot();
    const SiteRecord& site = dev.site_store.site();
    Bytes payload;
    payload.push_back('S');
    payload.push_back(static_cast<std::uint8_t>(snap.state));
    payload.push_back(snap.action_pending ? 1 : 0);
    payload.push_back(static_cast<std::uint8_t>(snap.pending_action));
    put_u64(payload, site.site_id);
    put_u32(payload, site.assignment_generation);
    put_u16(payload, static_cast<std::uint16_t>(dev.site_storage.successful_writes()));
    put_u64(payload, last_op_at(dev.site_storage, 'w'));
    put_u64(payload, last_op_at(dev.site_storage, 'r'));
    put_u32(payload, dev.radio.sends);
    put_u64(payload, terminal_at_);
    payload.push_back(terminal_kind_);
    if (!write_frame(payload)) fatal("S write failed");
  }

  void emit_member() {
    const SiteRecord& site = device_->site_store.site();
    Bytes payload;
    payload.push_back('M');
    put_u16(payload, static_cast<std::uint16_t>(site.site_cert.size));
    payload.insert(payload.end(), site.site_cert.bytes.begin(),
                   site.site_cert.bytes.begin() + site.site_cert.size);
    put_u16(payload, static_cast<std::uint16_t>(site.member_cert.size));
    payload.insert(payload.end(), site.member_cert.bytes.begin(),
                   site.member_cert.bytes.begin() + site.member_cert.size);
    ScopeDigest digest{};
    sha256(ByteView{site.dams.data(), site.dams.size()}, digest);
    payload.insert(payload.end(), digest.begin(), digest.end());
    if (!write_frame(payload)) fatal("M exceeds the RPC bound");
  }

  void emit_flash() {
    DeviceEnds& dev = *device_;
    const std::vector<std::uint8_t>* slots[4] = {
        &dev.identity_storage.inner_.slot(0), &dev.identity_storage.inner_.slot(1),
        &dev.site_storage.inner_.slot(0), &dev.site_storage.inner_.slot(1)};
    for (int i = 0; i < 4; ++i) {
      Bytes payload;
      payload.push_back('P');
      payload.push_back(i < 2 ? 0 : 1);
      payload.push_back(static_cast<std::uint8_t>(i % 2));
      payload.insert(payload.end(), slots[i]->begin(), slots[i]->end());
      payload.resize(3 + kFlashSlotBytes, 0xFF);
      if (!write_frame(payload)) fatal("P exceeds the RPC bound");
    }
  }

 private:
  static std::uint64_t last_op_at(const LoggingStorage& storage, char op) {
    std::uint64_t at = 0;
    for (const auto& entry : storage.log_) {
      if (entry.op == op && entry.result == StatusCode::Ok) at = entry.at;
    }
    return at;
  }

  void round() {
    DeviceEnds& dev = *device_;
    dev.now_ms = now_;
    dev.identity_storage.now_ms = now_;
    dev.site_storage.now_ms = now_;
    // Queued host traffic first: the gateway is idle here, never inside
    // a sink callback, so host_down/host_abort cannot report Busy.
    while (!downs_.empty()) {
      const QueuedDown down = downs_.front();
      downs_.pop_front();
      if (down.site >= sites_.size()) fatal("down for an unknown site");
      const Status status = sites_[down.site]->apply_down(down.to_proxy, down.object, now_);
      if (!status.ok()) fatal("gateway host_down rejected a down object");
    }
    while (!aborts_.empty()) {
      const QueuedAbort abort = aborts_.front();
      aborts_.pop_front();
      if (abort.site >= sites_.size()) fatal("abort for an unknown site");
      const Status status = sites_[abort.site]->apply_abort(abort.proxy, abort.token, now_);
      if (!status.ok()) fatal("gateway host_abort failed");
    }
    deliver_radio();
    deliver_wire();
    for (auto& site : sites_) site->poll(now_);
    if (!dev.joiner.poll(now_).ok()) fatal("device poll failed");
    consume_actions();
    owner_->round(now_);
  }

  void deliver_radio() {
    DeviceEnds& dev = *device_;
    while (!dev.air.empty()) {
      RadioFrame frame = dev.air.front();
      dev.air.pop_front();
      if (frame.deliver_at > now_) {
        dev.air.push_front(frame);
        break;
      }
      for (auto& site : sites_) site->on_radio(frame, now_);
    }
    while (!air_.empty()) {
      RadioFrame frame = air_.front();
      if (frame.deliver_at > now_) break;
      air_.pop_front();
      if (frame.channel != dev.channel) continue;
      JoinRxMeta meta{};
      meta.source = frame.from;
      meta.destination = frame.to;
      meta.channel = frame.channel;
      meta.rssi = rssi_of(frame.from);
      const Status status = dev.joiner.on_rld1_rx(meta, view(frame.bytes), now_);
      if (!status.ok() && status.code != StatusCode::Busy) fatal("device on_rld1_rx failed");
    }
  }

  void deliver_wire() {
    while (!mesh_.empty()) {
      WireFrame frame = mesh_.front();
      if (frame.deliver_at > now_) break;
      mesh_.pop_front();
      for (auto& site : sites_) site->on_wire(frame, now_);
    }
  }

  void consume_actions() {
    DeviceEnds& dev = *device_;
    for (;;) {
      // Terminal actions belong to the driver: report them in S, take
      // channel tunes only.
      const JoinSnapshot snap = dev.joiner.snapshot();
      if (snap.action_pending && snap.pending_action != JoinActionKind::ChangeChannel) {
        if (terminal_at_ == 0) {
          terminal_at_ = now_;
          terminal_kind_ = static_cast<std::uint8_t>(snap.pending_action);
        }
        return;
      }
      JoinAction action{};
      const Status taken = dev.joiner.take_action(action);
      if (taken.code == StatusCode::NotFound) return;
      if (!taken.ok()) fatal("take_action failed");
      if (action.kind != JoinActionKind::ChangeChannel) fatal("unexpected action kind");
      dev.channel = action.channel;
      const Status reported =
          dev.joiner.on_channel_ready(action.channel_token, Status::success(), now_);
      if (!reported.ok()) fatal("on_channel_ready failed");
    }
  }

  std::int16_t rssi_of(const MacAddress& from) const {
    for (const auto& entry : rssi_map_) {
      if (entry.first == from) return entry.second;
    }
    return -90;
  }

  std::unique_ptr<DeviceEnds> device_;
  std::unique_ptr<OwnerLeg> owner_;
  std::uint64_t seed_;
  std::uint64_t now_;
  RadioFaults faults_;
  std::deque<RadioFrame> air_;
  std::deque<WireFrame> mesh_;
  std::vector<std::unique_ptr<PeerSite>> sites_;
  std::vector<std::pair<MacAddress, std::int16_t>> rssi_map_;
  std::deque<QueuedDown> downs_;
  std::deque<QueuedAbort> aborts_;
  std::uint64_t terminal_at_{0};
  std::uint8_t terminal_kind_{0};
};

std::uint64_t get_u64(const Bytes& payload, std::size_t& pos) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(payload.at(pos++)) << (8 * i);
  return value;
}

std::uint32_t get_u32(const Bytes& payload, std::size_t& pos) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) value |= static_cast<std::uint32_t>(payload.at(pos++)) << (8 * i);
  return value;
}

int run(int argc, char** argv) {
  PeerSetup setup{};
  if (!parse_setup(argc, argv, setup)) {
    usage();
    return 2;
  }
  PeerWorld world(setup);
  Bytes frame;
  while (read_frame(frame)) {
    const char tag = static_cast<char>(frame[0]);
    try {
      if (tag == 'T') {
        if (frame.size() != 9) fatal("bad T");
        std::size_t pos = 1;
        world.tick(get_u64(frame, pos));
        world.emit_ups_and_aborts();
        world.emit_snapshot();
        world.emit_member();
        world.emit_owner();
        if (!write_frame(Bytes{'D'})) fatal("D write failed");
        (void)std::fflush(stdout);
      } else if (tag == 'C') {
        if (frame.size() < 3) fatal("bad C");
        world.queue_authority_down(frame[1], Bytes(frame.begin() + 2, frame.end()));
      } else if (tag == 'V') {
        if (frame.size() != 2) fatal("bad V");
        world.request_pull(frame[1]);
      } else if (tag == 'J') {
        if (frame.size() < 2) fatal("bad J");
        world.inject_gossip(Bytes(frame.begin() + 1, frame.end()));
      } else if (tag == 'W') {
        if (frame.size() < 11) fatal("bad W");
        std::size_t pos = 1;
        const std::uint8_t site = frame[pos++];
        const NodeId to_proxy = get_u64(frame, pos);
        world.queue_down(site, to_proxy, Bytes(frame.begin() + pos, frame.end()));
      } else if (tag == 'B') {
        if (frame.size() != 22) fatal("bad B");
        std::size_t pos = 1;
        const std::uint8_t site = frame[pos++];
        const NodeId proxy = get_u64(frame, pos);
        RelayToken token{};
        token.relay_id = get_u32(frame, pos);
        token.gateway_epoch = get_u32(frame, pos);
        token.proxy_epoch = get_u32(frame, pos);
        world.queue_abort(site, proxy, token);
      } else if (tag == 'F') {
        if (frame.size() != 4) fatal("bad F");
        world.set_proxy_muted(frame[1], frame[2], frame[3] != 0);
      } else if (tag == 'P') {
        world.emit_flash();
        (void)std::fflush(stdout);
      } else if (tag == 'X') {
        world.emit_extended();
        (void)std::fflush(stdout);
      } else if (tag == 'Q') {
        return 0;
      } else {
        fatal("unknown tag");
      }
    } catch (const std::exception&) {
      fatal("rpc decode error");
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) { return run(argc, argv); }
