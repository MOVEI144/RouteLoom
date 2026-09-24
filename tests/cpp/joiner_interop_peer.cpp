// Live E2E peer (design P3-4 §10.2): the C++ end of the Rust Site
// Authority interop. A real Joiner + ZtJoinerLink + Identity/Site stores
// runs on a fake channel-switching radio and fake slot flash; each site
// runs a real JoinProxy + JoinRelayGateway whose host sink is the pipe to
// the Rust driver (host/routeloom-host/src/site/joiner_interop.rs) —
// there is deliberately no scripted authority on this side.
//
// Framing: u16le length (1..1100) + payload over stdin/stdout; stderr is
// diagnostics only and never carries key material. First payload byte is
// the tag. Rust -> C++:
//
//   T <now u64le>                    advance virtual time, run the pump
//   W <site u8><to_proxy u64le><relay object>   host down (queued, applied
//                                        at the next round, never in a callback)
//   B <site u8><proxy u64le><relay_id u32le>     host abort (queued likewise)
//   F <site u8><proxy u8><muted u8>   power a proxy off/on
//   P                              dump the flash image (4 slot replies)
//   Q                              quit (exit 0)
//
// C++ -> Rust, emitted after each T in this order:
//
//   U <site u8><proxy u64le><hops u8><relay object>   one relayed up
//   A <site u8><proxy u64le><relay_id u32le><reason u8> gateway/proxy abort
//   S <46 B snapshot>               state/action/store/counter observation
//   M <site cert><member cert><dams sha256>  member material (digests, no keys)
//   P <store u8><slot u8><1024 B>    flash slot image (power-cut handover)
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
// Setup arrives on argv (all integers accept 0x hex; blobs are hex):
//
//   --node <u64> --mac <12hex> --dev-priv <64hex> --dev-pub <128hex>
//   --dev-cert <hex> --site-ca-id <u64> --site-ca-pub <128hex>
//   --fw <u32> --cap <u32> --role <u8> --t0 <ms> --seed <u64>
//   --site <id,network,gateway,proxymac,proxynode,channel,rssi,hops>
//   --flash <file>   (optional 4096 B preload: identity slots, site slots)
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

#include "routeloom/device_credential.hpp"
#include "routeloom/discovery_scope.hpp"

#include "join_sim_network.hpp"

namespace {

using namespace join_sim;
using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kRpcMax = 1100;
constexpr std::size_t kFlashSlots = 4;  // identity 0/1, site 0/1
constexpr std::size_t kFlashBytes = kFlashSlots * kIdentitySlotBytes;
constexpr std::uint64_t kBootWitness = 0x0A11CE;
constexpr std::uint64_t kTickStepMs = 5;

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
  std::uint32_t relay_id{0};
  std::uint8_t reason{0};
};

class PipeSink final : public JoinRelayHostSink {
 public:
  Status relay_up(const NodeId proxy, const std::uint8_t hops,
                  const ByteView object) noexcept override {
    ups.push_back(PeerUp{proxy, hops, Bytes(object.data, object.data + object.size)});
    return Status::success();
  }
  Status relay_abort(const NodeId proxy, const std::uint32_t relay_id,
                     const RelayAbortReason reason) noexcept override {
    aborts.push_back(PeerAbort{proxy, relay_id, static_cast<std::uint8_t>(reason)});
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
  Status apply_abort(NodeId proxy, std::uint32_t relay_id, std::uint64_t now) {
    return gateway_.host_abort(proxy, relay_id, now);
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

// --- Setup -----------------------------------------------------------------------

struct PeerSetup {
  JoinerConfig config{};
  IdentityRecord identity{};
  std::uint64_t t0{0};
  std::uint64_t seed{0x5EED1234ULL};
  std::vector<SimSiteParams> sites;
  Bytes flash;  // empty, or exactly kFlashBytes
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
               "[--flash <file>]\n");
}

// The site CA keypair outlives the setup (SimSiteParams only borrows it).
routeloom_test::TestKeyPair g_site_ca{};

bool parse_setup(int argc, char** argv, PeerSetup& setup) {
  Bytes dev_priv, dev_pub, dev_cert, site_ca_pub, mac;
  std::uint64_t node = 0, site_ca_id = 0, fw = 0, cap = 0, role = 0;
  bool have_node = false, have_mac = false, have_priv = false, have_pub = false,
       have_cert = false, have_ca_id = false, have_ca_pub = false, have_t0 = false;
  std::string flash_path;
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
  return true;
}

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
  std::uint32_t relay_id{0};
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
                  setup.flash.data() + kIdentitySlotBytes, kIdentitySlotBytes);
      std::memcpy(dev.site_storage.inner_.slot(0).data(), setup.flash.data() + 2 * kSiteSlotBytes,
                  kSiteSlotBytes);
      std::memcpy(dev.site_storage.inner_.slot(1).data(), setup.flash.data() + 3 * kSiteSlotBytes,
                  kSiteSlotBytes);
    }
    for (const auto& site : setup.sites) add_site(site);
    JoinBootInput boot{};
    boot.boot_witness = static_cast<std::uint32_t>(kBootWitness);
    boot.prepared = true;
    const Status started = device_->joiner.start(boot, now_);
    if (!started.ok()) fatal("joiner start failed");
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
  void queue_abort(std::uint8_t site, NodeId proxy, std::uint32_t relay_id) {
    aborts_.push_back(QueuedAbort{site, proxy, relay_id});
  }
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
        put_u32(payload, abort.relay_id);
        payload.push_back(abort.reason);
        if (!write_frame(payload)) fatal("A write failed");
      }
    }
  }

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
      const Status status = sites_[abort.site]->apply_abort(abort.proxy, abort.relay_id, now_);
      if (!status.ok()) fatal("gateway host_abort failed");
    }
    deliver_radio();
    deliver_wire();
    for (auto& site : sites_) site->poll(now_);
    if (!dev.joiner.poll(now_).ok()) fatal("device poll failed");
    consume_actions();
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
        if (!write_frame(Bytes{'D'})) fatal("D write failed");
        (void)std::fflush(stdout);
      } else if (tag == 'W') {
        if (frame.size() < 11) fatal("bad W");
        std::size_t pos = 1;
        const std::uint8_t site = frame[pos++];
        const NodeId to_proxy = get_u64(frame, pos);
        world.queue_down(site, to_proxy, Bytes(frame.begin() + pos, frame.end()));
      } else if (tag == 'B') {
        if (frame.size() != 14) fatal("bad B");
        std::size_t pos = 1;
        const std::uint8_t site = frame[pos++];
        const NodeId proxy = get_u64(frame, pos);
        std::uint32_t relay_id = 0;
        for (int i = 0; i < 4; ++i)
          relay_id |= static_cast<std::uint32_t>(frame.at(pos++)) << (8 * i);
        world.queue_abort(site, proxy, relay_id);
      } else if (tag == 'F') {
        if (frame.size() != 4) fatal("bad F");
        world.set_proxy_muted(frame[1], frame[2], frame[3] != 0);
      } else if (tag == 'P') {
        world.emit_flash();
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
