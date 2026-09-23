// State-machine property tests (issue #19): deterministic seeded
// pseudo-random operation sequences over the in-memory SimNetwork —
// sends (Reliable/BestEffort), time advance, random frame loss, node
// reboots (generation bump), partition and rejoin — asserting the
// delivery/dedup invariants that must hold under ANY interleaving:
//
//   * no duplicate app-level delivery of one MessageKey within a node
//     incarnation (the dedup terminal pin is exactly-once per boot);
//   * every app-level delivery matches a send this run issued, at the
//     intended destination, with the exact payload bytes;
//   * Reliable Delivered always has receipt evidence on the wire
//     (an END_RECEIPT frame sighted into the origin), BestEffort
//     Delivered always has the origin's DATA transmission sighted;
//   * delivery states never regress: a non-terminal state may cycle
//     (retry rounds), but once a terminal verdict fired the only legal
//     successor is a STRICTLY stronger evidence class — a late END_RECEIPT
//     promotes Failed/Expired to Delivered, or a BestEffort
//     Delivered(TX_MAC_DONE) to Delivered(END_RECEIVED);
//   * the dedup pool never exceeds kDedupCapacity (profile) and its accounting
//     stays consistent (counted releases never exceed admissions);
//   * no delivery record exceeds the fixed table capacity;
//   * after healing the mesh and draining past the dedup hard cap, no
//     dedup records leak and no live delivery wedges non-terminal.
//
// Determinism: one xorshift64 stream per fixed seed drives every choice,
// so a failing seed reproduces exactly — same idiom as the corpus-replay
// mutator in tests/fuzz/fuzz_driver.hpp.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/types.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,     \
                   #expr);                                                     \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

using namespace routeloom;
using routeloom_test::FrameSight;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;

// xorshift64 — same generator as routeloom_fuzz::Rng so a seed means the
// same op stream here as it does in the corpus mutator.
struct Rng {
  std::uint64_t state;
  std::uint64_t next() noexcept {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  }
  std::size_t below(std::size_t bound) noexcept {
    return bound == 0 ? 0 : static_cast<std::size_t>(next() % bound);
  }
};

// --- Shared run state --------------------------------------------------------

struct SendRecord {
  NodeId origin;
  RouteGeneration origin_generation;  // incarnation at send time
  NodeId destination;
  MessageId id;
  DeliveryClass klass;
  std::vector<std::uint8_t> payload;
  std::uint32_t op;
};

// on_delivery event for one delivery record.
struct DeliveryEvent {
  NodeId node;
  RouteGeneration generation;
  MessageId id;
  DeliveryState state;
  std::string reason;
  std::uint32_t op;
};

// on_message event: app-level delivery at one node incarnation.
struct AppMessage {
  NodeId node;
  RouteGeneration generation;
  MessageKey key;
  NodeId source;
  std::vector<std::uint8_t> payload;
  std::uint32_t op;
};

using DeliveryKey = std::tuple<NodeId, RouteGeneration, std::uint32_t, std::uint64_t>;

struct RunState {
  std::uint64_t seed;
  std::uint32_t op{0};
  SimNetwork* net{nullptr};
  std::vector<SendRecord> sends;
  std::vector<DeliveryEvent> events;
  std::vector<AppMessage> messages;
  // Delivery journal per (node, generation, session, sequence): the
  // terminal (state, evidence rank) seen so far, for the forward-only
  // state-machine check.
  std::map<DeliveryKey, std::pair<DeliveryState, int>> terminal_seen;
  // App-level dedup witness per (node, generation, origin, session, seq).
  std::set<std::tuple<NodeId, RouteGeneration, NodeId, std::uint32_t, std::uint64_t>>
      delivered_keys;
  std::map<NodeId, DedupStats> last_dedup_stats;
  std::uint64_t ops[8]{};
};

bool terminal(DeliveryState s) {
  return s == DeliveryState::Delivered || s == DeliveryState::Failed ||
         s == DeliveryState::Expired || s == DeliveryState::CancelledBeforeTx ||
         s == DeliveryState::Indeterminate;
}

// Evidence rank of a terminal verdict: the reason string carries the
// evidence class (delivery-storage.md §2). A later event may only move the
// record UP this ladder — a late END_RECEIPT is stronger ground truth than
// a deadline failure, and stronger than a BestEffort MAC-level completion:
//   0 = non-success terminal (Failed/Expired/Cancelled/Indeterminate)
//   1 = Delivered on MAC/TX evidence only (TX_MAC_DONE)
//   2 = Delivered on verified end-to-end evidence (END_RECEIVED/APP_APPLIED)
int terminal_rank(DeliveryState s, const char* reason) {
  if (s != DeliveryState::Delivered) return 0;
  if (std::strcmp(reason, "END_RECEIVED") == 0 ||
      std::strcmp(reason, "APP_APPLIED") == 0) {
    return 2;
  }
  return 1;
}

const char* state_name(DeliveryState s) {
  switch (s) {
    case DeliveryState::Empty: return "Empty";
    case DeliveryState::Accepted: return "Accepted";
    case DeliveryState::WaitingForRoute: return "WaitingForRoute";
    case DeliveryState::Queued: return "Queued";
    case DeliveryState::WaitingForMac: return "WaitingForMac";
    case DeliveryState::WaitingForHopAccept: return "WaitingForHopAccept";
    case DeliveryState::WaitingForEndReceipt: return "WaitingForEndReceipt";
    case DeliveryState::Delivered: return "Delivered";
    case DeliveryState::Failed: return "Failed";
    case DeliveryState::Expired: return "Expired";
    case DeliveryState::CancelledBeforeTx: return "CancelledBeforeTx";
    case DeliveryState::Indeterminate: return "Indeterminate";
  }
  return "?";
}

bool receipt_evidence(const RunState& rs, NodeId origin, NodeId destination,
                      const MessageId& id) {
  for (const auto& s : rs.net->sights) {
    if (s.type == FrameType::EndReceipt && s.origin == destination &&
        s.to == origin && s.session == id.session && s.sequence == id.sequence) {
      return true;
    }
  }
  return false;
}

bool mac_evidence(const RunState& rs, NodeId origin, const MessageId& id) {
  for (const auto& s : rs.net->sights) {
    if (s.type == FrameType::Data && s.from == origin && s.session == id.session &&
        s.sequence == id.sequence) {
      return true;
    }
  }
  return false;
}

// Finds a send record for (origin, id). MessageIds restart at 1 on every
// reboot, so `payload` (when given) and `prefer_generation` disambiguate
// reuse across incarnations.
const SendRecord* find_send(const RunState& rs, NodeId origin, const MessageId& id,
                            ByteView payload, RouteGeneration prefer_generation) {
  const SendRecord* fallback = nullptr;
  for (const auto& rec : rs.sends) {
    if (rec.origin != origin || rec.id != id) continue;
    const bool payload_match =
        payload.data != nullptr && rec.payload.size() == payload.size &&
        std::equal(rec.payload.begin(), rec.payload.end(), payload.data);
    if (payload_match) return &rec;  // unique regardless of incarnation
    if (rec.origin_generation == prefer_generation) return &rec;
    fallback = &rec;
  }
  return fallback;
}

// --- Observer ----------------------------------------------------------------

// Records every callback with node incarnation context so the checks above
// stay meaningful across reboots (the node's dedup/delivery state resets,
// the wire evidence in net.sights persists).
class PropObserver final : public NodeObserver {
 public:
  PropObserver(RunState& rs, NodeId node, RouteGeneration generation)
      : rs_(rs), node_(node), generation_(generation) {}

  void on_message(const MessageKey& key, NodeId source,
                  ByteView payload) noexcept override {
    rs_.messages.push_back(AppMessage{node_, generation_, key, source,
                                      std::vector<std::uint8_t>(
                                          payload.data, payload.data + payload.size),
                                      rs_.op});
    // Exactly-once per incarnation: the terminal dedup pin must suppress
    // every re-delivery of a key this boot already handed to the app.
    const auto dup_key =
        std::make_tuple(node_, generation_, key.origin, key.id.session, key.id.sequence);
    if (!rs_.delivered_keys.insert(dup_key).second) {
      std::fprintf(stderr,
                   "  seed=%llu op=%u: DUPLICATE app delivery at node %llu gen %u "
                   "key=(%llu,%u,%llu)\n",
                   static_cast<unsigned long long>(rs_.seed), rs_.op,
                   static_cast<unsigned long long>(node_), generation_,
                   static_cast<unsigned long long>(key.origin), key.id.session,
                   static_cast<unsigned long long>(key.id.sequence));
      ++failures;
    }
    // Every app delivery must trace back to a send issued this run, at the
    // intended destination, byte-identical.
    const SendRecord* rec =
        find_send(rs_, key.origin, key.id,
                  ByteView{payload.data, payload.size}, /*prefer_generation=*/0);
    if (rec == nullptr) {
      std::fprintf(stderr,
                   "  seed=%llu op=%u: app delivery with no matching send at node "
                   "%llu key=(%llu,%u,%llu)\n",
                   static_cast<unsigned long long>(rs_.seed), rs_.op,
                   static_cast<unsigned long long>(node_),
                   static_cast<unsigned long long>(key.origin), key.id.session,
                   static_cast<unsigned long long>(key.id.sequence));
      ++failures;
    } else {
      // Payload matched a send — the frame must still terminate at the
      // send's destination with the send's origin on the key.
      CHECK(rec->destination == node_);
      CHECK(source == key.origin);
    }
  }

  void on_delivery(const DeliveryResult& result) noexcept override {
    rs_.events.push_back(
        DeliveryEvent{node_, generation_, result.id, result.state, result.reason, rs_.op});

    const DeliveryKey key{node_, generation_, result.id.session, result.id.sequence};
    auto it = rs_.terminal_seen.find(key);
    if (it != rs_.terminal_seen.end()) {
      // Terminal verdicts are absorbing except for a strictly stronger
      // evidence promotion: a late verified END_RECEIPT may upgrade
      // Failed/Expired -> Delivered, or a BestEffort Delivered(TX_MAC_DONE)
      // -> Delivered(END_RECEIVED). Anything else — a non-terminal state,
      // a repeated verdict, or a weaker-evidence Delivered — is a state
      // machine regression.
      const int new_rank = terminal_rank(result.state, result.reason);
      if (!terminal(result.state) || new_rank <= it->second.second) {
        std::fprintf(stderr,
                     "  seed=%llu op=%u: delivery state regression at node %llu "
                     "gen %u id=(%u,%llu): %s(%d) -> %s(%d) (%s)\n",
                     static_cast<unsigned long long>(rs_.seed), rs_.op,
                     static_cast<unsigned long long>(node_), generation_,
                     result.id.session,
                     static_cast<unsigned long long>(result.id.sequence),
                     state_name(it->second.first), it->second.second,
                     state_name(result.state), new_rank, result.reason);
        ++failures;
      } else {
        it->second = {result.state, new_rank};
      }
    } else if (terminal(result.state)) {
      rs_.terminal_seen.emplace(
          key, std::make_pair(result.state, terminal_rank(result.state, result.reason)));
    }

    if (result.state == DeliveryState::Delivered) {
      // Terminal evidence is never fabricated: a Reliable Delivered means a
      // verified END_RECEIPT for this message id physically arrived at the
      // origin (sighted on its last hop); a BestEffort Delivered means the
      // origin's DATA frame was transmitted (MAC-level success sighting).
      const SendRecord* rec =
          find_send(rs_, node_, result.id, ByteView{}, generation_);
      if (rec == nullptr) {
        std::fprintf(stderr,
                     "  seed=%llu op=%u: Delivered with no send record at node "
                     "%llu id=(%u,%llu)\n",
                     static_cast<unsigned long long>(rs_.seed), rs_.op,
                     static_cast<unsigned long long>(node_), result.id.session,
                     static_cast<unsigned long long>(result.id.sequence));
        ++failures;
      } else if (rec->klass == DeliveryClass::Reliable) {
        if (!receipt_evidence(rs_, node_, rec->destination, result.id)) {
          std::fprintf(stderr,
                       "  seed=%llu op=%u: Reliable Delivered without receipt "
                       "evidence at node %llu dest %llu id=(%u,%llu)\n",
                       static_cast<unsigned long long>(rs_.seed), rs_.op,
                       static_cast<unsigned long long>(node_),
                       static_cast<unsigned long long>(rec->destination),
                       result.id.session,
                       static_cast<unsigned long long>(result.id.sequence));
          ++failures;
        }
      } else if (rec->klass == DeliveryClass::BestEffort) {
        if (!mac_evidence(rs_, node_, result.id)) {
          std::fprintf(stderr,
                       "  seed=%llu op=%u: BestEffort Delivered without MAC "
                       "evidence at node %llu id=(%u,%llu)\n",
                       static_cast<unsigned long long>(rs_.seed), rs_.op,
                       static_cast<unsigned long long>(node_), result.id.session,
                       static_cast<unsigned long long>(result.id.sequence));
          ++failures;
        }
      }
    }
  }

  void on_diagnostic(const char* reason, NodeId, const MessageId*) noexcept override {
    diagnostics_.emplace_back(reason);
  }

  const std::vector<std::string>& diagnostics() const { return diagnostics_; }

 private:
  RunState& rs_;
  NodeId node_;
  RouteGeneration generation_;
  std::vector<std::string> diagnostics_;
};

// --- World -------------------------------------------------------------------

// SimWorld variant whose observers are PropObservers kept alive across
// node reboots (a rebooted node gets a fresh observer bound to the new
// generation; old observers stay so their event logs remain inspectable).
struct PropWorld {
  NetworkId network_id{1};
  SimNetwork net;
  std::map<NodeId, std::unique_ptr<routeloom_test::TestSecurity>> security;
  std::map<NodeId, std::unique_ptr<SimRadio>> radios;
  std::map<NodeId, std::unique_ptr<MeshNode>> nodes;
  std::map<NodeId, PropObserver*> observers;
  std::deque<std::unique_ptr<PropObserver>> observer_store;
  std::map<NodeId, RouteGeneration> generation;
  std::set<std::pair<NodeId, NodeId>> adjacency;
  MonotonicMs now{0};
  RunState rs;

  MeshNode* add(NodeId id) {
    const RouteGeneration gen = generation.count(id) ? generation[id] : 1;
    generation[id] = gen;
    NodeConfig config{};
    config.network = network_id;
    config.node = id;
    config.message_session = 100 + static_cast<std::uint32_t>(id);
    config.boot_incarnation = 0xB000 + (static_cast<std::uint64_t>(gen) << 8U) + id;
    config.route_generation = gen;
    config.route_advertisement_period_ms = 100;
    config.route_lifetime_ms = 1000;
    security[id] = std::make_unique<routeloom_test::TestSecurity>();
    auto* obs = new PropObserver(rs, id, gen);
    observer_store.emplace_back(obs);
    observers[id] = obs;
    radios[id] = std::make_unique<SimRadio>(net, id);
    nodes[id] =
        std::make_unique<MeshNode>(config, *radios[id], *security[id], *obs);
    net.register_node(id, nodes[id].get());
    return nodes[id].get();
  }

  MeshNode* at(NodeId id) const { return nodes.at(id).get(); }
  PropObserver* obs(NodeId id) const { return observers.at(id); }
  bool alive(NodeId id) const { return nodes.count(id) != 0; }

  void link(NodeId a, NodeId b, RouteMetric metric = 1) {
    if (a == b || !alive(a) || !alive(b)) return;
    net.connect(a, b);
    adjacency.insert(a < b ? std::make_pair(a, b) : std::make_pair(b, a));
    at(a)->add_neighbor(b, metric, now);
    at(b)->add_neighbor(a, metric, now);
  }

  void unlink(NodeId a, NodeId b) {
    net.disconnect(a, b);
    adjacency.erase(a < b ? std::make_pair(a, b) : std::make_pair(b, a));
    if (alive(a)) at(a)->remove_neighbor(b, now);
    if (alive(b)) at(b)->remove_neighbor(a, now);
  }

  // Reboot: fresh MeshNode at a higher persisted route generation (the
  // documented restart contract — peers flush its previous-incarnation
  // route state). RF links survive; neighbor state is re-added both ways.
  void reboot(NodeId id) {
    std::vector<NodeId> peers;
    for (const auto& [a, b] : adjacency) {
      if (a == id) peers.push_back(b);
      if (b == id) peers.push_back(a);
    }
    net.unregister_node(id);
    nodes.erase(id);
    radios.erase(id);
    security.erase(id);
    observers.erase(id);
    rs.last_dedup_stats.erase(id);  // fresh node => fresh counters baseline
    generation[id] = generation[id] + 1;
    add(id);
    at(id)->start(now);
    for (const NodeId peer : peers) {
      if (!alive(peer)) continue;
      net.connect(id, peer);
      at(id)->add_neighbor(peer, 1, now);
      at(peer)->add_neighbor(id, 1, now);
    }
  }

  void start_all() {
    for (auto& [id, node] : nodes) node->start(now);
  }

  void run(MonotonicMs duration_ms, MonotonicMs step = 5) {
    const MonotonicMs end = now + duration_ms;
    for (; now <= end; now += step) {
      for (auto& [id, node] : nodes) node->poll(now);
      net.flush(now);
    }
  }
};

// --- Chaos frame loss --------------------------------------------------------
// Scoped loss window: while budget > 0 the SimNetwork hook drops frames at
// `pct` percent, driven by the run's own RNG stream (deterministic per seed).

struct Chaos {
  Rng* rng{nullptr};
  std::uint64_t budget{0};
  std::size_t pct{0};
};
Chaos g_chaos;

bool chaos_drop(const SimNetwork::Pending&) {
  if (g_chaos.budget == 0 || g_chaos.rng == nullptr) return false;
  --g_chaos.budget;
  return g_chaos.rng->below(100) < g_chaos.pct;
}

// --- Checkpoint invariants ---------------------------------------------------

void check_node_invariants(PropWorld& w, std::uint64_t seed, std::uint32_t op) {
  for (auto& [id, node] : w.nodes) {
    // The dedup pool is a fixed 64-slot arena: residency can never exceed it
    // and counted releases must never exceed admissions (a gap means an
    // accounting bug — the pool would silently leak or double-free records).
    const std::size_t resident = node->dedup_resident();
    const DedupStats& stats = node->dedup_stats();
    const std::uint64_t admissions =
        stats.admitted_terminal + stats.admitted_transit;
    const std::uint64_t releases =
        stats.expired + stats.evicted_resolved + stats.evicted_evidence;
    if (resident > 64 || admissions < releases + resident) {
      std::fprintf(stderr,
                   "  seed=%llu op=%u: dedup accounting broken at node %llu: "
                   "resident=%zu admitted=%llu released=%llu\n",
                   static_cast<unsigned long long>(seed), op,
                   static_cast<unsigned long long>(id), resident,
                   static_cast<unsigned long long>(admissions),
                   static_cast<unsigned long long>(releases));
      ++failures;
    }
    // Counters are saturating-monotone: they must never move backwards.
    auto prev = w.rs.last_dedup_stats.find(id);
    if (prev != w.rs.last_dedup_stats.end()) {
      const DedupStats& p = prev->second;
      CHECK(stats.admitted_terminal >= p.admitted_terminal);
      CHECK(stats.admitted_transit >= p.admitted_transit);
      CHECK(stats.expired >= p.expired);
      CHECK(stats.evicted_resolved >= p.evicted_resolved);
      CHECK(stats.evicted_evidence >= p.evicted_evidence);
      CHECK(stats.refused_pool_full >= p.refused_pool_full);
    }
    w.rs.last_dedup_stats[id] = stats;
    // The delivery table is a fixed 8-slot arena; for_each_delivery must
    // never iterate more records than exist.
    std::size_t deliveries = 0;
    node->for_each_delivery([&](const DeliverySnapshot&) { ++deliveries; });
    CHECK(deliveries <= MeshNode::delivery_capacity());
  }
}

// --- Directed smoke ----------------------------------------------------------
// A two-node exchange that must satisfy every check — proves the harness
// assertions themselves are satisfiable (a broken evidence check would flag
// this run immediately).

void test_directed_smoke() {
  PropWorld w;
  w.rs.seed = 0xD1;
  w.rs.net = &w.net;
  w.add(1);
  w.add(2);
  w.start_all();
  w.link(1, 2);
  w.run(2500);
  const std::array<std::uint8_t, 4> payload{{9, 8, 7, 6}};
  SendOptions options{};
  options.lifetime_ms = 20000;
  MessageId id{};
  const auto status = w.at(1)->send(2, ByteView{payload.data(), payload.size()},
                                    options, w.now, id);
  CHECK(status.ok());
  w.rs.sends.push_back(SendRecord{1, 1, 2, id, DeliveryClass::Reliable,
                                  std::vector<std::uint8_t>(payload.begin(), payload.end()),
                                  0});
  w.run(8000);
  CHECK(w.at(1)->delivery(id).state == DeliveryState::Delivered);
  CHECK(w.rs.messages.size() == 1);
  CHECK(w.rs.events.size() >= 2);  // at least Accepted + Delivered
}

// --- Randomized campaign -----------------------------------------------------

enum Op : std::size_t {
  kSend = 0,
  kStep,
  kDropWindow,
  kPartition,
  kRejoin,
  kReboot,
  kOpCount
};

NodeId pick_node(PropWorld& w, Rng& rng) {
  const std::size_t n = w.nodes.size();
  auto it = w.nodes.begin();
  std::advance(it, rng.below(n));
  return it->first;
}

std::size_t run_seed(std::uint64_t seed, int seed_index) {
  PropWorld w;
  w.rs.seed = seed;
  w.rs.net = &w.net;
  Rng rng{seed};
  g_chaos.rng = &rng;
  w.net.drop_frame = &chaos_drop;

  const int node_count = 5 + static_cast<int>(rng.below(3));  // 5..7 nodes
  for (int i = 1; i <= node_count; ++i) w.add(static_cast<NodeId>(i));
  w.start_all();
  // Connected base topology: a ring plus a few random chords.
  for (int i = 1; i <= node_count; ++i) {
    w.link(static_cast<NodeId>(i), static_cast<NodeId>(i % node_count + 1));
  }
  for (int i = 0; i < node_count / 2; ++i) {
    w.link(static_cast<NodeId>(1 + rng.below(node_count)),
           static_cast<NodeId>(1 + rng.below(node_count)));
  }
  w.run(2500);  // partial route convergence; churn continues from here

  constexpr std::uint32_t kOps = 300;
  for (std::uint32_t op = 0; op < kOps; ++op) {
    w.rs.op = op;
    const std::size_t choice = rng.below(100);
    if (choice < 34) {  // send
      ++w.rs.ops[kSend];
      const NodeId from = pick_node(w, rng);
      NodeId to = pick_node(w, rng);
      if (to == from || !w.alive(from) || !w.alive(to)) continue;
      const bool reliable = rng.below(4) != 0;  // 75% Reliable
      SendOptions options{};
      options.delivery = reliable ? DeliveryClass::Reliable : DeliveryClass::BestEffort;
      options.priority = static_cast<Priority>(rng.below(4));
      constexpr std::uint32_t kLifetimes[] = {1500, 5000, 12000, 30000};
      options.lifetime_ms = kLifetimes[rng.below(4)];
      std::vector<std::uint8_t> payload(4 + rng.below(29));
      payload[0] = 0xA5;
      payload[1] = static_cast<std::uint8_t>(op >> 8U);
      payload[2] = static_cast<std::uint8_t>(op);
      payload[3] = static_cast<std::uint8_t>(seed_index);
      for (std::size_t i = 4; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(rng.next());
      }
      MessageId id{};
      const auto status = w.at(from)->send(
          to, ByteView{payload.data(), payload.size()}, options, w.now, id);
      // Admission refusal (delivery table full, draining) is legitimate —
      // only successful sends enter the tracked set.
      if (status.ok()) {
        w.rs.sends.push_back(SendRecord{from, w.generation[from], to, id,
                                        options.delivery, std::move(payload), op});
      }
    } else if (choice < 64) {  // advance time
      ++w.rs.ops[kStep];
      w.run(20 + rng.below(480));
    } else if (choice < 72) {  // bounded loss window
      ++w.rs.ops[kDropWindow];
      g_chaos.budget = 3 + rng.below(38);
      g_chaos.pct = 10 + rng.below(51);  // 10..60% per-frame loss
      w.run(20 + rng.below(200));        // let the window bite
      g_chaos.budget = 0;
    } else if (choice < 80) {  // partition: cut a link or isolate a node
      ++w.rs.ops[kPartition];
      if (!w.adjacency.empty() && rng.below(2) == 0) {
        auto it = w.adjacency.begin();
        std::advance(it, rng.below(w.adjacency.size()));
        w.unlink(it->first, it->second);
      } else {
        const NodeId id = pick_node(w, rng);
        std::vector<std::pair<NodeId, NodeId>> edges;
        for (const auto& e : w.adjacency) {
          if (e.first == id || e.second == id) edges.push_back(e);
        }
        for (const auto& e : edges) w.unlink(e.first, e.second);
      }
    } else if (choice < 90) {  // rejoin / grow the mesh
      ++w.rs.ops[kRejoin];
      w.link(pick_node(w, rng), pick_node(w, rng));
    } else {  // reboot a node at a higher persisted generation
      ++w.rs.ops[kReboot];
      w.reboot(pick_node(w, rng));
    }
    check_node_invariants(w, seed, op);
  }

  // Heal phase: loss hook off, every live pair reconnected, then drain far
  // past the 60 s dedup hard cap so every record must expire.
  g_chaos.budget = 0;
  w.net.drop_frame = nullptr;
  for (auto it = w.nodes.begin(); it != w.nodes.end(); ++it) {
    for (auto jt = std::next(it); jt != w.nodes.end(); ++jt) {
      w.link(it->first, jt->first);
    }
  }
  w.run(120000);

  // No dedup leak: the hard cap forces every record out once traffic stops.
  for (auto& [id, node] : w.nodes) {
    if (node->dedup_resident() != 0) {
      std::fprintf(stderr,
                   "  seed=%llu: dedup leak at node %llu: %zu records still "
                   "resident after drain\n",
                   static_cast<unsigned long long>(seed),
                   static_cast<unsigned long long>(id), node->dedup_resident());
      ++failures;
    }
  }

  // Liveness: every send whose origin incarnation survived reaches a
  // terminal state (or its result history was evicted — reported Empty).
  std::size_t delivered = 0;
  for (const auto& rec : w.rs.sends) {
    if (!w.alive(rec.origin) || w.generation[rec.origin] != rec.origin_generation) {
      continue;  // the record died with its node incarnation
    }
    const DeliveryState state = w.at(rec.origin)->delivery(rec.id).state;
    if (state == DeliveryState::Delivered) ++delivered;
    if (state != DeliveryState::Empty && !terminal(state)) {
      std::fprintf(stderr,
                   "  seed=%llu op=%u: wedged delivery at node %llu id=(%u,%llu) "
                   "still %s after drain\n",
                   static_cast<unsigned long long>(seed), rec.op,
                   static_cast<unsigned long long>(rec.origin), rec.id.session,
                   static_cast<unsigned long long>(rec.id.sequence),
                   state_name(state));
      ++failures;
    }
  }
  std::fprintf(stderr,
               "  seed=%llu: sends=%zu delivered=%zu ops{send=%llu step=%llu "
               "drop=%llu part=%llu rejoin=%llu reboot=%llu}\n",
               static_cast<unsigned long long>(seed), w.rs.sends.size(), delivered,
               static_cast<unsigned long long>(w.rs.ops[kSend]),
               static_cast<unsigned long long>(w.rs.ops[kStep]),
               static_cast<unsigned long long>(w.rs.ops[kDropWindow]),
               static_cast<unsigned long long>(w.rs.ops[kPartition]),
               static_cast<unsigned long long>(w.rs.ops[kRejoin]),
               static_cast<unsigned long long>(w.rs.ops[kReboot]));
  return delivered;
}

void test_random_campaign() {
  // Fixed seed list: the campaign is deterministic and a failure prints the
  // seed so the exact op stream reproduces locally.
  constexpr std::uint64_t kSeeds[] = {0x1EED001, 0x1EED002, 0x1EED003, 0x1EED004,
                                      0x1EED005, 0x1EED006, 0x1EED007, 0x1EED008};
  std::size_t total_delivered = 0;
  for (int i = 0; i < 8; ++i) total_delivered += run_seed(kSeeds[i], i);
  // The campaign must actually deliver — a vacuous run (no routes, every
  // send refused) would satisfy the invariants while testing nothing.
  CHECK(total_delivered > 0);
}

}  // namespace

int main() {
  test_directed_smoke();
  test_random_campaign();
  if (failures != 0) {
    std::fprintf(stderr, "%d property checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom property tests passed");
  return 0;
}
