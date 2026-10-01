# Smart join (#197)

Smart join is an opt-in `JoinPolicy` mode. Existing API 1 callers and stored
format-1 policies keep the previous behavior. A healthy stored membership
boots as Member without a ZeroTouch DISCOVER or a new join request. A fresh
smart search listens for `listen_ms`, adds the existing `start_jitter_ms`
random delay, then probes. `search_ms` bounds the whole search, including
listening and retries. One search can start at most one full procedure;
transport retransmissions stay within that procedure. The deadline starts
when the search is requested, including the boot/store check. A stopped
attempt releases its candidate reservation so a later API search can proceed.
A healthy retained membership resumes after a finite verification ends,
while the API reports timeout, pending or denial rather than a new join.
API calls can start
another finite search. `boot_join=false` disables automatic fresh boot joins.
`same_site_only=true` requires a retained site preference; an unassigned
node cannot select an arbitrary site. The existing `isolation_notice_s`
becomes a one-shot retained-site verification trigger when smart join is on.
It never leaves or automatically switches a retained membership (A2, #196b).

## Private marks and wire

`Device::join_mark` / `rl_dev_join_mark` returns a private installation mark:
the first 16 bytes of HMAC-SHA256 under the RLI1 private key, over
`RouteLoom/expected-join/v1` followed by NUL. The current implementation
supports the NvsPlaintext identity backend; other key backends return
Unsupported. Transfer this mark to the administrator over the provisioning
interface. It is a secret, not an inventory ID or an authorization token.

A smart DISCOVER uses ZeroTouch body version 4: the version-3 24-byte fields
plus a 16-byte probe. The probe is the first 16 bytes of HMAC-SHA256 under
the installation mark over `RouteLoom/join-probe/v1`, NUL, and the fresh
16-byte transaction nonce. The envelope claimed NodeId becomes a nonce-derived
transaction pseudonym. The same nonce/probe can be reused during one scan
cycle; the next cycle draws a fresh nonce. Version-3 DISCOVER and OFFER remain
supported for legacy peers. Version-4 OFFER keeps its 48-byte size and adds
flag 0x04 for expected. Unexpected devices receive this short answer but do
not open EDHOC. Smart joiners also wait past busy or authority-unreachable
hints. The first positive answer holds one existing pending-offer row for
one cookie window (2 s by default). Refresh probes from that MAC can update
the nonce without extending the reservation. Other contenders stay light;
m1 admission or expiry releases the row. This prevents simultaneous planned
joiners from consuming their single attempt on the same busy proxy. List expiry is checked again when sending a slotted OFFER, and the gateway
epoch cache must cover the cookie window before a smart positive is sent.
OFFER remains unauthenticated: a forged positive can cause
one procedure, while certificate verification, Authority decision, durable
membership commit/readback and JoinConfirm remain mandatory.

Observers without the installation mark cannot match probes across fresh
nonces from the probe alone. A proxy holding the mark can recognize that
device's probes. MAC addresses, timing and preferred-site hints can still
link observations; this is not MAC anonymity. The true NodeId is disclosed
during the selected full procedure. Existing nonce, source/destination,
organization and cookie checks reject unrelated or stale responses.

## Expected list and freshness

`join.policy.set` accepts `expected_devices` (zero to three 16-byte hex marks)
and `expected_ttl_s` (1..86400 seconds). Empty devices with a nonzero TTL
cancel the list. Marks are omitted from policy responses and redacted from
Debug output. Each content change uses the existing policy generation and
commit-before-publish path. Same generation/different content conflicts;
older generations never replace the stored policy.

The existing 64-byte ProxyPolicySet tail carries tag 0x18, length, version 1,
count, TTL as u32 big endian, then count marks (8 + 16*count bytes total).
Zero/duplicate marks and unknown versions of this tag are rejected. Legacy
opaque tails with a different leading tag retain their previous behavior.
RLPP record format 2 stores the marks; format 1 remains readable. A proxy's
TTL starts only after the authenticated policy arrives and durable readback
succeeds. After a proxy reboot its stored list is inactive until renewed.
The host renews at half the TTL and on channel return, using monotonic time.
Missing, canceled or expired lists do not start fresh EDHOC; discovery ends
at the search deadline. Closed intake and missing lists still permit probes
with the retained-site hint; only the full authenticated recovery can admit
such a node. A guessed hint grants no membership.

## Evidence and limits

`routeloom_smart_join_tests` compares two nearby sites: 2 versus 1 initial
EDHOC messages and 5085 versus 3203 simulated radio bytes. These are simulator
counts, not measured RF airtime. The live joiner interop uses two real Rust
Authorities. Owner mesh tests cover list cancellation/distribution, a mixed
cohort with OFFER and EDHOC reply loss, and retained cutover recovery under
closed intake. Scenario registration is in `tests/e2e/scenarios.json`.
H2 with C3/C6 gateways, two daemons and real RF is still required; these
host results do not establish its airtime or latency acceptance.

## Firmware footprint

ESP-IDF v6.0.3, compared with 4a931258 in the same cells:

| Cell | app.bin before → after | Static free RAM before → after | RTC/LP used |
|---|---|---|---|
| C3 bridge, normal DevRam gateway_small | 1218688 → 1223184 B (+4496) | 52896 → 52736 B (−160) | 6480 B, unchanged |
| C6 bench, normal Member relay | 1425056 → 1431616 B (+6560) | 147527 → 147367 B (−160) | 164 B, unchanged |

The expected keys and site/expiry binding account for the fixed RAM growth;
the positive-offer reservation reuses existing table rows. The measured
`app_bin_max` baselines of these two cells are refreshed for the new codecs,
policy records and probe selection. Static-RAM floors, recorded free-RAM
budgets, RTC limits, drift tolerance, partitions and capacity profiles are
unchanged. C3's 27648 B floor passes with 52736 B remaining. Other firmware
cells were not measured in this PR's targeted run.
