# AppObject foreground-wait regression

This is analysis of retained H7R2 evidence and a software regression. No
boards were accessed or flashed for this PR. Hardware requalification is
postponed to the combined main round under the PM's 2026-10-02 instruction.
The implementation baseline is `48142311ec4485783e76845b68347363c28e49eb`.

## Retained hardware evidence

The authoritative H7R2 record is in the `v2-h7r2` worktree. Private evidence
is under `/tmp/routeloom-hil-v2/h7r2/evidence/`; no raw serial logs, credentials
or payloads are included here.

- `objects/1hop-2048-window.json`: 42 admitted sends, 0 Delivered; all results
  are Expired at approximately 10 seconds, the unchanged no-progress limit.
- `objects/1hop-2048-baseline.json`: control-only delivery is already 21/100.
  The retained `scope-objects.py` runner uses 150 ms send spacing, approximately
  6.7 Hz, for both baseline and mixed control campaigns. This differs from the
  1 Hz regression requested by V2-HFIX-OBJECT2.
- During the mixed window, the source's serial diagnostics repeatedly report
  `DEDUP_TERMINAL_RESERVE` and also report `HOP_ACCEPT_TIMEOUT`. These are
  authenticated Reliable DATA admission/receipt failures, not evidence that
  object chunks consume terminal DATA pins.
- The later `objects-alone` samples deliver 2 KiB at one hop in 3804 ms and
  three hops in 8057 ms; 4 KiB at three hops takes 15214 ms. Each is one sample,
  not a 99% qualification. The mixed-load failure is not a universal failure
  of assembly, digest verification or completion acknowledgement.

| Evidence file | SHA-256 |
| --- | --- |
| `objects/1hop-2048-window.json` | `724f6d0d43a1b1ef3000b12943d3bc598fb29039f4de4d92b1f8634bd7df9219` |
| `objects/1hop-2048-baseline.json` | `fa7d24cea73c021f42114cc309072c0111a1afcac00fe7279ac542691bb29c9b` |
| `objects-alone/1hop-2048.json` | `7228447db62e02a98c96911b62ca966b259a2db220f6630f7225eb394f7ec6ec` |
| `objects-alone/3hop-2048.json` | `6e711ae05c84314520277854e5570eba4052c6522cb7cc3cb9aac99596219a89` |
| `objects-alone/3hop-4096.json` | `0a27b328d9fcad994d7c8cf3eafabfb6752716d29692fa6bf7690ac53ead3d21` |

The retained logs contain object admission and sender results, but no per-frame
START/OFFER, chunk or bitmap-ACK trace at both endpoints. Consequently they do
not establish the last completed stage of each failed transfer. The 10-second
result proves absent sender progress; attribution of every hardware expiry to
the scheduler remains an inference requiring the combined HIL run.

## Reproducer and correction

The scheduler counted every nonterminal foreground Delivery as pending, even
when it had no frame queued and was waiting for a route or a later retry.
An unrelated admitted send could therefore block all AppObject START, chunk
and ACK dispatch for longer than the 10-second object progress deadline.
The correction restricts the Delivery hold to Queued through
WaitingForEndReceipt. The existing queued-flow priority, outstanding hop
exchange priority and foreground airtime hold are retained. No new timer,
state, buffer or capacity is added.

`M10-HFIX-OBJECT2` uses real Device/Owner/MeshNode peers, Member security, 5 ms
virtual ticks, 10 ms frame/driver delays, 100 immediate 2 KiB objects and 1 Hz
Reliable controls. The existing crypto worker model is enabled with 154 ms
job latency, and every peer must have submitted and completed worker jobs.
An accepted Reliable send to an absent destination every 30 seconds keeps a separate foreground delivery waiting. Its intentional
expiry is excluded from healthy-control End-failure accounting; every hop
failure counter and healthy-control sender result remains checked.
Before the correction, the first two objects expire at 10000 and 20000 ms and
the test fails. After the correction: 100/100 objects and 728/728 healthy
controls Delivered.
A matched-duration baseline has the same 728 controls over 727110 ms.
Control p99 is 120 ms without objects and 150 ms with objects (+25%);
the required <=20% latency increase remains FAIL. This row stays `red`;
no threshold was weakened. The PM permits deferring known failures.
There are no added hop timeouts, healthy-control End failures, route flaps or
duplicate object callbacks. These are virtual-time host measurements.

The load peers use the host `full` resource profile with automatic dedup
capacity (96 entries), not the H7R2 C6 leaf dedup32 profile. The archived
control-only capacity failure is not repaired or qualified by these tests.

AppObject's receive path uses routed End AEAD verification, the Owner's bounded
component event drain, then ObjectAssembler and SHA-256 digest verification.
That digest verification is synchronous; it does not submit a crypto-worker
job. COSE/EDHOC worker scheduling and dedup authentication/admission order are
unchanged by this correction.

## Verification and limits

- Sanitizer CTest: AppObject codec/assembler, endpoint boundaries and congestion
  scheduler: 3/3 PASS.
- Rust 1.85.0 workspace fmt and clippy with warnings denied: PASS.
- Worker-enabled M10 route-wait regression: FAIL on p99 only, actual peers.
  Object progress and healthy-control delivery pass; the injected route-wait
  expiry is excluded as described above. There are no added hop timeouts,
  healthy-control End failures, route flaps or duplicate object callbacks.
- Existing immediate variants: PASS on the final correction, no missing-peer
  skip, 100/100 objects each. 2 KiB/two hop p99 120→130 ms,
  2 KiB/one hop 50→55 ms and 4 KiB/one hop 50→60 ms. Healthy controls
  deliver 751/751, 500/500 and 853/853 respectively.
- Existing 4 KiB three-hop regression: PASS, actual peers, no skip.
- Scenario table validation and `git diff --check`: PASS.
- `git clang-format --diff origin/main`: NOT_RUN, command unavailable locally.
- Full CTest, Rust workspace live suite, quick/selfcheck/nightly, other firmware
  cells and on-board acceptance: NOT_RUN by the current PM scope.

ESP-IDF v6.0.3, only cell `bridge_node-esp32c3-normal-off-app_object`, built
before/after with at most four jobs. This cell selects DevRam; the host Owner
regressions explicitly select Member security.

| C3 measurement | Before | After | Change |
| --- | ---: | ---: | ---: |
| app.bin | 1258064 B | 1258016 B | -48 B |
| static BSS | 222912 B | 222912 B | 0 B |
| static data | 13364 B | 13364 B | 0 B |
| static free | 35672 B | 35672 B | 0 B |
| RTC used | 6552 B | 6552 B | 0 B |

The unchanged 27648 B static-RAM guard passes both builds. The complete
`python3 tools/check.py firmware --cell bridge_node-esp32c3-normal-off-app_object`
command fails both builds at the existing soft cell budget: app maximum
1240976 B and static-free minimum 40480 B (even with the existing drift
allowances). Those budget values were not loosened. Runtime heap and Owner
CPU occupancy were not measured.

Wire/API/Kconfig, security requirements, dedup/replay retention, object
admission/completion records, no-progress and absolute deadlines, the single
frame window and 50000 us/s object airtime budget are unchanged. Dedup pressure
from the archived 6.7 Hz DATA campaign, recovery/worker qualification and cell
budget drift remain for their respective follow-ups. This PR does not claim
99% hardware success or update `docs/STATUS.md`.
