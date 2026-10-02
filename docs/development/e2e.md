# E2E scenario matrix

[tests/e2e/scenarios.json](../../tests/e2e/scenarios.json) is the test catalog.
It supersedes the old autonomous-mesh ledger. `live` rows name executable
regressions; `red` rows retain a failing reproducer and Issue; `pending` rows
name the missing feature or evidence in `blocked_by` and `note`. A live host
row does not establish its HIL variant. `acceptance_pending` maps the six
unverified V1 acceptance halves to the relevant V2 rows without treating
existing test tags as proof.

```sh
python3 tools/check.py scenarios
cmake -S . -B build -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j8 --target routeloom_owner_mesh_peer routeloom_joiner_interop_peer
ROUTELOOM_E2E_OUT="$PWD/build/e2e-out" python3 tools/check.py e2e --tier pr --shard all
```

`--build-dir` selects another CMake directory; `--test-bin` selects an already
compiled Rust libtest executable. The runner checks peer RPC versions, rejects
missing peers and success-shaped skips, and requires every selected case to
pass. Shards are `mesh`, `join` (including cutover), and `fault` (including
periodic load and product API scenarios). A row may override its `shard`: the
two long K1b variants are split between mesh (isolation) and fault (lost Pull
answers) to balance the measured load. Both stay required on PRs with their
original assertions. Shared cases belong to the first row
that names them, so shards do not duplicate work. All existing joiner interop
cases remain required. `matrix-summary.json` records the revision, tier, wall
time and row verdicts. Mixed CTest/Rust rows remain `NOT_RUN` in that summary
until their other layer is verified; each Owner world also writes its existing
run, metrics and assertion reports.

`.github/workflows/e2e.yml` builds peers and the Rust test binary once and passes
a tar archive to three jobs, preserving paths and executable permissions. PR
jobs have a ten-minute limit. Nightly jobs have a sixty-minute limit, use `-O2`
peers without sanitizers, and run the sanitizer variant on Sundays. Nightly
Owner tests run one at a time (including any 32-process world), and existing
product-timer scale models run separately. `/usr/bin/time -v` records CPU and
peak RSS beside the reports. These limits are budgets; a completed GitHub run
is needed to establish CI wall time. The `long` CTest label keeps the 100-node
models out of sanitizer core cells; sanitizer-free profile cells still run
them. M07-N's 20-seed/24-hour campaign remains pending.

The first local PR-shard run passed all 89 selected cases on a shared host:

| Shard before K1b redistribution | Cases | Wall time | Peak RSS |
| --- | ---: | ---: | ---: |
| mesh | 25 | 980.92 s | 269,272 KiB |
| join | 35 | 2,115.72 s | 254,300 KiB |
| fault | 29 | 740.16 s | 148,804 KiB |

These runs exceeded ten minutes and do not establish the CI budget. The
redistributed 26/33/30-case layout preserves the same 89 cases; its wall time
and the prepare job still need measurement on GitHub runners.

M08, K01/K03/K05 and M01-T3 run through real Owners. M08 checks the
7/8/9 admission boundary, accounts for every burst request, verifies each
Delivered result against a unique receive, and requires at least 99% sender
receipts, stable next hops, active membership and a 30-second queue drain.
The full topology settles before M08 begins its five-minute load. K01 covers two/three
hops, 127-byte content, periodic status/events and seeded noise. K03 exercises
ALL group delivery, admission-response replay and a full gateway delivery
table affecting the last destination. K05 additionally uses the documented
consumer and production API1 socket for durable cursor restart coverage.

K02 runs the 31-node product-timer model with churn, continuous view freshness
and the authoritative mean per-node/total management airtime limits. Stable
metric/sequence changes use periodic advertisements; topology repair stays
triggered. A 31-node real-Owner row also measures every discovery, probe,
HELLO and route transmission once per sender, including failed emissions,
while checking periodic view freshness and reliable status through churn. The mesh daemon calls the production API1 handler on its virtual
clock; the consumer cases cover socket framing. Nightly five/32-node and
30-minute configurations are dry-run coverage until executed. The 24-hour,
sleep and object variants remain with V2-15/16/18/19. No dry-run establishes
radio or on-board acceptance.

K02's Owner peers explicitly select Member security and use the default
non-smart join policy. Its staged boot exercises consecutive link exchanges
to the same peer: a completed exchange's retained demux row must not become
the send leg for a later resume's R3 retries. Current-context authentication
and the scenario's boot, freshness, status and airtime limits remain enforced.

## HIL plans

```sh
python3 tools/hil/scenarios.py --rig tools/hil/rigs.yaml \
  --bench bench-2026-09-29-h0 --dry-run M06
```

The thin loader reads the same row and `pass`, assigns distinct boards by role
and chip, and lists the existing scripts or `manual`. It never resolves ports,
resets boards, starts a daemon, or flashes firmware. Exit zero means the rig
configuration has the required boards; the verdict is always `NOT_RUN`. Missing
boards return one, invalid rows return two. Five-board campaigns require C3×3
and C6×2; they cannot pass on a smaller configured rig. S3/C5 variants need their
actual hardware.

Execute the listed scripts using their own arguments and the procedures in
[the HIL guide](../hil.md); the loader does not infer destructive actions or
invent a generic scenario executor. Record software, power, USB-data and process
resets separately. A dry-run does not provide RF, heap, timing, flash/MAC
preflight or on-board acceptance evidence.
