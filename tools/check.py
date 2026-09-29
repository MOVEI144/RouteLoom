#!/usr/bin/env python3
"""One entry point for the repository checks CI runs.

Each stage is a fixed list of the existing commands (this tool does not
reimplement any test); `--dry-run` prints them instead of running them.
The firmware cells, their sdkconfig overlays and assertions, and the
per-cell size budgets live in tools/ci/cells.json, the single list the
sdk.yml firmware matrix is generated from.

    check.py quick                  docs + portable C/C++ tests
    check.py ci [--dry-run]         every stage CI runs, in order
    check.py core|docs|golden|rust|interop|profile-mesh|fuzz
    check.py profiles [--build DIR]  portable suites per resource profile
    check.py scenarios              tests/e2e/scenarios.json rows
    check.py firmware --list [--format github]
    check.py firmware (--cell ID ... | --all)   needs an exported ESP-IDF
    check.py size --cell ID [--build-dir DIR]   budget of an existing build
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CELLS = ROOT / "tools" / "ci" / "cells.json"
SCENARIOS = ROOT / "tests" / "e2e" / "scenarios.json"
SCENARIO_SCHEMA = 1
SCENARIO_KEYS = ("id", "family", "variant", "tier", "layer", "topology", "faults", "pass",
                 "test", "prs", "issues", "hil", "status")
REQUIRED_V2_PRS = {f"V2-{number:02d}" for number in range(1, 23)}
JOBS = str(min(os.cpu_count() or 2, 8))
FUZZ_TARGETS = ("wire_frame", "usb_codec", "autonomy", "endpoint", "host_ops", "migration",
                "cose", "rlres1", "sdkv1", "sdkv1_ead", "sdkv1_join")
# Generated-vector directories: diff catches changed bytes, porcelain catches
# a generator that starts emitting an unreviewed (untracked) vector.
GENERATED_GOLDENS = (
    "protocol/golden", "protocol/usb-golden", "protocol/autonomy-golden",
    "protocol/provisioning-golden", "protocol/sdkv1-golden", "protocol/bench-golden",
    "protocol/endpoint-golden", "protocol/config-signed-golden", "protocol/edhoc-interop",
    "protocol/edhoc-rfc9529", "tests/fuzz/corpus/sdkv1_ead",
    "tests/fuzz/corpus/sdkv1_handshake", "tests/fuzz/corpus/sdkv1_join")
PEER = "build/tests/cpp/routeloom_joiner_interop_peer"
MESH_PEER = "build/tests/cpp/routeloom_owner_mesh_peer"
PEER_VERSION = "1"
MESH_PEER_VERSION = "4"
# A live interop suite that finds no C++ peer prints this and passes as a
# skip; the interop stage treats it as a failure. Not anchored: with
# --nocapture the harness output of parallel tests can share the line.
SKIP_MARK = re.compile(r"SKIP site::")
# One passed libtest case; not anchored for the same reason.
PASSED = re.compile(r"test (\S+) \.\.\. ok")


class Step:
    """One command: argv, working directory (relative to ROOT) and extra env."""

    def __init__(self, argv, cwd=".", env=None, forbid=None, stdout=None, require=None):
        self.argv, self.cwd, self.env = list(argv), cwd, dict(env or {})
        self.forbid, self.stdout = forbid, stdout
        # require_live: these libtest cases must pass, and at least one case must.
        self.require = require

    def text(self) -> str:
        env = " ".join(f"{k}={shlex.quote(v)}" for k, v in self.env.items())
        cmd = " ".join(shlex.quote(a) for a in self.argv)
        if self.stdout:
            cmd += f" > {self.stdout}"
        where = "" if self.cwd == "." else f"(cd {self.cwd} && "
        return f"{where}{env + ' ' if env else ''}{cmd}{')' if where else ''}"


def core(sanitizers: str = "ON") -> list[Step]:
    return [
        Step(["cmake", "-S", ".", "-B", "build", "-DROUTELOOM_BUILD_TESTS=ON",
              f"-DROUTELOOM_ENABLE_SANITIZERS={sanitizers}", "-DCMAKE_BUILD_TYPE=Debug"]),
        Step(["cmake", "--build", "build", "--parallel", JOBS]),
        Step(["ctest", "--test-dir", "build", "--output-on-failure", "-j", JOBS]),
    ]


def docs() -> list[Step]:
    return [Step(["python3", "tools/check_docs.py"]),
            Step(["python3", "tools/gen_manifest.py", "--check"]),
            Step(["python3", "tools/sync_reference_tables.py", "--check"]),
            Step(["python3", "tools/check_review_contracts.py"]),
            Step(["python3", "tools/check.py", "scenarios"]),
            Step(["python3", "-m", "unittest", "discover", "-s", "tests", "-v"])]


def golden() -> list[Step]:
    targets = ["routeloom_golden_tests", "routeloom_usb_tests", "routeloom_key_schedule_tests",
               "routeloom_sdkv1_golden_tests", "routeloom_sdkv1_ead_tests",
               "routeloom_sdkv1_join_transport_tests"]
    steps = [
        Step(["cmake", "-S", ".", "-B", "build-golden", "-DROUTELOOM_BUILD_TESTS=ON",
              "-DCMAKE_BUILD_TYPE=Debug"]),
        Step(["cmake", "--build", "build-golden", "--parallel", JOBS, "--target", *targets]),
        Step(["ctest", "--test-dir", "build-golden", "--output-on-failure", "-R",
              "routeloom_(golden|usb|key_schedule|sdkv1_golden|sdkv1_ead|sdkv1_join_transport)_tests"]),
        Step(["cargo", "test", "-p", "routeloom-wire", "-p", "routeloom-protocol",
              "-p", "routeloom-keysched"], cwd="host"),
        Step(["cargo", "test", "-p", "routeloom-provision", "--test", "sdkv1_golden"], cwd="host"),
        Step(["cargo", "test", "-p", "routeloom-join"], cwd="host"),
    ]
    for crate, example in (("routeloom-wire", "gen_golden"),
                           ("routeloom-protocol", "gen_usb_golden"),
                           ("routeloom-provision", "gen_provisioning_golden")):
        steps.append(Step(["cargo", "run", "-p", crate, "--example", example], cwd="host"))
    for gen in ("gen_autonomy_vectors", "gen_sdkv1_derivation_vectors",
                "gen_sdkv1_authority_vectors", "gen_sdkv1_vectors", "gen_sdkv1_ead_vectors",
                "gen_sdkv1_dams_vectors", "gen_sdkv1_join_transport_vectors",
                "gen_sdkv1_handshake_vectors", "gen_sdkv1_join_relay_v2_vectors",
                "gen_sdkv1_revocation_vectors", "gen_bench_vectors", "gen_endpoint_vectors"):
        steps.append(Step(["python3", f"tools/{gen}.py"]))
    steps.append(Step(["git", "diff", "--exit-code", "--", *GENERATED_GOLDENS]))
    # Untracked output: porcelain must be empty (forbid any output line).
    steps.append(Step(["git", "status", "--porcelain", "--", *GENERATED_GOLDENS],
                      forbid=re.compile(r".")))
    return steps


def rust() -> list[Step]:
    return [Step(["cargo", "fmt", "--all", "--check"], cwd="host"),
            Step(["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
                 cwd="host"),
            # The live Owner E2E suites need C++ peers and run in `interop`.
            Step(["cargo", "test", "--workspace", "--all-targets", "--", "--skip",
                  "joiner_interop", "--skip", "site::owner_mesh::"], cwd="host"),
            Step(["cargo", "build", "--workspace", "--release", "--all-targets"], cwd="host")]


def interop() -> list[Step]:
    env = {"ROUTELOOM_OWNER_PEER": str(ROOT / PEER), "UBSAN_OPTIONS": "halt_on_error=1"}
    mesh_env = {**env, "ROUTELOOM_MESH_PEER": str(ROOT / MESH_PEER)}
    rows = load_scenarios()
    return [
        Step(["cmake", "-S", ".", "-B", "build", "-DROUTELOOM_BUILD_TESTS=ON",
              "-DROUTELOOM_ENABLE_SANITIZERS=ON", "-DCMAKE_BUILD_TYPE=Debug"]),
        Step(["cmake", "--build", "build", "--parallel", JOBS, "--target",
              "routeloom_joiner_interop_peer", "routeloom_owner_mesh_peer"]),
        Step(["test", "-x", PEER]),
        Step(["test", "-x", MESH_PEER]),
        Step(["assert-peer-version", PEER, PEER_VERSION]),
        Step(["assert-peer-version", MESH_PEER, MESH_PEER_VERSION]),
        Step(["cargo", "test", "-p", "routeloom-host", "--bins", "site::joiner_interop",
              "--", "--nocapture"], cwd="host", env=env, forbid=SKIP_MARK,
             require=live_cases(rows, "site/joiner_interop.rs")),
        Step(["cargo", "test", "-p", "routeloom-host", "--bins", "site::owner_mesh::",
              "--", "--nocapture"], cwd="host", env=mesh_env, forbid=SKIP_MARK,
             require=live_cases(rows, "site/owner_mesh/")),
    ]


# Resource profiles besides the default `full` build
# (components/routeloom/include/routeloom/profile.hpp). Each build runs every
# portable suite except the ones pinned to a capacity or feature the profile
# leaves out; the two sanitizer-free relay builds also run the 100-node model
# (e2e-matrix M07). With 32 dedup records on every node the group 100-node
# load (burst + 2 uplinks/s) loses most uplinks, so the dedup-32 build runs
# the routing model only. Then the Owner mesh E2E mixes the
# profiles in one world: a gateway_small gateway, an endpoint member A and a
# relay member B.
USB_FEATURE_SUITES = ("usb", "host_ops")            # node status / gateway endpoint
DEDUP_96_SUITES = ("reply_admission", "fault")      # fills sized for dedup 96
GATEWAY_SUITES = USB_FEATURE_SUITES + ("espnow_owner_reapply",)  # the USB bridge itself
MODEL_100_SUITES = ("routing_scale_100_node", "group_100_node")
PROFILE_BUILDS = (
    # (build dir, profile, dedup override, sanitizers, suites left out)
    ("build-endpoint", "endpoint", "", "ON",
     GATEWAY_SUITES + DEDUP_96_SUITES + MODEL_100_SUITES + ("node_status",)),
    ("build-relay32", "relay", "leaf", "OFF",
     GATEWAY_SUITES + DEDUP_96_SUITES + ("group_100_node",)),
    ("build-relay96", "relay", "", "OFF", GATEWAY_SUITES),
    ("build-gateway-small", "gateway_small", "", "ON",
     USB_FEATURE_SUITES + DEDUP_96_SUITES + MODEL_100_SUITES),
)
# The join -> unicast -> multi-hop -> GK -> cutover rows and the role refusal.
PROFILE_MESH_TESTS = (
    "site::owner_mesh::mesh::mesh_direct_converges_and_delivers",
    "site::owner_mesh::mesh::mesh_forced_multihop_relays",
    "site::owner_mesh::join::mesh_group_key_rotate_acknowledged",
    "site::owner_mesh::cutover::mesh_cutover_prepare_commit_applied",
    "site::owner_mesh::mesh::mesh_profile_role_above_profile_refused",
)


def profile_configure(build: str) -> Step:
    _, profile, dedup, sanitizers, _ = next(b for b in PROFILE_BUILDS if b[0] == build)
    return Step(["cmake", "-S", ".", "-B", build, "-DROUTELOOM_BUILD_TESTS=ON",
                 f"-DROUTELOOM_ENABLE_SANITIZERS={sanitizers}", "-DCMAKE_BUILD_TYPE=Debug",
                 f"-DROUTELOOM_RESOURCE_PROFILE={profile}", f"-DROUTELOOM_DEDUP_PROFILE={dedup}"])


def profiles(only: str | None = None) -> list[Step]:
    steps = []
    for build, _, _, _, skip in PROFILE_BUILDS:
        if only is not None and build != only:
            continue
        steps += [
            profile_configure(build),
            Step(["cmake", "--build", build, "--parallel", JOBS]),
            Step(["ctest", "--test-dir", build, "--output-on-failure", "-j", JOBS, "-E",
                  "^routeloom_(" + "|".join(skip) + ")_tests$"]),
        ]
    if not steps:
        raise SystemExit(f"unknown profile build {only!r}")
    return steps


def profile_mesh() -> list[Step]:
    peer = "tests/cpp/routeloom_owner_mesh_peer"
    joiner_peer = "tests/cpp/routeloom_joiner_interop_peer"
    mix = {"ROUTELOOM_MESH_PEER_GW": "build-gateway-small",
           "ROUTELOOM_MESH_PEER_A": "build-endpoint", "ROUTELOOM_MESH_PEER_B": "build-relay32"}
    steps = []
    for build in mix.values():
        steps += [profile_configure(build),
                  Step(["cmake", "--build", build, "--parallel", JOBS, "--target",
                        "routeloom_owner_mesh_peer", "routeloom_joiner_interop_peer"])]
    env = {"ROUTELOOM_OWNER_PEER": str(ROOT / PEER), "ROUTELOOM_MESH_PEER": str(ROOT / MESH_PEER),
           **{key: str(ROOT / build / peer) for key, build in mix.items()},
           **{key.replace("MESH", "OWNER"): str(ROOT / build / joiner_peer)
              for key, build in mix.items()},
           "UBSAN_OPTIONS": "halt_on_error=1"}
    steps += [
        Step(["cmake", "-S", ".", "-B", "build", "-DROUTELOOM_BUILD_TESTS=ON",
              "-DROUTELOOM_ENABLE_SANITIZERS=ON", "-DCMAKE_BUILD_TYPE=Debug"]),
        Step(["cmake", "--build", "build", "--parallel", JOBS, "--target",
              "routeloom_joiner_interop_peer", "routeloom_owner_mesh_peer"]),
        Step(["cargo", "test", "-p", "routeloom-host", "--bins", "--", "--nocapture",
              *PROFILE_MESH_TESTS], cwd="host", env=env, forbid=SKIP_MARK,
             require=PROFILE_MESH_TESTS),
    ]
    return steps


def fuzz() -> list[Step]:
    # Bounded CI-time fuzzing (60 s per target over the seed corpus), not
    # continuous fuzzing.
    steps = [
        Step(["cmake", "-S", ".", "-B", "build-fuzz", "-DROUTELOOM_BUILD_TESTS=ON",
              "-DROUTELOOM_BUILD_FUZZERS=ON", "-DROUTELOOM_ENABLE_SANITIZERS=ON",
              "-DCMAKE_BUILD_TYPE=Debug"], env={"CC": "clang", "CXX": "clang++"}),
        Step(["cmake", "--build", "build-fuzz", "--parallel", JOBS, "--target",
              *(f"fuzz_{t}" for t in FUZZ_TARGETS)]),
        Step(["mkdir", "-p", "fuzz-artifacts", *(f"tests/fuzz/corpus/{t}" for t in FUZZ_TARGETS)]),
    ]
    for t in FUZZ_TARGETS:
        steps.append(Step([f"./build-fuzz/tests/fuzz/fuzz_{t}", f"tests/fuzz/corpus/{t}",
                           "-max_total_time=60", "-rss_limit_mb=2048",
                           "-artifact_prefix=fuzz-artifacts/", "-print_final_stats=1"]))
    return steps


# --- E2E scenario rows ----------------------------------------------------

def load_scenarios(path: Path = SCENARIOS) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_exists(ref: str, root: Path = ROOT) -> bool:
    """`ctest:<name>` is a registered ctest; `<file>::<fn>` a Rust #[test]."""
    if ref.startswith("ctest:"):
        cmake = (root / "tests/cpp/CMakeLists.txt").read_text(encoding="utf-8")
        return re.search(rf"add_test\(NAME {re.escape(ref[6:])}\s", cmake) is not None
    path, _, name = ref.partition("::")
    source = root / path
    if not name or not source.is_file():
        return False
    pattern = rf"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn {re.escape(name)}\("
    return re.search(pattern, source.read_text(encoding="utf-8")) is not None


def scenario_errors(data: dict, root: Path = ROOT) -> list[str]:
    """Check row references and keep the live Owner mesh tests in the table."""
    errors = []
    if data.get("schema_version") != SCENARIO_SCHEMA:
        errors.append(f"schema_version {data.get('schema_version')!r} != {SCENARIO_SCHEMA}")
    if not (root / str(data.get("supersedes"))).is_file():
        errors.append(f"supersedes {data.get('supersedes')!r} is not a file")
    if not data.get("rows"):
        errors.append("no scenario rows")
    seen = set()
    for row in data.get("rows", []):
        rid = row.get("id")
        missing = [key for key in SCENARIO_KEYS if key not in row]
        if missing:
            errors.append(f"{rid}: missing {', '.join(missing)}")
            continue
        if rid in seen:
            errors.append(f"{rid}: duplicate id")
        seen.add(rid)
        tiers = set(row["tier"])
        if not tiers or tiers - {"pr", "nightly", "hil"}:
            errors.append(f"{rid}: tier {row['tier']!r}")
        if row["status"] not in ("live", "red", "planned"):
            errors.append(f"{rid}: status {row['status']!r}")
        elif row["status"] == "planned":
            if row["test"]:
                errors.append(f"{rid}: a planned row names no test")
        elif tiers & {"pr", "nightly"}:
            if not row["test"]:
                errors.append(f"{rid}: a {row['status']} row names its tests")
            errors += [f"{rid}: no test {ref}" for ref in row["test"]
                       if not test_exists(ref, root)]
        hil = row["hil"]
        if "hil" not in tiers:
            if hil is not None:
                errors.append(f"{rid}: hil set on a row without the hil tier")
        elif not isinstance(hil, dict) or not hil.get("rounds"):
            errors.append(f"{rid}: an hil row names its rounds")
        elif hil.get("run") != "manual" and (
                not isinstance(hil.get("run"), list) or not hil["run"]
                or any(not isinstance(script, str)
                       or Path(script).parent != Path("tools/hil")
                       or Path(script).suffix != ".py"
                       or not (root / script).is_file() for script in hil["run"])):
            errors.append(f"{rid}: hil run {hil.get('run')!r} is neither manual nor HIL scripts")
    covered_prs = {pr for row in data.get("rows", []) for pr in row.get("prs", [])}
    errors += [f"{pr}: no scenario row" for pr in sorted(REQUIRED_V2_PRS - covered_prs)]
    registered = {ref for row in data.get("rows", [])
                  if row.get("status") in ("live", "red") for ref in row.get("test", [])}
    source_dir = root / "host/routeloom-host/src/site/owner_mesh"
    for source in sorted(source_dir.glob("*.rs")):
        for name in re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+(\w+)\(",
                               source.read_text(encoding="utf-8")):
            ref = f"{source.relative_to(root)}::{name}"
            if ref not in registered:
                errors.append(f"unregistered Owner mesh test {ref}")
    return errors


def live_cases(data: dict, source: str) -> list[str]:
    """The libtest paths of the live PR rows' Rust tests under
    host/routeloom-host/src/<source>."""
    prefix = "host/routeloom-host/src/"
    cases = []
    for row in data["rows"]:
        if row["status"] != "live" or "pr" not in row["tier"]:
            continue
        for ref in row["test"]:
            path, _, name = ref.partition("::")
            if not path.startswith(prefix + source):
                continue
            module = path[len(prefix):-len(".rs")].removesuffix("/mod").replace("/", "::")
            cases.append(f"{module}::{name}")
    return cases


# --- firmware cells -------------------------------------------------------

def load_cells(path: Path = CELLS) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    ids = [c["id"] for c in data["cells"]]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"{path}: duplicate cell id")
    return data


def find_cell(data: dict, cell_id: str) -> dict:
    for cell in data["cells"]:
        if cell["id"] == cell_id:
            return cell
    raise SystemExit(f"unknown cell {cell_id!r} (see check.py firmware --list)")


def cell_dir(cell: dict) -> str:
    """The ESP-IDF project of a cell: firmware/<app> unless the cell names one."""
    return cell.get("dir", f"firmware/{cell['app']}")


def firmware_steps(cell: dict, project_dir: str | Path | None = None,
                   env: dict[str, str] | None = None) -> list[Step]:
    app_dir = project_dir or cell_dir(cell)
    size_args = ["python3", str(ROOT / "tools/firmware_ram_report.py"), "build/size.json",
                 "--target", cell["target"], "--app", cell["app"], "--cell", cell["id"],
                 "--json-out", "build/ram-report.json"]
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        size_args += ["--summary", os.environ["GITHUB_STEP_SUMMARY"]]
    budget_args = ["python3", str(ROOT / "tools/check.py"), "size", "--cell", cell["id"]]
    if project_dir is not None:
        budget_args += ["--build-dir", str(Path(project_dir) / "build")]
    steps = [Step(["idf.py", "set-target", cell["target"]], cwd=app_dir, env=env)]
    if cell["overlay"]:
        steps.append(Step(["append", "sdkconfig", *cell["overlay"]], cwd=app_dir))
    steps += [
        Step(["idf.py", "build"], cwd=app_dir, env=env),
        Step(["assert-sdkconfig", cell["id"]], cwd=app_dir),
        Step(["idf.py", "size"], cwd=app_dir, env=env, stdout="build/size-report.txt"),
        Step(["idf.py", "size", "--format", "json2", "--output-file", "build/size.json"],
             cwd=app_dir, env=env),
        Step(size_args, cwd=app_dir),
        Step(budget_args),
    ]
    return steps


def run_firmware(cells: list[dict], dry_run: bool, data: dict) -> int:
    if dry_run:
        return run([step for cell in cells for step in firmware_steps(cell)], True, data)
    for cell in cells:
        if cell["app"] != "idf_consumer":
            code = run(firmware_steps(cell), False, data)
        else:
            # Build the consumer outside the checkout. Its only SDK input
            # is a Git dependency pinned to the checked-out commit.
            with tempfile.TemporaryDirectory(prefix="routeloom-consumer-") as tmp:
                project = Path(tmp) / "consumer"
                shutil.copytree(ROOT / cell_dir(cell), project,
                                ignore=shutil.ignore_patterns("build", "managed_components",
                                                              "dependencies.lock", "sdkconfig"))
                revision = subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
                manifest = project / "main/idf_component.yml"
                manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                    "__ROUTELOOM_COMPONENT_REF__", revision), encoding="utf-8")
                env = {"ROUTELOOM_COMPONENT_GIT": str(ROOT)}
                code = run(firmware_steps(cell, project, env), False, data)
                if code == 0:
                    artifacts = ROOT / cell_dir(cell)
                    shutil.copy2(project / "sdkconfig", artifacts / "sdkconfig")
                    (artifacts / "build").mkdir(exist_ok=True)
                    for pattern in ("*.bin", "*.elf", "*.map", "size-report.txt",
                                    "size.json", "ram-report.json"):
                        for output in (project / "build").glob(pattern):
                            shutil.copy2(output, artifacts / "build" / output.name)
        if code:
            return code
    return 0


def sdkconfig_errors(data: dict, cell: dict, text: str) -> list[str]:
    """Every overlay and `expect` line must appear verbatim; a watched
    symbol the cell does not name must not resolve to a forbidden value."""
    lines = set(text.splitlines())
    wanted = cell["overlay"] + cell.get("expect", [])
    errors = [f"missing `{line}`" for line in wanted if line not in lines]
    named = {line.split("=", 1)[0] for line in wanted}
    for symbol, values in data["forbid_unless_named"].items():
        if symbol in named:
            continue
        errors += [f"unexpected `{symbol}={v}`" for v in values if f"{symbol}={v}" in lines]
    return errors


def elf_symbols(path: Path) -> list[str]:
    """Names in the ELF .symtab (ELF32/ELF64, either byte order)."""
    blob = path.read_bytes()
    if blob[:4] != b"\x7fELF":
        raise ValueError(f"{path} is not an ELF file")
    wide, end = blob[4] == 2, "<" if blob[5] == 1 else ">"
    if wide:
        shoff, = struct.unpack_from(end + "Q", blob, 0x28)
        shentsize, shnum = struct.unpack_from(end + "HH", blob, 0x3A)
        sh_fmt, sym_size, name_at = end + "IIQQQQIIQQ", 24, 0
    else:
        shoff, = struct.unpack_from(end + "I", blob, 0x20)
        shentsize, shnum = struct.unpack_from(end + "HH", blob, 0x2E)
        sh_fmt, sym_size, name_at = end + "IIIIIIIIII", 16, 0
    sections = [struct.unpack_from(sh_fmt, blob, shoff + i * shentsize) for i in range(shnum)]
    names = []
    found_symtab = False
    for sec in sections:
        if sec[1] != 2:  # SHT_SYMTAB
            continue
        found_symtab = True
        offset, size, link = sec[4], sec[5], sec[6]
        str_off = sections[link][4]
        for pos in range(offset, offset + size, sym_size):
            start = str_off + struct.unpack_from(end + "I", blob, pos + name_at)[0]
            names.append(blob[start:blob.index(b"\0", start)].decode("utf-8", "replace"))
    if not found_symtab:
        raise ValueError(f"{path}: missing ELF symbol table")
    return [n for n in names if n]


# Budgets are ratcheted to CI measurements, but the same source builds a few
# dozen bytes apart between toolchain hosts and path layouts. Drift within these
# margins passes; anything larger must update the budget with a reason. The hard
# static-RAM floor is still enforced by tools/firmware_ram_report.py.
APP_BIN_DRIFT = 2048
STATIC_FREE_DRIFT = 256
RTC_DRIFT = 64


def size_errors(data: dict, cell: dict, build: Path) -> list[str]:
    budget = cell.get("budget")
    if not budget:
        return ["no budget in tools/ci/cells.json"]
    stem = f"routeloom_{cell['app']}"
    files = {kind: build / name for kind, name in (
        ("bin", f"{stem}.bin"), ("elf", f"{stem}.elf"), ("map", f"{stem}.map"),
        ("ram", "ram-report.json"))}
    missing = [str(p) for p in files.values() if not p.is_file()]
    if missing:
        return [f"missing {p}" for p in missing]
    errors = []
    app_bin = files["bin"].stat().st_size
    if app_bin > budget["app_bin_max"] + APP_BIN_DRIFT:
        errors.append(f"app.bin {app_bin} B > budget {budget['app_bin_max']} B "
                      f"(+{APP_BIN_DRIFT} B drift)")
    report = json.loads(files["ram"].read_text(encoding="utf-8"))
    for key, expected in (("cell", cell["id"]), ("app", cell["app"]),
                          ("target", cell["target"])):
        if report.get(key) != expected:
            errors.append(f"ram-report {key} {report.get(key)!r} != {expected!r}")
    free = report["guard"]["free"]
    if free < budget["static_free_min"] - STATIC_FREE_DRIFT:
        errors.append(f"static RAM free {free} B < budget {budget['static_free_min']} B "
                      f"(-{STATIC_FREE_DRIFT} B drift)")
    rtc = rtc_used(report)
    if rtc is None:
        errors.append("missing RTC/LP RAM measurement in ram-report")
    elif rtc > budget["rtc_used_max"] + RTC_DRIFT:
        errors.append(f"RTC/LP RAM used {rtc} B > budget {budget['rtc_used_max']} B "
                      f"(+{RTC_DRIFT} B drift)")
    patterns = data.get("symbols_absent", []) + cell.get("symbols_absent", [])
    if patterns:
        try:
            symbols = elf_symbols(files["elf"])
        except ValueError as exc:
            errors.append(str(exc))
        else:
            for pattern in patterns:
                hits = [s for s in symbols if re.search(pattern, s)]
                if hits:
                    errors.append(f"symbols_absent `{pattern}` matches {', '.join(hits[:5])}")
    print(f"{cell['id']}: app.bin {app_bin}/{budget['app_bin_max']} B, static free "
          f"{free}/{budget['static_free_min']} B, RTC {rtc}/{budget['rtc_used_max']} B")
    return errors


def rtc_used(report: dict) -> int | None:
    low_power = [m for m in report["memory"]
                 if m["name"].lower().startswith(("rtc", "lp "))]
    return sum(m["used"] for m in low_power) if low_power else None


# --- runner ---------------------------------------------------------------

def run(steps: list[Step], dry_run: bool, data: dict | None = None) -> int:
    for step in steps:
        print(f"$ {step.text()}", flush=True)
        if dry_run:
            continue
        cwd = ROOT / step.cwd
        if step.argv[0] == "append":
            with (cwd / step.argv[1]).open("a", encoding="utf-8") as out:
                out.write("".join(line + "\n" for line in step.argv[2:]))
            continue
        if step.argv[0] == "assert-sdkconfig":
            errors = sdkconfig_errors(data, find_cell(data, step.argv[1]),
                                      (cwd / "sdkconfig").read_text(encoding="utf-8"))
            if errors:
                print(f"{step.argv[1]}: sdkconfig: " + "; ".join(errors), file=sys.stderr)
                return 1
            continue
        if step.argv[0] == "assert-peer-version":
            try:
                result = subprocess.run([str(ROOT / step.argv[1]), "--harness-version"],
                                        capture_output=True, text=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                result = None
            if result is None or result.returncode != 0 or result.stdout != step.argv[2] + "\n":
                print(f"check.py: peer RPC version mismatch: {step.argv[1]}", file=sys.stderr)
                return 1
            continue
        env = {**os.environ, **step.env}
        if step.stdout:
            with (cwd / step.stdout).open("w", encoding="utf-8") as out:
                code = subprocess.run(step.argv, cwd=cwd, env=env, stdout=out).returncode
        elif step.forbid is None and step.require is None:
            code = subprocess.run(step.argv, cwd=cwd, env=env).returncode
        else:
            code, hit, passed = stream(step, cwd, env)
            if hit:
                print(f"check.py: forbidden output from `{step.text()}`: {hit}", file=sys.stderr)
                code = code or 1
            if step.require is not None:
                absent = [case for case in step.require if case not in passed]
                if absent or not passed:
                    print(f"check.py: require_live: {len(passed)} passed, not passed: "
                          f"{', '.join(absent) or '(no case ran)'}", file=sys.stderr)
                    code = code or 1
        if code != 0:
            print(f"check.py: FAILED ({code}): {step.text()}", file=sys.stderr)
            return code
    return 0


def stream(step: Step, cwd: Path, env: dict) -> tuple[int, str, set[str]]:
    hit, passed = "", set()
    with subprocess.Popen(step.argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as proc:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            if not hit and step.forbid is not None and step.forbid.search(line):
                hit = line.strip()
            passed.update(PASSED.findall(line))
    return proc.returncode, hit, passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="stage", required=True)
    for name in ("quick", "ci", "docs", "golden", "rust", "interop", "profile-mesh", "fuzz"):
        sub.add_parser(name).add_argument("--dry-run", action="store_true")
    p_profiles = sub.add_parser("profiles")
    p_profiles.add_argument("--dry-run", action="store_true")
    p_profiles.add_argument("--build", choices=[b[0] for b in PROFILE_BUILDS],
                            help="one profile build (default: all)")
    p_scen = sub.add_parser("scenarios")
    p_scen.add_argument("--file", type=Path, default=SCENARIOS, help=argparse.SUPPRESS)
    p_core = sub.add_parser("core")
    p_core.add_argument("--dry-run", action="store_true")
    p_core.add_argument("--sanitizers", choices=("ON", "OFF"), default="ON")
    p_fw = sub.add_parser("firmware")
    p_fw.add_argument("--dry-run", action="store_true")
    group = p_fw.add_mutually_exclusive_group(required=True)
    group.add_argument("--cell", action="append")
    group.add_argument("--all", action="store_true")
    group.add_argument("--list", action="store_true")
    p_fw.add_argument("--format", choices=("text", "github"), default="text")
    p_size = sub.add_parser("size")
    p_size.add_argument("--cell", required=True)
    p_size.add_argument("--build-dir", type=Path,
                        help="default firmware/<app>/build of the cell")
    p_size.add_argument("--cells-file", type=Path, default=CELLS, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.stage == "size":
        data = load_cells(args.cells_file)
        cell = find_cell(data, args.cell)
        build = args.build_dir or ROOT / cell_dir(cell) / "build"
        errors = size_errors(data, cell, build)
        for error in errors:
            print(f"{cell['id']}: {error}", file=sys.stderr)
        return 1 if errors else 0

    if args.stage == "scenarios":
        errors = scenario_errors(load_scenarios(args.file))
        for error in errors:
            print(f"{args.file.name}: {error}", file=sys.stderr)
        return 1 if errors else 0

    data = load_cells()
    if args.stage == "firmware":
        if args.list:
            if args.format == "github":
                include = [{"id": c["id"], "app": c["app"], "dir": cell_dir(c),
                            "target": c["target"],
                            "artifact": c.get("artifact", f"firmware-{c['id']}")}
                           for c in data["cells"]]
                print("matrix=" + json.dumps({"include": include}, separators=(",", ":")))
            else:
                print("\n".join(c["id"] for c in data["cells"]))
            return 0
        cells = data["cells"] if args.all else [find_cell(data, i) for i in args.cell]
        return run_firmware(cells, args.dry_run, data)

    stages = {"core": lambda: core(getattr(args, "sanitizers", "ON")), "docs": docs,
              "golden": golden, "rust": rust, "interop": interop,
              "profiles": lambda: profiles(getattr(args, "build", None)),
              "profile-mesh": profile_mesh, "fuzz": fuzz,
              "firmware": lambda: [s for c in data["cells"] for s in firmware_steps(c)]}
    order = {"quick": ("docs", "core"),
             "ci": ("docs", "core", "golden", "rust", "interop", "profiles", "profile-mesh",
                    "fuzz", "firmware")}
    for name in order.get(args.stage, (args.stage,)):
        print(f"=== {name}", flush=True)
        code = (run_firmware(data["cells"], args.dry_run, data) if name == "firmware"
                else run(stages[name](), args.dry_run, data))
        if code:
            return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
