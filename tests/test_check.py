"""tools/check.py: the cell list, the sdkconfig assertions and the budgets."""
from pathlib import Path
import importlib.util
import io
import json
import os
import subprocess
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "sdk.yml"


def run_main(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = check.main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


def elf32(symbols):
    """Minimal little-endian ELF32 with a .symtab/.strtab pair."""
    strtab = b"\0" + b"".join(s.encode() + b"\0" for s in symbols)
    offsets, pos = [], 1
    for s in symbols:
        offsets.append(pos)
        pos += len(s) + 1
    symtab = bytes(16) + b"".join(struct.pack("<IIIBBH", o, 0, 0, 0, 0, 1) for o in offsets)
    str_off = 52
    sym_off = str_off + len(strtab)
    shoff = sym_off + len(symtab)
    header = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9) + struct.pack(
        "<HHIIIIIHHHHHH", 2, 0xF3, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 3, 0)
    sections = bytes(40)
    sections += struct.pack("<IIIIIIIIII", 0, 2, 0, 0, sym_off, len(symtab), 2, 0, 4, 16)
    sections += struct.pack("<IIIIIIIIII", 0, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)
    return header + strtab + symtab + sections


class CellList(unittest.TestCase):
    def test_check_parallelism_is_bounded(self):
        build = check.core()[1]
        self.assertLessEqual(int(build.argv[-1]), 8)

    def test_cells_cover_every_app_and_target_with_a_budget(self):
        data = check.load_cells()
        cells = data["cells"]
        # 37 cells of the pre-v2 matrix, the 5 C6 cells made required, bench C6,
        # the C3 gateway-128 and endpoint cells, and two release (-Os) comparisons.
        self.assertEqual(len(cells), 47)
        for cell in cells:
            self.assertTrue((ROOT / "firmware" / cell["app"]).is_dir(), cell["id"])
            if cell["id"].startswith("experimental-c6-"):
                self.assertEqual(cell["target"], "esp32c6")
            else:
                self.assertTrue(cell["id"].startswith(f"{cell['app']}-{cell['target']}-"),
                                cell["id"])
            self.assertEqual(set(cell["budget"]), {"app_bin_max", "static_free_min",
                                                   "rtc_used_max"}, cell["id"])
        pairs = {(c["app"], c["target"]) for c in cells}
        for app in ("reference_node", "bridge_node", "bench_node"):
            for target in ("esp32c3", "esp32s3", "esp32c5", "esp32c6"):
                self.assertIn((app, target), pairs)

    def test_workflow_matrix_comes_from_the_list(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("python3 tools/check.py firmware --list --format github", workflow)
        self.assertIn("fromJSON(needs.firmware-cells.outputs.matrix)", workflow)
        self.assertIn('python3 tools/check.py firmware --cell "${{ matrix.id }}"', workflow)
        self.assertIn("name: ${{ matrix.artifact }}", workflow)
        self.assertNotIn("c6-experimental", workflow)
        code, out, _ = run_main(["firmware", "--list", "--format", "github"])
        self.assertEqual(code, 0)
        include = json.loads(out.removeprefix("matrix="))["include"]
        self.assertEqual([c["id"] for c in include],
                         [c["id"] for c in check.load_cells()["cells"]])

    def test_existing_c6_artifact_names_are_preserved(self):
        ids = {cell["id"] for cell in check.load_cells()["cells"]}
        old_c6 = {
            "experimental-c6-bridge_node-devram",
            "experimental-c6-reference_node-devram",
            "experimental-c6-bridge_node-member",
            "experimental-c6-reference_node-member",
            "experimental-c6-reference_node-member_sleep",
        }
        self.assertTrue(old_c6 <= ids)
        code, out, _ = run_main(["firmware", "--list", "--format", "github"])
        self.assertEqual(code, 0)
        include = json.loads(out.removeprefix("matrix="))["include"]
        for cell in include:
            expected = cell["id"] if cell["id"] in old_c6 else f"firmware-{cell['id']}"
            self.assertEqual(cell["artifact"], expected)

    def test_workflow_runs_every_ci_stage(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for stage in ("core --sanitizers", "docs", "golden", "rust", "interop",
                      "profiles --build", "profile-mesh", "fuzz"):
            self.assertIn(f"python3 tools/check.py {stage}", workflow)

    def test_ci_requires_e2e_report_artifact(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        artifact = workflow.split("name: e2e-report", 1)[1].split("retention-days:", 1)[0]
        self.assertIn("if-no-files-found: error", artifact)

    def test_ci_dry_run_lists_every_stage_and_cell(self):
        code, out, _ = run_main(["ci", "--dry-run"])
        self.assertEqual(code, 0)
        for stage in ("docs", "core", "golden", "rust", "interop", "profiles", "profile-mesh",
                      "fuzz", "firmware"):
            self.assertIn(f"=== {stage}\n", out)
        for cell in check.load_cells()["cells"]:
            self.assertIn(f"check.py size --cell {cell['id']}\n", out)

    def test_ci_rust_toolchain_setup_uses_the_manifest(self):
        for name in ("sdk.yml", "host-os-matrix.yml", "release.yml"):
            lines = (ROOT / ".github" / "workflows" / name).read_text().splitlines()
            for i, line in enumerate(lines):
                if "- name: Rust toolchain (host/rust-toolchain.toml)" not in line:
                    continue
                command = next(row.strip().removeprefix("run: ") for row in lines[i + 1:i + 4]
                               if row.strip().startswith("run: "))
                self.assertEqual(command, "cargo --version", name)


class Sdkconfig(unittest.TestCase):
    DATA = {"forbid_unless_named": {"CONFIG_A": ["y"], "CONFIG_M": ["1", "2"]}}

    def test_overlay_expect_and_forbidden_values(self):
        cell = {"overlay": ["CONFIG_A=y"], "expect": ["CONFIG_P=5000"]}
        self.assertEqual(check.sdkconfig_errors(self.DATA, cell, "CONFIG_A=y\nCONFIG_P=5000\n"), [])
        self.assertEqual(check.sdkconfig_errors(self.DATA, cell, "CONFIG_P=5000\nCONFIG_M=2\n"),
                         ["missing `CONFIG_A=y`", "unexpected `CONFIG_M=2`"])


class HilMatrix(unittest.TestCase):
    def test_result_points_to_the_packaged_ram_report(self):
        spec = importlib.util.spec_from_file_location(
            "build_ci_matrix", ROOT / "tools" / "hil" / "build_ci_matrix.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cell = ("bench_node", "esp32c6", "bench_node-esp32c6-normal-off-off", [])
        label = "full-r9-ci-00-bench_node-esp32c6-normal-off-off"
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "artifacts" / "hil" / "images" / label
            bundle.mkdir(parents=True)
            (bundle / "ram-report.json").write_text("{}")
            completed = subprocess.CompletedProcess([], 0, "ok", "")
            with mock.patch.object(module, "ROOT", Path(tmp)), \
                 mock.patch.object(module, "BUILD", Path(tmp) / "builder"), \
                 mock.patch.object(module.fcntl, "flock"), \
                 mock.patch.object(module.subprocess, "run", return_value=completed):
                row = module.build(0, cell, "full-r9-ci")
            self.assertEqual(row["ram_report"],
                             f"artifacts/hil/images/{label}/ram-report.json")
            self.assertIsNone(row["build_log"])

    def test_builder_reaches_idf_for_bench_and_paired_cells(self):
        script = ROOT / "tools" / "meshviz" / "build_bundle.sh"
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            docker = work / "docker"
            docker.write_text("#!/bin/sh\nexit 7\n")
            docker.chmod(0o755)
            python = work / "python3"
            python.write_text(f"#!/bin/sh\nif [ \"$1\" = -c ]; then echo test-image; "
                              f"else exec {sys.executable} \"$@\"; fi\n")
            python.chmod(0o755)
            env = {**os.environ, "PATH": f"{work}:{os.environ['PATH']}"}
            cases = (("bench_node", "esp32c6", []),
                     ("reference_node", "esp32c3",
                      ['CONFIG_ROUTELOOM_PEER_MAC="94:a9:90:6a:ee:c4"']))
            for app, target, overlay in cases:
                with self.subTest(app=app, target=target):
                    result = subprocess.run([str(script), app, target, str(work / "bundle"),
                                             str(work / "key"), "test", *overlay], env=env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 7, result.stderr)


class Budget(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        cells = [{"id": f"bench_node-esp32c3-{name}", "app": "bench_node", "target": "esp32c3",
                  "overlay": [],
                  "budget": {"app_bin_max": 1000, "static_free_min": 500, "rtc_used_max": 40}}
                 for name in ("a", "b")]
        self.cells = self.dir / "cells.json"
        self.cells.write_text(json.dumps({"forbid_unless_named": {}, "symbols_absent": [],
                                          "cells": cells}))
        for name in ("a", "b"):
            self.build(name, app_bin=1000, free=500, rtc=40)

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, name, app_bin, free, rtc, symbols=("app_main",)):
        build = self.dir / name
        build.mkdir(exist_ok=True)
        (build / "routeloom_bench_node.bin").write_bytes(bytes(app_bin))
        (build / "routeloom_bench_node.elf").write_bytes(elf32(list(symbols)))
        (build / "routeloom_bench_node.map").write_text("link map\n")
        (build / "ram-report.json").write_text(json.dumps({
            "cell": f"bench_node-esp32c3-{name}", "app": "bench_node", "target": "esp32c3",
            "guard": {"free": free},
            "memory": [{"name": "DRAM", "used": 1}, {"name": "RTC SLOW", "used": rtc}]}))

    def size(self, name):
        return run_main(["size", "--cells-file", self.cells, "--cell",
                         f"bench_node-esp32c3-{name}", "--build-dir", self.dir / name])

    def test_drift_within_margin_passes(self):
        self.build("a", app_bin=1000 + check.APP_BIN_DRIFT, free=500 - check.STATIC_FREE_DRIFT,
                   rtc=40 + check.RTC_DRIFT)
        self.assertEqual(self.size("a")[0], 0)

    def test_one_byte_over_the_margin_fails_only_that_cell(self):
        self.assertEqual(self.size("a")[0], 0)
        for over in ({"app_bin": 1001 + check.APP_BIN_DRIFT, "free": 500, "rtc": 40},
                     {"app_bin": 1000, "free": 499 - check.STATIC_FREE_DRIFT, "rtc": 40},
                     {"app_bin": 1000, "free": 500, "rtc": 41 + check.RTC_DRIFT}):
            self.build("a", **over)
            code, _, err = self.size("a")
            self.assertEqual(code, 1, over)
            self.assertIn("budget", err)
            self.assertEqual(self.size("b")[0], 0)

    def test_missing_output_fails(self):
        (self.dir / "a" / "routeloom_bench_node.map").unlink()
        code, _, err = self.size("a")
        self.assertEqual(code, 1)
        self.assertIn("missing", err)

    def test_report_must_belong_to_the_cell(self):
        report = self.dir / "a" / "ram-report.json"
        data = json.loads(report.read_text())
        data["cell"] = "bench_node-esp32c3-b"
        report.write_text(json.dumps(data))
        code, _, err = self.size("a")
        self.assertEqual(code, 1)
        self.assertIn("cell", err)

    def test_missing_rtc_measurement_fails(self):
        report = self.dir / "a" / "ram-report.json"
        data = json.loads(report.read_text())
        data["memory"] = [m for m in data["memory"] if m["name"] == "DRAM"]
        report.write_text(json.dumps(data))
        code, _, err = self.size("a")
        self.assertEqual(code, 1)
        self.assertIn("RTC/LP", err)

    def test_symbols_absent(self):
        data = json.loads(self.cells.read_text())
        data["symbols_absent"] = [r"^legacy_psk_"]
        self.cells.write_text(json.dumps(data))
        self.assertEqual(self.size("a")[0], 0)
        self.build("a", app_bin=1000, free=500, rtc=40, symbols=("app_main", "legacy_psk_load"))
        code, _, err = self.size("a")
        self.assertEqual(code, 1)
        self.assertIn("legacy_psk_load", err)

    def test_symbols_absent_requires_a_symbol_table(self):
        data = json.loads(self.cells.read_text())
        data["symbols_absent"] = [r"^legacy_psk_"]
        self.cells.write_text(json.dumps(data))
        path = self.dir / "a" / "routeloom_bench_node.elf"
        blob = bytearray(path.read_bytes())
        section_offset = struct.unpack_from("<I", blob, 0x20)[0]
        struct.pack_into("<I", blob, section_offset + 40 + 4, 1)
        path.write_bytes(blob)
        code, _, err = self.size("a")
        self.assertEqual(code, 1)
        self.assertIn("symbol table", err)


if __name__ == "__main__":
    unittest.main()


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.data = check.load_scenarios()

    def rows(self, rid):
        return [row for row in self.data["rows"] if row["id"] == rid]

    def test_repository_rows_pass(self):
        self.assertEqual(check.scenario_errors(self.data), [])
        code, _, err = run_main(["scenarios"])
        self.assertEqual((code, err), (0, ""))

    def test_duplicate_id_and_missing_test_fail(self):
        row = dict(self.rows("M01")[0])
        self.data["rows"].append(row)
        self.rows("M03")[0]["test"] = self.rows("M03")[0]["test"] + [
            "host/routeloom-host/src/site/owner_mesh/mesh.rs::mesh_no_such_test"]
        self.rows("M07")[0]["test"] = ["ctest:routeloom_no_such_tests"]
        errors = check.scenario_errors(self.data)
        self.assertIn("M01: duplicate id", errors)
        self.assertIn("M03: no test host/routeloom-host/src/site/owner_mesh/mesh.rs::"
                      "mesh_no_such_test", errors)
        self.assertIn("M07: no test ctest:routeloom_no_such_tests", errors)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scenarios.json"
            path.write_text(json.dumps(self.data), encoding="utf-8")
            code, _, err = run_main(["scenarios", "--file", path])
        self.assertEqual(code, 1)
        self.assertIn("M01: duplicate id", err)

    def test_empty_scenario_table_fails(self):
        self.data["rows"] = []
        self.assertIn("no scenario rows", check.scenario_errors(self.data))

    def test_planned_and_hil_rows(self):
        self.rows("M02")[0]["test"] = self.rows("M01")[0]["test"]
        self.rows("M05")[0]["hil"]["run"] = ["tools/hil/no_such_script.py"]
        self.rows("M03")[0]["hil"] = {"rounds": ["H0"], "run": "manual"}
        errors = check.scenario_errors(self.data)
        self.assertIn("M02: a planned row names no test", errors)
        self.assertIn("M05: hil run ['tools/hil/no_such_script.py'] is neither manual nor "
                      "HIL scripts", errors)
        self.assertIn("M03: hil set on a row without the hil tier", errors)

    def test_hil_run_must_be_a_hil_script(self):
        self.rows("M05")[0]["hil"]["run"] = ["tools/check.py"]
        self.assertTrue(any("M05: hil run" in error
                            for error in check.scenario_errors(self.data)))

    def test_interop_requires_every_live_pr_case(self):
        steps = [s for s in check.interop() if s.require is not None]
        self.assertEqual(len(steps), 2)
        self.assertIn("site::joiner_interop::live_owner_removal_notice_erase_holdoff",
                      steps[0].require)
        self.assertIn("site::owner_mesh::mesh::mesh_direct_converges_and_delivers",
                      steps[1].require)
        # The red three-hop row is ignored by the suite, not required.
        self.assertNotIn("site::owner_mesh::mesh::mesh_line_three_hops_delivers",
                         steps[1].require)

    def test_profile_mesh_requires_every_mixed_case(self):
        step = check.profile_mesh()[-1]
        self.assertEqual(set(step.require or ()), {
            "site::owner_mesh::mesh::mesh_direct_converges_and_delivers",
            "site::owner_mesh::mesh::mesh_forced_multihop_relays",
            "site::owner_mesh::join::mesh_group_key_rotate_acknowledged",
            "site::owner_mesh::cutover::mesh_cutover_prepare_commit_applied",
            "site::owner_mesh::mesh::mesh_profile_role_above_profile_refused",
        })

    def test_interop_rejects_incompatible_peer_protocol(self):
        checks = [step.argv for step in check.interop()
                  if step.argv[0] == "assert-peer-version"]
        self.assertEqual(checks, [["assert-peer-version", check.PEER],
                                  ["assert-peer-version", check.MESH_PEER]])
        with tempfile.TemporaryDirectory() as tmp:
            peer = Path(tmp) / "peer"
            for version, expected in (("0", 1), ("1", 0)):
                peer.write_text(f"#!/bin/sh\nprintf '{version}\\n'\n")
                peer.chmod(0o700)
                step = check.Step(["assert-peer-version", str(peer)])
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(check.run([step], dry_run=False), expected)

    def test_require_live_fails_on_a_missing_or_empty_run(self):
        script = "print('test site::a ... ok'); print('test site::b ... FAILED')"
        for require, expect in ((["site::a"], 0), (["site::a", "site::b"], 1), ([], 0)):
            step = check.Step([sys.executable, "-c", script], require=require)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(check.run([step], dry_run=False), expect, require)
        empty = check.Step([sys.executable, "-c", "print('running 0 tests')"], require=[])
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(check.run([empty], dry_run=False), 1)
        self.assertIn("(no case ran)", err.getvalue())
