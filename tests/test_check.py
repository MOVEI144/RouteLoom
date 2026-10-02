"""tools/check.py: the cell list, the sdkconfig assertions and the budgets."""
from pathlib import Path
import importlib.util
import io
import json
import os
import re
import shutil
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
    def test_distribution_defaults_and_quick_start_modes(self):
        dev = "CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y"
        member = "CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y"
        for app in ("bridge_node", "reference_node"):
            self.assertIn(member, (ROOT / "firmware" / app / "sdkconfig.defaults").read_text())
        for cell in check.load_cells()["cells"]:
            settings = cell["overlay"] + cell.get("expect", [])
            if cell["app"] in ("bridge_node", "reference_node") and not cell["overlay"]:
                self.assertIn(member, settings, cell["id"])
            if "devram" in cell["id"] or "app_object" in cell["id"] or cell["app"] in (
                    "endpoint_cpp", "endpoint_c", "standalone_gateway", "idf_consumer"):
                self.assertIn(dev, settings, cell["id"])
                if cell["app"] in ("bridge_node", "reference_node"):
                    self.assertIn(dev, cell["overlay"], cell["id"])

    def test_check_parallelism_is_bounded(self):
        build = check.core()[1]
        self.assertLessEqual(int(build.argv[-1]), 8)

    def test_c6_antenna_variants_cover_measured_image_size(self):
        # Both antenna paths link the GPIO driver and must fit its measured footprint.
        cells = {cell["id"]: cell for cell in check.load_cells()["cells"]}
        for name in ("experimental-c6-reference_node-devram",
                     "reference_node-esp32c6-normal-off-external_antenna"):
            with self.subTest(cell=name):
                self.assertGreaterEqual(cells[name]["budget"]["app_bin_max"]
                                        + check.APP_BIN_DRIFT, 1246032)

    def test_cells_cover_every_app_and_target_with_a_budget(self):
        data = check.load_cells()
        cells = data["cells"]
        # Every app/target and feature branch, including C6 external antenna selection.
        self.assertEqual(len(cells), 65)
        self.assertTrue({
            "bridge_node-esp32c5-normal-off-app_object-small",
            "bridge_node-esp32c3-normal-off-maintenance_member",
            "reference_node-esp32c6-normal-off-maintenance_member",
            "bridge_node-esp32c6-normal-off-maintenance_member",
            "reference_node-esp32c6-normal-off-external_antenna",
        } <= {cell["id"] for cell in cells})
        for cell in cells:
            self.assertTrue((ROOT / check.cell_dir(cell)).is_dir(), cell["id"])
            if cell["id"].startswith("experimental-c6-"):
                self.assertEqual(cell["target"], "esp32c6")
            else:
                self.assertTrue(cell["id"].startswith(f"{cell['app']}-{cell['target']}-"),
                                cell["id"])
            self.assertEqual(set(cell["budget"]), {"app_bin_max", "static_free_min",
                                                   "rtc_used_max"}, cell["id"])
        pairs = {(c["app"], c["target"]) for c in cells}
        for app in ("reference_node", "bridge_node", "bench_node", "idf_consumer"):
            for target in ("esp32c3", "esp32s3", "esp32c5", "esp32c6"):
                self.assertIn((app, target), pairs)

    def test_consumer_dependencies_survive_isolation_from_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "consumer"
            shutil.copytree(ROOT / "tests/idf_consumer", project)
            defaults = (project / "sdkconfig.defaults").read_text()
            table = re.search(r'^CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="([^"]+)"$',
                              defaults, re.M)
            self.assertIsNotNone(table)
            self.assertTrue((project / table.group(1)).is_file())
            manifest = (project / "main/idf_component.yml").read_text()
            self.assertNotIn("override_path:", manifest)
            self.assertRegex(manifest, r"routeloom/routeloom_device:\n\s+git:")

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
        # Artifacts come from each cell's own project directory.
        self.assertIn("${{ matrix.dir }}/build/*.bin", workflow)
        dirs = {c["id"]: c["dir"] for c in include}
        self.assertEqual(dirs["endpoint_cpp-esp32c3-example"], "examples/endpoint_cpp")
        self.assertEqual(dirs["bridge_node-esp32c3-normal-off-off"], "firmware/bridge_node")

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

    def test_ci_builds_enabled_weak_link_images_for_c3_and_c6(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('- name: Build HIL weak-link image', workflow)
        step = workflow.split('- name: Build HIL weak-link image', 1)[1].split(
            '- uses:', 1)[0]
        for cell in ('bridge_node-esp32c3-normal-off-off',
                     'experimental-c6-bridge_node-member'):
            self.assertIn(cell, step)
        for setting in ('CONFIG_ROUTELOOM_TX_POWER_QDBM=8',
                        'CONFIG_ROUTELOOM_HIL_RX_MIN_RSSI=-80',
                        'CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE=100'):
            self.assertIn(setting, step)
        self.assertIn('idf.py -B build-hil -D SDKCONFIG=sdkconfig.hil reconfigure', step)
        self.assertIn('cmake --build build-hil -j4', step)
        self.assertIn('firmware_ram_report.py', step)

    def test_workflow_runs_every_ci_stage(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for stage in ("core --sanitizers", "docs", "golden", "rust",
                      "profiles --build", "profile-mesh", "object-mesh", "fuzz"):
            self.assertIn(f"python3 tools/check.py {stage}", workflow)

    def test_ci_requires_e2e_report_artifact(self):
        artifact = (ROOT / ".github/workflows/e2e.yml").read_text().split("name: e2e-${{ matrix.shard }}", 1)[1].split("retention-days:", 1)[0]
        self.assertIn("if-no-files-found: error", artifact)

    def test_ci_dry_run_lists_every_stage_and_cell(self):
        code, out, _ = run_main(["ci", "--dry-run"])
        self.assertEqual(code, 0)
        for stage in ("docs", "core", "golden", "rust", "interop", "profiles", "profile-mesh", "object-mesh",
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

    def test_project_rejects_retired_mode_before_idf_rewrites_sdkconfig(self):
        guard = ROOT / "components/routeloom_device/retired_mode_guard.cmake"
        for project in ("firmware/reference_node", "firmware/bridge_node",
                        "firmware/bench_node", "examples/endpoint_cpp", "examples/endpoint_c",
                        "examples/standalone_gateway"):
            lines = (ROOT / project / "CMakeLists.txt").read_text(encoding="utf-8")
            self.assertLess(lines.index("retired_mode_guard.cmake"),
                            lines.index("project.cmake"), project)
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "sdkconfig"
            token = "CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY" + "_FIXTURE=y\n"
            config.write_text(token, encoding="utf-8")
            args = ["cmake", f"-DSDKCONFIG={config}", "-P", str(guard)]
            rejected = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("retired RouteLoom security mode", rejected.stderr)
            config.write_text("CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y\n", encoding="utf-8")
            accepted = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            defaults = Path(tmp) / "sdkconfig.defaults"
            defaults.write_text(token, encoding="utf-8")
            rejected_defaults = subprocess.run(args, cwd=tmp, capture_output=True, text=True)
            self.assertNotEqual(rejected_defaults.returncode, 0)

    def test_cell_refuses_retired_selection_before_compiling(self):
        cell = {"id": "test", "app": "reference_node", "target": "esp32c3", "overlay": []}
        steps = [step.argv for step in check.firmware_steps(cell)]
        self.assertLess(steps.index(["assert-security-mode", "test"]),
                        steps.index(["idf.py", "build"]))
        switching = ("CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y\n"
                     "CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y\n")
        self.assertEqual(check.security_mode_errors(switching), [])

    def test_overlay_expect_and_forbidden_values(self):
        cell = {"overlay": ["CONFIG_A=y"], "expect": ["CONFIG_P=5000"]}
        self.assertEqual(check.sdkconfig_errors(self.DATA, cell, "CONFIG_A=y\nCONFIG_P=5000\n"), [])
        self.assertEqual(check.sdkconfig_errors(self.DATA, cell, "CONFIG_P=5000\nCONFIG_M=2\n"),
                         ["missing `CONFIG_A=y`", "unexpected `CONFIG_M=2`"])

    def test_retired_security_mode_is_refused(self):
        old = "CONFIG_ROUTELOOM_SECURITY_MODE_" + "LEGACY" + "_FIXTURE=y"
        cell = {"overlay": [], "expect": []}
        self.assertTrue(check.sdkconfig_errors(self.DATA, cell, old + "\n"))

    def test_c3_config_requires_endpoint_role_as_well_as_capacity(self):
        cell = {"target": "esp32c3", "overlay": [], "expect": []}
        common = "CONFIG_ROUTELOOM_CONFIG=y\nCONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y\n"
        self.assertEqual(check.sdkconfig_errors(
            self.DATA, cell, common + "CONFIG_ROUTELOOM_ROLE_ENDPOINT=y\n"), [])
        self.assertTrue(check.sdkconfig_errors(
            self.DATA, cell, common + "CONFIG_ROUTELOOM_ROLE_RELAY=y\n"))

    def test_channel_plan_is_member_only(self):
        cell = {"overlay": [], "expect": []}
        data = {"forbid_unless_named": {}}
        member = "CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y\nCONFIG_ROUTELOOM_MIGRATION=2\n"
        self.assertEqual(check.sdkconfig_errors(data, cell, member), [])
        for mode in ("1", "2"):
            devram = f"CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y\nCONFIG_ROUTELOOM_MIGRATION={mode}\n"
            self.assertTrue(check.sdkconfig_errors(data, cell, devram))
        self.assertEqual(check.sdkconfig_errors(
            data, cell, "CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y\nCONFIG_ROUTELOOM_MIGRATION=0\n"), [])

    def test_device_cmake_refuses_devram_channel_plan(self):
        text = (ROOT / "components/routeloom_device/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("CONFIG_ROUTELOOM_MIGRATION", text)
        self.assertIn("NOT CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC", text)


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
                      ['CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:6a:ee:c4"']),
                     ("bridge_node", "esp32c3", ['CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS=""']),
                     ("reference_node", "esp32s3",
                      ['CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS="AA:bb:cc:dd:ee:ff,11:22:33:44:55:66"']))
            for app, target, overlay in cases:
                with self.subTest(app=app, target=target):
                    result = subprocess.run([str(script), app, target, str(work / "bundle"),
                                             str(work / "key"), "test", *overlay], env=env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 7, result.stderr)

    def test_builder_rejects_invalid_allow_lists_before_docker(self):
        script = ROOT / "tools" / "meshviz" / "build_bundle.sh"
        for value in ("aa:bb:cc:dd:ee:ff,", "aa:bb:cc:dd:ee:fz",
                      ",".join(["aa:bb:cc:dd:ee:ff"] * 9),
                      "aa:bb:cc:dd:ee:ff\nCONFIG_SECURE_BOOT=y"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                result = subprocess.run([str(script), "bridge_node", "esp32c3", tmp + "/out",
                                         tmp + "/key", "test",
                                         f'CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS="{value}"'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("unsupported or unsafe", result.stderr)


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

    def test_member_image_refuses_development_key(self):
        data = json.loads(self.cells.read_text())
        data["cells"][0]["expect"] = ["CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y"]
        self.cells.write_text(json.dumps(data))
        key_hex = re.search(
            r'config ROUTELOOM_DEVELOPMENT_KEY_HEX\s+string[^\n]*\n\s+default "([0-9a-fA-F]+)"',
            (ROOT / "components/routeloom_device/Kconfig").read_text()).group(1)
        image = self.dir / "a" / "routeloom_bench_node.bin"
        self.assertEqual(self.size("a")[0], 0)
        for key in (bytes.fromhex(key_hex), key_hex.encode(), key_hex.upper().encode()):
            image.write_bytes(bytes(100) + key + bytes(1000 - 100 - len(key)))
            code, _, err = self.size("a")
            self.assertEqual(code, 1)
            self.assertIn("development key", err)
        # The explicit development profile still admits its quick-start key.
        data["cells"][0]["expect"] = ["CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y"]
        self.cells.write_text(json.dumps(data))
        self.assertEqual(self.size("a")[0], 0)

    def test_member_image_refuses_development_providers(self):
        data = json.loads(self.cells.read_text())
        member = "CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y"
        data["cells"][0]["expect"] = [member]
        self.cells.write_text(json.dumps(data))
        self.assertEqual(self.size("a")[0], 0)
        for provider in ("DevGroupProvider", "DevGroupSender", "DevScopeProvider",
                         "DevMembershipHooks", "DevelopmentPskSecurityProvider",
                         "DevPskAuthenticator", "DevConfigAuthorityVerifier"):
            with self.subTest(provider=provider):
                self.build("a", 1000, 500, 40, symbols=("app_main", provider))
                code, _, err = self.size("a")
                self.assertEqual(code, 1)
                self.assertIn(provider, err)
        data["cells"][0]["expect"] = ["CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y"]
        self.cells.write_text(json.dumps(data))
        self.assertEqual(self.size("a")[0], 0)

    def test_member_image_refuses_configured_development_key(self):
        key_hex = bytes(range(32)).hex()
        setting = f'CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX="{key_hex}"'
        image = self.dir / "a" / "routeloom_bench_node.bin"
        config = self.dir / "sdkconfig"
        for source in ("overlay", "sdkconfig"):
            data = json.loads(self.cells.read_text())
            data["cells"][0]["expect"] = ["CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y"]
            data["cells"][0]["overlay"] = [setting] if source == "overlay" else []
            config.write_text(setting if source == "sdkconfig" else "")
            self.cells.write_text(json.dumps(data))
            image.write_bytes(bytes(1000))
            self.assertEqual(self.size("a")[0], 0)
            for key in (bytes.fromhex(key_hex), key_hex.encode(), key_hex.upper().encode()):
                with self.subTest(source=source, encoding=key == bytes.fromhex(key_hex)):
                    image.write_bytes(bytes(100) + key + bytes(1000 - 100 - len(key)))
                    code, _, err = self.size("a")
                    self.assertEqual(code, 1)
                    self.assertIn("development key", err)
                    self.assertNotIn(key_hex, err)

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

    def test_repeated_bursts_use_gateway_dedup_without_changing_other_peers(self):
        case = "site::owner_mesh::load::mesh_m08_repeated_bursts_account_for_every_send"
        for tier in ("pr", "nightly"):
            with self.subTest(tier=tier):
                steps = check.e2e(tier, "mesh", "build-e2e", None)
                load = next(step for step in steps if case in (step.require or ()))
                self.assertEqual(load.require, [case])
                self.assertEqual(load.env["ROUTELOOM_MESH_PEER_GW"],
                                 str(ROOT / "build-e2e-gateway/tests/cpp/routeloom_owner_mesh_peer"))
                self.assertEqual(load.env["ROUTELOOM_MESH_PEER"],
                                 str(ROOT / "build-e2e/tests/cpp/routeloom_owner_mesh_peer"))
                self.assertTrue(any("-DROUTELOOM_DEDUP_PROFILE=gateway" in step.argv
                                    for step in steps))
                other = next(step for step in steps if step.require and step is not load)
                self.assertNotIn("ROUTELOOM_MESH_PEER_GW", other.env)

    def test_object_rows_are_live_and_use_feature_peers(self):
        for row_id in ("M10", "M10-HFIX-OBJECT", "P04-O"):
            self.assertEqual(self.rows(row_id)[0]["status"], "live")
        steps = check.e2e("pr", "mesh", "build-e2e", None)
        case = "site::owner_mesh::object::mesh_m10_three_hop_with_control"
        obj = next(step for step in steps if case in (step.require or ()))
        self.assertIn("site::owner_mesh::object::load::mesh_m10_immediate_objects_with_1hz_control",
                      obj.require)
        self.assertIn("--include-ignored", obj.argv)
        self.assertIn("build-e2e-object", obj.env["ROUTELOOM_MESH_PEER"])
        self.assertEqual(obj.env["ROUTELOOM_MESH_PEER_B"],
                         str(ROOT / "build-e2e/tests/cpp/routeloom_owner_mesh_peer"))
        off = next(step for step in steps if
                   "site::owner_mesh::object::mesh_p04_object_off_terminal" in (step.require or ()))
        self.assertEqual(off.env["ROUTELOOM_MESH_PEER_GW"], obj.env["ROUTELOOM_MESH_PEER_B"])

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

    def test_every_v2_pr_has_a_scenario(self):
        for row in self.data["rows"]:
            row["prs"] = [pr for pr in row["prs"] if pr != "V2-21"]
        self.assertIn("V2-21: no scenario row", check.scenario_errors(self.data))

    def test_owner_mesh_case_cannot_be_left_out_of_the_table(self):
        ref = ("host/routeloom-host/src/site/owner_mesh/mesh.rs::"
               "mesh_provision_snapshot_reused_without_shared_world_state")
        for row in self.data["rows"]:
            row["test"] = [test for test in row["test"] if test != ref]
        self.assertIn(f"unregistered Owner mesh test {ref}",
                      check.scenario_errors(self.data))

    def test_planned_and_hil_rows(self):
        self.rows("M10")[0]["status"] = "planned"
        self.rows("M10")[0]["test"] = self.rows("M01")[0]["test"]
        self.rows("M05")[0]["hil"]["run"] = ["tools/hil/no_such_script.py"]
        self.rows("M03")[0]["hil"] = {"rounds": ["H0"], "run": "manual"}
        errors = check.scenario_errors(self.data)
        self.assertIn("M10: a planned row names no test", errors)
        self.assertIn("M05: hil run ['tools/hil/no_such_script.py'] is neither manual nor "
                      "HIL scripts", errors)
        self.assertIn("M03: hil set on a row without the hil tier", errors)

    def test_hil_run_must_be_a_hil_script(self):
        self.rows("M05")[0]["hil"]["run"] = ["tools/check.py"]
        self.assertTrue(any("M05: hil run" in error
                            for error in check.scenario_errors(self.data)))

    def test_hil_requirements_and_acceptance_mapping_are_checked(self):
        self.rows("M06")[0]["hil"]["requires"][0]["count"] = 0
        self.data["acceptance_pending"][0]["rows"] = ["missing"]
        errors = check.scenario_errors(self.data)
        self.assertIn("M06: hil requires bounded roles and chips", errors)
        self.assertIn("V1-F04: invalid pending acceptance mapping", errors)

    def test_pending_row_needs_a_wait_reason(self):
        row = self.rows("F08")[0]
        row.pop("blocked_by")
        self.assertIn("F08: pending needs blocked_by and note", check.scenario_errors(self.data))

    def test_shards_keep_all_live_cases_and_exclude_pending_and_red(self):
        cases = [set(check.e2e_cases(self.data, "pr", shard)) for shard in check.E2E_SHARDS]
        self.assertEqual(set.union(*cases), set(check.e2e_cases(self.data, "pr", "all")))
        self.assertFalse(any(a & b for i, a in enumerate(cases) for b in cases[i + 1:]))
        self.assertTrue(any("cpp_joiner_removed_rediscovers" in c for c in cases[1]))
        self.assertTrue(any("mesh_j08_k1b_isolated_miss_recovers" in c for c in cases[0]))
        self.assertTrue(any("mesh_j08_k1b_pull_answers_dropped" in c for c in cases[2]))
        all_cases = set.union(*cases)
        self.assertIn("site::owner_mesh::consumer::mesh_k01_display_direct_smoke", all_cases)
        for row_id in ("K01", "K01-D", "K03", "M08", "M01-T3", "M05-C", "J03-C", "F08-C", "K04-C"):
            for case in check.rust_cases(self.rows(row_id)[0]["test"]):
                self.assertIn(case, all_cases)
        self.assertIn("site::owner_mesh::kg::mesh_k05_cursor_replay_gap_and_epoch_change",
                      all_cases)
        self.assertIn("site::owner_mesh::mesh::mesh_line_three_hops_delivers", all_cases)

    def test_interop_requires_every_live_pr_case(self):
        steps = [s for s in check.interop() if s.require is not None]
        self.assertEqual(len(steps), 2)
        self.assertIn("site::joiner_interop::live_owner_removal_notice_erase_holdoff",
                      steps[0].require)
        self.assertIn("site::owner_mesh::mesh::mesh_direct_converges_and_delivers",
                      steps[1].require)
        self.assertIn("site::owner_mesh::mesh::mesh_line_three_hops_delivers",
                      steps[1].require)
        for profile in ("member", "devram"):
            for hops in (2, 3, 4):
                self.assertIn(f"site::owner_mesh::end::mesh_end_{profile}_{hops}_hops_deliver",
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
        self.assertEqual(checks, [["assert-peer-version", check.PEER, check.PEER_VERSION],
                                  ["assert-peer-version", check.MESH_PEER,
                                   check.MESH_PEER_VERSION]])
        with tempfile.TemporaryDirectory() as tmp:
            peer = Path(tmp) / "peer"
            for version, required, expected in (("0", "1", 1), ("1", "1", 0),
                                                ("1", "2", 1), ("2", "2", 0)):
                peer.write_text(f"#!/bin/sh\nprintf '{version}\\n'\n")
                peer.chmod(0o700)
                step = check.Step(["assert-peer-version", str(peer), required])
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(check.run([step], dry_run=False), expected)

    def test_require_live_fails_on_a_missing_or_empty_run(self):
        script = "print('test site::a ... ok'); print('test site::b ... FAILED')"
        for require, expect in ((["site::a"], 0), (["site::a", "site::b"], 1), ([], 0)):
            step = check.Step([sys.executable, "-c", script], require=require)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(check.run([step], dry_run=False), expect, require)
            self.assertEqual(step.failed, {"site::b"})
        empty = check.Step([sys.executable, "-c", "print('running 0 tests')"], require=[])
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(check.run([empty], dry_run=False), 1)
        self.assertIn("(no case ran)", err.getvalue())
