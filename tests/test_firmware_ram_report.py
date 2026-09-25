"""Static RAM report / headroom guard (tools/firmware_ram_report.py).

The fixtures under tests/fixtures/idf-size/ are hand-built in the exact
shape esp-idf-size 2.x emits for `idf.py size --format json2` (format_json.py
show_summary: version/total_size/layout[name,total,used,free,parts]) with the
memory-type names its chip_info tables give the C3 ("DRAM") and S3
("DIRAM"). CI uploads the real per-cell size.json next to each firmware
image; a fixture can be replaced by one of those without touching the tests.
"""
from pathlib import Path
import copy
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import firmware_ram_report as frr  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "idf-size"
DOC = ROOT / "docs" / "design" / "sdk-v1" / "ram-budget.md"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def run_main(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = frr.main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class Parse(unittest.TestCase):
    def test_c3_json2_guards_dram(self):
        result = frr.evaluate(load("esp32c3-json2.json"), "esp32c3", "bridge_node")
        guard = result["guard"]
        self.assertEqual(guard["memory_type"], "DRAM")
        self.assertEqual(guard["free"], 321296 - 283642)
        self.assertEqual(guard["static_bss"], 174276)
        self.assertEqual(guard["static_data"], 21054)
        self.assertEqual(guard["min_free"], 8192)
        self.assertTrue(guard["passed"])
        # Flash is never RAM budget; RTC SLOW is reported but not guarded
        # although its RTC_DATA_ATTR section abbreviates to ".data" and its
        # free space (8156 B) is below the floor.
        names = [m["name"] for m in result["memory"]]
        self.assertEqual(names, ["DRAM", "RTC SLOW"])

    def test_c5_guards_hp_sram_not_lp_sram(self):
        report = {"version": "1.2", "layout": [
            {"name": "HP SRAM", "total": 393216, "used": 250000, "free": 143216,
             "parts": {".bss": {"size": 150000}, ".text": {"size": 80000},
                       ".data": {"size": 20000}}},
            {"name": "LP SRAM", "total": 16384, "used": 16000, "free": 384,
             "parts": {".bss": {"size": 8000}, ".data": {"size": 8000}}},
            {"name": "Flash", "total": 33554432, "used": 900000, "free": 32654432,
             "parts": {".text": {"size": 700000}, ".rodata": {"size": 200000}}},
        ]}
        result = frr.evaluate(report, "esp32c5", "reference_node")
        self.assertEqual(result["guard"]["memory_type"], "HP SRAM")
        self.assertTrue(result["guard"]["passed"])
        self.assertEqual([m["name"] for m in result["memory"]], ["HP SRAM", "LP SRAM"])

    def test_s3_json2_guards_diram_not_iram(self):
        result = frr.evaluate(load("esp32s3-json2.json"), "esp32s3", "bridge_node")
        # IRAM is almost full but holds no static data: the guard must pick
        # the type that holds .bss, not the smallest free overall.
        self.assertEqual(result["guard"]["memory_type"], "DIRAM")
        self.assertEqual(result["guard"]["free"], 96642)
        self.assertIn("IRAM", [m["name"] for m in result["memory"]])

    def test_missing_free_is_derived(self):
        report = load("esp32c3-json2.json")
        for entry in report["layout"]:
            entry.pop("free")
        result = frr.evaluate(report, "esp32c3", "bridge_node")
        self.assertEqual(result["guard"]["free"], 37654)

    def test_raw_memory_map_layout(self):
        # `--format raw` shape: memory_types{name: size/used/sections{...}}
        # with full output-section names and abbreviations.
        raw = {
            "version": "1.0",
            "target": "esp32c3",
            "memory_types": {
                "DRAM": {"size": 321296, "used": 300000, "sections": {
                    ".dram0.bss": {"abbrev_name": ".bss", "size": 190000},
                    ".dram0.data": {"abbrev_name": ".data", "size": 20000},
                    ".iram0.text": {"abbrev_name": ".text", "size": 90000}}},
                "Flash Code": {"size": 8388576, "used": 1000, "sections": {
                    ".flash.text": {"abbrev_name": ".text", "size": 1000}}},
            },
        }
        result = frr.evaluate(raw, "esp32c3", "reference_node")
        self.assertEqual(result["guard"]["memory_type"], "DRAM")
        self.assertEqual(result["guard"]["free"], 21296)
        self.assertEqual(result["guard"]["static_bss"], 190000)

    def test_unrecognised_report_is_an_error(self):
        for bad in ({}, {"layout": "x"}, [], {"layout": [{"name": "Flash Code",
                                                          "total": 10, "used": 1,
                                                          "parts": {".text": {"size": 1}}}]}):
            with self.assertRaises(frr.ReportError):
                frr.evaluate(bad, "esp32c3", "bridge_node")

    def test_non_numeric_field_is_an_error(self):
        report = load("esp32c3-json2.json")
        report["layout"][1]["used"] = "283642"
        with self.assertRaises(frr.ReportError):
            frr.evaluate(report, "esp32c3", "bridge_node")


class Guard(unittest.TestCase):
    def test_threshold_lookup(self):
        self.assertEqual(frr.threshold("esp32c3", "bridge_node"), 8192)
        self.assertEqual(frr.threshold("esp32c3", "reference_node"), 8192)
        self.assertEqual(frr.threshold("esp32s3", "anything"), 8192)
        self.assertEqual(frr.threshold("esp32h2", "bridge_node"), frr.DEFAULT_MIN_FREE_BYTES)

    def test_below_floor_fails_with_report_written(self):
        report = load("esp32c3-json2.json")
        dram = report["layout"][1]
        dram["used"] = dram["total"] - 8191
        dram["free"] = 8191
        with tempfile.TemporaryDirectory() as tmp:
            size = Path(tmp) / "size.json"
            size.write_text(json.dumps(report), encoding="utf-8")
            summary = Path(tmp) / "summary.md"
            out_json = Path(tmp) / "ram.json"
            code, stdout, stderr = run_main([size, "--target", "esp32c3", "--app",
                                             "bridge_node", "--cell", "c3-bridge",
                                             "--summary", summary, "--json-out", out_json])
            self.assertEqual(code, 1)
            self.assertIn("8191 B is below the 8192 B floor", stderr)
            self.assertIn("**FAIL**", summary.read_text(encoding="utf-8"))
            written = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertFalse(written["guard"]["passed"])
            self.assertEqual(written["cell"], "c3-bridge")

    def test_at_floor_passes(self):
        report = load("esp32c3-json2.json")
        dram = report["layout"][1]
        dram["used"] = dram["total"] - 8192
        dram["free"] = 8192
        with tempfile.TemporaryDirectory() as tmp:
            size = Path(tmp) / "size.json"
            size.write_text(json.dumps(report), encoding="utf-8")
            code, stdout, _ = run_main([size, "--target", "esp32c3", "--app", "bridge_node"])
            self.assertEqual(code, 0)
            self.assertIn("**PASS**", stdout)
            self.assertIn("| DRAM | 313104 | 321296 | 8192 |", stdout)

    def test_unreadable_report_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            size = Path(tmp) / "size.json"
            size.write_text("{not json", encoding="utf-8")
            summary = Path(tmp) / "summary.md"
            code, _, stderr = run_main([size, "--target", "esp32c3", "--app",
                                        "bridge_node", "--summary", summary])
            self.assertEqual(code, 2)
            self.assertIn("**ERROR**", summary.read_text(encoding="utf-8"))
            code, _, _ = run_main([Path(tmp) / "missing.json", "--target", "esp32c3",
                                   "--app", "bridge_node"])
            self.assertEqual(code, 2)

    def test_input_not_mutated(self):
        report = load("esp32c3-json2.json")
        before = copy.deepcopy(report)
        frr.evaluate(report, "esp32c3", "bridge_node")
        self.assertEqual(report, before)


class Documentation(unittest.TestCase):
    def test_owner_matrix_covers_targets(self):
        workflow = (ROOT / ".github/workflows/sdk.yml").read_text(encoding="utf-8")
        cells = set(re.findall(
            r"(?m)^          - app: (reference_node|bridge_node)\n"
            r"            target: (esp32c3|esp32s3|esp32c5)\n"
            r"            profile: normal\n"
            r"            autonomy: off\n"
            r"            features: owner_member$", workflow))
        self.assertEqual(cells, {
            (app, target)
            for app in ("reference_node", "bridge_node")
            for target in ("esp32c3", "esp32s3", "esp32c5")
        })

    def test_owner_main_task_stack_budget(self):
        for app in ("bridge_node", "reference_node"):
            defaults = (ROOT / "firmware" / app / "sdkconfig.defaults").read_text(
                encoding="utf-8")
            matches = re.findall(r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)$", defaults, re.M)
            self.assertEqual(len(matches), 1, app)
            self.assertGreaterEqual(int(matches[0]), 16 * 1024, app)

    def test_floor_table_matches_tool(self):
        text = DOC.read_text(encoding="utf-8")
        rows = re.findall(r"^\| `(esp32\w+)` \| `([\w*]+)` \| ([\d,]+) \|", text, re.M)
        documented = {(target, app): int(value.replace(",", ""))
                      for target, app, value in rows}
        self.assertEqual(documented, frr.MIN_FREE_BYTES)

    def test_workflow_runs_the_guard_on_every_cell(self):
        workflow = (ROOT / ".github" / "workflows" / "sdk.yml").read_text(encoding="utf-8")
        self.assertIn("idf.py size --format json2 --output-file build/size.json", workflow)
        self.assertIn("tools/firmware_ram_report.py", workflow)
        self.assertIn("firmware/${{ matrix.app }}/build/ram-report.json", workflow)


if __name__ == "__main__":
    unittest.main()
