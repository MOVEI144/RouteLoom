"""protocol/manifest.json drift must fail tools/gen_manifest.py --check."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import gen_manifest  # noqa: E402

INPUTS = [
    "protocol/manifest.json",
    "docs/reference/radio-defaults.json",
    ".github/workflows/sdk.yml",
    "host/Cargo.toml",
    "host/Cargo.lock",
    "host/rust-toolchain.toml",
    "tools/meshviz/pyproject.toml",
    *(f"components/{name}/idf_component.yml" for name in gen_manifest.IDF_COMPONENTS),
    gen_manifest.HEADER,
    gen_manifest.CPP_CHECK,
    gen_manifest.RUST_MODULE,
    gen_manifest.RUST_CHECK,
    gen_manifest.COMPAT_DOC,
]


def run(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "tools/gen_manifest.py"), "--root", str(root), *extra],
                          capture_output=True, text=True, check=False)


def copy_inputs(root: Path) -> None:
    for relative in INPUTS:
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, root / relative)


class ManifestDriftTest(unittest.TestCase):
    def test_component_target_docs_cover_manifest(self) -> None:
        component = (ROOT / "components/routeloom_espnow/idf_component.yml").read_text(encoding="utf-8")
        targets = re.search(r"^targets:\n((?:  - esp32\w+\n)+)", component, re.M)
        self.assertIsNotNone(targets)
        cells = json.loads((ROOT / "tools/ci/cells.json").read_text(encoding="utf-8"))["cells"]
        cell_targets = {cell["target"] for cell in cells}
        for doc in ("docs/implementation/component-distribution.md", "examples/espnow_node/README.md"):
            text = (ROOT / doc).read_text(encoding="utf-8")
            for target in re.findall(r"^  - (esp32\w+)$", targets.group(1), re.M):
                self.assertIn(target, text, f"{doc}: {target}")
                self.assertIn(target, cell_targets, f"tools/ci/cells.json: {target}")
            self.assertIn("tools/ci/cells.json", text, doc)

    def test_persisted_versions_have_distinct_format_entries(self) -> None:
        manifest = gen_manifest.load(ROOT)
        api1 = next(entry for entry in manifest["surfaces"] if entry["id"] == "api1_envelope")
        self.assertEqual(api1.get("rust_check"), [
            "crate::api1::API_VERSION",
            "routeloom_client::api1::API_VERSION",
        ])
        versions = {entry["id"]: entry["value"] for entry in manifest["persisted"]}
        for name, value in {
            "config_journal_format": 2,
            "config_journal_schema": 1,
            "resume_slot_rlp1": 1,
            "resume_slot_rlp2": 1,
            "security_floor_format": 1,
            "migration_commit_record": 2,
            "canonical_node": 1,
            "canonical_gateway": 2,
        }.items():
            self.assertEqual(versions.get(name), value, name)
        rust_checks = {entry["id"]: entry.get("rust_check") for entry in manifest["persisted"]}
        for name, constant in {
            "trust_store_format": "routeloom_provision::image::TRUST_FORMAT",
            "device_credential_format": "routeloom_provision::credential::CRED_FORMAT",
            "revocation_object": "routeloom_provision::sdkv1::revocation::REVOCATION_VERSION",
            "resume_slot_rlp1": "routeloom_provision::sdkv1::resume::RESUME_FORMAT",
            "resume_slot_rlp2": "routeloom_provision::sdkv1::resume2::RESUME2_FORMAT",
        }.items():
            self.assertEqual(rust_checks.get(name), constant, name)

    def test_changed_value_fails_until_regenerated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_inputs(root)
            self.assertEqual(run(root, "--check").returncode, 0)

            path = root / "protocol/manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            wire = next(e for e in manifest["surfaces"] if e["id"] == "wire_minor")
            wire["value"] += 1
            path.write_text(json.dumps(manifest), encoding="utf-8")
            stale = run(root, "--check")
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn(gen_manifest.HEADER, stale.stderr)

            self.assertEqual(run(root).returncode, 0)
            self.assertEqual(run(root, "--check").returncode, 0)
            header = (root / gen_manifest.HEADER).read_text(encoding="utf-8")
            self.assertIn(f"#define ROUTELOOM_WIRE_MINOR {wire['value']}", header)

    def test_package_version_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_inputs(root)
            cargo = root / "host/Cargo.toml"
            text = cargo.read_text(encoding="utf-8")
            version = json.loads((root / "protocol/manifest.json").read_text(encoding="utf-8"))["sdk_version"]
            cargo.write_text(text.replace(f'version = "{version}"', 'version = "9.9.9"', 1), encoding="utf-8")
            result = run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("host/Cargo.toml", result.stderr)

    def test_lockfile_version_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_inputs(root)
            lock = root / "host/Cargo.lock"
            original = lock.read_text(encoding="utf-8")
            changed = original.replace('name = "routeloom-host"\nversion = "2.0.0-dev"',
                                       'name = "routeloom-host"\nversion = "9.9.9"', 1)
            self.assertNotEqual(changed, original)
            lock.write_text(changed, encoding="utf-8")
            result = run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("host/Cargo.lock", result.stderr)

    def test_missing_component_constraint_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_inputs(root)
            component = root / "components/routeloom_espnow/idf_component.yml"
            original = component.read_text(encoding="utf-8")
            changed = original.replace('  routeloom/routeloom: "^2.0.0-dev"\n', "", 1)
            self.assertNotEqual(changed, original)
            component.write_text(changed, encoding="utf-8")
            result = run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("routeloom/routeloom", result.stderr)

    def test_ci_toolchain_pin_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_inputs(root)
            workflow = root / ".github/workflows/sdk.yml"
            original = workflow.read_text(encoding="utf-8")
            changed = original.replace("espressif/idf:v6.0.3", "espressif/idf:v6.1.0")
            self.assertNotEqual(changed, original)
            workflow.write_text(changed, encoding="utf-8")
            toolchain = root / "host/rust-toolchain.toml"
            pinned = toolchain.read_text(encoding="utf-8")
            bumped = re.sub(r'^channel = ".*"$', 'channel = "1.99.0"', pinned, flags=re.M)
            self.assertNotEqual(bumped, pinned)
            toolchain.write_text(bumped, encoding="utf-8")
            result = run(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ESP-IDF", result.stderr)
            self.assertIn("rust", result.stderr)

    def test_reason_width_is_u16(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_inputs(root)
            path = root / "protocol/manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["reason_codes"]["width_bits"] = 32
            path.write_text(json.dumps(manifest), encoding="utf-8")
            result = run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("width_bits", result.stderr)


if __name__ == "__main__":
    unittest.main()
