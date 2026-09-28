"""protocol/manifest.json drift must fail tools/gen_manifest.py --check."""
from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
