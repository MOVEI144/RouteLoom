"""Vendored EDHOC sources match pinned blobs, with one checked zcbor patch.

components/routeloom/third_party/VENDORED.json records, for libedhoc, zcbor
and the TF-PSA-Crypto AES/CCM subset, the upstream URL, commit, SPDX license
and the checked-in git blob id of every vendored file. This test
recomputes the blob ids (sha1 of "blob <len>\\0" + bytes, what `git hash-object`
prints), so any unreviewed edit, added or missing file fails; RouteLoom glue must
live outside these directories (components/routeloom/src/edhoc/). It also
checks that each component's license is credited in NOTICE with its commit
and that the libedhoc pin is the one the design fixed (05-production-security
§1). No network access.
"""
from pathlib import Path
import hashlib
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "components" / "routeloom" / "third_party"
LOCK = json.loads((THIRD_PARTY / "VENDORED.json").read_text(encoding="utf-8"))
DESIGN_PIN = "c8857b62d66be3664d1694bbe4eea37c56c05d9e"


def blob_id_bytes(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def blob_id(path: Path) -> str:
    return blob_id_bytes(path.read_bytes())


class VendoredSources(unittest.TestCase):
    def test_lock_shape(self):
        self.assertEqual(LOCK["format"], "routeloom-vendored-sources-v1")
        names = [c["name"] for c in LOCK["components"]]
        self.assertEqual(names, ["libedhoc", "zcbor", "TF-PSA-Crypto"])
        for component in LOCK["components"]:
            self.assertRegex(component["commit"], r"^[0-9a-f]{40}$")
            self.assertIn(component["license_file"], component["files"])

    def test_libedhoc_is_the_design_pin(self):
        libedhoc = LOCK["components"][0]
        self.assertEqual(libedhoc["commit"], DESIGN_PIN)
        self.assertEqual(libedhoc["version"], "v2.3.2")
        self.assertEqual(libedhoc["license"], "MIT")
        design = (ROOT / "docs/design/host-security-readiness/05-production-security.md").read_text(
            encoding="utf-8")
        self.assertIn(DESIGN_PIN, design)

    def test_files_match_upstream_blobs(self):
        for component in LOCK["components"]:
            directory = THIRD_PARTY / component["directory"]
            on_disk = {
                p.relative_to(directory).as_posix()
                for p in directory.rglob("*")
                if p.is_file()
            }
            with self.subTest(component=component["name"]):
                self.assertEqual(on_disk, set(component["files"]))
                for relative, expected in component["files"].items():
                    self.assertEqual(blob_id(directory / relative), expected, relative)

    def test_zcbor_patch_is_only_the_null_zero_length_guard(self):
        zcbor = LOCK["components"][1]
        self.assertEqual(set(zcbor["local_patches"]), {"src/zcbor_encode.c"})
        source = (THIRD_PARTY / zcbor["directory"] / "src/zcbor_encode.c").read_bytes()
        fixed = b"if (input->len != 0 && state->payload_mut != input->value) {"
        upstream = b"if (state->payload_mut != input->value) {"
        self.assertEqual(source.count(fixed), 1)
        restored = source.replace(fixed, upstream, 1)
        self.assertEqual(blob_id_bytes(restored),
                         zcbor["local_patches"]["src/zcbor_encode.c"]["upstream_blob"])

    def test_notice_credits_every_component(self):
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        for component in LOCK["components"]:
            with self.subTest(component=component["name"]):
                self.assertIn(component["commit"], notice)
                self.assertIn(component["upstream"], notice)
                self.assertIn(
                    f"components/routeloom/third_party/{component['directory']}/", notice)


if __name__ == "__main__":
    unittest.main()
