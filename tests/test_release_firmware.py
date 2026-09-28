"""Release flash arguments must resolve to images in the staged artifact."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.release_firmware import package_firmware


class ReleaseFirmwareTest(unittest.TestCase):
    def test_stage_preserves_all_flash_file_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            build.mkdir()
            flash_files = {
                "0x0": "bootloader/bootloader.bin",
                "0x8000": "partition_table/partition-table.bin",
                "0x10000": "ota_data_initial.bin",
                "0x40000": "routeloom_reference_node.bin",
            }
            for filename in flash_files.values():
                path = build / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(filename.encode())
            (build / "flasher_args.json").write_text(json.dumps({"flash_files": flash_files}))
            (root / "sdkconfig").write_text('CONFIG_ESPTOOLPY_FLASHSIZE="4MB"\n')
            stage = root / "stage"
            package_firmware(build, root / "sdkconfig", stage)
            args = json.loads((stage / "flasher_args.json").read_text())
            for filename in args["flash_files"].values():
                self.assertEqual((stage / filename).read_bytes(),
                                 (build / filename).read_bytes())


if __name__ == "__main__":
    unittest.main()
