"""Topology overlays use radio source MACs; flash identity stays independent."""
import csv
import contextlib
import io
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.hil import flash, rig, topology


class TopologyTests(unittest.TestCase):
    def boards(self, count):
        return [{"name": f"b{i}", "by_id": f"/dev/serial/by-id/board{i}",
                 "mac": f"02:00:00:00:00:{i:02x}",
                 "chip": "esp32c6" if i == 1 else "esp32c3",
                 "app": "bridge_node" if i == 0 else "reference_node",
                 "probe_mac": f"02:00:00:ff:fe:00:00:{i:02x}" if i == 1 else ""}
                for i in range(count)]

    def table(self, root, boards):
        path = root / "boards.csv"
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=boards[0].keys())
            writer.writeheader()
            writer.writerows(boards)
        return path

    def test_generate_symmetric_topologies_and_manual_steps(self):
        cases = (("line7", 7, [[1], [0, 2], [1, 3], [2, 4], [3, 5], [4, 6], [5]]),
                 ("diamond", 4, [[1, 2], [0, 3], [0, 3], [1, 2]]),
                 ("star", 7, [list(range(1, 7)), *[[0] for _ in range(6)]]),
                 ("star", 9, [list(range(1, 9)), *[[0] for _ in range(8)]]))
        for name, count, expected in cases:
            with self.subTest(name=name, count=count), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                boards = self.boards(count)
                output = root / "topology"
                topology.generate(name, self.table(root, boards), output)
                for i, adjacent in enumerate(expected):
                    allow = ",".join(boards[j]["mac"] for j in adjacent)
                    self.assertEqual((output / f"b{i}.sdkconfig").read_text(),
                                     f'CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS="{allow}"\n')
                loaded = rig.load_rigs(str(output / "rig.json"))[name]
                self.assertEqual(loaded.boards["b1"].mac, boards[1]["probe_mac"])
                self.assertEqual(loaded.boards["b1"].port_globs, [boards[1]["by_id"]])
                steps = (output / "STEPS.md").read_text()
                self.assertEqual(steps.count("tools/hil/build_image.sh"), count)
                self.assertEqual(steps.count("tools/hil/flash.py"), count)
                self.assertIn("only in an authorized hardware round", steps)

    def test_generated_flash_command_accepts_option_like_board_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            boards = self.boards(2)
            boards[1]["name"] = "-relay"
            output = root / "out"
            topology.generate("star", self.table(root, boards), output)
            command = next(line for line in (output / "STEPS.md").read_text().splitlines()
                           if line.startswith("python3 tools/hil/flash.py") and "-relay" in line)
            with patch.object(rig, "resolve_board_port", return_value=(None, [], "OFFLINE")) as resolve, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(flash.main(shlex.split(command)[2:]), 3)
            self.assertEqual(resolve.call_args.args[0].name, "-relay")

    def test_invalid_input_is_rejected_before_output(self):
        for column, value in (("mac", "02:00:00:ff:fe:00:00:01"),
                              ("probe_mac", "02:00:00:00:00:01"),
                              ("by_id", "/dev/serial/by-id/board*"),
                              ("name", "../bad"), ("chip", "esp32c5"),
                              ("app", "bad"), ("name", "b0"), ("mac", "02:00:00:00:00:00")):
            with self.subTest(column=column, value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                boards = self.boards(7)
                boards[1][column] = value
                output = root / "out"
                with self.assertRaises(ValueError):
                    topology.generate("line7", self.table(root, boards), output)
                self.assertFalse(output.exists())
        for name, count in (("line7", 6), ("diamond", 7), ("star", 10)):
            with self.assertRaises(ValueError):
                topology.neighbors(name, count)


if __name__ == "__main__":
    unittest.main()
