"""Check the shared EDHOC rejection inputs against the pinned RFC trace."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1] / "protocol" / "edhoc-rfc9529"


def vectors(name: str) -> dict[str, bytes]:
    out = {}
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split(" = ")
            out[key] = bytes.fromhex(value)
    return out


class EdhocRejectionVectors(unittest.TestCase):
    def test_each_surplus_byte_extends_one_complete_rfc_message(self):
        base = vectors("chapter3.txt")
        invalid = vectors("trailing-invalid.txt")
        expected = {
            f"message_{number}_trailing_{kind}": base[f"message_{number}"] + bytes([byte])
            for number in (2, 3, 4)
            for kind, byte in (("break", 0xFF), ("item", 0x00))
        }
        self.assertEqual(invalid, expected)


if __name__ == "__main__":
    unittest.main()
