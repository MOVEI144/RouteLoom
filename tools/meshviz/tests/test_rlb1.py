"""RLB1 codec conformance — the Python port must be byte-identical to
host/routeloom-protocol/src/bench.rs, pinned by protocol/bench-golden."""
import json
import unittest
from pathlib import Path

from routeloom_meshviz import rlb1

GOLDEN = Path(__file__).resolve().parents[3] / 'protocol' / 'bench-golden'


def _vectors():
    return sorted(GOLDEN.glob('*.json'))


class GoldenVectorTest(unittest.TestCase):
    def test_every_wire_hex_decodes_or_rejects_as_expected(self):
        self.assertTrue(_vectors(), 'bench-golden vectors missing')
        for path in _vectors():
            with self.subTest(vector=path.name):
                spec = json.loads(path.read_text())
                wire = bytes.fromhex(spec['wire_hex'])
                if spec['expect'] == 'ok':
                    msg = rlb1.decode(wire)
                    self.assertEqual(msg['opcode'], spec['opcode'])
                    self.assertEqual(msg['flags'], spec['flags'])
                    self.assertEqual(msg['run'].hex(), spec['run_uuid_hex'])
                    self.assertEqual(msg['sequence'], spec['sequence'])
                    self.assertEqual(msg['body'].hex(), spec['body_hex'])
                    # Re-encoding a well-formed frame is the identity.
                    self.assertEqual(
                        rlb1.encode(msg['opcode'], msg['flags'], msg['run'],
                                    msg['sequence'], msg['body']), wire)
                else:
                    with self.assertRaises(ValueError):
                        rlb1.decode(wire)

    def test_typed_bodies_roundtrip(self):
        start = rlb1.encode_peer_send_start(
            expected_boot=0xB0071D0001, expected_dest_boot=0xB0071D0002,
            destination=0xB, sequence_begin=100, count=64, payload_len=24,
            seed=0xDEADBEEF, interval_ms=250, ttl_ms=30_000, max_inflight=1)
        self.assertEqual(len(start), 44)
        back = rlb1.decode_peer_send_start(start)
        self.assertEqual(back['count'], 64)
        self.assertEqual(back['destination'], 0xB)
        self.assertEqual(back['seed'], 0xDEADBEEF)

        status = rlb1.encode_peer_send_status(
            {'result': rlb1.PS_QUERY, 'state': rlb1.GEN_COMPLETE,
             'planned': 64, 'submitted': 64, 'admitted': 64,
             'delivered': 63, 'failed': 1, 'unknown': 0,
             'first_ms': 100, 'last_ms': 16000})
        self.assertEqual(len(status), 22)
        got = rlb1.decode_peer_send_status(status)
        self.assertEqual(got['delivered'], 63)
        self.assertEqual(got['state'], rlb1.GEN_COMPLETE)

        count = rlb1.encode_count_status(
            {'state': rlb1.COUNT_ACTIVE, 'unique_packets': 63,
             'unique_bytes': 1512, 'duplicates': 1, 'crc_invalid': 0,
             'first_ms': 100, 'last_ms': 16000, 'window_base': 64,
             'window': 0x7FFF_FFFF_FFFF_FFFF})
        self.assertEqual(len(count), 37)
        got = rlb1.decode_count_status(count)
        self.assertEqual(got['unique_packets'], 63)
        self.assertEqual(got['window'], 0x7FFF_FFFF_FFFF_FFFF)

    def test_fixed_bodies_reject_truncation_and_trailing_garbage(self):
        with self.assertRaises(ValueError):
            rlb1.decode_peer_send_status(b'\x00' * 21)
        with self.assertRaises(ValueError):
            rlb1.decode_peer_send_status(b'\x00' * 23)
        with self.assertRaises(ValueError):
            rlb1.decode_peer_send_start(b'\x00' * 43)
        with self.assertRaises(ValueError):
            rlb1.decode_count_status(b'\x00' * 38)

    def test_encode_bounds(self):
        run = bytes(16)
        self.assertEqual(len(rlb1.encode(rlb1.Opcode.COUNT_ONLY, 0, run, 0,
                                         bytes(rlb1.MAX_BODY))),
                         rlb1.MAX_UNICAST_PAYLOAD)
        with self.assertRaises(ValueError):
            rlb1.encode(rlb1.Opcode.COUNT_ONLY, 0, run, 0,
                        bytes(rlb1.MAX_BODY + 1))
        with self.assertRaises(ValueError):
            rlb1.encode(rlb1.Opcode.HELLO, 0, b'\x00' * 15, 0, b'')


if __name__ == '__main__':
    unittest.main()
