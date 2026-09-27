"""Counter metadata export must reject corrupt NVS records and omit secrets."""

import base64
import struct
import unittest
import zlib

import counter_snapshot


class CounterSnapshotTest(unittest.TestCase):
    def test_valid_record_and_replay_blob_is_not_exported(self):
        prefix = struct.pack("<IIBB6sQI", 0x12345678, 9, 1, 2, bytes(6), 512, 3)
        record = prefix + struct.pack("<I", zlib.crc32(prefix))
        rows = [
            {"namespace": "rlcounter", "key": "c12345678", "encoding": "blob_data",
             "data": base64.b64encode(record).decode()},
            {"namespace": "rlcounter", "key": "cmax", "data": 14},
            {"namespace": "rlreplay", "key": "r12345678", "encoding": "blob_data",
             "data": "DO_NOT_EXPORT"},
        ]
        result = counter_snapshot.summarize(rows)
        self.assertEqual(result["counter_witness"], 14)
        self.assertEqual(result["counter_records"], [{
            "slot": "c12345678", "context_id": "12345678", "key_epoch": 9,
            "direction": 1, "high_water_exclusive": 512, "generation": 3}])
        self.assertNotIn("DO_NOT_EXPORT", str(result))

    def test_corrupt_crc_fails_closed(self):
        raw = struct.pack("<IIBB6sQII", 1, 1, 1, 2, bytes(6), 256, 1, 0)
        result = counter_snapshot.summarize([{
            "namespace": "rlcounter", "key": "c00000001", "encoding": "blob_data",
            "data": base64.b64encode(raw).decode()}])
        self.assertEqual(result["counter_records"], [])
        self.assertEqual(len(result["invalid_records"]), 1)


if __name__ == "__main__":
    unittest.main()
