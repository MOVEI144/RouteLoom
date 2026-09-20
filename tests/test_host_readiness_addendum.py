"""Design-only deadline arithmetic; not SDK, clock, storage, crypto or HIL tests."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_host_readiness_design import strict_json

DIRECTORY = ROOT / "docs/design/host-security-readiness"
MAX64 = (1 << 64) - 1
CONTRACT = strict_json((DIRECTORY / "contracts.json").read_text(encoding="utf-8"))
FIELDS = ("h", "h0", "h1", "host_now", "d", "device_now")


def model_deadline(*, h: int, ttl: int, h0: int, h1: int, host_now: int,
                   d: int, device_now: int, clock_valid: bool = True) -> tuple[str, int | None]:
    """Reference math using unbounded Python intermediates, with u64 boundaries.

    Results are local model reasons, NOT new runtime Status enum members.
    An expired budget never establishes that an earlier write did not happen.
    """
    clocks = (h, h0, h1, host_now, d, device_now)
    if (any(type(value) is not int or not 0 <= value <= MAX64 for value in clocks)
            or type(ttl) is not int
            or not CONTRACT["send"]["ttl_min_ms"] <= ttl <= CONTRACT["send"]["ttl_max_ms"]
            or type(clock_valid) is not bool):
        return "invalid_argument", None
    if not clock_valid or not h0 <= h1 <= host_now or host_now < h or device_now < d:
        return "time_uncertain", None
    if h > MAX64 - ttl:
        return "arithmetic_overflow", None
    deadline = h + ttl
    if host_now >= deadline:
        return "expired_budget", None
    if host_now - h0 > CONTRACT["send"]["time_sample_max_age_ms"]:
        return "time_uncertain", None
    remaining = deadline - h1
    horizon = deadline - h0
    ppm = CONTRACT["send"]["clock_bound_ppm_design"]
    margin = CONTRACT["send"]["clock_quantization_ms"] + (ppm * horizon + 999_999) // 1_000_000
    if remaining <= margin:
        return "expired_budget", None
    safe_remaining = remaining - margin
    if d > MAX64 - safe_remaining:
        return "arithmetic_overflow", None
    device_deadline = d + safe_remaining
    if device_now >= device_deadline:
        return "expired_budget", None
    return "ready", device_deadline


def vector_input(value: dict) -> dict:
    result = dict(value)
    for name in FIELDS:
        raw = result[name]
        if not isinstance(raw, str) or re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
            raise ValueError("clock fixture must use an exact decimal string")
        result[name] = int(raw)
    return result


class DeadlineDesignTests(unittest.TestCase):
    def test_review_vectors(self):
        vectors = strict_json((DIRECTORY / "review-addendum/deadline-vectors.json").read_text(encoding="utf-8"))
        self.assertEqual(vectors["scope"], "design_arithmetic_not_runtime_or_hil")
        self.assertEqual(len({case["id"] for case in vectors["cases"]}), len(vectors["cases"]))
        for case in vectors["cases"]:
            with self.subTest(case=case["id"]):
                expected = case["expected"]
                deadline = None if expected["device_deadline"] is None else int(expected["device_deadline"])
                self.assertEqual(model_deadline(**vector_input(case["input"])), (expected["reason"], deadline))

    def test_small_equal_rate_clock_domain_exhaustive(self):
        # 21*11*6*5 = 6,930 combinations; no device or real clock is involved.
        for h in range(0, 21):
            for ttl in range(1, 12):
                for age in range(0, 6):
                    for rtt in range(0, 5):
                        h0 = h
                        h1 = h0 + rtt
                        now = h1 + age
                        offset = 100
                        # Choose the earliest permitted sample within the observed RTT.
                        d = h0 + offset
                        dn = now + offset
                        reason, deadline = model_deadline(h=h, ttl=ttl, h0=h0, h1=h1,
                                                         host_now=now, d=d, device_now=dn)
                        if reason == "ready":
                            self.assertGreater(deadline, dn)
                            self.assertLessEqual(deadline, h + ttl + offset)
                            self.assertLessEqual(deadline, MAX64)
                        else:
                            self.assertIsNone(deadline)

    def test_scope_and_input_guards(self):
        base = dict(h=1000, ttl=5000, h0=1100, h1=1110, host_now=1120,
                    d=2000, device_now=2020)
        self.assertEqual(model_deadline(**base), ("ready", 6884))
        for changes in ({"ttl": True}, {"ttl": 0}, {"ttl": 30001}, {"d": -1},
                        {"d": MAX64 + 1}, {"h": 1.5}, {"clock_valid": 1}):
            with self.subTest(changes=changes):
                self.assertEqual(model_deadline(**(base | changes)), ("invalid_argument", None))
        for changes in ({"clock_valid": False}, {"h0": 1111}, {"device_now": 1999}):
            with self.subTest(changes=changes):
                self.assertEqual(model_deadline(**(base | changes)), ("time_uncertain", None))
        with self.assertRaises(ValueError):
            vector_input(dict(h=MAX64, ttl=1, h0="0", h1="0", host_now="0", d="0", device_now="0"))

    def test_runtime_acceptance_not_promoted(self):
        cases = strict_json((DIRECTORY / "scenarios.json").read_text(encoding="utf-8"))["cases"]
        self.assertEqual(len(cases), 62)
        self.assertTrue(all(case["status"] == "planned_not_run" for case in cases))
        self.assertIs(CONTRACT["runtime_changed"], False)
        self.assertIs(CONTRACT["qualified_by_this_pr"], False)
        self.assertIs(CONTRACT["receive"]["durable_receive"], False)
        self.assertIs(CONTRACT["receive"]["pc_service_destination"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
