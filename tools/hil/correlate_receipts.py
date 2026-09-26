#!/usr/bin/env python3
"""Match host unicast outcomes to application receipts in a HIL console log."""

import argparse
import datetime
import json
import pathlib
import re
import statistics


RECEIPT = re.compile(
    r"^\[([^]]+)\].*message origin=(\d+) session=(\d+) sequence=(\d+)\b"
)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traffic", required=True)
    parser.add_argument("--console", required=True)
    parser.add_argument("--origin", type=int, default=1)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in pathlib.Path(args.traffic).read_text().splitlines()
            if line]
    receipts = {}
    for line in pathlib.Path(args.console).read_text(errors="replace").splitlines():
        match = RECEIPT.search(line)
        if match is None or int(match.group(2)) != args.origin:
            continue
        key = (int(match.group(3)), int(match.group(4)))
        receipts.setdefault(key, []).append(match.group(1))
    correlated = []
    for row in rows:
        delivery = row.get("delivery", {})
        session, sequence = delivery.get("msg_session"), delivery.get("msg_seq")
        matches = receipts.get((session, sequence), [])
        result = {"index": row["index"], "request": row["request"],
                  "host_state": delivery.get("state"),
                  "host_reason": delivery.get("reason"),
                  "msg_session": session, "msg_seq": sequence,
                  "receiver_count": len(matches)}
        if matches:
            observed = datetime.datetime.fromisoformat(matches[0]).timestamp()
            result["receiver_observed_at"] = matches[0]
            result["receiver_delay_ms"] = round(
                (observed - row["admitted_at_unix"]) * 1000, 2)
        correlated.append(result)
    delays = [row["receiver_delay_ms"] for row in correlated
              if "receiver_delay_ms" in row]
    result = {"traffic": args.traffic, "console": args.console,
              "origin": args.origin, "host_accepted": len(rows),
              "host_delivered": sum(row["host_state"] == "delivered"
                                    for row in correlated),
              "receiver_confirmed": len(delays),
              "host_failed_receiver_confirmed": [row for row in correlated
                                                   if row["receiver_count"] > 0
                                                   and row["host_state"] != "delivered"],
              "host_delivered_receiver_missing": [row for row in correlated
                                                  if row["receiver_count"] == 0
                                                  and row["host_state"] == "delivered"],
              "receiver_delay_ms_median": statistics.median(delays) if delays else None,
              "receiver_delay_ms_p95": percentile(delays, 0.95),
              "receiver_delay_ms_max": max(delays) if delays else None,
              "rows": correlated}
    pathlib.Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
