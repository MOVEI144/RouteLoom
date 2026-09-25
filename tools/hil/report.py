#!/usr/bin/env python3
"""HIL run report: artifacts dir + report.json + human summary.

A run writes ``artifacts/hil/<UTC-timestamp>-<rig>/`` containing:

* ``report.json``      — machine-readable verdicts + evidence paths
* ``summary.txt``      — one human line per scenario
* ``environment.json`` — repo/git/toolchain/OS evidence
* ``usb-inventory.txt``— ``system_profiler``/``lsusb`` output (evidence)
* ``scenarios/<name>/``— per-scenario captures, command logs, tails

Honesty contract (docs/hil.md): a scenario may only claim PASS when every
step has captured evidence in the run dir — ``ScenarioResult.finalize``
enforces that PASS with zero evidence files is impossible. A bench whose
boards are absent is SKIP-OFFLINE, never FAIL and never PASS.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ARTIFACTS_ROOT = os.path.join(REPO_ROOT, "artifacts", "hil")

VERDICTS = ("PASS", "FAIL", "SKIP-OFFLINE")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def run_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%d-%H%M%S")


def _git(*args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", REPO_ROOT, *args],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def repo_evidence() -> dict:
    """Repo identity recorded in every report — never inferred."""
    return {
        "git_head": _git("rev-parse", "HEAD"),
        "git_describe": _git("describe", "--tags", "--always", "--dirty"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "repo_root": REPO_ROOT,
    }


def environment(serial_backend: str, esptool_path: Optional[str]) -> dict:
    env = {
        "utc": utc_now(),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": platform.python_version(),
        "serial_backend": serial_backend,
        "esptool_path": esptool_path,
        "esptool_version": None,
        "hardware_note": (
            "PASS requires real captured evidence; selftest is not HIL; "
            "OFFLINE rigs are SKIP"
        ),
    }
    if esptool_path:
        try:
            out = subprocess.run(
                [esptool_path, "version"],
                capture_output=True, text=True, timeout=15,
            )
            env["esptool_version"] = (out.stdout or out.stderr or "").strip().splitlines()[-1] \
                if (out.stdout or out.stderr).strip() else None
        except (OSError, subprocess.TimeoutExpired):
            env["esptool_version"] = None
    return env


def firmware_evidence(app: str, repo: str = REPO_ROOT) -> dict:
    """Per-app build evidence: binary sha256 + image mtime + project name."""
    build_dir = os.path.join(repo, "firmware", app, "build")
    ev: dict = {"app": app, "build_dir": os.path.relpath(build_dir, repo),
                "present": os.path.isdir(build_dir)}
    desc_path = os.path.join(build_dir, "project_description.json")
    if os.path.isfile(desc_path):
        try:
            with open(desc_path, encoding="utf-8") as fh:
                desc = json.load(fh)
            ev["project_name"] = desc.get("project_name")
            ev["project_version"] = desc.get("project_version")
            ev["idf_version"] = desc.get("idf_version")
        except (json.JSONDecodeError, OSError):
            pass
    bins = [
        f for f in (os.listdir(build_dir) if os.path.isdir(build_dir) else [])
        if f.endswith(".bin") and "bootloader" not in f
        and "partition" not in f
    ]
    if len(bins) == 1:
        import hashlib

        path = os.path.join(build_dir, bins[0])
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        ev["app_bin"] = bins[0]
        ev["app_sha256"] = h.hexdigest()
        ev["app_mtime_utc"] = datetime.datetime.fromtimestamp(
            os.path.getmtime(path), tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ev


@dataclass
class StepResult:
    step: str
    ok: bool
    detail: str = ""
    duration_s: float = 0.0


@dataclass
class ScenarioResult:
    name: str
    verdict: str = "FAIL"          # PASS | FAIL | SKIP-OFFLINE
    detail: str = ""
    steps: list[StepResult] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # paths rel. to run dir
    started_utc: str = field(default_factory=utc_now)
    duration_s: float = 0.0

    def finalize(self, run_dir: str) -> None:
        """Enforce the honesty contract before the verdict is written.

        PASS requires at least one evidence file that exists and is
        non-empty. Anything else is downgraded to FAIL with a note — a
        scenario must never claim success without captured evidence.
        """
        if self.verdict == "PASS":
            real = [
                p for p in self.evidence
                if os.path.isfile(os.path.join(run_dir, p))
                and os.path.getsize(os.path.join(run_dir, p)) > 0
            ]
            if not real:
                self.verdict = "FAIL"
                self.detail = (
                    "verdict downgraded: PASS claimed with no captured "
                    "evidence files (honesty rule — see docs/hil.md). "
                    + self.detail
                )

    def summary_line(self) -> str:
        line = f"[{self.verdict}] {self.name}"
        if self.detail:
            line += f" — {self.detail}"
        line += f" ({self.duration_s:.1f}s)"
        return line

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "detail": self.detail,
            "started_utc": self.started_utc,
            "duration_s": round(self.duration_s, 3),
            "steps": [
                {"step": s.step, "ok": s.ok, "detail": s.detail,
                 "duration_s": round(s.duration_s, 3)}
                for s in self.steps
            ],
            "evidence": self.evidence,
        }


class RunReport:
    """Owns the artifacts/hil/<stamp>-<rig>/ directory for one run."""

    def __init__(self, rig_name: str, artifacts_root: str = ARTIFACTS_ROOT,
                 label: str = ""):
        self.rig_name = rig_name
        suffix = f"-{label}" if label else ""
        self.dir = os.path.join(
            artifacts_root, f"{run_stamp()}-{rig_name}{suffix}")
        os.makedirs(self.dir, exist_ok=True)
        self.results: list[ScenarioResult] = []
        self.meta: dict = {}

    def scenario_dir(self, name: str) -> str:
        path = os.path.join(self.dir, "scenarios", name)
        os.makedirs(path, exist_ok=True)
        return path

    def rel(self, path: str) -> str:
        return os.path.relpath(path, self.dir)

    def write_text(self, rel_path: str, text: str) -> str:
        full = os.path.join(self.dir, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)
        return full

    def add(self, result: ScenarioResult) -> None:
        result.finalize(self.dir)
        self.results.append(result)
        print(result.summary_line())

    def finalize(self) -> dict:
        """Write report.json + summary.txt. Returns the report dict."""
        totals = {v: 0 for v in VERDICTS}
        for r in self.results:
            totals[r.verdict] = totals.get(r.verdict, 0) + 1
        report = {
            "run_id": os.path.basename(self.dir),
            "rig": self.rig_name,
            "generated_utc": utc_now(),
            "meta": self.meta,
            "totals": totals,
            "scenarios": [r.to_json() for r in self.results],
        }
        self.write_text("report.json", json.dumps(report, indent=2) + "\n")
        lines = [r.summary_line() for r in self.results]
        lines.append(
            f"totals: PASS={totals['PASS']} FAIL={totals['FAIL']} "
            f"SKIP-OFFLINE={totals['SKIP-OFFLINE']}"
        )
        self.write_text("summary.txt", "\n".join(lines) + "\n")
        return report


# --------------------------------------------------------------------------
# CLI: inspect an existing run dir
# --------------------------------------------------------------------------

def _latest_run(root: str) -> Optional[str]:
    if not os.path.isdir(root):
        return None
    runs = sorted(
        d for d in os.listdir(root)
        if os.path.isdir(os.path.join(root, d))
    )
    return os.path.join(root, runs[-1]) if runs else None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print the summary of a HIL run directory.")
    parser.add_argument("--run-dir", help="artifacts/hil/<run> directory")
    parser.add_argument("--latest", action="store_true",
                        help="use the newest run under artifacts/hil")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    run_dir = args.run_dir
    if args.latest or not run_dir:
        run_dir = _latest_run(ARTIFACTS_ROOT)
        if not run_dir:
            print("no runs under", ARTIFACTS_ROOT, file=sys.stderr)
            return 2
    report_path = os.path.join(run_dir, "report.json")
    if not os.path.isfile(report_path):
        print(f"no report.json in {run_dir}", file=sys.stderr)
        return 2
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        summary = os.path.join(run_dir, "summary.txt")
        if os.path.isfile(summary):
            print(open(summary, encoding="utf-8").read(), end="")
        else:
            for s in report["scenarios"]:
                print(f"[{s['verdict']}] {s['name']} — {s['detail']}")
        print(f"run: {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
