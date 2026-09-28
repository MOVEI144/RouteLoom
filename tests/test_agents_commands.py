"""AGENTS.md may only name commands, paths and crates that exist."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_docs  # noqa: E402


class AgentsCommandsTest(unittest.TestCase):
    def test_repository_agents_md_passes_and_a_missing_tool_fails(self) -> None:
        self.assertEqual(check_docs.agents_command_problems(ROOT), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "host/routeloom-host").mkdir(parents=True)
            (root / "host/routeloom-host/Cargo.toml").write_text("", encoding="utf-8")
            (root / "tools").mkdir()
            shutil.copyfile(ROOT / "tools/check_docs.py", root / "tools/check_docs.py")
            filler = "\n".join(f"line {i}" for i in range(60))
            (root / "AGENTS.md").write_text(
                "# t\n```sh\npython3 tools/check_docs.py && python3 tools/check_gone.py\n"
                "cd host && cargo test -p routeloom-host && cargo test -p routeloom-gone\n```\n" + filler + "\n",
                encoding="utf-8")
            problems = check_docs.agents_command_problems(root)
        self.assertEqual(len(problems), 2, problems)
        self.assertIn("tools/check_gone.py", problems[0])
        self.assertIn("routeloom-gone", problems[1])


if __name__ == "__main__":
    unittest.main()
