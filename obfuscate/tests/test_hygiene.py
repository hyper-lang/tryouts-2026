"""Repo hygiene tests (task 28 / AC9).

1. test_no_multiprocessing_in_package - recursively grep obfuscate/**/*.py for
   'multiprocessing.Process' and 'from multiprocessing' / 'import multiprocessing'
   and assert zero matches (AC9; the 3.13 bug python/cpython#134381 constraint
   is documented in the module docstring).

2. test_cmd_unimplemented_is_gone - assert obfuscate/cli.py has no reachable
   `_cmd_unimplemented` (it was union-reachable dead code since all five subparsers
   have real handlers; the function is deleted).

3. test_auth_reminder_present - import AUTH_REMINDER from obfuscate.cli and assert
   it is non-empty (R1 'every command prints a one-line authorization reminder').
"""

import re
from pathlib import Path

import pytest

from obfuscate.cli import AUTH_REMINDER


class TestHygiene:
    def test_no_multiprocessing_in_package(self):
        """AC9: no multiprocessing.Process anywhere in the package.

        CPython 3.13 bug python/cpython#134381 makes multiprocessing.Process
        broken; ThreadPoolExecutor only.
        """
        pkg_dir = Path(__file__).resolve().parents[1] / "obfuscate"
        offenders = []
        for py in pkg_dir.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            # Look for actual usage patterns
            if re.search(r"\bmultiprocessing\s*\.\s*Process\b", text):
                offenders.append((str(py.relative_to(pkg_dir)), "multiprocessing.Process"))
            if re.search(r"^\s*from\s+multiprocessing\b", text, re.MULTILINE):
                offenders.append((str(py.relative_to(pkg_dir)), "from multiprocessing"))
            if re.search(r"^\s*import\s+multiprocessing\b", text, re.MULTILINE):
                offenders.append((str(py.relative_to(pkg_dir)), "import multiprocessing"))
        assert offenders == [], f"multiprocessing found in: {offenders}"

    def test_cmd_unimplemented_is_gone(self):
        """The `_cmd_unimplemented` function was dead code (all subparsers wired);
        it has been deleted from cli.py."""
        cli_path = Path(__file__).resolve().parents[1] / "obfuscate" / "cli.py"
        text = cli_path.read_text(encoding="utf-8")
        assert "_cmd_unimplemented" not in text, (
            "_cmd_unimplemented still present in cli.py; it should be deleted "
            "since all five subparsers have real handlers"
        )

    def test_auth_reminder_present(self):
        """R1: every command prints a one-line authorization reminder."""
        assert AUTH_REMINDER, "AUTH_REMINDER is empty"
        assert "AUTHORIZATION REMINDER" in AUTH_REMINDER
        assert "CCDC" in AUTH_REMINDER
        assert "team-owned" in AUTH_REMINDER