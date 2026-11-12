"""A bare clone can run its own tests.

Every other job installs the package first, which hides a src-layout bootstrap
regression: the root conftest is the only thing that puts ``src`` on the path.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_collection_works_without_the_package_installed():
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # pytest prints "N tests collected" on success; anything else means the
    # import of unitlint failed before collection even started.
    assert "collected" in result.stdout


def test_root_conftest_adds_src():
    text = (ROOT / "conftest.py").read_text(encoding="utf-8")
    assert "src" in text
    assert "sys.path.insert" in text
