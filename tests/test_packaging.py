"""Packaging contracts a `pip install` would otherwise break silently.

The console script is the first thing a new user runs, so a script pointing at a
module that imports a third-party package at module scope fails for everyone who
installed without the extra -- while CI, which installs `.[all]`, stays green.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import unitlint
from unitlint.__about__ import __version__

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_version_matches_pyproject():
    declared = re.search(r'^version = "([^"]+)"', PYPROJECT, re.MULTILINE)
    assert declared is not None
    assert declared.group(1) == __version__ == unitlint.__version__


def test_console_scripts_resolve():
    block = PYPROJECT.split("[project.scripts]", 1)[1].split("[", 1)[0]
    targets = dict(re.findall(r'^(\S+) = "([^"]+)"', block, re.MULTILINE))
    assert set(targets) == {"unitlint", "unitlint-mcp"}
    for module_path, attribute in (target.split(":") for target in targets.values()):
        module = __import__(module_path, fromlist=[attribute])
        assert callable(getattr(module, attribute))


def test_core_package_imports_nothing_third_party():
    stdlib_or_local = {
        "__future__",
        "argparse",
        "collections",
        "contextlib",
        "dataclasses",
        "json",
        "pathlib",
        "re",
        "sys",
        "typing",
    }
    offenders: list[str] = []
    for path in sorted((ROOT / "src" / "unitlint").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:  # module scope only: a lazy import is fine
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]] if node.level == 0 else []
            else:
                continue
            offenders.extend(f"{path.name}: {name}" for name in names if name and name not in stdlib_or_local)
    assert offenders == []


def test_mcp_is_imported_lazily():
    text = (ROOT / "src" / "unitlint" / "mcp_server.py").read_text(encoding="utf-8")
    top_level = [line for line in text.splitlines() if line.startswith(("import mcp", "from mcp"))]
    assert top_level == []
    assert "from mcp.server.fastmcp import FastMCP" in text


def test_mcp_extra_is_pinned_below_two():
    assert 'mcp = ["mcp>=1.2,<2"]' in PYPROJECT


def test_py_typed_is_shipped():
    assert (ROOT / "src" / "unitlint" / "py.typed").is_file()
    assert 'unitlint = ["py.typed"]' in PYPROJECT


def test_python_floor_is_three_ten():
    assert 'requires-python = ">=3.10"' in PYPROJECT
