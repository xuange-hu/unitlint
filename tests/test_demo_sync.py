"""The demo corpus, the tree on disk, and the rule coverage invariant.

``examples/rootfs`` is the tree a reader is invited to inspect. It must be the
same bytes the demo runs on, or the demo is a story about a tree that does not
exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from unitlint import demo, engine
from unitlint.rulebook import REGISTRY

ROOT = Path(__file__).resolve().parent.parent
DEMO_TREE = ROOT / "examples" / "rootfs"


def test_every_rule_fires_in_the_demo():
    fired, total = demo.coverage()
    missing = demo.missing_rules()
    assert missing == [], f"{len(missing)} rule(s) without a sample: {missing}"
    assert len(fired) == total == len(REGISTRY)


def test_demo_findings_are_substantial():
    reports = demo.reports()
    assert len(reports) >= 15
    assert sum(report.count for report in reports) >= 45


def test_demo_tree_exists():
    assert DEMO_TREE.is_dir(), "run python -c 'from unitlint import demo; demo.materialise(...)'"


@pytest.mark.parametrize("relative", sorted(demo.DEMO_FILES))
def test_demo_file_matches_the_tree_on_disk(relative):
    on_disk = (DEMO_TREE / relative).read_text(encoding="utf-8")
    assert on_disk == demo.DEMO_FILES[relative], f"{relative} drifted from demo.DEMO_FILES"


def test_no_extra_files_in_the_demo_tree():
    on_disk = {
        path.relative_to(DEMO_TREE).as_posix()
        for path in DEMO_TREE.rglob("*")
        if path.is_file()
    }
    assert on_disk == set(demo.DEMO_FILES)


def test_demo_tree_scans_the_same_as_the_embedded_corpus():
    from unitlint.cli import load

    from_disk = engine.scan(load(DEMO_TREE))
    from_memory = demo.reports()

    def shape(reports):
        # The label of the "not a unit" report carries the path it was scanned
        # from, which differs by construction; everything else must match.
        return {(report.unit.name, report.count): sorted(report.fired) for report in reports if report.unit is not None}

    assert shape(from_disk) == shape(from_memory)


def test_materialise_is_idempotent(tmp_path: Path):
    first = demo.materialise(tmp_path)
    second = demo.materialise(tmp_path)
    assert [path.name for path in first] == [path.name for path in second]
    for path in first:
        assert path.read_text(encoding="utf-8") == demo.DEMO_FILES[path.relative_to(tmp_path).as_posix()]
