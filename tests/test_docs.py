"""Generated documents match the code that generates them."""

from __future__ import annotations

from pathlib import Path

from unitlint.rulebook import REGISTRY, full_markdown

ROOT = Path(__file__).resolve().parent.parent


def test_rules_markdown_is_current():
    on_disk = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert on_disk == full_markdown(), "run `unitlint rules --markdown > docs/rules.md`"


def test_readme_states_the_right_rule_count():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{len(REGISTRY)} rules" in readme
    assert "zero" in readme.lower()


def test_chinese_readme_exists_and_is_not_a_stub():
    text = (ROOT / "README_CN.md").read_text(encoding="utf-8")
    assert len(text) > 2000
    assert "drop-in" in text


def test_changelog_records_the_first_release():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "0.1.0" in text


def test_docs_folder_has_the_attack_guide():
    assert (ROOT / "docs" / "attack-guide.md").is_file()
