"""The command line: exit codes, output modes, and each subcommand."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unitlint.cli import main
from unitlint.rulebook import full_markdown

ROOT = Path(__file__).resolve().parent.parent
DEMO_TREE = ROOT / "examples" / "rootfs"


def run(capsys, *argv: str) -> tuple[int, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0


def test_scan_tree_fails_on_high(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE))
    assert code == 1
    assert "risk=" in out
    assert "UNT101" in out


def test_scan_with_fail_on_none_succeeds(capsys):
    code, _out = run(capsys, "scan", str(DEMO_TREE), "--fail-on", "none", "--quiet")
    assert code == 0


def test_scan_quiet_prints_nothing(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE), "--quiet")
    assert code == 1
    assert out == ""


def test_scan_json_shape(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE), "--json")
    assert code == 1
    payload = json.loads(out)
    assert payload["tool"] == "unitlint"
    assert payload["summary"]["units"] >= 15
    assert payload["summary"]["findings"] > 40
    assert payload["reports"][0]["unit"]["name"]
    rules = {finding["rule"] for report in payload["reports"] for finding in report["findings"]}
    assert "UNT101" in rules


def test_scan_sarif_is_one_run(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE), "--sarif")
    assert code == 1
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"]) == 1
    assert payload["runs"][0]["tool"]["driver"]["name"] == "unitlint"
    assert payload["runs"][0]["results"]


def test_scan_single_unit(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE), "--unit", "report.service", "--json")
    assert code == 1
    payload = json.loads(out)
    assert len(payload["reports"]) == 1
    assert payload["reports"][0]["unit"]["name"] == "report.service"
    assert {"UNT012", "UNT013", "UNT019"} <= {f["rule"] for f in payload["reports"][0]["findings"]}


def test_scan_unknown_unit_is_an_input_error(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE), "--unit", "nope.service")
    assert code == 2
    assert "no unit named" in out


def test_scan_missing_path_is_an_input_error(capsys):
    code, out = run(capsys, "scan", str(ROOT / "does-not-exist"))
    assert code == 2
    assert "no such file or directory" in out


def test_scan_a_single_file(tmp_path: Path, capsys):
    unit = tmp_path / "a.service"
    unit.write_text("[Service]\nUser=app\nExecStart=/usr/bin/app\n", encoding="utf-8")
    code, out = run(capsys, "scan", str(unit), "--fail-on", "none")
    assert code == 0
    assert "a.service" in out


def test_scan_directory_without_units_is_an_input_error(tmp_path: Path, capsys):
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    code, out = run(capsys, "scan", str(tmp_path))
    assert code == 2
    assert "no unit files" in out


def test_why_shows_the_whole_chain(capsys):
    code, out = run(capsys, "why", str(DEMO_TREE), "web-api.service", "NoNewPrivileges")
    assert code == 0
    assert "->  no" in out
    assert "yes" in out
    assert "<= effective" in out
    assert "99-debug.conf" in out


def test_why_json(capsys):
    code, out = run(capsys, "why", str(DEMO_TREE), "web-api.service", "protectsystem", "--json")
    assert code == 0
    payload = json.loads(out)
    assert payload["unit"] == "web-api.service"
    assert payload["entries"][0]["effective"] == "no"
    assert len(payload["entries"][0]["history"]) == 2


def test_why_unknown_directive_exits_one(capsys):
    code, out = run(capsys, "why", str(DEMO_TREE), "web-api.service", "NoSuchKey")
    assert code == 1
    assert "no directive named" in out


def test_why_unknown_unit_exits_two(capsys):
    code, out = run(capsys, "why", str(DEMO_TREE), "nope.service", "User")
    assert code == 2
    assert "Known:" in out


def test_rules_text(capsys):
    code, out = run(capsys, "rules")
    assert code == 0
    assert "UNT101" in out
    assert out.strip().endswith("rules")


def test_rules_json(capsys):
    code, out = run(capsys, "rules", "--json")
    assert code == 0
    rows = json.loads(out)
    assert rows[0]["id"].startswith("UNT")
    assert all(row["why"] for row in rows)


def test_rules_markdown_is_byte_stable(capsys):
    code, out = run(capsys, "rules", "--markdown")
    assert code == 0
    assert out == full_markdown()


def test_rules_stage_filter(capsys):
    code, out = run(capsys, "rules", "--stage", "2", "--json")
    assert code == 0
    rows = json.loads(out)
    assert rows and all(row["stage"] == 2 for row in rows)


def test_rules_severity_filter(capsys):
    code, out = run(capsys, "rules", "--severity", "high", "--json")
    assert code == 0
    assert all(row["severity"] == "high" for row in json.loads(out))


def test_explain_known_rule(capsys):
    code, out = run(capsys, "explain", "unt101")
    assert code == 0
    assert "drop-in" in out
    assert "why it matters" in out


def test_explain_unknown_rule_exits_two(capsys):
    code, out = run(capsys, "explain", "UNT999")
    assert code == 2
    assert "no rule" in out


def test_demo_covers_every_rule(capsys):
    code, out = run(capsys, "demo", "--quiet")
    assert code == 0
    assert "every rule in the table has a sample" in out


def test_demo_json(capsys):
    code, out = run(capsys, "demo", "--json")
    assert code == 0
    payload = json.loads(out)
    assert payload["summary"]["units"] >= 15


def test_no_color_flag_is_accepted_after_the_subcommand(capsys):
    code, out = run(capsys, "scan", str(DEMO_TREE), "--no-color", "--fail-on", "none")
    assert code == 0
    assert "\033[" not in out


def test_module_entry_point_importable():
    import unitlint.__main__ as entry

    assert entry.main is not None
