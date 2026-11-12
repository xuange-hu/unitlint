"""Unit model: last-wins values, resets, list items, reports, provenance."""

from __future__ import annotations

from helpers import report, vendor

from unitlint import engine
from unitlint.merge import build_units
from unitlint.model import to_bool


def test_last_wins():
    unit, _context = vendor("[Service]\nUser=first\nUser=second\n")
    assert unit.text("Service", "User") == "second"
    assert [d.text for d in unit.present("Service", "User")] == ["first", "second"]


def test_reset_unsets_the_value():
    unit, _context = vendor("[Service]\nUser=app\nUser=\n")
    assert unit.last("Service", "User") is None
    assert unit.text("Service", "User", default="fallback") == "fallback"


def test_flag_and_text_defaults():
    unit, _context = vendor("[Service]\nNoNewPrivileges=yes\nPrivateTmp=maybe\n")
    assert unit.flag("Service", "NoNewPrivileges") is True
    assert unit.flag("Service", "PrivateTmp") is None
    assert unit.flag("Service", "ProtectHome") is None
    assert unit.text("Service", "ProtectHome") == ""
    assert unit.text("Service", "ProtectHome", "no") == "no"


def test_items_split_on_whitespace_but_respect_quotes():
    unit, _context = vendor('[Service]\nEnvironment="A=1 2" B=3\n')
    assert [item.text for item in unit.items("Service", "Environment")] == ["A=1 2", "B=3"]


def test_values_and_every_differ_on_resets():
    unit, _context = vendor("[Service]\nExecStartPre=/bin/a\nExecStartPre=\nExecStartPre=/bin/b\n")
    assert [d.text for d in unit.every("Service", "ExecStartPre")] == ["/bin/a", "", "/bin/b"]
    assert unit.values("Service", "ExecStartPre") == ["/bin/a", "/bin/b"]


def test_has_section_sees_empty_sections():
    unit, _context = vendor("[Service]\nExecStart=/usr/bin/a\n[Install]\n")
    assert unit.has_section("Install") is True
    assert unit.has_section("Timer") is False
    assert unit.sections == {"Service", "Install"}


def test_report_risk_saturates_and_counts_by_severity():
    unit, context = vendor("[Service]\nExecStart=/bin/sh -c /tmp/a\n", name="a.service")
    result = report(unit, context)
    assert result.risk <= 100
    assert sum(result.by_severity().values()) == result.count
    assert result.count > 0
    severities = [finding.severity for finding in result.findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
    assert severities == sorted(severities, key=lambda name: order[name])


def test_report_fired_is_the_rule_set():
    unit, context = vendor("[Service]\nExecStart=/usr/bin/a\n")
    result = report(unit, context)
    assert result.fired == {finding.rule for finding in result.findings}


def test_provenance_lists_the_whole_chain():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nUser=app\nNoNewPrivileges=yes\n",
            "etc/systemd/system/a.service.d/99.conf": "[Service]\nNoNewPrivileges=no\n",
        }
    )
    entries = engine.provenance(context.units["a.service"], "nonewprivileges")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["effective"] == "no"
    assert [item["value"] for item in entry["history"]] == ["yes", "no"]
    assert entry["history"][0]["role"] == "vendor"
    assert entry["history"][1]["dropin"] is True


def test_provenance_is_case_insensitive_and_section_aware():
    unit, _context = vendor("[Service]\nUser=app\n[Install]\nWantedBy=multi-user.target\n")
    assert engine.provenance(unit, "user")[0]["section"] == "Service"
    assert engine.provenance(unit, "wantedby")[0]["section"] == "Install"
    assert engine.provenance(unit, "nope") == []


def test_totals_counts_units_and_findings():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/a\n",
            "usr/lib/systemd/system/b.timer": "[Timer]\nOnCalendar=minutely\n",
        }
    )
    totals = engine.totals(engine.scan(context))
    assert totals["units"] == 2
    assert totals["findings"] == sum(r.count for r in engine.scan(context))
    assert totals["risk"] > 0


def test_to_bool_vocabulary():
    assert to_bool("YES") is True
    assert to_bool("on") is True
    assert to_bool("off") is False
    assert to_bool("2") is None
