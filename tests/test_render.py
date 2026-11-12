"""Rendering: text, JSON and SARIF carry the same evidence."""

from __future__ import annotations

import json

from helpers import report, tree, vendor

from unitlint import engine, render


def _one():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nUser=app\nExecStart=/tmp/app --flag\n",
        }
    )
    return report(context.units["a.service"], context)


def test_text_names_file_line_and_offset():
    text = render.text(_one())
    assert "UNT003" in text
    assert "/usr/lib/systemd/system/a.service:3" in text
    assert "offset 0x" in text
    assert "saw:" in text


def test_text_without_findings_says_so():
    context = tree({"usr/lib/systemd/system/app.target": "[Unit]\nDescription=t\n"})
    text = render.text(report(context.units["app.target"], context))
    assert "no findings" in text


def test_json_dict_matches_the_findings():
    payload = render.json_dict(_one())
    assert payload["summary"]["findings"] == len(payload["findings"])
    assert payload["unit"]["name"] == "a.service"
    assert payload["unit"]["base"]["role"] == "vendor"
    assert payload["unit"]["sections"] == ["Service"]


def test_json_dict_for_a_context_report_has_no_unit():
    context = tree({"etc/systemd/system/a.service.d/README": "x\n"})
    reports = engine.scan(context)
    stray = [item for item in reports if item.unit is None][0]
    assert render.json_dict(stray)["unit"] is None


def test_to_json_wraps_reports_with_totals():
    context = tree({"usr/lib/systemd/system/a.service": "[Service]\nExecStart=/tmp/app\n"})
    reports = engine.scan(context)
    payload = json.loads(render.to_json(reports, engine.totals(reports)))
    assert payload["tool"] == "unitlint"
    assert payload["version"]
    assert payload["summary"]["units"] == 1
    assert payload["reports"][0]["findings"]


def test_sarif_structure():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nUser=app\nExecStart=/tmp/app\n",
            "usr/lib/systemd/system/b.service": "[Service]\nExecStart=/usr/bin/b\n",
        }
    )
    payload = render.sarif(engine.scan(context))
    run = payload["runs"][0]
    assert run["tool"]["driver"]["informationUri"].endswith("unitlint")
    ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert ids == sorted(ids)
    assert all(rule["fullDescription"]["text"] for rule in run["tool"]["driver"]["rules"])
    for result in run["results"]:
        assert result["level"] in {"error", "warning", "note"}
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        if "byteLength" in region:
            assert region["byteOffset"] >= 0


def test_sarif_uri_uses_forward_slashes():
    unittest_context = tree({"usr/lib/systemd/system/a.service": "[Service]\nExecStart=/tmp/app\n"})
    payload = render.sarif(engine.scan(unittest_context))
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_sarif_level_mapping():
    assert render._sarif_level("critical") == "error"
    assert render._sarif_level("high") == "error"
    assert render._sarif_level("medium") == "warning"
    assert render._sarif_level("low") == "note"


def test_brief_is_one_line():
    line = render.brief(_one())
    assert "\n" not in line
    assert "worst=" in line and "risk=" in line


def test_why_text_explains_an_empty_result():
    assert "no directive named" in render.why_text("a.service", "User", [])


def test_why_text_marks_the_effective_line():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nUser=app\n",
            "etc/systemd/system/a.service.d/9.conf": "[Service]\nUser=nobody\n",
        }
    )
    unit = context.units["a.service"]
    entries = engine.provenance(unit, "User")
    text = render.why_text(unit.name, "User", entries)
    assert "->  nobody" in text
    assert "<= effective" in text
    # History is printed in merge order: the vendor line first, the override last.
    assert text.index("/usr/lib/systemd/system/a.service:2") < text.index("a.service.d/9.conf:2")


def test_vendor_helper_is_importable():
    unit, context = vendor("[Service]\nExecStart=/usr/bin/a\n")
    assert unit.name == "x.service"
    assert engine.run(unit, context).rules_run > 40
