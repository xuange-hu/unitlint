"""Render reports as text, JSON or SARIF.

The text form leads with the severity, the rule id and the file:line that
produced the finding, then the raw bytes. The SARIF form carries the same byte
offset, so a finding in a code-scanning UI and a finding in the file point at
the same character.
"""

from __future__ import annotations

import json
from typing import Any

from .__about__ import __version__
from .model import Report, Unit
from .rulebook import BY_ID

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "note")

_ANSI = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "note": "\033[2m",
}
_RESET = "\033[0m"


def _paint(text: str, severity: str, color: bool) -> str:
    if not color:
        return text
    return f"{_ANSI.get(severity, '')}{text}{_RESET}"


def _summary_line(report: Report) -> str:
    counts = report.by_severity()
    parts = "  ".join(f"{name}={counts.get(name, 0)}" for name in _SEVERITY_ORDER)
    return f"{report.count} finding(s)  {parts}  risk={report.risk}/100"


def _unit_line(unit: Unit | None) -> str:
    if unit is None:
        return ""
    pieces = [f"kind={unit.kind}"]
    if unit.base is not None:
        pieces.append(f"base={unit.base.path} ({unit.base.role})")
    else:
        pieces.append("base=<none>")
    if unit.dropins:
        pieces.append("drop-ins=" + ", ".join(dropin.basename for dropin in unit.dropins))
    if unit.replaced:
        pieces.append("replaced=" + ", ".join(file.path for file in unit.replaced))
    if unit.shadowed:
        pieces.append("shadowed=" + ", ".join(file.basename for file in unit.shadowed))
    return "  " + "  ".join(pieces)


def text(report: Report, color: bool = False) -> str:
    """The terminal report for one unit."""
    lines = [report.source]
    detail = _unit_line(report.unit)
    if detail:
        lines.append(detail)
    lines.append("  " + _summary_line(report))
    lines.append("")

    if not report.findings:
        lines.append("  no findings")
        lines.append("")
        return "\n".join(lines)

    for finding in report.findings:
        rule = BY_ID.get(finding.rule)
        title = rule.title if rule else finding.rule
        head = f"[{finding.severity:<8s}] {finding.rule}  {title}"
        lines.append(_paint(head, finding.severity, color))
        lines.append(f"           {finding.message}")
        where = f"{finding.where}:{finding.line}"
        if finding.length:
            where += f", offset 0x{finding.offset:x}+{finding.length}"
        lines.append(f"           {where}")
        if finding.saw:
            lines.append(f"           saw:  {finding.saw}")
        if finding.fix:
            lines.append(f"           fix:  {finding.fix}")
        lines.append("")

    return "\n".join(lines)


def brief(report: Report) -> str:
    """One line per unit, for a tree scan."""
    counts = report.by_severity()
    worst = next((name for name in _SEVERITY_ORDER if counts.get(name)), "-")
    return f"{report.source}: {report.count} finding(s), worst={worst}, risk={report.risk}/100"


def json_dict(report: Report) -> dict[str, Any]:
    """The machine-readable report for one unit."""
    counts = report.by_severity()
    unit = report.unit
    return {
        "source": report.source,
        "summary": {
            "findings": report.count,
            "risk": report.risk,
            "by_severity": {name: counts.get(name, 0) for name in _SEVERITY_ORDER},
            "by_rule": report.by_rule(),
            "rules_run": report.rules_run,
        },
        "unit": None
        if unit is None
        else {
            "name": unit.name,
            "kind": unit.kind,
            "base": None if unit.base is None else {"path": unit.base.path, "role": unit.base.role},
            "dropins": [{"path": dropin.path, "basename": dropin.basename} for dropin in unit.dropins],
            "replaced": [{"path": file.path, "role": file.role} for file in unit.replaced],
            "shadowed": [{"path": file.path, "basename": file.basename} for file in unit.shadowed],
            "sections": [entry[0] for entry in unit.declared],
            "errors": [error for file in unit.files for error in file.errors],
        },
        "findings": [
            {
                "rule": finding.rule,
                "severity": finding.severity,
                "message": finding.message,
                "where": finding.where,
                "line": finding.line,
                "offset": finding.offset,
                "length": finding.length,
                "saw": finding.saw,
                "fix": finding.fix,
                "score": finding.score,
            }
            for finding in report.findings
        ],
    }


def to_json(reports: list[Report], totals: dict | None = None, indent: int = 2) -> str:
    payload: dict[str, Any] = {
        "tool": "unitlint",
        "version": __version__,
        "summary": totals or {},
        "reports": [json_dict(report) for report in reports],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _descriptor(rule_id: str) -> dict[str, Any] | None:
    rule = BY_ID.get(rule_id)
    if rule is None:  # pragma: no cover - every emitted id comes from the table
        return None
    return {
        "id": rule.id,
        "name": rule.title.replace(" ", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.why},
        "help": {"text": f"{rule.why}\n\nFix: {rule.fix}"},
        "defaultConfiguration": {"level": _sarif_level(rule.severity)},
        "properties": {"security-severity": str(rule.score), "stage": rule.stage},
    }


def sarif(reports: list[Report]) -> dict[str, Any]:
    """SARIF 2.1.0 for one or more reports, in a single run."""
    descriptors: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for report in reports:
        for finding in report.findings:
            if finding.rule not in descriptors:
                descriptor = _descriptor(finding.rule)
                if descriptor is not None:
                    descriptors[finding.rule] = descriptor
            region: dict[str, Any] = {"startLine": max(finding.line, 1)}
            if finding.length:
                region["byteOffset"] = finding.offset
                region["byteLength"] = finding.length
            results.append(
                {
                    "ruleId": finding.rule,
                    "level": _sarif_level(finding.severity),
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.where.replace("\\", "/")},
                                "region": region,
                            }
                        }
                    ],
                    "properties": {"saw": finding.saw, "fix": finding.fix, "score": finding.score},
                }
            )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "unitlint",
                        "version": __version__,
                        "informationUri": "https://github.com/xuange-hu/unitlint",
                        "rules": [descriptors[key] for key in sorted(descriptors)],
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif(reports: list[Report]) -> str:
    return json.dumps(sarif(reports), indent=2, ensure_ascii=False)


def why_text(unit_name: str, directive: str, entries: list[dict]) -> str:
    """The ``unitlint why`` body: the winner first, then who it beat."""
    if not entries:
        return f"{unit_name}: no directive named {directive}"
    lines: list[str] = []
    for entry in entries:
        effective = entry["effective"]
        shown = "(reset to default)" if effective is None else effective
        lines.append(f"{unit_name}  {entry['name']}  ->  {shown}")
        lines.append(f"  section [{entry['section']}]")
        history = entry["history"]
        for index, directive in enumerate(history):
            marker = "  <= effective" if index == len(history) - 1 else ""
            tag = "dropin" if directive["dropin"] else directive["role"]
            value = "(reset)" if directive["empty_reset"] else directive["value"]
            lines.append(
                f"    {directive['source']}:{directive['line']}  {value:<24s} "
                f"{tag} priority {directive['priority']}{marker}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


__all__ = ["brief", "json_dict", "sarif", "text", "to_json", "to_sarif", "why_text"]
