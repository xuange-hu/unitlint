"""Run the rule table over assembled units.

The engine is deliberately boring: it walks the table, calls each check, sorts
by severity and hands back a report. All the knowledge is in the rules and all
the parsing is in the merge, so a bug in one rule cannot corrupt another's
evidence.
"""

from __future__ import annotations

from . import rules
from .merge import ScanContext
from .model import Finding, Report, Unit
from .rulebook import REGISTRY

SEVERITIES = ("critical", "high", "medium", "low", "note")


def run(unit: Unit, context: ScanContext | None = None) -> Report:
    """Audit one assembled unit."""
    if context is None:
        context = ScanContext(units={unit.name: unit}, label=unit.name, complete=False)
    findings: list[Finding] = []
    ran = 0
    for rule in REGISTRY:
        if rule.check is None:
            continue
        ran += 1
        findings.extend(rule.check(unit, context))
    findings.sort(key=Finding.sort_key)
    return Report(source=unit.label, unit=unit, findings=findings, rules_run=ran)


def scan(context: ScanContext) -> list[Report]:
    """Audit every unit in a tree, plus the files that never became a unit."""
    reports = [run(unit, context) for unit in context.sorted_units()]
    strays = rules.stray_findings(context)
    if strays:
        reports.append(
            Report(
                source=f"{context.label}: files that are not units",
                unit=None,
                findings=strays,
                rules_run=1,
            )
        )
    return reports


def totals(reports: list[Report]) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    for report in reports:
        for name, value in report.by_severity().items():
            counts[name] = counts.get(name, 0) + value
    return {
        "units": sum(1 for report in reports if report.unit is not None),
        "reports": len(reports),
        "findings": sum(report.count for report in reports),
        "risk": min(100, sum(report.risk for report in reports)),
        "by_severity": counts,
    }


def provenance(unit: Unit, name: str) -> list[dict]:
    """Every occurrence of ``name``, per section, with its file and line.

    This is what ``unitlint why`` prints: not just the winning value but the
    whole chain, so a person can see that the hardening line existed and who
    overwrote it.
    """
    wanted = name.strip().lower()
    out: list[dict] = []
    for (section, key), history in sorted(unit.history.items()):
        if key.lower() != wanted:
            continue
        effective = unit.effective.get((section, key))
        out.append(
            {
                "section": section,
                "name": key,
                "effective": None if effective is None else effective.text.strip(),
                "history": [
                    {
                        "value": directive.text.strip(),
                        "empty_reset": directive.is_empty,
                        "source": directive.source,
                        "line": directive.lineno,
                        "role": directive.role,
                        "priority": directive.priority,
                        "dropin": directive.dropin,
                        "raw": directive.raw,
                        "offset": directive.offset,
                    }
                    for directive in history
                ],
            }
        )
    return out


__all__ = ["SEVERITIES", "provenance", "run", "scan", "totals"]
