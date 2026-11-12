"""Shared helpers for the test suite."""

from __future__ import annotations

from unitlint import engine
from unitlint.merge import ScanContext, build_units
from unitlint.model import Report, Unit


def vendor(text: str, name: str = "x.service") -> tuple[Unit, ScanContext]:
    """One vendor unit, no drop-ins."""
    context = build_units({f"usr/lib/systemd/system/{name}": text}, complete=False)
    return context.units[name], context


def tree(files: dict[str, str]) -> ScanContext:
    return build_units(files, label="<test>", complete=True)


def fired(unit: Unit, context: ScanContext) -> set[str]:
    return engine.run(unit, context).fired


def report(unit: Unit, context: ScanContext) -> Report:
    return engine.run(unit, context)


def messages(unit: Unit, context: ScanContext, rule: str) -> list[str]:
    return [finding.message for finding in engine.run(unit, context).findings if finding.rule == rule]
