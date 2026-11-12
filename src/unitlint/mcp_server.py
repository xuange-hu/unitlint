"""MCP facade: seven tools over the same engine the CLI runs.

Every tool is a thin wrapper over a function that already exists in this
package, so what an agent sees and what a human runs cannot drift apart. The
import of the optional ``mcp`` extra stays inside :func:`build_server`, which is
what keeps the core package dependency-free.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import demo, engine, render
from .cli import load
from .merge import build_units
from .rulebook import BY_ID, table


def _failed(reports, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = engine.SEVERITIES.index(fail_on)
    return any(engine.SEVERITIES.index(f.severity) >= threshold for r in reports for f in r.findings)


def unitlint_scan(path: str, fail_on: str = "high", unit: str | None = None) -> str:
    """Audit a unit file, a directory of units, or a mounted root filesystem.

    Each report names the unit, its merge chain and one block per finding with
    the file, line and byte offset. fail_on accepts none, note, low, medium,
    high or critical and controls the PASS/FAIL header.
    """
    target = Path(path)
    if not target.exists():
        return f"unitlint: no such file or directory: {path}"
    context = load(target)
    if unit is None:
        reports = engine.scan(context)
    else:
        found = context.unit(unit)
        if found is None:
            return f"unitlint: no unit named {unit}. Known: {', '.join(sorted(context.units)) or 'none'}"
        reports = [engine.run(found, context)]
    if not reports:
        return f"unitlint: no unit files under {path}"

    totals = engine.totals(reports)
    verdict = "FAIL" if _failed(reports, fail_on) else "PASS"
    blocks = [render.text(report, color=False) for report in reports if report.count]
    if not blocks:
        blocks = [f"no findings in {totals['units']} unit(s)"]
    header = (
        f"{verdict} at fail_on={fail_on}  "
        f"units={totals['units']} findings={totals['findings']} risk={totals['risk']}/100\n"
    )
    return header + "\n" + "\n".join(blocks)


def unitlint_text(text: str, name: str = "inline.service", fail_on: str = "high") -> str:
    """Audit unit text passed in directly, without touching the filesystem.

    Useful when the unit comes from a pull request, a chat message or a rendered
    template. Cross-unit rules that need the rest of the tree stay silent,
    because there is no tree.
    """
    context = build_units({name: text}, label=name, complete=False)
    unit = context.units.get(name)
    if unit is None:
        return f"unitlint: {name} does not look like a unit file name (.service, .socket, .timer, ...)"
    report = engine.run(unit, context)
    verdict = "FAIL" if _failed([report], fail_on) else "PASS"
    return f"{verdict} at fail_on={fail_on}\n\n" + render.text(report, color=False)


def unitlint_why(path: str, unit: str, directive: str) -> str:
    """Show which file and line set a directive last, and what it overrode.

    This is the drop-in question: the base unit says ProtectSystem=strict, the
    service is not protected, and the answer is the last line of this chain.
    """
    target = Path(path)
    if not target.exists():
        return f"unitlint: no such file or directory: {path}"
    context = load(target)
    found = context.unit(unit)
    if found is None:
        return f"unitlint: no unit named {unit}. Known: {', '.join(sorted(context.units)) or 'none'}"
    entries = engine.provenance(found, directive)
    if not entries:
        return f"{unit}: no directive named {directive} in any contributing file"
    return render.why_text(found.name, directive, entries)


def unitlint_rules(stage: int | None = None, severity: str | None = None) -> str:
    """List the rule table as id, severity, stage and title, filterable by
    stage (1 single unit, 2 assembled unit and relations) or severity."""
    rows = table(stage=stage, severity=severity)
    if not rows:
        return "unitlint: no rules match that filter"
    lines = [f"{rule.id}  {rule.severity:<8s} stage {rule.stage}  {rule.title}" for rule in rows]
    return "\n".join(lines) + f"\n\n{len(rows)} rules"


def unitlint_explain(rule: str) -> str:
    """Explain one rule: what it detects, why it matters, and the fix."""
    wanted = rule.strip().upper()
    found = BY_ID.get(wanted)
    if found is None:
        return f"unitlint: no rule {wanted}. Known ids: {', '.join(sorted(BY_ID))}"
    return (
        f"{found.id}  {found.title}\n"
        f"severity: {found.severity} (weight {found.score})   stage: {found.stage}\n\n"
        f"why it matters\n{found.why}\n\n"
        f"fix\n{found.fix}"
    )


def unitlint_sarif(path: str, unit: str | None = None) -> str:
    """Audit a tree and return SARIF 2.1.0, ready for a code-scanning upload."""
    target = Path(path)
    if not target.exists():
        return f"unitlint: no such file or directory: {path}"
    context = load(target)
    if unit is None:
        reports = engine.scan(context)
    else:
        found = context.unit(unit)
        if found is None:
            return f"unitlint: no unit named {unit}"
        reports = [engine.run(found, context)]
    return render.to_sarif(reports)


def unitlint_demo() -> str:
    """Audit a built-in tree of units that between them trigger every rule.

    One call proves the parser, the merge and the whole table work end to end,
    with no files of your own needed.
    """
    reports = demo.reports()
    totals = engine.totals(reports)
    lines = [render.brief(report) for report in reports if report.count]
    fired, total = demo.coverage()
    lines.append("")
    lines.append(f"units={totals['units']} findings={totals['findings']} risk={totals['risk']}/100")
    lines.append(f"rules fired: {len(fired)}/{total}")
    missing = demo.missing_rules()
    lines.append("NOT fired: " + " ".join(missing) if missing else "every rule fired")
    return "\n".join(lines)


def tool_manifest() -> list[dict[str, str]]:
    """Names and descriptions, for a CLI self-check and for tests."""
    tools = [
        unitlint_scan,
        unitlint_text,
        unitlint_why,
        unitlint_rules,
        unitlint_explain,
        unitlint_sarif,
        unitlint_demo,
    ]
    return [{"name": tool.__name__, "description": tool.__doc__ or ""} for tool in tools]


def build_server() -> Any:
    """Build the MCP server, importing the optional extra lazily."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("unitlint")
    for tool in (
        unitlint_scan,
        unitlint_text,
        unitlint_why,
        unitlint_rules,
        unitlint_explain,
        unitlint_sarif,
        unitlint_demo,
    ):
        server.tool()(tool)
    return server


def main() -> None:  # pragma: no cover - requires the mcp extra
    build_server().run()


__all__ = ["build_server", "main", "tool_manifest"]


if __name__ == "__main__":  # pragma: no cover
    main()
