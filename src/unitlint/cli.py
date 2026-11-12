"""The command line.

Exit codes follow the usual convention so the tool can gate a CI job: 0 when
nothing at or above ``--fail-on`` was found, 1 when something was, 2 when the
input could not be read at all.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import demo, engine, render
from .__about__ import __version__
from .merge import ScanContext, build_unit_from_file, build_units, collect_from_disk
from .model import Report
from .rulebook import REGISTRY, SEVERITIES, table

_SKIP_SUFFIXES = (".d",)


def _configure_output() -> None:
    """Windows defaults to a legacy code page; findings carry byte offsets."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:  # pragma: no branch - always present on 3.10+
            with contextlib.suppress(ValueError, OSError):  # pragma: no cover
                reconfigure(encoding="utf-8", errors="replace")


def _threshold(name: str) -> int:
    return SEVERITIES.index(name)


def _failed(report: Report, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _threshold(fail_on)
    return any(_threshold(finding.severity) >= threshold for finding in report.findings)


def load(path: Path) -> ScanContext:
    """Build a scan context from a unit file, a directory, or a root filesystem."""
    if not path.exists():
        raise FileNotFoundError(str(path))
    if path.is_file():
        return build_unit_from_file(path)
    files, skipped = collect_from_disk(path)
    context = build_units(files, label=str(path), complete=True)
    for entry in skipped:
        context.strays.append((entry, "", "unreadable"))
    return context


def _select(context: ScanContext, wanted: str | None) -> list[Report]:
    if not wanted:
        return engine.scan(context)
    unit = context.unit(wanted)
    if unit is None:
        raise KeyError(wanted)
    return [engine.run(unit, context)]


def _cmd_scan(args: argparse.Namespace) -> int:
    reports: list[Report] = []
    try:
        for raw in args.paths:
            context = load(Path(raw))
            reports.extend(_select(context, args.unit))
    except FileNotFoundError as missing:
        print(f"unitlint: no such file or directory: {missing}", file=sys.stderr)
        return 2
    except KeyError as missing:
        print(f"unitlint: no unit named {missing.args[0]} in that tree", file=sys.stderr)
        return 2

    if not reports:
        print("unitlint: no unit files found", file=sys.stderr)
        return 2

    totals = engine.totals(reports)
    color = not args.no_color and sys.stdout.isatty()

    if args.json:
        print(render.to_json(reports, totals))
    elif args.sarif:
        print(render.to_sarif(reports))
    elif not args.quiet:
        for report in reports:
            print(render.text(report, color=color))
        print(
            f"{totals['units']} unit(s), {totals['findings']} finding(s), "
            f"risk={totals['risk']}/100  "
            + "  ".join(f"{name}={totals['by_severity'].get(name, 0)}" for name in SEVERITIES)
        )

    return 1 if any(_failed(report, args.fail_on) for report in reports) else 0


def _cmd_why(args: argparse.Namespace) -> int:
    try:
        context = load(Path(args.path))
    except FileNotFoundError:
        print(f"unitlint: no such file or directory: {args.path}", file=sys.stderr)
        return 2

    unit = context.unit(args.unit)
    if unit is None:
        known = ", ".join(sorted(context.units)) or "none"
        print(f"unitlint: no unit named {args.unit}. Known: {known}", file=sys.stderr)
        return 2

    entries = engine.provenance(unit, args.directive)
    if args.json:
        payload = {"unit": unit.name, "directive": args.directive, "entries": entries}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if entries else 1
    print(render.why_text(unit.name, args.directive, entries))
    return 0 if entries else 1


def _cmd_rules(args: argparse.Namespace) -> int:
    rows = table(stage=args.stage, severity=args.severity)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": rule.id,
                        "title": rule.title,
                        "severity": rule.severity,
                        "score": rule.score,
                        "stage": rule.stage,
                        "why": rule.why,
                        "fix": rule.fix,
                    }
                    for rule in rows
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if args.markdown:
        from .rulebook import full_markdown

        # write(), not print(): the generated document ends with its own
        # newline, and `unitlint rules --markdown > docs/rules.md` has to
        # reproduce it byte for byte or the CI docs job diffs forever.
        sys.stdout.write(full_markdown())
        return 0
    for rule in rows:
        print(f"{rule.id}  {rule.severity:<8s} stage {rule.stage}  {rule.title}")
    print(f"\n{len(rows)} rules")
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    wanted = args.rule.strip().upper()
    for rule in REGISTRY:
        if rule.id == wanted:
            print(f"{rule.id}  {rule.title}")
            print(f"severity: {rule.severity} (weight {rule.score})   stage: {rule.stage}")
            print(f"\nwhy it matters\n{rule.why}")
            print(f"\nfix\n{rule.fix}")
            return 0
    print(f"unitlint: no rule {wanted}", file=sys.stderr)
    return 2


def _cmd_demo(args: argparse.Namespace) -> int:
    reports = demo.reports()
    color = not args.no_color and sys.stdout.isatty()
    totals = engine.totals(reports)
    if args.json:
        print(render.to_json(reports, totals))
        return 0 if not demo.missing_rules() else 1
    if not args.quiet:
        for report in reports:
            print(render.text(report, color=color))
    fired, total = demo.coverage()
    print(f"units: {totals['units']}, findings: {totals['findings']}, risk: {totals['risk']}/100")
    print(f"rules fired: {len(fired)}/{total}")
    missing = demo.missing_rules()
    if missing:
        print(f"NOT fired: {' '.join(missing)}")
        return 1
    print("every rule in the table has a sample that triggers it")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unitlint",
        description="Audit systemd units the way systemd assembles them: search path, drop-ins, overrides.",
    )
    parser.add_argument("--version", action="version", version=f"unitlint {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit a unit file, a directory, or a root filesystem")
    scan.add_argument("paths", nargs="+", help="file, unit directory, or rootfs")
    scan.add_argument("--unit", help="only this unit name, e.g. web-api.service")
    scan.add_argument("--json", action="store_true", help="JSON report")
    scan.add_argument("--sarif", action="store_true", help="SARIF 2.1.0, one run for every unit")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--quiet", action="store_true", help="no report, exit code only")
    scan.add_argument(
        "--fail-on",
        choices=["none", *SEVERITIES],
        default="high",
        help="exit 1 at or above this severity (default: high)",
    )
    scan.set_defaults(func=_cmd_scan)

    why = sub.add_parser("why", help="show who set a directive last, and what it overrode")
    why.add_argument("path", help="unit file, unit directory, or rootfs")
    why.add_argument("unit", help="unit name, e.g. web-api.service")
    why.add_argument("directive", help="directive name, e.g. NoNewPrivileges")
    why.add_argument("--json", action="store_true")
    why.set_defaults(func=_cmd_why)

    rules = sub.add_parser("rules", help="list the rule table")
    rules.add_argument("--json", action="store_true")
    rules.add_argument("--markdown", action="store_true", help="full table for docs/rules.md")
    rules.add_argument("--stage", type=int, choices=[1, 2], help="only one stage")
    rules.add_argument("--severity", choices=list(SEVERITIES), help="only one severity")
    rules.set_defaults(func=_cmd_rules)

    explain = sub.add_parser("explain", help="one rule: what it detects and how to fix it")
    explain.add_argument("rule", help="rule id, e.g. UNT101")
    explain.set_defaults(func=_cmd_explain)

    show = sub.add_parser("demo", help="audit the built-in tree that fires every rule")
    show.add_argument("--json", action="store_true")
    show.add_argument("--no-color", action="store_true")
    show.add_argument("--quiet", action="store_true")
    show.set_defaults(func=_cmd_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_output()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
