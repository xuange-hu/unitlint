"""Discovery and merge: which files make up a unit, and which one wins.

This is the module that makes the tool different from a grep over ``*.service``.
systemd does not read a unit file; it *assembles* one from a search path plus
drop-in directories, and the assembly has three properties that a single-file
scanner cannot see:

1. **A unit in ``/etc`` replaces the vendor unit**, it does not merge with it.
   The vendor copy is dead code from that moment on.
2. **Drop-ins apply in filename order across every search directory**, after
   the base unit -- which is how ``99-debug.conf`` undoes ``ProtectSystem=strict``
   that nobody edited.
3. **The same drop-in filename in two directories is not merged**: the file from
   the higher-priority directory wins and the other one is silently ignored.

The merge keeps the full chain of directives, not just the winner, so
``unitlint why`` can show who overrode whom.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path

from .model import Directive, Unit, UnitFile
from .parser import parse_unit_text

#: Search path, highest priority first. systemd has generator and transient
#: directories above these; they hold no hand-written units, so naming them
#: would only add noise to every finding's "role" label.
SEARCH_DIRS: tuple[tuple[str, str, int], ...] = (
    ("etc/systemd/system", "admin", 0),
    ("run/systemd/system", "run", 1),
    ("usr/local/lib/systemd/system", "local", 2),
    ("usr/lib/systemd/system", "vendor", 3),
    ("lib/systemd/system", "vendor", 4),
)

UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".swap",
    ".slice",
    ".scope",
    ".device",
    ".target",
)

#: Used when a file sits outside every known search directory: a flat directory
#: of units, a container build context, a git checkout. Lowest priority so a
#: real admin file in the same tree still wins.
FALLBACK_ROLE = "vendor"
FALLBACK_PRIORITY = 9


def normalise(path: str) -> str:
    """POSIX-ish, no leading ``./``, no backslashes."""
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def classify(path: str) -> tuple[str, str, int, str, str, str]:
    """Return ``(display, role, priority, kind, unit_name, basename)``.

    ``kind`` is ``base``, ``dropin`` or ``stray``. ``stray`` means the file lives
    inside a ``.d`` directory but does not end in ``.conf``, so systemd ignores
    it outright -- an override that looks applied and is not.
    """
    text = normalise(path)
    parts = text.split("/")

    display_tail = text
    role = FALLBACK_ROLE
    priority = FALLBACK_PRIORITY
    for dir_path, dir_role, dir_priority in SEARCH_DIRS:
        wanted = dir_path.split("/")
        width = len(wanted)
        for index in range(len(parts) - width + 1):
            if parts[index : index + width] == wanted:
                display_tail = "/".join(parts[index:])
                role, priority = dir_role, dir_priority
                break
        else:
            continue
        break

    display = "/" + display_tail
    tail_parts = display_tail.split("/")
    basename = tail_parts[-1]

    if len(tail_parts) >= 2 and tail_parts[-2].endswith(".d"):
        unit_name = tail_parts[-2][:-2]
        if basename.endswith(".conf"):
            return display, role, priority, "dropin", unit_name, basename
        return display, role, priority, "stray", unit_name, basename

    if basename.endswith(UNIT_SUFFIXES):
        return display, role, priority, "base", basename, basename
    return display, role, priority, "skip", basename, basename


@dataclass
class ScanContext:
    """Every unit discovered in one scan, plus what did not become a unit."""

    units: dict[str, Unit] = dc_field(default_factory=dict)
    strays: list[tuple[str, str, str]] = dc_field(default_factory=list)
    label: str = "<memory>"
    complete: bool = True

    def unit(self, name: str) -> Unit | None:
        return self.units.get(name)

    def of_kind(self, kind: str) -> list[Unit]:
        return [unit for unit in self.units.values() if unit.kind == kind]

    def sorted_units(self) -> list[Unit]:
        return [self.units[name] for name in sorted(self.units)]

    @property
    def findings_hint(self) -> int:
        return len(self.strays)


def kind_of(name: str) -> str:
    return name.rsplit(".", 1)[-1] if "." in name else "unit"


def build_units(
    files: Mapping[str, str],
    label: str = "<memory>",
    complete: bool = True,
) -> ScanContext:
    """Assemble units from a mapping of ``display path -> file text``.

    ``complete`` says whether the mapping is the whole world: cross-unit rules
    ("this timer points at a service that does not exist") may only trust a
    missing unit when it is.
    """
    bases: dict[str, list[tuple[int, str, str]]] = {}
    dropins: dict[str, dict[str, list[tuple[int, str, str]]]] = {}
    strays: list[tuple[str, str, str]] = []

    for path in sorted(files):
        display, role, priority, kind, unit_name, basename = classify(path)
        if kind == "base":
            bases.setdefault(unit_name, []).append((priority, display, path))
        elif kind == "dropin":
            dropins.setdefault(unit_name, {}).setdefault(basename, []).append((priority, display, path))
        elif kind == "stray":
            strays.append((display, unit_name, "inside a .d directory but does not end in .conf"))

    context = ScanContext(strays=strays, label=label, complete=complete)
    for name in sorted(set(bases) | set(dropins)):
        context.units[name] = _assemble(name, bases.get(name, []), dropins.get(name, {}), files)
    return context


def _file(text: str, display: str, role: str, priority: int, dropin: bool) -> UnitFile:
    return parse_unit_text(text, source=display, role=role, priority=priority, dropin=dropin)


def _assemble(
    name: str,
    base_candidates: list[tuple[int, str, str]],
    dropin_candidates: dict[str, list[tuple[int, str, str]]],
    files: Mapping[str, str],
) -> Unit:
    base_candidates = sorted(base_candidates)
    base: UnitFile | None = None
    replaced: list[UnitFile] = []
    if base_candidates:
        priority, display, key = base_candidates[0]
        role = _role_of(display)
        base = _file(files[key], display, role, priority, dropin=False)
        for priority, display, key in base_candidates[1:]:
            replaced.append(_file(files[key], display, _role_of(display), priority, dropin=False))

    chosen: dict[str, tuple[int, str, str]] = {}
    shadowed: list[UnitFile] = []
    for basename, versions in dropin_candidates.items():
        versions.sort()
        chosen[basename] = versions[0]
        for priority, display, key in versions[1:]:
            shadowed.append(_file(files[key], display, _role_of(display), priority, dropin=True))

    applied: list[UnitFile] = []
    for basename in sorted(chosen):
        priority, display, key = chosen[basename]
        applied.append(_file(files[key], display, _role_of(display), priority, dropin=True))

    chain: list[Directive] = []
    declared: list[tuple[str, str, int, int]] = []
    if base is not None:
        chain.extend(base.directives)
        declared.extend((section, base.path, lineno, offset) for section, lineno, offset in base.sections)
    for dropin in applied:
        chain.extend(dropin.directives)
        declared.extend(
            (section, dropin.path, lineno, offset) for section, lineno, offset in dropin.sections
        )

    unit = Unit(
        name=name,
        kind=kind_of(name),
        base=base,
        replaced=replaced,
        dropins=applied,
        shadowed=shadowed,
        chain=chain,
        declared=declared,
    )
    unit.install()
    return unit


def _role_of(display: str) -> str:
    for dir_path, role, _priority in SEARCH_DIRS:
        if display.startswith("/" + dir_path + "/"):
            return role
    return FALLBACK_ROLE


def build_unit_from_file(path: Path) -> ScanContext:
    """Audit one file plus a sibling ``<file>.d`` directory, if there is one.

    This is the ``unitlint scan some.service`` path: the base file is the one
    the user pointed at, and drop-ins are looked for next to it because that is
    the only place they can be without a root to search.
    """
    display = str(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    base = parse_unit_text(text, source=display, role="unknown", priority=0)
    chain: list[Directive] = list(base.directives)
    declared: list[tuple[str, str, int, int]] = [
        (section, base.path, lineno, offset) for section, lineno, offset in base.sections
    ]
    applied: list[UnitFile] = []
    dropin_dir = path.parent / (path.name + ".d")
    if dropin_dir.is_dir():
        for candidate in sorted(dropin_dir.glob("*.conf")):
            dropin = parse_unit_text(
                candidate.read_text(encoding="utf-8", errors="replace"),
                source=str(candidate),
                role="admin",
                priority=0,
                dropin=True,
            )
            applied.append(dropin)
            chain.extend(dropin.directives)
            declared.extend(
            (section, dropin.path, lineno, offset) for section, lineno, offset in dropin.sections
        )

    unit = Unit(
        name=path.name,
        kind=kind_of(path.name),
        base=base,
        dropins=applied,
        chain=chain,
        declared=declared,
    )
    unit.install()
    return ScanContext(units={path.name: unit}, label=display, complete=False)


def collect_from_disk(root: Path) -> tuple[dict[str, str], list[str]]:
    """Read every candidate unit file under ``root`` into memory.

    Files are returned with their path relative to ``root``; the display path
    is derived from the search directory they sit in, so a finding points at
    ``/etc/systemd/system/foo.service`` and not at
    ``D:\\images\\web\\etc\\systemd\\system\\foo.service``.
    """
    files: dict[str, str] = {}
    skipped: list[str] = []
    if root.is_file():
        files[str(root)] = root.read_text(encoding="utf-8", errors="replace")
        return files, skipped

    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file():
            continue
        name = candidate.name
        inside_dropin_dir = candidate.parent.name.endswith(".d")
        if not (name.endswith(UNIT_SUFFIXES) or inside_dropin_dir):
            continue
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError:  # pragma: no cover - rglob should always be under root
            skipped.append(str(candidate))
            continue
        try:
            files[relative] = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError as error:  # pragma: no cover - permissions, unreadable image
            skipped.append(f"{relative}: {error}")
    return files, skipped


def iter_units(contexts: Iterable[ScanContext]) -> Iterable[Unit]:
    for context in contexts:
        yield from context.sorted_units()


__all__ = [
    "FALLBACK_PRIORITY",
    "FALLBACK_ROLE",
    "SEARCH_DIRS",
    "UNIT_SUFFIXES",
    "ScanContext",
    "build_unit_from_file",
    "build_units",
    "classify",
    "collect_from_disk",
    "kind_of",
    "normalise",
]
