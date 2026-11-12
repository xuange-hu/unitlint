"""Data model for a merged systemd unit.

Every directive keeps the file it came from, the physical line number, the byte
offset and the raw text. A finding that cannot name the file and the line that
produced it is an opinion, so provenance is recorded while parsing and carried
through the merge instead of being reconstructed afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dc_field

# Sections documented in systemd.unit(5), plus the ``[X-Name]`` vendor
# extension convention. A section outside this set is ignored by systemd
# itself: the unit still starts, the directives inside it silently do nothing.
KNOWN_SECTIONS = frozenset(
    {
        "Unit",
        "Service",
        "Install",
        "Timer",
        "Socket",
        "Path",
        "Mount",
        "Automount",
        "Swap",
        "Slice",
        "Scope",
        "Device",
        "Target",
    }
)

# Directives that take more than one value: every occurrence adds to the set
# instead of replacing the previous one. Everything else is last-wins, which is
# exactly why a drop-in can quietly undo a hardening line.
LIST_DIRECTIVES = frozenset(
    {
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
        "Environment",
        "EnvironmentFile",
        "SupplementaryGroups",
        "After",
        "Before",
        "Wants",
        "Requires",
        "Requisite",
        "BindsTo",
        "PartOf",
        "Conflicts",
        "Documentation",
        "OnCalendar",
        "OnActiveSec",
        "OnBootSec",
        "OnStartupSec",
        "OnUnitActiveSec",
        "OnUnitInactiveSec",
        "ListenStream",
        "ListenDatagram",
        "ListenSequentialPacket",
        "ListenFIFO",
        "ReadWritePaths",
        "ReadOnlyPaths",
        "InaccessiblePaths",
        "BindPaths",
        "BindReadOnlyPaths",
        "TemporaryFileSystem",
        "DeviceAllow",
        "StandardInputText",
        "PathExists",
        "PathExistsGlob",
        "PathChanged",
        "PathModified",
        "PathDirectoryNotEmpty",
        "Alias",
        "WantedBy",
        "RequiredBy",
        "Also",
    }
)

_TRUE = frozenset({"1", "yes", "true", "on", "y", "t"})
_FALSE = frozenset({"0", "no", "false", "off", "n", "f", ""})

_ITEM_SPLIT = re.compile(r"""(?:[^\s"']+|"[^"]*"|'[^']*')+""")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "s": " ", "\\": "\\", '"': '"', "'": "'"}


def to_bool(value: str) -> bool | None:
    """systemd's boolean vocabulary, or None when the token is neither."""
    token = value.strip().lower()
    if token in _TRUE:
        return True
    if token in _FALSE:
        return False
    return None


def unquote(value: str) -> str:
    """Strip the quoting systemd allows and expand its C-style escapes.

    Only the escapes documented in systemd.syntax(7) are expanded; anything
    else is left as-is so an unknown escape cannot silently eat a backslash.
    """
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        body = text[1:-1]
        out: list[str] = []
        index = 0
        while index < len(body):
            char = body[index]
            if char != "\\" or index + 1 >= len(body):
                out.append(char)
                index += 1
                continue
            nxt = body[index + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                index += 2
            elif nxt == "x" and index + 3 < len(body):
                try:
                    out.append(chr(int(body[index + 2 : index + 4], 16)))
                except ValueError:
                    out.append(char)
                    index += 1
                    continue
                index += 4
            elif nxt in "01234567" and index + 3 < len(body):
                try:
                    out.append(chr(int(body[index + 1 : index + 4], 8)))
                except ValueError:
                    out.append(char)
                    index += 1
                    continue
                index += 4
            else:
                out.append(nxt)
                index += 2
        return "".join(out)
    return text


def split_items(value: str) -> list[str]:
    """Split an assignment list the way systemd does: quotes group, spaces split.

    ``Environment="A=1 2" B=3`` is two items, not three. A naive ``split()``
    turns it into three and then reports a bogus ``A=1`` assignment.
    """
    return [match.group(0) for match in _ITEM_SPLIT.finditer(value.strip())]


@dataclass(frozen=True)
class Directive:
    """One ``Key=Value`` line, after continuation joining."""

    section: str
    name: str
    value: str
    lineno: int  # physical line the statement starts on
    offset: int  # byte offset of that physical line inside its file
    length: int  # byte length of the joined statement
    raw: str  # the joined text, exactly as read
    source: str  # file path (already made display-friendly)
    role: str  # admin | run | local | vendor | unknown
    priority: int  # lower wins; see merge.SEARCH_DIRS
    dropin: bool = False

    @property
    def text(self) -> str:
        """The value with systemd quoting removed."""
        return unquote(self.value)

    @property
    def is_empty(self) -> bool:
        """True for the ``Key=`` form, which resets the directive to default."""
        return self.value.strip() == ""

    @property
    def where(self) -> str:
        return f"{self.source}:{self.lineno}"

    @property
    def is_dropin(self) -> bool:
        return self.dropin

    def flag(self, default: bool | None = None) -> bool | None:
        parsed = to_bool(self.value)
        return default if parsed is None else parsed


@dataclass
class UnitFile:
    """One file that contributes to a unit: a base unit or a drop-in."""

    path: str
    role: str
    priority: int
    directives: list[Directive] = dc_field(default_factory=list)
    errors: list[str] = dc_field(default_factory=list)
    dropin: bool = False
    #: Every section header seen, as ``(name, lineno, offset)``. An empty
    #: ``[Install]`` produces no directives, so without this the fact that the
    #: section exists at all would be lost.
    sections: list[tuple[str, int, int]] = dc_field(default_factory=list)

    @property
    def basename(self) -> str:
        return self.path.replace("\\", "/").rsplit("/", 1)[-1]


@dataclass
class Unit:
    """A unit name with everything that contributes to it, already merged."""

    name: str
    kind: str
    base: UnitFile | None = None
    replaced: list[UnitFile] = dc_field(default_factory=list)
    dropins: list[UnitFile] = dc_field(default_factory=list)
    shadowed: list[UnitFile] = dc_field(default_factory=list)
    chain: list[Directive] = dc_field(default_factory=list)
    #: Section headers from every contributing file, as
    #: ``(section, source, lineno, offset)`` in merge order.
    declared: list[tuple[str, str, int, int]] = dc_field(default_factory=list)
    effective: dict[tuple[str, str], Directive | None] = dc_field(default_factory=dict)
    history: dict[tuple[str, str], list[Directive]] = dc_field(default_factory=dict)

    def install(self) -> None:
        """Fold the merge chain into last-wins values plus the full history."""
        self.effective.clear()
        self.history.clear()
        for directive in self.chain:
            key = (directive.section, directive.name)
            self.history.setdefault(key, []).append(directive)
            # An empty assignment resets to the built-in default, so the
            # effective value is "not set" again -- not the previous value.
            self.effective[key] = None if directive.is_empty else directive

    # -- reads ---------------------------------------------------------------

    def last(self, section: str, name: str) -> Directive | None:
        """The directive that is in force for ``section.name``, if any."""
        return self.effective.get((section, name))

    def every(self, section: str, name: str) -> list[Directive]:
        """Every occurrence, in merge order, including empty resets."""
        return list(self.history.get((section, name), []))

    def present(self, section: str, name: str) -> list[Directive]:
        """Occurrences that actually carry a value."""
        return [d for d in self.history.get((section, name), []) if not d.is_empty]

    def text(self, section: str, name: str, default: str = "") -> str:
        found = self.last(section, name)
        return default if found is None else found.text

    def flag(self, section: str, name: str) -> bool | None:
        found = self.last(section, name)
        return None if found is None else found.flag()

    def items(self, section: str, name: str) -> list[Directive]:
        """One entry per whitespace-separated item, each keeping its directive.

        Splitting happens on the *raw* value: unquoting first would turn
        ``Environment="A=1 2"`` into two items, which is how a scanner ends up
        reporting an assignment that the service never had.
        """
        out: list[Directive] = []
        for directive in self.present(section, name):
            for item in split_items(directive.value):
                out.append(
                    Directive(
                        section=directive.section,
                        name=directive.name,
                        value=unquote(item),
                        lineno=directive.lineno,
                        offset=directive.offset,
                        length=directive.length,
                        raw=directive.raw,
                        source=directive.source,
                        role=directive.role,
                        priority=directive.priority,
                        dropin=directive.dropin,
                    )
                )
        return out

    def values(self, section: str, name: str) -> list[str]:
        return [item.text for item in self.items(section, name)]

    def has_section(self, name: str) -> bool:
        """True when the section header exists, even if it holds nothing."""
        return any(entry[0] == name for entry in self.declared)

    @property
    def sections(self) -> set[str]:
        """Every section header, including the ones that hold nothing."""
        return {entry[0] for entry in self.declared}

    @property
    def files(self) -> list[UnitFile]:
        out = [self.base] if self.base is not None else []
        return [file for file in out if file is not None] + self.dropins

    @property
    def label(self) -> str:
        if self.base is not None:
            return f"{self.name} ({self.base.path})"
        return f"{self.name} (drop-ins only)"


@dataclass
class Finding:
    """One rule's opinion about one place in one file."""

    rule: str
    severity: str  # critical | high | medium | low | note
    message: str
    where: str
    line: int
    offset: int
    length: int = 0
    saw: str = ""
    fix: str = ""
    score: int = 1

    @property
    def span(self) -> tuple[int, int]:
        return (self.offset, self.offset + max(self.length, 0))

    def sort_key(self) -> tuple:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
        return (order.get(self.severity, 5), self.where, self.line, self.offset, self.rule)


SEVERITY_SCORE = {"critical": 40, "high": 20, "medium": 8, "low": 3, "note": 1}


@dataclass
class Report:
    """Every rule's output for one unit."""

    source: str
    unit: Unit | None
    findings: list[Finding] = dc_field(default_factory=list)
    rules_run: int = 0

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def risk(self) -> int:
        """0-100. Three criticals already saturate it, which is the point."""
        return min(100, sum(f.score for f in self.findings))

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def by_rule(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.rule] = out.get(finding.rule, 0) + 1
        return out

    @property
    def fired(self) -> set[str]:
        return {f.rule for f in self.findings}


def finding(
    rule: str,
    severity: str,
    message: str,
    directive: Directive | None = None,
    *,
    where: str = "",
    line: int = 0,
    offset: int = 0,
    length: int = 0,
    saw: str = "",
    fix: str = "",
) -> Finding:
    """Build a finding, defaulting the evidence fields to a directive's span.

    Passing the directive instead of loose numbers is what keeps ``--sarif``
    honest: byte offset, line and file all come from the same place the value
    was read from.
    """
    if directive is not None:
        where = where or directive.source
        line = line or directive.lineno
        offset = offset or directive.offset
        length = length or directive.length
        saw = saw or directive.raw.strip()
    return Finding(
        rule=rule,
        severity=severity,
        message=message,
        where=where,
        line=max(line, 1),
        offset=max(offset, 0),
        length=max(length, 0),
        saw=saw,
        fix=fix,
        score=SEVERITY_SCORE.get(severity, 1),
    )
