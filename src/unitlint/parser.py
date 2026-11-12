"""Read a systemd unit file without a systemd around.

Two things a generic ini reader gets wrong and this module gets right:

* **Continuation lines** -- a trailing backslash joins the next physical line
  and the backslash is replaced by a single space. The joined statement keeps
  the line number of its first physical line, which is the line an editor, a
  code review and ``--sarif`` all point at.
* **``Key=`` with an empty value is a reset**, not a value. That form is how an
  admin disables a hardening line without deleting it, so the merge logic must
  see it as "unset" rather than "set to empty string".

Every statement also carries its byte offset, so a finding can quote the exact
bytes it is talking about.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from .model import Directive, UnitFile

_SECTION_OPEN = "["
_SECTION_CLOSE = "]"


def iter_logical(text: str) -> Iterator[tuple[int, str, int, int]]:
    """Yield ``(first_lineno, joined_text, byte_offset, byte_length)``.

    Offsets are byte offsets, not character offsets: a unit file with a Chinese
    comment must not shift every later offset by the extra bytes of its UTF-8
    encoding.
    """
    lines = text.split("\n")
    # A trailing newline produces one empty phantom line; dropping it keeps the
    # iterator from reporting a statement on the line after the last one.
    if lines and lines[-1] == "":
        lines = lines[:-1]
    offsets: list[int] = []
    position = 0
    for line in lines:
        offsets.append(position)
        position += len(line.encode("utf-8")) + 1  # +1 for the newline

    index = 0
    total = len(lines)
    while index < total:
        start = index
        chunk = lines[index].rstrip("\r")
        # A trailing backslash continues the statement. systemd joins as many
        # lines as are continued, and replaces each backslash with a space.
        while chunk.rstrip().endswith("\\") and index + 1 < total:
            index += 1
            head = chunk.rstrip()
            chunk = head[:-1] + " " + lines[index].strip().rstrip("\r")
        yield start + 1, chunk, offsets[start], len(chunk.encode("utf-8"))
        index += 1


def _split_section(stripped: str) -> str | None:
    if len(stripped) >= 3 and stripped.startswith(_SECTION_OPEN) and stripped.endswith(_SECTION_CLOSE):
        name = stripped[1:-1].strip()
        return name or None
    return None


def parse_unit_text(
    text: str,
    source: str,
    role: str = "unknown",
    priority: int = 9,
    dropin: bool = False,
) -> UnitFile:
    """Parse unit text into directives, keeping line and byte provenance."""
    if text.startswith("\ufeff"):
        text = text[1:]

    unit_file = UnitFile(path=source, role=role, priority=priority, dropin=dropin)
    section: str | None = None

    for lineno, raw, offset, length in iter_logical(text):
        stripped = raw.strip()
        if not stripped:
            continue
        # Comments are recognised after joining, exactly as systemd does. A
        # "#" line that follows a backslash is therefore part of the value --
        # a real way to hide a directive from a line-oriented grep.
        if stripped[0] in "#;":
            continue

        name = _split_section(stripped)
        if name is not None:
            section = name
            unit_file.sections.append((name, lineno, offset))
            continue

        key, sep, value = stripped.partition("=")
        if not sep:
            unit_file.errors.append(f"line {lineno}: not a section and not a Key=Value: {stripped[:60]!r}")
            continue

        key = key.strip()
        if not key:
            unit_file.errors.append(f"line {lineno}: empty directive name: {stripped[:60]!r}")
            continue
        if any(char.isspace() for char in key):
            unit_file.errors.append(f"line {lineno}: directive name contains whitespace: {key[:60]!r}")
            continue
        if section is None:
            unit_file.errors.append(f"line {lineno}: {key}= appears before any [Section]")
            continue

        unit_file.directives.append(
            Directive(
                section=section,
                name=key,
                value=value.strip(),
                lineno=lineno,
                offset=offset,
                length=length,
                raw=raw.strip(),
                source=source,
                role=role,
                priority=priority,
                dropin=dropin,
            )
        )

    return unit_file


def parse_unit_file(
    path: Path,
    source: str | None = None,
    role: str = "unknown",
    priority: int = 9,
    dropin: bool = False,
) -> UnitFile:
    """Read one file from disk. Undecodable bytes are replaced, never raised.

    A unit file with a stray Latin-1 byte in a comment must still be audited;
    refusing to read it would hide every other finding in the same file.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_unit_text(
        text,
        source=source or str(path),
        role=role,
        priority=priority,
        dropin=dropin,
    )


__all__ = ["iter_logical", "parse_unit_file", "parse_unit_text"]
