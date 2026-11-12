"""Parser behaviour: joining, comments, offsets, sections, quoting."""

from __future__ import annotations

import pytest

from unitlint.model import split_items, to_bool, unquote
from unitlint.parser import iter_logical, parse_unit_text


def test_continuation_joins_and_keeps_first_line():
    text = "[Service]\nExecStart=/usr/bin/app \\\n  --flag one\n"
    unit = parse_unit_text(text, source="a.service")
    (directive,) = [d for d in unit.directives if d.name == "ExecStart"]
    assert directive.value == "/usr/bin/app  --flag one"
    assert directive.lineno == 2
    assert "\\" not in directive.value


def test_continuation_keeps_line_count():
    text = "[Service]\nA=1 \\\n2 \\\n3\nB=4\n"
    unit = parse_unit_text(text, source="a.service")
    values = {d.name: d.value for d in unit.directives}
    # Each backslash is replaced by one space; the continuation's own leading
    # whitespace is stripped, which is why it is two spaces and then one.
    assert values["A"] == "1  2  3"
    assert values["B"] == "4"
    assert [d.lineno for d in unit.directives] == [2, 5]


def test_comment_lines_are_skipped():
    text = "[Service]\n# comment\n; also a comment\n   # indented\nExecStart=/usr/bin/app\n"
    unit = parse_unit_text(text, source="a.service")
    assert [d.name for d in unit.directives] == ["ExecStart"]


def test_hash_after_continuation_becomes_part_of_the_value():
    # systemd joins first, then looks for comments, so a "#" line swallowed by
    # a trailing backslash is data. A line-oriented scanner misses this.
    text = "[Service]\nExecStart=/usr/bin/app \\\n# not a comment\n"
    unit = parse_unit_text(text, source="a.service")
    assert unit.directives[0].value == "/usr/bin/app  # not a comment"


def test_bom_is_stripped():
    unit = parse_unit_text("\ufeff[Service]\nExecStart=/usr/bin/app\n", source="a.service")
    assert unit.sections[0][0] == "Service"
    assert unit.errors == []


def test_crlf_line_numbers_and_values():
    unit = parse_unit_text("[Service]\r\nRestart=always\r\n", source="a.service")
    assert [(d.name, d.value, d.lineno) for d in unit.directives] == [("Restart", "always", 2)]


def test_empty_value_is_a_reset_not_a_value():
    unit = parse_unit_text("[Service]\nNoNewPrivileges=\nNoNewPrivileges=yes\n", source="a.service")
    first, second = unit.directives
    assert first.is_empty is True
    assert first.text == ""
    assert second.is_empty is False


def test_empty_section_is_recorded():
    unit = parse_unit_text("[Unit]\nDescription=x\n[Install]\n", source="a.service")
    assert [name for name, _line, _offset in unit.sections] == ["Unit", "Install"]


def test_section_with_whitespace_around_brackets():
    unit = parse_unit_text("[ Service ]\nExecStart=/usr/bin/app\n", source="a.service")
    assert unit.directives[0].section == "Service"


def test_directive_before_any_section_is_an_error():
    unit = parse_unit_text("ExecStart=/usr/bin/app\n", source="a.service")
    assert unit.directives == []
    assert "before any [Section]" in unit.errors[0]


def test_line_without_equals_is_an_error():
    unit = parse_unit_text("[Service]\nthis is not a directive\n", source="a.service")
    assert unit.directives == []
    assert "not a section and not a Key=Value" in unit.errors[0]


def test_directive_name_with_space_is_an_error():
    unit = parse_unit_text("[Service]\nExec Start=/usr/bin/app\n", source="a.service")
    assert unit.directives == []
    assert "whitespace" in unit.errors[0]


def test_empty_directive_name_is_an_error():
    unit = parse_unit_text("[Service]\n=x\n", source="a.service")
    assert unit.directives == []
    assert "empty directive name" in unit.errors[0]


def test_offsets_are_bytes_not_characters():
    # A Chinese comment must not shift the offsets of everything after it.
    text = "[Unit]\n# 中文注释\n[Service]\nExecStart=/usr/bin/app\n"
    unit = parse_unit_text(text, source="a.service")
    directive = unit.directives[0]
    assert directive.offset == len("[Unit]\n# 中文注释\n[Service]\n".encode())
    assert directive.length == len(b"ExecStart=/usr/bin/app")


def test_second_line_offset_accounts_for_newline():
    unit = parse_unit_text("[Service]\nA=1\nB=2\n", source="a.service")
    first, second = unit.directives
    assert second.offset == first.offset + len(b"A=1\n")


def test_iter_logical_reports_physical_and_logical_counts():
    rows = list(iter_logical("[A]\nX=1 \\\n2\n"))
    assert [row[0] for row in rows] == [1, 2]
    assert rows[1][1] == "X=1  2"


def test_trailing_backslash_at_eof_does_not_hang():
    # A truncated file: there is no next line to join, so the backslash stays
    # where systemd would leave it. What matters is that parsing terminates.
    unit = parse_unit_text("[Service]\nExecStart=/usr/bin/app \\\n", source="a.service")
    assert unit.directives[0].value.endswith("\\")
    assert unit.directives[0].lineno == 2


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"a b"', "a b"),
        ("'a b'", "a b"),
        ("plain", "plain"),
        ('"line\\nbreak"', "line\nbreak"),
        ('"quote\\"inside"', 'quote"inside'),
        ('"tab\\there"', "tab\there"),
        ('"unknown\\qescape"', "unknownqescape"),
    ],
)
def test_unquote(raw, expected):
    assert unquote(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("A=1 B=2", ["A=1", "B=2"]),
        ('"A=1 2" B=3', ['"A=1 2"', "B=3"]),
        ("single", ["single"]),
        ("", []),
    ],
)
def test_split_items(raw, expected):
    assert split_items(raw) == expected


@pytest.mark.parametrize(("raw", "expected"), [("yes", True), ("0", False), ("maybe", None), ("", False)])
def test_to_bool(raw, expected):
    assert to_bool(raw) is expected
