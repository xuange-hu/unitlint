"""Discovery and merge: priority, replacement, drop-in order, shadowing."""

from __future__ import annotations

from pathlib import Path

import pytest

from unitlint.merge import (
    SEARCH_DIRS,
    build_unit_from_file,
    build_units,
    classify,
    collect_from_disk,
    kind_of,
    normalise,
)

BASE = """[Service]
ExecStart=/usr/bin/app
User=app
"""


@pytest.mark.parametrize(
    ("path", "role", "priority", "kind"),
    [
        ("etc/systemd/system/a.service", "admin", 0, "base"),
        ("run/systemd/system/a.service", "run", 1, "base"),
        ("usr/local/lib/systemd/system/a.service", "local", 2, "base"),
        ("usr/lib/systemd/system/a.service", "vendor", 3, "base"),
        ("lib/systemd/system/a.service", "vendor", 4, "base"),
        ("etc/systemd/system/a.service.d/9-x.conf", "admin", 0, "dropin"),
        ("etc/systemd/system/a.service.d/README", "admin", 0, "stray"),
        ("srv/units/a.service", "vendor", 9, "base"),
        ("srv/units/notes.txt", "vendor", 9, "skip"),
    ],
)
def test_classify(path, role, priority, kind):
    _display, got_role, got_priority, got_kind, unit_name, _basename = classify(path)
    assert (got_role, got_priority, got_kind) == (role, priority, kind)
    assert unit_name == ("a.service" if kind != "skip" else "notes.txt")


def test_classify_display_path_points_at_the_real_location():
    display, *_ = classify("image/rootfs/etc/systemd/system/web.service")
    assert display == "/etc/systemd/system/web.service"


def test_normalise_strips_dot_slash_and_backslashes():
    assert normalise(".\\etc\\systemd\\system\\a.service") == "etc/systemd/system/a.service"
    assert normalise("././a.service") == "a.service"


def test_kind_of():
    assert kind_of("a.service") == "service"
    assert kind_of("a.timer") == "timer"
    assert kind_of("nodot") == "unit"


def test_priority_ordering_matches_the_table():
    assert [priority for _dir, _role, priority in SEARCH_DIRS] == sorted(
        priority for _dir, _role, priority in SEARCH_DIRS
    )


def test_later_search_dir_wins():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": BASE,
            "etc/systemd/system/a.service": BASE.replace("/usr/bin/app", "/opt/app"),
        }
    )
    unit = context.units["a.service"]
    assert unit.base is not None
    assert unit.base.role == "admin"
    assert unit.text("Service", "ExecStart") == "/opt/app"
    assert [file.path for file in unit.replaced] == ["/usr/lib/systemd/system/a.service"]


def test_admin_unit_replaces_rather_than_merges():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": BASE + "NoNewPrivileges=yes\n",
            "etc/systemd/system/a.service": "[Service]\nExecStart=/opt/app\n",
        }
    )
    unit = context.units["a.service"]
    # The vendor hardening is not inherited: the whole file was replaced.
    assert unit.last("Service", "NoNewPrivileges") is None
    assert "NoNewPrivileges" not in {directive.name for directive in unit.chain}


def test_dropin_applies_after_the_base_unit():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": BASE,
            "etc/systemd/system/a.service.d/50-user.conf": "[Service]\nUser=nobody\n",
        }
    )
    unit = context.units["a.service"]
    assert unit.text("Service", "User") == "nobody"
    assert [file.basename for file in unit.dropins] == ["50-user.conf"]


def test_dropins_apply_in_filename_order():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": BASE,
            "etc/systemd/system/a.service.d/90-last.conf": "[Service]\nUser=last\n",
            "etc/systemd/system/a.service.d/10-first.conf": "[Service]\nUser=first\n",
        }
    )
    unit = context.units["a.service"]
    assert unit.text("Service", "User") == "last"
    assert [file.basename for file in unit.dropins] == ["10-first.conf", "90-last.conf"]
    assert [directive.text for directive in unit.present("Service", "User")] == ["app", "first", "last"]


def test_same_dropin_filename_in_two_dirs_is_shadowed():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": BASE,
            "usr/lib/systemd/system/a.service.d/50-x.conf": "[Service]\nUser=vendor\n",
            "etc/systemd/system/a.service.d/50-x.conf": "[Service]\nUser=admin\n",
        }
    )
    unit = context.units["a.service"]
    assert unit.text("Service", "User") == "admin"
    assert [file.basename for file in unit.shadowed] == ["50-x.conf"]
    assert unit.shadowed[0].path.startswith("/usr/lib/")


def test_dropin_without_a_unit_is_kept_as_an_orphan():
    context = build_units({"etc/systemd/system/ghost.service.d/override.conf": BASE})
    unit = context.units["ghost.service"]
    assert unit.base is None
    assert [file.basename for file in unit.dropins] == ["override.conf"]
    assert len(unit.chain) == 2


def test_file_in_a_dropin_dir_that_is_not_conf_is_a_stray():
    context = build_units(
        {
            "usr/lib/systemd/system/a.service": BASE,
            "etc/systemd/system/a.service.d/README.md": "docs\n",
        }
    )
    assert context.strays == [
        ("/etc/systemd/system/a.service.d/README.md", "a.service", "inside a .d directory but does not end in .conf")
    ]


def test_non_unit_files_are_ignored():
    context = build_units({"usr/lib/systemd/system/README": "hello\n"})
    assert context.units == {}
    assert context.strays == []


def test_unknown_directory_uses_the_fallback_priority():
    context = build_units({"units/a.service": BASE})
    unit = context.units["a.service"]
    assert unit.base is not None
    assert unit.base.role == "vendor"
    assert unit.base.path == "/units/a.service"


def test_flat_directory_with_a_dropin_dir():
    context = build_units(
        {
            "units/a.service": BASE,
            "units/a.service.d/99.conf": "[Service]\nUser=override\n",
        }
    )
    assert context.units["a.service"].text("Service", "User") == "override"


def test_build_unit_from_file_reads_a_sibling_dropin_dir(tmp_path: Path):
    base = tmp_path / "a.service"
    base.write_text(BASE, encoding="utf-8")
    dropin_dir = tmp_path / "a.service.d"
    dropin_dir.mkdir()
    (dropin_dir / "99.conf").write_text("[Service]\nUser=override\n", encoding="utf-8")

    context = build_unit_from_file(base)
    unit = context.units["a.service"]
    assert context.complete is False
    assert unit.text("Service", "User") == "override"
    assert [file.basename for file in unit.dropins] == ["99.conf"]


def test_build_unit_from_file_without_a_dropin_dir(tmp_path: Path):
    base = tmp_path / "a.service"
    base.write_text(BASE, encoding="utf-8")
    unit = build_unit_from_file(base).units["a.service"]
    assert unit.dropins == []
    assert unit.text("Service", "ExecStart") == "/usr/bin/app"


def test_collect_from_disk_reads_units_and_dropins(tmp_path: Path):
    (tmp_path / "etc/systemd/system/a.service.d").mkdir(parents=True)
    (tmp_path / "etc/systemd/system/a.service.d/9.conf").write_text("[Service]\nUser=x\n", encoding="utf-8")
    (tmp_path / "usr/lib/systemd/system").mkdir(parents=True)
    (tmp_path / "usr/lib/systemd/system/a.service").write_text(BASE, encoding="utf-8")
    (tmp_path / "usr/lib/systemd/system/notes.md").write_text("nope\n", encoding="utf-8")

    files, skipped = collect_from_disk(tmp_path)
    assert skipped == []
    assert set(files) == {
        "etc/systemd/system/a.service.d/9.conf",
        "usr/lib/systemd/system/a.service",
    }

    context = build_units(files, label=str(tmp_path))
    unit = context.units["a.service"]
    assert unit.base is not None and unit.base.path == "/usr/lib/systemd/system/a.service"
    assert unit.text("Service", "User") == "x"


def test_collect_from_disk_accepts_a_single_file(tmp_path: Path):
    base = tmp_path / "a.service"
    base.write_text(BASE, encoding="utf-8")
    files, _skipped = collect_from_disk(base)
    assert len(files) == 1


def test_units_are_sorted_and_stable():
    context = build_units(
        {
            "usr/lib/systemd/system/b.service": BASE,
            "usr/lib/systemd/system/a.service": BASE,
            "usr/lib/systemd/system/c.timer": "[Timer]\nOnCalendar=daily\n",
        }
    )
    assert [unit.name for unit in context.sorted_units()] == ["a.service", "b.service", "c.timer"]
    assert {unit.name for unit in context.of_kind("timer")} == {"c.timer"}


def test_parse_errors_are_carried_on_the_file(tmp_path: Path):
    base = tmp_path / "a.service"
    base.write_text("[Service]\nnot a directive\n", encoding="utf-8")
    unit = build_unit_from_file(base).units["a.service"]
    assert unit.base is not None
    assert unit.base.errors
