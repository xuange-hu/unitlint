"""One trigger per rule, plus the false positives each rule must not produce."""

from __future__ import annotations

import pytest
from helpers import fired, messages, tree, vendor

from unitlint import engine

#: rule id -> (unit name, unit text). Kept deliberately small: one line of
#: violation per rule, so a failure names the rule and nothing else.
CASES: dict[str, tuple[str, str]] = {
    "UNT001": ("a.service", "[Service]\nType=simple\n"),
    "UNT002": ("a.service", "[Service]\nExecStart=/usr/bin/app\n"),
    "UNT003": ("a.service", "[Service]\nUser=app\nExecStart=/tmp/app\n"),
    "UNT004": ("a.service", '[Service]\nUser=app\nExecStart=/bin/sh -c "app --flag"\n'),
    "UNT005": ("a.service", "[Service]\nUser=app\nExecStart=./run.sh\n"),
    "UNT006": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nEnvironmentFile=-/tmp/app.env\n"),
    "UNT007": ("a.service", '[Service]\nUser=app\nExecStart=/usr/bin/app\nEnvironment="DB_PASSWORD=x"\n'),
    "UNT008": ("a.service", "[Service]\nExecStart=/usr/bin/app\n"),
    "UNT009": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nProtectSystem=strict\nReadWritePaths=/etc\n"),
    "UNT010": (
        "a.service",
        "[Service]\nUser=app\nExecStart=/usr/bin/app\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
    ),
    "UNT011": (
        "a.service",
        "[Service]\nUser=app\nExecStart=/usr/bin/app\nAmbientCapabilities=CAP_SETUID\n",
    ),
    "UNT012": ("a.service", "[Service]\nUser=app\nGroup=root\nExecStart=/usr/bin/app\n"),
    "UNT013": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nSupplementaryGroups=root\n"),
    "UNT014": (
        "a.service",
        "[Unit]\nStartLimitIntervalSec=0\n[Service]\nUser=app\nExecStart=/usr/bin/app\nRestart=always\n",
    ),
    "UNT015": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nRestart=always\n"),
    "UNT016": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nUMask=0000\n"),
    "UNT017": (
        "a.service",
        "[Service]\nUser=app\nExecStart=/usr/bin/app\nStandardOutput=append:/tmp/app.log\n",
    ),
    "UNT018": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nWorkingDirectory=/home/app\n"),
    "UNT019": ("a.service", "[Service]\nUser=app\nType=forking\nExecStart=/usr/bin/app\n"),
    "UNT020": ("a.service", "[Service]\nUser=app\nType=notify\nExecStart=/usr/bin/app\n"),
    "UNT021": ("a.timer", "[Timer]\nOnCalendar=minutely\n"),
    "UNT022": ("a.timer", "[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\n"),
    "UNT023": ("a.timer", "[Timer]\nOnCalendar=daily\n"),
    "UNT024": ("a.socket", "[Socket]\nSocketMode=0666\n"),
    "UNT025": ("a.socket", "[Socket]\nListenStream=0.0.0.0:80\n"),
    "UNT026": ("a.socket", "[Socket]\nAccept=yes\n"),
    "UNT027": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\n[Install]\n"),
    "UNT028": (
        "a.service",
        "[Unit]\nDefaultDependencies=no\n[Service]\nUser=app\nExecStart=/usr/bin/app\n"
        "[Install]\nWantedBy=multi-user.target\n",
    ),
    "UNT029": ("a.service", "[Services]\nUser=app\n[Service]\nExecStart=/usr/bin/app\n"),
    "UNT030": (
        "a.service",
        "[Unit]\nWants=network-online.target\n[Service]\nUser=app\nExecStart=/usr/bin/app\n",
    ),
    "UNT031": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nPermissionsStartOnly=true\n"),
    "UNT032": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nExecStop=pkill app\n"),
    "UNT033": (
        "a.service",
        "[Service]\nUser=app\nType=oneshot\nExecStart=/usr/bin/app\n[Install]\nWantedBy=multi-user.target\n",
    ),
    "UNT034": ("a.service", "[Service]\nUser=app\nExecStart=/usr/bin/app\nLimitNOFILE=infinity\n"),
    "UNT035": ("a.service", "[Unit]\nProtectSystem=strict\n[Service]\nUser=app\nExecStart=/usr/bin/app\n"),
}


@pytest.mark.parametrize(("rule", "case"), sorted(CASES.items()))
def test_rule_fires_on_its_sample(rule, case):
    name, text = case
    unit, context = vendor(text, name=name)
    assert rule in fired(unit, context), f"{rule} did not fire on:\n{text}"


# -- guards: the same shapes, done correctly, must stay silent ---------------


def test_dynamic_user_is_not_root():
    unit, context = vendor("[Service]\nDynamicUser=yes\nExecStart=/usr/bin/app\n")
    assert "UNT002" not in fired(unit, context)


def test_user_root_is_flagged_with_its_value():
    unit, context = vendor("[Service]\nUser=root\nExecStart=/usr/bin/app\n")
    assert any("User=root" in message for message in messages(unit, context, "UNT002"))


def test_secret_reference_is_not_a_literal_secret():
    unit, context = vendor(
        '[Service]\nUser=app\nExecStart=/usr/bin/app\n'
        'Environment="DB_PASSWORD_FILE=/etc/app/pw" "API_TOKEN=$FROM_CREDENTIAL"\n'
    )
    assert "UNT007" not in fired(unit, context)


def test_conservative_umask_is_fine():
    unit, context = vendor("[Service]\nUser=app\nExecStart=/usr/bin/app\nUMask=0027\n")
    assert "UNT016" not in fired(unit, context)


def test_restart_with_a_delay_is_fine():
    unit, context = vendor("[Service]\nUser=app\nExecStart=/usr/bin/app\nRestart=always\nRestartSec=10s\n")
    assert "UNT015" not in fired(unit, context)


def test_read_write_path_scoped_to_state_directory_is_fine():
    unit, context = vendor(
        "[Service]\nUser=app\nExecStart=/usr/bin/app\nProtectSystem=strict\nReadWritePaths=/var/lib/app\n"
    )
    assert "UNT009" not in fired(unit, context)


def test_narrow_capability_is_fine():
    unit, context = vendor(
        "[Service]\nUser=app\nExecStart=/usr/bin/app\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
    )
    assert "UNT010" not in fired(unit, context)


def test_tilde_capability_is_a_removal_not_a_grant():
    unit, context = vendor("[Service]\nUser=app\nExecStart=/usr/bin/app\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n")
    assert "UNT010" not in fired(unit, context)


def test_socket_with_a_connection_limit_is_fine():
    unit, context = vendor("[Socket]\nAccept=yes\nMaxConnections=64\n")
    assert "UNT026" not in fired(unit, context)


def test_install_with_a_target_is_fine():
    unit, context = vendor("[Service]\nUser=app\nExecStart=/usr/bin/app\n[Install]\nWantedBy=multi-user.target\n")
    assert "UNT027" not in fired(unit, context)


def test_online_target_with_ordering_is_fine():
    unit, context = vendor(
        "[Unit]\nWants=network-online.target\nAfter=network-online.target\n"
        "[Service]\nUser=app\nExecStart=/usr/bin/app\n"
    )
    assert "UNT030" not in fired(unit, context)


def test_hardened_unit_has_no_hardening_findings():
    text = """[Unit]
Description=Hardened
StartLimitIntervalSec=60

[Service]
Type=simple
User=app
Group=app
ExecStart=/usr/lib/app/app
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET
RestrictNamespaces=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0027
ReadWritePaths=/var/lib/app
Restart=on-failure
RestartSec=5s
StateDirectory=app

[Install]
WantedBy=multi-user.target
"""
    unit, context = vendor(text, name="hardened.service")
    result = fired(unit, context)
    assert "UNT101" not in result
    assert "UNT008" not in result
    assert result == set(), sorted(result)


# -- stage 2: cases that need more than one file ----------------------------


def test_unt101_dropin_weakens_hardening():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nUser=app\nExecStart=/usr/bin/app\nNoNewPrivileges=yes\n",
            "etc/systemd/system/a.service.d/99-debug.conf": "[Service]\nNoNewPrivileges=no\n",
        }
    )
    unit = context.units["a.service"]
    found = messages(unit, context, "UNT101")
    assert len(found) == 1
    assert "99-debug.conf" in found[0]
    assert "a.service:4" in found[0]


def test_unt101_reset_counts_as_weakening():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\nProtectSystem=strict\n",
            "etc/systemd/system/a.service.d/9.conf": "[Service]\nProtectSystem=\n",
        }
    )
    unit = context.units["a.service"]
    assert "<reset>" in messages(unit, context, "UNT101")[0]


def test_unt101_stronger_dropin_is_not_a_finding():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\nProtectSystem=no\n",
            "etc/systemd/system/a.service.d/9.conf": "[Service]\nProtectSystem=strict\n",
        }
    )
    assert "UNT101" not in fired(context.units["a.service"], context)


def test_unt102_admin_replaces_vendor():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app --old\n",
            "etc/systemd/system/a.service": "[Service]\nExecStart=/opt/app --new\n",
        }
    )
    found = messages(context.units["a.service"], context, "UNT102")
    assert len(found) == 1
    assert "replaces" in found[0]
    assert "--new" in found[0]


def test_unt103_orphan_dropin():
    context = tree({"etc/systemd/system/ghost.service.d/x.conf": "[Service]\nExecStart=/usr/bin/true\n"})
    found = messages(context.units["ghost.service"], context, "UNT103")
    assert len(found) == 1
    assert "does not exist" in found[0]


def test_unt104_shadowed_dropin():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\n",
            "usr/lib/systemd/system/a.service.d/50-x.conf": "[Service]\nRestart=always\n",
            "etc/systemd/system/a.service.d/50-x.conf": "[Service]\nRestart=no\n",
        }
    )
    found = messages(context.units["a.service"], context, "UNT104")
    assert len(found) == 1
    assert "/usr/lib/systemd/system/a.service.d/50-x.conf" in found[0]


def test_unt105_timer_without_its_service():
    context = tree({"usr/lib/systemd/system/backup.timer": "[Timer]\nOnCalendar=daily\n"})
    found = messages(context.units["backup.timer"], context, "UNT105")
    assert "backup.service" in found[0]


def test_unt105_silent_when_the_service_is_there():
    context = tree(
        {
            "usr/lib/systemd/system/backup.timer": "[Timer]\nOnCalendar=daily\n",
            "usr/lib/systemd/system/backup.service": "[Service]\nExecStart=/usr/bin/backup\n",
        }
    )
    assert "UNT105" not in fired(context.units["backup.timer"], context)


def test_unt105_silent_without_a_tree():
    unit, context = vendor("[Timer]\nOnCalendar=daily\nUnit=elsewhere.service\n", name="a.timer")
    assert "UNT105" not in fired(unit, context)


def test_unt106_two_sockets_on_one_address():
    context = tree(
        {
            "usr/lib/systemd/system/a.socket": "[Socket]\nListenStream=0.0.0.0:9090\n",
            "usr/lib/systemd/system/b.socket": "[Socket]\nListenStream=0.0.0.0:9090\n",
        }
    )
    found = messages(context.units["b.socket"], context, "UNT106")
    assert len(found) == 1 and "a.socket" in found[0]
    assert "UNT106" not in fired(context.units["a.socket"], context)


def test_unt107_same_unit_in_two_vendor_dirs():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\n",
            "lib/systemd/system/a.service": "[Service]\nExecStart=/usr/lib/app\n",
        }
    )
    found = messages(context.units["a.service"], context, "UNT107")
    assert len(found) == 1 and "/lib/systemd/system/a.service" in found[0]


def test_unt108_stray_file_in_a_dropin_dir():
    context = tree(
        {
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\n",
            "etc/systemd/system/a.service.d/notes.md": "text\n",
        }
    )
    reports = engine.scan(context)
    stray = [report for report in reports if report.unit is None]
    assert len(stray) == 1
    assert stray[0].fired == {"UNT108"}


def test_unt109_unknown_wanted_target():
    context = tree(
        {
            "usr/lib/systemd/system/app.target": "[Unit]\nDescription=t\n",
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\n[Install]\nWantedBy=other.target\n",
        }
    )
    found = messages(context.units["a.service"], context, "UNT109")
    assert any("other.target" in message for message in found)


def test_unt109_silent_when_the_target_exists():
    context = tree(
        {
            "usr/lib/systemd/system/app.target": "[Unit]\nDescription=t\n",
            "usr/lib/systemd/system/a.service": "[Service]\nExecStart=/usr/bin/app\n[Install]\nWantedBy=app.target\n",
        }
    )
    assert "UNT109" not in fired(context.units["a.service"], context)


def test_every_rule_id_has_a_check_or_is_a_context_check():
    from unitlint.rulebook import REGISTRY
    from unitlint.rules import CONTEXT_CHECKS

    missing = [rule.id for rule in REGISTRY if rule.check is None and rule.id not in CONTEXT_CHECKS]
    assert missing == []


def test_rule_table_has_unique_ids():
    from unitlint.rulebook import REGISTRY

    ids = [rule.id for rule in REGISTRY]
    assert len(ids) == len(set(ids))


def test_every_rule_has_prose():
    from unitlint.rulebook import REGISTRY

    for rule in REGISTRY:
        assert len(rule.why) > 80, rule.id
        assert rule.fix, rule.id
        assert rule.severity in {"critical", "high", "medium", "low", "note"}
