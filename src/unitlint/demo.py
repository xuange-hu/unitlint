"""A built-in tree of units that, between them, fire every rule.

The corpus is embedded so ``unitlint demo`` works from a wheel with no checkout
and no root filesystem. ``tests/test_demo_sync.py`` asserts that the files under
``examples/rootfs`` are byte-identical to this mapping, so the demo cannot
drift away from the tree a reader is invited to inspect.
"""

from __future__ import annotations

from pathlib import Path

from . import engine
from .merge import ScanContext, build_units
from .model import Report
from .rulebook import REGISTRY

DEMO_LABEL = "examples/rootfs"

DEMO_FILES: dict[str, str] = {
    # -- a hardened vendor unit that a drop-in quietly un-hardens ------------
    "usr/lib/systemd/system/web-api.service": """[Unit]
Description=Web API
Documentation=https://example.invalid/web-api
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/bin/sh -c "/tmp/web-api --port 8080"
EnvironmentFile=/tmp/web-api.env
Environment="DB_PASSWORD=hunter2" "API_KEY_FILE=/etc/web-api/api.key"
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc /var/lib/web-api
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_SETUID
UMask=0000
StandardOutput=append:/tmp/web-api.log
WorkingDirectory=/home/deploy
ExecStop=killall web-api
LimitNOFILE=infinity
PermissionsStartOnly=true
Restart=always

[Install]
""",
    # A binary that a local user can replace, in the plainest possible form.
    "usr/lib/systemd/system/poller.service": """[Unit]
Description=Poller that lives in /tmp

[Service]
Type=simple
User=poller
ExecStart=/tmp/poller --watch
WorkingDirectory=/tmp/poller

[Install]
WantedBy=multi-user.target
""",
    # The override nobody re-read: it sets two hardening lines back to "no"
    # and the base file still shows them as enabled.
    "etc/systemd/system/web-api.service.d/99-debug.conf": """# Temporary: debugging the payments timeout.
[Service]
NoNewPrivileges=no
ProtectSystem=no
""",
    # Same filename in two search directories: the /etc copy wins, the vendor
    # copy is never read.
    "etc/systemd/system/web-api.service.d/10-limits.conf": """[Service]
RestartSec=2s
""",
    "usr/lib/systemd/system/web-api.service.d/10-limits.conf": """[Service]
RestartSec=30s
""",
    # A file in a drop-in directory that systemd will not read at all.
    "etc/systemd/system/web-api.service.d/README.txt": """This directory holds the payment-team override.
See the ticket for why ProtectSystem is off here.
""",
    # -- privilege and lifecycle problems ------------------------------------
    "usr/lib/systemd/system/report.service": """[Unit]
Description=Nightly report

[Service]
Type=forking
User=report
Group=root
SupplementaryGroups=root
ExecStart=/usr/lib/report/report --all
Restart=always
RestartSec=0

[Install]
WantedBy=multi-user.target
""",
    "usr/lib/systemd/system/collector.service": """[Unit]
Description=Metrics collector

[Service]
Type=notify
User=stats
ExecStart=/usr/lib/collector/collector

[Install]
WantedBy=multi-user.target
""",
    "usr/lib/systemd/system/oneshot.service": """[Unit]
Description=Apply sysctl knobs once

[Service]
Type=oneshot
User=sysadmin
ExecStart=/usr/lib/knobs/apply

[Install]
WantedBy=multi-user.target
""",
    "usr/lib/systemd/system/empty.service": """[Unit]
Description=A unit that forgot its command

[Service]
Restart=on-failure

[Install]
WantedBy=multi-user.target
""",
    # A typo turns the whole block into configuration that looks real.
    "usr/lib/systemd/system/weird.service": """[Unit]
Description=Legacy helper

[Services]
User=legacy
ExecStart=/usr/lib/legacy/helper

[Service]
ExecStart=bin/legacy-helper
""",
    "usr/lib/systemd/system/settings.service": """[Unit]
Description=Tune the host
DefaultDependencies=no

[Service]
User=admin-tools
ExecStart=/usr/lib/tuning/apply
ProtectSystem=strict
ReadWritePaths=/etc
WantedBy=multi-user.target

[Install]
WantedBy=multi-user.target
""",
    # -- timers --------------------------------------------------------------
    "usr/lib/systemd/system/backup.timer": """[Unit]
Description=Backup, every minute, for reasons

[Timer]
OnCalendar=*:*:00
Unit=backup-missing.service

[Install]
WantedBy=timers.target
""",
    # -- sockets -------------------------------------------------------------
    "usr/lib/systemd/system/metrics.socket": """[Unit]
Description=Metrics endpoint

[Socket]
ListenStream=0.0.0.0:9090
SocketMode=0666
Accept=yes

[Install]
WantedBy=sockets.target
""",
    "usr/lib/systemd/system/metrics-alt.socket": """[Unit]
Description=Metrics endpoint, second attempt

[Socket]
ListenStream=0.0.0.0:9090

[Install]
WantedBy=sockets.target
""",
    # -- an admin unit that replaced the vendor unit -------------------------
    "usr/lib/systemd/system/legacy-agent.service": """[Unit]
Description=Legacy agent

[Service]
Type=simple
User=legacy
ExecStart=/usr/lib/legacy-agent/agent
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
""",
    "etc/systemd/system/legacy-agent.service": """[Unit]
Description=Legacy agent (patched 2019)

[Service]
Type=simple
User=root
ExecStart=/opt/legacy-agent/agent --compat
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
""",
    # -- the same unit name in two vendor directories ------------------------
    "usr/lib/systemd/system/lang.service": """[Unit]
Description=Language service

[Service]
User=lang
ExecStart=/usr/lib/lang/langd

[Install]
WantedBy=multi-user.target
""",
    "lib/systemd/system/lang.service": """[Unit]
Description=Language service, older copy

[Service]
User=root
ExecStart=/usr/lib/lang/langd --legacy

[Install]
WantedBy=multi-user.target
""",
    # -- a target that exists, and a WantedBy that does not ------------------
    "usr/lib/systemd/system/app.target": """[Unit]
Description=Application stack
""",
    "usr/lib/systemd/system/app-driver.service": """[Unit]
Description=Driver for the application stack
After=app.target

[Service]
User=app
ExecStart=/usr/lib/app/driver

[Install]
WantedBy=app-stack.target
""",
    # -- a drop-in directory whose unit no longer exists ---------------------
    "etc/systemd/system/ghost.service.d/override.conf": """[Service]
ExecStart=/usr/bin/true
""",
}


def context() -> ScanContext:
    return build_units(DEMO_FILES, label=DEMO_LABEL)


def reports() -> list[Report]:
    return engine.scan(context())


def coverage() -> tuple[set[str], int]:
    """Rules that fired, and how many rules exist."""
    fired: set[str] = set()
    for report in reports():
        fired |= report.fired
    return fired, len(REGISTRY)


def missing_rules() -> list[str]:
    fired, _total = coverage()
    return sorted(rule.id for rule in REGISTRY if rule.id not in fired)


def materialise(root: Path) -> list[Path]:
    """Write the demo tree to disk. Used by the sync test, not at runtime."""
    written: list[Path] = []
    for relative, text in sorted(DEMO_FILES.items()):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        written.append(target)
    return written


__all__ = ["DEMO_FILES", "DEMO_LABEL", "context", "coverage", "materialise", "missing_rules", "reports"]
