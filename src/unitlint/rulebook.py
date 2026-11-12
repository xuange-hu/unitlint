"""The rule table.

Metadata lives here and the checks live in :mod:`unitlint.rules`, joined by id
at import time. Keeping them apart means ``unitlint rules`` and
``unitlint explain`` work from the table alone, and a test can assert that every
id in the table has a check that actually runs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .model import SEVERITY_SCORE

SEVERITIES = ("critical", "high", "medium", "low", "note")


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    stage: int
    why: str
    fix: str
    check: Callable | None = field(default=None, repr=False, compare=False)

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 1)


def _r(rid: str, title: str, severity: str, stage: int, why: str, fix: str) -> Rule:
    return Rule(id=rid, title=title, severity=severity, stage=stage, why=why, fix=fix)


REGISTRY: list[Rule] = [
    # -- stage 1: what a single unit says about itself ------------------------
    _r(
        "UNT001",
        "Service has no ExecStart",
        "high",
        1,
        "A .service without ExecStart cannot be started. systemd rejects the unit at load "
        "time, so the failure surfaces as a missing service rather than as a bad line.",
        "Add ExecStart= with the absolute path of the program, or delete the unit.",
    ),
    _r(
        "UNT002",
        "Service runs as root",
        "medium",
        1,
        "Without User= the service runs as root for its whole lifetime. Every file it "
        "writes, every child it spawns and every parsing bug it has runs with full "
        "privileges, which turns a memory-safety issue into a host compromise.",
        "Add User= and Group= for a dedicated account, and keep the privileged part in a "
        "separate unit or a helper binary with file capabilities.",
    ),
    _r(
        "UNT003",
        "ExecStart points into a writable directory",
        "high",
        1,
        "The binary lives where an unprivileged user can replace it. A root-owned service "
        "executing /tmp/app, /home/user/app or anything under /dev/shm is a privilege "
        "escalation waiting for a local account.",
        "Install the binary under /usr/local/lib or /opt owned by root, mode 0755, and "
        "point ExecStart there.",
    ),
    _r(
        "UNT004",
        "ExecStart spawns a shell",
        "medium",
        1,
        "Going through /bin/sh -c means the effective command line depends on the "
        "environment, word splitting and shell builtins. Quoting bugs then become "
        "command injection, and the process tree hides the real program from supervision.",
        "Call the program directly with its arguments as separate words. If a shell is "
        "genuinely needed, put the logic in a script owned by root.",
    ),
    _r(
        "UNT005",
        "Executable path is relative",
        "medium",
        1,
        "A relative path is resolved against WorkingDirectory at start time, so the daemon "
        "starts a different program depending on where it was launched from -- or fails "
        "with a status code that says nothing about the real cause.",
        "Use an absolute path in ExecStart, ExecStartPre and ExecStop.",
    ),
    _r(
        "UNT006",
        "EnvironmentFile comes from a writable directory",
        "high",
        1,
        "EnvironmentFile is read as the service user at start time. A file under /tmp or a "
        "home directory can be swapped by anyone who can write there, which lets them "
        "inject LD_PRELOAD or rewrite the interpreter path of the process.",
        "Move the environment file to /etc/<name>/env, mode 0600, owned by root.",
    ),
    _r(
        "UNT007",
        "Environment= carries a literal secret",
        "high",
        1,
        "A password written into a unit file is readable by every local user through "
        "systemctl show, ends up in the journal through the unit's own logging, and gets "
        "copied into configuration management and backups.",
        "Use LoadCredential= or LoadCredentialEncrypted= and read the file from "
        "$CREDENTIALS_DIRECTORY; keep the secret out of the unit entirely.",
    ),
    _r(
        "UNT008",
        "Root service leaves NoNewPrivileges off",
        "low",
        1,
        "NoNewPrivileges=yes costs nothing and blocks the whole setuid/setgid/file-capability "
        "escalation path from inside the service. Leaving it off on a root service removes "
        "the cheapest available mitigation.",
        "Add NoNewPrivileges=yes.",
    ),
    _r(
        "UNT009",
        "ReadWritePaths re-opens what ProtectSystem closed",
        "high",
        1,
        "ProtectSystem=strict mounts /usr, /boot and /etc read-only, and then ReadWritePaths "
        "punches a hole back through it. Re-opening /etc or / makes the hardening cosmetic: "
        "a compromised service rewrites its own unit file or the dynamic linker cache.",
        "Narrow ReadWritePaths to the one directory the service actually writes "
        "(/var/lib/<name>, /run/<name>) and never list /, /etc, /usr or /boot.",
    ),
    _r(
        "UNT010",
        "CapabilityBoundingSet keeps a kernel-level capability",
        "medium",
        1,
        "CAP_SYS_ADMIN, CAP_SYS_MODULE and CAP_SYS_PTRACE are equivalent to root on most "
        "kernels: they load code into the kernel, read any process memory or mount "
        "filesystems. A bounding set that keeps them bounds nothing useful.",
        "Start from CapabilityBoundingSet= (empty) and add only the capabilities the "
        "program needs, one per line, with a comment saying why.",
    ),
    _r(
        "UNT011",
        "AmbientCapabilities hands out a privilege-escalation capability",
        "high",
        1,
        "Ambient capabilities survive exec, so the service user keeps CAP_SETUID, "
        "CAP_SETGID or CAP_DAC_OVERRIDE for every child process. That is a complete "
        "escalation to root from a non-root account.",
        "Drop the ambient capability and use a small setuid-free helper with file "
        "capabilities, or a privileged broker service with a narrow interface.",
    ),
    _r(
        "UNT012",
        "Group=root with a non-root User",
        "high",
        1,
        "User=app plus Group=root puts the process in the root group. Group ownership is "
        "how most of /etc and /var/log is protected, so the daemon can rewrite "
        "configuration and truncate logs it has no business touching.",
        "Set Group= to the service's own group, or drop Group= so the user's primary group "
        "is used.",
    ),
    _r(
        "UNT013",
        "SupplementaryGroups includes root",
        "high",
        1,
        "SupplementaryGroups=root grants root-group access on top of whatever User= says. "
        "It is the same exposure as Group=root but easier to miss in review, because the "
        "User= line looks correct.",
        "Remove root from SupplementaryGroups; grant access to the specific device or "
        "directory with a dedicated group and a udev rule.",
    ),
    _r(
        "UNT014",
        "Restart loop is unbounded",
        "medium",
        1,
        "StartLimitIntervalSec=0 disables the start rate limiter, so a crashing service is "
        "restarted as fast as systemd can fork it. That burns CPU, floods the journal and "
        "hides the original error behind a wall of restart messages.",
        "Delete StartLimitIntervalSec=0 and keep the default limiter, or set an explicit "
        "StartLimitBurst= with a RestartSec= of at least one second.",
    ),
    _r(
        "UNT015",
        "Restart=always without a restart delay",
        "low",
        1,
        "With Restart=always and no RestartSec, a service that fails on a dependency "
        "outage hammers that dependency while it is down. The default of 100ms is short "
        "enough to matter for a database or an API.",
        "Set RestartSec=5s or more, and prefer Restart=on-failure where a clean exit "
        "should not be retried.",
    ),
    _r(
        "UNT016",
        "UMask lets other users write",
        "medium",
        1,
        "UMask=0000 creates every file the service writes as world-writable. Combined "
        "with a shared spool or cache directory, any local user can replace the service's "
        "state files.",
        "Set UMask=0027 (or 0077 for secrets) and let the unit's own RuntimeDirectory "
        "carry the permissions.",
    ),
    _r(
        "UNT017",
        "StandardOutput writes through a writable path",
        "medium",
        1,
        "StandardOutput=append:/tmp/x.log follows symlinks. A local user who replaces that "
        "path with a link to /etc/shadow turns the service's logging into an arbitrary "
        "file write as root.",
        "Log to the journal (the default) and let journald handle rotation, or use "
        "LogsDirectory= which systemd creates with the right ownership.",
    ),
    _r(
        "UNT018",
        "WorkingDirectory is writable by others",
        "medium",
        1,
        "A working directory under /tmp, /home or /dev/shm is writable by other users. "
        "Anything the service opens by relative path -- a config, a plugin, a cache -- can "
        "be planted in advance.",
        "Use StateDirectory=, CacheDirectory= or a root-owned path under /var/lib.",
    ),
    _r(
        "UNT019",
        "Type=forking without PIDFile",
        "low",
        1,
        "For Type=forking, systemd guesses the main process from the forking behaviour. "
        "Without PIDFile= it can guess wrong, and then tracks a process that exits "
        "immediately -- so the unit reports 'inactive' while the daemon is still running.",
        "Set PIDFile= to the pid file the daemon writes, or switch to Type=notify / "
        "Type=simple if the program supports it.",
    ),
    _r(
        "UNT020",
        "Type=notify without NotifyAccess",
        "low",
        1,
        "Type=notify waits for sd_notify from the main process. If the program sends it "
        "from a worker thread, NotifyAccess=main rejects the message and the start times "
        "out after the default 90 seconds.",
        "Set NotifyAccess=all (or mixed) when the notification can come from a child, and "
        "keep TimeoutStartSec= explicit.",
    ),
    _r(
        "UNT021",
        "Timer fires every minute",
        "medium",
        1,
        "A minutely timer turns any periodic job into a load generator: it wakes the CPU "
        "1440 times a day, and on a fleet it synchronises every host on the same minute "
        "boundary. Very few jobs need that resolution.",
        "Use a longer OnCalendar= interval, or OnUnitInactiveSec= to get spacing between "
        "runs instead of wall-clock alignment.",
    ),
    _r(
        "UNT022",
        "Timer without RandomizedDelaySec",
        "low",
        1,
        "A fixed OnCalendar= time makes every host in a fleet fire in the same second. The "
        "result is a spike on the package mirror, the backup target or the API that the "
        "job talks to.",
        "Add RandomizedDelaySec= (a few minutes is enough) so the fleet spreads out.",
    ),
    _r(
        "UNT023",
        "Timer without Persistent",
        "note",
        1,
        "Without Persistent=true, a run that was due while the machine was off is simply "
        "skipped. Backups and certificate renewals are the usual victims: the timer looks "
        "healthy and the last run is a month old.",
        "Add Persistent=true for anything that must happen at least once per interval.",
    ),
    _r(
        "UNT024",
        "Socket is world-writable",
        "high",
        1,
        "SocketMode=0666 lets any local user connect to a socket that the service treats "
        "as authenticated, because the only authentication was filesystem permission. "
        "Privileged daemons exposed this way accept commands from every account on the box.",
        "Set SocketMode=0660 with SocketUser=/SocketGroup= naming the client group.",
    ),
    _r(
        "UNT025",
        "Socket listens on every interface",
        "medium",
        1,
        "Binding 0.0.0.0 or [::] exposes the socket to every network the host is on, "
        "including the one you did not think about. Most services that do this only ever "
        "needed localhost or a private interface.",
        "Bind 127.0.0.1:port or a specific address, and put a reverse proxy in front when "
        "remote access is required.",
    ),
    _r(
        "UNT026",
        "Accept=yes without MaxConnections",
        "low",
        1,
        "Accept=yes spawns one service instance per connection. Without MaxConnections= the "
        "only ceiling is the process limit, so a connection flood becomes a fork bomb with "
        "a nice name.",
        "Set MaxConnections= to a number the host can actually serve, and keep "
        "MaxConnectionsPerSource= in mind for a shared network.",
    ),
    _r(
        "UNT027",
        "[Install] section enables nothing",
        "low",
        1,
        "An [Install] section without WantedBy=, RequiredBy= or Alias= means `systemctl "
        "enable` has nothing to link. The unit works when started by hand and never comes "
        "back after a reboot -- the classic 'it worked yesterday'.",
        "Add WantedBy=multi-user.target, or delete the empty section so the intent is "
        "explicit.",
    ),
    _r(
        "UNT028",
        "DefaultDependencies=no on a multi-user unit",
        "medium",
        1,
        "DefaultDependencies=no drops the ordering against basic.target and the conflict "
        "with shutdown.target. A unit that is still wanted by multi-user.target then starts "
        "too early and may not be stopped on shutdown, which shows up as a hang.",
        "Remove DefaultDependencies=no unless the unit is early-boot infrastructure, and "
        "add the After=/Before= it would otherwise have inherited.",
    ),
    _r(
        "UNT029",
        "Unknown section name",
        "medium",
        1,
        "systemd ignores sections it does not know, and logs nothing at the default log "
        "level. A typo such as [Services] or [Service ] therefore turns the entire "
        "hardening block into comments that still look like configuration in review.",
        "Use one of the documented section names ([Unit], [Service], [Install], [Timer], "
        "[Socket], [Path], [Mount]) or the [X-...] extension prefix.",
    ),
    _r(
        "UNT030",
        "Wants=network-online.target without After=",
        "medium",
        1,
        "Wants= only pulls the target in; it does not order against it. Without After= the "
        "service starts in parallel with the network coming up, fails to resolve its "
        "backend, and then sits in a restart loop that looks like an application bug.",
        "Add After=network-online.target next to Wants=network-online.target.",
    ),
    _r(
        "UNT031",
        "Deprecated directive",
        "low",
        1,
        "These keys were removed or renamed years ago. systemd logs a warning and ignores "
        "them, so the unit silently loses the behaviour the author intended -- usually a "
        "resource limit or a start-up permission.",
        "Replace with the current spelling: PermissionsStartOnly= -> User= on the specific "
        "ExecStartPre, CPUShares=/MemoryLimit= -> CPUWeight=/MemoryMax= in [Slice].",
    ),
    _r(
        "UNT032",
        "ExecStop kills processes by name",
        "low",
        1,
        "killall/pkill in ExecStop matches every process with that name on the host, "
        "including ones this unit never started. On a shared host that is an outage "
        "delivered by a stop command.",
        "Let systemd stop the cgroup with KillMode=control-group (the default) and remove "
        "the ExecStop= that shells out to a killer.",
    ),
    _r(
        "UNT033",
        "Type=oneshot without RemainAfterExit yet enabled",
        "low",
        1,
        "A oneshot unit that is wanted by a target but does not remain active shows as "
        "inactive right after a successful run. Anything ordered After= it then runs "
        "immediately, which defeats the ordering the author wrote.",
        "Add RemainAfterExit=yes when later units must wait for this one.",
    ),
    _r(
        "UNT034",
        "LimitNOFILE is unbounded",
        "note",
        1,
        "LimitNOFILE=infinity removes the file-descriptor ceiling for the whole cgroup. A "
        "leak in the service then exhausts kernel memory instead of failing a single "
        "request, which turns a bug into a host-wide incident.",
        "Set a concrete number that matches the expected concurrency, for example "
        "LimitNOFILE=65536.",
    ),
    _r(
        "UNT035",
        "Directive sits in a section that ignores it",
        "medium",
        1,
        "systemd honours a fixed set of keys per section and logs an 'Unknown key name' "
        "warning for anything else, at a level nobody reads. A hardening line written into "
        "[Unit] instead of [Service] is therefore a control that reviews as present and does "
        "nothing at runtime -- the same failure as a typo in the section name, one level "
        "deeper.",
        "Move the key into the section that defines it: hardening and Exec* into [Service], "
        "ordering into [Unit], enablement into [Install].",
    ),
    # -- stage 2: the assembled unit -----------------------------------------
    _r(
        "UNT101",
        "A drop-in weakens a hardening directive",
        "high",
        2,
        "This is the failure mode a single-file scanner cannot see: the vendor unit is "
        "hardened, a drop-in written months later sets one key back to 'no', and every "
        "review of the base file still shows the hardening. systemd applies the last value "
        "silently.",
        "Decide which value is intended. If the drop-in is temporary, gate it behind a "
        "ConditionPathExists=; if it is permanent, fix the base unit so the two agree.",
    ),
    _r(
        "UNT102",
        "Admin unit replaces the vendor unit",
        "medium",
        2,
        "A unit file in /etc does not merge with the vendor copy -- it replaces it whole. "
        "Upstream fixes to the vendor unit (a hardening line, an ExecStart path fix) never "
        "reach this host again, and nobody notices because the file still exists.",
        "Keep the override as a drop-in under /etc/systemd/system/<unit>.d/ so the vendor "
        "unit keeps receiving updates, and diff the two files before copying.",
    ),
    _r(
        "UNT103",
        "Drop-in directory has no unit to attach to",
        "medium",
        2,
        "Drop-ins are only read when the unit itself exists. A leftover "
        "<name>.service.d/ after the unit was removed is dead configuration that makes the "
        "next reader believe a control is in place.",
        "Delete the directory, or restore the unit it belongs to.",
    ),
    _r(
        "UNT104",
        "Drop-in file is shadowed by a same-name file",
        "medium",
        2,
        "When the same drop-in filename exists in more than one search directory, systemd "
        "reads only the one from the highest-priority directory. The other file is never "
        "applied, so two admins can each believe their override is live.",
        "Rename one of the files so both apply in a defined order, or delete the dead one.",
    ),
    _r(
        "UNT105",
        "Timer points at a service that is not there",
        "high",
        2,
        "Without Unit=, a timer drives the service with the same name. When that service "
        "does not exist the timer fires forever and does nothing, and `systemctl list-timers` "
        "shows a healthy schedule next to an empty result.",
        "Fix the Unit= name, or create the service the timer names.",
    ),
    _r(
        "UNT106",
        "Two sockets bind the same address",
        "medium",
        2,
        "The second socket unit fails to bind at start time, so one of the two features is "
        "silently unavailable while both units report loaded. The failure only shows in the "
        "journal, at boot, once.",
        "Give each socket its own address, or merge them into one socket with several "
        "ListenStream= lines.",
    ),
    _r(
        "UNT107",
        "Same unit name exists in two vendor directories",
        "medium",
        2,
        "Both /usr/lib/systemd/system and /lib/systemd/system holding the same unit name "
        "means the winner depends on the search path, which differs between distributions "
        "and between container images and their hosts.",
        "Keep one copy and make the other a symlink, so the effective unit is unambiguous.",
    ),
    _r(
        "UNT108",
        "File in a drop-in directory is not a .conf",
        "low",
        2,
        "systemd reads only *.conf inside a .d directory. An override saved as "
        "<name>.service.d/override or override.conf.bak is ignored without a warning, and "
        "the reviewer sees a file that looks like it does something.",
        "Rename it to <something>.conf, or move documentation out of the .d directory.",
    ),
    _r(
        "UNT109",
        "WantedBy names a target nothing defines",
        "note",
        2,
        "The target named in WantedBy= is not among the units in this tree and is not a "
        "built-in one. On a minimal image that is usually a missing package, and the unit "
        "is never enabled.",
        "Install the package that ships the target, or point WantedBy= at "
        "multi-user.target.",
    ),
]

BY_ID: dict[str, Rule] = {rule.id: rule for rule in REGISTRY}


def get(rule_id: str) -> Rule | None:
    return BY_ID.get(rule_id.strip().upper())


def table(stage: int | None = None, severity: str | None = None) -> list[Rule]:
    rows = [rule for rule in REGISTRY if rule.id]
    if stage is not None:
        rows = [rule for rule in rows if rule.stage == stage]
    if severity is not None:
        rows = [rule for rule in rows if rule.severity == severity]
    return sorted(rows, key=lambda rule: rule.id)


def full_markdown() -> str:
    """The whole table as `unitlint rules --markdown`, byte-stable for CI."""
    lines = [
        "# Rules",
        "",
        "Generated by `unitlint rules --markdown`. Do not edit by hand.",
        "",
        f"{len(REGISTRY)} rules. Stage 1 looks at one unit on its own; stage 2 looks at the "
        "unit as systemd assembles it, and at the other units in the same tree.",
        "",
    ]
    for stage, heading in ((1, "Stage 1 - a single unit"), (2, "Stage 2 - assembled units and relations")):
        lines.append(f"## {heading}")
        lines.append("")
        lines.append("| Rule | Severity | What it detects |")
        lines.append("| --- | --- | --- |")
        for rule in table(stage=stage):
            lines.append(f"| `{rule.id}` | {rule.severity} | {rule.title} |")
        lines.append("")
    for rule in sorted(REGISTRY, key=lambda item: item.id):
        lines.append(f"### {rule.id} - {rule.title}")
        lines.append("")
        lines.append(f"Severity **{rule.severity}**, stage {rule.stage}, weight {rule.score}.")
        lines.append("")
        lines.append(f"**Why it matters.** {rule.why}")
        lines.append("")
        lines.append(f"**Fix.** {rule.fix}")
        lines.append("")
    return "\n".join(lines)


__all__ = ["BY_ID", "REGISTRY", "SEVERITIES", "Rule", "full_markdown", "get", "table"]
