"""The checks behind the rule table.

Each function takes the assembled unit (base plus drop-ins, already merged) and
the scan context, and returns findings. Functions that only look at one unit
ignore the context; the stage-2 ones use it to reason about the other units in
the same tree.

Severity and prose live in :mod:`unitlint.rulebook`, so a check can never drift
from the table it is registered in.
"""

from __future__ import annotations

import re

from .merge import ScanContext
from .model import KNOWN_SECTIONS, Directive, Finding, Unit, finding, split_items, unquote
from .rulebook import BY_ID

#: Directories an unprivileged local user can write to. A binary, an
#: environment file or a log path under one of these is attacker-controlled
#: input to a service that may well be running as root.
WRITABLE_PREFIXES = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
    "/run/user",
    "/mnt",
    "/media",
    "/var/cache",
)

#: Executable prefixes systemd strips before resolving the binary:
#: ``-`` ignore failure, ``@`` argv[0], ``+``/``!``/``!!`` full privileges.
_EXEC_PREFIX = "-@+!:"

_SHELLS = ("sh", "bash", "dash", "ksh", "zsh", "ash", "busybox")

_SECRET_NAME = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|auth[_-]?key|signing[_-]?key|client[_-]?secret)"
)

_KILLERS = ("killall", "killall5", "pkill", "kill", "killproc", "start-stop-daemon")

_DEPRECATED = {
    "PermissionsStartOnly": "put User=/Group= on the specific ExecStartPre= instead",
    "SysVStartPriority": "ordering is expressed with After=/Before= now",
    "CPUShares": "use CPUWeight= in [Slice] or [Service]",
    "MemoryLimit": "use MemoryMax= / MemoryHigh=",
    "BlockIOWeight": "use IOWeight=",
    "StartLimitInterval": "renamed to StartLimitIntervalSec=",
}

#: Directives that only ever make a unit *more* confined. Stage 2 compares the
#: first and the last occurrence: if the first was stronger, a drop-in (or a
#: second line in the same file) silently undid it.
_BOOLEAN_HARDENING = (
    "NoNewPrivileges",
    "PrivateTmp",
    "PrivateDevices",
    "PrivateUsers",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "ProtectProc",
    "RestrictNamespaces",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "RemoveIPC",
)

_RANKED_HARDENING = {
    "ProtectSystem": {"strict": 3, "full": 3, "yes": 2, "no": 0},
    "ProtectHome": {"strict": 3, "yes": 2, "tmpfs": 2, "read-only": 2, "no": 0},
}

_LIST_HARDENING = ("RestrictAddressFamilies", "SystemCallFilter", "SystemCallArchitectures")

_DANGEROUS_CAPS = ("CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_SYS_BOOT")

_ESCALATION_CAPS = (
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_CHOWN",
    "CAP_FOWNER",
)

_UNIT_SECONDS = (
    ("usec", 1e-6),
    ("us", 1e-6),
    ("msec", 1e-3),
    ("ms", 1e-3),
    ("seconds", 1.0),
    ("second", 1.0),
    ("sec", 1.0),
    ("min", 60.0),
    ("minutes", 60.0),
    ("minute", 60.0),
    ("hours", 3600.0),
    ("hour", 3600.0),
    ("days", 86400.0),
    ("day", 86400.0),
    ("s", 1.0),
    ("m", 60.0),
    ("h", 3600.0),
    ("d", 86400.0),
)


def attach(rule_id: str):
    """Bind a check to its table entry."""

    def decorate(function):
        rule = BY_ID[rule_id]
        rule.check = function
        return function

    return decorate


def _mk(rule_id: str, message: str, directive: Directive | None = None, fix: str = "", **kwargs) -> Finding:
    rule = BY_ID[rule_id]
    return finding(rule.id, rule.severity, message, directive, fix=fix, **kwargs)


def _one(unit: Unit, *candidates: tuple[str, str]) -> Directive | None:
    """First directive that exists from the given ``(section, name)`` pairs."""
    for section, name in candidates:
        found = unit.last(section, name)
        if found is not None:
            return found
    return None


def _first(unit: Unit) -> Directive | None:
    return unit.chain[0] if unit.chain else None


def _strip_prefix(word: str) -> str:
    index = 0
    while index < len(word) and word[index] in _EXEC_PREFIX:
        index += 1
    return word[index:]


def _items(value: str) -> list[str]:
    return [unquote(item) for item in split_items(value)]


def _binary(value: str) -> str:
    items = _items(value)
    return _strip_prefix(items[0]) if items else ""


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


def _writable(path: str) -> bool:
    """True when a local user can write the path or replace it."""
    candidate = path.strip()
    if candidate.startswith("-"):  # EnvironmentFile=-/tmp/x ignores failures
        candidate = candidate[1:]
    candidate = candidate.rstrip("/") or "/"
    return any(candidate == prefix or candidate.startswith(prefix + "/") for prefix in WRITABLE_PREFIXES)


def _seconds(value: str) -> float | None:
    text = value.strip().lower()
    if not text:
        return None
    if text in {"infinity", "inf", "max"}:
        return float("inf")
    for suffix, factor in _UNIT_SECONDS:
        if text.endswith(suffix) and len(text) > len(suffix):
            head = text[: -len(suffix)].strip()
            try:
                return float(head) * factor
            except ValueError:
                continue
    try:
        return float(text)
    except ValueError:
        return None


def _runs_as_root(unit: Unit) -> bool:
    if unit.flag("Service", "DynamicUser") is True:
        return False
    user = unit.text("Service", "User").strip()
    return user in {"", "root", "0"}


def _octal(value: str) -> int | None:
    text = value.strip().lower()
    if text.startswith("0o"):
        text = text[2:]
    try:
        return int(text, 8)
    except ValueError:
        return None


def _install_targets(unit: Unit) -> list[str]:
    return [item for item in unit.values("Install", "WantedBy") if item]


# ---------------------------------------------------------------------------
# Stage 1
# ---------------------------------------------------------------------------


@attach("UNT001")
def no_exec_start(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "service" or unit.base is None:
        return []
    if unit.present("Service", "ExecStart"):
        return []
    # Point at the file even when it holds nothing: an empty unit is still the
    # file someone has to fix, and a finding with no location is unactionable.
    evidence = _first(unit)
    if evidence is not None:
        return [_mk("UNT001", "the [Service] section defines no ExecStart, so the unit cannot start", evidence)]
    return [
        _mk(
            "UNT001",
            "the unit file defines no ExecStart, so the unit cannot start",
            None,
            where=unit.base.path,
            line=1,
            saw="",
        )
    ]


@attach("UNT002")
def runs_as_root(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "service" or unit.base is None:
        return []
    # A unit with no command is UNT001's finding, not a privilege finding: there
    # is nothing to run, and reporting both would bury the one that matters.
    if not unit.present("Service", "ExecStart"):
        return []
    if not _runs_as_root(unit):
        return []
    user = unit.text("Service", "User").strip()
    reason = f"User={user}" if user else "no User="
    return [
        _mk(
            "UNT002",
            f"runs as root ({reason}); every file it writes and every child it spawns is root",
            _one(unit, ("Service", "ExecStart"), ("Service", "Type")) or _first(unit),
            fix="add User= and Group= for a dedicated account",
        )
    ]


@attach("UNT003")
def exec_in_writable_dir(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for name in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload"):
        for directive in unit.present("Service", name):
            binary = _binary(directive.value)
            if binary and _writable(binary):
                out.append(
                    _mk(
                        "UNT003",
                        f"{name} executes {binary}, which a local user can replace",
                        directive,
                        fix="install the binary under /usr/local/lib or /opt, root-owned, mode 0755",
                    )
                )
    return out


@attach("UNT004")
def exec_through_shell(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for name in ("ExecStart", "ExecStartPre", "ExecStop", "ExecReload"):
        for directive in unit.present("Service", name):
            items = _items(directive.value)
            if not items:
                continue
            binary = _strip_prefix(items[0])
            if _basename(binary) in _SHELLS and "-c" in items[1:]:
                out.append(
                    _mk(
                        "UNT004",
                        f"{name} runs {binary} -c; quoting bugs in the string become command injection",
                        directive,
                        fix="call the program directly and pass its arguments as separate words",
                    )
                )
    return out


@attach("UNT005")
def relative_exec_path(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for name in ("ExecStart", "ExecStartPre", "ExecStop"):
        for directive in unit.present("Service", name):
            binary = _binary(directive.value)
            if not binary or binary.startswith("/") or binary.startswith("%") or binary.startswith("$"):
                continue
            if "/" not in binary:
                continue  # a simple name is searched in a fixed path list
            out.append(
                _mk(
                    "UNT005",
                    f"{name} uses the relative path {binary}, resolved against WorkingDirectory at start time",
                    directive,
                )
            )
    return out


@attach("UNT006")
def environment_file_writable(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.items("Service", "EnvironmentFile"):
        path = directive.value
        if _writable(path):
            out.append(
                _mk(
                    "UNT006",
                    f"EnvironmentFile={path} is writable by unprivileged users; LD_PRELOAD comes from here",
                    directive,
                    fix="move the file to /etc/<name>/env, mode 0600, owned by root",
                )
            )
    return out


@attach("UNT007")
def literal_secret(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.items("Service", "Environment"):
        assignment = directive.value
        name, sep, value = assignment.partition("=")
        if not sep:
            continue
        if not _SECRET_NAME.search(name):
            continue
        # A name that ends in _FILE/_PATH holds a reference, not the secret.
        if re.search(r"(?i)(_file|_path|_dir|_url)$", name):
            continue
        if not value or value.startswith("$") or value.startswith("%"):
            continue
        out.append(
            _mk(
                "UNT007",
                f"Environment= sets {name} to a literal value; `systemctl show` prints it to any local user",
                directive,
                fix="use LoadCredential= and read $CREDENTIALS_DIRECTORY",
            )
        )
    return out


@attach("UNT008")
def no_new_privileges_off(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "service" or unit.base is None or not _runs_as_root(unit):
        return []
    if not unit.present("Service", "ExecStart"):
        return []
    if unit.flag("Service", "NoNewPrivileges") is True:
        return []
    return [
        _mk(
            "UNT008",
            "a root service without NoNewPrivileges=yes keeps the whole setuid escalation path open",
            _one(unit, ("Service", "NoNewPrivileges"), ("Service", "ExecStart")) or _first(unit),
            fix="add NoNewPrivileges=yes",
        )
    ]


@attach("UNT009")
def readwrite_paths_reopen(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    protect = unit.text("Service", "ProtectSystem").strip().lower()
    if protect not in {"strict", "full", "yes"}:
        return []
    dangerous = ("/", "/etc", "/usr", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/var")
    out: list[Finding] = []
    for directive in unit.items("Service", "ReadWritePaths"):
        path = directive.value.rstrip("/") or "/"
        if path in dangerous:
            out.append(
                _mk(
                    "UNT009",
                    f"ProtectSystem={protect} makes {path} read-only, then ReadWritePaths={path} writes it again",
                    directive,
                    fix="narrow ReadWritePaths to /var/lib/<name> or /run/<name>",
                )
            )
    return out


@attach("UNT010")
def dangerous_capability(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.items("Service", "CapabilityBoundingSet"):
        capability = directive.value.strip()
        if capability.startswith("~"):
            continue  # "~CAP_X" removes the capability, it does not keep it
        if capability.upper() in _DANGEROUS_CAPS:
            out.append(
                _mk(
                    "UNT010",
                    f"CapabilityBoundingSet keeps {capability}, which is root-equivalent on most kernels",
                    directive,
                    fix="start from an empty bounding set and add only what the program needs",
                )
            )
    return out


@attach("UNT011")
def ambient_escalation(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.items("Service", "AmbientCapabilities"):
        capability = directive.value.strip().upper()
        if capability in _ESCALATION_CAPS:
            out.append(
                _mk(
                    "UNT011",
                    f"AmbientCapabilities={capability} survives exec, so every child keeps it",
                    directive,
                    fix="drop the ambient capability; use a narrow privileged helper instead",
                )
            )
    return out


@attach("UNT012")
def group_root(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    user = unit.text("Service", "User").strip()
    group = unit.text("Service", "Group").strip()
    if not group or group != "root" or user in {"", "root", "0"}:
        return []
    return [
        _mk(
            "UNT012",
            f"User={user} but Group=root; the process can rewrite /etc and truncate logs",
            _one(unit, ("Service", "Group")),
            fix="set Group= to the service's own group",
        )
    ]


@attach("UNT013")
def supplementary_root(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.items("Service", "SupplementaryGroups"):
        if directive.value.strip() == "root":
            out.append(
                _mk(
                    "UNT013",
                    "SupplementaryGroups=root grants root-group access on top of a correct-looking User=",
                    directive,
                )
            )
    return out


@attach("UNT014")
def restart_unbounded(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    restart = unit.text("Service", "Restart").strip().lower()
    if restart not in {"always", "on-failure", "on-abnormal", "on-abort"}:
        return []
    limit = unit.last("Unit", "StartLimitIntervalSec") or unit.last("Unit", "StartLimitInterval")
    if limit is None or _seconds(limit.value) != 0:
        return []
    return [
        _mk(
            "UNT014",
            "StartLimitIntervalSec=0 disables the start rate limiter, so a crash loops as fast as systemd can fork",
            limit,
            fix="delete the line and keep the default limiter",
        )
    ]


@attach("UNT015")
def restart_no_delay(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.text("Service", "Restart").strip().lower() != "always":
        return []
    delay = unit.last("Service", "RestartSec")
    seconds = 0.0 if delay is None else _seconds(delay.value)
    if seconds is not None and seconds >= 1.0:
        return []
    return [
        _mk(
            "UNT015",
            "Restart=always with a restart delay below one second hammers a dependency while it is down",
            _one(unit, ("Service", "Restart"), ("Service", "RestartSec")) or _first(unit),
            fix="set RestartSec=5s or more",
        )
    ]


@attach("UNT016")
def permissive_umask(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    directive = unit.last("Service", "UMask")
    if directive is None:
        return []
    mode = _octal(directive.value)
    if mode is None or mode & 0o007:
        return []
    return [
        _mk(
            "UNT016",
            f"UMask={directive.value} leaves newly created files writable by every local user",
            directive,
            fix="set UMask=0027",
        )
    ]


@attach("UNT017")
def stdout_writable(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for name in ("StandardOutput", "StandardError"):
        directive = unit.last("Service", name)
        if directive is None:
            continue
        value = directive.text.strip()
        for prefix in ("append:", "file:", "truncate:"):
            if value.startswith(prefix):
                path = value[len(prefix) :]
                if _writable(path):
                    out.append(
                        _mk(
                            "UNT017",
                            f"{name}={value} follows symlinks through a writable path",
                            directive,
                            fix="log to the journal, or use LogsDirectory=",
                        )
                    )
                break
    return out


@attach("UNT018")
def working_directory_writable(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    directive = unit.last("Service", "WorkingDirectory")
    if directive is None:
        return []
    path = directive.text.strip()
    if path in {"~", "-~"}:
        return []
    if _writable(path):
        return [
            _mk(
                "UNT018",
                f"WorkingDirectory={path} is writable by others, so relative paths are attacker-controlled",
                directive,
                fix="use StateDirectory= or CacheDirectory=",
            )
        ]
    return []


@attach("UNT019")
def forking_without_pidfile(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "service" or unit.text("Service", "Type").strip() != "forking":
        return []
    if unit.last("Service", "PIDFile") is not None:
        return []
    return [
        _mk(
            "UNT019",
            "Type=forking without PIDFile= guesses the main process and can track a process that already exited",
            _one(unit, ("Service", "Type")),
            fix="set PIDFile= or switch to Type=notify",
        )
    ]


@attach("UNT020")
def notify_without_access(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "service" or unit.text("Service", "Type").strip() != "notify":
        return []
    if unit.last("Service", "NotifyAccess") is not None:
        return []
    return [
        _mk(
            "UNT020",
            "Type=notify with the default NotifyAccess=main drops notifications sent from a child process",
            _one(unit, ("Service", "Type")),
            fix="set NotifyAccess=all when the notification comes from a worker",
        )
    ]


@attach("UNT021")
def timer_minutely(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "timer":
        return []
    out: list[Finding] = []
    for directive in unit.items("Timer", "OnCalendar"):
        spec = directive.value.strip()
        if spec == "minutely" or "*:*" in spec:
            out.append(
                _mk(
                    "UNT021",
                    f"OnCalendar={spec} fires every minute; that is 1440 wake-ups a day per host",
                    directive,
                    fix="use a longer interval or OnUnitInactiveSec=",
                )
            )
    return out


@attach("UNT022")
def timer_no_jitter(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "timer" or unit.last("Timer", "RandomizedDelaySec") is not None:
        return []
    calendar = [item for item in unit.values("Timer", "OnCalendar") if ":" in item]
    if not calendar:
        return []
    return [
        _mk(
            "UNT022",
            "a fixed OnCalendar= time makes every host in the fleet fire in the same second",
            unit.last("Timer", "OnCalendar"),
            fix="add RandomizedDelaySec=5min",
        )
    ]


@attach("UNT023")
def timer_not_persistent(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "timer" or not unit.values("Timer", "OnCalendar"):
        return []
    if unit.flag("Timer", "Persistent") is True:
        return []
    return [
        _mk(
            "UNT023",
            "without Persistent=true a run missed while the machine was off is skipped silently",
            unit.last("Timer", "OnCalendar"),
            fix="add Persistent=true for backups and renewals",
        )
    ]


@attach("UNT024")
def socket_world_writable(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "socket":
        return []
    directive = unit.last("Socket", "SocketMode")
    if directive is None:
        return []
    mode = _octal(directive.value)
    if mode is None or not mode & 0o002:
        return []
    return [
        _mk(
            "UNT024",
            f"SocketMode={directive.value} lets any local user connect to a socket the service trusts",
            directive,
            fix="set SocketMode=0660 with SocketUser=/SocketGroup=",
        )
    ]


@attach("UNT025")
def socket_all_interfaces(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "socket":
        return []
    out: list[Finding] = []
    for name in ("ListenStream", "ListenDatagram", "ListenSequentialPacket"):
        for directive in unit.items("Socket", name):
            address = directive.value.strip()
            if address.startswith(("0.0.0.0:", "[::]:", "*:")):
                out.append(
                    _mk(
                        "UNT025",
                        f"{name}={address} is reachable from every network the host is on",
                        directive,
                        fix="bind 127.0.0.1 or a specific address",
                    )
                )
    return out


@attach("UNT026")
def socket_accept_unbounded(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.kind != "socket" or unit.flag("Socket", "Accept") is not True:
        return []
    if unit.last("Socket", "MaxConnections") is not None:
        return []
    return [
        _mk(
            "UNT026",
            "Accept=yes spawns one instance per connection with no MaxConnections= ceiling",
            _one(unit, ("Socket", "Accept")),
            fix="set MaxConnections=",
        )
    ]


@attach("UNT027")
def install_enables_nothing(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    headers = [entry for entry in unit.declared if entry[0] == "Install"]
    if not headers:
        return []
    for key in ("WantedBy", "RequiredBy", "Alias", "Also"):
        if unit.present("Install", key):
            return []
    section, source, lineno, offset = headers[0]
    return [
        _mk(
            "UNT027",
            f"[Install] at {source}:{lineno} names no target, so `systemctl enable` links nothing",
            None,
            where=source,
            line=lineno,
            offset=offset,
            saw=f"[{section}]",
            fix="add WantedBy=multi-user.target, or delete the empty section",
        )
    ]


@attach("UNT028")
def default_dependencies_off(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.flag("Unit", "DefaultDependencies") is not False:
        return []
    wanted = _install_targets(unit)
    clash = [target for target in wanted if target in {"multi-user.target", "graphical.target", "basic.target"}]
    if not clash:
        return []
    return [
        _mk(
            "UNT028",
            f"DefaultDependencies=no but WantedBy={clash[0]}: the unit loses its ordering "
            "against basic.target and shutdown.target",
            unit.last("Unit", "DefaultDependencies"),
            fix="remove DefaultDependencies=no, or add the After=/Conflicts= it would have inherited",
        )
    ]


@attach("UNT029")
def unknown_section(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for section, source, lineno, offset in unit.declared:
        if section in KNOWN_SECTIONS or section.startswith("X-") or section in seen:
            continue
        seen.add(section)
        out.append(
            _mk(
                "UNT029",
                f"[{section}] is not a section systemd knows, so every directive inside it "
                "is ignored without a warning",
                None,
                where=source,
                line=lineno,
                offset=offset,
                saw=f"[{section}]",
                fix="rename the section; check the spelling against systemd.unit(5)",
            )
        )
    return out


@attach("UNT030")
def online_target_without_after(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    wants = set(unit.values("Unit", "Wants")) | set(unit.values("Unit", "Requires"))
    if "network-online.target" not in wants:
        return []
    after = set(unit.values("Unit", "After"))
    if "network-online.target" in after:
        return []
    return [
        _mk(
            "UNT030",
            "Wants=network-online.target without After= starts the service in parallel with the network coming up",
            _one(unit, ("Unit", "Wants"), ("Unit", "Requires")),
            fix="add After=network-online.target",
        )
    ]


@attach("UNT031")
def deprecated_directive(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.chain:
        if directive.name in _DEPRECATED:
            out.append(
                _mk(
                    "UNT031",
                    f"{directive.name}= is no longer honoured; systemd logs a warning and ignores it "
                    f"({_DEPRECATED[directive.name]})",
                    directive,
                    fix=_DEPRECATED[directive.name],
                )
            )
    return out


@attach("UNT032")
def exec_stop_kills_by_name(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for name in ("ExecStop", "ExecStopPost"):
        for directive in unit.present("Service", name):
            binary = _binary(directive.value)
            if _basename(binary) in _KILLERS:
                out.append(
                    _mk(
                        "UNT032",
                        f"{name} runs {_basename(binary)}, which matches every process with that name on the host",
                        directive,
                        fix="remove ExecStop= and let KillMode=control-group stop the cgroup",
                    )
                )
    return out


@attach("UNT033")
def oneshot_not_remaining(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.text("Service", "Type").strip() != "oneshot":
        return []
    if unit.flag("Service", "RemainAfterExit") is True:
        return []
    if not _install_targets(unit):
        return []
    return [
        _mk(
            "UNT033",
            "Type=oneshot without RemainAfterExit=yes shows as inactive right after success, "
            "so anything ordered after it runs immediately",
            _one(unit, ("Service", "Type")),
            fix="add RemainAfterExit=yes",
        )
    ]


@attach("UNT034")
def limit_nofile_infinity(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    directive = unit.last("Service", "LimitNOFILE")
    if directive is None or directive.text.strip().lower() not in {"infinity", "inf", "max"}:
        return []
    return [
        _mk(
            "UNT034",
            "LimitNOFILE=infinity removes the fd ceiling for the whole cgroup, so a leak exhausts kernel memory",
            directive,
            fix="set a concrete limit such as 65536",
        )
    ]


#: Where a key is actually honoured. systemd reads a fixed set of keys per
#: section and logs an "Unknown key name" warning for the rest -- at a level
#: most people never look at. A misplaced hardening line is therefore a control
#: that reads as present in review and does nothing at runtime.
_KEY_SECTIONS = {
    "NoNewPrivileges": {"Service"},
    "ProtectSystem": {"Service"},
    "ProtectHome": {"Service"},
    "PrivateTmp": {"Service"},
    "PrivateDevices": {"Service"},
    "PrivateUsers": {"Service"},
    "ProtectKernelTunables": {"Service"},
    "ProtectKernelModules": {"Service"},
    "ProtectControlGroups": {"Service"},
    "RestrictAddressFamilies": {"Service"},
    "RestrictNamespaces": {"Service"},
    "SystemCallFilter": {"Service"},
    "CapabilityBoundingSet": {"Service"},
    "AmbientCapabilities": {"Service"},
    "ReadWritePaths": {"Service"},
    "ReadOnlyPaths": {"Service"},
    "InaccessiblePaths": {"Service"},
    "UMask": {"Service"},
    "User": {"Service"},
    "Group": {"Service"},
    "SupplementaryGroups": {"Service"},
    "DynamicUser": {"Service"},
    "ExecStart": {"Service"},
    "ExecStartPre": {"Service"},
    "ExecStartPost": {"Service"},
    "ExecStop": {"Service"},
    "ExecReload": {"Service"},
    "Type": {"Service"},
    "Restart": {"Service"},
    "RestartSec": {"Service"},
    "NotifyAccess": {"Service"},
    "PIDFile": {"Service"},
    "StandardOutput": {"Service"},
    "StandardError": {"Service"},
    "WorkingDirectory": {"Service"},
    "Environment": {"Service"},
    "EnvironmentFile": {"Service"},
    "LimitNOFILE": {"Service"},
    "RemainAfterExit": {"Service"},
    "RuntimeDirectory": {"Service"},
    "StateDirectory": {"Service"},
    "LogsDirectory": {"Service"},
    "After": {"Unit"},
    "Before": {"Unit"},
    "Wants": {"Unit"},
    "Requires": {"Unit"},
    "Conflicts": {"Unit"},
    "DefaultDependencies": {"Unit"},
    "StartLimitIntervalSec": {"Unit"},
    "StartLimitBurst": {"Unit"},
    "ConditionPathExists": {"Unit"},
    "WantedBy": {"Install"},
    "RequiredBy": {"Install"},
    "Alias": {"Install"},
    "Also": {"Install"},
    "OnCalendar": {"Timer"},
    "OnUnitInactiveSec": {"Timer"},
    "Persistent": {"Timer"},
    "RandomizedDelaySec": {"Timer"},
    "Unit": {"Timer", "Path"},
    "ListenStream": {"Socket"},
    "ListenDatagram": {"Socket"},
    "SocketMode": {"Socket"},
    "SocketUser": {"Socket"},
    "SocketGroup": {"Socket"},
    "Accept": {"Socket"},
    "MaxConnections": {"Socket"},
    "PathExists": {"Path"},
}


@attach("UNT035")
def directive_in_wrong_section(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for directive in unit.chain:
        allowed = _KEY_SECTIONS.get(directive.name)
        if allowed is None or directive.section in allowed:
            continue
        expected = " or ".join(sorted(f"[{name}]" for name in allowed))
        out.append(
            _mk(
                "UNT035",
                f"{directive.name}= is set in [{directive.section}], where systemd ignores it; "
                f"it belongs in {expected}",
                directive,
                fix=f"move the line into {expected}",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Stage 2
# ---------------------------------------------------------------------------


def _rank(key: str, value: str) -> int:
    if not value.strip():
        # An empty assignment is a reset, and the default for every directive in
        # these tables is the permissive value.
        return 0
    if key in _RANKED_HARDENING:
        return _RANKED_HARDENING[key].get(value.strip().lower(), 1)
    if key in _LIST_HARDENING:
        token = value.strip()
        if not token or token.startswith("~"):
            return 0
        return 2
    parsed = {"1": True, "yes": True, "true": True, "on": True, "0": False, "no": False, "false": False, "off": False}
    return 2 if parsed.get(value.strip().lower()) else 0


@attach("UNT101")
def dropin_weakens(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    for key in (*_BOOLEAN_HARDENING, *_RANKED_HARDENING, *_LIST_HARDENING):
        # every(), not present(): `NoNewPrivileges=` with an empty value resets
        # the directive to its default, which for all of these is the weak one.
        history = unit.every("Service", key)
        if len(history) < 2:
            continue
        first, last = history[0], history[-1]
        before, after = _rank(key, first.value), _rank(key, last.value)
        if before > after:
            out.append(
                _mk(
                    "UNT101",
                    f"{key}={first.value.strip()} at {first.where} is undone by "
                    f"{key}={last.value.strip() or '<reset>'} at {last.where}",
                    last,
                    where=last.source,
                    fix="make both files agree, or gate the override behind ConditionPathExists=",
                )
            )
    return out


@attach("UNT102")
def admin_replaces_vendor(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.base is None or unit.base.role not in {"admin", "run", "local"}:
        return []
    vendors = [file for file in unit.replaced if file.role == "vendor"]
    if not vendors:
        return []
    vendor = vendors[0]
    vendor_exec = next((d for d in vendor.directives if d.name == "ExecStart"), None)
    admin_exec = unit.last("Service", "ExecStart")
    note = ""
    if vendor_exec is not None and admin_exec is not None and vendor_exec.value.strip() != admin_exec.value.strip():
        note = f"; ExecStart differs ({vendor_exec.value.strip()!r} vs {admin_exec.value.strip()!r})"
    return [
        _mk(
            "UNT102",
            f"{unit.base.path} replaces {vendor.path} whole, so upstream fixes never reach this host{note}",
            unit.base.directives[0] if unit.base.directives else None,
            where=unit.base.path,
            line=1,
            length=0,
            fix="keep the override as a drop-in under /etc/systemd/system/<unit>.d/",
        )
    ]


@attach("UNT103")
def orphan_dropin(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.base is not None or not unit.dropins:
        return []
    dropin = unit.dropins[0]
    return [
        _mk(
            "UNT103",
            f"{dropin.path} belongs to {unit.name}, which does not exist; drop-ins are only read when the unit does",
            dropin.directives[0] if dropin.directives else None,
            where=dropin.path,
            line=1,
            length=0,
            fix="delete the directory or restore the unit",
        )
    ]


@attach("UNT104")
def shadowed_dropin(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    out: list[Finding] = []
    applied = {dropin.basename: dropin for dropin in unit.dropins}
    for dropin in unit.shadowed:
        winner = applied.get(dropin.basename)
        target = winner.directives[0] if winner is not None and winner.directives else None
        out.append(
            _mk(
                "UNT104",
                f"{dropin.path} is never read: {winner.path if winner else 'a higher-priority copy'} "
                f"has the same filename and wins",
                target,
                where=dropin.path,
                line=1,
                length=0,
                fix="rename one of the two files so both apply in a defined order",
            )
        )
    return out


@attach("UNT105")
def timer_to_missing_service(unit: Unit, context: ScanContext | None) -> list[Finding]:
    if unit.kind != "timer":
        return []
    if context is None or not context.complete:
        return []
    target = unit.text("Timer", "Unit").strip()
    if not target:
        target = unit.name[: -len(".timer")] + ".service"
    if target in context.units:
        return []
    directive = unit.last("Timer", "Unit") or unit.last("Timer", "OnCalendar")
    return [
        _mk(
            "UNT105",
            f"the timer drives {target}, which is not in this tree; it fires forever and does nothing",
            directive,
            where=directive.source if directive else "",
            fix="fix Unit= or create the service",
        )
    ]


@attach("UNT106")
def socket_port_collision(unit: Unit, context: ScanContext | None) -> list[Finding]:
    if unit.kind != "socket" or context is None:
        return []
    out: list[Finding] = []
    mine = set()
    for name in ("ListenStream", "ListenDatagram", "ListenSequentialPacket"):
        for directive in unit.items("Socket", name):
            mine.add(directive.value.strip())
    for other in context.sorted_units():
        # Reported once, on the unit whose name sorts later, so a tree with two
        # colliding sockets yields one finding and not a mirrored pair.
        if other.kind != "socket" or other.name >= unit.name:
            continue
        theirs = set()
        for name in ("ListenStream", "ListenDatagram", "ListenSequentialPacket"):
            theirs.update(item for item in other.values("Socket", name))
        shared = mine & theirs
        if not shared:
            continue
        address = sorted(shared)[0]
        out.append(
            _mk(
                "UNT106",
                f"{address} is also bound by {other.name}; whichever starts second fails to bind",
                unit.last("Socket", "ListenStream") or unit.last("Socket", "ListenDatagram"),
                fix="give each socket its own address",
            )
        )
    return out


@attach("UNT107")
def duplicate_vendor_unit(unit: Unit, _context: ScanContext | None) -> list[Finding]:
    if unit.base is None:
        return []
    rivals = [file for file in unit.replaced if file.role == unit.base.role == "vendor"]
    if not rivals:
        return []
    return [
        _mk(
            "UNT107",
            f"{unit.name} also exists at {rivals[0].path}; which one wins depends on the "
            "search path of the distribution",
            unit.base.directives[0] if unit.base.directives else None,
            where=unit.base.path,
            line=1,
            length=0,
            fix="keep one copy and make the other a symlink",
        )
    ]


#: UNT108 is about files that never become a unit, so it is a context-level
#: check: it cannot be attributed to a unit and would return nothing if it were
#: written as a per-unit check. engine.scan runs it once per tree.
CONTEXT_CHECKS = ("UNT108",)


def stray_findings(context: ScanContext) -> list[Finding]:
    """UNT108, run once per tree instead of once per unit."""
    out: list[Finding] = []
    for path, _owner, reason in context.strays:
        out.append(
            _mk(
                "UNT108",
                f"{path} is {reason}; systemd reads only *.conf inside a .d directory",
                None,
                where=path,
                line=1,
                length=0,
                saw=path,
                fix="rename it to <something>.conf",
            )
        )
    return out


@attach("UNT109")
def unknown_wanted_target(unit: Unit, context: ScanContext | None) -> list[Finding]:
    if context is None or not context.complete:
        return []
    targets = {other.name for other in context.units.values() if other.kind == "target"}
    if not targets:
        return []
    builtin = {
        "multi-user.target",
        "graphical.target",
        "basic.target",
        "sysinit.target",
        "network.target",
        "network-online.target",
        "local-fs.target",
        "remote-fs.target",
        "sockets.target",
        "timers.target",
        "default.target",
        "shutdown.target",
        "reboot.target",
        "poweroff.target",
        "rescue.target",
        "emergency.target",
        "getty.target",
        "nss-lookup.target",
        "time-sync.target",
        "paths.target",
        "slices.target",
        "systemd-journald.service",
    }
    out: list[Finding] = []
    for directive in unit.items("Install", "WantedBy"):
        target = directive.value.strip()
        if not target or target in builtin or target in targets:
            continue
        out.append(
            _mk(
                "UNT109",
                f"WantedBy={target} names a target nothing in this tree defines",
                directive,
                fix="install the package that ships the target, or use multi-user.target",
            )
        )
    return out


#: Stage-2 checks that need the whole tree; kept in table order for the report.
ALL_CHECKS = [rule for rule in BY_ID.values() if rule.check is not None]


__all__ = ["ALL_CHECKS", "CONTEXT_CHECKS", "WRITABLE_PREFIXES", "attach", "stray_findings"]
