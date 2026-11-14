# unitlint

**Audit systemd units the way systemd assembles them** — search-path priority, drop-in overrides, and who set a directive last.

[![CI](https://github.com/xuange-hu/unitlint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/unitlint/actions/workflows/ci.yml)
![tests-247%20passing](https://img.shields.io/badge/tests-247%20passing-brightgreen)
![rules-44](https://img.shields.io/badge/rules-44-blue)
![dependencies-0](https://img.shields.io/badge/dependencies-0-brightgreen)
![python-3.10%2B](https://img.shields.io/badge/python-3.10%2B-blue)
![license-MIT](https://img.shields.io/badge/license-MIT-blue)

Zero dependencies. 44 deterministic rules. Byte-offset evidence. SARIF for CI. Reads a root filesystem, a container image layer, or a single file.

中文说明见 [README_CN.md](README_CN.md).

---

## The unit you read is not the unit that runs

`systemctl cat web-api.service` prints the base file and the drop-ins one after another. Nothing prints the **result**. What actually runs is the result of three rules that no single-file scanner implements:

```
/etc/systemd/system/web-api.service      ← replaces the vendor unit, does not merge with it
/usr/lib/systemd/system/web-api.service  ← dead code the moment the above exists
/etc/systemd/system/web-api.service.d/   ← applied in filename order, after the base unit
   10-limits.conf
   99-debug.conf                        ← sets NoNewPrivileges=no, months later, nobody re-read it
/usr/lib/systemd/system/web-api.service.d/
   10-limits.conf                       ← never read: same filename, lower priority directory
```

`systemd-analyze security` scores a **running** unit; by then the value is already in effect and the file that caused it is not named. A grep over `*.service` sees the hardening line and reports the service as hardened. Both miss the case that actually happens in production: a drop-in that quietly undoes the base file.

unitlint builds the merge first, then audits the result, and can always answer **which file and line won**:

```console
$ unitlint why examples/rootfs web-api.service NoNewPrivileges
web-api.service  NoNewPrivileges  ->  no
  section [Service]
    /usr/lib/systemd/system/web-api.service:13             yes   vendor priority 3
    /etc/systemd/system/web-api.service.d/99-debug.conf:3   no    dropin priority 0  <= effective
```

That output is the whole reason this tool exists.

---

## Three steps

```bash
# 1. install from the checkout (PyPI is not published yet; afterwards: pip install unitlint)
pip install .

# 2. audit a tree - a mounted rootfs, a container layer, or one file
unitlint scan /path/to/rootfs

# 3. gate CI on it
unitlint scan ./image-rootfs --fail-on high --sarif > unitlint.sarif
```

### In a GitHub Actions workflow

The repository is also a composite Action, so there is nothing to install and no
PyPI release to wait for. It installs itself from the Action's own checkout:

```yaml
- uses: xuange-hu/unitlint@v0.1.1
  id: lint
  with:
    path: ./examples/rootfs
    fail-on: high
    sarif: true
- uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9  # v5
  if: always()
  with:
    name: unitlint-sarif
    path: ${{ steps.lint.outputs.report }}
```

Inputs: `path` (default `.`), `unit` (one unit only), `fail-on`
(`none|note|low|medium|high|critical`, default `high`), `sarif` (default `false`).
Outputs: `report` (file path), `verdict` (`PASS`/`FAIL`), `exit-code`.
Inputs travel through environment variables, so a path containing shell
metacharacters is data and not code. Ten tests exercise the entry point for
real, including the exit-code gate and SARIF parsing.

---

No rootfs handy? The built-in corpus fires all 44 rules:

```console
$ unitlint demo
units: 16, findings: 55, risk: 100/100
rules fired: 44/44
every rule in the table has a sample that triggers it
```

---

## What a finding looks like

```
web-api.service (/usr/lib/systemd/system/web-api.service)
  kind=service  base=/usr/lib/systemd/system/web-api.service (vendor)  drop-ins=10-limits.conf, 99-debug.conf
  19 finding(s)  critical=0  high=8  medium=8  low=2  note=1  risk=100/100

[high    ] UNT101  A drop-in weakens a hardening directive
           NoNewPrivileges=yes at /usr/lib/systemd/system/web-api.service:13 is undone by NoNewPrivileges=no at /etc/systemd/system/web-api.service.d/99-debug.conf:3
           /etc/systemd/system/web-api.service.d/99-debug.conf:3, offset 0x2a+22
           saw:  NoNewPrivileges=no
           fix:  make both files agree, or gate the override behind ConditionPathExists=

[high    ] UNT003  ExecStart points into a writable directory
           ExecStart executes /tmp/web-api, which a local user can replace
           /usr/lib/systemd/system/web-api.service:11, offset 0x14c+45
           saw:  ExecStart=/bin/sh -c "/tmp/web-api --port 8080"
           fix:  install the binary under /usr/local/lib or /opt, root-owned, mode 0755
```

Every finding carries the file, the line, the byte offset and the bytes themselves. A finding you cannot check is an opinion.

---

## The 44 rules

Stage 1 looks at one unit; stage 2 looks at the unit as systemd assembled it, and at the units around it.

| Area | Rules | Examples |
| --- | --- | --- |
| Privileges | UNT002, 008, 010, 011, 012, 013 | `AmbientCapabilities=CAP_SETUID`, `Group=root` with a non-root user, root service without `NoNewPrivileges=` |
| Filesystem exposure | UNT003, 006, 009, 017, 018 | binary in `/tmp`, `EnvironmentFile` in `/home`, `ReadWritePaths=/etc` under `ProtectSystem=strict` |
| Secrets | UNT007 | literal `PASSWORD=` in `Environment=` |
| Lifecycle | UNT001, 014, 015, 019, 020, 033 | `Restart=always` with `StartLimitIntervalSec=0`, `Type=forking` without `PIDFile=` |
| Timers | UNT021, 022, 023, 105 | minutely `OnCalendar=`, no `RandomizedDelaySec=`, timer whose service does not exist |
| Sockets | UNT024, 025, 026, 106 | `SocketMode=0666`, `ListenStream=0.0.0.0:9090`, two sockets on one address |
| Configuration traps | UNT027, 028, 029, 030, 031, 034, 035 | `[Services]` typo, directive in a section that ignores it, deprecated `PermissionsStartOnly=` |
| The merge itself | UNT101, 102, 103, 104, 107, 108 | drop-in that weakens hardening, `/etc` unit replacing the vendor unit, shadowed drop-in filename |
| Enablement | UNT109 | `WantedBy=` a target nothing defines |

Full text with the reasoning and the fix for each rule: [docs/rules.md](docs/rules.md) — or `unitlint explain UNT101`.

The threat model behind the rules is in [docs/attack-guide.md](docs/attack-guide.md): what each finding costs an attacker, and which ones are the difference between a compromised service and a compromised host.

---

## Use it in CI

```yaml
- name: Audit the image's units
  run: |
    pip install unitlint
    unitlint scan ./rootfs --fail-on high --sarif > unitlint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: unitlint.sarif
```

Exit codes: `0` nothing at or above `--fail-on`, `1` something was found, `2` the input could not be read. `--fail-on none` runs the rules for the report without failing the job.

Scanning an image without unpacking it by hand:

```bash
docker create --name u img:tag && docker export u | tar -x -C ./rootfs && docker rm u
unitlint scan ./rootfs --fail-on high
```

## Use it from an agent (MCP)

```bash
pip install "unitlint[mcp]"
uvx --from "unitlint[mcp]" unitlint-mcp      # stdio server, 7 tools
```

| Tool | What it answers |
| --- | --- |
| `unitlint_scan` | audit a file, a directory or a rootfs; returns a verdict and evidence |
| `unitlint_text` | audit unit text from a pull request or a chat message, no files |
| `unitlint_why` | which file and line set a directive last, and what it overrode |
| `unitlint_rules` | the table, filterable by stage or severity |
| `unitlint_explain` | one rule: what it detects, why, and the fix |
| `unitlint_sarif` | SARIF 2.1.0 for a code-scanning upload |
| `unitlint_demo` | one call that proves the whole path works |

## What it does not do

- It does not start, stop or query systemd. It is a static reader: it answers "what would systemd load", not "what is loaded".
- It does not follow symlinks out of the tree you point it at, and it does not read `/proc`.
- It does not know about generator output (`/run/systemd/generator`). Units created at boot by a generator are out of scope; the search-path priorities it models are the hand-written ones.
- It does not guess intent. `User=root` on a unit that genuinely needs root is still reported, at `medium`, with the reasoning — lower `--fail-on` or ignore the rule in your pipeline.

## Development

```bash
git clone https://github.com/xuange-hu/unitlint && cd unitlint
python -m pytest -q                 # 237 tests, no install needed
python -m ruff check .
python -m unitlint demo             # 44/44 rules must fire
```

Layout: `parser.py` (one file → directives with offsets), `merge.py` (search path + drop-ins → one unit), `rules.py` (44 checks), `rulebook.py` (severity and prose), `engine.py` (table → report), `render.py` (text / JSON / SARIF), `cli.py`, `mcp_server.py`.

The rule table is data; the checks are code; a test asserts every id in the table has a check that runs. Adding a rule means adding both, plus one sample that triggers it — the demo coverage test fails otherwise.

MIT.
