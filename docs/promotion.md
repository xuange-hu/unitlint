# Promotion copy

Four channels, written to be pasted as-is. Nothing here is auto-posted: posting
is a human decision and a human account.

## Show HN

**Title:** Show HN: unitlint – audit systemd units the way systemd assembles them

**Body:**

`systemctl cat foo.service` prints the base unit and then the drop-ins, one after another. It never prints the result. `systemd-analyze security` scores the *running* unit, so by the time you see a score the value is already in effect and it does not tell you which file set it.

So two things keep happening: a vendor unit is hardened, a drop-in written months later sets one key back to `no`, and every review of the base file still shows the hardening. Or a unit file in `/etc` silently replaces the vendor unit, and upstream fixes never arrive again.

unitlint builds the merge first (search-path priority, drop-in order, same-filename shadowing, base replacement), then audits the assembled unit, and can always name the file and line that won:

```
$ unitlint why ./rootfs web-api.service NoNewPrivileges
web-api.service  NoNewPrivileges  ->  no
  section [Service]
    /usr/lib/systemd/system/web-api.service:13             yes   vendor priority 3
    /etc/systemd/system/web-api.service.d/99-debug.conf:3   no    dropin priority 0  <= effective
```

44 rules, every finding carries file + line + byte offset + the raw bytes. Zero runtime dependencies (it should be able to run inside the image it audits). SARIF for code scanning. `unitlint demo` runs a built-in corpus that fires all 44 rules, and a test pins that corpus to `examples/rootfs` byte for byte.

What it does not do: it never talks to systemd, so it answers "what would be loaded", not "what is loaded". Generator output is out of scope.

```
pip install unitlint
unitlint scan ./rootfs --fail-on high
```

Repo: https://github.com/xuange-hu/unitlint — I would particularly like false positives on stock distribution units, since a noisy scanner gets switched off.

## Reddit — r/linuxadmin

**Title:** I wrote a static auditor for systemd units that reports *which drop-in* undid the hardening

**Body:**

Long version of the story: we had a service that was "hardened" — `ProtectSystem=strict`, `NoNewPrivileges=yes`, all of it — and still ended up writing into `/etc` during an incident. The base file was fine. A drop-in added eight months earlier by someone debugging a timeout had `ProtectSystem=no` and `NoNewPrivileges=no`, and no review had touched the base file since.

`systemctl cat` shows you the files in order, so the information was technically there; nobody reads four files and diffs them in their head. `systemd-analyze security` gave the unit a bad score but not a cause.

So: unitlint assembles the unit (search path, drop-in filename order, same-name shadowing, `/etc` replacing vendor) and audits the *result*. `unitlint why <unit> <Directive>` prints the whole chain with priorities and marks the winner.

44 rules, two stages: single-unit attributes, then the assembled unit and its relations (timer → missing service, two sockets on one port, drop-in that weakens hardening, `/etc` override of a vendor unit).

It reads a mounted rootfs, so the useful CI shape is "unpack the image, scan it, fail the build". Zero dependencies, so it runs in the image.

```bash
unitlint scan ./rootfs --fail-on high
```

https://github.com/xuange-hu/unitlint — feedback on false positives is the most useful thing you can send.

## Reddit — r/devops

**Title:** unitlint: systemd unit audit that can gate a container build (44 rules, SARIF, zero deps)

**Body:**

Container images carry systemd units more often than people expect — base images, init wrappers, sidecar images built FROM a distro base. Those units inherit the distro's vendor files and then get drop-ins layered on during the build, which is exactly the situation where "the file you read" and "the unit that runs" diverge.

unitlint models the merge (search path, drop-in order, shadowing, replacement) and audits the result. It also knows where a directive is actually honoured: a `ProtectSystem=` line in `[Unit]` instead of `[Service]` is ignored by systemd with a warning nobody reads, and that is a rule (UNT035).

CI shape:

```yaml
- run: |
    pip install unitlint
    unitlint scan ./rootfs --fail-on high --sarif > unitlint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: unitlint.sarif }
```

Exit codes: 0 clean, 1 findings at or above the threshold, 2 unreadable input. Zero runtime dependencies; 235 tests including a bare-clone run.

https://github.com/xuange-hu/unitlint

## X / Mastodon thread

1/ `systemctl cat` prints your unit and its drop-ins. It never prints the result. So a drop-in can set `ProtectSystem=no` eight months after the fact and every review of the base file still shows the hardening. I wrote a tool that audits the assembled unit instead.

2/ unitlint builds the merge the way systemd does: search-path priority (`/etc` > `/run` > `/usr/local/lib` > `/usr/lib` > `/lib`), drop-ins in filename order after the base, same filename in two dirs → only the higher-priority one is read. Then it audits what came out.

3/ And it can name the winner:

```
$ unitlint why ./rootfs web-api.service NoNewPrivileges
  ->  no
  /usr/lib/.../web-api.service:13             yes   vendor priority 3
  /etc/.../web-api.service.d/99-debug.conf:3   no    dropin priority 0  <= effective
```

4/ 44 rules, two stages: the unit on its own, then the assembled unit plus its neighbours (timer → missing service, two sockets on one port, `/etc` unit replacing the vendor one).

5/ Every finding carries file + line + byte offset + the raw bytes. SARIF out, so it can gate a build. Zero dependencies, so it runs inside the image it audits.

6/ `pip install unitlint && unitlint demo` — the built-in corpus fires all 44 rules, and a test pins that corpus to `examples/rootfs` byte for byte, so the demo cannot describe a tree that does not exist.

https://github.com/xuange-hu/unitlint

## One-line description (for awesome lists / directories)

> **unitlint** – Static audit for systemd units that models the merge first: search-path priority, drop-in overrides, `/etc` replacement. 44 rules, byte-offset evidence, SARIF, zero dependencies. Answers "which file set this value last".

Suggested awesome-list sections: `Security` → `Hardening / Auditing`, `Linux` → `Systemd`, `DevOps` → `Static analysis`.
