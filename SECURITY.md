# Security policy

## Reporting

Open a private security advisory on this repository
(`Security` -> `Report a vulnerability`). Please do not open a public issue for
a bug that can make a scan report "clean" on a vulnerable tree.

## What counts as a vulnerability here

unitlint is a static reader. The interesting failures are:

- **A false negative**: a unit that is exploitable but reported clean. Most
  serious class: a merge-semantics bug (wrong drop-in order, wrong priority,
  `/etc` unit treated as a merge instead of a replacement) that hides a finding.
- **A false positive on a stock distribution unit**, which gets the tool
  switched off in CI and therefore hides everything else.
- **A crash on malformed input.** A scanner that dies on a truncated unit file
  is a scanner an attacker can silence by shipping a malformed unit.
- **Unbounded resource use** on adversarial input (deep nesting, very long
  continuation chains, pathological quoting).

## What does not count

- Findings the tool intentionally reports at `medium` because the pattern is
  common in legitimate units (`User=root`). Lower `--fail-on`, or exclude the
  rule in your pipeline.
- Anything about a *running* system's state. unitlint never executes systemd.

## Scope of a scan

`unitlint scan` reads only the tree you point it at and does not follow symlinks
out of it. It never writes, never starts a service and never contacts the
network.
