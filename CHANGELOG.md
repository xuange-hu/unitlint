# Changelog

## 0.1.0 - 2026-11-13

First release.

- **Merge before audit.** Discovery over the real systemd search path
  (`/etc` > `/run` > `/usr/local/lib` > `/usr/lib` > `/lib`), drop-in
  application in filename order, same-filename shadowing across directories,
  and `/etc` units replacing rather than merging with vendor units.
- **44 rules**, 35 on a single unit and 9 on the assembled unit and the tree
  around it. Each has a severity, a reasoning paragraph and a fix.
- **`unitlint why ROOT UNIT DIRECTIVE`**: the full chain for one directive, with
  the file, line, priority and a marker on the line that won.
- **Evidence.** Every finding carries the file, the physical line, the byte
  offset, the byte length and the raw statement. Continuation lines are joined
  the way systemd joins them, so the line number is the one an editor shows.
- **Outputs.** Text, JSON and SARIF 2.1.0 (one run for a whole tree).
- **Inputs.** A single unit file, a directory of units, a mounted rootfs, or a
  container layer.
- **Zero runtime dependencies.** 235 tests, including a bare-clone bootstrap
  test that runs without installing the package.
- **MCP server** (`unitlint-mcp`), 7 tools over the same engine the CLI runs.
- **Built-in corpus** (`unitlint demo`) that fires all 44 rules; a test asserts
  `examples/rootfs` on disk is byte-identical to the corpus the demo runs on.
