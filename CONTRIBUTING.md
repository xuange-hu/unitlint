# Contributing

The most useful contribution is a **false positive**: a unit file that a real
system ships, which unitlint reports and should not. Those are worth more than
new rules, because a noisy scanner gets switched off.

## Adding a rule

Three places, all required:

1. **`src/unitlint/rulebook.py`** — the metadata: id, title, severity, stage,
   `why` (what it detects and why it matters) and `fix` (what to do instead).
   Prose is not decoration here; it is what a reader sees in `explain`.
2. **`src/unitlint/rules.py`** — the check, decorated with `@attach("UNTxxx")`.
   Return findings built through `_mk(...)` so the evidence fields stay tied to
   the directive that caused them. If the rule needs other units, use the
   `context` argument and skip when `context.complete` is false.
3. **A sample that triggers it** — add one to `demo.DEMO_FILES` (and regenerate
   `examples/rootfs`), or the coverage test fails.

Rule ids: stage 1 is `UNT0xx`, stage 2 is `UNT1xx`. Do not renumber an existing
rule; a rule id is a stable identifier that people put in ignore lists.

```bash
# after editing the table
python -m unitlint rules --markdown > docs/rules.md
python -c "import pathlib; from unitlint import demo; demo.materialise(pathlib.Path('examples/rootfs'))"
python -m pytest -q
python -m unitlint demo     # must print 44/44
```

## Reporting a bug

Include the smallest unit tree that reproduces it:

```
$ unitlint scan ./mini --json | head -40
$ unitlint why ./mini the.service TheDirective
```

and the output of `unitlint --version`. A tree of two files (base + drop-in) is
usually enough.

## Style

- Zero runtime dependencies. Standard library only, in `src/unitlint`. The MCP
  server may import `mcp`, but only inside `build_server()`.
- Every finding keeps its evidence: file, line, byte offset, raw statement.
- Comments explain *why*, not *what*. If a line exists because systemd does
  something surprising, say what.
- Tests run without installing the package (`python -m pytest -q` from a fresh
  clone). Do not add a test that needs `pip install -e .` first.

## Commit messages

`area: what changed and why`, one line, imperative. Example:

```
rules: UNT009 also flags ReadWritePaths=/var

/var holds the journal and the container runtime state; re-opening it under
ProtectSystem=strict undoes the protection the same way /etc does.
```
