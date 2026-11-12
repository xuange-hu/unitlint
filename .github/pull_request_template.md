## What

## Why

## Evidence

- [ ] `python -m pytest -q` passes (a fresh clone, no install)
- [ ] `python -m ruff check .` is clean
- [ ] `python -m unitlint demo` still prints 44/44
- [ ] If a rule was added: `docs/rules.md` regenerated and a sample added
- [ ] If a false positive was fixed: the unit that triggered it is in the PR
      description, reduced to the smallest tree that still reproduces

## Risk

Which merge-semantics behaviour does this touch, if any (priority order,
drop-in ordering, shadowing, base replacement)? An answer of "none" is fine and
useful.
