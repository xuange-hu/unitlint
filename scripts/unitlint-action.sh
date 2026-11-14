#!/usr/bin/env bash
# Entry point shared by action.yml and its tests. Keeping the logic in one
# script means the composite action and the local smoke test cannot drift.
set -euo pipefail

: "${UL_PATH:=.}"
: "${UL_FAIL_ON:=high}"
: "${UL_REPORT:=unitlint-report.txt}"
: "${UL_SARIF_FILE:=unitlint.sarif}"

UNITLINT_CMD="${UNITLINT_CMD:-unitlint}"
read -r -a cmd <<< "$UNITLINT_CMD"

args=(scan "$UL_PATH" --fail-on "$UL_FAIL_ON" --no-color)
if [ -n "${UL_UNIT:-}" ]; then
  args+=(--unit "$UL_UNIT")
fi
if [ "${UL_SARIF:-false}" = "true" ]; then
  args+=(--sarif)
  UL_REPORT="$UL_SARIF_FILE"
fi

set +e
"${cmd[@]}" "${args[@]}" > "$UL_REPORT" 2>&1
status=$?
set -e

cat "$UL_REPORT"

if [ "${status}" -eq 0 ]; then
  verdict=PASS
else
  verdict=FAIL
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'report=%s\n' "$UL_REPORT"
    printf 'verdict=%s\n' "$verdict"
    printf 'exit-code=%s\n' "$status"
  } >> "$GITHUB_OUTPUT"
fi

exit "$status"
