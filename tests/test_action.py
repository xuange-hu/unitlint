"""The GitHub Action is a deliverable too: verify its metadata and really run
its entry point locally, so a broken composite step is caught before a user
tries it in a workflow.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"
SCRIPT = ROOT / "scripts" / "unitlint-action.sh"
SRC = ROOT / "src"

CLEAN = "[Service]\nUser=app\nGroup=app\nExecStart=/usr/lib/app/app\nNoNewPrivileges=yes\n"
BAD = "[Service]\nExecStart=/tmp/bad\n"


def _run(tmp_path: Path, *, path: str = ".", fail_on: str = "high", unit: str = "",
         sarif: bool = False) -> tuple[int, str, dict[str, str]]:
    bash = shutil.which("bash")
    assert bash, "bash is required to exercise the composite action entry point"
    output_file = tmp_path / "github_output"
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(SRC) + os.pathsep + env.get("PYTHONPATH", ""),
            "UNITLINT_CMD": "python -m unitlint.cli",
            "UL_PATH": path,
            "UL_FAIL_ON": fail_on,
            "UL_UNIT": unit,
            "UL_SARIF": "true" if sarif else "false",
            "UL_SKIP_INSTALL": "1",
            "GITHUB_OUTPUT": str(output_file),
        }
    )
    result = subprocess.run(
        [bash, str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
    )
    outputs: dict[str, str] = {}
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                outputs[key] = value
    return result.returncode, result.stdout + result.stderr, outputs


def test_action_metadata_is_complete():
    text = ACTION.read_text(encoding="utf-8")
    for field in ("name:", "description:", "inputs:", "outputs:", "runs:", "using: composite"):
        assert field in text
    for name in ("path:", "unit:", "fail-on:", "sarif:"):
        assert name in text
    assert "${{ github.action_path }}" in text
    assert "${{ steps.audit.outputs.report }}" in text


def test_inputs_reach_the_script_through_env_only():
    text = ACTION.read_text(encoding="utf-8")
    audit_step = text.split("- name: Audit", 1)[1]
    for variable in ("UL_PATH", "UL_UNIT", "UL_FAIL_ON", "UL_SARIF"):
        assert variable in audit_step
    # Interpolating an input straight into `run:` is shell injection.
    assert "${{ inputs." not in audit_step.split("run:", 1)[1]


def test_entrypoint_has_unix_line_endings():
    data = SCRIPT.read_bytes()
    assert b"\r\n" not in data
    assert data.startswith(b"#!/usr/bin/env bash")


def test_action_installs_from_its_own_checkout_not_pypi():
    text = ACTION.read_text(encoding="utf-8")
    assert 'python -m pip install --quiet "$UL_ACTION_PATH"' in text
    assert "UL_ACTION_PATH: ${{ github.action_path }}" in text


def test_clean_unit_passes_and_writes_outputs(tmp_path):
    (tmp_path / "clean.service").write_text(CLEAN, encoding="utf-8")
    code, out, outputs = _run(tmp_path)
    assert code == 0, out
    assert outputs["verdict"] == "PASS"
    assert outputs["exit-code"] == "0"
    assert (tmp_path / outputs["report"]).is_file()


def test_bad_unit_fails_the_gate(tmp_path):
    (tmp_path / "bad.service").write_text(BAD, encoding="utf-8")
    code, out, outputs = _run(tmp_path, path="bad.service")
    assert code == 1, out
    assert outputs["verdict"] == "FAIL"


def test_fail_on_none_never_fails(tmp_path):
    (tmp_path / "bad.service").write_text(BAD, encoding="utf-8")
    code, out, outputs = _run(tmp_path, path="bad.service", fail_on="none")
    assert code == 0, out
    assert outputs["verdict"] == "PASS"


def test_unit_filter_selects_one_unit(tmp_path):
    (tmp_path / "clean.service").write_text(CLEAN, encoding="utf-8")
    (tmp_path / "bad.service").write_text(BAD, encoding="utf-8")
    code, out, _ = _run(tmp_path, unit="clean.service")
    assert code == 0, out
    assert "bad.service" not in out


def test_sarif_mode_writes_parseable_json(tmp_path):
    (tmp_path / "bad.service").write_text(BAD, encoding="utf-8")
    code, _, outputs = _run(tmp_path, path="bad.service", sarif=True, fail_on="none")
    assert code == 0
    assert outputs["report"] == "unitlint.sarif"
    payload = json.loads((tmp_path / "unitlint.sarif").read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"]


def test_shell_metacharacters_in_path_are_not_executed(tmp_path):
    (tmp_path / "bad.service").write_text(BAD, encoding="utf-8")
    marker = tmp_path / "pwned"
    tricky = f"bad.service; touch {marker}"
    code, _, _ = _run(tmp_path, path=tricky, fail_on="none")
    assert code in (0, 1, 2)  # argparse/loader rejects the odd path, but nothing runs
    assert not marker.exists()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
