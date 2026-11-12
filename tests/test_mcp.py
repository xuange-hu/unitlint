"""The MCP facade. Skipped when the optional extra is not installed."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp.server.fastmcp", reason="the mcp extra is optional")

from unitlint import mcp_server  # noqa: E402 - after the importorskip guard

ROOT = Path(__file__).resolve().parent.parent
DEMO_TREE = ROOT / "examples" / "rootfs"


def test_manifest_lists_all_tools():
    manifest = mcp_server.tool_manifest()
    names = [tool["name"] for tool in manifest]
    assert names == [
        "unitlint_scan",
        "unitlint_text",
        "unitlint_why",
        "unitlint_rules",
        "unitlint_explain",
        "unitlint_sarif",
        "unitlint_demo",
    ]
    assert all(tool["description"] for tool in manifest)


def test_server_registers_exactly_the_manifest():
    server = mcp_server.build_server()

    async def collect():
        return await server.list_tools()

    tools = asyncio.run(collect())
    assert {tool.name for tool in tools} == {tool["name"] for tool in mcp_server.tool_manifest()}


def test_server_descriptions_are_not_empty():
    server = mcp_server.build_server()

    async def collect():
        return await server.list_tools()

    for tool in asyncio.run(collect()):
        assert tool.description, tool.name


def test_scan_tool_reports_a_verdict():
    out = mcp_server.unitlint_scan(str(DEMO_TREE))
    assert out.startswith("FAIL at fail_on=high")
    assert "UNT101" in out


def test_scan_tool_with_a_unit_filter():
    out = mcp_server.unitlint_scan(str(DEMO_TREE), fail_on="none", unit="report.service")
    assert "report.service" in out
    assert out.startswith("PASS at fail_on=none")


def test_scan_tool_missing_path():
    assert "no such file" in mcp_server.unitlint_scan(str(ROOT / "nope"))


def test_text_tool_does_not_touch_the_filesystem():
    out = mcp_server.unitlint_text("[Service]\nExecStart=/tmp/app\n", name="inline.service")
    assert "inline.service" in out
    assert "UNT003" in out


def test_text_tool_rejects_a_non_unit_name():
    assert "does not look like a unit file name" in mcp_server.unitlint_text("[Service]\n", name="notes.txt")


def test_why_tool():
    out = mcp_server.unitlint_why(str(DEMO_TREE), "web-api.service", "NoNewPrivileges")
    assert "<= effective" in out
    assert "99-debug.conf" in out


def test_why_tool_unknown_directive():
    assert "no directive named" in mcp_server.unitlint_why(str(DEMO_TREE), "web-api.service", "Nope")


def test_rules_tool_filters():
    out = mcp_server.unitlint_rules(stage=2)
    assert "UNT101" in out and "UNT002" not in out


def test_rules_tool_empty_filter():
    assert "no rules match" in mcp_server.unitlint_rules(severity="impossible")


def test_explain_tool():
    out = mcp_server.unitlint_explain("UNT101")
    assert "drop-in" in out and "why it matters" in out


def test_explain_tool_unknown():
    assert "no rule UNT999" in mcp_server.unitlint_explain("UNT999")


def test_sarif_tool_returns_valid_json():
    payload = json.loads(mcp_server.unitlint_sarif(str(DEMO_TREE)))
    assert payload["runs"][0]["results"]


def test_demo_tool_covers_every_rule():
    out = mcp_server.unitlint_demo()
    assert "every rule fired" in out


def test_call_tool_round_trip():
    """The wrapper an agent actually goes through, not just the function."""

    async def call():
        server = mcp_server.build_server()
        return await server.call_tool("unitlint_rules", {"stage": 1})

    content, _meta = asyncio.run(call())
    text = content[0].text if isinstance(content, list) else str(content)
    assert "UNT001" in text


def test_main_exists():
    assert callable(mcp_server.main)
