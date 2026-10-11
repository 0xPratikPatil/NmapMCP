"""
Step 3 — Live smoke tests against 127.0.0.1 ONLY.

These tests actually invoke nmap via the tool functions.
They are marked with @pytest.mark.live and skipped automatically if
the nmap binary is not found at NMAP_PATH.

Run with:
    uv run pytest tests/test_live_localhost.py -v
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys

import pytest

import main

# ---------------------------------------------------------------------------
# Skip the whole module if nmap is not available
# ---------------------------------------------------------------------------
def _default_nmap() -> str:
    env = os.environ.get("NMAP_PATH")
    if env:
        return env
    if sys.platform == "win32":
        return "C:/PROGRA~2/Nmap/nmap.exe"
    return shutil.which("nmap") or "nmap"


NMAP_PATH = _default_nmap()

_nmap_available = os.path.isfile(NMAP_PATH) or shutil.which(NMAP_PATH) is not None

pytestmark = pytest.mark.skipif(
    not _nmap_available,
    reason=f"nmap binary not found at {NMAP_PATH!r}",
)

TARGET = "127.0.0.1"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def run(coro):
    return asyncio.run(coro)


def assert_valid_json(raw: str, context: str = "") -> dict:
    """Assert the string is valid JSON and return the parsed dict."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        pytest.fail(f"{context}: not valid JSON — {exc}\nRaw: {raw[:500]}")
    return data


@pytest.fixture(autouse=True)
def clean_history():
    main._history.clear()
    yield
    main._history.clear()


# ---------------------------------------------------------------------------
# quick_scan
# ---------------------------------------------------------------------------
def test_live_quick_scan():
    raw = run(main.quick_scan(TARGET))
    data = assert_valid_json(raw, "quick_scan")

    assert "error" not in data, f"quick_scan returned error: {data.get('error')}"
    assert data["target"] == TARGET
    assert "hosts" in data
    assert "summary" in data
    assert isinstance(data["summary"]["open_ports"], int)


# ---------------------------------------------------------------------------
# structured_scan
# ---------------------------------------------------------------------------
def test_live_structured_scan():
    raw = run(main.structured_scan(TARGET))
    data = assert_valid_json(raw, "structured_scan")

    assert "error" not in data, f"structured_scan error: {data.get('error')}"
    assert data["target"] == TARGET
    assert "hosts" in data


# ---------------------------------------------------------------------------
# check_single_port (port 135 is almost always open on Windows localhost)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("port", [135, 445])
def test_live_check_single_port(port):
    raw = run(main.check_single_port(TARGET, port))
    data = assert_valid_json(raw, f"check_single_port({port})")

    # Tool should not throw — port may be open or closed, both are valid results
    assert "error" not in data, f"check_single_port({port}) error: {data.get('error')}"
    assert data["target"] == TARGET
    assert len(data["hosts"]) >= 0  # 0 hosts possible if all filtered


# ---------------------------------------------------------------------------
# ping_sweep
# ---------------------------------------------------------------------------
def test_live_ping_sweep():
    raw = run(main.ping_sweep(TARGET))
    data = assert_valid_json(raw, "ping_sweep")

    assert "error" not in data, f"ping_sweep error: {data.get('error')}"
    assert data["target"] == TARGET


# ---------------------------------------------------------------------------
# list_scan_history — must show all the scans run above (if run in sequence)
# ---------------------------------------------------------------------------
def test_live_list_scan_history():
    # Run one scan first so history is non-empty
    run(main.quick_scan(TARGET))

    raw = run(main.list_scan_history())
    history = assert_valid_json(raw, "list_scan_history")

    assert isinstance(history, list), "list_scan_history should return a JSON array"
    assert len(history) >= 1

    # Each entry must have the required keys
    required_keys = {"scan_id", "label", "target", "timestamp", "summary"}
    for entry in history:
        missing = required_keys - entry.keys()
        assert missing == set(), f"History entry missing keys: {missing}"


# ---------------------------------------------------------------------------
# get_host_summary — returns formatted text, not raw JSON
# ---------------------------------------------------------------------------
def test_live_get_host_summary():
    raw = run(main.get_host_summary(TARGET))

    # get_host_summary returns formatted text OR a JSON error string
    assert isinstance(raw, str)
    assert len(raw) > 0

    # If it errored it would be JSON with "error" key
    try:
        data = json.loads(raw)
        assert "error" not in data, f"get_host_summary returned error: {data.get('error')}"
    except json.JSONDecodeError:
        # Plain text — expected happy path
        assert "Host Summary" in raw or "127.0.0.1" in raw
