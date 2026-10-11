"""
Step 4 — Guardrail verification.

Each test confirms a dangerous/invalid call is rejected BEFORE
any subprocess is ever touched.
"""
from __future__ import annotations

import asyncio
import json

import pytest

import main


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def ensure_public_blocked(monkeypatch):
    """All guardrail tests run with public scanning OFF."""
    monkeypatch.setenv("NMAP_ALLOW_PUBLIC", "0")
    monkeypatch.setattr(main, "ALLOW_PUBLIC", False)
    yield


# ---------------------------------------------------------------------------
# G1: Public IP blocked without NMAP_ALLOW_PUBLIC=1
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("public_ip", ["8.8.8.8", "1.1.1.1", "208.67.222.222"])
def test_public_ip_blocked_in_scan_tool(public_ip):
    """
    nmap_scan against a public IP must return an error dict,
    not raise an unhandled exception and not invoke nmap.
    """
    raw = run(main.nmap_scan(public_ip, flags="-F -T4"))
    data = json.loads(raw)
    assert "error" in data, f"Expected error for public IP {public_ip!r}, got: {data}"
    assert "Public target" in data["error"] or "blocked" in data["error"].lower()


@pytest.mark.parametrize("public_ip", ["8.8.8.8", "1.1.1.1"])
def test_public_ip_blocked_in_quick_scan(public_ip):
    raw = run(main.quick_scan(public_ip))
    data = json.loads(raw)
    assert "error" in data
    assert "Public target" in data["error"] or "blocked" in data["error"].lower()


# ---------------------------------------------------------------------------
# G2: Disallowed / made-up flags rejected before subprocess
# ---------------------------------------------------------------------------
def test_disallowed_flag_raises_valueerror():
    """
    nmap_scan with bad flags must return a JSON error dict — never invoke nmap.
    _arun_with_flags catches the ValueError from validate_flags and
    serialises it cleanly.
    """
    raw = run(main.nmap_scan("127.0.0.1", flags="-Z --evil"))
    data = json.loads(raw)
    assert "error" in data, f"Expected JSON error dict, got: {raw[:200]}"
    assert "allowlist" in data["error"].lower() or "not in allowlist" in data["error"]


def test_multiple_disallowed_flags():
    raw = run(main.nmap_scan("127.0.0.1", flags="-sV --badopt -T4"))
    data = json.loads(raw)
    assert "error" in data
    assert "allowlist" in data["error"].lower()


def test_another_made_up_flag():
    raw = run(main.nmap_scan("127.0.0.1", flags="--delete-everything"))
    data = json.loads(raw)
    assert "error" in data
    assert "allowlist" in data["error"].lower()


# ---------------------------------------------------------------------------
# G3: Shell metacharacters in target rejected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_target", [
    "127.0.0.1; whoami",
    "127.0.0.1 && id",
    "$(hostname)",
    "127.0.0.1`id`",
    "127.0.0.1 | cat /etc/passwd",
    "127.0.0.1>evil.txt",
])
def test_shell_metachar_in_target_rejected(bad_target):
    """
    _validate_target must reject targets with shell metacharacters.
    _arun catches the ValueError and returns an error JSON dict.
    """
    raw = run(main.nmap_scan(bad_target, flags="-F -T4"))
    data = json.loads(raw)
    assert "error" in data, (
        f"Target {bad_target!r} should have been rejected, got: {data}"
    )
    assert "illegal characters" in data["error"].lower()


# ---------------------------------------------------------------------------
# G4: validate_flags raises directly (not wrapped by _arun)
# ---------------------------------------------------------------------------
def test_validate_flags_raises_for_disallowed():
    with pytest.raises(ValueError, match="not in allowlist"):
        main.validate_flags("-Z")


def test_validate_flags_raises_for_missing_value():
    with pytest.raises(ValueError, match="Missing value"):
        main.validate_flags("-p")


# ---------------------------------------------------------------------------
# G5: _validate_target raises directly
# ---------------------------------------------------------------------------
def test_validate_target_raises_for_metachar():
    with pytest.raises(ValueError, match="illegal characters"):
        main._validate_target("127.0.0.1; whoami")


def test_validate_target_raises_for_public_when_blocked():
    with pytest.raises(ValueError, match="Public target"):
        main._validate_target("8.8.8.8")


def test_validate_target_raises_for_overlong():
    with pytest.raises(ValueError, match="too long"):
        main._validate_target("a" * 600)
