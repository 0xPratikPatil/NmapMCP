"""
RED tests for the prod-hardening pass (TDD).

Each test below FAILS on current main and defines the intended behavior:
 1. pyproject must not depend on python3-nmap (dead dep: new code uses the
    nmap binary via subprocess, never the nmap3 package).
 2. _is_private() must fail CLOSED on DNS resolution failure (return False),
    so an unresolvable hostname can never slip past the public-IP guard.
 3. script_scan must reject NSE script selectors containing shell metachars
    or path traversal (validated BEFORE any scan runs).
"""
from __future__ import annotations

import asyncio
import json
import pathlib

import pytest

import main


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. Dead dependency
# ---------------------------------------------------------------------------
def test_pyproject_has_no_nmap3_dependency():
    text = pathlib.Path(__file__).resolve().parent.parent.joinpath(
        "pyproject.toml").read_text()
    assert "python3-nmap" not in text, "python3-nmap is unused: main.py calls the nmap binary directly"


def test_main_does_not_import_nmap3():
    assert "nmap3" not in dir(main), "main must not expose nmap3"
    import sys
    assert "nmap3" not in sys.modules, "importing main must not pull in nmap3"


# ---------------------------------------------------------------------------
# 2. Fail-closed DNS guard
# ---------------------------------------------------------------------------
def test_is_private_unresolvable_hostname_is_public_fail_closed(monkeypatch):
    """Unresolvable hostname -> treated as PUBLIC (blocked unless allowed)."""
    import socket
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda _: (_ for _ in ()).throw(OSError("no DNS")))
    assert main._is_private("totally-invalid-hostname.example") is False


def test_validate_target_blocks_unresolvable_when_public_blocked(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda _: (_ for _ in ()).throw(OSError("no DNS")))
    monkeypatch.setattr(main, "ALLOW_PUBLIC", False)
    with pytest.raises(ValueError, match="blocked"):
        main._validate_target("totally-invalid-hostname.example")


# ---------------------------------------------------------------------------
# 3. NSE script selector validation (no scan runs on rejection)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "default;rm -rf /",
    "http-*|cat /etc/passwd",
    "../../etc/nse-evil",
    "vuln$(id)",
    "default`id`",
    "a&b",
])
def test_script_scan_rejects_dangerous_selectors(bad):
    raw = run(main.script_scan("127.0.0.1", bad))
    data = json.loads(raw)
    assert "error" in data, f"{bad!r} must be rejected, got: {raw[:200]}"


@pytest.mark.parametrize("good", ["default", "vuln", "http-*", "default,vuln", "ssh-*"])
def test_validate_scripts_accepts_legit_selectors(good):
    assert main._validate_scripts(good) == good
