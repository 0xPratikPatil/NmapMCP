"""
Unit tests for main._is_private()

No network calls needed — all assertions are against known IP literals.
The only case that triggers DNS is a hostname; we test that separately
using a mock so the suite stays offline.
"""
from __future__ import annotations

import pytest

import main


# ---------------------------------------------------------------------------
# Private / loopback addresses that must return True
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("addr", [
    # RFC-1918 class A
    "10.0.0.1",
    "10.255.255.255",
    # RFC-1918 class B
    "172.16.0.1",
    "172.20.0.1",
    "172.31.255.255",
    # RFC-1918 class C
    "192.168.0.1",
    "192.168.255.254",
    # Loopback
    "127.0.0.1",
    "127.0.0.2",
    # IPv6 loopback
    "::1",
    # IPv6 unique-local (fc00::/7)
    "fc00::1",
    "fd00::dead:beef",
    "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
])
def test_is_private_true(addr):
    assert main._is_private(addr) is True, f"{addr!r} should be private"


# ---------------------------------------------------------------------------
# Public addresses that must return False
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("addr", [
    "8.8.8.8",        # Google DNS
    "1.1.1.1",        # Cloudflare DNS
    "208.67.222.222", # OpenDNS
    "172.15.255.255", # just below 172.16/12
    "172.32.0.1",     # just above 172.31/12
    "11.0.0.1",       # just above 10/8
    "192.169.0.1",    # just above 192.168/16
])
def test_is_private_false(addr):
    assert main._is_private(addr) is False, f"{addr!r} should be public"


# ---------------------------------------------------------------------------
# Hostname that cannot be resolved → treated as private (safe default)
# ---------------------------------------------------------------------------
def test_is_private_unresolvable_hostname_treated_as_private(monkeypatch):
    """An unresolvable hostname falls back to True (safe-fail)."""
    import socket
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda _: (_ for _ in ()).throw(OSError("no DNS")))
    assert main._is_private("totally-invalid-hostname.example") is True


# ---------------------------------------------------------------------------
# Hostname that resolves to a private IP
# ---------------------------------------------------------------------------
def test_is_private_hostname_resolves_to_private(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyname", lambda _: "192.168.1.50")
    assert main._is_private("myrouter.local") is True


# ---------------------------------------------------------------------------
# Hostname that resolves to a public IP
# ---------------------------------------------------------------------------
def test_is_private_hostname_resolves_to_public(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyname", lambda _: "8.8.8.8")
    assert main._is_private("dns.google") is False
