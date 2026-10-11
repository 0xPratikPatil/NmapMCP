"""
Unit tests for main._validate_target()
"""
from __future__ import annotations

import pytest

import main


# ---------------------------------------------------------------------------
# Valid private targets (must not raise)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("target", [
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.0/8",
    "172.16.5.100",
    "192.168.1.0/24",
    "192.168.1.1 192.168.1.2",   # space-separated list
    "localhost",                   # resolves to 127.0.0.1 — treated private
    "192.168.1.1,192.168.1.2",    # comma-separated (valid regex chars)
])
def test_valid_private_targets(target, block_public):
    # Should return the target unchanged, no exception
    result = main._validate_target(target)
    assert result == target


# ---------------------------------------------------------------------------
# Targets with illegal characters (must raise ValueError)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_target", [
    "127.0.0.1; whoami",          # semicolon — shell metachar
    "127.0.0.1 && id",            # double-ampersand
    "127.0.0.1 | cat /etc/passwd",# pipe
    "192.168.1.1`id`",            # backtick
    "$(hostname)",                 # command substitution
    "127.0.0.1\nwhoami",          # newline injection
    "192.168.1.1>out.txt",        # redirect
    '192.168.1.1"',               # double-quote
    "192.168.1.1'",               # single-quote
])
def test_illegal_characters_rejected(bad_target, block_public):
    with pytest.raises(ValueError, match="illegal characters"):
        main._validate_target(bad_target)


# ---------------------------------------------------------------------------
# Overlong target (> 512 chars) must raise ValueError
# ---------------------------------------------------------------------------
def test_overlong_target_rejected(block_public):
    long_target = "192.168.1.1 " * 50   # well over 512 chars
    assert len(long_target) > 512
    with pytest.raises(ValueError, match="too long"):
        main._validate_target(long_target)


# ---------------------------------------------------------------------------
# Public IP blocked when NMAP_ALLOW_PUBLIC is unset / 0
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("public_ip", [
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
])
def test_public_ip_blocked_by_default(public_ip, block_public):
    with pytest.raises(ValueError, match="Public target"):
        main._validate_target(public_ip)


# ---------------------------------------------------------------------------
# Public IP allowed when NMAP_ALLOW_PUBLIC=1
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("public_ip", [
    "8.8.8.8",
    "1.1.1.1",
])
def test_public_ip_allowed_when_env_set(public_ip, allow_public):
    result = main._validate_target(public_ip)
    assert result == public_ip


# ---------------------------------------------------------------------------
# Edge: exactly 512 chars should be OK; 513 should not
# ---------------------------------------------------------------------------
def test_target_length_boundary(block_public, monkeypatch):
    # Use a string that passes the regex and is private
    # 'a' chars won't match TARGET_RE by themselves (no IP),
    # so build a valid-looking string with dots and digits
    # that is still treated private (DNS fallback → private)
    monkeypatch.setattr(main, "ALLOW_PUBLIC", False)
    import socket
    monkeypatch.setattr(socket, "gethostbyname", lambda _: "192.168.1.1")

    # Exactly 512 characters of valid regex chars — should pass length check
    ok_target = "a" * 512
    # This will fail the public/private check (since ALLOW_PUBLIC=False
    # and the hostname mock returns private), so just confirm no "too long" error
    try:
        main._validate_target(ok_target)
    except ValueError as exc:
        assert "too long" not in str(exc), "512-char target should not be 'too long'"

    # 513 characters — must raise "too long"
    with pytest.raises(ValueError, match="too long"):
        main._validate_target("a" * 513)
