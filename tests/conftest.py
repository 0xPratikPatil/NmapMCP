"""
Shared pytest fixtures and configuration.
"""
from __future__ import annotations

import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Make sure the project root is importable regardless of how pytest is invoked
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ---------------------------------------------------------------------------
# Fixture: temporarily set NMAP_ALLOW_PUBLIC=1
# ---------------------------------------------------------------------------
@pytest.fixture()
def allow_public(monkeypatch):
    """Enable public-IP scanning for the duration of a test."""
    monkeypatch.setenv("NMAP_ALLOW_PUBLIC", "1")
    # main.ALLOW_PUBLIC is read at module-level, so patch the module attribute too
    import main
    monkeypatch.setattr(main, "ALLOW_PUBLIC", True)
    yield


# ---------------------------------------------------------------------------
# Fixture: ensure NMAP_ALLOW_PUBLIC is unset / 0
# ---------------------------------------------------------------------------
@pytest.fixture()
def block_public(monkeypatch):
    """Ensure public-IP scanning is blocked for the duration of a test."""
    monkeypatch.setenv("NMAP_ALLOW_PUBLIC", "0")
    import main
    monkeypatch.setattr(main, "ALLOW_PUBLIC", False)
    yield
