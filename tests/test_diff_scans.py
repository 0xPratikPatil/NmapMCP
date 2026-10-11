"""
Unit tests for the diff_scans() MCP tool.

We inject fake records directly into main._history so no nmap or
network calls are needed.
"""
from __future__ import annotations

import asyncio
import json

import pytest

import main


def _make_record(scan_id: str, hosts: list[dict]) -> dict:
    """Build a minimal scan record matching _run_scan's output shape."""
    return {
        "scan_id": scan_id,
        "label": "test",
        "command": "nmap ...",
        "target": "192.168.1.1",
        "timestamp": "2024-01-01T00:00:00+00:00",
        "elapsed_seconds": 1.0,
        "return_code": 0,
        "hosts": hosts,
        "raw_stdout": "",
        "stderr": None,
        "summary": {},
    }


def _make_host(ip: str, ports: list[dict]) -> dict:
    """Build a minimal host record."""
    return {
        "status": "up",
        "ip": ip,
        "mac": "",
        "mac_vendor": "",
        "hostnames": [],
        "os": [],
        "ports": ports,
        "scripts": [],
        "traceroute": [],
        "uptime": "",
        "distance": "",
    }


def _make_port(portid: str, state: str = "open",
               service: str = "", product: str = "",
               version: str = "", protocol: str = "tcp") -> dict:
    return {
        "port": portid,
        "protocol": protocol,
        "state": state,
        "reason": "syn-ack",
        "service": service,
        "product": product,
        "version": version,
        "extra_info": "",
        "cpe": [],
        "scripts": [],
    }


@pytest.fixture(autouse=True)
def clean_history():
    """Clear _history before and after each test to prevent bleed."""
    main._history.clear()
    yield
    main._history.clear()


# ---------------------------------------------------------------------------
# Helper: run async tool synchronously
# ---------------------------------------------------------------------------
def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Test: new port appeared in scan B
# ---------------------------------------------------------------------------
def test_diff_detects_opened_port():
    rec_a = _make_record("aaa111", [
        _make_host("192.168.1.1", [
            _make_port("22", "open", "ssh"),
        ])
    ])
    rec_b = _make_record("bbb222", [
        _make_host("192.168.1.1", [
            _make_port("22", "open", "ssh"),
            _make_port("80", "open", "http"),   # NEW
        ])
    ])
    main._history["aaa111"] = rec_a
    main._history["bbb222"] = rec_b

    result = json.loads(run(main.diff_scans("aaa111", "bbb222")))
    changes = result["changes"]
    opened = [c for c in changes if c["change"] == "opened"]
    assert len(opened) == 1
    assert opened[0]["port"] == "80/tcp"
    assert opened[0]["ip"] == "192.168.1.1"
    assert result["total_changes"] == 1


# ---------------------------------------------------------------------------
# Test: port closed between scans
# ---------------------------------------------------------------------------
def test_diff_detects_closed_port():
    rec_a = _make_record("aaa222", [
        _make_host("10.0.0.1", [
            _make_port("22", "open", "ssh"),
            _make_port("3306", "open", "mysql"),  # will disappear
        ])
    ])
    rec_b = _make_record("bbb333", [
        _make_host("10.0.0.1", [
            _make_port("22", "open", "ssh"),
        ])
    ])
    main._history["aaa222"] = rec_a
    main._history["bbb333"] = rec_b

    result = json.loads(run(main.diff_scans("aaa222", "bbb333")))
    changes = result["changes"]
    closed = [c for c in changes if c["change"] == "closed"]
    assert len(closed) == 1
    assert closed[0]["port"] == "3306/tcp"
    assert result["total_changes"] == 1


# ---------------------------------------------------------------------------
# Test: service version changed
# ---------------------------------------------------------------------------
def test_diff_detects_version_change():
    rec_a = _make_record("ver_a", [
        _make_host("172.16.0.1", [
            _make_port("80", "open", "http", "nginx", "1.18.0"),
        ])
    ])
    rec_b = _make_record("ver_b", [
        _make_host("172.16.0.1", [
            _make_port("80", "open", "http", "nginx", "1.24.0"),  # upgraded
        ])
    ])
    main._history["ver_a"] = rec_a
    main._history["ver_b"] = rec_b

    result = json.loads(run(main.diff_scans("ver_a", "ver_b")))
    changes = result["changes"]
    ver_changes = [c for c in changes if c["change"] == "version_changed"]
    assert len(ver_changes) == 1
    assert ver_changes[0]["port"] == "80/tcp"
    assert "1.18.0" in ver_changes[0]["was"]
    assert "1.24.0" in ver_changes[0]["now"]


# ---------------------------------------------------------------------------
# Test: no changes between identical scans
# ---------------------------------------------------------------------------
def test_diff_no_changes():
    ports = [_make_port("22", "open", "ssh"), _make_port("443", "open", "https")]
    rec_a = _make_record("same_a", [_make_host("192.168.0.1", ports)])
    rec_b = _make_record("same_b", [_make_host("192.168.0.1", ports)])
    main._history["same_a"] = rec_a
    main._history["same_b"] = rec_b

    result = json.loads(run(main.diff_scans("same_a", "same_b")))
    assert result["total_changes"] == 0
    assert result["changes"] == []


# ---------------------------------------------------------------------------
# Test: missing scan_id returns error dict
# ---------------------------------------------------------------------------
def test_diff_missing_scan_id_a():
    rec_b = _make_record("only_b", [_make_host("10.0.0.1", [])])
    main._history["only_b"] = rec_b

    result = json.loads(run(main.diff_scans("nonexistent", "only_b")))
    assert "error" in result


def test_diff_missing_scan_id_b():
    rec_a = _make_record("only_a", [_make_host("10.0.0.1", [])])
    main._history["only_a"] = rec_a

    result = json.loads(run(main.diff_scans("only_a", "nonexistent")))
    assert "error" in result


# ---------------------------------------------------------------------------
# Test: multiple IPs, changes on different hosts
# ---------------------------------------------------------------------------
def test_diff_multi_host():
    rec_a = _make_record("mh_a", [
        _make_host("192.168.1.1", [_make_port("22", "open", "ssh")]),
        _make_host("192.168.1.2", [_make_port("80", "open", "http")]),
    ])
    rec_b = _make_record("mh_b", [
        _make_host("192.168.1.1", [
            _make_port("22", "open", "ssh"),
            _make_port("443", "open", "https"),  # new on host 1
        ]),
        _make_host("192.168.1.2", []),  # port 80 closed on host 2
    ])
    main._history["mh_a"] = rec_a
    main._history["mh_b"] = rec_b

    result = json.loads(run(main.diff_scans("mh_a", "mh_b")))
    assert result["total_changes"] == 2
    ips = {c["ip"] for c in result["changes"]}
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips
