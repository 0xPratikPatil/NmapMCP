"""
Unit tests for main.parse_nmap_xml()

Uses temporary XML files with fixture content — no real nmap required.
"""
from __future__ import annotations

import os
import tempfile
import textwrap

import pytest

import main


# ---------------------------------------------------------------------------
# Helper: write XML to a temp file and parse it
# ---------------------------------------------------------------------------
def _parse(xml_content: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write(textwrap.dedent(xml_content))
        path = f.name
    try:
        return main.parse_nmap_xml(path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Fixture 1: normal host with two open TCP ports
# ---------------------------------------------------------------------------
NORMAL_HOST_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme Corp"/>
    <hostnames>
      <hostname name="myhost.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu">
          <cpe>cpe:/a:openbsd:openssh:8.9</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0">
        </service>
        <script id="http-title" output="Welcome"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https"/>
      </port>
    </ports>
    <uptime lastboot="Mon Jan  1 00:00:00 2024"/>
    <distance value="1"/>
  </host>
</nmaprun>
"""


def test_normal_host_parsed():
    hosts = _parse(NORMAL_HOST_XML)
    assert len(hosts) == 1
    h = hosts[0]

    # Status
    assert h["status"] == "up"

    # IP and MAC
    assert h["ip"] == "192.168.1.100"
    assert h["mac"] == "AA:BB:CC:DD:EE:FF"
    assert h["mac_vendor"] == "Acme Corp"

    # Hostnames
    assert len(h["hostnames"]) == 1
    assert h["hostnames"][0]["name"] == "myhost.local"
    assert h["hostnames"][0]["type"] == "PTR"

    # Ports — 3 total, check they're all present
    assert len(h["ports"]) == 3

    # SSH port
    ssh = next(p for p in h["ports"] if p["port"] == "22")
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.9"
    assert ssh["extra_info"] == "Ubuntu"
    assert "cpe:/a:openbsd:openssh:8.9" in ssh["cpe"]

    # HTTP port with NSE script
    http = next(p for p in h["ports"] if p["port"] == "80")
    assert http["state"] == "open"
    assert http["service"] == "http"
    assert http["product"] == "nginx"
    assert len(http["scripts"]) == 1
    assert http["scripts"][0]["id"] == "http-title"
    assert http["scripts"][0]["output"] == "Welcome"

    # Closed port is also returned
    https = next(p for p in h["ports"] if p["port"] == "443")
    assert https["state"] == "closed"

    # Metadata
    assert h["uptime"] != ""
    assert h["distance"] == "1"


# ---------------------------------------------------------------------------
# Fixture 2: OS detection data
# ---------------------------------------------------------------------------
OS_DETECTION_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames/>
    <ports/>
    <os>
      <osmatch name="Linux 5.4" accuracy="97">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X"/>
      </osmatch>
      <osmatch name="Linux 4.15" accuracy="92">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X"/>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""


def test_os_detection_parsed():
    hosts = _parse(OS_DETECTION_XML)
    assert len(hosts) == 1
    h = hosts[0]

    assert h["ip"] == "10.0.0.5"
    assert len(h["os"]) == 2

    best = h["os"][0]
    assert best["name"] == "Linux 5.4"
    assert best["accuracy"] == "97"
    assert best["family"] == "Linux"
    assert best["gen"] == "5.X"
    assert best["vendor"] == "Linux"
    assert best["type"] == "general purpose"

    second = h["os"][1]
    assert second["accuracy"] == "92"


# ---------------------------------------------------------------------------
# Fixture 3: host-level scripts (hostscript block)
# ---------------------------------------------------------------------------
HOST_SCRIPT_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.200" addrtype="ipv4"/>
    <hostnames/>
    <ports/>
    <hostscript>
      <script id="smb-security-mode" output="Message signing enabled but not required"/>
      <script id="smb2-capabilities" output="2.02 2.10 3.00 3.02 3.11"/>
    </hostscript>
  </host>
</nmaprun>
"""


def test_host_scripts_parsed():
    hosts = _parse(HOST_SCRIPT_XML)
    h = hosts[0]
    assert len(h["scripts"]) == 2
    ids = {s["id"] for s in h["scripts"]}
    assert "smb-security-mode" in ids
    assert "smb2-capabilities" in ids


# ---------------------------------------------------------------------------
# Fixture 4: traceroute data
# ---------------------------------------------------------------------------
TRACEROUTE_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <hostnames/>
    <ports/>
    <trace>
      <hop ttl="1" ipaddr="192.168.1.1" rtt="1.23" host="gateway.local"/>
      <hop ttl="2" ipaddr="10.10.10.1" rtt="5.67" host=""/>
    </trace>
  </host>
</nmaprun>
"""


def test_traceroute_parsed():
    hosts = _parse(TRACEROUTE_XML)
    h = hosts[0]
    assert len(h["traceroute"]) == 2
    hop1 = h["traceroute"][0]
    assert hop1["ttl"] == "1"
    assert hop1["ip"] == "192.168.1.1"
    assert hop1["rtt"] == "1.23"
    assert hop1["host"] == "gateway.local"


# ---------------------------------------------------------------------------
# Fixture 5: malformed / empty XML
# ---------------------------------------------------------------------------
def test_malformed_xml_returns_error():
    hosts = _parse("this is not xml at all <<<<")
    assert len(hosts) == 1
    assert "error" in hosts[0]
    assert "XML parse error" in hosts[0]["error"]


def test_empty_xml_returns_empty_list():
    hosts = _parse('<?xml version="1.0"?><nmaprun></nmaprun>')
    assert hosts == []


def test_no_hosts_in_valid_xml():
    hosts = _parse('<?xml version="1.0"?><nmaprun><runstats/></nmaprun>')
    assert hosts == []


# ---------------------------------------------------------------------------
# Structural key completeness: every host dict must have all expected keys
# ---------------------------------------------------------------------------
EXPECTED_HOST_KEYS = {
    "status", "ip", "mac", "mac_vendor", "hostnames",
    "os", "ports", "scripts", "traceroute", "uptime", "distance",
}


def test_all_expected_keys_present():
    hosts = _parse(NORMAL_HOST_XML)
    assert len(hosts) == 1
    missing = EXPECTED_HOST_KEYS - hosts[0].keys()
    assert missing == set(), f"Missing keys: {missing}"
