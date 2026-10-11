"""
Enhanced Nmap MCP Server
========================
A comprehensive, production-grade MCP server wrapping nmap with:
- Rich XML parsing (OS, scripts, hostnames, traceroute, CVEs)
- 15+ specialized scan tools
- Full flag allowlist with value validation
- Async subprocess execution with progress streaming
- Concurrency limiting (max 3 parallel scans)
- In-process scan history with diffing
- Target allowlist / private-range guard
- Structured JSON output everywhere
- Human-readable summary formatting
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Nmap binary path  (Windows: use 8.3 short path with forward slashes so
# shlex.split does not strip backslashes)
# ---------------------------------------------------------------------------
def _resolve_nmap_path() -> str:
    env = os.environ.get("NMAP_PATH")
    if env:
        return env
    if sys.platform == "win32":
        return "C:/PROGRA~2/Nmap/nmap.exe"
    return shutil.which("nmap") or "nmap"


NMAP_PATH = _resolve_nmap_path()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("nmap-mcp")

# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------
mcp = FastMCP("nmap-enhanced")

# ---------------------------------------------------------------------------
# Concurrency guard
# ---------------------------------------------------------------------------
MAX_PARALLEL = 3
_semaphore: asyncio.Semaphore | None = None  # lazy-init inside async context


def get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_PARALLEL)
    return _semaphore


# ---------------------------------------------------------------------------
# In-memory scan history  { scan_id -> ScanRecord }
# ---------------------------------------------------------------------------
_history: dict[str, dict] = {}
MAX_HISTORY = 100

# ---------------------------------------------------------------------------
# Private / loopback ranges
# ---------------------------------------------------------------------------
_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
]
ALLOW_PUBLIC = os.environ.get("NMAP_ALLOW_PUBLIC", "0") == "1"

# ---------------------------------------------------------------------------
# Flag allowlist
# ---------------------------------------------------------------------------
ALLOWED_FLAGS: set[str] = {
    # Scan techniques
    "-sS", "-sT", "-sA", "-sW", "-sM", "-sU", "-sN", "-sF", "-sX",
    "-sI", "-sO", "-b",
    # Host discovery
    "-sn", "-Pn", "-PS", "-PA", "-PU", "-PY", "-PE", "-PP", "-PM",
    "-PO", "-PR", "-sL",
    # Port spec
    "-p", "-F", "--top-ports", "--port-ratio", "-r",
    # Service / version
    "-sV", "--version-intensity", "--version-light", "--version-all",
    "--version-trace",
    # OS detection
    "-O", "--osscan-limit", "--osscan-guess", "--fuzzy",
    # Timing
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
    "--max-retries", "--host-timeout", "--scan-delay", "--max-scan-delay",
    "--min-rate", "--max-rate",
    # Aggressive
    "-A",
    # Scripts
    "-sC", "--script", "--script-args", "--script-args-file",
    "--script-trace", "--script-updatedb",
    # Output
    "-oX", "-oN", "-oG", "-oA", "--append-output",
    # Verbosity / debugging
    "-v", "-vv", "-d", "-dd", "--reason", "--open", "--packet-trace",
    # Misc
    "-6", "-n", "-R", "--dns-servers", "--traceroute", "--badsum",
    "--ip-options", "--ttl", "--spoof-mac", "--proxies",
    # Firewall / IDS evasion
    "-f", "--mtu", "-D", "-S", "-e", "-g", "--source-port",
    "--data-length", "--randomize-hosts",
}

FLAGS_WITH_VALUES: set[str] = {
    "-p", "--top-ports", "--port-ratio",
    "--script", "--script-args", "--script-args-file", "--dns-servers",
    "-oX", "-oN", "-oG", "-oA",
    "--version-intensity",
    "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
    "--max-retries", "--host-timeout", "--scan-delay", "--max-scan-delay",
    "--min-rate", "--max-rate",
    "--mtu", "-D", "-S", "-e", "-g", "--source-port",
    "--data-length", "--ttl", "--spoof-mac", "--proxies",
}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:/,_\[\] ]+$")


def _is_private(host: str) -> bool:
    parts = [p.strip() for p in host.strip().split(",")]
    parts = [p for p in parts if p]
    if not parts:
        return False
    return all(_is_private_single(p) for p in parts)


def _is_private_single(h: str) -> bool:
    try:
        return any(ip_address(h) in net for net in _PRIVATE_NETS)
    except ValueError:
        pass
    try:
        return any(
            ip_network(h, strict=False).subnet_of(net) for net in _PRIVATE_NETS
        )
    except ValueError:
        pass
    try:
        addr = ip_address(socket.gethostbyname(h))
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return False  # fail CLOSED: unresolvable != provably private


def _validate_target(target: str) -> str:
    if not TARGET_RE.match(target):
        raise ValueError(f"Target contains illegal characters: {target!r}")
    if len(target) > 512:
        raise ValueError("Target string too long")
    if not ALLOW_PUBLIC:
        for token in target.split():
            token = token.strip(",")
            if token and not _is_private(token):
                raise ValueError(
                    f"Public target {token!r} blocked. "
                    "Set NMAP_ALLOW_PUBLIC=1 to enable."
                )
    return target


def validate_flags(flags: str) -> list[str]:
    parsed = shlex.split(flags)
    validated: list[str] = []
    skip_next = False
    for i, item in enumerate(parsed):
        if skip_next:
            skip_next = False
            continue
        if item.startswith("-"):
            base = item.split("=")[0]
            if base not in ALLOWED_FLAGS:
                raise ValueError(f"Flag not in allowlist: {item!r}")
            validated.append(item)
            if base in FLAGS_WITH_VALUES and "=" not in item:
                if i + 1 >= len(parsed):
                    raise ValueError(f"Missing value for flag {base!r}")
                validated.append(parsed[i + 1])
                skip_next = True
        else:
            validated.append(item)
    return validated


# NSE script selectors: names, wildcards (http-*), categories, comma lists.
# No shell metachars, no path separators (blocks --script path traversal).
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_*,.\- ]+$")


def _validate_scripts(scripts: str) -> str:
    if not scripts or not SCRIPT_RE.match(scripts):
        raise ValueError(f"Illegal NSE script selector: {scripts!r}")
    if ".." in scripts:
        raise ValueError(f"Illegal NSE script selector: {scripts!r}")
    return scripts


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------
def parse_nmap_xml(xml_path: str) -> list[dict]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        return [{"error": f"XML parse error: {exc}"}]

    hosts_out = []
    for host in root.findall("host"):
        hinfo: dict[str, Any] = {
            "status": "",
            "ip": "",
            "mac": "",
            "mac_vendor": "",
            "hostnames": [],
            "os": [],
            "ports": [],
            "scripts": [],
            "traceroute": [],
            "uptime": "",
            "distance": "",
        }

        status_el = host.find("status")
        if status_el is not None:
            hinfo["status"] = status_el.attrib.get("state", "")

        for addr in host.findall("address"):
            atype = addr.attrib.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                hinfo["ip"] = addr.attrib.get("addr", "")
            elif atype == "mac":
                hinfo["mac"] = addr.attrib.get("addr", "")
                hinfo["mac_vendor"] = addr.attrib.get("vendor", "")

        for hn in host.findall("hostnames/hostname"):
            hinfo["hostnames"].append({
                "name": hn.attrib.get("name", ""),
                "type": hn.attrib.get("type", ""),
            })

        os_node = host.find("os")
        if os_node is not None:
            for osmatch in os_node.findall("osmatch"):
                oc = osmatch.find("osclass")
                hinfo["os"].append({
                    "name": osmatch.attrib.get("name", ""),
                    "accuracy": osmatch.attrib.get("accuracy", ""),
                    "family": oc.attrib.get("osfamily", "") if oc is not None else "",
                    "gen": oc.attrib.get("osgen", "") if oc is not None else "",
                    "type": oc.attrib.get("type", "") if oc is not None else "",
                    "vendor": oc.attrib.get("vendor", "") if oc is not None else "",
                })

        ports_node = host.find("ports")
        if ports_node is not None:
            for port in ports_node.findall("port"):
                pdata: dict[str, Any] = {
                    "port": port.attrib.get("portid", ""),
                    "protocol": port.attrib.get("protocol", ""),
                    "state": "",
                    "reason": "",
                    "service": "",
                    "product": "",
                    "version": "",
                    "extra_info": "",
                    "cpe": [],
                    "scripts": [],
                }
                state_el = port.find("state")
                if state_el is not None:
                    pdata["state"] = state_el.attrib.get("state", "")
                    pdata["reason"] = state_el.attrib.get("reason", "")
                svc_el = port.find("service")
                if svc_el is not None:
                    pdata["service"] = svc_el.attrib.get("name", "")
                    pdata["product"] = svc_el.attrib.get("product", "")
                    pdata["version"] = svc_el.attrib.get("version", "")
                    pdata["extra_info"] = svc_el.attrib.get("extrainfo", "")
                    pdata["cpe"] = [c.text for c in svc_el.findall("cpe") if c.text]
                for scr in port.findall("script"):
                    pdata["scripts"].append({
                        "id": scr.attrib.get("id", ""),
                        "output": scr.attrib.get("output", "").strip(),
                    })
                hinfo["ports"].append(pdata)

        for scr in host.findall("hostscript/script"):
            hinfo["scripts"].append({
                "id": scr.attrib.get("id", ""),
                "output": scr.attrib.get("output", "").strip(),
            })

        trace = host.find("trace")
        if trace is not None:
            for hop in trace.findall("hop"):
                hinfo["traceroute"].append({
                    "ttl": hop.attrib.get("ttl", ""),
                    "ip": hop.attrib.get("ipaddr", ""),
                    "rtt": hop.attrib.get("rtt", ""),
                    "host": hop.attrib.get("host", ""),
                })

        uptime = host.find("uptime")
        if uptime is not None:
            hinfo["uptime"] = uptime.attrib.get("lastboot", "")
        dist = host.find("distance")
        if dist is not None:
            hinfo["distance"] = dist.attrib.get("value", "")

        hosts_out.append(hinfo)

    return hosts_out


# ---------------------------------------------------------------------------
# Core async runner
# ---------------------------------------------------------------------------
async def _run_scan(
    target: str,
    extra_flags: list[str],
    xml_output: bool = True,
    label: str = "scan",
) -> dict:
    start_ts = time.monotonic()
    utc_now = datetime.now(timezone.utc).isoformat()
    _validate_target(target)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    # Build command using the explicit nmap path
    cmd = [NMAP_PATH] + extra_flags
    if xml_output:
        cmd += ["-oX", xml_path]
    cmd += [target]

    log.info("Running: %s", " ".join(cmd))

    stdout_b = b""
    stderr_b = b""

    async with get_semaphore():
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=1800
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"error": "Scan timed out after 1800 s", "command": " ".join(cmd)}
        except FileNotFoundError:
            return {
                "error": f"nmap not found at {NMAP_PATH!r}. "
                         "Set NMAP_PATH env var to override.",
                "command": " ".join(cmd),
            }

    elapsed = round(time.monotonic() - start_ts, 2)
    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")

    parsed_hosts: list[dict] = []
    if xml_output and os.path.exists(xml_path):
        parsed_hosts = parse_nmap_xml(xml_path)
        try:
            os.remove(xml_path)
        except OSError:
            pass

    result = {
        "scan_id": _make_scan_id(target, extra_flags),
        "label": label,
        "command": " ".join(cmd),
        "target": target,
        "timestamp": utc_now,
        "elapsed_seconds": elapsed,
        "return_code": proc.returncode,
        "hosts": parsed_hosts,
        "raw_stdout": stdout,
        "stderr": stderr if stderr else None,
        "summary": _summarise(parsed_hosts),
    }
    _store_history(result)
    return result


def _make_scan_id(target: str, flags: list[str]) -> str:
    key = target + "|" + " ".join(flags) + "|" + str(time.time())
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def _store_history(record: dict) -> None:
    sid = record["scan_id"]
    _history[sid] = record
    if len(_history) > MAX_HISTORY:
        oldest = next(iter(_history))
        del _history[oldest]


def _summarise(hosts: list[dict]) -> dict:
    total = len(hosts)
    up = sum(1 for h in hosts if h.get("status") == "up")
    all_ports: list[dict] = []
    for h in hosts:
        all_ports.extend(h.get("ports", []))
    open_ports = [p for p in all_ports if p.get("state") == "open"]
    services: dict[str, int] = defaultdict(int)
    for p in open_ports:
        svc = p.get("service") or "unknown"
        services[svc] += 1
    return {
        "total_hosts": total,
        "hosts_up": up,
        "open_ports": len(open_ports),
        "services": dict(services),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _arun(target: str, extra_flags: list[str], **kwargs) -> str:
    try:
        result = await _run_scan(target, extra_flags, **kwargs)
    except ValueError as exc:
        result = {"error": str(exc)}
    except Exception as exc:
        log.exception("Unexpected error during scan")
        result = {"error": f"Unexpected error: {exc}"}
    return json.dumps(result, indent=2, ensure_ascii=False)


def _flags(raw: str) -> list[str]:
    return validate_flags(raw)


async def _arun_with_flags(target: str, raw_flags: str, **kwargs) -> str:
    """Like _arun but validates raw flag string first, returning JSON error on bad flags."""
    try:
        flags = validate_flags(raw_flags)
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, indent=2)
    return await _arun(target, flags, **kwargs)


# ===========================================================================
# MCP TOOLS
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. Generic / fully-configurable
# ---------------------------------------------------------------------------
@mcp.tool()
async def nmap_scan(target: str, flags: str = "-F -T4") -> str:
    """
    General-purpose nmap scan with full flag control.

    Args:
        target: IP, hostname, CIDR range, or space-separated list.
        flags:  Raw nmap flags string (only allowlisted flags accepted).

    Returns:
        JSON with parsed hosts, open ports, services, scripts, and raw stdout.
    """
    return await _arun_with_flags(target, flags)


@mcp.tool()
async def structured_scan(target: str, flags: str = "-sV -T4") -> str:
    """
    Service-detection scan returning a clean structured JSON result.

    Args:
        target: Scan target.
        flags:  Nmap flags (default: service detection + timing T4).

    Returns:
        JSON array of hosts with ip, hostnames, ports, services, CPEs.
    """
    return await _arun_with_flags(target, flags, label="structured")


# ---------------------------------------------------------------------------
# 2. Discovery
# ---------------------------------------------------------------------------
@mcp.tool()
async def ping_sweep(target: str) -> str:
    """
    Discover which hosts are up using TCP Connect scan on common ports.
    Works without administrator privileges.

    Args:
        target: CIDR range or address (e.g. "192.168.1.0/24").

    Returns:
        JSON list of responsive hosts.
    """
    return await _arun(
        target,
        ["-sT", "-Pn", "-p", "22,80,443,445,3389", "-T4", "--open", "--reason"],
        label="ping_sweep",
    )


@mcp.tool()
async def arp_scan(target: str) -> str:
    """
    ARP scan for local-subnet host discovery (requires root/npcap).

    Args:
        target: Local subnet CIDR (e.g. "192.168.1.0/24").

    Returns:
        JSON list of hosts with MAC addresses and vendors.
    """
    return await _arun(target, ["-sn", "-PR", "-T4"], label="arp_scan")


@mcp.tool()
async def list_scan(target: str) -> str:
    """
    List scan – enumerate targets WITHOUT sending any packets.

    Args:
        target: Target specification.

    Returns:
        JSON list of resolved hostnames.
    """
    return await _arun(target, ["-sL", "-n"], label="list_scan")


# ---------------------------------------------------------------------------
# 3. Port scanning
# ---------------------------------------------------------------------------
@mcp.tool()
async def quick_scan(target: str) -> str:
    """
    Fast scan of the 100 most common ports. Skips ping check (-Pn)
    so results are accurate even when ICMP is blocked.

    Args:
        target: Scan target.

    Returns:
        JSON with open ports and services.
    """
    return await _arun(target, ["-sT", "-F", "-Pn", "-T4", "--open"], label="quick_scan")


@mcp.tool()
async def full_port_scan(target: str) -> str:
    """
    Scan all 65535 TCP ports.

    Args:
        target: Scan target.

    Returns:
        JSON with all open TCP ports.
    """
    return await _arun(target, ["-sT", "-p-", "-Pn", "-T4", "--open"], label="full_port_scan")


@mcp.tool()
async def top_ports_scan(target: str, count: int = 1000) -> str:
    """
    Scan the N most common ports (default 1000).

    Args:
        target: Scan target.
        count:  Number of top ports to scan (1-65535).

    Returns:
        JSON with open ports and services.
    """
    if not 1 <= count <= 65535:
        return json.dumps({"error": "count must be between 1 and 65535"})
    return await _arun(
        target,
        ["--top-ports", str(count), "-sT", "-Pn", "-T4", "--open"],
        label="top_ports_scan",
    )


@mcp.tool()
async def udp_scan(target: str, ports: str = "53,67,68,69,123,161,162,500,514,1900") -> str:
    """
    UDP scan on specified ports. Requires administrator privileges.

    Args:
        target: Scan target.
        ports:  Comma-separated port list or range.

    Returns:
        JSON with open|filtered UDP ports.
    """
    return await _arun(
        target,
        ["-sU", "-p", ports, "-T4", "--open", "--reason"],
        label="udp_scan",
    )


@mcp.tool()
async def syn_stealth_scan(target: str, ports: str = "1-1024") -> str:
    """
    TCP SYN (half-open / stealth) scan. Requires administrator privileges.

    Args:
        target: Scan target.
        ports:  Port range (default: 1-1024).

    Returns:
        JSON with open ports.
    """
    return await _arun(
        target,
        ["-sS", "-p", ports, "-T4", "--open", "--reason"],
        label="syn_stealth",
    )


# ---------------------------------------------------------------------------
# 4. Service & version detection
# ---------------------------------------------------------------------------
@mcp.tool()
async def service_scan(target: str) -> str:
    """
    Detect services and their versions on common ports.

    Args:
        target: Scan target.

    Returns:
        JSON with service name, product, version, and CPE for each port.
    """
    return await _arun(target, ["-sT", "-sV", "-Pn", "-T4", "--open"], label="service_scan")


@mcp.tool()
async def aggressive_scan(target: str) -> str:
    """
    Aggressive scan: OS detection + version detection + scripts + traceroute.

    Args:
        target: Scan target.

    Returns:
        JSON with full host profiling data.
    """
    return await _arun(target, ["-sT", "-A", "-Pn", "-T4"], label="aggressive_scan")


@mcp.tool()
async def banner_grab(target: str, ports: str = "21,22,23,25,80,110,143,443,3306,5432") -> str:
    """
    Grab service banners from common ports using the banner NSE script.

    Args:
        target: Scan target.
        ports:  Ports to probe (default: common service ports).

    Returns:
        JSON with banner text per port.
    """
    return await _arun(
        target,
        ["-sV", "--script", "banner", "-p", ports, "-T4"],
        label="banner_grab",
    )


# ---------------------------------------------------------------------------
# 5. OS detection
# ---------------------------------------------------------------------------
@mcp.tool()
async def os_detection(target: str) -> str:
    """
    Fingerprint the operating system of the target host.

    Args:
        target: Scan target.

    Returns:
        JSON with OS name, accuracy, family, vendor, and generation.
    """
    return await _arun(
        target,
        ["-O", "--osscan-guess", "-Pn", "-T4"],
        label="os_detection",
    )


# ---------------------------------------------------------------------------
# 6. Vulnerability scanning
# ---------------------------------------------------------------------------
@mcp.tool()
async def vuln_scan(target: str) -> str:
    """
    Run the nmap 'vuln' script category to check for known CVEs.

    Args:
        target: Scan target.

    Returns:
        JSON with vulnerability findings per port/service.
    """
    return await _arun(
        target,
        ["-sV", "--script", "vuln", "-T4"],
        label="vuln_scan",
    )


@mcp.tool()
async def safe_vuln_scan(target: str) -> str:
    """
    Run only 'safe' and 'vuln' category scripts – avoids intrusive checks.

    Args:
        target: Scan target.

    Returns:
        JSON with vulnerability findings.
    """
    return await _arun(
        target,
        ["-sV", "--script", "safe,vuln", "-T4"],
        label="safe_vuln_scan",
    )


@mcp.tool()
async def smb_vuln_scan(target: str) -> str:
    """
    Check for critical SMB vulnerabilities (EternalBlue/MS17-010, SMBGhost, etc.).

    Args:
        target: Target with SMB (port 445/139).

    Returns:
        JSON with SMB vulnerability script results.
    """
    return await _arun(
        target,
        [
            "-p", "445,139",
            "--script",
            "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,"
            "smb-vuln-cve-2020-0796,smb-security-mode",
            "-T4",
        ],
        label="smb_vuln_scan",
    )


@mcp.tool()
async def ssl_scan(target: str, ports: str = "443,8443,8080,8888") -> str:
    """
    Enumerate SSL/TLS ciphers, certificate details, and known weaknesses
    (POODLE, HEARTBLEED, LOGJAM, etc.).

    Args:
        target: Scan target.
        ports:  HTTPS / TLS ports.

    Returns:
        JSON with TLS cipher lists, cert info, and vulnerability flags.
    """
    return await _arun(
        target,
        [
            "-p", ports,
            "--script",
            "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,"
            "ssl-dh-params,ssl-ccs-injection",
            "-T4",
        ],
        label="ssl_scan",
    )


# ---------------------------------------------------------------------------
# 7. Protocol-specific enumeration
# ---------------------------------------------------------------------------
@mcp.tool()
async def http_enum(target: str, ports: str = "80,443,8080,8443") -> str:
    """
    Enumerate HTTP/HTTPS servers: paths, methods, headers, auth, web apps.

    Args:
        target: Scan target.
        ports:  HTTP(S) ports to probe.

    Returns:
        JSON with HTTP findings per port.
    """
    return await _arun(
        target,
        [
            "-p", ports,
            "--script",
            "http-enum,http-methods,http-headers,http-title,"
            "http-server-header,http-auth-finder,http-generator,"
            "http-robots.txt",
            "-T4",
        ],
        label="http_enum",
    )


@mcp.tool()
async def dns_enum(target: str) -> str:
    """
    DNS enumeration: zone transfer, brute-force subdomains, recursion check.

    Args:
        target: DNS server IP or hostname.

    Returns:
        JSON with DNS findings.
    """
    return await _arun(
        target,
        [
            "-p", "53",
            "--script",
            "dns-zone-transfer,dns-brute,dns-recursion,"
            "dns-cache-snoop,dns-service-discovery",
            "-sU", "-sT",
            "-T4",
        ],
        label="dns_enum",
    )


@mcp.tool()
async def smb_enum(target: str) -> str:
    """
    Enumerate SMB shares, users, sessions, OS, domain, and security mode.

    Args:
        target: Windows / Samba target.

    Returns:
        JSON with SMB enumeration results.
    """
    return await _arun(
        target,
        [
            "-p", "445,139",
            "--script",
            "smb-enum-shares,smb-enum-users,smb-enum-sessions,"
            "smb-os-discovery,smb-security-mode,smb2-capabilities",
            "-T4",
        ],
        label="smb_enum",
    )


@mcp.tool()
async def ftp_scan(target: str) -> str:
    """
    FTP service scan: anonymous login, banner, bounce, and brute-prep.

    Args:
        target: FTP server target.

    Returns:
        JSON with FTP script results.
    """
    return await _arun(
        target,
        ["-p", "21", "--script", "ftp-anon,ftp-banner,ftp-bounce,ftp-syst", "-sV", "-T4"],
        label="ftp_scan",
    )


@mcp.tool()
async def ssh_audit(target: str) -> str:
    """
    SSH audit: host-key algorithms, auth methods, supported ciphers.

    Args:
        target: SSH server target.

    Returns:
        JSON with SSH configuration details.
    """
    return await _arun(
        target,
        ["-p", "22", "--script", "ssh-hostkey,ssh-auth-methods,ssh2-enum-algos", "-sV", "-T4"],
        label="ssh_audit",
    )


@mcp.tool()
async def rdp_scan(target: str) -> str:
    """
    RDP scan: fingerprint, NLA detection, BlueKeep check.

    Args:
        target: Windows target.

    Returns:
        JSON with RDP findings.
    """
    return await _arun(
        target,
        ["-p", "3389", "--script", "rdp-enum-encryption,rdp-vuln-ms12-020", "-sV", "-T4"],
        label="rdp_scan",
    )


@mcp.tool()
async def database_scan(target: str) -> str:
    """
    Scan for exposed database services (MySQL, PostgreSQL, MSSQL, MongoDB,
    Redis, Cassandra, CouchDB, Oracle).

    Args:
        target: Scan target.

    Returns:
        JSON with database service findings.
    """
    return await _arun(
        target,
        [
            "-p", "1433,1521,3306,5432,5984,6379,7474,9042,27017,28017",
            "--script",
            "mysql-info,mysql-databases,pgsql-brute,"
            "ms-sql-info,ms-sql-empty-password,"
            "mongodb-info,redis-info,cassandra-info",
            "-sV", "-T4",
        ],
        label="database_scan",
    )


# ---------------------------------------------------------------------------
# 8. Infrastructure & network
# ---------------------------------------------------------------------------
@mcp.tool()
async def firewall_detection(target: str) -> str:
    """
    Detect firewall/IDS presence using ACK scan, window scan, and reason analysis.

    Args:
        target: Scan target.

    Returns:
        JSON with firewall/filter indicators per port.
    """
    return await _arun(
        target,
        ["-sA", "-sW", "-p", "1-1024", "-T4", "--reason"],
        label="firewall_detection",
    )


@mcp.tool()
async def traceroute_scan(target: str) -> str:
    """
    Map the network path to the target host.

    Args:
        target: Destination host or IP.

    Returns:
        JSON with hop-by-hop RTT and IP information.
    """
    return await _arun(target, ["-sn", "--traceroute", "-T4"], label="traceroute")


@mcp.tool()
async def ipv6_scan(target: str) -> str:
    """
    Full scan over IPv6.

    Args:
        target: IPv6 address or hostname with AAAA record.

    Returns:
        JSON with scan results over IPv6.
    """
    return await _arun(target, ["-6", "-sV", "-T4", "--open"], label="ipv6_scan")


# ---------------------------------------------------------------------------
# 9. Scan history & diffing
# ---------------------------------------------------------------------------
@mcp.tool()
async def list_scan_history() -> str:
    """
    List all scans performed in this session.

    Returns:
        JSON array of { scan_id, label, target, timestamp, summary }.
    """
    out = [
        {
            "scan_id": v["scan_id"],
            "label": v["label"],
            "target": v["target"],
            "timestamp": v["timestamp"],
            "elapsed_seconds": v["elapsed_seconds"],
            "summary": v["summary"],
        }
        for v in _history.values()
    ]
    return json.dumps(out, indent=2)


@mcp.tool()
async def get_scan_result(scan_id: str) -> str:
    """
    Retrieve the full result of a previous scan by its ID.

    Args:
        scan_id: 12-char hex ID returned in any scan result.

    Returns:
        Full JSON scan record or an error if not found.
    """
    rec = _history.get(scan_id)
    if not rec:
        return json.dumps({"error": f"Scan ID {scan_id!r} not found"})
    return json.dumps(rec, indent=2)


@mcp.tool()
async def diff_scans(scan_id_a: str, scan_id_b: str) -> str:
    """
    Compare two scans and highlight changes in open ports and services.

    Args:
        scan_id_a: Earlier scan ID.
        scan_id_b: Later scan ID.

    Returns:
        JSON diff with new_ports, closed_ports, changed_services.
    """
    a = _history.get(scan_id_a)
    b = _history.get(scan_id_b)
    if not a:
        return json.dumps({"error": f"Scan {scan_id_a!r} not found"})
    if not b:
        return json.dumps({"error": f"Scan {scan_id_b!r} not found"})

    def _port_map(hosts: list[dict]) -> dict[str, dict]:
        out: dict[str, dict] = defaultdict(dict)
        for h in hosts:
            ip = h.get("ip", "?")
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    key = f"{p['port']}/{p['protocol']}"
                    out[ip][key] = p
        return out

    pm_a = _port_map(a["hosts"])
    pm_b = _port_map(b["hosts"])
    all_ips = set(pm_a) | set(pm_b)
    diff: dict = {
        "scan_a": {"id": scan_id_a, "timestamp": a["timestamp"]},
        "scan_b": {"id": scan_id_b, "timestamp": b["timestamp"]},
        "changes": [],
    }
    for ip in sorted(all_ips):
        ports_a = pm_a.get(ip, {})
        ports_b = pm_b.get(ip, {})
        all_ports = set(ports_a) | set(ports_b)
        for p in sorted(all_ports):
            pa, pb = ports_a.get(p), ports_b.get(p)
            if pa and not pb:
                diff["changes"].append({
                    "ip": ip, "port": p, "change": "closed",
                    "was": {"service": pa.get("service"), "version": pa.get("version")},
                })
            elif pb and not pa:
                diff["changes"].append({
                    "ip": ip, "port": p, "change": "opened",
                    "now": {"service": pb.get("service"), "version": pb.get("version")},
                })
            elif pa and pb:
                va = f"{pa.get('product','')} {pa.get('version','')}".strip()
                vb = f"{pb.get('product','')} {pb.get('version','')}".strip()
                if va != vb:
                    diff["changes"].append({
                        "ip": ip, "port": p, "change": "version_changed",
                        "was": va, "now": vb,
                    })
    diff["total_changes"] = len(diff["changes"])
    return json.dumps(diff, indent=2)


# ---------------------------------------------------------------------------
# 10. Utility
# ---------------------------------------------------------------------------
@mcp.tool()
async def get_host_summary(target: str) -> str:
    """
    Run a balanced scan and return a concise human-readable summary
    (hostname, OS guess, open ports with services, and script highlights).

    Args:
        target: Single host IP or hostname.

    Returns:
        Formatted text summary.
    """
    raw = await _arun(target, ["-sT", "-A", "-Pn", "-T4", "--open"], label="host_summary")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw

    if "error" in data:
        return f"Error: {data['error']}"

    lines = [
        f"=== Host Summary: {data['target']} ===",
        f"Scanned at : {data['timestamp']}",
        f"Elapsed    : {data['elapsed_seconds']}s",
        f"Command    : {data['command']}",
        "",
    ]
    for host in data.get("hosts", []):
        ip = host.get("ip", "?")
        status = host.get("status", "?")
        hostnames = ", ".join(h["name"] for h in host.get("hostnames", []) if h.get("name"))
        lines.append(f"Host : {ip}  ({hostnames or 'no PTR'})  [{status}]")
        if host.get("mac"):
            lines.append(f"MAC  : {host['mac']}  {host.get('mac_vendor','')}")
        for osm in host.get("os", [])[:2]:
            lines.append(f"OS   : {osm['name']}  ({osm['accuracy']}% confidence)")
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        if open_ports:
            lines.append(f"\nOpen ports ({len(open_ports)}):")
            for p in open_ports:
                svc = p.get("product") or p.get("service") or "?"
                ver = p.get("version", "")
                cpe = ", ".join(p.get("cpe", []))
                lines.append(f"  {p['port']:>6}/{p['protocol']:<4}  {svc} {ver}  {cpe}".rstrip())
                for scr in p.get("scripts", []):
                    first_line = scr["output"].split("\n")[0][:120]
                    lines.append(f"          [script:{scr['id']}] {first_line}")
        for scr in host.get("scripts", []):
            lines.append(f"\n[Host script: {scr['id']}]")
            for scr_line in scr["output"].split("\n")[:10]:
                lines.append(f"  {scr_line}")
        if host.get("traceroute"):
            lines.append(f"\nTraceroute ({len(host['traceroute'])} hops):")
            for hop in host["traceroute"]:
                lines.append(
                    f"  TTL {hop['ttl']:>3}  {hop['ip']:<20} {hop['rtt']}ms  {hop.get('host','')}"
                )
        lines.append("")
    return "\n".join(lines)


@mcp.tool()
async def check_single_port(target: str, port: int) -> str:
    """
    Check whether a specific TCP port is open on a host.

    Args:
        target: Host IP or hostname.
        port:   TCP port number (1-65535).

    Returns:
        JSON with port state, service, and version.
    """
    if not 1 <= port <= 65535:
        return json.dumps({"error": "port must be 1-65535"})
    return await _arun(
        target,
        ["-sT", "-p", str(port), "-Pn", "-sV", "-T4", "--reason"],
        label=f"single_port_{port}",
    )


@mcp.tool()
async def script_scan(target: str, scripts: str, ports: str = "", extra_flags: str = "") -> str:
    """
    Run arbitrary NSE scripts against a target.

    Args:
        target:      Scan target.
        scripts:     Comma-separated NSE script names or categories.
        ports:       Optional port filter (e.g. "80,443").
        extra_flags: Additional nmap flags string.

    Returns:
        JSON with script output per host/port.
    """
    try:
        _validate_scripts(scripts)
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, indent=2)
    flags: list[str] = ["--script", scripts, "-T4"]
    if ports:
        flags += ["-p", ports]
    if extra_flags:
        try:
            flags += validate_flags(extra_flags)
        except ValueError as exc:
            return json.dumps({"error": str(exc)}, indent=2)
    return await _arun(target, flags, label="script_scan")


@mcp.tool()
async def network_inventory(subnet: str) -> str:
    """
    Full network inventory: ping sweep then service scan on all live hosts.

    Args:
        subnet: CIDR notation (e.g. "192.168.1.0/24").

    Returns:
        JSON inventory with all live hosts, open ports, and services.
    """
    sweep_json = await _arun(subnet, ["-sn", "-T4"], label="inv_sweep")
    try:
        sweep = json.loads(sweep_json)
    except json.JSONDecodeError:
        return sweep_json

    live_ips = [
        h["ip"] for h in sweep.get("hosts", [])
        if h.get("status") == "up" and h.get("ip")
    ]
    if not live_ips:
        return json.dumps({"subnet": subnet, "live_hosts": 0, "inventory": []})

    target_str = " ".join(live_ips)
    inv_json = await _arun(target_str, ["-sV", "--open", "-T4"], label="inv_service")
    try:
        inv = json.loads(inv_json)
    except json.JSONDecodeError:
        return inv_json

    return json.dumps(
        {
            "subnet": subnet,
            "live_hosts": len(live_ips),
            "inventory": inv.get("hosts", []),
            "summary": inv.get("summary", {}),
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Backward-compat shims for pre-PR5 API (15 original nmap3 tools).
# Old code was sync `def foo(target, args="") -> dict` via python3-nmap.
# New core is async subprocess returning JSON str. These wrappers keep the
# old names discoverable so existing MCP clients don't break. 3 names
# (list_scan, os_detection, udp_scan) already exist above with new signatures.
# ---------------------------------------------------------------------------


@mcp.tool()
async def scan_top_ports(target: str, args: str = "") -> str:
    """Legacy alias: scan top ports. Prefer `top_ports_scan`."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"--top-ports 1000 -T4{extra}", label="scan_top_ports")


@mcp.tool()
async def dns_brute_force(target: str, args: str = "") -> str:
    """Legacy alias: DNS brute-force. Prefer `dns_enum`."""
    return await dns_enum(target)


@mcp.tool()
async def version_detection(target: str, args: str = "") -> str:
    """Legacy alias: service/version detection. Prefer `service_scan`."""
    return await service_scan(target)


@mcp.tool()
async def fin_scan(target: str, args: str = "") -> str:
    """Legacy alias: FIN stealth scan."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"-sF{extra}", label="fin_scan")


@mcp.tool()
async def idle_scan(target: str, args: str = "") -> str:
    """Legacy alias: idle scan (requires zombie host in args)."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"-sI{extra}", label="idle_scan")


@mcp.tool()
async def ping_scan(target: str, args: str = "") -> str:
    """Legacy alias: ping/host discovery. Prefer `ping_sweep`."""
    return await ping_sweep(target)


@mcp.tool()
async def syn_scan(target: str, args: str = "") -> str:
    """Legacy alias: SYN scan. Prefer `syn_stealth_scan`."""
    return await syn_stealth_scan(target)


@mcp.tool()
async def tcp_scan(target: str, args: str = "") -> str:
    """Legacy alias: TCP connect scan."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"-sT{extra}", label="tcp_scan")


@mcp.tool()
async def portscan_only(target: str, args: str = "") -> str:
    """Legacy alias: ports only, skip host discovery."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"-Pn{extra}", label="portscan_only")


@mcp.tool()
async def no_portscan(target: str, args: str = "") -> str:
    """Legacy alias: host discovery only, no port scan."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"-sn{extra}", label="no_portscan")


@mcp.tool()
async def arp_discovery(target: str, args: str = "") -> str:
    """Legacy alias: ARP discovery. Prefer `arp_scan`."""
    return await arp_scan(target)


@mcp.tool()
async def disable_dns_resolution(target: str, args: str = "") -> str:
    """Legacy alias: scan with `-n` (no DNS resolution)."""
    extra = f" {args}" if args else ""
    return await _arun_with_flags(target, f"-n{extra}", label="disable_dns_resolution")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")
