# NmapMCP

**A production-grade Nmap MCP (Model Context Protocol) server — not a thin wrapper.**

Most Nmap MCP servers pipe `nmap` output straight to an AI as raw text and call it done. NmapMCP parses nmap's XML output into structured JSON, ships 35 purpose-built tools instead of one generic `nmap_scan`, and adds the safety rails a tool that runs arbitrary network scans actually needs.

> ⚠️ **Educational use only.** Only scan hosts and networks you own or are explicitly authorized to test. See [Responsible Use](#responsible-use) below.

---

## Why this one is different

**Structured output, not raw text.**
nmap's XML output is fully parsed into clean JSON — OS fingerprints, MAC vendor lookups, CPE strings, per-port NSE script results, traceroute hops, uptime — so an AI assistant can reason over fields instead of regex-ing a wall of stdout.

**35 specialized tools, not one generic scan.**
Instead of forcing the AI to remember correct NSE script names and flag combos, there's a purpose-built tool per use case: `ssl_scan`, `smb_vuln_scan`, `database_scan`, `dns_enum`, `rdp_scan`, `ftp_scan`, `ssh_audit`, and more — each pre-configured with the right scripts and flags.

**Scan history and diffing.**
`list_scan_history`, `get_scan_result`, and `diff_scans` let you run a scan, run it again later, and ask "what changed?" — producing a structured diff of ports that opened, closed, or changed version. Most Nmap MCP servers don't track history at all.

**Security guardrails baked in.**
- **Flag allowlist** — every nmap flag is checked against an explicit allowlist before it reaches the shell; nothing arbitrary gets through
- **Target validation** — regex-checked, length-capped input
- **Private-range guard** — public IPs are blocked by default; scanning them requires explicitly setting `NMAP_ALLOW_PUBLIC=1`
- **Concurrency limiting** — a semaphore caps parallel scans at 3, so an AI can't accidentally saturate the network with simultaneous full-port scans
- **Hard timeout** — every scan is killed after 1800s if it hangs

**Two-phase network inventory.**
`network_inventory` runs a ping sweep first, then only runs service detection against hosts that responded — far more efficient than blindly throwing a service scan at an entire `/24`.

**Human-readable summaries.**
`get_host_summary` returns a formatted text report (hostname, OS guess, open ports, script highlights, traceroute) designed to be read directly by a person, not just parsed by a model.

---

## Tool reference

| Category | Tools |
|---|---|
| General scanning | `nmap_scan`, `structured_scan`, `quick_scan`, `top_ports_scan`, `full_port_scan`, `check_single_port` |
| Host discovery | `ping_sweep`, `arp_scan`, `network_inventory` |
| Scan techniques | `syn_stealth_scan`, `udp_scan`, `ipv6_scan` |
| Service / OS | `service_scan`, `os_detection`, `aggressive_scan`, `banner_grab` |
| Vulnerability | `vuln_scan`, `safe_vuln_scan`, `smb_vuln_scan` |
| Protocol audits | `ssl_scan`, `http_enum`, `dns_enum`, `smb_enum`, `ftp_scan`, `ssh_audit`, `rdp_scan`, `database_scan` |
| Network analysis | `firewall_detection`, `traceroute_scan` |
| Scripting | `script_scan` (run any NSE script/category by name) |
| History & reporting | `list_scan`, `list_scan_history`, `get_scan_result`, `diff_scans`, `get_host_summary` |

**Example prompts once connected to Claude:**
```
run a quick_scan on 192.168.1.100
get_host_summary on 192.168.1.1
run a vuln_scan on 192.168.1.50
network_inventory of 192.168.1.0/24
diff_scans between scan_id_a and scan_id_b
```

---

## Setup

### Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.13+ | |
| Nmap | 7.9+ | The actual scanner binary |
| uv | Latest | Python package manager |
| Claude Desktop | Latest | Or any MCP-compatible client |

### 1. Install Python 3.13+

Download from [python.org](https://www.python.org/downloads/). On Windows, check **"Add Python to PATH"** during install. Verify:
```
python --version
```

### 2. Install Nmap

Download from [nmap.org](https://nmap.org/download.html). Keep Npcap checked during install (Windows). Verify:
```
nmap --version
```

### 3. Install uv

```
pip install uv
```

### 4. Get the project

```
git clone https://github.com/<your-username>/NmapMCP.git
cd NmapMCP
```

### 5. Point the server at your Nmap binary

By default the server looks for Nmap via the `NMAP_PATH` environment variable (falls back to a Windows default). Set it to your actual nmap path — on macOS/Linux this is usually just `nmap` or `/usr/bin/nmap`; on Windows it needs the 8.3 short path with forward slashes, e.g. `C:/PROGRA~1/Nmap/nmap.exe` (find yours with `where nmap`, then convert to short path if it contains spaces).

Set it as an environment variable rather than editing the source:
```
export NMAP_PATH=/usr/bin/nmap   # macOS/Linux
set NMAP_PATH=C:/PROGRA~1/Nmap/nmap.exe   # Windows
```

### 6. Install dependencies

```
uv venv
uv pip install -e .
```

### 7. Configure your MCP client

Add to your Claude Desktop config (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "NmapMCP": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/NmapMCP", "run", "main.py"]
    }
  }
}
```

Restart Claude Desktop and look for the tools icon to confirm it loaded.

### Docker

A `Dockerfile` is included for containerized deployment; see it for details.

---

## Responsible Use

This project is published for **educational and authorized-testing purposes only**. Network scanning tools like Nmap can be misused to probe systems without authorization, which is illegal in most jurisdictions.

- Only run scans against hosts, networks, or services **you own** or have **explicit written permission** to test
- Public-IP scanning is disabled by default (`NMAP_ALLOW_PUBLIC=1` required to override) — leave this off unless you specifically need it and have authorization
- The maintainer(s) of this repository are not responsible for misuse

---

## Troubleshooting

**"nmap not found"** — Confirm `nmap --version` works in your terminal, and that `NMAP_PATH` points to the correct binary.

**"0 hosts up" on everything (Windows)** — Usually a Npcap permissions issue. Use `quick_scan` or `get_host_summary` (TCP-connect based, no admin needed) instead of `ping_sweep`/`arp_scan`, or run your terminal/Claude Desktop as Administrator.

**Tools icon doesn't appear in Claude Desktop** — Validate your config JSON, confirm the path is correct and absolute, then fully quit and reopen Claude Desktop.

**Some scans need elevated privileges** — `syn_stealth_scan`, `udp_scan`, `arp_scan`, and `os_detection` typically require admin/root.

---

## Roadmap / Known Limitations

Being transparent about where this stands:

- No automated test suite yet
- Single-file architecture (`main.py`) — works well, but a future split into runner/parser/validator/tools modules would improve maintainability
- Scan history is in-memory only and does not persist across restarts; no persistent audit log yet
- No per-target rate limiting (only global parallelism is capped)

---

## License

MIT — see [LICENSE](LICENSE).
