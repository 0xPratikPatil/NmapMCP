
# NmapMCP 
NmapMCP  is a robust integration of the Nmap scanning tool with the Model Context Protocol (MCP), enabling seamless network scanning capabilities within MCP-compatible environments. This project allows users to perform various network scans, such as top ports scanning, DNS brute force, and more, directly through MCP interfaces.

## Features

-   **Top Ports Scanning:** Quickly identify the most commonly used ports on target hosts to assess potential entry points.
    
-   **DNS Brute Force:** Discover subdomains associated with a target domain, aiding in comprehensive domain mapping.
    
-   **List Scan:** Obtain a list of active hosts within a specified range without port scanning, useful for network inventory.
    
-   **OS Detection:** Determine the operating system of a target host by analyzing network responses, assisting in vulnerability assessment.
    
-   **Version Detection:** Identify service versions running on open ports to detect outdated or vulnerable services.
    
-   **FIN Scan:** Perform stealthy scans by sending FIN packets to detect open ports without establishing a full connection.
    
-   **Idle Scan:** Conduct highly stealthy scans by leveraging idle hosts to probe target systems, minimizing detection risks.
    
-   **Ping Scan:** Detect active hosts in a network by sending ICMP echo requests, useful for network mapping.
    
-   **SYN Scan:** Perform half-open TCP scans to identify open ports without completing the TCP handshake, reducing detection likelihood.
    
-   **TCP Connect Scan:** Establish full TCP connections to probe open ports, useful when SYN scans are not feasible.
    
-   **UDP Scan:** Identify open UDP ports on a target host to detect services that do not use TCP.
    
-   **Port Scan Only:** Focus solely on scanning ports without additional host discovery, streamlining the scanning process.
    
-   **No Port Scan:** Perform host discovery without scanning ports, useful for identifying live hosts without probing services.
    
-   **ARP Discovery:** Identify active devices within a local network segment using ARP requests, effective in LAN environments.
    
-   **Disable DNS Resolution:** Perform scans without resolving IP addresses to hostnames, enhancing scan speed and reducing DNS query traffic.

## Installation

1.  **Clone the Repository:**
    
    ```bash
    git clone https://github.com/0xPratikPatil/NmapMCP.git
    cd NmapMCP
    ```
2.  **Install `uv`:**
    
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```    

3. **Create environment:**
	```bash
	uv venv
	```
5.  **Install dependencies from `pyproject.toml`**
    
    ```bash
    uv pip install
    ```
    or
    ```bash
    uv pip install -r pyproject.toml
    ```

## Configuration

To configure the Nmap MCP Server, edit the `claude_desktop_config.json` file located in the project root. This file allows you to set default scan arguments, define MCP tool behaviors, and adjust logging settings.

**Example `claude_desktop_config.json`:**

```json
{
  "mcpServers": {
    "NmapMCP": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/NmapMCP",
        "run",
        "main.py"
      ]
    }
  }
}
```

## Contributing

Contributions are welcome! To contribute:

1.  **Fork the Repository:** Click the "Fork" button at the top right of the repository page.
    
2.  **Clone Your Fork:**
    
    ```bash
    git clone https://github.com/0xPratikPatil/NmapMCP.git
    ```
    
3.  **Create a New Branch:**
    
    ```bash
    git checkout -b feature/your-feature-name
    ```
4.  **Make Your Changes:** Implement your feature or fix.
    
5.  **Run Tests:** Ensure all tests pass.
    
6.  **Commit Changes:**
    
    ```bash
    git commit -m "Add feature: your feature name"
    ```
7.  **Push to Your Fork:**
    
    ```bash
    git push origin feature/your-feature-name
    ```
8.  **Submit a Pull Request:** Navigate to the original repository and click "New Pull Request."
    

## License

This project is licensed under the MIT License.

## Acknowledgments

Special thanks to the Nmap and MCP communities for their invaluable tools and support.
