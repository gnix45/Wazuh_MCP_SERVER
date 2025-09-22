# Wazuh MCP Server

A Model Context Protocol (MCP) server that exposes tools to fetch Wazuh agents and categorized alerts (matches Wazuh Dashboard categories).

## Purpose

This MCP server provides tools for an assistant to query:
- Running Wazuh agents
- Alerts grouped by Wazuh modules (FIM, Malware, Threat Hunting, Vulnerabilities, IT Hygiene, etc.)

## Features

### Current Implementation
- `get_running_agents` - List enrolled Wazuh agents.
- `wazuh_FIM_Alerts` - File Integrity Monitoring alerts (syscheck).
- `wazuh_Malware_Alerts` - Malware detection alerts (yara/virustotal/rootcheck).
- `wazuh_Threat_Hunting_Alerts` - Threat hunting / MITRE mapped alerts.
- `wazuh_Vulnerability_Alerts` - Vulnerability detection alerts.
- `wazuh_Configuration_Alerts` - Configuration assessment alerts.
- `wazuh_IT_Hygiene_Alerts` - IT hygiene alerts (auth/ssh/sudo/system).
- `wazuh_PCI_DSS_Alerts` - PCI related alerts.
- `wazuh_GDPR_Alerts` - GDPR related alerts.
- `wazuh_HIPAA_Alerts` - HIPAA related alerts.
- `wazuh_Docker_Alerts` - Docker/container related alerts.
- `wazuh_AWS_Alerts` - AWS/cloud alerts.
- `wazuh_GitHub_Alerts` - GitHub/audit alerts.
- `wazuh_GoogleCloud_Alerts` - Google Cloud alerts.
- `wazuh_MITRE_Alerts` - MITRE ATT&CK mapped alerts.

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Wazuh server and indexer reachable from the running container
- Recommended: set the following environment variables to avoid baking secrets into images:
  - `WAZUH_API_USER`, `WAZUH_API_PASS`
  - `INDEXER_USER`, `INDEXER_PASS`
  - `WAZUH_API_URLS` (comma-separated)
  - `INDEXER_URLS` (comma-separated)

If not set, defaults in the script will be used (as provided by the user).

## Installation

Follow the steps in the provided installation instructions.

## Usage Examples

- "List running agents"
- "Show latest File Integrity Monitoring alerts"
- "Fetch 20 Malware Detection alerts"

Example via MCP protocol (Claude Desktop will use tools automatically):
- call tool `get_running_agents` with param `limit = "20"`

## Architecture

Claude Desktop → MCP Gateway → wazuh_mcp MCP Server → Wazuh API / Wazuh Indexer (Elasticsearch)

## Development

### Local Testing
1. Export credentials in your shell:
   export WAZUH_API_USER="wazuh"
   export WAZUH_API_PASS="vhqnO85EFu4r*7lNCB*gzBp9AY1YF.jy"
   export INDEXER_USER="admin"
   export INDEXER_PASS="UjXP+zjI3O5Ne6sFe7OoXW9p8hUdRtKC"

2. Run locally (without Docker) for debugging:
   python wazuh_mcp_server.py

3. To test a single tool over stdio:
   echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python wazuh_mcp_server.py

## Troubleshooting

- If tools fail to connect, verify network reachability and credentials.
- Check Docker container logs for stack traces.
- Ensure INDEXER_URLS contains the correct indexer endpoint and credentials.

## Security Considerations

- Prefer storing credentials as Docker/Docker Desktop secrets, or environment variables.
- The server runs as non-root inside the container.
- Logs are written to stderr.

## License

MIT
