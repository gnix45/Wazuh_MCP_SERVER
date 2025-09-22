#!/usr/bin/env python3
"""Wazuh MCP server exposing categorized alerts and agents (single-file)."""

import os
import sys
import logging
from datetime import datetime, timedelta
import httpx
from mcp.server.fastmcp import FastMCP

# Logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("wazuh_mcp_server")

# Initialize MCP server - no prompt parameter
mcp = FastMCP("wazuh_mcp")

# Configuration defaults (can be overridden via Docker MCP secrets / env vars)
ALTERNATIVE_URLS = [
    "https://192.168.1.150:55000",
    "https://127.0.0.1:55000",
    "https://172.17.0.1:55000",
    "https://host.docker.internal:55000",
]
ALTERNATIVE_INDEXER_URLS = [
    "https://192.168.1.150:9200",
    "https://127.0.0.1:9200",
    "https://172.17.0.1:9200",
    "https://host.docker.internal:9200",
]

WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "vhqnO85EFu4r*7lNCB*gzBp9AY1YF.jy")
WAZUH_API_URLS = os.environ.get("WAZUH_API_URLS", ",".join(ALTERNATIVE_URLS)).split(",")

INDEXER_USER = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("INDEXER_PASS", "UjXP+zjI3O5Ne6sFe7OoXW9p8hUdRtKC")
INDEXER_URLS = os.environ.get("INDEXER_URLS", ",".join(ALTERNATIVE_INDEXER_URLS)).split(",")

# Token cache
_jwt_cache = {"token": "", "expiry": datetime.min}

# Wazuh modules mapping (as requested)
WAZUH_MODULES = {
    "file_integrity_monitoring": {
        "groups": ["syscheck"],
        "name": "File Integrity Monitoring",
        "description": "Alerts related to file changes, permissions, content, ownership, and attributes",
        "icon": "📁",
    },
    "malware_detection": {
        "groups": ["yara", "virustotal", "malware", "rootcheck"],
        "name": "Malware Detection",
        "description": "Check indicators of compromise triggered by malware infections or cyberattacks",
        "icon": "🦠",
    },
    "threat_hunting": {
        "groups": ["attack", "mitre", "threat"],
        "name": "Threat Hunting",
        "description": "Browse through security alerts, identifying issues and threats in your environment",
        "icon": "🎯",
    },
    "vulnerability_detection": {
        "groups": ["vulnerability", "cve", "vulnerabilities"],
        "name": "Vulnerability Detection",
        "description": "Discover what applications in your environment are affected by well-known vulnerabilities",
        "icon": "🛡️",
    },
    "configuration_assessment": {
        "groups": ["configuration", "assessment", "sca"],
        "name": "Configuration Assessment",
        "description": "Scan your assets as part of a configuration assessment audit",
        "icon": "⚙️",
    },
    "it_hygiene": {
        "groups": ["system", "authentication", "ssh", "sudo", "systemd"],
        "name": "IT Hygiene",
        "description": "Assess system, software, processes, and network layers to detect misconfigurations and unauthorized changes",
        "icon": "🔧",
    },
    "pci_dss": {
        "groups": ["pci_dss", "pci", "payment"],
        "name": "PCI DSS",
        "description": "Global security standard for entities that process, store, or transmit payment cardholder data",
        "icon": "💳",
    },
    "gdpr": {
        "groups": ["gdpr", "privacy", "data_protection"],
        "name": "GDPR",
        "description": "General Data Protection Regulation sets guidelines for processing personal data",
        "icon": "🔒",
    },
    "hipaa": {
        "groups": ["hipaa", "health", "medical"],
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act provides data privacy and security provisions for safeguarding medical information",
        "icon": "🏥",
    },
    "docker": {
        "groups": ["docker", "container"],
        "name": "Docker",
        "description": "Monitor and collect the activity from Docker containers such as creation, running, starting, stopping or pausing events",
        "icon": "🐳",
    },
    "aws": {
        "groups": ["aws", "amazon", "cloud"],
        "name": "Amazon Web Services",
        "description": "Security events related to your Amazon AWS services, collected directly via AWS API",
        "icon": "☁️",
    },
    "github": {
        "groups": ["github", "git", "audit"],
        "name": "GitHub",
        "description": "Monitoring events from audit logs of your GitHub organizations",
        "icon": "🐙",
    },
    "google_cloud": {
        "groups": ["gcp", "google_cloud", "gcloud"],
        "name": "Google Cloud",
        "description": "Security events related to your Google Cloud Platform services, collected directly via GCP API",
        "icon": "☁️",
    },
    "mitre_attack": {
        "groups": ["mitre", "attack", "tactics", "techniques"],
        "name": "MITRE ATT&CK",
        "description": "Explore security alerts mapped to adversary tactics and techniques for better threat understanding",
        "icon": "🎯",
    },
}


# --- Utility helpers ---

async def _first_working_url(urls, username, password, check_path="/", timeout=5):
    """Try list of URLs and return the first that responds successfully."""
    if not urls:
        return ""
    for u in urls:
        u = u.strip()
        if not u:
            continue
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                resp = await client.get(u.rstrip("/") + check_path, auth=(username, password))
                if resp.status_code in (200, 401, 403, 204):
                    logger.info(f"Connected to {u} (status {resp.status_code})")
                    return u.rstrip("/")
        except Exception as e:
            logger.debug(f"URL {u} not reachable: {e}")
    return ""


async def get_jwt_headers():
    """Obtain or return cached Wazuh JWT Authorization header."""
    try:
        now = datetime.utcnow()
        token = _jwt_cache.get("token", "")
        expiry = _jwt_cache.get("expiry", datetime.min)
        if token and expiry > now:
            return {"Authorization": f"Bearer {token}"}
        base = await _first_working_url(WAZUH_API_URLS, WAZUH_API_USER, WAZUH_API_PASS, check_path="/")
        if not base:
            return "❌ Error: Could not reach any Wazuh API URL for authentication."
        auth_url = base.rstrip("/") + "/security/user/authenticate?raw=true"
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.post(auth_url, auth=(WAZUH_API_USER, WAZUH_API_PASS))
            if resp.status_code not in (200, 201):
                return f"❌ API Error: authentication failed with status {resp.status_code}"
            text = resp.text.strip()
            token_val = ""
            if text:
                token_val = text
            else:
                try:
                    body = resp.json()
                    # Common Wazuh responses might include data.token
                    token_val = body.get("data", {}).get("token", "") or body.get("token", "")
                except Exception:
                    token_val = ""
            if not token_val:
                return "❌ Error: authentication returned empty token."
            _jwt_cache["token"] = token_val
            _jwt_cache["expiry"] = now + timedelta(seconds=300)
            logger.info("Obtained Wazuh JWT token")
            return {"Authorization": f"Bearer {token_val}"}
    except Exception as e:
        logger.error("JWT auth error", exc_info=True)
        return f"❌ Error: {str(e)}"


def _format_alerts_from_hits(hits, limit_int=10):
    """Format Elasticsearch hits into a readable string list."""
    if not hits:
        return "📊 Results: No alerts found."
    lines = []
    count = 0
    for h in hits:
        if count >= limit_int:
            break
        src = h.get("_source") or {}
        ts = src.get("@timestamp") or src.get("timestamp") or ""
        agent = src.get("agent", {}) or {}
        agent_name = agent.get("name") or agent.get("id") or agent.get("ip") or "unknown"
        rule = src.get("rule", {}) or {}
        rule_desc = rule.get("description") or rule.get("title") or ""
        rule_level = rule.get("level", "")
        full_msg = src.get("full_log") or src.get("raw") or src.get("message") or ""
        short = rule_desc if rule_desc else (full_msg[:120] + "..." if full_msg else "No description")
        lines.append(f"- [{ts}] (agent:{agent_name}) level:{rule_level} — {short}")
        count += 1
    header = f"📊 Results: {count} alerts"
    return header + "\n\n" + "\n".join(lines)


async def _search_wazuh_alerts_index(groups, limit="10", agent_filter=""):
    """Search the Wazuh indexer for alerts matching groups and optional agent filter."""
    try:
        if not str(limit).strip():
            limit_int = 10
        else:
            try:
                limit_int = int(limit)
            except Exception:
                return f"❌ Error: invalid limit value: {limit}"
        indexer = await _first_working_url(INDEXER_URLS, INDEXER_USER, INDEXER_PASS, check_path="/")
        if not indexer:
            return "❌ Error: Could not reach any indexer URL from INDEXER_URLS."
        must_clauses = []
        if groups:
            must_clauses.append({"terms": {"rule.groups": groups}})
        if str(agent_filter).strip():
            a = str(agent_filter).strip()
            must_clauses.append(
                {
                    "bool": {
                        "should": [
                            {"match_phrase": {"agent.name": a}},
                            {"match_phrase": {"agent.id": a}},
                            {"match_phrase": {"agent.ip": a}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
        body = {"size": limit_int, "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}} , "sort": [{"@timestamp": {"order": "desc"}}]}
        search_url = indexer.rstrip("/") + "/wazuh-alerts-*/_search"
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.post(search_url, auth=(INDEXER_USER, INDEXER_PASS), json=body)
            if resp.status_code != 200:
                return f"❌ API Error: indexer returned status {resp.status_code}"
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            return _format_alerts_from_hits(hits, limit_int)
    except Exception as e:
        logger.error("Indexer search error", exc_info=True)
        return f"❌ Error: {str(e)}"


async def _call_wazuh_api(path, params=None):
    """Call the Wazuh API using JWT and return parsed JSON or an error string."""
    try:
        headers = await get_jwt_headers()
        if isinstance(headers, str):
            return headers
        base = await _first_working_url(WAZUH_API_URLS, WAZUH_API_USER, WAZUH_API_PASS, check_path="/")
        if not base:
            return "❌ Error: Could not reach any Wazuh API URL."
        url = base.rstrip("/") + path
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code >= 400:
                return f"❌ API Error: Wazuh API returned status {resp.status_code}"
            return resp.json()
    except Exception as e:
        logger.error("Wazuh API error", exc_info=True)
        return f"❌ Error: {str(e)}"


# --- MCP Tools ---

@mcp.tool()
async def get_running_agents(limit: str = "") -> str:
    """Get list of running/enrolled Wazuh agents."""
    logger.info("Tool get_running_agents called")
    try:
        lim = int(limit) if str(limit).strip() else 100
    except Exception:
        return f"❌ Error: invalid limit value: {limit}"
    res = await _call_wazuh_api("/agents")
    if isinstance(res, str):
        return res
    try:
        agents = res.get("data", {}).get("affected_items") or res.get("data", {}).get("items") or res.get("data", [])
        if not agents:
            agents = res.get("data", [])
        lines = []
        count = 0
        for a in agents:
            if count >= lim:
                break
            aid = a.get("id") or a.get("agent_id") or ""
            name = a.get("name") or a.get("hostname") or ""
            ip = a.get("ip") or ""
            status = a.get("status") or a.get("connected") or ""
            lines.append(f"- id:{aid} name:{name} ip:{ip} status:{status}")
            count += 1
        if not lines:
            return "📊 Results: no agents found."
        return f"📊 Results: {count} agents\n\n" + "\n".join(lines)
    except Exception as e:
        logger.error("Parsing agents failed", exc_info=True)
        return f"❌ Error parsing agents response: {str(e)}"


# Module tools generated explicitly (each returns a formatted string)

@mcp.tool()
async def wazuh_FIM_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch File Integrity Monitoring alerts (syscheck)."""
    logger.info("Tool wazuh_FIM_Alerts called")
    mod = WAZUH_MODULES["file_integrity_monitoring"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_Malware_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch Malware Detection alerts (yara/virustotal/rootcheck)."""
    logger.info("Tool wazuh_Malware_Alerts called")
    mod = WAZUH_MODULES["malware_detection"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_Threat_Hunting_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch Threat Hunting alerts (attack/mitre/threat)."""
    logger.info("Tool wazuh_Threat_Hunting_Alerts called")
    mod = WAZUH_MODULES["threat_hunting"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_Vulnerability_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch Vulnerability Detection alerts (vulnerability/cve)."""
    logger.info("Tool wazuh_Vulnerability_Alerts called")
    mod = WAZUH_MODULES["vulnerability_detection"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_Configuration_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch Configuration Assessment alerts (configuration/assessment/sca)."""
    logger.info("Tool wazuh_Configuration_Alerts called")
    mod = WAZUH_MODULES["configuration_assessment"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_IT_Hygiene_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch IT Hygiene alerts (system/authentication/ssh/sudo/systemd)."""
    logger.info("Tool wazuh_IT_Hygiene_Alerts called")
    mod = WAZUH_MODULES["it_hygiene"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_PCI_DSS_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch PCI DSS alerts."""
    logger.info("Tool wazuh_PCI_DSS_Alerts called")
    mod = WAZUH_MODULES["pci_dss"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_GDPR_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch GDPR alerts."""
    logger.info("Tool wazuh_GDPR_Alerts called")
    mod = WAZUH_MODULES["gdpr"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_HIPAA_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch HIPAA alerts."""
    logger.info("Tool wazuh_HIPAA_Alerts called")
    mod = WAZUH_MODULES["hipaa"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_Docker_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch Docker/container alerts."""
    logger.info("Tool wazuh_Docker_Alerts called")
    mod = WAZUH_MODULES["docker"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_AWS_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch AWS alerts."""
    logger.info("Tool wazuh_AWS_Alerts called")
    mod = WAZUH_MODULES["aws"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_GitHub_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch GitHub/audit alerts."""
    logger.info("Tool wazuh_GitHub_Alerts called")
    mod = WAZUH_MODULES["github"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_GoogleCloud_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch Google Cloud alerts."""
    logger.info("Tool wazuh_GoogleCloud_Alerts called")
    mod = WAZUH_MODULES["google_cloud"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'

@mcp.tool()
async def wazuh_MITRE_Alerts(agent: str = "", limit: str = "") -> str:
    """Fetch MITRE ATT&CK mapped alerts."""
    logger.info("Tool wazuh_MITRE_Alerts called")
    mod = WAZUH_MODULES["mitre_attack"]
    out = await _search_wazuh_alerts_index(mod["groups"], limit or "10", agent)
    return f'{mod["icon"]} {mod["name"]} — {mod["description"]}\n\n{out}'


# Startup
if __name__ == "__main__":
    logger.info("Starting wazuh_mcp MCP server...")
    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
