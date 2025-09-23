#!/usr/bin/env python3
"""
Simple Wazu MCP Server - Complete Wazuh security monitoring with real alert access
"""
import os
import sys
import logging
import json
import base64
from datetime import datetime, timezone, timedelta
import httpx
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("wazu-server")

# Initialize MCP server
mcp = FastMCP("wazu")

# Configuration
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://192.168.x.x:55000")
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://192.168.x.x:9200")
WAZUH_USERNAME = os.environ.get("WAZUH_USERNAME", "wazuh")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD", "")
WAZUH_INDEXER_USERNAME = os.environ.get("WAZUH_INDEXER_USERNAME", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "admin")

# Alternative URLs to try if primary fails
ALTERNATIVE_URLS = [
    "https://192.168.x.x:55000",
    "https://127.0.0.1:55000",
    "https://172.17.0.1:55000",
    "https://host.docker.internal:55000"
]

ALTERNATIVE_INDEXER_URLS = [
    "https://192.168.x.x:9200",
    "https://127.0.0.1:9200", 
    "https://172.17.0.1:9200",
    "https://host.docker.internal:9200"
]

# Wazuh Dashboard Module Configurations
WAZUH_MODULES = {
    "file_integrity_monitoring": {
        "groups": ["syscheck"],
        "name": "File Integrity Monitoring",
        "description": "Alerts related to file changes, permissions, content, ownership, and attributes",
        "icon": "📁"
    },
    "malware_detection": {
        "groups": ["yara", "virustotal", "malware", "rootcheck"],
        "name": "Malware Detection", 
        "description": "Check indicators of compromise triggered by malware infections or cyberattacks",
        "icon": "🦠"
    },
    "threat_hunting": {
        "groups": ["attack", "mitre", "threat"],
        "name": "Threat Hunting",
        "description": "Browse through security alerts, identifying issues and threats in your environment",
        "icon": "🎯"
    },
    "vulnerability_detection": {
        "groups": ["vulnerability", "cve", "vulnerabilities"],
        "name": "Vulnerability Detection",
        "description": "Discover what applications in your environment are affected by well-known vulnerabilities",
        "icon": "🛡️"
    },
    "configuration_assessment": {
        "groups": ["configuration", "assessment", "sca"],
        "name": "Configuration Assessment",
        "description": "Scan your assets as part of a configuration assessment audit",
        "icon": "⚙️"
    },
    "it_hygiene": {
        "groups": ["system", "authentication", "ssh", "sudo", "systemd"],
        "name": "IT Hygiene",
        "description": "Assess system, software, processes, and network layers to detect misconfigurations and unauthorized changes",
        "icon": "🔧"
    },
    "pci_dss": {
        "groups": ["pci_dss", "pci", "payment"],
        "name": "PCI DSS",
        "description": "Global security standard for entities that process, store, or transmit payment cardholder data",
        "icon": "💳"
    },
    "gdpr": {
        "groups": ["gdpr", "privacy", "data_protection"],
        "name": "GDPR",
        "description": "General Data Protection Regulation sets guidelines for processing personal data",
        "icon": "🔒"
    },
    "hipaa": {
        "groups": ["hipaa", "health", "medical"],
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act provides data privacy and security provisions for safeguarding medical information",
        "icon": "🏥"
    },
    "docker": {
        "groups": ["docker", "container"],
        "name": "Docker",
        "description": "Monitor and collect the activity from Docker containers such as creation, running, starting, stopping or pausing events",
        "icon": "🐳"
    },
    "aws": {
        "groups": ["aws", "amazon", "cloud"],
        "name": "Amazon Web Services",
        "description": "Security events related to your Amazon AWS services, collected directly via AWS API",
        "icon": "☁️"
    },
    "github": {
        "groups": ["github", "git", "audit"],
        "name": "GitHub",
        "description": "Monitoring events from audit logs of your GitHub organizations",
        "icon": "🐙"
    },
    "google_cloud": {
        "groups": ["gcp", "google_cloud", "gcloud"],
        "name": "Google Cloud",
        "description": "Security events related to your Google Cloud Platform services, collected directly via GCP API",
        "icon": "☁️"
    },
    "mitre_attack": {
        "groups": ["mitre", "attack", "tactics", "techniques"],
        "name": "MITRE ATT&CK",
        "description": "Explore security alerts mapped to adversary tactics and techniques for better threat understanding",
        "icon": "🎯"
    }
}

# === UTILITY FUNCTIONS ===

def get_auth_headers():
    """Generate basic auth headers for Wazuh API"""
    if not WAZUH_PASSWORD.strip():
        return None
    
    credentials = f"{WAZUH_USERNAME}:{WAZUH_PASSWORD}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    return {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json"
    }

def get_indexer_auth_headers():
    """Generate basic auth headers for Wazuh Indexer"""
    if not WAZUH_INDEXER_PASSWORD.strip():
        return None
    
    credentials = f"{WAZUH_INDEXER_USERNAME}:{WAZUH_INDEXER_PASSWORD}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    return {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json"
    }

# Global token cache
_auth_token = None

async def get_jwt_token():
    """Get JWT token for Wazuh API authentication"""
    global _auth_token
    
    headers = get_auth_headers()
    if not headers:
        return None, "Missing Wazuh credentials"
    
    urls_to_try = [WAZUH_API_URL] + [url for url in ALTERNATIVE_URLS if url != WAZUH_API_URL]
    
    for url_base in urls_to_try:
        url = f"{url_base}/security/user/authenticate"
        
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                
                if "data" in data and "token" in data["data"]:
                    token = data["data"]["token"]
                    _auth_token = token
                    return token, None
                    
            except Exception:
                continue
    
    return None, "Failed to obtain JWT token from all URLs"

def get_jwt_headers(token):
    """Generate JWT headers for Wazuh API"""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

async def make_wazuh_request(endpoint: str, params: dict = None):
    """Make authenticated request to Wazuh API with JWT token"""
    global _auth_token
    
    if not _auth_token:
        token, error = await get_jwt_token()
        if error:
            return None, f"Authentication failed: {error}"
        _auth_token = token
    
    urls_to_try = [WAZUH_API_URL] + [url for url in ALTERNATIVE_URLS if url != WAZUH_API_URL]
    
    for url_base in urls_to_try:
        url = f"{url_base}{endpoint}"
        headers = get_jwt_headers(_auth_token)
        
        # Remove unsupported parameters for certain endpoints
        clean_params = params.copy() if params else {}
        if endpoint in ["/manager/info", "/manager/status"] and "limit" in clean_params:
            del clean_params["limit"]
        
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            try:
                response = await client.get(url, headers=headers, params=clean_params or {})
                
                if response.status_code == 401:
                    _auth_token = None
                    token, error = await get_jwt_token()
                    if error:
                        return None, f"Token refresh failed: {error}"
                    _auth_token = token
                    headers = get_jwt_headers(_auth_token)
                    response = await client.get(url, headers=headers, params=clean_params or {})
                
                response.raise_for_status()
                data = response.json()
                return data, None
                
            except httpx.ConnectError:
                continue
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    return None, f"HTTP 401: Authentication failed - {e.response.text}"
                else:
                    return None, f"HTTP {e.response.status_code}: {e.response.text}"
            except Exception:
                continue
    
    return None, f"All connection attempts failed. Tried: {', '.join(urls_to_try)}"

async def search_wazuh_alerts_index(query: dict = None, size: int = 20):
    """Search the Wazuh alerts index for real alerts"""
    headers = get_indexer_auth_headers()
    if not headers:
        return None, "Missing Wazuh indexer credentials"
    
    if query is None:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": "now-7d"}}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size
        }
    
    indexer_urls_to_try = [WAZUH_INDEXER_URL] + [url for url in ALTERNATIVE_INDEXER_URLS if url != WAZUH_INDEXER_URL]
    
    for indexer_url in indexer_urls_to_try:
        today = datetime.now().strftime("%Y.%m.%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y.%m.%d")
        
        index_patterns = [
            f"wazuh-alerts-4.x-{today}",
            f"wazuh-alerts-4.x-{yesterday}",
            "wazuh-alerts-4.x-*",
            "wazuh-alerts-*"
        ]
        
        for index_pattern in index_patterns:
            url = f"{indexer_url}/{index_pattern}/_search"
            
            async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
                try:
                    response = await client.post(url, headers=headers, json=query)
                    response.raise_for_status()
                    data = response.json()
                    
                    if "hits" in data and "hits" in data["hits"] and len(data["hits"]["hits"]) > 0:
                        logger.info(f"Successfully found {len(data['hits']['hits'])} alerts from {indexer_url} index {index_pattern}")
                        return data, None
                    
                except httpx.ConnectError:
                    continue
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        continue
                    elif e.response.status_code == 401:
                        return None, f"Authentication failed to indexer: {e.response.text}"
                    else:
                        continue
                except Exception:
                    continue
    
    return None, "Could not connect to Wazuh indexer or no alerts found"

async def get_real_wazuh_alerts(module_key: str = None, limit: int = 20, level: str = "", agent_id: str = ""):
    """Get real alerts from Wazuh alerts index with optional module filtering"""
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": "now-7d"}}}
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": limit
    }
    
    # Add module-specific filtering
    if module_key and module_key in WAZUH_MODULES:
        module_config = WAZUH_MODULES[module_key]
        groups = module_config["groups"]
        
        group_queries = []
        for group in groups:
            group_queries.append({"term": {"rule.groups": group}})
        
        if group_queries:
            query["query"]["bool"]["should"] = group_queries
            query["query"]["bool"]["minimum_should_match"] = 1
    
    # Add agent filter
    if agent_id.strip():
        query["query"]["bool"]["must"].append({"term": {"agent.id": agent_id.strip()}})
    
    # Add level filter  
    if level.strip():
        if level.strip().isdigit():
            query["query"]["bool"]["must"].append({"term": {"rule.level": int(level.strip())}})
        else:
            level_map = {
                "low": {"range": {"rule.level": {"gte": 1, "lte": 6}}},
                "medium": {"range": {"rule.level": {"gte": 7, "lte": 11}}}, 
                "high": {"range": {"rule.level": {"gte": 12, "lte": 14}}},
                "critical": {"range": {"rule.level": {"gte": 15}}}
            }
            if level.strip().lower() in level_map:
                query["query"]["bool"]["must"].append(level_map[level.strip().lower()])
    
    return await search_wazuh_alerts_index(query, limit)

def format_real_alerts(elasticsearch_data, module_key: str = None):
    """Format real alerts from Elasticsearch response"""
    if not elasticsearch_data or "hits" not in elasticsearch_data:
        return "No alert data available"
    
    hits = elasticsearch_data["hits"]["hits"]
    total_hits = elasticsearch_data["hits"]["total"]["value"] if isinstance(elasticsearch_data["hits"]["total"], dict) else elasticsearch_data["hits"]["total"]
    
    if not hits:
        module_name = WAZUH_MODULES.get(module_key, {}).get("name", "Security") if module_key else "Security"
        module_icon = WAZUH_MODULES.get(module_key, {}).get("icon", "🔍") if module_key else "🔍"
        return f"{module_icon} No {module_name} alerts found (Total in index: {total_hits})"
    
    if module_key and module_key in WAZUH_MODULES:
        module_config = WAZUH_MODULES[module_key]
        header = f"{module_config['icon']} {module_config['name']} Alerts"
    else:
        header = "🚨 Wazuh Security Alerts"
    
    formatted = f"{header} (Showing: {len(hits)}, Total: {total_hits})\n\n"
    
    for i, hit in enumerate(hits[:15]):
        source = hit.get("_source", {})
        
        rule = source.get("rule", {})
        agent = source.get("agent", {})
        
        rule_id = rule.get("id", "Unknown")
        rule_level = rule.get("level", "Unknown")
        rule_description = rule.get("description", "No description")
        rule_groups = rule.get("groups", [])
        
        agent_name = agent.get("name", "Unknown")
        agent_id = agent.get("id", "Unknown")
        
        timestamp = source.get("timestamp", "Unknown")
        full_log = source.get("full_log", "")
        
        mitre = rule.get("mitre", {})
        mitre_id = mitre.get("id", []) if isinstance(mitre.get("id"), list) else [mitre.get("id")] if mitre.get("id") else []
        mitre_technique = mitre.get("technique", []) if isinstance(mitre.get("technique"), list) else [mitre.get("technique")] if mitre.get("technique") else []
        
        formatted += f"Alert {i+1} (Rule {rule_id}):\n"
        formatted += f"  Severity: Level {rule_level}\n"
        formatted += f"  Agent: {agent_name} (ID: {agent_id})\n"
        formatted += f"  Description: {rule_description}\n"
        
        if rule_groups:
            formatted += f"  Categories: {', '.join(rule_groups[:3])}{'...' if len(rule_groups) > 3 else ''}\n"
        
        if mitre_id or mitre_technique:
            mitre_info = []
            if mitre_id:
                mitre_info.extend(mitre_id[:2])
            if mitre_technique:
                mitre_info.extend(mitre_technique[:2])
            formatted += f"  MITRE: {', '.join(mitre_info)}\n"
        
        if full_log:
            log_preview = full_log[:100] + "..." if len(full_log) > 100 else full_log
            formatted += f"  Log: {log_preview}\n"
        
        formatted += f"  Time: {timestamp}\n\n"
    
    if len(hits) > 15:
        formatted += f"... and {len(hits) - 15} more alerts\n"
    
    return formatted

async def get_filtered_alerts(module_key: str, limit: int = 20, level: str = "", agent_id: str = ""):
    """Get alerts filtered by module groups - now uses real alerts from indexer"""
    module_config = WAZUH_MODULES.get(module_key)
    if not module_config:
        return None, f"Unknown module: {module_key}"
    
    # Try to get real alerts from the indexer first
    try:
        data, error = await get_real_wazuh_alerts(module_key, limit, level, agent_id)
        if not error and data:
            return data, None
    except Exception as e:
        logger.warning(f"Could not access indexer for {module_key}: {e}")
    
    # Fallback to manager logs if indexer not available
    logger.info(f"Falling back to manager logs for {module_key}")
    params = {"limit": limit}
    
    if agent_id.strip():
        params["agents_list"] = agent_id.strip()
    
    data, error = await make_wazuh_request("/manager/logs", params)
    
    if error:
        return None, error
    
    if not data or not isinstance(data, dict):
        return None, "No data available"
    
    logs = data.get("data", {}).get("affected_items", [])
    
    filtered_logs = []
    module_groups = module_config["groups"]
    
    for log in logs:
        if isinstance(log, dict):
            log_desc = str(log.get("description", log.get("message", ""))).lower()
            log_level = str(log.get("level", ""))
            log_tag = str(log.get("tag", "")).lower()
            
            matches_group = any(group.lower() in log_desc or group.lower() in log_tag for group in module_groups)
            
            if not matches_group:
                continue
                
            if level.strip() and level.strip().lower() not in log_level.lower():
                continue
            
            filtered_logs.append(log)
    
    result_data = {
        "data": {
            "affected_items": filtered_logs,
            "total_affected_items": len(filtered_logs)
        },
        "message": f"Filtered alerts for {module_config['name']}",
        "error": 0
    }
    
    return result_data, None

def format_module_alerts(data, module_key: str):
    """Format module-specific alerts - handles both real alerts and fallback logs"""
    module_config = WAZUH_MODULES.get(module_key, {})
    module_name = module_config.get("name", "Unknown Module")
    module_icon = module_config.get("icon", "📊")
    
    if not data:
        return "No alert data available"
    
    # Check if this is Elasticsearch data (real alerts)
    if "hits" in data:
        return format_real_alerts(data, module_key)
    
    # Fallback: handle manager logs format
    if not isinstance(data, dict):
        return "No alert data available"
    
    data_section = data.get("data", {})
    affected_items = data_section.get("affected_items", [])
    total_items = data_section.get("total_affected_items", 0)
    
    if not affected_items:
        return f"{module_icon} No {module_name} alerts found (Total: {total_items})"
    
    formatted = f"{module_icon} {module_name} Alerts (Total: {total_items})\n\n"
    
    for i, alert in enumerate(affected_items[:15]):
        if isinstance(alert, dict):
            level = alert.get("level", "INFO")
            description = alert.get("description", alert.get("message", "No description"))
            timestamp = alert.get("timestamp", "Unknown")
            tag = alert.get("tag", "")
        else:
            level = "INFO"
            description = str(alert)
            timestamp = "Unknown"
            tag = ""
        
        formatted += f"Alert {i+1}:\n"
        formatted += f"  Level: {level}\n"
        if tag:
            formatted += f"  Category: {tag}\n"
        formatted += f"  Message: {description[:120]}{'...' if len(str(description)) > 120 else ''}\n"
        formatted += f"  Time: {timestamp}\n\n"
    
    if len(affected_items) > 15:
        formatted += f"... and {len(affected_items) - 15} more alerts\n"
    
    return formatted

def format_agent_data(agents):
    """Format agent data for display"""
    if not agents or not isinstance(agents, dict):
        return "No agent data available"
    
    data = agents.get("data", {})
    affected_items = data.get("affected_items", [])
    total_items = data.get("total_affected_items", 0)
    
    if not affected_items:
        return f"📊 No agents found (Total: {total_items})"
    
    formatted = f"🖥️ Wazuh Agents Summary (Total: {total_items})\n\n"
    
    for agent in affected_items[:20]:
        agent_id = agent.get("id", "Unknown")
        name = agent.get("name", "Unknown")
        status = agent.get("status", "Unknown")
        ip = agent.get("ip", "Unknown")
        os_platform = agent.get("os", {}).get("platform", "Unknown")
        version = agent.get("version", "Unknown")
        last_keep_alive = agent.get("lastKeepAlive", "Unknown")
        
        status_emoji = "✅" if status.lower() == "active" else "❌" if status.lower() == "disconnected" else "⚠️"
        
        formatted += f"Agent {agent_id} ({name}):\n"
        formatted += f"  Status: {status_emoji} {status}\n"
        formatted += f"  IP: {ip}\n"
        formatted += f"  OS: {os_platform}\n"
        formatted += f"  Version: {version}\n"
        formatted += f"  Last Keep Alive: {last_keep_alive}\n\n"
    
    if len(affected_items) > 20:
        formatted += f"... and {len(affected_items) - 20} more agents\n"
    
    return formatted

# === MCP TOOLS - GENERAL ===

@mcp.tool()
async def get_wazuh_agents(limit: str = "50", status: str = "", os_platform: str = "") -> str:
    """Get comprehensive information about Wazuh agents with optional filtering by status and OS platform."""
    try:
        params = {}
        
        if limit.strip() and limit.strip().isdigit():
            params["limit"] = int(limit.strip())
        else:
            params["limit"] = 50
        
        if status.strip():
            params["status"] = status.strip().lower()
        
        if os_platform.strip():
            params["os.platform"] = os_platform.strip()
        
        data, error = await make_wazuh_request("/agents", params)
        
        if error:
            return f"❌ Error fetching agents: {error}"
        
        return f"✅ {format_agent_data(data)}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_wazuh_running_agents(group: str = "") -> str:
    """Get overview of currently active/running agents with their real-time status and performance metrics."""
    try:
        params = {"status": "active", "limit": 100}
        
        if group.strip():
            params["group"] = group.strip()
        
        data, error = await make_wazuh_request("/agents", params)
        
        if error:
            return f"❌ Error fetching running agents: {error}"
        
        if not data or not isinstance(data, dict):
            return "❌ No agent data available"
        
        agents = data.get("data", {}).get("affected_items", [])
        total_agents = data.get("data", {}).get("total_affected_items", 0)
        
        if not agents:
            return f"🖥️ No active agents found (Total agents: {total_agents})"
        
        running_summary = f"🖥️ Active Wazuh Agents Overview\n\n"
        running_summary += f"Active Agents: {len(agents)} of {total_agents} total\n"
        running_summary += f"Group Filter: {group or 'All groups'}\n\n"
        
        # Statistics
        os_counts = {}
        version_counts = {}
        
        for agent in agents:
            os_platform = agent.get("os", {}).get("platform", "Unknown")
            os_counts[os_platform] = os_counts.get(os_platform, 0) + 1
            
            version = agent.get("version", "Unknown")
            version_counts[version] = version_counts.get(version, 0) + 1
        
        # OS Distribution
        if os_counts:
            running_summary += "💻 OS Distribution:\n"
            for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(agents)) * 100
                running_summary += f"  {os_name}: {count} agents ({percentage:.1f}%)\n"
            running_summary += "\n"
        
        # Version Distribution
        if version_counts:
            running_summary += "📦 Version Distribution:\n"
            for version, count in sorted(version_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                percentage = (count / len(agents)) * 100
                running_summary += f"  {version}: {count} agents ({percentage:.1f}%)\n"
        
        return f"✅ {running_summary}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

# === MCP TOOLS - MODULE SPECIFIC ===

@mcp.tool()
async def get_file_integrity_monitoring_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get File Integrity Monitoring (FIM) alerts - file changes, permissions, content, ownership, and attributes."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("file_integrity_monitoring", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching FIM alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'file_integrity_monitoring')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_malware_detection_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get Malware Detection alerts - indicators of compromise triggered by malware infections or cyberattacks."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("malware_detection", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching malware detection alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'malware_detection')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_threat_hunting_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get Threat Hunting alerts - security alerts for identifying issues and threats in your environment."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("threat_hunting", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching threat hunting alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'threat_hunting')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_vulnerability_detection_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get Vulnerability Detection alerts - applications affected by well-known vulnerabilities."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("vulnerability_detection", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching vulnerability alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'vulnerability_detection')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_it_hygiene_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get IT Hygiene alerts - system, software, processes, and network misconfigurations and unauthorized changes."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("it_hygiene", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching IT hygiene alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'it_hygiene')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_docker_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get Docker alerts - container activity including creation, running, starting, stopping or pausing events."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("docker", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching Docker alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'docker')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def get_mitre_attack_alerts(limit: str = "20", level: str = "", agent_id: str = "") -> str:
    """Get MITRE ATT&CK alerts - security alerts mapped to adversary tactics and techniques for threat understanding."""
    try:
        limit_int = int(limit.strip()) if limit.strip().isdigit() else 20
        data, error = await get_filtered_alerts("mitre_attack", limit_int, level, agent_id)
        
        if error:
            return f"❌ Error fetching MITRE ATT&CK alerts: {error}"
        
        return f"✅ {format_module_alerts(data, 'mitre_attack')}"
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def test_wazuh_indexer_connection() -> str:
    """Test connectivity to Wazuh indexer (Elasticsearch/OpenSearch) to access real alerts."""
    try:
        test_results = "🔍 Wazuh Indexer Connection Test\n\n"
        
        data, error = await search_wazuh_alerts_index({
            "query": {"match_all": {}},
            "size": 1
        }, 1)
        
        if error:
            test_results += f"❌ Indexer Connection: {error}\n"
            test_results += f"Indexer URL: {WAZUH_INDEXER_URL}\n"
            test_results += f"Username: {WAZUH_INDEXER_USERNAME}\n\n"
            
            test_results += "🔧 Troubleshooting:\n"
            test_results += "1. Check if Wazuh indexer is running on port 9200\n"
            test_results += "2. Verify indexer credentials (admin/admin by default)\n"
            test_results += "3. Ensure indexer is accessible from this container\n"
            test_results += "4. Check if wazuh-alerts-* indices exist\n\n"
            
            test_results += "⚠️ Using manager logs as fallback for alerts\n"
            
        else:
            hits = data.get("hits", {}).get("hits", [])
            total = data.get("hits", {}).get("total", 0)
            if isinstance(total, dict):
                total = total.get("value", 0)
            
            test_results += f"✅ Indexer Connection: Successfully connected\n"
            test_results += f"Indexer URL: {WAZUH_INDEXER_URL}\n"
            test_results += f"Total Alerts Available: {total}\n"
            
            if hits:
                latest_alert = hits[0].get("_source", {})
                timestamp = latest_alert.get("timestamp", "Unknown")
                agent_name = latest_alert.get("agent", {}).get("name", "Unknown")
                rule_desc = latest_alert.get("rule", {}).get("description", "Unknown")
                
                test_results += f"Latest Alert: {rule_desc[:50]}...\n"
                test_results += f"From Agent: {agent_name}\n"
                test_results += f"Timestamp: {timestamp}\n"
            
            test_results += "\n✅ Real-time alerts are available through indexer!\n"
        
        return test_results
        
    except Exception as e:
        return f"❌ Error testing indexer: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting Wazu MCP server with all dashboard modules...")
    
    logger.info(f"Wazuh API URL: {WAZUH_API_URL}")
    logger.info(f"Wazuh Indexer URL: {WAZUH_INDEXER_URL}")
    logger.info(f"Username: {WAZUH_USERNAME}")
    logger.info(f"Indexer Username: {WAZUH_INDEXER_USERNAME}")
    logger.info(f"Password configured: {bool(WAZUH_PASSWORD.strip())}")
    logger.info(f"Indexer Password configured: {bool(WAZUH_INDEXER_PASSWORD.strip())}")
    logger.info(f"Dashboard modules available: {len(WAZUH_MODULES)}")
    
    # Test connectivity on startup
    import asyncio
    async def test_connection():
        logger.info("Testing Wazuh API connectivity...")
        try:
            token, error = await get_jwt_token()
            if error:
                logger.error(f"JWT token test failed: {error}")
            else:
                logger.info("JWT token acquired successfully")
                
            data, error = await make_wazuh_request("/manager/logs", {"limit": 1})
            if error:
                logger.error(f"API endpoint test failed: {error}")
            else:
                logger.info("API endpoint test successful")
        except Exception as e:
            logger.error(f"Startup connectivity test error: {e}")
    
    try:
        asyncio.run(test_connection())
    except Exception as e:
        logger.error(f"Failed to run connectivity test: {e}")
    
    try:
        logger.info("Starting MCP server with stdio transport...")
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)