# 📋 Changelog

All notable changes to the Wazuh MCP Server project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2025-09-23

### 🎉 Major Release - Production Ready

#### ✨ Added
- **🔧 Proper Function Placement**: All functions are now properly defined before they're used
- **🧪 New Testing Tool**: Added `test_wazuh_indexer_connection` for connectivity validation
- **📦 Simplified Module Structure**: Focused on the most essential modules that actually work
- **🔗 Function Access**: All functions are properly accessible and defined
- **📊 Enhanced Rule Groups**: Added "systemd" to IT Hygiene module to catch systemd alerts
- **🛡️ Smart Fallback System**: Uses manager logs when indexer is unavailable

#### 🔧 Fixed
- **📥 Clean Imports**: Fixed all import statements and added missing `timedelta`
- **⚠️ Error Handling**: Improved error handling for API requests with comprehensive fallbacks
- **🔐 Authentication**: Better JWT token management and refresh logic
- **🌐 Network Issues**: Enhanced connectivity handling for both API and indexer

#### 🚀 Performance
- **⚡ Real Alert Access**: Connects to Wazuh indexer on port 9200 to get actual alerts
- **🔄 Efficient Caching**: Improved token caching and reuse mechanisms
- **📈 Better Error Messages**: More informative error messages for debugging

#### 🛠️ Technical Improvements
- **🏗️ Simplified Structure**: Focused on core functionality that actually works
- **📝 Better Documentation**: Enhanced code comments and documentation
- **🧪 Comprehensive Testing**: Added multiple test scenarios and validation

---

## [1.0.0] - 2025-09-22

### 🎊 Initial Release

#### ✨ Core Features Added
- **🤖 MCP Server Implementation**: Complete Model Context Protocol server
- **🔐 JWT Authentication**: Secure authentication with Wazuh API
- **📊 Multi-Module Support**: Support for all major Wazuh security modules
- **🐳 Docker Integration**: Full containerization with Docker support
- **🔧 Claude Desktop Integration**: Seamless integration with Claude Desktop

#### 🛡️ Security Modules Implemented
- **📁 File Integrity Monitoring (FIM)**: Track file changes and modifications
- **🦠 Malware Detection**: Identify potential threats and suspicious activities
- **🔍 Threat Hunting**: Advanced threat detection and analysis
- **🔓 Vulnerability Assessment**: Security vulnerability tracking
- **🧹 IT Hygiene**: System configuration and compliance monitoring
- **🐳 Docker Monitoring**: Container security and activity tracking
- **🎯 MITRE ATT&CK Mapping**: Tactics, techniques, and procedures analysis

#### 🔧 Core Functionality Tools
- `get_wazuh_agents` - Retrieve all Wazuh agents
- `get_wazuh_running_agents` - Get currently active agents
- `test_wazuh_indexer_connection` - Validate indexer connectivity

#### 🎯 Key Security Module Tools
- `get_file_integrity_monitoring_alerts` - FIM alert retrieval
- `get_malware_detection_alerts` - Malware detection alerts
- `get_threat_hunting_alerts` - Threat hunting analysis
- `get_vulnerability_detection_alerts` - Vulnerability assessment
- `get_it_hygiene_alerts` - IT hygiene and compliance
- `get_docker_alerts` - Docker container monitoring
- `get_mitre_attack_alerts` - MITRE ATT&CK framework mapping

#### 📦 Infrastructure
- **🐳 Dockerfile**: Complete containerization setup
- **📋 Requirements**: Python dependencies management
- **🔧 Setup Script**: Automated configuration and setup
- **📖 Documentation**: Comprehensive README and guides
- **📄 License**: MIT License for open source distribution

---

## 🔮 Planned Features

### Version 1.3.0 (Upcoming)

- **🔔 N8N intergration**: automate get and push summary to SOC team
- **📈 Analytics**: Advanced security analytics and reporting
- **🌐 Multi-Tenant Support**: Support for multiple Wazuh instances

---

## 🐛 Bug Reports

Found a bug? Please report it in our [Issues](https://github.com/gnix45/wazuh-mcp-server/issues) section.

## 💡 Feature Requests

Have an idea for a new feature? We'd love to hear it! Submit your request [here](https://github.com/gnix45/wazuh-mcp-server/issues).

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.


---

<div align="center">

**📅 Last Updated**: September 23, 2025  
**👨‍💻 Maintained by**: Mr PK  
**📧 Contact**: [Your Email](mailto:tectrib@gmail.com)

</div>