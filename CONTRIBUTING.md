# 🤝 Contributing to Wazuh MCP Server

Thank you for your interest in contributing to the Wazuh MCP Server! This document provides guidelines and requirements for contributing to this project.

---

## 📋 Table of Contents

- [🎯 How to Contribute](#-how-to-contribute)
- [🔧 Development Setup](#-development-setup)
- [📝 Code Standards](#-code-standards)
- [🧪 Testing Requirements](#-testing-requirements)
- [📋 Pull Request Process](#-pull-request-process)
- [🐛 Bug Reports](#-bug-reports)
- [💡 Feature Requests](#-feature-requests)
- [📄 Code of Conduct](#-code-of-conduct)
- [📞 Contact](#-contact)

---

## 🎯 How to Contribute

We welcome contributions in many forms:

- 🐛 **Bug Fixes**: Fix issues and improve stability
- ✨ **New Features**: Add new functionality and tools
- 📚 **Documentation**: Improve docs, examples, and guides
- 🧪 **Testing**: Add tests and improve test coverage
- 🎨 **UI/UX**: Improve user experience and interface
- 🔧 **DevOps**: Improve build, deployment, and CI/CD
- 🌍 **Internationalization**: Add multi-language support

---

## 🔧 Development Setup

### Prerequisites

- **🐍 Python 3.11+** - Required for development
- **🐳 Docker Desktop** - For containerization and testing
- **📦 Git** - Version control
- **🔧 Code Editor** - VS Code, PyCharm, or your preferred editor

### Environment Setup

1. **Fork and Clone the Repository**

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/gnix45/wazuh-mcp-server.git
cd wazuh-mcp-server

# Add upstream remote
git remote add upstream https://github.com/gnix45/wazuh-mcp-server.git
```

2. **Create a Development Environment**

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available
```

3. **Set Up Pre-commit Hooks**

```bash
# Install pre-commit
pip install pre-commit

# Install git hooks
pre-commit install
```

4. **Configure Environment Variables**

```bash
# Copy example environment file
cp .env.example .env

# Edit with your Wazuh configuration
nano .env
```

---

## 📝 Code Standards

### Python Code Style

We follow **PEP 8** and use **Black** for code formatting:

```bash
# Format code with Black
black wazuh_mcp_server.py

# Check code style
flake8 wazuh_mcp_server.py

# Type checking with mypy
mypy wazuh_mcp_server.py
```

### Code Quality Requirements

- **📏 Line Length**: Maximum 88 characters (Black default)
- **📚 Docstrings**: All functions must have Google-style docstrings
- **🏷️ Type Hints**: Use type hints for all function parameters and returns
- **🧪 Test Coverage**: Maintain minimum 80% test coverage
- **📝 Comments**: Add comments for complex logic and business rules

### Example Code Style

```python
def get_wazuh_alerts(
    module: str,
    limit: int = 20,
    agent_id: Optional[str] = None
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Retrieve alerts from a specific Wazuh module.
    
    Args:
        module: The Wazuh module name (e.g., 'FIM', 'Malware')
        limit: Maximum number of alerts to return (default: 20)
        agent_id: Optional agent ID to filter alerts
        
    Returns:
        Tuple containing (alert_data, error_message)
        
    Raises:
        ValueError: If module is not supported
        ConnectionError: If unable to connect to Wazuh API
    """
    # Implementation here
    pass
```

### Git Commit Standards

We use **Conventional Commits** format:

```bash
# Format: type(scope): description
git commit -m "feat(fim): add file integrity monitoring alerts"
git commit -m "fix(auth): resolve JWT token refresh issue"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(api): add unit tests for Wazuh API client"
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

---

## 🧪 Testing Requirements

### Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── test_auth.py        # Authentication tests
│   ├── test_alerts.py      # Alert retrieval tests
│   └── test_api.py         # API client tests
├── integration/            # Integration tests
│   ├── test_wazuh_api.py   # Wazuh API integration
│   └── test_indexer.py     # Indexer integration
├── fixtures/               # Test data and fixtures
│   ├── sample_alerts.json
│   └── mock_responses.json
└── conftest.py            # Pytest configuration
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=wazuh_mcp_server --cov-report=html

# Run specific test file
pytest tests/unit/test_auth.py

# Run with verbose output
pytest -v

# Run integration tests only
pytest tests/integration/
```

### Test Requirements

- **✅ All tests must pass** before submitting PR
- **📊 Minimum 80% code coverage** for new features
- **🧪 Integration tests** for Wazuh API interactions
- **🔒 Security tests** for authentication and authorization
- **📱 Docker tests** for container functionality

### Mock Testing

For testing without actual Wazuh infrastructure:

```python
import pytest
from unittest.mock import Mock, patch

@patch('wazuh_mcp_server.requests.post')
def test_authenticate_success(mock_post):
    """Test successful authentication."""
    mock_response = Mock()
    mock_response.json.return_value = {"data": {"token": "test-token"}}
    mock_response.status_code = 200
    mock_post.return_value = mock_response
    
    result = authenticate_wazuh_api("user", "pass")
    assert result == "test-token"
```

---

## 📋 Pull Request Process

### Before Submitting

1. **🔍 Check Existing Issues**: Search for related issues or PRs
2. **📋 Create Issue**: For significant changes, create an issue first
3. **🌿 Create Branch**: Create a feature branch from `main`
4. **✅ Run Tests**: Ensure all tests pass
5. **📝 Update Docs**: Update documentation if needed
6. **🔍 Self Review**: Review your own code before submitting

### Creating a Pull Request

1. **🌿 Create Feature Branch**

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

2. **💻 Make Changes**

```bash
# Make your changes
# Add tests
# Update documentation
# Run tests to ensure they pass
```

3. **📝 Commit Changes**

```bash
git add .
git commit -m "feat(module): add new functionality"
```

4. **📤 Push and Create PR**

```bash
git push origin feature/your-feature-name
# Create PR on GitHub
```

### PR Requirements

- **📝 Clear Description**: Explain what the PR does and why
- **🔗 Link Issues**: Reference related issues with `Fixes #123`
- **📊 Test Results**: Include test results and coverage
- **📸 Screenshots**: For UI changes, include before/after screenshots
- **📋 Checklist**: Complete the PR template checklist

### PR Template

```markdown
## 📋 Description
Brief description of changes

## 🔗 Related Issues
Fixes #123

## 🧪 Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Code coverage maintained

## 📸 Screenshots
(If applicable)

## 📋 Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes (or documented)
```

---

## 🐛 Bug Reports

### Before Reporting

1. **🔍 Search Issues**: Check if the bug is already reported
2. **🧪 Reproduce**: Ensure you can reproduce the issue
3. **📋 Gather Info**: Collect relevant system information

### Bug Report Template

```markdown
## 🐛 Bug Description
Clear description of the bug

## 🔄 Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## 🎯 Expected Behavior
What you expected to happen

## 🚨 Actual Behavior
What actually happened

## 📊 Environment
- OS: [e.g., Ubuntu 24.04]
- Python: [e.g., 3.11.5]
- Docker: [e.g., 24.0.7]
- Wazuh: [e.g., 4.13.0]

## 📸 Screenshots
(If applicable)

## 📋 Additional Context
Any other relevant information
```

---

## 💡 Feature Requests

### Before Requesting

1. **🔍 Search Issues**: Check if feature is already requested
2. **💭 Consider Scope**: Ensure it fits the project's goals
3. **📋 Provide Details**: Be specific about requirements

### Feature Request Template

```markdown
## 💡 Feature Description
Clear description of the requested feature

## 🎯 Use Case
Why is this feature needed? What problem does it solve?

## 📋 Requirements
- Requirement 1
- Requirement 2
- Requirement 3

## 🎨 Mockups/Examples
(If applicable)

## 📊 Priority
- [ ] Low
- [ ] Medium
- [ ] High
- [ ] Critical

## 📋 Additional Context
Any other relevant information
```

---

## 📄 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of:

- Age, body size, disability, ethnicity
- Gender identity and expression
- Level of experience, education
- Nationality, personal appearance
- Race, religion, sexual orientation

### Expected Behavior

- **🤝 Be Respectful**: Use welcoming and inclusive language
- **🤔 Be Open**: Accept constructive criticism gracefully
- **💡 Be Helpful**: Focus on what's best for the community
- **📚 Be Learning**: Show empathy towards other community members

### Unacceptable Behavior

- Harassment, trolling, or inappropriate comments
- Personal attacks or political discussions
- Public or private harassment
- Publishing private information without permission
- Any conduct inappropriate in a professional setting

### Enforcement

Instances of unacceptable behavior can be reported to [tectrib@gmail.com](mailto:tectrib@gmail.com). All complaints will be reviewed and investigated.

---

## 📞 Contact

### Maintainer
- **👨‍💻 Name**: Mr PK
- **📧 Email**: [tectrib@gmail.com](mailto:tectrib@gmail.com)
- **🐙 GitHub**: [@gnix45](https://github.com/gnix45)

### Project Links
- **🏠 Repository**: [wazuh-mcp-server](https://github.com/gnix45/wazuh-mcp-server)
- **📋 Issues**: [GitHub Issues](https://github.com/gnix45/wazuh-mcp-server/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/gnix45/wazuh-mcp-server/discussions)

---

## 🙏 Thank You

Thank you for contributing to the Wazuh MCP Server! Your contributions help make security monitoring more accessible and powerful for everyone.

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

*Built with ❤️ for the security community*

</div>
