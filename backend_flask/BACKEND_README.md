# CyberMind Sentinel - Flask Backend

> Autonomous Security Analyst with Cross-Platform Firewall Integration
> 
> A sophisticated cybersecurity platform that operates as a "Commander" interfacing with native firewalls to detect and respond to security threats.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Core Components](#core-components)
- [Service Features](#service-features)
- [Firewall Integration](#firewall-integration)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Deployment](#deployment)

---

## 🎯 Overview

**CyberMind Sentinel** is an advanced autonomous security analyst powered by Flask. Unlike traditional firewalls, it operates as a "Commander" that:

- 🔍 **Detects** the host operating system
- 🛡️ **Interfaces** with native firewalls (Windows Defender, iptables/ufw, pf)
- 🚨 **Analyzes** threats using AI/LLM integration
- ⚡ **Responds** automatically with remediation playbooks
- 🔒 **Isolates** networks in emergencies with Kill Switch
- 📊 **Monitors** fleet activity and honeypot attacks

---

## 🏗️ Architecture

```
CyberMind Sentinel Flask Backend
│
├── Core Layer (firewall_manager.py)
│   ├── OS Detection (Windows/Linux/macOS)
│   ├── Native Firewall Interfacing
│   ├── IP Blocking via netsh/iptables/pf
│   └── Network Isolation (Kill Switch)
│
├── Service Layer (app/services/)
│   ├── AITranslator - LLM integration for threat analysis
│   ├── FleetMonitor - Network reconnaissance
│   ├── NetworkHoneypot - Deception & attack logging
│   ├── PhishingSandbox - URL/email threat analysis
│   ├── RemediationPlaybook - Orchestration engine
│   └── KillSwitch - Emergency network isolation
│
├── API Layer (app/api/routes.py)
│   └── REST Endpoints (20+ endpoints)
│
└── Configuration (config/config.py)
    ├── Development mode
    ├── Production mode
    └── Testing mode
```

---

## ✨ Features

### 🔐 Security Management
- ✅ **Cross-Platform Firewall Control** - Windows (netsh), Linux (iptables/ufw), macOS (pf)
- ✅ **IP Blocking** - Block malicious IPs at OS level
- ✅ **Network Isolation** - Emergency kill switch (drops all traffic)
- ✅ **Permission Error Handling** - Graceful degradation with detailed logging

### 🤖 Intelligence
- 🔜 **AI Threat Analysis** - LLM integration for smart analysis
- 🔜 **Log Translation** - Convert raw logs to human-readable format
- 🔜 **Security Q&A** - Ask AI security questions

### 🛰️ Monitoring
- 🔄 **Fleet Monitor** - Network discovery and device tracking
- 📊 **Connection Tracking** - Active connection monitoring
- 🏓 **Ping Sweep** - Network reconnaissance (stub)
- 📈 **Bandwidth Monitoring** - (Stub for implementation)

### 🍯 Honeypot
- 🪤 **Port Binding** - Bind to fake service ports
- 📋 **Connection Logging** - Capture attacker information
- 🎭 **Service Emulation** - Fake SSH/FTP/HTTP responses
- 🔍 **Pattern Analysis** - Identify attack trends

### 📧 Threat Intelligence
- 🔗 **URL Reputation Checking** - Integration-ready (VirusTotal, URLhaus)
- 📬 **Email Analysis** - Phishing indicator detection
- 📎 **Attachment Scanning** - File hash reputation
- 🌐 **Domain Reputation** - Domain analysis (stub)

### ⚙️ Automation
- 📋 **Remediation Playbooks** - Predefined response templates
  - Block Malicious IP
  - Emergency Network Isolation
  - Contain Active Breach
  - DDoS Mitigation
  - Ransomware Response
- 🎬 **Action Orchestration** - Chain multiple security actions
- 📬 **Alert Notifications** - IR team notifications (stub)

---

## 🛠️ Tech Stack

### Backend Framework
- **Flask** 3.0.0 - Lightweight Python web framework
- **Flask-CORS** 4.0.0 - Cross-origin request handling
- **Python 3.8+** - Core language

### Security & Cryptography
- **bcrypt** 4.1.1 - Password hashing
- **PyJWT** 2.8.1 - JSON Web Token authentication
- **cryptography** 41.0.7 - Encryption utilities

### System Integration
- **psutil** 5.9.6 - System/process utilities
- **subprocess** - Native OS command execution
- **paramiko** 3.4.0 - SSH support for remote execution

### Network Tools (Advanced Features)
- **scapy** 2.5.0 - Packet generation/sniffing
- **socket** - Low-level socket operations
- **requests** 2.31.0 - HTTP requests

### Development & Testing
- **pytest** 7.4.3 - Testing framework
- **black** 23.12.0 - Code formatter
- **flake8** 6.1.0 - Linter
- **mypy** 1.7.1 - Type checker

---

## 📁 Project Structure

```
backend_flask/
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── core/
│   │   ├── __init__.py
│   │   └── firewall_manager.py     # Cross-platform firewall control
│   ├── services/
│   │   ├── __init__.py
│   │   ├── ai_translator.py        # LLM integration
│   │   ├── fleet_monitor.py        # Network monitoring
│   │   ├── network_honeypot.py     # Deception/logging
│   │   ├── phishing_sandbox.py     # Threat intelligence
│   │   ├── remediation_playbook.py # Automation engine
│   │   └── kill_switch.py          # Emergency isolation
│   └── api/
│       ├── __init__.py
│       └── routes.py               # REST endpoints
├── config/
│   └── config.py                   # Configuration classes
├── logs/
│   └── cybermind.log              # Application logs
├── tests/
│   ├── test_firewall.py           # Firewall tests
│   ├── test_services.py           # Service tests
│   └── test_api.py                # API endpoint tests
├── run.py                          # Entry point
├── setup.py                        # Setup utilities
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment template
├── API_REFERENCE.md               # Endpoint documentation
└── README.md                       # This file
```

---

## 📦 Installation

### Prerequisites
- Python 3.8+ ([Download](https://www.python.org/))
- pip (comes with Python)
- Git (optional)
- macOS/Linux: Elevated privileges for firewall commands
- Windows: Admin privileges for netsh commands

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/CyberMind.git
cd CyberMind/backend_flask
```

### Step 2: Create Virtual Environment
```bash
# macOS/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment
```bash
# Copy example configuration
cp .env.example .env

# Edit .env with your settings
nano .env  # or use your preferred editor
```

### Step 5: Run Setup Verification
```bash
python setup.py
```

---

## 🚀 Quick Start

### Development Server
```bash
# Start backend
python run.py

# In another terminal, start React frontend
cd ../frontend
npm run dev
```

### Access Points
- **API Server**: http://localhost:5000
- **Health Check**: http://localhost:5000/api/health
- **System Status**: http://localhost:5000/api/status
- **API Docs**: See `API_REFERENCE.md`

### Test Endpoints
```bash
# Health check
curl http://localhost:5000/api/health

# Get firewall status
curl http://localhost:5000/api/firewall/status

# Get system status
curl http://localhost:5000/api/status

# Block an IP (requires token)
curl -X POST http://localhost:5000/api/firewall/block_ip \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "reason": "Testing"}'
```

---

## ⚙️ Configuration

### Environment Variables

```env
# Flask Configuration
FLASK_ENV=development              # development|production|testing
FLASK_HOST=0.0.0.0               # Host binding
FLASK_PORT=5000                  # Port number
SECRET_KEY=your-secret-key       # Session key (change in production!)

# LLM Configuration
LLM_PROVIDER=openai              # openai|anthropic|huggingface|local
OPENAI_API_KEY=sk_...            # OpenAI API key
ANTHROPIC_API_KEY=...            # Anthropic API key

# Email Configuration
EMAIL_METHOD=demo                # demo|gmail|sendgrid
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=app-password
EMAIL_FROM=noreply@cybermind.com

# Security Features
FIREWALL_ENABLED=true            # Enable firewall control
HONEYPOT_ENABLED=true            # Enable honeypot
MONITORING_ENABLED=true          # Enable monitoring

# Logging
LOG_LEVEL=INFO                   # DEBUG|INFO|WARNING|ERROR|CRITICAL
```

### Configuration Modes

- **Development**: Debug enabled, detailed logging
- **Production**: Debug disabled, secure cookies (HTTPS required)
- **Testing**: No CSRF, faster responses

---

## 📡 API Documentation

### Quick Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/health` | Health check |
| GET | `/api/status` | System status |
| GET | `/api/firewall/status` | Firewall status |
| POST | `/api/firewall/block_ip` | Block IP address |
| POST | `/api/kill_switch/activate` | Emergency isolation |
| POST | `/api/kill_switch/deactivate` | Release isolation |
| GET | `/api/honeypot/logs` | Honeypot logs |
| POST | `/api/phishing/check_url` | Check URL reputation |
| GET | `/api/remediation/playbooks` | List playbooks |
| POST | `/api/remediation/execute` | Execute playbook |

**Full API Reference**: See [API_REFERENCE.md](API_REFERENCE.md)

---

## 🔧 Core Components

### 1. FirewallManager (`app/core/firewall_manager.py`)

**Purpose**: Cross-platform firewall control

**Key Methods**:
```python
firewall = FirewallManager()

# Block an IP
result = firewall.block_ip("192.168.1.100", "Malicious")

# Emergency isolation
result = firewall.isolate_network("Critical threat")

# Release isolation
result = firewall.release_network_isolation()

# Get status
status = firewall.get_status()
```

**Supported Platforms**:
- **Windows**: `netsh advfirewall firewall` commands
- **Linux**: `ufw` (Debian/Ubuntu) or `iptables` (system-level)
- **macOS**: `pf` (packet filter) and `pfctl`

**Error Handling**:
- Graceful subprocess timeout (10s default)
- Permission error detection with helpful messages
- Comprehensive logging for debugging

### 2. AITranslator (`app/services/ai_translator.py`)

**Purpose**: LLM integration for threat analysis

**Supported Providers**:
- OpenAI GPT-4/3.5
- Anthropic Claude
- Hugging Face Inference
- Local models (Ollama, etc.)

**Example Usage**:
```python
ai = AITranslator(provider="openai", api_key="sk_...")

# Analyze threat
analysis = ai.analyze_threat({
    "threat_type": "port_scan",
    "source_ip": "203.0.113.45"
})

# Ask question
answer = ai.ask_security_question("What is social engineering?")
```

### 3. FleetMonitor (`app/services/fleet_monitor.py`)

**Purpose**: Network discovery and device tracking

**Features**:
- Ping sweep discovery
- Port scanning
- Connection tracking
- Bandwidth monitoring
- Device information collection

### 4. NetworkHoneypot (`app/services/network_honeypot.py`)

**Purpose**: Deception and threat intelligence

**Capabilities**:
- Bind to multiple ports
- Emulate services (SSH, FTP, HTTP)
- Log connection attempts
- Pattern analysis
- Attacker IP tracking

### 5. PhishingSandbox (`app/services/phishing_sandbox.py`)

**Purpose**: Email and URL threat analysis

**Integration Points**:
- VirusTotal API
- URLhaus
- Email header analysis
- Attachment scanning
- Domain reputation

### 6. RemediationPlaybook (`app/services/remediation_playbook.py`)

**Purpose**: Automated response orchestration

**Built-in Playbooks**:
- `block_ip` - Block malicious IP
- `isolate_network` - Emergency isolation
- `contain_breach` - Activate monitoring
- `ddos_mitigation` - Rate limiting
- `ransomware_response` - Network isolation + backup

### 7. KillSwitch (`app/services/kill_switch.py`)

**Purpose**: Emergency network isolation

**Features**:
- Single-command total network lockdown
- Authorization-based deactivation
- Logging and audit trail
- Panic button for critical threats

---

## 🛡️ Firewall Integration

### Windows (netsh)

```python
# Block IP
netsh advfirewall firewall add rule name=CYBERMIND_BLOCK_192_168_1_100 \
  dir=in action=block remoteip=192.168.1.100 protocol=any

# Isolate network
netsh advfirewall firewall add rule name=CYBERMIND_KILL_SWITCH \
  dir=in action=block remoteip=any
```

### Linux (ufw/iptables)

```bash
# Block IP (ufw)
sudo ufw deny from 192.168.1.100

# Block IP (iptables)
sudo iptables -I INPUT -s 192.168.1.100 -j DROP
sudo iptables -I OUTPUT -d 192.168.1.100 -j DROP

# Isolate network
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP
```

### macOS (pf)

```bash
# Block IP
echo "block drop in from 192.168.1.100" >> /etc/pf.conf
pfctl -f /etc/pf.conf

# Isolate network
echo "block drop all" | pfctl -f -
```

---

## ⚠️ Error Handling

### Permission Errors

```python
# When running without elevated privileges:
return {
    "success": False,
    "message": "Permission denied. Run with sudo/admin.",
    "error": "Permission error executing netsh"
}
```

### Timeout Handling

```python
# Commands timeout after 10 seconds
return {
    "success": False,
    "message": "Command timeout after 10s",
    "error": "subprocess.TimeoutExpired"
}
```

### Graceful Degradation

- Invalid IP validation
- OS detection
- Command availability checks
- Comprehensive logging for debugging

---

## 🧪 Testing

### Run All Tests
```bash
pytest
```

### Run Specific Tests
```bash
# Test firewall manager
pytest tests/test_firewall.py

# Test API endpoints
pytest tests/test_api.py -v

# With coverage
pytest --cov=app tests/
```

### Manual Smoke Test
```bash
# Run setup verification
python setup.py

# Check dependencies
python -c "from app.core.firewall_manager import FirewallManager; print('✓ FirewallManager imported successfully')"
```

---

## 🚢 Deployment

### Production Checklist

- [ ] Change `SECRET_KEY` in `.env`
- [ ] Set `FLASK_ENV=production`
- [ ] Enable HTTPS/SSL certificates
- [ ] Configure `CORS_ORIGINS` for frontend domain
- [ ] Set up database (upgrade from JSON)
- [ ] Configure email service (Gmail/SendGrid)
- [ ] Set up monitoring/logging
- [ ] Configure backup strategy
- [ ] Test firewall commands with elevated privileges
- [ ] Set up systemd service or Docker container

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

ENV FLASK_ENV=production
EXPOSE 5000

CMD ["python", "run.py"]
```

### Systemd Service (Linux)

```ini
[Unit]
Description=CyberMind Sentinel Flask Backend
After=network.target

[Service]
Type=simple
User=cybermind
WorkingDirectory=/opt/cybermind/backend_flask
ExecStart=/opt/cybermind/backend_flask/venv/bin/python run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 📚 Additional Resources

- [API Reference](API_REFERENCE.md) - Complete endpoint documentation
- [Main README](../README.md) - Project overview
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Python subprocess](https://docs.python.org/3/library/subprocess.html)
- [netsh firewall commands](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netsh)
- [iptables guide](https://netfilter.org/projects/iptables/index.html)
- [pf (macOS) manual](https://man.freebsd.org/cgi/man.cgi?sektion=5&query=pf.conf)

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## 📞 Support

- 📖 Documentation: See README.md and API_REFERENCE.md
- 🐛 Report bugs: Open GitHub issue
- 💡 Suggest features: Submit feature request
- 📧 Email: support@cybermind.com

---

## 📄 License

MIT License - See LICENSE file for details

---

<div align="center">

**CyberMind Sentinel - Autonomous Cybersecurity Defense**

Made with ❤️ for cybersecurity professionals

© 2025 CyberMind. All rights reserved.

</div>
