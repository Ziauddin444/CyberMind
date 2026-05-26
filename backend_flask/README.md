# CyberMind Sentinel - Flask Backend

## Overview
CyberMind Sentinel is a **production-ready cybersecurity operations platform** with automated threat detection and response capabilities. The Flask backend provides a REST API for managing security operations across Windows, Linux, and macOS systems.

## ⚠️ IMPORTANT: Scapy Requires Root/Admin Privileges

**For live packet capture to work**, the Flask server MUST run with elevated privileges:

### macOS / Linux
```bash
sudo python3 run.py
# or with the startup script:
sudo bash start_all.sh
```

### Windows
Run Command Prompt **as Administrator**, then:
```bash
python run.py
```

**Without root/admin privileges:**
- ✗ Scapy silently falls back to **synthetic simulation**
- ✗ Your "live scan" demo will NOT capture real network traffic
- ✓ API still works, but with simulated data only

**For testing/development without privileges:**
Use the environment variable to explicitly enable synthetic mode:
```bash
export RF_CLASSIFIER_USE_SYNTHETIC=1
python3 run.py
```

---

## Quick Start

### 1. Start the Server (with root privileges for live capture)

#### Option A: Direct (Live packet capture enabled)
```bash
cd /Users/ziauddin/Documents/GitHub/CyberMind/backend_flask
source ../.venv/bin/activate
sudo python3 run.py  # ← ROOT REQUIRED
```

#### Option B: Using startup script (Live packet capture enabled)
```bash
cd /Users/ziauddin/Documents/GitHub/CyberMind
sudo bash start_all.sh  # ← ROOT REQUIRED for packet capture
```

Server runs on `http://localhost:5000`

### 2. Test the API
In another terminal:
```bash
python3 test_api.py
```

## Core Features

### 🔐 **1. Cross-Platform Firewall Management**
- **Automatic OS Detection**: Windows (netsh), Linux (ufw/iptables), macOS (pf)
- **IP Blocking**: Block/unblock IPs at the OS firewall level
- **Network Isolation**: Emergency network lockdown (kill switch)
- **Status Monitoring**: Real-time firewall status

**Endpoints:**
- `GET /api/firewall/status` - Check firewall status
- `POST /api/blacklist/ip` - Block an IP address

### 📱 **2. Device Management** ⭐ NEW
Manage network devices in your inventory - add, delete, update, and search devices.

**Endpoints:**
```
GET    /api/devices/list           # List all devices
GET    /api/devices/status         # Get device inventory status
POST   /api/devices/add            # Add new device
GET    /api/devices/<device_id>    # Get device details
PUT    /api/devices/<device_id>    # Update device
DELETE /api/devices/<device_id>    # Delete device
GET    /api/devices/search?q=      # Search devices by name/IP
```

**Example - Add Device:**
```bash
curl -X POST http://localhost:5000/api/devices/add \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production-Server-01",
    "ip_address": "192.168.1.100",
    "mac_address": "00:1A:2B:3C:4D:5E",
    "device_type": "server",
    "os": "Linux",
    "tags": ["critical", "production"]
  }'
```

### 🍯 **3. Honeypot & File Handling** ⭐ NEW
Capture and manage attack payloads with comprehensive file storage and analysis.

**Endpoints:**
```
GET    /api/honeypot/files              # List all captures
GET    /api/honeypot/files/<id>         # Download specific capture
DELETE /api/honeypot/files/<id>         # Delete capture
GET    /api/honeypot/files/export       # Export captures (json/csv)
GET    /api/honeypot/summary            # Threat summary from captures
POST   /api/honeypot/cleanup            # Clean old captures (30+ days)
```

**Example - Get Threat Summary:**
```bash
curl http://localhost:5000/api/honeypot/summary
```

Response:
```json
{
  "total_captures": 42,
  "unique_ips": 15,
  "threat_types": {"sql_injection": 18, "port_scan": 24},
  "top_attackers": [
    {"ip": "203.0.113.50", "count": 12}
  ]
}
```

### ⚡ **4. One-Click Emergency Remediation** ⭐ NEW
Instantly block threats and isolate networks with a single API call.

**Endpoint:**
```
POST /api/remediation/one-click
```

**Example - Block Critical Threat:**
```bash
curl -X POST http://localhost:5000/api/remediation/one-click \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "threat_ip": "203.0.113.50",
    "threat_type": "c2_communication",
    "severity": "critical"
  }'
```

Response:
```json
{
  "success": true,
  "message": "Emergency remediation activated",
  "threat_ip": "203.0.113.50",
  "actions_taken": {
    "ip_blocked": true,
    "network_isolated": true,
    "alert_escalated": true
  }
}
```

### 🛡️ **5. Network Monitoring & Fleet Management**
Real-time asset discovery and health monitoring.

**Endpoints:**
```
GET  /api/fleet/status          # Fleet status
POST /api/fleet/ping            # Ping device
POST /api/fleet/ping_sweep      # Scan network
GET  /api/fleet/connections    # Network connections
POST /api/fleet/register_asset # Register asset
POST /api/fleet/monitor_assets # Monitor all assets
GET  /api/fleet/anomalies      # Detect anomalies
```

### 🔍 **6. Threat Analysis & Response**
Automated threat evaluation and incident management.

**Endpoints:**
```
POST /api/remediation/evaluate_threat      # Evaluate threat
GET  /api/remediation/status               # Remediation status
GET  /api/remediation/incidents            # List incidents
POST /api/remediation/manual_response      # Manual response
POST /api/remediation/close_incident       # Close incident
```

### 🎯 **7. Phishing & Malware Detection**
Email and URL threat analysis.

**Endpoints:**
```
POST /api/phishing/check_url        # Check URL reputation
POST /api/phishing/analyze_email   # Analyze email
GET  /api/phishing/statistics      # Phishing stats
```

### 🤖 **8. AI Traffic Translation**
LLM-powered threat analysis (ready for OpenAI/Anthropic integration).

**Endpoints:**
```
POST /api/traffic/translate   # Translate network traffic
POST /api/traffic/analyze     # Analyze with AI
```

## Project Structure

```
backend_flask/
├── app/
│   ├── core/
│   │   └── firewall_manager.py         # OS-specific firewall control
│   ├── services/
│   │   ├── device_manager.py           # ⭐ Device inventory management
│   │   ├── honeypot_file_handler.py    # ⭐ Capture file management
│   │   ├── fleet_monitor.py            # Network monitoring
│   │   ├── remediation_playbook.py     # Automated responses
│   │   ├── network_honeypot.py         # Deception technology
│   │   ├── phishing_sandbox.py         # Email/URL analysis
│   │   ├── ai_translator.py            # LLM integration
│   │   ├── kill_switch.py              # Emergency isolation
│   │   ├── ip_blacklist_service.py     # IP blocking
│   │   └── rogue_asset_detector.py     # Asset discovery
│   ├── api/
│   │   └── routes.py                   # 50+ REST endpoints
│   └── __init__.py                     # Flask app factory
├── config/
│   └── config.py                       # Environment configuration
├── data/
│   ├── devices.json                    # Device inventory (persistent)
│   ├── blocked_ips.json                # Blocked IP records (persistent)
│   └── honeypot_captures/              # Captured payloads
├── logs/
│   └── cybermind.log                   # Security audit log
├── run.py                              # Application entry point
├── test_api.py                         # 50+ test cases
└── requirements.txt                    # Python dependencies
```

## Configuration

Edit `config/config.py` for:
- Flask environment (development/production/testing)
- CORS settings
- Logging configuration
- API authentication
- Firewall permissions

## API Authentication

All `POST` endpoints require Bearer token authentication:

```bash
curl -X POST http://localhost:5000/api/devices/add \
  -H "Authorization: Bearer your-token-here" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

## Data Storage

- **Devices**: `data/devices.json` (persistent device inventory)
- **Blocked IPs**: `data/blocked_ips.json` (firewall blacklist records)
- **Honeypot Captures**: `data/honeypot_captures/` (attack payloads)
- **Logs**: `logs/cybermind.log` (security audit trail)

## Common Use Cases

### Use Case 1: Add & Monitor Devices
```bash
# Add device
curl -X POST http://localhost:5000/api/devices/add ...

# List all devices
curl http://localhost:5000/api/devices/list

# Get device status
curl http://localhost:5000/api/devices/status
```

### Use Case 2: Block Malicious IP (One-Click)
```bash
curl -X POST http://localhost:5000/api/remediation/one-click \
  -H "Authorization: Bearer token" \
  -d '{
    "threat_ip": "203.0.113.50",
    "threat_type": "botnet",
    "severity": "critical"
  }'
```

### Use Case 3: Review Honeypot Attacks
```bash
# Get threat summary
curl http://localhost:5000/api/honeypot/summary

# List captures from specific IP
curl http://localhost:5000/api/honeypot/files?limit=50

# Export for analysis
curl "http://localhost:5000/api/honeypot/files/export?format=csv"
```

### Use Case 4: Automated Threat Response
```bash
# Evaluate threat
curl -X POST http://localhost:5000/api/remediation/evaluate_threat \
  -H "Authorization: Bearer token" \
  -d '{
    "threat_type": "port_scan",
    "source_ip": "10.0.0.50",
    "failed_auth_attempts": 5
  }'
```

## Testing

### Run Full Test Suite
```bash
python3 test_api.py
```

### Test Single Endpoint
```bash
# Device management
curl http://localhost:5000/api/devices/list

# Firewall status
curl http://localhost:5000/api/firewall/status

# Honeypot summary
curl http://localhost:5000/api/honeypot/summary
```

### Run pytest
```bash
pytest test_api.py -v
```

## Requirements

- Python 3.8+
- Flask 2.3.3
- Flask-CORS
- python-dotenv

Install: `pip install -r requirements.txt`

## Environment Variables

Create `.env` file:
```
FLASK_ENV=development
FLASK_DEBUG=true
API_VERSION=1.0.0
LOG_LEVEL=INFO
```

## Security Notes

- All sensitive endpoints require authentication
- Firewall operations may require elevated privileges (sudo on Linux/macOS)
- Audit logs stored in `logs/cybermind.log`
- Device/honeypot data persisted to JSON files
- Input validation on all endpoints

## Troubleshooting

**Port 5000 already in use:**
```bash
lsof -i :5000
kill -9 <PID>
```

**Permission denied (firewall operations):**
```bash
# Linux/macOS - may need sudo for actual blocking
sudo python3 run.py
```

**Import errors:**
```bash
source ../.venv/bin/activate
pip install -r requirements.txt
```

## Support & Documentation

- API Reference: Test with `python3 test_api.py` for endpoint examples
- Code Docstrings: Each service has detailed docstrings
- Logs: Check `logs/cybermind.log` for detailed operation logs

## Version
**CyberMind Sentinel v1.0.0** - Production Ready

Last Updated: April 17, 2026
