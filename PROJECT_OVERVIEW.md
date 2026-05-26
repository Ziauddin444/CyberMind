# CyberMind Sentinel - Complete Project Overview

## Project Summary
**CyberMind Sentinel** is a lightweight, passive out-of-band IDS for SMEs. A 2-tier architecture combining a Vite frontend dashboard with a Python Flask operations backend featuring signature-based detection, ML-powered classification (NSL-KDD), and automated firewall integration.

**Status**: Active | Version: 1.0.0 | License: MIT | **Architecture**: 2-Tier (Passive/Out-of-Band)

---

## 🏗️ Architecture

### 2-Tier Lightweight IDS (Out-of-Band / Passive)
```
┌──────────────────────────────────────────────────────────┐
│  FRONTEND (Vite + Vanilla JS + Tailwind CSS)            │
│  Port: 5173 (dev) | Dashboard + Analysis UI             │
└────────────────┬─────────────────────────────────────────┘
                 │ HTTP/REST
                 ▼
        ┌─────────────────────┐        ┌─────────────────┐
        │ Flask Operations    │        │  Data Storage   │
        │  Backend (Port 5000)│────────│ (SQLite + JSON) │
        └─────────────────────┘        └─────────────────┘
                 │
         (Packet Mirror / SPAN Port)
                 │
        Real Network Traffic ◄─────────── Zero Inline Latency
        (monitored, analyzed, logged)

Core IDS Components:
  ✓ Packet Scanner (Scapy) - Live capture & stateless analysis
  ✓ IDS Engine - 50+ attack signatures
  ✓ RF Classifier - NSL-KDD ML model (125K+ training samples)
  ✓ Firewall Manager - OS-level remediation
  ✓ IP Blacklist - Dynamic blocking
  ✓ Honeypot Network - Threat capture
```

---

## 📂 Project Structure

### Root Files
- **README.md** - Main project documentation
- **CAPSTONE_NSL_KDD_IMPLEMENTATION.md** - ML dataset specification (NSL-KDD)
- **PROJECT_OVERVIEW.md** - This file
- **start_all.sh** - Startup Flask backend + instruct on frontend
- **stop_servers.sh** - Shutdown script

### 1. Frontend (`/frontend/`)
**Stack**: Vite v6.2.0 + Vanilla JS + Tailwind CSS + Font Awesome 6

**Key Files**:
- `index.html` - Main HTML entry point
- `src/js/app.js` - Application logic (dashboard, theme, UI management)
- `src/js/api.js` - Flask backend API client
- `src/css/styles.css` - Styling + light/dark theme
- `vite.config.js` - Build configuration
- `package.json` - Vite dev dependencies

**Features**:
- Real-time threat dashboard (via REST polling)
- Device inventory management
- Live threat activity feed
- Scan job management (start, monitor, view results)
- Light/dark theme toggle
- Responsive security-focused UI
- 30+ mock attack scenarios for demo

### 2. Flask Backend (`/backend_flask/`) — Core IDS Engine
**Stack**: Flask 2.3.3 + scikit-learn + Scapy + SQLite
   - Nmap, masscan, nikto, zmap, shodan
   - SQLmap, UNION injection, XSS, LFI
   - Hydra, medusa, credential stuffing
   - Metasploit, shellcode, buffer overflow
   - Netcat, reverse shell, mimikatz, Cobalt Strike, PowerShell

2. **rf_classifier.py** - Random Forest ML model (NSL-KDD dataset, 120 trees, 41 features)
   - Trained on 125,973 real-world network samples
   - Predicts: safe, ddos, port_scan, brute_force, malware_c2, anomaly

3. **nsl_kdd_loader.py** - NSL-KDD dataset auto-download & preprocessing
   - 22,544 test samples
   - 41 extracted network attributes
   - Automatic feature normalization

4. **packet_scanner.py** - Scapy-based live packet capture & analysis
5. **network_honeypot.py** - Honeypot service to attract & log attacks
6. **firewall_manager.py** (core/) - OS firewall rule management
7. **ip_blacklist_service.py** - IP reputation & blocking
8. **device_manager.py** - Managed device tracking & health checks
9. **fleet_monitor.py** - Monitor multiple devices in real-time
10. **rogue_asset_detector.py** - Detect unauthorized devices on network
11. **kill_switch.py** - Emergency network isolation
12. **phishing_sandbox.py** - Safe URL/email analysis
13. **ai_translator.py** - Log translation & contextual analysis
14. **remediation_playbook.py** - Automated response playbooks
15. **honeypot_file_handler.py** - Malware sample capture & analysis

**Configuration** (`config/`):
- `config.py` - Flask app config (Dev/Prod/Test modes, CORS, logging, security settings)

**Data Files**:
- `data/nsl_kdd/` - NSL-KDD training/test CSV files (125K+ training samples)
- `data/honeypot_captures/` - Captured malicious traffic samples
- `data/blocked_ips.json` - IP blacklist
- `data/devices.json` - Device inventory
- `logs/cybermind.log` - Application logs
- `data/cybermind_logs.db` - SQLite scan/threat logs (thread-safe)

**Key Endpoints**:
- `POST /api/analyze` - Submit packet/payload for IDS analysis
- `GET /api/scan/live` - Live packet capture & analysis
- `GET /api/stats` - Threat statistics & dashboard data
- `POST /api/blacklist` - Add/remove IPs from blacklist
- `GET /api/devices` - Fleet device status
- `POST /api/remediation` - Trigger automated response
- `GET /api/logs` - Threat log history

**Advanced Features**:
- **ML-based Detection**: Random Forest trained on NSL-KDD (real-world dataset)
- **Signature Matching**: 50+ hardcoded attack signatures
- **Live Packet Analysis**: Requires root/admin; falls back to synthetic if unprivileged
- **Role-Based Access**: JWT tokens with role levels (viewer → analyst → admin)
- **SQLite Audit Logging**: Thread-safe scan results & traffic counts
- **NSL-KDD Integration**: Automatic dataset download on first run

---

## 🔧 Tech Stack Summary

| Layer | Technologies |
|-------|--------------|
| **Frontend** | Vite 6.2.0, Vanilla JS, Tailwind CSS, Font Awesome 6 |
| **Operations Backend** | Python 3.9+, Flask 2.3.3, scikit-learn, Scapy |
| **Data** | JSON files, SQLite 3, NSL-KDD CSV dataset |
| **IDS/ML** | Signature engine (50+ patterns), Random Forest (120 trees), NSL-KDD trained |
| **Security Integration** | OS firewall injection, IP blacklist, honeypot capture |

---

## 🚀 How to Run

### Prerequisites
- Node.js 16+ (for /backend)
- Python 3.9+ (for /backend_flask)
- Node.js 16+ (for /frontend, Vite dev server only)
- macOS/Linux (for Scapy/firewall features; Windows via WSL)
- Virtual environment (.venv in root)

### Quick Start
```bash
# Activate Python venv
source .venv/bin/activate

# Start Flask backend
cd backend_flask && python run.py

# In a new terminal, start frontend
cd frontend && npm install && npm run dev

# Access:
# - Frontend:   http://localhost:5173
# - API:        http://localhost:5000/api
```

### Individual Services
```bash
# Flask Ops Backend (Port 5000)
cd backend_flask && python run.py

# With root for live packet capture:
sudo python run.py

# Frontend Dev Server (Port 5173)
cd frontend && npm run dev

---

## 🎯 Key Features by Domain

### Authentication & Authorization
✓ User registration with email verification  
✓ Secure login with JWT tokens  
✓ Password reset via email  
✓ RBAC (4-tier: viewer → analyst → admin → super-admin)
✓ JWT token validation (from X-User-Role header)
✓ No login required for core IDS endpoints (`/api/analyze`, `/api/scan/*`)
✓ Auth required for sensitive operations (blacklist, remediation)s)  
✓ ML-based classification (Random Forest + NSL-KDD)  
✓ Live packet capture & analysis  
✓ Honeypot network simulation  
✓ Real-time threat severity scoring  

### Network Defense
✓ Firewall rule management  
✓ IP blacklist/whitelist management  
✓ Rogue device detection  
✓ Kill-switch for emergency isolation  
✓ Phishing URL sandbox analysis  

### Device Management
✓ Device inventory & health tracking  
✓ Fleet-wide monitoring  
✓ Device configuration management  
✓ Alert aggregation & routing  

### Operational Intelligence
✓ Audit logging (SQLite)  
✓ Attack trend analytics  
✓ Remediation playbook automation  
✓ Log aggregation & translation  

---

## 📊 Data Models

### User (Node.js)
- id, username, email, passwordHash, role, createdAt, lastLogin, preferences

### Device (Both Backends)
- id, name, type, ip, mac, status, threatLevel, lastSeen, owner

### Threat Log (Flask SQLite)
- id, timestamp, label, severity, confidence, packet_count, capture_mode, threat_detected

### NSL-KDD Dataset (41 Features)
Network security attributes including:
- Duration, protocol type, service, flag
- src_bytes, dst_bytes, land, wrong_fragment
- urgent, ack, rst, syn, fin flags
- And 26+ more network indicators
- Classification: {normal, dos, probe, r2l, u2r}

---

## ⚙️ Environment Variables

Key .env vars for production (backend_flask):
- `FLASK_ENV` - development/production/testing
- `SECRET_KEY` - Flask session encryption key (change from default in prod)
- `RF_CLASSIFIER_USE_SYNTHETIC` - 1 to skip NSL-KDD download (faster dev)
- `MAIL_SERVER` - SMTP server for email
- `MAIL_PORT` - SMTP port
- `MAIL_USERNAME` - Email account username
- `MAIL_PASSWORD` - Email account password

---

## 🔒 Security Considerations

### Production Checklist
✓ Set real `SECRET_KEY` env var (not default)  
✓ Enable `SESSION_COOKIE_SECURE=True` with HTTPS  
✓ Restrict CORS to real domain  
✓ Run Flask with root for packet capture (or use unprivileged sandbox)  
✓ Enable SQLite WAL mode for concurrent access  
✓ Rotate JWT secret regularly  
✓ Configure rate limiting on auth endpoints  
✓ Enable HTTPS/TLS for all connections  

### Root Privileges
- Packet capture (Scapy) requires root/admin
- Firewall rule injection requires elevated permissions
- Falls back to synthetic data if unprivileged (demo mode)

### Data Privacy
- Passwords hashed with bcrypt (10 rounds, industry standard)
- Sensitive files in .gitignore (users.json, .env)
- Email verification prevents spam registration
- SQLite audit logs include all security events

---

## 📝 Development Notes

### Port Management
- **Port Fallback**: run.py auto-falls back to 5001, 5002, 5003 if 5000 is busy
- **Root Warning**: Warns on startup if not running with elevated privileges for packet capture
- **Synthetic Fallback**: NSL-KDD download failure doesn't crash; uses synthetic data instead

### Concurrency & Thread Safety
- SQLite access guarded by threading locks (_DB_LOCK)
- Scan logging thread-safe with context manager pattern
- Connection reuse avoided; new per-operation

### Demo Features
- **Mock Attacks**: Frontend includes 30+ mock attack scenarios for live demo
- **Dev Login Bypass**: Set ALLOW_UNVERIFIED_LOGIN=true in backend for quick testing
- **Synthetic Data**: Both IDS and RF classifier support synthetic generation for testing

### Capstone NSL-KDD Implementation
- Real-world dataset: 125,973 training samples
- Automatic download from GitHub mirror on first run
- 41 network features extracted and normalized
- 5 attack categories mapped to 6-class system
- Production model: ~5MB serialized Random Forest
- Training time: 2-5 minutes on typical hardware

### Common Issues & Solutions
| Issue | Solution |
|-------|----------|
| Port 3001/5000 busy | Change PORT in backend/server.js or use fallback ports |
| Packet capture fails (non-root) | Run with `sudo python run.py` or use synthetic mode |
| NSL-KDD download fails | Set `RF_CLASSIFIER_USE_SYNTHETIC=1` env var |
| Email not sending | Configure SMTP env vars (MAIL_SERVER, MAIL_PORT, etc.) |
| CORS errors | Check CORS_ORIGINS in backend_flask/config/config.py |

---

## 🎓 Capstone Requirements

✅ **NSL-KDD Dataset**: Real, industry-standard cybersecurity dataset (125K+ samples)  
✅ **Random Forest Classifier**: Trained on authentic network traffic patterns  
✅ **41 Network Features**: Full NSL-KDD feature set with normalization  
✅ **5 Attack Categories**: DoS, Probe, R2L, U2R, Normal traffic  
✅ **Production Integration**: Automatic download, caching, fallback strategy  

---

## 💡 Key Highlights

🔴 **Real Threat Detection**: 50+ signature patterns + ML classifier trained on 125K samples  
🔴 **Live Network Analysis**: Packet capture with root privileges (Scapy)  
🔴 **Enterprise Ready**: Role-based access, audit logs, playbook automation  
🔴 **Modern Stack**: Vite frontend, dual-backend architecture, RESTful APIs  
🔴 **Extensible Design**: Modular service-oriented architecture  
🔴 **Demo-Friendly**: 30+ mock attack scenarios, synthetic fallback mode  

---

## 📞 Support & Troubleshooting

For issues or questions:
1. Check the README.md for basic setup
2. Review CAPSTONE_NSL_KDD_IMPLEMENTATION.md for ML details
3. Check application logs: `backend_flask/logs/cybermind.log`
4. Check threat database: `backend_flask/data/cybermind_logs.db` (SQLite)
5. Verify Python environment: `source .venv/bin/activate`

---

**Last Updated**: May 24, 2026  
**Version**: 1.0.0  
**Status**: Production Ready
