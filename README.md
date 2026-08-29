<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/node.js-18+-green?style=flat-square&logo=nodedotjs" />
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?style=flat-square" />
</p>

# 🛡️ CyberMind Sentinel

> AI-powered Intrusion Detection System for Small-to-Medium Business networks.

CyberMind Sentinel is a lightweight network security tool that captures live network traffic, classifies it using a **Random Forest ML model**, and displays plain-English alerts through a modern dashboard — no security expertise required.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Live Packet Scanning** | Captures real network packets via Scapy and extracts header-level features |
| **AI Threat Classification** | Random Forest model trained on NSL-KDD dataset detects 6 attack types |
| **Honeypot Decoy Network** | Fake service ports (SSH, Telnet, FTP, MySQL, RDP) trap and log attackers |
| **AI Log Translation** | Ollama + Mistral translates technical alerts into plain English locally |
| **IP Blacklisting** | One-click blocking of malicious IPs through OS-native firewall |
| **IDS Signature Engine** | 30+ regex patterns detect known attack tools (nmap, hydra, sqlmap, etc.) |
| **Security Dashboard** | Real-time threat monitoring with live scan results and activity feed |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Vite)                         │
│                     http://localhost:5173                       │
│          Dashboard · Analyzer · Honeypot · Logs                │
└──────────────┬──────────────────────────┬──────────────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────┐  ┌──────────────────────────────────┐
│   Node.js Auth Backend   │  │     Flask Security Backend       │
│   http://localhost:3001   │  │     http://localhost:5000        │
│                          │  │                                  │
│  • User registration     │  │  • Packet Scanner (Scapy)        │
│  • Login / JWT tokens    │  │  • RF Classifier (scikit-learn)  │
│  • Password reset        │  │  • IDS Signature Engine          │
│                          │  │  • Honeypot (TCP listeners)      │
└──────────────────────────┘  │  • AI Translator (Ollama)        │
                              │  • IP Blacklist & Kill Switch    │
                              │  • SQLite audit logging          │
                              └──────────────────────────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────────┐
                              │     Ollama (Local AI)            │
                              │     http://localhost:11434       │
                              │     Mistral 7B model             │
                              └──────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.9+**
- **Node.js 18+**
- **macOS or Linux** (Windows not supported — requires raw socket access)

### 1. Clone the Repository

```bash
git clone https://github.com/Ziauddin444/CyberMind.git
cd CyberMind
```

### 2. Install Dependencies

```bash
# Backend (Flask) — Python dependencies
cd backend_flask
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..

# Backend (Auth) — Node.js dependencies
cd backend
npm install
cd ..

# Frontend
cd frontend
npm install
cd ..
```

### 3. Set Up Environment Variables

```bash
# Copy the example env file
cp backend_flask/.env.example backend_flask/.env
cp backend/.env.example backend/.env
```

> **Security Note:** Edit `backend_flask/.env` and set a strong `SECRET_KEY` before running in production.

### 3.5. Download the NSL-KDD Dataset

The ML model training dataset is not included in the repository (too large). Download it manually:

```bash
# Download NSL-KDD from the official source
mkdir -p backend_flask/data/nsl_kdd
curl -L "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt" \
     -o backend_flask/data/nsl_kdd/KDDTrain+.csv
curl -L "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt" \
     -o backend_flask/data/nsl_kdd/KDDTest+.csv
```

> **Note:** The AI model (`rf_model.pkl`) is auto-generated on first run if the dataset is present. If you skip this step, the system will still work using the rule-based IDS engine — only the Random Forest AI component will be disabled.

### 3.6. Default Login Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `changeme123` | Super Admin |
| `analyst` | `changeme123` | Analyst |

> ⚠️ **Change these immediately** — edit `backend/users.json` or use the Settings page after first login.



### 4. Install Ollama (AI Translation)

```bash
# macOS
brew install ollama

# Pull the Mistral model
ollama pull mistral

# Start the Ollama server
ollama serve
```

> **Note:** Ollama is optional. If not running, the AI translator falls back to a rule-based engine automatically.

### 5. Start All Services

```bash
# Option A: One-command startup (recommended)
sudo bash start_all.sh

# Option B: Manual startup (3 terminals)
# Terminal 1 — Flask backend (sudo for live packet capture)
cd backend_flask && sudo python3 run.py

# Terminal 2 — Node.js auth backend
cd backend && node server.js

# Terminal 3 — Frontend dev server
cd frontend && npm run dev
```

### 6. Open the Dashboard

```
http://localhost:5173
```

Default login: `admin` / `admin123`

---

## 🧪 Developer Sandbox (Attack Simulation Lab)

> **This is for contributors and developers only — not needed for production deployment.**

The Docker-based attack sandbox (isolated lab with a simulated attacker container) lives in a separate branch so it never pollutes the production codebase:

```bash
# Check out the developer sandbox branch
git checkout feature/docker-sandbox-lab

# Follow the instructions in docker/SANDBOX.md
```

The sandbox lets you simulate port scans, brute-force attacks, DDoS, SQL injection, and C2 beacons against a local CyberMind instance — all contained inside Docker with no risk to your real network.

---

4. Go to **Honeypot** screen to see captured attacker connections
5. Use **Block Suspicious IP** to blacklist the attacker

> A pre-built Kali attack script is included: `bash kali_attack.sh`

---

## 🔌 API Reference

### Security Operations (Flask — Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/start` | Start background packet capture + ML classification |
| `GET` | `/api/scan/status/<job_id>` | Poll scan job progress and results |
| `POST` | `/api/analyze` | Submit log text or file for IDS analysis |
| `GET` | `/api/get_latest_traffic` | Dashboard metrics: threats, scans, logs |
| `GET` | `/api/honeypot/status` | Honeypot listener status and stats |
| `GET` | `/api/honeypot/logs` | Honeypot connection log history |
| `POST` | `/api/blacklist/ip` | Block an IP address |
| `GET` | `/api/blacklist/status` | View blocked IP list |
| `POST` | `/api/kill_switch` | Trigger network isolation |
| `GET` | `/api/logs` | Scan audit log history (SQLite) |
| `GET` | `/api/ollama/status` | Check AI translation availability |

### Authentication (Node.js — Port 3001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Create new user account |
| `POST` | `/api/auth/login` | Login, returns JWT token |
| `POST` | `/api/auth/forgot-password` | Request password reset code |
| `POST` | `/api/auth/reset-password` | Reset password with code |

---

## 📁 Project Structure

```
CyberMind/
├── frontend/                    # Vite + Vanilla JS dashboard
│   ├── index.html               # Main SPA
│   ├── src/js/app.js            # Dashboard logic
│   └── src/js/api.js            # API client
│
├── backend/                     # Node.js authentication server
│   ├── server.js                # Express server + JWT auth
│   └── email.js                 # Password reset emails
│
├── backend_flask/               # Flask security operations server
│   ├── run.py                   # Entry point
│   ├── app/
│   │   ├── __init__.py          # App factory
│   │   ├── api/routes.py        # All API endpoints
│   │   ├── core/
│   │   │   └── firewall_manager.py
│   │   └── services/
│   │       ├── packet_scanner.py      # Scapy packet capture
│   │       ├── rf_classifier.py       # Random Forest ML model
│   │       ├── ids_engine.py          # Signature-based IDS
│   │       ├── ai_translator.py       # Ollama/Mistral integration
│   │       ├── network_honeypot.py    # TCP honeypot listeners
│   │       ├── ip_blacklist_service.py
│   │       ├── kill_switch.py
│   │       └── remediation_playbook.py
│   ├── data/
│   │   ├── nsl_kdd/             # ML training dataset
│   │   ├── rf_model.pkl         # Trained Random Forest model
│   │   └── rf_label_encoder.pkl # Label encoder
│   └── requirements.txt
│
├── start_all.sh                 # Launch all services
├── stop_servers.sh              # Stop all services
├── capture_demo_traffic.sh      # Capture real packets for offline analysis
└── kali_attack.sh               # Attack simulation script for Kali Linux
```

---

## 🧠 How It Works

### Threat Detection Pipeline

```
Network Traffic → Scapy Capture → Feature Extraction (8 dimensions)
                                         │
                                         ▼
                                  Random Forest Model
                                  (trained on NSL-KDD)
                                         │
                                         ▼
                              Classification Result
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
                 safe            port_scan             brute_force
                              ddos    sql_injection    malware_c2
```

**Features extracted per packet:**
1. Packet length
2. Source port
3. Destination port
4. Protocol number
5. TCP flags
6. TTL (Time-to-Live)
7. Inter-arrival time
8. Payload size

### Capture Modes

| Mode | When | Indicator |
|------|------|-----------|
| **Live** | Running with `sudo` | 🟢 Green "LIVE CAPTURE" |
| **PCAP** | `.pcap` file found in `data/` | 🔵 Blue "PCAP FILE" |
| **Simulated** | No root access, no pcap | 🟡 Yellow "SIMULATED" |

---

## 🛡️ Security Features

- **JWT Authentication** with role-based access control (viewer → analyst → admin)
- **bcrypt** password hashing (10 salt rounds)
- **SQLite audit logging** for all scan results
- **OS-native firewall** integration (macOS `pf`, Linux `iptables`)

---

## 📄 License

This project is developed as a university capstone project.

---

## 👥 Authors

Built by **Ziauddin** — Capstone 2 Project
