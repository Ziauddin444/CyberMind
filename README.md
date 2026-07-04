# CyberMind Sentinel: The "Check Engine Light" for SMB Networks

**Capstone 2 Demo Release**

CyberMind Sentinel is a lightweight, AI-driven network intrusion detection tool explicitly designed for Small-to-Medium Businesses (SMBs) without a dedicated security operations center (SOC).

---

## 🎓 Capstone 2 Scope & Grading Highlights

This project is built around the Capstone 2 scope: **port scan and DoS detection, AI-translated terminal alerting, and a low CPU / low-cost footprint.** Enterprise cloud integration, automated malware removal, and a mobile app are explicitly **out of scope** for this phase, keeping the project focused on a deployable SMB edge solution.

### 1. Ingestion Engine & Packet Scanner (Low CPU Footprint)

* **Goal:** Detect threats without the computational cost of Deep Packet Inspection (DPI).
* **Implementation:** The Scapy sniffer (`backend_flask/app/services/packet_scanner.py`) performs **stateless header extraction** — it reads only header-level metadata per packet and drops the payload immediately.
* **The Math:** A standard packet on a 1500-byte MTU network is reduced to a **150-byte** processing footprint per packet, a **90% reduction** in processing load compared to full payload inspection. At 100,000 packets/sec, this drops throughput requirements from ~143 MB/s to ~14.3 MB/s. `sniff(store=False)` keeps RAM flat regardless of capture duration, since packets are processed and discarded rather than accumulated.
* **Fault-Tolerant Demo Mode:** If the host lacks `root` privileges (required for raw packet sniffing), the engine falls back to realistic synthetic traffic generation so the system remains demonstrable in any environment.

### 2. Random Forest AI Model (Threat Classification)

* **Goal:** Accurate anomaly detection without the overhead of deep learning models.
* **Implementation:** The classifier (`backend_flask/app/services/rf_classifier.py`) is trained offline on the industry-standard **NSL-KDD dataset** (~125,973 samples, 41 features) to learn attack patterns.
* **Live Inference:** At prediction time, the model receives a real-time feature vector derived from `packet_scanner.py`. Categories detected include: Safe, Brute Force, Port Scan, DDoS, SQL Injection, and Malware C2 traffic.

### 3. AI Log Translation (Ollama + Mistral — Zero Cost)

* **Goal:** Make technical alerts understandable to a non-technical SMB owner, with no ongoing API cost.
* **Implementation:** `ai_translator.py` connects to a **locally running Ollama instance with the Mistral model**. All translation happens on-device — no internet connection or paid API key required.
* **Fallback:** If Ollama is not running, the system automatically falls back to a rule-based translator so alerting never breaks.

### 4. Honeypot (Real Socket Listeners)

* **Goal:** Capture and log reconnaissance/brute-force attempts against common attacker-targeted ports.
* **Implementation:** `network_honeypot.py` binds real TCP sockets on ports 22 (SSH), 23 (Telnet), 8080 (HTTP-Admin), and 3389 (RDP), serving decoy banners and logging connection attempts and payloads to disk.
* **Note:** Ports below 1024 (22, 23) require elevated privileges on macOS/Linux — run with `sudo` for full coverage.

### 5. Frontend & Live Alerting

* **Goal:** Provide an accessible "Check Engine Light" dashboard for non-technical users.
* **Implementation:** The dashboard (`frontend/`) polls the Flask backend and displays AI-translated, plain-English alerts in a live activity feed.

---

## 🏗️ Architecture

```
Frontend (Vite)         Port 5173   — Dashboard & live alert feed
Node.js Auth Backend    Port 3001   — Registration, login, JWT issuance
Flask Ops Backend       Port 5000   — IDS engine, RF classifier, honeypot,
                                       packet capture, AI translation, kill switch
Ollama (local)          Port 11434  — Mistral model for AI log translation
SQLite                  —           — Scan/threat audit logging
```

The frontend communicates with **two separate backends**: Node.js handles authentication and user accounts, while Flask handles all security operations (detection, classification, honeypot, blacklist, kill switch).

---

## 🚀 Running the Project

### Quick Start

```bash
# Start all three services (Node.js, Flask, Vite)
sudo bash start_all.sh
```

> `sudo` is required for live packet capture (Scapy) and for the honeypot to bind ports 22/23. Without `sudo`, the system runs fully functional in synthetic/demo mode.

**Services started:**
* Frontend: `http://localhost:5173`
* Auth API (Node.js): `http://localhost:3001/api`
* Security Ops API (Flask): `http://localhost:5000/api`

**To stop:** `bash stop_servers.sh`, or `Ctrl+C` if running in the foreground.

### Ollama Setup (one-time)

```bash
brew install ollama          # macOS
ollama pull mistral
ollama serve
```

### System Verification

A full diagnostic script is included to verify every component end-to-end:

```bash
sudo python3 diagnostic_check.py
```

This checks Flask health, Ollama/Mistral availability, AI translation, honeypot port binding, the RF classifier, live packet capture, IP blacklist, kill switch, SQLite logging, and JWT authentication — 10 components in total.

---

## 🔌 Key API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/start` | Start a background packet capture + classification job |
| GET | `/api/scan/status/<job_id>` | Poll scan job status/results |
| POST | `/api/analyze` | Submit raw log text/data for IDS analysis |
| GET | `/api/honeypot/status` | Honeypot threat summary |
| POST | `/api/blacklist/ip` | Blacklist an IP (requires auth) |
| GET | `/api/blacklist/status` | View blacklist records |
| POST | `/api/kill_switch` | Trigger network isolation |
| GET | `/api/isolation/status` | Check kill switch / isolation status |
| GET | `/api/logs` | SQLite audit log history |
| POST | `/api/ollama/test` | Test AI translation pipeline |
| GET | `/api/ollama/status` | Check Ollama/Mistral availability |
| POST | `/api/auth/login` (Node.js, port 3001) | User login, returns JWT |

---

## 🛡️ Security Features

* **JWT Authentication** — role-based access (viewer → analyst → admin → super-admin)
* **Password Hashing** — bcrypt, 10 salt rounds
* **Protected Routes** — blacklist and remediation endpoints require authentication
* **SQLite Audit Logging** — thread-safe scan/threat history
* **OS-native Firewall Integration** — cross-platform (macOS/Linux/Windows)

---

## 🚫 Out of Scope (Capstone 2)

* Enterprise cloud / SIEM integration
* Automated malware removal
* Mobile application
* Multi-tenant deployment

---

## 📦 Prerequisites

* Node.js 18+
* Python 3.9+
* Ollama (for local AI translation)
* macOS/Linux recommended for full Scapy + honeypot functionality (`sudo` required for ports < 1024 and live capture)

---

