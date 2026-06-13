# CyberMind Sentinel

> **Enterprise-Grade Security Platform for SMEs**  
> A comprehensive security management and device monitoring system designed to protect small and medium-sized enterprises from cyber threats.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-brightgreen)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Email Setup](#email-setup)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**CyberMind Sentinel** is an AI-powered autonomous cybersecurity platform delivering real-time threat detection, intelligent log analysis, and automated defense mechanisms. It provides SMEs with tools to:
- Manage user authentication and authorization securely
- Monitor and manage connected devices
- Receive security alerts and notifications
- Maintain audit logs of security events
- Detect threats using OS-specific log ingestion and AI

---

## 🏗️ Architecture

The platform uses a modern 3-tier architecture to separate concerns:

1. **Frontend (Port 5173)**
   - Built with **Vite**, **Tailwind CSS**, and **Vanilla JS/React**.
   - Provides an interactive dashboard and real-time security event feed.

2. **Authentication Backend (Port 3001)**
   - Built with **Node.js** and **Express.js**.
   - Handles secure registration, JWT token generation, password hashing (bcrypt), and email verification.

3. **Operations & AI Backend (Port 5000)**
   - Built with **Python** and **Flask/FastAPI**.
   - Handles active defense mechanisms, live packet captures, threat analysis (via Google Gemini AI), and device honeypots.

---

## ✨ Features

### 🔍 Real-Time Log Monitoring
- **Windows**: Event Viewer integration (Security, System, Application logs)
- **Linux**: Syslog, auth.log, audit logs monitoring
- **macOS**: System logs and security event monitoring
- Automatic OS-specific log source detection

### 🤖 AI-Powered Threat Analysis
- AI for intelligent threat assessment
- Plain-English threat summaries
- Automatic severity scoring (Critical → Low)
- Contextual remediation recommendations

### 🛡️ Active Defense Mechanisms
- **Kill Switch**: File Integrity Monitoring (FIM) for ransomware detection
- **Honeypot Manager**: Decoy systems to trap attackers
- Adaptive protection based on OS

### 🔐 Authentication & User Management
- **Secure Registration** - Create accounts with email verification
- **Login System** - Session-based authentication with JWT tokens
- **Password Recovery** - Secure password reset flow via email
- **Profile Management** - Update user information and preferences

---

## 📁 Project Structure

```
CyberMind/
├── backend/                       # Node.js Auth & User Backend (Port 3001)
│   ├── server.js                  # Express server & API routes
│   ├── email.js                   # Email service configuration
│   ├── package.json               # Node.js dependencies
│   └── users.json                 # User database (created at runtime)
│
├── backend_flask/                 # Python Ops & Security Backend (Port 5000)
│   ├── app/                       # Flask application
│   ├── run.py                     # Entry point for Flask backend
│   └── requirements.txt           # Python dependencies
│
├── frontend/                      # Vite Frontend (Port 5173)
│   ├── index.html                 # Frontend entry point
│   ├── vite.config.js             # Vite configuration
│   └── package.json               # Frontend dependencies
│
├── start_all.sh                   # Script to start all 3 services
├── stop_servers.sh                # Script to kill all 3 services
└── README.md                      # This documentation
```

---

## 📦 Prerequisites

Ensure you have the following installed before proceeding:

- **Node.js** (v18.0.0 or higher)
- **Python** (3.10 or higher)
- **npm** (Comes with Node.js)
- **Git**

Check your versions:
```bash
node --version
python3 --version
```

---

## 🚀 Installation

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/CyberMind.git
cd CyberMind
```

2. **Install Node Backend Dependencies**
```bash
cd backend
npm install
cd ..
```

3. **Install Python Backend Dependencies**
```bash
cd backend_flask
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements.txt
cd ..
```

4. **Install Frontend Dependencies**
```bash
cd frontend
npm install
cd ..
```

---

## 🎮 Running the Application

### The Easy Way (Automated Script)

To start the entire application stack (Node.js backend, Python backend, and Vite frontend):

```bash
./start_all.sh
```

**⚠️ Live Packet Capture:** If you want the Python backend to perform live network packet scanning (via Scapy), it requires elevated privileges. Run the script with `sudo`:

```bash
sudo bash start_all.sh
```

*(Without sudo, the packet scanner silently falls back to synthetic simulation).*

To stop all servers:
```bash
./stop_servers.sh
```

### Manual Startup (Development)

If you prefer to start each component in a separate terminal:

**Terminal 1 - Auth Backend (Node.js)**
```bash
cd backend
npm start
```

**Terminal 2 - Ops Backend (Python)**
```bash
cd backend_flask
source ../.venv/bin/activate
python3 run.py
```

**Terminal 3 - Frontend (Vite)**
```bash
cd frontend
npm run dev
```

Then open your browser to: **http://localhost:5173**

---

## 🔌 API Endpoints

### Authentication (Node.js - Port 3001)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create new account |
| POST | `/api/auth/login` | User login |
| GET | `/api/auth/verify` | Check session validity |
| POST | `/api/auth/logout` | End session |

### Security Ops (Python - Port 5000)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | System status & detected OS |
| GET | `/api/logs` | Fetch security logs |
| GET | `/api/devices/list` | List all monitored devices |
| GET | `/api/firewall/status` | Check firewall status |
| GET | `/api/honeypot/summary` | Honeypot metrics |

---

## 🛡️ Security Features

- **Password Hashing** - Bcrypt with 10 salt rounds
- **JWT Tokens** - Stateless authentication
- **HTTPS Ready** - Supports secure connections
- **CORS Protection** - Restricted origin access
- **Input Validation** - Sanitized user inputs

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the LICENSE file for details.
You are free to use this project for personal, commercial, and open-source purposes.

<div align="center">

**[⬆ Back to Top](#cybermind-sentinel)**

Made with ❤️ for cybersecurity professionals

</div>
