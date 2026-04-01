<<<<<<< HEAD
# CyberMind Sentinel

An AI-powered autonomous cybersecurity platform delivering real-time threat detection, intelligent log analysis, and automated defense mechanisms.

## 🌍 Cross-Platform Support

CyberMind Sentinel is **fully supported on Windows, Linux, and macOS**. The application automatically detects your operating system and configures appropriate defaults.

### Platform-Specific Guides

Choose your operating system for detailed setup instructions:

- **[🪟 Windows Setup Guide](WINDOWS_SETUP.md)** - Windows 10/11 (Recommended for enterprise)
- **[🐧 Linux Setup Guide](LINUX_SETUP.md)** - Ubuntu, Debian, CentOS, Fedora
- **[🍎 macOS Setup Guide](MACOS_SETUP.md)** - macOS 10.15+

---

## 📋 Features

### 🔍 Real-Time Log Monitoring
- **Windows**: Event Viewer integration (Security, System, Application logs)
- **Linux**: Syslog, auth.log, audit logs monitoring
- **macOS**: System logs and security event monitoring
- Automatic OS-specific log source detection

### 🤖 AI-Powered Threat Analysis
- Google Gemini AI for intelligent threat assessment
- Plain-English threat summaries
- Automatic severity scoring (Critical → Low)
- Contextual remediation recommendations

### 🛡️ Active Defense Mechanisms
- **Kill Switch**: File Integrity Monitoring (FIM) for ransomware detection
- **Honeypot Manager**: Decoy systems to trap attackers
- Cross-platform file monitoring with Watchdog
- Adaptive protection based on OS

### 📊 Interactive Dashboard
- Real-time security event feed
- Threat level indicators and statistics
- Phishing URL sandbox
- Defense status monitoring
- Mobile-responsive design

### 🔌 REST API + WebSocket
- Complete REST API for integrations
- Real-time WebSocket notifications
- Interactive API documentation (Swagger/ReDoc)

---

## 🚀 Quick Start

### Automatic OS Detection

The application automatically detects your operating system and configures:
- ✅ Protected directories (OS-specific paths)
- ✅ Log sources (Event Viewer, syslog, system logs)
- ✅ Security monitoring patterns
- ✅ System paths and configuration

### Universal Commands

```bash
# Backend (works on all platforms)
cd cybermind-backend
python3 -m venv venv
source venv/bin/activate

# Frontend (works on all platforms)
cd cybermind-frontend
npm install
npm run dev
```

> 📌 **For detailed platform-specific setup, see the guides above**

---

## 📁 Project Structure

```
CyberMind/
├── cybermind-backend/              # Python FastAPI backend
│   ├── ingest/                     # Log ingestion (auto-detects OS)
│   ├── ai_engine/                  # LLM threat analysis (Gemini)
│   ├── defense/                    # Active defense mechanisms
│   ├── api/                        # REST API routes
│   ├── utils/
│   │   ├── config.py              # Cross-platform configuration
│   │   ├── os_detector.py         # 🆕 OS detection & paths
│   │   ├── logger.py              # Logging setup
│   │   └── models.py              # Data models
│   ├── main.py                    # FastAPI entry point
│   └── requirements.txt           # Python dependencies
│
├── cybermind-frontend/             # Next.js React frontend
│   ├── src/
│   │   ├── app/                   # Next.js pages
│   │   ├── components/            # React components
│   │   └── utils/                 # API utilities
│   ├── package.json              # Node dependencies
│   └── tsconfig.json             # TypeScript config
│
├── WINDOWS_SETUP.md               # 🆕 Windows installation guide
├── LINUX_SETUP.md                 # 🆕 Linux installation guide
├── MACOS_SETUP.md                 # 🆕 macOS installation guide
└── README.md                       # This file
```

---

## 🔧 Configuration

### Automatic OS-Specific Defaults

The application uses intelligent defaults based on your OS:

#### Windows
```
Protected Directories: C:\Users, C:\Documents, C:\Desktop, %APPDATA%
Log Sources: Security, System, Application, PowerShell/Operational
```

#### Linux
```
Protected Directories: /home, /root, ~/.*, /etc
Log Sources: /var/log/auth.log, /var/log/syslog, /var/log/audit/audit.log
```

#### macOS
```
Protected Directories: /Users, ~/Library, ~/Documents, ~/Desktop
Log Sources: /var/log/system.log, /var/log/auth.log, ~/Library/Logs
```

### Custom Configuration

Edit `cybermind-backend/.env` to customize:

```env
# Google Gemini API Configuration
OPENAI_API_KEY=your-key-here
OPENAI_MODEL=gemini-1.5-pro

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# Custom Protected Directories (leave blank for OS defaults)
# PROTECTED_DIRS=/Users,~/Documents    # macOS example
# PROTECTED_DIRS=C:\Users,C:\Documents # Windows example
# PROTECTED_DIRS=/home,/root           # Linux example
```

---

## 🔐 Security Features

### Multi-OS Threat Detection

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Event Viewer Logs | ✅ | - | - |
| Syslog Monitoring | - | ✅ | ✅ |
| File Integrity Monitoring | ✅ | ✅ | ✅ |
| Ransomware Detection | ✅ | ✅ | ✅ |
| Threat Scoring | ✅ | ✅ | ✅ |
| Automated Response | ✅ | ✅ | ✅ |

---

## 📊 API Endpoints

### Available on All Platforms

```
GET  /                          # API information
GET  /health                    # Health check
GET  /api/status               # System status & detected OS
GET  /api/logs                 # Fetch security logs
POST /api/sandbox              # Phishing URL analysis
POST /api/remediate            # Trigger defense actions
```

See full API documentation at: `http://localhost:8000/docs`

---

## 🐛 Troubleshooting

### Platform-Specific Issues

- **Windows**: See [WINDOWS_SETUP.md](WINDOWS_SETUP.md#troubleshooting)
- **Linux**: See [LINUX_SETUP.md](LINUX_SETUP.md#troubleshooting)
- **macOS**: See [MACOS_SETUP.md](MACOS_SETUP.md#troubleshooting)

### Common Issues (All Platforms)

| Issue | Solution |
|-------|----------|
| Port already in use | Change `SERVER_PORT` in `.env` or kill existing process |
| Module not found | Activate virtual environment: `source venv/bin/activate` |
| API key not working | Verify `OPENAI_API_KEY` in `.env` and Gemini API access |
| File monitoring not working | Run with administrator/sudo privileges |

---

## 📈 Performance Considerations

### Recommended System Requirements

| Component | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| CPU | 4 cores | 4 cores | 4 cores |
| RAM | 8GB | 8GB | 8GB |
| Storage | 50GB | 50GB | 50GB |
| Python | 3.10+ | 3.10+ | 3.10+ |
| Node.js | 18+ | 18+ | 18+ |

### Optimization Tips

- Run backend on dedicated machine for production
- Use Nginx/Apache reverse proxy for frontend
- Enable log rotation for large environments
- Monitor system resources with OS tools

---

## 🔄 Deployment Options

### Development
```bash
# Terminal 1 — Start Backend
cd /Users/ziauddin/demo/backend
npm start

# Terminal 2 — Start Frontend
cd /Users/ziauddin/demo/frontend
npm run dev
```

### Production
- See **[Windows Guide - Production](WINDOWS_SETUP.md)**
- See **[Linux Guide - Production](LINUX_SETUP.md)**
- See **[macOS Guide - Production](MACOS_SETUP.md)**

---

## 📚 Technology Stack

### Backend
- **Framework**: FastAPI (Python web framework)
- **AI**: Google Generative AI (Gemini API)
- **File Monitoring**: Watchdog
- **System Access**: psutil
- **Server**: Uvicorn ASGI

### Frontend
- **Framework**: Next.js 14 (React)
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **HTTP Client**: Axios
- **Language**: TypeScript

---

## 🌐 Environment Detection

The application includes a new cross-platform environment detection system:

**File**: `cybermind-backend/utils/os_detector.py`

Features:
- Automatic OS detection (Windows, Linux, macOS)
- Platform-specific path management
- Intelligent default configurations
- Home directory expansion
- Application data directory resolution

---

## 📖 Documentation

- [Windows Setup](WINDOWS_SETUP.md) - Detailed Windows installation
- [Linux Setup](LINUX_SETUP.md) - Detailed Linux installation
- [macOS Setup](MACOS_SETUP.md) - Detailed macOS installation
- [API Documentation](http://localhost:8000/docs) - Interactive API docs
- [Backend README](cybermind-backend/README.md) - Backend details
- [Frontend README](cybermind-frontend/README.md) - Frontend details

---

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:

- Additional log source integrations
- More AI models (OpenAI, Claude, etc.)
- Enhanced threat detection algorithms
- Mobile app development
- Cloud deployment templates
- Additional OS support (Docker containers)

---

## 📄 License

[Your License Here]

---

## 🆘 Support

For issues:
1. Consult the platform-specific guide for your OS
2. Check the troubleshooting section
3. Review application logs in `logs/cybermind.log`
4. Check API documentation at `http://localhost:8000/docs`

---

## 🚀 Features Coming Soon

- [ ] Grafana/Kibana integration
- [ ] Machine learning anomaly detection
- [ ] SIEM integration
- [ ] Mobile dashboard app
- [ ] Multi-tenant support
- [ ] Advanced reporting

---

**Last Updated**: March 16, 2026

Made with ❤️ for cybersecurity professionals

=======
**CyberMind-Sentinel**
>>>>>>> 61e5f7a6fae4399d65656dbbf864b5fb08ce1a00

Small and Medium Enterprises (SMEs) face a rising wave of sophisticated cyber threats but lack the budgets, expertise, and infrastructure of large enterprises. Traditional built-in Operating System tools, like Windows Event Viewer, generate thousands of cryptic error codes that non-technical business owners cannot interpret. The core problem is a "translation gap" where vital security telemetry is ignored due to information overload and complex terminology. The challenge is to bridge this gap by creating an affordable, user-friendly solution that automates threat detection and translates technical logs into actionable, plain-English insights. For example, instead of displaying "Event ID 4625," the system should instantly alert the user that an external IP address is actively trying to guess their administrator password.





**commands for terminal**

cd cybermind-backend
python3 -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python3 main.py
