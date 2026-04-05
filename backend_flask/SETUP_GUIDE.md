# CyberMind Sentinel Flask Backend - Complete Terminal Setup Guide

> Complete step-by-step commands to set up, configure, and run the Flask backend

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [macOS Setup](#macos-setup)
3. [Linux Setup](#linux-setup)
4. [Windows Setup](#windows-setup)
5. [Configuration](#configuration)
6. [Running the Backend](#running-the-backend)
7. [Firewall Configuration](#firewall-configuration)
8. [Testing & Verification](#testing--verification)
9. [Troubleshooting](#troubleshooting)

---

## 📦 System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **pip**: 6.0 or higher
- **Git**: (optional)
- **RAM**: 512 MB minimum
- **Disk**: 500 MB for dependencies

### Elevated Privileges Required For:
- Firewall operations (Windows: Admin, macOS/Linux: sudo)
- Binding to ports < 1024 (macOS/Linux: sudo)
- Network interface access (macOS/Linux: sudo)

---

## 🍎 macOS Setup

### Step 1: Check Python Installation
```bash
# Check if Python 3 is installed
python3 --version

# If not installed, install via Homebrew (recommended)
brew install python@3.11

# Or download from https://www.python.org/
```

### Step 2: Navigate to Backend Directory
```bash
cd CyberMind/backend_flask
```

### Step 3: Automated Setup (Recommended)
```bash
# Make setup script executable
chmod +x setup.sh

# Run automated setup
./setup.sh
```

### Step 4: Manual Setup (if preferred)
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p logs data data/honeypot_logs data/alerts config

# Copy environment template
cp .env.example .env
```

### Step 5: Edit Configuration
```bash
# Edit .env file
nano .env
# or
vim .env
# or
open -a TextEdit .env
```

### Step 6: Verify Installation
```bash
# Run setup verification
python setup.py

# Expected output: All checks should pass ✓
```

### Step 7: Start Backend Server
```bash
# Make sure venv is activated
source venv/bin/activate

# Start server (defaults to http://localhost:5000)
python run.py

# Should see: "* Running on http://0.0.0.0:5000"

# If port 5000 is already in use on macOS, use the validated fallback:
FLASK_PORT=5001 python run.py
```

### Step 8: Test in Another Terminal
```bash
# Open new terminal tab/window
# Check health
curl http://localhost:5000/api/health

# Get status
curl http://localhost:5000/api/status

# If you started the server on the fallback port:
curl http://localhost:5001/api/health
curl http://localhost:5001/api/status
```

---

## 🐧 Linux Setup

### Step 1: Install Python (Ubuntu/Debian)
```bash
# Update package manager
sudo apt update
sudo apt upgrade -y

# Install Python 3
sudo apt install -y python3 python3-pip python3-venv

# Verify installation
python3 --version
pip3 --version
```

### Step 2: Install System Dependencies
```bash
# For network tools
sudo apt install -y net-tools iputils-ping

# For firewall management
sudo apt install -y ufw

# For scapy (optional)
sudo apt install -y libpcap-dev
```

### Step 3: Navigate and Setup
```bash
cd ~/CyberMind/backend_flask
```

### Step 4: Automated Setup
```bash
# Make setup script executable
chmod +x setup.sh

# Run with elevated privileges (if binding to ports < 1024)
sudo -E ./setup.sh
```

### Step 5: Manual Setup
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir -p logs data data/honeypot_logs data/alerts config

# Copy config
cp .env.example .env
```

### Step 6: Configure Environment
```bash
# Edit configuration
nano .env

# Or use your preferred editor (gedit, vim, etc.)
```

### Step 7: Verify Setup
```bash
python setup.py
```

### Step 8: Start Backend
```bash
source venv/bin/activate
python run.py
```

### Step 9: Test (New Terminal)
```bash
# Basic health check
curl http://localhost:5000/api/health

# Get full status
curl -s http://localhost:5000/api/status | jq .

# Note: jq is useful for JSON formatting
sudo apt install -y jq
```

### Firewall Setup (Linux)

If you want to test firewall functionality locally:

```bash
# Enable UFW
sudo ufw enable

# Allow Flask port
sudo ufw allow 5000/tcp

# Allow SSH (important!)
sudo ufw allow 22/tcp

# Check status
sudo ufw status

# Test firewall blocking (in another terminal)
# This requires authorization and may need sudo
python3 -c "
from app.core.firewall_manager import FirewallManager
fm = FirewallManager()
# Note: These commands require elevated privileges
# result = fm.block_ip('192.168.1.100', 'Testing')
# print(result)
"
```

---

## 🪟 Windows Setup

### Step 1: Install Python
```powershell
# Check if Python is installed
python --version

# If not, download from https://www.python.org/
# Run installer and make sure to:
# ✓ Check "Add Python to PATH"
# ✓ Click "Install Now"

# Verify installation
python --version
pip --version
```

### Step 2: Open Command Prompt as Administrator
```
Press: Win + X
Select: Command Prompt (Admin)
```

### Step 3: Navigate to Backend
```powershell
cd C:\Users\YourUsername\Documents\CyberMind\backend_flask
# or wherever you cloned the repository
```

### Step 4: Automated Setup (Recommended)
```powershell
# Run setup script
setup.bat
```

### Step 5: Manual Setup
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir logs
mkdir data
mkdir data\honeypot_logs
mkdir data\alerts
mkdir config

# Copy environment file
copy .env.example .env
```

### Step 6: Edit Configuration
```powershell
# Edit .env file
notepad .env
# or
start .env
```

### Step 7: Verify Installation
```powershell
python setup.py
```

### Step 8: Start Backend Server
```powershell
# Activate venv
venv\Scripts\activate

# Start server
python run.py

# Should see: "* Running on http://0.0.0.0:5000"
```

### Step 9: Test from Another Terminal
```powershell
# Open new PowerShell window
# Health check
curl http://localhost:5000/api/health

# Status
curl http://localhost:5000/api/status
```

### Windows Firewall Testing

To test firewall functionality on Windows:

```powershell
# Run as Administrator
# This is already handled by the netsh commands in FirewallManager

# Check current firewall rules
netsh advfirewall firewall show rule name=all

# Check specific rule
netsh advfirewall firewall show rule name="CYBERMIND_BLOCK_*"
```

---

## ⚙️ Configuration

### Edit .env File

```bash
# macOS/Linux
nano .env
# or
vim .env

# Windows
notepad .env
```

### Key Configuration Variables

```env
# Flask Settings
FLASK_ENV=development              # Switch to 'production' for deployment
FLASK_HOST=0.0.0.0                # Binding address
FLASK_PORT=5000                   # Port number; use 5001 if macOS port 5000 is occupied
SECRET_KEY=change-this-in-prod    # Must change for production!

# LLM/AI Configuration
LLM_PROVIDER=openai               # Options: openai, anthropic, huggingface
OPENAI_API_KEY=sk_...             # Get from https://platform.openai.com/
ANTHROPIC_API_KEY=...             # Get from https://console.anthropic.com/

# Email Configuration
EMAIL_METHOD=demo                 # Options: demo, gmail, sendgrid
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=noreply@cybermind.com

# Feature Toggles
FIREWALL_ENABLED=true
HONEYPOT_ENABLED=true
MONITORING_ENABLED=true

# Logging
LOG_LEVEL=INFO                    # Options: DEBUG, INFO, WARNING, ERROR
```

---

## 🚀 Running the Backend

### Standard Startup

```bash
# Navigate to backend directory
cd backend_flask

# Activate virtual environment
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Start server
python run.py

# Expected output:
# * Running on http://0.0.0.0:5000
# * Debug mode: on
# Flask app 'run' loaded
```

### With Elevated Privileges (for Firewall)

```bash
# macOS/Linux - for firewall testing
sudo -E venv/bin/python run.py

# Windows - Must run Command Prompt as Administrator already
python run.py
```

### Development Mode with Auto-Reload

```bash
# Already enabled when FLASK_ENV=development
python run.py

# Code changes will automatically reload the server
```

### Production Mode

```bash
# Set environment
export FLASK_ENV=production  # macOS/Linux
set FLASK_ENV=production     # Windows

# Run with production WSGI server
pip install gunicorn         # Install production server
gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app()'
```

---

## 🔐 Firewall Configuration

### Testing Firewall Manager (Requires Elevated Privileges)

```bash
# macOS/Linux - with sudo
sudo python << 'EOF'
import sys
sys.path.insert(0, '.')
from app.core.firewall_manager import FirewallManager

fm = FirewallManager()
print("OS:", fm.get_status()['os'])

# Test blocking an IP (SAFE - won't ruin your network)
result = fm.block_ip('0.0.0.0', 'Test block')
print("Block result:", result)
EOF
```

### Making Script Executable (macOS/Linux)

```bash
# Make setup script executable
chmod +x setup.sh

# Run it
./setup.sh
```

### Windows UAC Elevation

```powershell
# Firewall operations automatically request elevation
# Run PowerShell as Administrator for firewall testing

# Check firewall rules
Get-NetFirewallRule -DisplayName "*CYBERMIND*"
```

---

## 🧪 Testing & Verification

### Health Checks

```bash
# Basic health check
curl http://localhost:5000/api/health

# System status
curl http://localhost:5000/api/status

# Pretty print JSON (requires jq)
curl -s http://localhost:5000/api/status | jq .
```

### Complete API Test Suite

```bash
# Test 1: Firewall status
curl http://localhost:5000/api/firewall/status

# Test 2: Honeypot status
curl http://localhost:5000/api/honeypot/status

# Test 3: Fleet monitor status
curl http://localhost:5000/api/fleet/status

# Test 4: Phishing sandbox stats
curl http://localhost:5000/api/phishing/statistics

# Test 5: Available playbooks
curl http://localhost:5000/api/remediation/playbooks

# Test 6: Check URL reputation (no auth required)
curl -X POST http://localhost:5000/api/phishing/check_url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Testing with Secure Authentication

```bash
# For endpoints requiring authorization:
# Set mock token in headers

curl -X POST http://localhost:5000/api/firewall/block_ip \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "reason": "Testing"
  }'
```

### Using Postman for API Testing

```
1. Download Postman: https://www.postman.com/
2. Create new collection
3. Import endpoints from API_REFERENCE.md
4. Test each endpoint
5. Export results for documentation
```

### Unit Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_firewall.py -v

# Run specific test
pytest tests/test_firewall.py::TestFirewallManager::test_block_ip -v
```

---

## 🔧 Troubleshooting

### Port Already in Use

```bash
# Find process using port 5000
# macOS/Linux:
lsof -i :5000

# Windows:
netstat -ano | findstr :5000

# Kill the process
# macOS/Linux:
kill -9 <PID>

# Windows (PowerShell as Admin):
taskkill /PID <PID> /F

# Or use different port
FLASK_PORT=5001 python run.py
```

### Permission Denied (Firewall Operations)

```bash
# macOS/Linux - Run with sudo:
sudo -E venv/bin/python run.py

# Firewall operations will show:
# "Requires elevated privileges. Re-run with Administrator (Windows) or sudo (Linux/macOS)."
# This is expected when firewall actions are attempted without admin/sudo privileges.

# For destructive or native-firewall actions, use an elevated shell.
# Example (macOS/Linux):
# sudo -E FLASK_PORT=5001 venv/bin/python run.py
```

### Module Not Found Errors

```bash
# Verify virtual environment is activated
# macOS/Linux:
which python  # Should show path in venv/

# Windows:
where python  # Should show path in venv\

# If not, reinstall dependencies:
pip install -r requirements.txt
```

### Cannot Connect to API

```bash
# Check if server is running
curl http://localhost:5000/api/health

# Check firewall isn't blocking port 5000
# macOS/Linux (UFW):
sudo ufw allow 5000/tcp

# Windows Firewall:
# Settings > Firewall > Allow app through > Add Python

# Check if port is correct
# Default: 5000
# Custom: Set FLASK_PORT in .env
```

### Virtual Environment Issues

```bash
# Delete and recreate if corrupted
rm -rf venv  # macOS/Linux
rmdir /s venv  # Windows

# Recreate
python3 -m venv venv  # macOS/Linux
python -m venv venv  # Windows

# Reactivate and reinstall
pip install -r requirements.txt
```

### Import Errors

```bash
# Ensure PYTHONPATH is correct
export PYTHONPATH=.  # macOS/Linux
set PYTHONPATH=.     # Windows

# Verify package structure
ls -la app/          # macOS/Linux
dir app              # Windows

# Check __init__.py files exist
ls -la app/*/__init__.py  # macOS/Linux
```

---

## 📊 Monitoring & Logs

### View Application Logs

```bash
# Real-time logs
tail -f logs/cybermind.log  # macOS/Linux
type logs/cybermind.log     # Windows (not real-time)

# On Windows for real-time:
Get-Content logs/cybermind.log -Wait

# Last 50 lines
tail -50 logs/cybermind.log  # macOS/Linux
```

### Enable Debug Logging

```bash
# Edit .env
LOG_LEVEL=DEBUG

# Restart server
# Will show very detailed logs
```

---

## 🚢 Quick Start (Copy-Paste)

### macOS/Linux - One-Command Setup

```bash
cd ~/CyberMind/backend_flask && \
python3 -m venv venv && \
source venv/bin/activate && \
pip install --upgrade pip && \
pip install -r requirements.txt && \
mkdir -p logs data data/honeypot_logs data/alerts config && \
cp .env.example .env && \
python setup.py && \
echo "✓ Setup complete! Run: python run.py"
```

### Windows - One-Command Setup

```powershell
cd C:\Users\YourUsername\Documents\CyberMind\backend_flask; `
python -m venv venv; `
venv\Scripts\activate; `
python -m pip install --upgrade pip; `
pip install -r requirements.txt; `
mkdir logs, data, data/honeypot_logs, data/alerts, config; `
copy .env.example .env; `
python setup.py; `
Write-Host "Setup complete! Run: python run.py"
```

---

## 🎯 Summary

| Task | Command |
|------|---------|
| **Setup** | `./setup.sh` (macOS/Linux) or `setup.bat` (Windows) |
| **Activate Env** | `source venv/bin/activate` or `venv\Scripts\activate` |
| **Install Deps** | `pip install -r requirements.txt` |
| **Start Server** | `python run.py` |
| **Test Health** | `curl http://localhost:5000/api/health` |
| **View Logs** | `tail -f logs/cybermind.log` |
| **Run Tests** | `pytest` |
| **Firewall Test** | `sudo python run.py` (macOS/Linux) |

---

## 📞 Getting Help

- **Server won't start**: Check port 5000 is not in use
- **Firewall errors**: Run with sudo/Admin privileges
- **Module errors**: Reinstall: `pip install -r requirements.txt`
- **Config issues**: Check .env file with correct values
- **Permission denied**: Activate virtual environment properly

---

<div align="center">

**CyberMind Sentinel - Flask Backend Successfully Set Up!**

Next: Start the React frontend in `../frontend/`

</div>
