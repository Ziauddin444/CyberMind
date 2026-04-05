#!/bin/bash
# CyberMind Sentinel - Quick Terminal Command Reference
# Copy and paste commands directly into your terminal
# Updated: April 4, 2026

# ═══════════════════════════════════════════════════════════════════════════════
# macOS/Linux SETUP - COPY & PASTE ⬇️
# ═══════════════════════════════════════════════════════════════════════════════

# 1. Navigate to backend directory
cd ~/CyberMind/backend_flask
# or if in Documents
cd ~/Documents/GitHub/CyberMind/backend_flask

# 2. AUTOMATED SETUP (Recommended)
chmod +x setup.sh && ./setup.sh

# 3. MANUAL SETUP (if preferred)
# 3a. Create virtual environment
python3 -m venv venv

# 3b. Activate it
source venv/bin/activate

# 3c. Upgrade pip
pip install --upgrade pip

# 3d. Install dependencies
pip install -r requirements.txt

# 3e. Create directories
mkdir -p logs data data/honeypot_logs data/alerts config

# 3f. Copy configuration template
cp .env.example .env

# 3g. Edit configuration (choose your editor)
nano .env              # or
vim .env               # or
open -a TextEdit .env  # or

# 3h. Verify setup
python setup.py

# 4. START BACKEND SERVER
python run.py
# Then open: http://localhost:5000/api/health
# If port 5000 is busy on macOS, the app automatically falls back to http://localhost:5001

# 5. TEST IN ANOTHER TERMINAL
curl http://localhost:5000/api/health
curl http://localhost:5000/api/status
curl http://localhost:5000/api/firewall/status

# 6. VIEW LOGS
tail -f logs/cybermind.log

# 7. TEST WITH FIREWALL (requires sudo)
sudo -E python run.py

# 8. RUN TESTS
pytest -v
pytest --cov=app tests/

# 9. STOP SERVER
# Press Ctrl+C in terminal running server

# 10. DEACTIVATE VIRTUAL ENVIRONMENT
deactivate

# ═══════════════════════════════════════════════════════════════════════════════
# Windows SETUP - COPY & PASTE ⬇️
# ═══════════════════════════════════════════════════════════════════════════════

# 1. Open Command Prompt or PowerShell as Administrator
# Press: Win + X, then select Command Prompt (Admin)

# 2. Navigate to backend directory
cd C:\Users\YourUsername\Documents\GitHub\CyberMind\backend_flask

# 3. AUTOMATED SETUP (Recommended)
setup.bat

# 4. MANUAL SETUP (if preferred)
# 4a. Create virtual environment
python -m venv venv

# 4b. Activate it
venv\Scripts\activate

# 4c. Upgrade pip
python -m pip install --upgrade pip

# 4d. Install dependencies
pip install -r requirements.txt

# 4e. Create directories
mkdir logs data data\honeypot_logs data\alerts config

# 4f. Copy configuration
copy .env.example .env

# 4g. Edit configuration
notepad .env

# 4h. Verify setup
python setup.py

# 5. START BACKEND SERVER
python run.py
# Then open: http://localhost:5000/api/health
# If port 5000 is busy on macOS, the app automatically falls back to http://localhost:5001

# 6. TEST IN ANOTHER TERMINAL
# Open new Command Prompt/PowerShell
curl http://localhost:5000/api/health
curl http://localhost:5000/api/status

# 7. RUN TESTS
pytest -v

# 8. STOP SERVER
# Press Ctrl+C in terminal running server

# 9. DEACTIVATE VIRTUAL ENVIRONMENT
venv\Scripts\deactivate

# ═══════════════════════════════════════════════════════════════════════════════
# TROUBLESHOOTING COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

# Port 5000 already in use?
# macOS/Linux:
lsof -i :5000
kill -9 <PID>

# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Use different port:
export FLASK_PORT=5001  # macOS/Linux
set FLASK_PORT=5001     # Windows

# Updated commander endpoints:
# /api/traffic/translate
# /api/assets/status
# /api/assets/discover
# /api/assets/rogue
# /api/blacklist/ip
# /api/blacklist/status
# /api/isolation/status
# /api/isolation/activate
# /api/isolation/deactivate

# Permission denied (firewall operations)?
# macOS/Linux:
sudo -E python run.py

# Virtual environment not activating?
# macOS/Linux:
python3 -m venv venv
source venv/bin/activate
# Windows:
python -m venv venv
venv\Scripts\activate

# Module import errors?
pip install -r requirements.txt --upgrade

# Check Python version:
python --version
python3 --version

# Check pip:
pip --version
pip3 --version

# List installed packages:
pip list

# ═══════════════════════════════════════════════════════════════════════════════
# API TESTING COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

# Health check
curl http://localhost:5000/api/health

# System status
curl http://localhost:5000/api/status

# Firewall status
curl http://localhost:5000/api/firewall/status

# Blacklist status
curl http://localhost:5000/api/blacklist/status

# Honeypot status
curl http://localhost:5000/api/honeypot/status

# Get honeypot logs
curl http://localhost:5000/api/honeypot/logs

# Rogue asset status
curl http://localhost:5000/api/assets/status

# Rogue asset discovery
curl -X POST http://localhost:5000/api/assets/discover \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"network_range":"192.168.1.0/24"}'

# Phishing statistics
curl http://localhost:5000/api/phishing/statistics

# Isolation status
curl http://localhost:5000/api/isolation/status

# Traffic translation
curl -X POST http://localhost:5000/api/traffic/translate \
  -H "Content-Type: application/json" \
  -d '{"telemetry":["deny src=1.2.3.4 dst=10.0.0.2 port=443"]}'

# One-click IP blacklisting (requires auth header)
curl -X POST http://localhost:5000/api/blacklist/ip \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"1.2.3.4","reason":"suspected malicious traffic"}'

# Activate kill-switch (requires auth header)
curl -X POST http://localhost:5000/api/isolation/activate \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"reason":"containment drill"}'

# Check URL (POST request)
curl -X POST http://localhost:5000/api/phishing/check_url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Analyze email (requires auth)
curl -X POST http://localhost:5000/api/phishing/analyze_email \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{
    "email_headers": {"from": "test@test.com", "subject": "Test"},
    "body": "Email body"
  }'

# Block IP (requires auth)
curl -X POST http://localhost:5000/api/firewall/block_ip \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "reason": "Testing"}'

# Activate kill switch (requires auth)
curl -X POST http://localhost:5000/api/kill_switch/activate \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Critical threat detected"}'

# Pretty print JSON (requires jq)
curl -s http://localhost:5000/api/status | jq .

# Install jq for pretty printing:
# macOS: brew install jq
# Ubuntu/Debian: sudo apt install jq
# Windows: choco install jq

# ═══════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# View .env file
# macOS/Linux:
cat .env
# Windows:
type .env

# Edit .env (choose one)
# macOS:
nano .env
vim .env
open -a TextEdit .env

# Linux:
nano .env
vim .env
gedit .env

# Windows:
notepad .env
start .env

# Set environment variables directly (temporary)
# macOS/Linux:
export FLASK_ENV=production
export FLASK_PORT=8000
export SECRET_KEY=your-secret-key

# Windows:
set FLASK_ENV=production
set FLASK_PORT=8000
set SECRET_KEY=your-secret-key

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING & MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# View logs (macOS/Linux)
tail -f logs/cybermind.log           # Real-time
tail -50 logs/cybermind.log          # Last 50 lines
head -20 logs/cybermind.log          # First 20 lines
grep "ERROR" logs/cybermind.log      # Filter errors
grep "WARNING" logs/cybermind.log    # Filter warnings

# View logs (Windows)
type logs\cybermind.log              # View entire file
Get-Content logs\cybermind.log -Wait # Real-time view (PowerShell)

# Clear logs
# macOS/Linux:
rm logs/cybermind.log

# Windows:
del logs\cybermind.log

# ═══════════════════════════════════════════════════════════════════════════════
# FIREWALL OPERATIONS (Requires elevated privileges)
# ═══════════════════════════════════════════════════════════════════════════════

# macOS/Linux - Test firewall manager
sudo python << 'EOF'
import sys
sys.path.insert(0, '.')
from app.core.firewall_manager import FirewallManager
fm = FirewallManager()
print("Status:", fm.get_status())
EOF

# Windows - Check firewall rules
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall show rule name="CYBERMIND*"

# List all firewall rules (Windows)
Get-NetFirewallRule -DisplayName "*CYBERMIND*"

# ═══════════════════════════════════════════════════════════════════════════════
# GIT COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

# Initialize git repository
git init

# Add all files
git add .

# Commit changes
git commit -m "Initial CyberMind Sentinel Flask backend commit"

# Add remote (GitHub)
git remote add origin https://github.com/yourusername/CyberMind.git

# Push to GitHub
git push -u origin main

# Check status
git status

# View commit history
git log --oneline

# ═══════════════════════════════════════════════════════════════════════════════
# CLEAN UP & RESET
# ═══════════════════════════════════════════════════════════════════════════════

# Remove virtual environment completely and start fresh
# macOS/Linux:
rm -rf venv

# Windows:
rmdir /s venv

# Clean pip cache
pip cache purge

# Reset to fresh install
python3 -m venv venv  # macOS/Linux
python -m venv venv   # Windows
source venv/bin/activate  # macOS/Linux (or venv\Scripts\activate for Windows)
pip install -r requirements.txt

# ═══════════════════════════════════════════════════════════════════════════════
# ONE-LINER SETUP COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

# Complete setup in one command (macOS/Linux):
cd backend_flask && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && mkdir -p logs data config && cp .env.example .env && python setup.py && echo "✓ Setup complete! Run: python run.py"

# Complete setup in one command (Windows PowerShell):
cd backend_flask; python -m venv venv; .\venv\Scripts\activate; pip install -r requirements.txt; mkdir logs, data, config; copy .env.example .env; python setup.py; Write-Host "Setup complete!"

# ═══════════════════════════════════════════════════════════════════════════════
# PRODUCTION DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Install production server (Gunicorn)
pip install gunicorn

# Run with Gunicorn (4 workers)
gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app()'

# Run with Gunicorn (production)
FLASK_ENV=production gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app()'

# ═══════════════════════════════════════════════════════════════════════════════
# DOCKER COMMANDS (Optional)
# ═══════════════════════════════════════════════════════════════════════════════

# Build Docker image
docker build -t cybermind-flask:latest .

# Run Docker container
docker run -p 5000:5000 cybermind-flask:latest

# Run with environment variables
docker run -p 5000:5000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY=your-secret \
  cybermind-flask:latest

# ═══════════════════════════════════════════════════════════════════════════════
# USEFUL ALIASES (Add to .bashrc or .zshrc)
# ═══════════════════════════════════════════════════════════════════════════════

# alias cybermind-setup="cd ~/Documents/GitHub/CyberMind/backend_flask && source venv/bin/activate && python setup.py"
# alias cybermind-run="cd ~/Documents/GitHub/CyberMind/backend_flask && source venv/bin/activate && python run.py"
# alias cybermind-test="cd ~/Documents/GitHub/CyberMind/backend_flask && source venv/bin/activate && pytest"
# alias cybermind-logs="tail -f ~/Documents/GitHub/CyberMind/backend_flask/logs/cybermind.log"

# ═══════════════════════════════════════════════════════════════════════════════

# Save this file for future reference!
# Location: backend_flask/TERMINAL_COMMANDS.md
