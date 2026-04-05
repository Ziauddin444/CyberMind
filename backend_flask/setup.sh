#!/bin/bash
# CyberMind Sentinel - Complete Flask Backend Setup
# Run this script to set up the entire backend environment
# Usage: bash setup.sh

set -e  # Exit on error

echo "================================"
echo "CyberMind Sentinel - Backend Setup"
echo "================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if in correct directory
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}✗ Error: requirements.txt not found${NC}"
    echo "Please run this script from the backend_flask directory"
    exit 1
fi

echo -e "${BLUE}Step 1: Checking Python installation${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 not found${NC}"
    echo "Install Python 3.8+ from https://www.python.org/"
    exit 1
fi
echo -e "${GREEN}✓ Python $(python3 --version)${NC}"
echo ""

echo -e "${BLUE}Step 2: Creating virtual environment${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}→ Virtual environment already exists${NC}"
fi
echo ""

echo -e "${BLUE}Step 3: Activating virtual environment${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"
echo ""

echo -e "${BLUE}Step 4: Upgrading pip${NC}"
pip install --upgrade pip setuptools wheel &> /dev/null
echo -e "${GREEN}✓ pip upgraded${NC}"
echo ""

echo -e "${BLUE}Step 5: Installing dependencies${NC}"
pip install -r requirements.txt
echo -e "${GREEN}✓ All dependencies installed${NC}"
echo ""

echo -e "${BLUE}Step 6: Creating directories${NC}"
mkdir -p logs data data/honeypot_logs data/alerts config
echo -e "${GREEN}✓ Directories created${NC}"
echo ""

echo -e "${BLUE}Step 7: Setting up environment configuration${NC}"
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}✓ Created .env from template${NC}"
        echo -e "${YELLOW}→ Edit .env with your configuration${NC}"
    else
        echo -e "${RED}✗ .env.example not found${NC}"
    fi
else
    echo -e "${YELLOW}→ .env already exists${NC}"
fi
echo ""

echo -e "${BLUE}Step 8: Verifying package structure${NC}"
python3 << 'EOF'
import os
import sys

packages = [
    'app/__init__.py',
    'app/core/__init__.py',
    'app/core/firewall_manager.py',
    'app/services/__init__.py',
    'app/services/ai_translator.py',
    'app/services/fleet_monitor.py',
    'app/services/network_honeypot.py',
    'app/services/phishing_sandbox.py',
    'app/services/remediation_playbook.py',
    'app/services/kill_switch.py',
    'app/api/__init__.py',
    'app/api/routes.py',
    'config/config.py'
]

missing = []
for pkg in packages:
    if not os.path.exists(pkg):
        missing.append(pkg)

if missing:
    print(f"\033[0;31m✗ Missing files: {', '.join(missing)}\033[0m")
    sys.exit(1)
else:
    print("\033[0;32m✓ All package files present\033[0m")
EOF
echo ""

echo -e "${BLUE}Step 9: Running setup verification${NC}"
python3 setup.py
echo ""

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}✓ Setup completed successfully!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Edit .env with your configuration:"
echo "   nano .env"
echo ""
echo "2. Start the backend server:"
echo "   python run.py"
echo ""
echo "3. In another terminal, start the frontend:"
echo "   cd ../frontend && npm run dev"
echo ""
echo "4. Access the API:"
echo "   http://localhost:5000/api/health"
echo ""
