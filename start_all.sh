#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# CyberMind Sentinel - Dual-Backend Startup Script
# Starts: Node.js Auth Backend (3001) + Flask Operations Backend (5000)
# ════════════════════════════════════════════════════════════════════════════

set -e

CYBERMIND_DIR="/Users/ziauddin/Documents/GitHub/CyberMind"
PROJECT_NAME="CyberMind Sentinel"

echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║               Starting $PROJECT_NAME                     ║"
echo "║          Dual-Backend Architecture - 2 Servers Running               ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to start Node.js backend
start_nodejs_backend() {
    echo -e "${BLUE}[1/2] Starting Node.js Authentication Backend (Port 3001)...${NC}"
    cd "$CYBERMIND_DIR/backend"
    
    # Check if node_modules exists
    if [ ! -d "node_modules" ]; then
        echo "Installing Node.js dependencies..."
        npm install
    fi
    
    # Start Node.js server in background with dev login bypass enabled.
    ALLOW_UNVERIFIED_LOGIN=true node server.js > "$CYBERMIND_DIR/backend.log" 2>&1 &
    NODE_PID=$!
    echo "export NODE_PID=$NODE_PID" > /tmp/cybermind_pids.sh
    
    # Wait for server to start
    sleep 2
    
    if ps -p $NODE_PID > /dev/null; then
        echo -e "${GREEN}✓ Node.js Backend Started (PID: $NODE_PID)${NC}"
        echo -e "  📍 Authentication Server: ${YELLOW}http://localhost:3001${NC}"
        echo -e "  📍 API Base: ${YELLOW}http://localhost:3001/api${NC}"
        echo -e "  🔓 Dev Login Bypass: ${YELLOW}ALLOW_UNVERIFIED_LOGIN=true${NC}"
    else
        echo -e "${YELLOW}✗ Node.js Backend failed to start${NC}"
        echo "Check backend.log for details"
        exit 1
    fi
}

# Function to start Flask backend
start_flask_backend() {
    echo ""
    echo -e "${BLUE}[2/2] Starting Flask Security Operations Backend (Port 5000)...${NC}"
    cd "$CYBERMIND_DIR/backend_flask"
    
    # Activate virtual environment
    if [ ! -d "../.venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv ../.venv
    fi
    source ../.venv/bin/activate
    
    # Install requirements
    if ! python3 -c "import flask" 2>/dev/null; then
        echo "Installing Python dependencies..."
        pip install -r requirements.txt > /dev/null 2>&1
    fi
    
    # Start Flask server in background
    python3 run.py > "$CYBERMIND_DIR/flask.log" 2>&1 &
    FLASK_PID=$!
    echo "export FLASK_PID=$FLASK_PID" >> /tmp/cybermind_pids.sh
    
    # Wait for server to start
    sleep 2
    
    if ps -p $FLASK_PID > /dev/null; then
        echo -e "${GREEN}✓ Flask Backend Started (PID: $FLASK_PID)${NC}"
        echo -e "  📍 Operations Server: ${YELLOW}http://localhost:5000${NC}"
        echo -e "  📍 API Base: ${YELLOW}http://localhost:5000/api${NC}"
    else
        echo -e "${YELLOW}✗ Flask Backend failed to start${NC}"
        echo "Check flask.log for details"
        exit 1
    fi
}

# Function to show frontend info
show_frontend_info() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 Both Backends Running 🎉                        ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}✓ Dual-Backend Architecture Active:${NC}"
    echo ""
    echo -e "  ${BLUE}Node.js Backend (Port 3001):${NC}"
    echo -e "    • Authentication & User Management"
    echo -e "    • User login/registration"
    echo -e "    • Session management"
    echo -e "    • Admin user management"
    echo -e "    ${YELLOW}http://localhost:3001/api${NC}"
    echo ""
    echo -e "  ${BLUE}Flask Backend (Port 5000):${NC}"
    echo -e "    • Security Operations"
    echo -e "    • Firewall Management"
    echo -e "    • Device Inventory (Add/Delete/Update)"
    echo -e "    • Honeypot File Management"
    echo -e "    • One-Click Emergency Remediation"
    echo -e "    • Network Monitoring"
    echo -e "    • Threat Analysis"
    echo -e "    ${YELLOW}http://localhost:5000/api${NC}"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║                      🌐 Frontend Options                              ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Option 1: Open Frontend with Vite Dev Server"
    echo "  $ cd $CYBERMIND_DIR/frontend"
    echo "  $ npm install  # if needed"
    echo "  $ npm run dev"
    echo "  Then open: ${YELLOW}http://localhost:5173${NC}"
    echo ""
    echo "Option 2: Open Frontend in Browser (direct HTML)"
    echo "  $ open $CYBERMIND_DIR/cybermind.html"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "📋 To stop both servers, run:"
    echo "   $ cd $CYBERMIND_DIR && bash stop_servers.sh"
    echo ""
    echo "📊 View logs:"
    echo "   • Node.js: tail -f $CYBERMIND_DIR/backend.log"
    echo "   • Flask:   tail -f $CYBERMIND_DIR/flask.log"
    echo ""
    echo "🧪 Test API Endpoints:"
    echo "   • List devices: curl http://localhost:5000/api/devices/list"
    echo "   • Check firewall: curl http://localhost:5000/api/firewall/status"
    echo "   • Honeypot summary: curl http://localhost:5000/api/honeypot/summary"
    echo ""
}

# Function to cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down servers...${NC}"
    if [ -f /tmp/cybermind_pids.sh ]; then
        source /tmp/cybermind_pids.sh
        if [ ! -z "$NODE_PID" ]; then
            kill $NODE_PID 2>/dev/null || true
            echo "Stopped Node.js Backend"
        fi
        if [ ! -z "$FLASK_PID" ]; then
            kill $FLASK_PID 2>/dev/null || true
            echo "Stopped Flask Backend"
        fi
        rm /tmp/cybermind_pids.sh
    fi
    echo "All servers stopped"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Start both backends
start_nodejs_backend
start_flask_backend
show_frontend_info

# Keep script running
echo -e "${YELLOW}Servers running. Press Ctrl+C to stop.${NC}"
wait

