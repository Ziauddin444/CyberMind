#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# CyberMind Sentinel - 3-Tier IDS Startup Script
# Starts: Node.js Auth Backend (3001) + Flask Operations Backend (5000) + Vite Frontend (5173)
# ════════════════════════════════════════════════════════════════════════════

set -e

CYBERMIND_DIR="/Users/ziauddin/Documents/GitHub/CyberMind"
PROJECT_NAME="CyberMind Sentinel"

echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║               Starting $PROJECT_NAME                     ║"
echo "║   Architecture: Node.js Auth + Flask Ops + Vite Frontend               ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize PID file
echo "#!/bin/bash" > /tmp/cybermind_pids.sh

# Function to start Node.js backend
start_node_backend() {
    echo -e "${BLUE}[1/3] Starting Node.js Authentication Backend (Port 3001)...${NC}"
    cd "$CYBERMIND_DIR/backend"
    
    if [ ! -d "node_modules" ]; then
        echo "Installing Node.js dependencies..."
        npm install > /dev/null 2>&1
    fi
    
    npm start > "$CYBERMIND_DIR/backend.log" 2>&1 &
    NODE_PID=$!
    echo "export NODE_PID=$NODE_PID" >> /tmp/cybermind_pids.sh
    
    sleep 2
    if ps -p $NODE_PID > /dev/null; then
        echo -e "${GREEN}✓ Node.js Backend Started (PID: $NODE_PID)${NC}"
    else
        echo -e "${YELLOW}✗ Node.js Backend failed to start${NC}"
        exit 1
    fi
    echo ""
}

# Function to start Flask backend
start_flask_backend() {
    echo -e "${BLUE}[2/3] Starting Flask Security Operations Backend (Port 5000)...${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}⚠️  WARNING: Flask is NOT running with root/admin privileges${NC}"
        echo "Live packet capture requires elevated privileges. Falling back to synthetic simulation."
        echo -e "For live network scanning, restart with: ${YELLOW}sudo bash start_all.sh${NC}"
    else
        echo -e "${GREEN}✓ Running with root privileges — live packet capture ENABLED${NC}"
    fi
    
    cd "$CYBERMIND_DIR/backend_flask"
    
    if [ ! -d "../.venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv ../.venv
    fi
    source ../.venv/bin/activate
    
    if ! python3 -c "import flask" 2>/dev/null; then
        echo "Installing Python dependencies..."
        pip install -r requirements.txt > /dev/null 2>&1
    fi
    
    python3 run.py > "$CYBERMIND_DIR/flask.log" 2>&1 &
    FLASK_PID=$!
    echo "export FLASK_PID=$FLASK_PID" >> /tmp/cybermind_pids.sh
    
    sleep 2
    if ps -p $FLASK_PID > /dev/null; then
        echo -e "${GREEN}✓ Flask Backend Started (PID: $FLASK_PID)${NC}"
    else
        echo -e "${YELLOW}✗ Flask Backend failed to start${NC}"
        exit 1
    fi
    echo ""
}

# Function to start Vite frontend
start_vite_frontend() {
    echo -e "${BLUE}[3/3] Starting Vite Frontend (Port 5173)...${NC}"
    cd "$CYBERMIND_DIR/frontend"
    
    if [ ! -d "node_modules" ]; then
        echo "Installing Frontend dependencies..."
        npm install > /dev/null 2>&1
    fi
    
    npm run dev > "$CYBERMIND_DIR/frontend.log" 2>&1 &
    VITE_PID=$!
    echo "export VITE_PID=$VITE_PID" >> /tmp/cybermind_pids.sh
    
    sleep 2
    if ps -p $VITE_PID > /dev/null; then
        echo -e "${GREEN}✓ Vite Frontend Started (PID: $VITE_PID)${NC}"
    else
        echo -e "${YELLOW}✗ Vite Frontend failed to start${NC}"
        exit 1
    fi
    echo ""
}

show_info() {
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 All Services Running 🎉                         ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "  📍 Frontend: ${GREEN}http://localhost:5173${NC}"
    echo -e "  📍 Auth API (Node): ${YELLOW}http://localhost:3001/api${NC}"
    echo -e "  📍 Ops API (Flask): ${YELLOW}http://localhost:5000/api${NC}"
    echo ""
    echo "📋 To stop all servers, run: bash stop_servers.sh"
    echo ""
    echo "📊 Logs:"
    echo "   • tail -f $CYBERMIND_DIR/backend.log"
    echo "   • tail -f $CYBERMIND_DIR/flask.log"
    echo "   • tail -f $CYBERMIND_DIR/frontend.log"
    echo ""
}

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down servers...${NC}"
    if [ -f /tmp/cybermind_pids.sh ]; then
        source /tmp/cybermind_pids.sh
        [ ! -z "$NODE_PID" ] && kill $NODE_PID 2>/dev/null && echo "Stopped Node Backend"
        [ ! -z "$FLASK_PID" ] && kill $FLASK_PID 2>/dev/null && echo "Stopped Flask Backend"
        [ ! -z "$VITE_PID" ] && kill $VITE_PID 2>/dev/null && echo "Stopped Vite Frontend"
        rm /tmp/cybermind_pids.sh
    fi
    echo "All servers stopped"
    exit 0
}

trap cleanup EXIT INT TERM

start_node_backend
start_flask_backend
start_vite_frontend
show_info

echo -e "${YELLOW}Servers running in background. Press Ctrl+C to stop.${NC}"
wait
