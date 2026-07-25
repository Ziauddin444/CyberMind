#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# CyberMind Sentinel - Complete Startup Script
# Starts: Ollama + Node.js Auth (3001) + Flask Ops (5000) + Vite Frontend (5173)
# ════════════════════════════════════════════════════════════════════════════

set -e

CYBERMIND_DIR="/Users/ziauddin/Documents/GitHub/CyberMind"
PROJECT_NAME="CyberMind Sentinel"

echo "════════════════════════════════════════════════════════════════════════╗"
echo "║               Starting $PROJECT_NAME                     ║"
echo "║   Architecture: Ollama AI + Node Auth + Flask Ops + Vite UI            ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Initialize PID file
echo "#!/bin/bash" > /tmp/cybermind_pids.sh

# Function to start Ollama
start_ollama() {
    echo -e "${BLUE}[1/4] Starting Ollama AI Server...${NC}"
    
    # Check if Ollama is already running
    if pgrep -x "ollama" > /dev/null; then
        echo -e "${GREEN}✓ Ollama is already running${NC}"
    else
        # Check if Ollama is installed
        if ! command -v ollama &> /dev/null; then
            echo -e "${YELLOW}️  Ollama not found. Install with: brew install ollama${NC}"
            echo "   AI translation will use fallback mode."
            return 0
        fi
        
        ollama serve > "$CYBERMIND_DIR/ollama.log" 2>&1 &
        OLLAMA_PID=$!
        echo "export OLLAMA_PID=$OLLAMA_PID" >> /tmp/cybermind_pids.sh
        
        sleep 3
        
        # Check if Mistral model is available
        if ollama list | grep -q mistral; then
            echo -e "${GREEN}✓ Ollama Started with Mistral model (PID: $OLLAMA_PID)${NC}"
        else
            echo -e "${YELLOW}⚠️  Mistral model not found. Pulling it now...${NC}"
            ollama pull mistral > /dev/null 2>&1 &
            echo -e "${GREEN}✓ Ollama Started (PID: $OLLAMA_PID) - Mistral downloading in background${NC}"
        fi
    fi
    echo ""
}

# Function to start Node.js backend
start_node_backend() {
    echo -e "${BLUE}[2/4] Starting Node.js Authentication Backend (Port 3001)...${NC}"
    cd "$CYBERMIND_DIR/backend"
    
    if [ ! -d "node_modules" ]; then
        echo "Installing Node.js dependencies..."
        npm install
    fi
    
    npm start > "$CYBERMIND_DIR/backend.log" 2>&1 &
    NODE_PID=$!
    echo "export NODE_PID=$NODE_PID" >> /tmp/cybermind_pids.sh
    
    sleep 2
    if ps -p $NODE_PID > /dev/null; then
        echo -e "${GREEN}✓ Node.js Backend Started (PID: $NODE_PID)${NC}"
    else
        echo -e "${RED}✗ Node.js Backend failed to start${NC}"
        echo "Check logs: tail -f $CYBERMIND_DIR/backend.log"
        exit 1
    fi
    echo ""
}

# Function to start Flask backend
start_flask_backend() {
    echo -e "${BLUE}[3/4] Starting Flask Security Operations Backend (Port 5000)...${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}⚠️  WARNING: NOT running with root privileges${NC}"
        echo "   Live packet capture DISABLED (using simulation mode)"
        echo -e "   For live scanning, restart with: ${YELLOW}sudo bash start_all.sh${NC}"
    else
        echo -e "${GREEN}✓ Running with root privileges — live packet capture ENABLED${NC}"
    fi
    
    cd "$CYBERMIND_DIR/backend_flask"
    
    # Create virtual environment if needed
    if [ ! -d "../.venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv ../.venv
    fi
    source ../.venv/bin/activate
    
    # FIX: Upgrade pip and install build tools BEFORE requirements
    echo "Updating pip and build tools..."
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    
    # Install dependencies if needed
    if ! python3 -c "import flask" 2>/dev/null; then
        echo "Installing Python dependencies..."
        pip install -r requirements.txt
    fi
    
    python3 run.py > "$CYBERMIND_DIR/flask.log" 2>&1 &
    FLASK_PID=$!
    echo "export FLASK_PID=$FLASK_PID" >> /tmp/cybermind_pids.sh
    
    sleep 3
    if ps -p $FLASK_PID > /dev/null; then
        echo -e "${GREEN}✓ Flask Backend Started (PID: $FLASK_PID)${NC}"
    else
        echo -e "${RED}✗ Flask Backend failed to start${NC}"
        echo "Check logs: tail -f $CYBERMIND_DIR/flask.log"
        exit 1
    fi
    echo ""
}

# Function to start Vite frontend
start_vite_frontend() {
    echo -e "${BLUE}[4/4] Starting Vite Frontend (Port 5173)...${NC}"
    cd "$CYBERMIND_DIR/frontend"
    
    if [ ! -d "node_modules" ]; then
        echo "Installing Frontend dependencies..."
        npm install
    fi
    
    npm run dev > "$CYBERMIND_DIR/frontend.log" 2>&1 &
    VITE_PID=$!
    echo "export VITE_PID=$VITE_PID" >> /tmp/cybermind_pids.sh
    
    sleep 2
    if ps -p $VITE_PID > /dev/null; then
        echo -e "${GREEN}✓ Vite Frontend Started (PID: $VITE_PID)${NC}"
    else
        echo -e "${RED}✗ Vite Frontend failed to start${NC}"
        echo "Check logs: tail -f $CYBERMIND_DIR/frontend.log"
        exit 1
    fi
    echo ""
}

show_info() {
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 All Services Running 🎉                         ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "  🌐 Frontend:        ${GREEN}http://localhost:5173${NC}"
    echo -e "  🔐 Auth API (Node): ${YELLOW}http://localhost:3001/api${NC}"
    echo -e "  🛡️  Ops API (Flask): ${YELLOW}http://localhost:5000/api${NC}"
    echo -e "  🤖 Ollama AI:       ${BLUE}http://localhost:11434${NC}"
    echo ""
    echo "📋 To stop all servers, run: ${YELLOW}bash stop_servers.sh${NC}"
    echo ""
    echo "📊 View Logs:"
    echo "   • Ollama:   tail -f $CYBERMIND_DIR/ollama.log"
    echo "   • Node:     tail -f $CYBERMIND_DIR/backend.log"
    echo "   • Flask:    tail -f $CYBERMIND_DIR/flask.log"
    echo "   • Frontend: tail -f $CYBERMIND_DIR/frontend.log"
    echo ""
    echo " Quick Start:"
    echo "   1. Open: http://localhost:5173"
    echo "   2. Login: admin / admin123"
    echo "   3. Navigate to Analyze → Click 'START SCAN'"
    echo ""
}

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down all services...${NC}"
    if [ -f /tmp/cybermind_pids.sh ]; then
        source /tmp/cybermind_pids.sh
        [ ! -z "$OLLAMA_PID" ] && kill $OLLAMA_PID 2>/dev/null && echo "✓ Stopped Ollama"
        [ ! -z "$NODE_PID" ] && kill $NODE_PID 2>/dev/null && echo "✓ Stopped Node Backend"
        [ ! -z "$FLASK_PID" ] && kill $FLASK_PID 2>/dev/null && echo "✓ Stopped Flask Backend"
        [ ! -z "$VITE_PID" ] && kill $VITE_PID 2>/dev/null && echo "✓ Stopped Vite Frontend"
        rm /tmp/cybermind_pids.sh
    fi
    echo -e "${GREEN}All servers stopped${NC}"
    exit 0
}

trap cleanup EXIT INT TERM

# Start all services
start_ollama
start_node_backend
start_flask_backend
start_vite_frontend
show_info

echo -e "${YELLOW}⏳  All services running. Press Ctrl+C to stop.${NC}"
wait