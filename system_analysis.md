=== File: ./start_all.sh ===
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

=== File: ./start_demo.sh ===
#!/bin/bash

# Trap SIGINT (Ctrl+C) and SIGTERM to ensure clean shutdown of all child processes
trap 'echo -e "\nShutting down CyberMind Demo..."; kill $NODE_PID $FLASK_PID $VITE_PID 2>/dev/null; exit 0' SIGINT SIGTERM EXIT

echo "==============================================="
echo "Starting CyberMind Capstone 2 Demo Environment"
echo "==============================================="

echo "[1/3] Starting Node.js Backend (Port 3001)..."
cd backend
npm install --silent
npm run dev &
NODE_PID=$!
cd ..

echo "[2/3] Starting Flask Backend (Port 5000)..."
cd backend_flask
python3 run.py &
FLASK_PID=$!
cd ..

echo "[3/3] Starting Vite Frontend..."
cd frontend
npm install --silent
npm run dev &
VITE_PID=$!
cd ..

echo "==============================================="
echo "✅ CyberMind is fully running!"
echo ""
echo "📱 Frontend:   http://localhost:5173"
echo "🛡️  Flask API:  http://localhost:5000"
echo "⚙️  Node API:   http://localhost:3001"
echo ""
echo "Press Ctrl+C at any time to stop all services."
echo "==============================================="

# Wait indefinitely until interrupted
wait

=== File: ./stop_servers.sh ===
#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# CyberMind Sentinel - Stop All Servers
# ════════════════════════════════════════════════════════════════════════════

echo "Stopping CyberMind Sentinel servers..."
echo ""

# Kill Node backend (port 3001)
echo "Stopping Node Auth Backend (port 3001)..."
lsof -ti:3001 | xargs kill -9 2>/dev/null || true

# Kill Flask backend (port 5000)
echo "Stopping Flask Ops Backend (port 5000)..."
lsof -ti:5000 | xargs kill -9 2>/dev/null || true

# Kill Vite dev server if running (port 5173)
echo "Stopping Vite Dev Server (port 5173)..."
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

echo ""
echo "✓ All servers stopped"
echo ""
echo "Open ports:"
lsof -i -P -n | grep LISTEN | grep -E "300[0-9]|500[0-9]|517[0-9]" || echo "All target ports are free"

=== File: ./backend_flask/run.py ===
"""
CyberMind Sentinel - Main Entry Point
Run this to start the Flask backend server

⚠️  IMPORTANT: Live packet capture requires root/admin privileges
    For live network scanning demos, run with:
      sudo python3 run.py          (macOS/Linux)
      python run.py (as Administrator)  (Windows)
    
    Without root, packet scanner falls back to synthetic simulation.
"""

import os
import sys
import logging
import socket
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

# Import Flask app factory
from app import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(name)s: %(message)s'
)

logger = logging.getLogger(__name__)


def _check_root_privileges() -> bool:
    """Check if running with root/admin privileges needed for Scapy packet capture."""
    try:
        # Unix/Linux/macOS
        return os.geteuid() == 0  # type: ignore
    except AttributeError:
        # Windows
        import ctypes
        try:
            return bool(ctypes.windll.shell.IsUserAnAdmin())  # type: ignore
        except Exception:
            return False


def _warn_about_packet_capture() -> None:
    """Warn user if not running with root privileges (packet capture will fail)."""
    if not _check_root_privileges():
        print("\n" + "=" * 80)
        print("⚠️  WARNING: NOT RUNNING WITH ROOT/ADMIN PRIVILEGES")
        print("=" * 80)
        print("\nLive packet capture requires elevated privileges.")
        print("\nWithout root/admin, the Scapy packet scanner will SILENTLY FALL BACK")
        print("to synthetic simulation. Your 'live scan' demo will NOT capture real traffic.\n")
        print("TO FIX FOR DEMO DAY:")
        print("  macOS/Linux:  sudo python3 run.py")
        print("  Windows:      Run Command Prompt as Administrator, then: python run.py\n")
        print("=" * 80 + "\n")
        logger.warning("Running without root/admin — packet capture disabled (using synthetic fallback)")
    else:
        logger.info("✓ Running with root/admin privileges — live packet capture ENABLED")


def _port_is_available(host: str, port: int) -> bool:
    """Return True when the requested TCP port can be bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _find_available_port(host: str, preferred_port: int, fallback_ports: range) -> int:
    """Find the first available port, starting with the preferred port."""
    if _port_is_available(host, preferred_port):
        return preferred_port

    for candidate_port in fallback_ports:
        if candidate_port == preferred_port:
            continue
        if _port_is_available(host, candidate_port):
            logger.warning(
                f"Port {preferred_port} is busy; switching CyberMind Sentinel to fallback port {candidate_port}"
            )
            return candidate_port

    logger.warning(
        f"Port {preferred_port} is busy and no fallback ports are available"
    )
    return preferred_port


def main():
    """Main entry point."""
    
    # Check for root privileges (needed for live packet capture)
    _warn_about_packet_capture()
    
    # Get configuration mode
    config_name = os.environ.get('FLASK_ENV', 'development')
    
    logger.info(f"Starting CyberMind Sentinel - Mode: {config_name}")
    
    # Create Flask app
    app = create_app(config_name)
    
    # Get server configuration
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = config_name == 'development'

    if port == 5000:
        port = _find_available_port(host, 5000, range(5001, 5011))
    
    logger.info(f"Server starting: {host}:{port}")
    logger.info(f"Dashboard: http://localhost:{port}")
    logger.info(f"API Docs: http://localhost:{port}/api")
    
    # Start server
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False
    )


if __name__ == '__main__':
    main()
