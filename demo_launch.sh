#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  CyberMind — One-Command Demo Launcher (Phase 3.2)                      ║
# ║  Starts Node.js + Flask + Vite with proper dependency checks            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# USAGE:
#   bash demo_launch.sh
#
# For LIVE traffic capture (Scapy needs raw socket access):
#   sudo bash demo_launch.sh
#
# Access at:
#   http://localhost:5173    — CyberMind frontend
#   http://localhost:5000    — Flask API
#   http://localhost:3001    — Node.js Auth API

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Cleanup on exit ──────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo -e "${YELLOW}Shutting down CyberMind...${NC}"
  [[ -n "$NODE_PID"  ]] && kill "$NODE_PID"  2>/dev/null || true
  [[ -n "$FLASK_PID" ]] && kill "$FLASK_PID" 2>/dev/null || true
  [[ -n "$VITE_PID"  ]] && kill "$VITE_PID"  2>/dev/null || true
  echo -e "${GREEN}All services stopped.${NC}"
  exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║            CyberMind Sentinel — Demo Launch                        ║${NC}"
echo -e "${CYAN}║     AI-Powered Intrusion Detection System for Professor Demo       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Check if running as sudo (needed for live Scapy capture) ─────────────────
if [[ $EUID -eq 0 ]]; then
  echo -e "${GREEN}✔  Running as root — Scapy live packet capture ENABLED${NC}"
else
  echo -e "${YELLOW}⚠  Not root — Scapy will use pcap or simulated mode${NC}"
  echo -e "${YELLOW}   For live capture during Kali demo: sudo bash demo_launch.sh${NC}"
fi
echo ""

# ─── 1. Node.js Auth Backend ──────────────────────────────────────────────────
echo -e "${BLUE}[1/3] Starting Node.js Auth Backend (port 3001)...${NC}"
cd "$SCRIPT_DIR/backend"
if ! command -v node &>/dev/null; then
  echo -e "${RED}ERROR: Node.js not found. Install from https://nodejs.org/${NC}"
  exit 1
fi
npm install --silent 2>/dev/null || true
node server.js &
NODE_PID=$!
echo -e "${GREEN}     ✔ Node.js PID $NODE_PID${NC}"
cd "$SCRIPT_DIR"

sleep 2

# ─── 2. Flask Operations Backend ──────────────────────────────────────────────
echo -e "${BLUE}[2/3] Starting Flask Operations Backend (port 5000)...${NC}"
cd "$SCRIPT_DIR/backend_flask"
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}ERROR: python3 not found.${NC}"
  exit 1
fi

# Install requirements silently if venv exists
if [[ -d "venv" ]]; then
  source venv/bin/activate 2>/dev/null || true
elif [[ -d "../venv" ]]; then
  source ../venv/bin/activate 2>/dev/null || true
fi

python3 run.py &
FLASK_PID=$!
echo -e "${GREEN}     ✔ Flask PID $FLASK_PID${NC}"
cd "$SCRIPT_DIR"

sleep 3

# ─── 3. Vite Frontend ─────────────────────────────────────────────────────────
echo -e "${BLUE}[3/3] Starting Vite Frontend (port 5173)...${NC}"
cd "$SCRIPT_DIR/frontend"
if [[ ! -d "node_modules" ]]; then
  echo "     Installing frontend dependencies..."
  npm install --silent 2>/dev/null || true
fi
npm run dev -- --host &
VITE_PID=$!
echo -e "${GREEN}     ✔ Vite PID $VITE_PID${NC}"
cd "$SCRIPT_DIR"

sleep 3

# ─── Ready ────────────────────────────────────────────────────────────────────
MAC_IP=$(python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',80)); print(s.getsockname()[0]); s.close()" 2>/dev/null || echo "unknown")

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  CyberMind is RUNNING                                              ║${NC}"
echo -e "${GREEN}║                                                                    ║${NC}"
echo -e "${GREEN}║  Frontend:     http://localhost:5173                               ║${NC}"
echo -e "${GREEN}║  Flask API:    http://localhost:5000/api/stats                     ║${NC}"
echo -e "${GREEN}║  Node API:     http://localhost:3001/api/status                    ║${NC}"
echo -e "${GREEN}║                                                                    ║${NC}"
echo -e "${GREEN}║  This Mac IP:  ${MAC_IP}                                           ║${NC}"
echo -e "${GREEN}║  (Give this IP to Kali: export MAC_IP=${MAC_IP})                   ║${NC}"
echo -e "${GREEN}║                                                                    ║${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop all services                                 ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Keep script running until Ctrl+C
wait
