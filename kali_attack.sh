#!/usr/bin/env bash
# ==============================================================================
#  CyberMind Sentinel — Attack Demo Script
#  Sends real network attacks that CyberMind's packet scanner will detect.
#
#  Run this AFTER starting the CyberMind scan on the dashboard.
#
#  Two modes:
#    MODE 1 (DEFAULT): Use Python/Scapy injector — works from Mac, sends real
#                      raw packets through en0 that Scapy can capture.
#    MODE 2 (KALI VM): Run tools (nmap, hping3) from inside the Kali VM in UTM,
#                      targeting Mac IP 192.168.0.4
# ==============================================================================

set -euo pipefail

MAC_IP="192.168.0.4"
IFACE="en0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python3"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
    echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  CyberMind Sentinel — Live Attack Demo                       ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

banner

# ── Detect if we're running as root (needed for raw sockets) ──────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run with sudo for raw socket access${NC}"
    echo -e "       ${BOLD}sudo bash kali_attack.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}⚡ IMPORTANT: Start the scan on your CyberMind dashboard FIRST!${NC}"
echo -e "   Then press ENTER here to launch the attack...\n"
read -r

echo -e "${BOLD}[1/3] PORT SCAN — Injecting real SYN packets through $IFACE${NC}"
echo -e "      (Simulates: nmap -sS -p 1-1000 --max-rate 50 $MAC_IP)\n"

# Use Python/Scapy injector to send real raw packets through en0
if [[ -f "$VENV_PYTHON" ]]; then
    PYTHON="$VENV_PYTHON"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    echo -e "${RED}  Python3 not found — install python3${NC}"
    PYTHON=""
fi

PORT_SCAN_DONE=false
if [[ -n "$PYTHON" && -f "$SCRIPT_DIR/inject_attack.py" ]]; then
    echo -e "  Using Scapy injector (real raw packets)..."
    "$PYTHON" "$SCRIPT_DIR/inject_attack.py" --type port_scan --target "$MAC_IP" --iface "$IFACE"
    PORT_SCAN_DONE=true
elif command -v nmap &>/dev/null; then
    # nmap against gateway/router IP (NOT self-IP) so packets go through en0
    GATEWAY=$(route -n get default 2>/dev/null | grep gateway | awk '{print $2}' || echo "192.168.0.1")
    echo -e "  Using nmap against gateway $GATEWAY (traffic goes through $IFACE)..."
    nmap -sS -p 1-200 --max-rate 50 --data-length 0 "$GATEWAY" 2>/dev/null || true
    PORT_SCAN_DONE=true
fi

if [[ "$PORT_SCAN_DONE" == "false" ]]; then
    echo -e "${RED}  Neither injector nor nmap available${NC}"
fi
echo -e "${GREEN}  ✔ Port scan sent.${NC}\n"

echo -e "${BOLD}[2/3] BRUTE FORCE — Injecting SSH connection attempts${NC}"
echo -e "      (Simulates: hydra -l root -P wordlist.txt ssh://$MAC_IP)\n"

BRUTE_DONE=false
if [[ -n "$PYTHON" && -f "$SCRIPT_DIR/inject_attack.py" ]]; then
    echo -e "  Injecting SYN packets → port 22 (SSH)..."
    "$PYTHON" "$SCRIPT_DIR/inject_attack.py" --type brute_force --target "$MAC_IP" --iface "$IFACE"
    BRUTE_DONE=true
elif command -v hydra &>/dev/null; then
    hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -f "ssh://$MAC_IP:2222" 2>/dev/null || true
    BRUTE_DONE=true
fi
[[ "$BRUTE_DONE" == "false" ]] && echo -e "  ${YELLOW}(install hydra: sudo apt install hydra)${NC}"
echo -e "${GREEN}  ✔ Brute force sent.${NC}\n"

echo -e "${BOLD}[3/3] DDOS — SYN flood on $MAC_IP:8080 for 10 seconds${NC}"
echo -e "      (Simulates: hping3 --flood --rand-source -S -p 8080 $MAC_IP)\n"

DDOS_DONE=false
if [[ -n "$PYTHON" && -f "$SCRIPT_DIR/inject_attack.py" ]]; then
    echo -e "  Injecting SYN flood packets (200 pps for 10s)..."
    "$PYTHON" "$SCRIPT_DIR/inject_attack.py" --type ddos --target "$MAC_IP" --iface "$IFACE"
    DDOS_DONE=true
elif command -v hping3 &>/dev/null; then
    timeout 10 hping3 --flood --rand-source -S -p 8080 "$MAC_IP" 2>/dev/null || true
    DDOS_DONE=true
fi
[[ "$DDOS_DONE" == "false" ]] && echo -e "  ${YELLOW}(install hping3: brew install hping on Mac, or sudo apt install hping3 on Kali)${NC}"
echo -e "${GREEN}  ✔ DDoS flood sent.${NC}\n"

echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  ALL ATTACKS SENT!                                           ║${NC}"
echo -e "${BOLD}${GREEN}║  → Check Mac Dashboard for PORT SCAN and DDOS detection      ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

# ── Optional: Kali VM instructions ───────────────────────────────────────────
echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  ALTERNATIVE: Run from Kali VM in UTM for more realistic demo${NC}"
echo -e "${YELLOW}  1. Open UTM → Start Kali VM${NC}"
echo -e "${YELLOW}  2. In Kali terminal:${NC}"
echo -e "${YELLOW}     sudo nmap -sS -p 1-1000 --max-rate 50 $MAC_IP${NC}"
echo -e "${YELLOW}     sudo hping3 --flood --rand-source -S -p 8080 $MAC_IP${NC}"
echo -e "${YELLOW}  3. The CyberMind scanner on Mac will detect these attacks${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}\n"