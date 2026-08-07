# CyberMind — How to Test (Shareable Guide)

**For:** teammate / reviewer verifying CyberMind works  
**Lab:** Docker sandbox (isolated — safe to attack)  
**Author note:** Run only against this lab, not production or other people’s machines.

---

## What you will prove

| Check | What “working” looks like |
|-------|---------------------------|
| Live scan | Dashboard/API shows `capture_mode: live` and a class breakdown |
| Honeypot | Connections logged from attacker IP on decoy ports |
| IDS engine | Log/text analysis returns threat labels (nmap, hydra, sqlmap, etc.) |

---

## One-time setup

### 1) Install Docker runtime (pick one)

**Docker Desktop**  
Install from https://www.docker.com/products/docker-desktop/ and start it.

**Or Colima (Mac CLI):**
```bash
brew install colima docker docker-compose docker-buildx
colima start --cpu 4 --memory 6
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"
```

Verify:
```bash
docker --version
docker compose version
docker info
```

### 2) Get the code

```bash
git clone https://github.com/Ziauddin444/CyberMind.git
cd CyberMind
git checkout feature/docker-sandbox-lab   # or main after PR #4 is merged
```

---

## Start the lab

```bash
cd CyberMind
chmod +x docker/sandbox/*.sh
mkdir -p sandbox-results

docker compose -f docker-compose.sandbox.yml up -d --build
```

Wait until healthy:
```bash
curl -s http://127.0.0.1:5000/api/health
```

Open dashboard:
```bash
open http://localhost:5173
```

**Login:** check auth logs for the printed demo credentials (typically `admin` / `cybermind2025`):
```bash
docker compose -f docker-compose.sandbox.yml logs auth | head -20
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:5173 |
| Ops API (Flask) | http://localhost:5000 |
| Auth API | http://localhost:3001 |

---

## Run the full attack test (recommended)

From the repo root:

```bash
bash docker/sandbox/test-all.sh
```

This will:

1. Start/ensure the lab is up  
2. Start a live packet scan on CyberMind  
3. Run attacks from the `attacker` container (`nmap`, honeypot probes, hydra, hping3, IDS tests)  
4. Write a JSON report under `sandbox-results/`

If the lab is already running, you can attack only:

```bash
docker compose -f docker-compose.sandbox.yml exec attacker bash /attacks/run_attacks.sh
```

---

## How to read results

### A) Report file (best for sharing)

```bash
ls -lt sandbox-results/sandbox_report_*.json

jq '{
  capture_mode: .scan.status.result.capture_mode,
  breakdown: .scan.status.result.breakdown,
  ids: [.ids_battery[].response | {label, threat_type, severity, confidence}],
  honeypot: .cybermind_state.honeypot_logs.meta
}' sandbox-results/sandbox_report_*.json
```

**Good signs:**
- `capture_mode` = `"live"`
- `breakdown` includes `ddos` / `port_scan` / `brute_force` > 0
- IDS list has ~10 detections with severities
- `honeypot.total_connections` ≥ 1 (usually 6–8+)

### B) Dashboard

1. Open http://localhost:5173  
2. **Analyze** — scan label, confidence, breakdown  
3. **Honeypot** — attacker hits on ports 2222, 2323, 8080, 3390, 2121, 3307  

### C) Quick API checks

```bash
# Honeypot hits
curl -s http://127.0.0.1:5000/api/honeypot/logs | jq '.meta, .data[:5]'

# IDS signature test (no network attack needed)
curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"nmap -sS hydra sqlmap ransomware"}' \
  | jq '{label, threat_type, severity, confidence, threat_detected}'
```

---

## Optional: attack manually (watch live)

**Terminal 1 — start scan via UI**  
Dashboard → **Analyze** → **Start Scan**

**Terminal 2 — attack:**
```bash
docker compose -f docker-compose.sandbox.yml exec attacker bash
```

Inside attacker:
```bash
nmap -sS -p 1-1000,2222,8080 flask

for p in 2222 2323 8080 3390 2121 3307; do
  printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 2 flask $p
done

timeout 8 hping3 -S --flood -p 8080 flask
```

Then refresh Analyze + Honeypot screens.

---

## What each attack should trigger

| Attack | Command (inside attacker) | Where to look |
|--------|---------------------------|---------------|
| Port scan | `nmap -sS … flask` | Analyze → `port_scan` share; IDS “Nmap” |
| Honeypot probe | `nc flask 2222` (etc.) | Honeypot logs |
| SSH spray | `hydra … ssh://flask:2222` | Honeypot `brute_force` |
| SYN flood | `hping3 --flood -p 8080 flask` | Analyze → `ddos` share |
| Log/signature | `POST /api/analyze` | IDS labels (injection, malware, …) |

Honeypot decoy ports: **2222** SSH · **2323** Telnet · **8080** HTTP · **3390** RDP · **2121** FTP · **3307** MySQL

---

## Stop the lab

```bash
docker compose -f docker-compose.sandbox.yml down

# If using Colima:
colima stop
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `colima is not running` | `colima start` then set `DOCKER_HOST` |
| Flask not healthy | `docker compose -f docker-compose.sandbox.yml logs flask` |
| Auth login fails | Read credentials from `logs auth` |
| Scan says `simulated` | Rebuild flask; compose must keep `privileged: true` |
| Majority label = “safe” | Still OK if breakdown shows ddos/port_scan — start attacks *during* the scan window |
| Hydra “could not connect” on 2222 | Expected for banner decoy — check **Honeypot** logs instead |

---

## Extra docs in the repo

| File | Content |
|------|---------|
| `docker/sandbox/DEPLOY_AND_ATTACK_GUIDE.md` | Longer deploy/attack reference |
| `docker/sandbox/ATTACK_REPORT.md` | Sample detailed report from a successful lab run |
| `docker/SANDBOX.md` | Architecture overview |

**PR (if not merged yet):** https://github.com/Ziauddin444/CyberMind/pull/4

---

## Checklist to send back

After you run the test, reply with:

- [ ] Lab started (`/api/health` OK)  
- [ ] `test-all.sh` finished  
- [ ] `sandbox_report_*.json` created  
- [ ] Honeypot showed attacker connections  
- [ ] IDS `/api/analyze` returned `threat_detected: true`  
- [ ] (Optional) Attach `sandbox_report_*.json` or a screenshot of Analyze + Honeypot  

---

*Authorized lab testing only. Do not use these attack commands against systems you do not own.*
