# CyberMind — Docker Deploy & Attack Guide

This guide covers how to **deploy** the CyberMind sandbox with Docker, how to **scan / attack** it safely, and how to **collect results**.

For the recorded lab findings from 2026-07-31, see [ATTACK_REPORT.md](./ATTACK_REPORT.md).

---

## 1. What you get

| Service | Container | Role | Host URL |
|---------|-----------|------|----------|
| Frontend dashboard | `cm-frontend` | UI | http://localhost:5173 |
| Auth API (Node) | `cm-auth` | Login / JWT | http://localhost:3001 |
| Ops API (Flask) | `cm-flask` | Scan, IDS, honeypot, blacklist | http://localhost:5000 |
| Attacker toolkit | `cm-attacker` | nmap, hydra, hping3, nc, curl | (no host port; exec in) |
| Ollama (optional) | `cm-ollama` | Local AI translation | http://localhost:11434 |

Isolated bridge: `cybermind-lab` (`10.10.0.0/24`)

- Defender: `flask` → `10.10.0.10`
- Attacker: `attacker` → `10.10.0.99`

Attacks stay on the Docker network. Your Mac firewall is not the target.

---

## 2. Prerequisites

### Option A — Docker Desktop (simplest GUI)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Start Docker Desktop
3. Verify:

```bash
docker --version
docker compose version
docker info
```

### Option B — Colima (CLI / lighter on Mac)

```bash
brew install colima docker docker-compose docker-buildx

# Wire Compose + Buildx plugins (once)
mkdir -p ~/.docker/cli-plugins
ln -sf "$(brew --prefix)/opt/docker-compose/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
ln -sf "$(brew --prefix)/opt/docker-buildx/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx

# If you previously used Docker Desktop, remove broken cred helper:
# edit ~/.docker/config.json and remove "credsStore": "desktop"

colima start --cpu 4 --memory 6 --disk 40
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"

docker info
```

### Resources

- ~4 GB RAM free for the base lab
- Extra RAM/disk if you enable the `ai` profile (Ollama + Mistral)

---

## 3. Deploy the lab

From the **repo root**:

```bash
cd /path/to/CyberMind
chmod +x docker/sandbox/*.sh
mkdir -p sandbox-results

# Build images and start all core services
docker compose -f docker-compose.sandbox.yml up -d --build
```

Check health:

```bash
docker compose -f docker-compose.sandbox.yml ps
curl -s http://127.0.0.1:5000/api/health
curl -s http://127.0.0.1:3001/api/status
```

Open the dashboard:

```bash
open http://localhost:5173
```

Login (from auth container logs): typically `admin` / `cybermind2025`  
(If your `users.json` still has a different demo password, use that.)

### Useful logs

```bash
docker compose -f docker-compose.sandbox.yml logs -f flask
docker compose -f docker-compose.sandbox.yml logs -f auth
docker compose -f docker-compose.sandbox.yml logs -f frontend
```

### Optional: AI translator (Ollama)

```bash
docker compose -f docker-compose.sandbox.yml --profile ai up -d
docker exec -it cm-ollama ollama pull mistral
curl -s http://127.0.0.1:5000/api/ollama/status
```

### Stop / reset

```bash
# Stop containers (keep volumes)
docker compose -f docker-compose.sandbox.yml down

# Stop + wipe flask data volume
docker compose -f docker-compose.sandbox.yml down -v

# Clear old reports
rm -rf sandbox-results/*
```

---

## 4. One-command full test (recommended)

Builds (if needed), waits for Flask, runs every attack, writes a JSON report:

```bash
bash docker/sandbox/test-all.sh
```

Then:

```bash
ls -lt sandbox-results/
jq '{
  scan: .scan.status.result.breakdown,
  ids: [.ids_battery[].response.threat_type],
  honeypot: .cybermind_state.honeypot_logs.meta
}' sandbox-results/sandbox_report_*.json | tail -n +1
```

---

## 5. How scanning works (defender side)

### A. Dashboard scan (UI)

1. Open http://localhost:5173 and log in  
2. Go to **Analyze**  
3. Click **Start Scan**  
4. Within a few seconds, run attacks (section 6)  
5. Wait for the job to finish — check label, confidence, breakdown  
6. Open **Honeypot** for connection captures  
7. Optionally **Block** the attacker IP from the dashboard  

### B. API scan (scripted)

```bash
# Start capture + RF classify
curl -s -X POST http://127.0.0.1:5000/api/scan/start \
  -H 'Content-Type: application/json' \
  -d '{"packet_count":120}' | jq .

# Poll (replace JOB_ID)
curl -s http://127.0.0.1:5000/api/scan/status/JOB_ID | jq .
```

Capture modes:

| Mode | When |
|------|------|
| `live` | Scapy sniff works (privileged flask container — default in this compose) |
| `pcap` | `.pcap` present under Flask `data/` |
| `simulated` | No live capture / no pcap |

---

## 6. How to attack (attacker side)

> **Authorized lab use only.** Only attack `flask` / published lab ports on this compose network.

### 6.1 Enter the attacker container

```bash
docker compose -f docker-compose.sandbox.yml exec attacker bash
```

Inside the container, the target hostname is **`flask`** (IP `10.10.0.10`).

### 6.2 Automated suite (same as CI/demo)

```bash
# From host:
docker compose -f docker-compose.sandbox.yml exec attacker bash /attacks/run_attacks.sh
```

This runs, in order:

1. Start scan job  
2. Nmap SYN scan  
3. Honeypot probes  
4. Hydra SSH brute → `:2222`  
5. hping3 SYN flood → `:8080`  
6. IDS signature battery via `/api/analyze`  
7. Demo `/api/demo/attack-sim`  
8. Collect honeypot / firewall / stats into `sandbox-results/`  

### 6.3 Manual network attacks

Run these **while a scan is active** for best RF results.

```bash
# Port scan
nmap -sS -p 1-1000 --min-rate 300 flask
nmap -sS -p 2222,2323,5000,8080,3390,2121,3307 flask

# Honeypot probes
for p in 2222 2323 8080 3390 2121 3307; do
  echo "=== $p ==="
  printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 2 flask $p || true
done

# SSH-style brute against decoy
printf 'admin\npassword\n123456\n' > /tmp/wl.txt
hydra -l admin -P /tmp/wl.txt ssh://flask:2222 -t 4 -f || true

# Short SYN flood (sandbox-safe)
timeout 8 hping3 -S --flood -p 8080 flask || true
```

### 6.4 Host-side attacks (optional)

Honeypot ports are published to the host. From another Mac terminal:

```bash
nmap -sS -p 2222,2323,8080,3390,2121,3307 127.0.0.1
nc -v 127.0.0.1 2222
curl -v http://127.0.0.1:8080/
```

Prefer in-network attacks via `attacker` → `flask` so source IP `10.10.0.99` shows clearly in honeypot logs.

### 6.5 IDS / log analysis attacks (no packets needed)

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"nmap -sS -p 1-1000 10.0.0.5"}' | jq .

curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"sqlmap -u http://x/?id=1 UNION SELECT"}' | jq .

curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"hydra -l admin -P rockyou.txt ssh://10.0.0.5"}' | jq .

curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"lockbit ransomware cobalt strike beacon"}' | jq .
```

### 6.6 Demo simulation endpoint (DEBUG / development)

```bash
curl -s -X POST http://127.0.0.1:5000/api/demo/attack-sim \
  -H 'Content-Type: application/json' \
  -d '{
    "threat_type":"port_scan",
    "tool":"nmap",
    "target_port":8080,
    "payload":"sandbox nmap SYN",
    "auto_block":false,
    "source_ip":"10.10.0.99"
  }' | jq .
```

### 6.7 Kali / Parrot VM against published ports

If you attack from a VM instead of the `attacker` container:

1. Deploy lab on the Mac as above  
2. Find Mac LAN IP: `ipconfig getifaddr en0`  
3. On Kali:

```bash
export MAC_IP=192.168.x.x
bash kali_attack.sh
```

Ensure the VM can reach the Mac’s published ports (`5000`, `2222`, …).

---

## 7. How to read results

### Dashboard

| Screen | What to check |
|--------|----------------|
| Analyze | Label, confidence, class breakdown, capture mode badge |
| Honeypot | Connections from attacker IP, port, severity |
| Logs / stats | Scan history, counts |
| Blacklist | After blocking an IP |

### API snapshots

```bash
curl -s http://127.0.0.1:5000/api/honeypot/logs | jq .
curl -s http://127.0.0.1:5000/api/honeypot/status | jq .
curl -s http://127.0.0.1:5000/api/honeypot/summary | jq .
curl -s http://127.0.0.1:5000/api/blacklist/status | jq .
curl -s http://127.0.0.1:5000/api/get_latest_traffic | jq .
curl -s http://127.0.0.1:5000/api/stats | jq .
```

### Automated report files

After `run_attacks.sh` / `test-all.sh`:

```text
sandbox-results/
  sandbox_report_<timestamp>.json   ← master report
  sandbox_run_<timestamp>.log
  run_<timestamp>/
    nmap.txt, hydra.txt, hping3.txt
    ids_battery.ndjson
    honeypot_logs.json, scan_status.json, …
```

Collect a snapshot without re-attacking:

```bash
docker compose -f docker-compose.sandbox.yml exec attacker bash /attacks/collect_results.sh
```

---

## 8. Expected detections cheat sheet

| Attack | Tool | Where it shows up |
|--------|------|-------------------|
| Port scan | `nmap -sS` | Analyze breakdown `port_scan`; IDS “Nmap Port Scan” |
| Honeypot touch | `nc` / `curl` | Honeypot logs (SSH/Telnet/HTTP/RDP/FTP/MySQL) |
| SSH spray | `hydra` → `:2222` | Honeypot `brute_force`; IDS “Hydra …” |
| SYN flood | `hping3 --flood` | Analyze breakdown `ddos`; IDS “DDoS / Flood” |
| SQLi / XSS / LFI text | `/api/analyze` | IDS injection / xss / lfi |
| Ransomware / C2 text | `/api/analyze` | IDS malware / post_exploitation |
| Demo sim | `/api/demo/attack-sim` | Honeypot capture + optional auto-block |

Honeypot ports (decoys):

| Port | Emulates |
|------|----------|
| 2222 | SSH |
| 2323 | Telnet |
| 8080 | HTTP admin |
| 3390 | RDP |
| 2121 | FTP |
| 3307 | MySQL |

---

## 9. Troubleshooting

| Problem | Fix |
|---------|-----|
| `docker-credential-desktop` error | Remove `credsStore` from `~/.docker/config.json` (Colima) |
| `docker compose` unknown | Install/link `docker-compose` plugin (see §2) |
| Flask unhealthy / SyntaxError | Ensure merge conflicts are resolved; rebuild: `docker compose -f docker-compose.sandbox.yml up -d --build flask` |
| Auth `Exec format error` (bcrypt) | Ensure `.dockerignore` excludes host `node_modules`; rebuild auth with `--no-cache` |
| Scan always `simulated` | Flask must be privileged (`privileged: true` in compose) |
| Majority label always `safe` | Start attacks **during** the scan window; increase flood duration / `packet_count` |
| Hydra “could not connect” on 2222 | Normal for banner-only honeypot — check honeypot logs instead |
| Frontend can’t reach APIs | Confirm host ports `5000` and `3001` are published and healthy |

---

## 10. Safety notes

- Lab traffic is confined to the compose network when using `attacker` → `flask`.
- IP blacklist / kill-switch rules apply **inside the flask container**, not your host pf/iptables (unless you intentionally run host-native mode).
- Do **not** point `kali_attack.sh` or flood tools at production or third-party hosts.
- Keep `auto_block: false` in demos unless you intend to blacklist the source inside the container.

---

## 11. Quick reference commands

```bash
# Deploy
docker compose -f docker-compose.sandbox.yml up -d --build

# Full attack + results
bash docker/sandbox/test-all.sh

# Interactive attacker
docker compose -f docker-compose.sandbox.yml exec attacker bash

# Tear down
docker compose -f docker-compose.sandbox.yml down -v
```

Related docs:

- [ATTACK_REPORT.md](./ATTACK_REPORT.md) — detailed results from the recorded lab run  
- [RESULTS.md](./RESULTS.md) — short scorecard  
- [../SANDBOX.md](../SANDBOX.md) — architecture overview  
