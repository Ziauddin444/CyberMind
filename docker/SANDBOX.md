# CyberMind Docker Sandbox Lab

Isolated lab network to attack CyberMind safely and collect full detection results.

## Docs in this folder

| Doc | Description |
|-----|-------------|
| **[sandbox/DEPLOY_AND_ATTACK_GUIDE.md](./sandbox/DEPLOY_AND_ATTACK_GUIDE.md)** | Full deploy + scan + attack walkthrough |
| **[sandbox/ATTACK_REPORT.md](./sandbox/ATTACK_REPORT.md)** | Detailed report of the recorded lab attack run |
| **[sandbox/RESULTS.md](./sandbox/RESULTS.md)** | Short scorecard / index |

```
┌──────────────────── cybermind-lab (10.10.0.0/24) ────────────────────┐
│                                                                      │
│   attacker 10.10.0.99  ──nmap/hydra/hping3──▶  flask 10.10.0.10     │
│                                                     │                │
│   frontend :5173  ◀── browser (host)                │                │
│   auth     :3001  ◀───────────────────────────────┘                │
│   ollama   :11434 (optional --profile ai)                            │
└──────────────────────────────────────────────────────────────────────┘
         │
         ▼
   ./sandbox-results/   ← JSON reports + nmap/hydra artifacts
```

Attacks stay on the Docker bridge. Host browser only opens published ports.

---

## Prerequisites

- Docker Desktop (macOS) or Docker Engine + Compose v2 (or Colima — see deploy guide)
- ~4 GB free RAM (more if you enable Ollama)

```bash
docker --version
docker compose version
```

---

## Quick start (full test + results)

From the repo root:

```bash
cd /path/to/CyberMind
chmod +x docker/sandbox/*.sh
mkdir -p sandbox-results

# Build, start lab, run all attacks, write report
bash docker/sandbox/test-all.sh
```

Or step by step:

```bash
# 1) Start lab
docker compose -f docker-compose.sandbox.yml up -d --build

# 2) Watch flask logs (honeypot bind + scan)
docker compose -f docker-compose.sandbox.yml logs -f flask

# 3) Run full attack suite (other terminal)
docker compose -f docker-compose.sandbox.yml exec attacker bash /attacks/run_attacks.sh

# 4) Read results on host
ls -la sandbox-results/
jq . sandbox-results/sandbox_report_*.json | less
```

Dashboard: http://localhost:5173  

For login credentials, check `docker compose … logs auth` (demo user is typically `admin`).

Full instructions: **[sandbox/DEPLOY_AND_ATTACK_GUIDE.md](./sandbox/DEPLOY_AND_ATTACK_GUIDE.md)**.

---

## What the suite tests

| # | Attack | Tool | Expected CyberMind signal |
|---|--------|------|---------------------------|
| 1 | Port scan | `nmap -sS` | scan / `port_scan` |
| 2 | Honeypot probes | `nc` → 2222,2323,8080,3390,2121,3307 | honeypot logs |
| 3 | SSH brute | `hydra` → :2222 | `brute_force` + honeypot |
| 4 | SYN flood | `hping3 --flood` | `ddos` / flood traffic |
| 5 | IDS signatures | `POST /api/analyze` | nmap, sqlmap, XSS, ransomware, etc. |
| 6 | Demo ingest | `POST /api/demo/attack-sim` | detection record |

After attacks it snapshots: honeypot status/logs/summary, blacklist, firewall, stats, traffic, logs, ollama.

---

## Interactive attacker shell

```bash
docker compose -f docker-compose.sandbox.yml exec attacker bash

# Manual examples inside the container:
nmap -sS -p 1-1000 flask
nc -v flask 2222
hydra -l admin -P <(printf 'admin\npassword\n') ssh://flask:2222 -t 4
timeout 5 hping3 -S --flood -p 8080 flask
curl -s http://flask:5000/api/honeypot/logs | jq .
```

---

## Collect results without re-attacking

```bash
docker compose -f docker-compose.sandbox.yml exec attacker bash /attacks/collect_results.sh
ls -la sandbox-results/snapshot_*.json
```

---

## Optional: Ollama AI translator

```bash
docker compose -f docker-compose.sandbox.yml --profile ai up -d
docker exec -it cm-ollama ollama pull mistral
```

Flask is already pointed at `http://ollama:11434` when that service is up.

---

## Stop / reset

```bash
# Stop containers
docker compose -f docker-compose.sandbox.yml down

# Stop + wipe flask data volume
docker compose -f docker-compose.sandbox.yml down -v

# Clear previous reports
rm -rf sandbox-results/*
```

---

## Notes / limits in Docker

| Feature | Sandbox behavior |
|---------|------------------|
| Live packet capture | Enabled (`privileged` + `NET_RAW`). Scapy falls back to `eth0` inside Linux containers. |
| Honeypots | Bound inside `flask`; also published to host for optional host-side probes. |
| IP blacklist / iptables | Works inside the flask container network namespace (does not touch your Mac firewall). |
| Kill switch | Isolates the container network path — safe for lab; avoid if you need host net. |
| Frontend APIs | Browser uses `localhost:5000` / `localhost:3001` (published ports). |
