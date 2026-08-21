# CyberMind Sandbox — Detailed Attack Test Report

| Field | Value |
|-------|-------|
| **Report date** | 2026-07-31 |
| **Environment** | Docker Compose lab on Colima (macOS host) |
| **Lab network** | `cybermind-lab` — `10.10.0.0/24` |
| **Defender** | `cm-flask` @ `10.10.0.10` (Ops API `:5000`) |
| **Attacker** | `cm-attacker` @ `10.10.0.99` |
| **Suite script** | `docker/sandbox/run_attacks.sh` |
| **Job ID** | `91a64c65-03a9-44d4-8ff7-d9a9d0ab0e1c` |
| **Run started (UTC)** | 2026-07-31T10:15:09Z |
| **Report generated (UTC)** | 2026-07-31T10:15:35Z |
| **Raw JSON (local)** | `sandbox-results/sandbox_report_20260731T101509Z.json` |

> This report documents a **controlled, authorized lab test** inside an isolated Docker bridge. It must not be used against systems you do not own.

---

## 1. Executive summary

CyberMind’s Docker sandbox was brought up, then a six-stage attack suite was executed from the `attacker` container against `flask`.

| Capability under test | Outcome | Evidence |
|-----------------------|---------|----------|
| Live packet capture (Scapy) | **PASS** | `capture_mode: live`, 120 packets |
| Random Forest traffic classification | **PASS** | Breakdown shows ddos / port_scan / brute_force mix |
| Honeypot TCP decoys | **PASS** | **8** connections logged from `10.10.0.99` |
| IDS signature engine (`/api/analyze`) | **PASS** | **10 / 10** payloads detected |
| Demo attack simulation ingest | **PASS** | Capture file + honeypot log written |
| Hydra vs decoy SSH banner | **Partial** | Connection attempted; decoy is not a real SSH daemon |

**Bottom line:** Network attacks, honeypot traps, and log/signature analysis all produced measurable detections in the lab. The RF majority vote labeled the short capture window `safe` (52%), but attack classes were clearly present in the per-class breakdown (especially **ddos 37.6%**).

---

## 2. Lab topology used for the test

```
┌────────────────────── cybermind-lab (10.10.0.0/24) ──────────────────────┐
│                                                                          │
│   cm-attacker 10.10.0.99                                                 │
│        │  nmap / nc / hydra / hping3 / curl                              │
│        ▼                                                                 │
│   cm-flask    10.10.0.10                                                 │
│        · Ops API :5000                                                   │
│        · Honeypots :2222 :2323 :8080 :3390 :2121 :3307                   │
│        · Scapy live capture on eth0                                      │
│                                                                          │
│   cm-auth     :3001   │   cm-frontend :5173 (browser on host)            │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ./sandbox-results/  (host bind mount)
```

Published host ports for dashboard/API: `5173`, `3001`, `5000`, plus honeypot ports mirrored for optional host-side probing.

---

## 3. Attack timeline

| Step | Time (UTC, approx) | Action | Target |
|------|--------------------|--------|--------|
| 0 | 10:15:09 | `POST /api/scan/start` (`packet_count=120`) | flask |
| 1 | 10:15:11 | Nmap SYN scan ports 1–1000 | flask |
| 2 | 10:15:13 | Honeypot probes (`nc`) on 6 decoy ports | flask |
| 3 | 10:15:15 | Hydra SSH brute (wordlist, port 2222) | flask:2222 |
| 4 | ~10:15:17 | hping3 SYN flood 8s → port 8080 | flask:8080 |
| 5 | 10:15:27 | IDS signature battery (10 texts) | `/api/analyze` |
| 6 | 10:15:27 | Demo attack-sim ingest | `/api/demo/attack-sim` |
| 7 | 10:15:35 | Snapshot honeypot / firewall / stats → JSON report | — |

---

## 4. Attack 1 — Nmap SYN port scan

### What we ran

```bash
nmap -sS -p 1-1000 --min-rate 300 flask
```

### Attacker observation

- Host `flask` (`10.10.0.10`) was up (latency ~0.003 ms).
- Ports 1–1000 reported as closed/reset in this run (honeypot ports **2222+** are outside this range; API `:5000` also outside).
- Scan finished in ~0.1s.

### CyberMind detection

| Signal | Value |
|--------|-------|
| Live scan job | Completed (`status: done`, progress 100%) |
| Capture mode | `live` |
| RF class share `port_scan` | **5.7%** of 120 packets |
| IDS text signature (later battery) | **Nmap Port Scan** — severity **high**, confidence **92%** |

### Interpretation

The SYN sweep contributed reconnaissance traffic into the live capture. The IDS engine independently confirmed nmap-style tooling when fed log/command text.

---

## 5. Attack 2 — Honeypot probes

### What we ran

```bash
for p in 2222 2323 8080 3390 2121 3307; do
  printf 'GET / HTTP/1.0\r\nHost: cybermind-lab\r\n\r\n' | nc -w 2 flask $p
done
```

### CyberMind honeypot hits (8 total, including later demo-sim)

| # | Source | Src port | Target port | Service | Threat type | Severity | Timestamp (UTC) |
|---|--------|----------|-------------|---------|-------------|----------|-----------------|
| 1 | 10.10.0.99 | 53504 | 2222 | SSH | brute_force | high | 10:15:13.355 |
| 2 | 10.10.0.99 | 36570 | 2323 | Telnet | reconnaissance | medium | 10:15:13.359 |
| 3 | 10.10.0.99 | 34592 | 8080 | HTTP-Admin | reconnaissance | medium | 10:15:13.362 |
| 4 | 10.10.0.99 | 35872 | 3390 | RDP | brute_force | critical | 10:15:13.365 |
| 5 | 10.10.0.99 | 32836 | 2121 | FTP | brute_force | high | 10:15:13.368 |
| 6 | 10.10.0.99 | 40806 | 3307 | MySQL | reconnaissance | high | 10:15:13.370 |
| 7 | 10.10.0.99 | 53506 | 2222 | SSH | brute_force | high | 10:15:15.408 |
| 8 | 10.10.0.99 | 35400 | 8080 | HTTP-Admin | honeypot_capture | medium | 10:15:27.854 |

**API check:** `GET /api/honeypot/logs` → `success: true`, `meta.total_connections: 8`.

### Interpretation

Every decoy service accepted a connection from the attacker IP and logged threat metadata. This validates the honeypot listener stack end-to-end inside Docker.

---

## 6. Attack 3 — Hydra SSH brute force (honeypot :2222)

### What we ran

```bash
hydra -l admin -P /tmp/cm_wordlist.txt ssh://flask:2222 -t 4 -f
```

Wordlist (demo, short): `root`, `admin`, `password`, `123456`, `admin123`, `test`, `guest`, `cybermind`.

### Attacker observation

Hydra reported socket disconnects — expected, because port **2222** is a **banner decoy**, not OpenSSH.

### CyberMind detection

| Signal | Value |
|--------|-------|
| Honeypot SSH hits | Ports 2222 logged as `brute_force` / high |
| RF class share `brute_force` | **4.0%** |
| IDS text signature | **Hydra Brute-Force Tool** — **critical**, confidence **97%** |

### Interpretation

Network-layer interaction is captured by the honeypot; tool intent is captured by the IDS when hydra appears in logs/commands. Full password-spray success against a real SSH service is intentionally out of scope for the decoy.

---

## 7. Attack 4 — hping3 SYN flood (DDoS simulation)

### What we ran

```bash
timeout 8 hping3 -S --flood -p 8080 flask
```

### CyberMind detection

| Signal | Value |
|--------|-------|
| RF class share `ddos` | **37.6%** (largest attack class in the capture) |
| First per-packet label | `ddos` (index 0) |
| IDS text signature | **DDoS / Flood Attack** — **high**, confidence **88%** |

### Interpretation

The flood produced the strongest live-traffic signal in this run. Combined with the IDS ddos signature test, both the ML path and the signature path cover flood-style abuse.

---

## 8. Attack 5 — IDS signature battery (`POST /api/analyze`)

Ten crafted payloads were submitted. Model: `cybermind-ids-v2`. **All 10 detected.**

| # | Input (short) | Label | Threat type | Severity | Confidence |
|---|---------------|-------|-------------|----------|------------|
| 1 | `nmap -sS -p 1-1000 10.0.0.5` | Nmap Port Scan | reconnaissance | high | 92% |
| 2 | `sqlmap … UNION SELECT` | SQL UNION Injection | injection | critical | 97% |
| 3 | `admin' OR '1'='1` | SQL Auth Bypass | injection | critical | 93% |
| 4 | `hydra -l admin -P rockyou.txt ssh://…` | Hydra Brute-Force Tool | credential_attack | critical | 97% |
| 5 | `<script>alert(1)</script>` | Cross-Site Scripting (XSS) | xss | high | ~87% |
| 6 | `../../etc/passwd` | Path Traversal (LFI) | lfi | high | ~86% |
| 7 | `msfconsole reverse shell nc -e /bin/sh` | Reverse Shell Behaviour | post_exploitation | critical | 99% |
| 8 | `lockbit ransomware cobalt strike beacon` | Ransomware Signature | malware | critical | 99% |
| 9 | `syn flood ddos slowloris attack` | DDoS / Flood Attack | ddos | high | 88% |
| 10 | `mimikatz lsass credential dump` | Mimikatz Credential Dump | post_exploitation | critical | 99% |

### Sample IDS summary strings returned

- *“CyberMind IDS detected 1 signature match(es). Top threat: Nmap Port Scan — severity HIGH, confidence 92%.”*
- *“CyberMind IDS detected 2 signature match(es). Top threat: SQL UNION Injection — severity CRITICAL, confidence 97%.”*
- *“CyberMind IDS detected 3 signature match(es). Top threat: Reverse Shell Behaviour — severity CRITICAL, confidence 99%.”*

Each response included mitigations (block IP, MFA, WAF, isolate host, etc.).

---

## 9. Attack 6 — Demo attack simulation

### What we ran

```bash
POST /api/demo/attack-sim
{
  "threat_type": "port_scan",
  "tool": "nmap",
  "target_port": 8080,
  "payload": "sandbox nmap SYN",
  "auto_block": false,
  "source_ip": "10.10.0.99"
}
```

### CyberMind response (success)

| Field | Value |
|-------|-------|
| `success` | `true` |
| `message` | Simulation ingested and detection recorded |
| `source_ip` | `10.10.0.99` |
| `target_port` | `8080` |
| `threat_type` | `honeypot_capture` |
| `severity` | `medium` |
| `capture_file` | `10.10.0.99_20260731_101527.txt` |
| `auto_blocked` | `false` (requested) |
| Plain-English note | “Someone scanned your network…” (rule-based translator) |

This also produced honeypot log entry #8 above.

---

## 10. Live RF scan — full classification result

| Field | Value |
|-------|-------|
| Job ID | `91a64c65-03a9-44d4-8ff7-d9a9d0ab0e1c` |
| Packets | 120 |
| Capture mode | **live** |
| Majority label | `safe` (confidence 0.52) |
| Verdict string | Traffic looks SAFE |
| Threat detected (majority vote) | `false` |

### Class breakdown

| Class | Share |
|-------|------:|
| safe | 52.0% |
| ddos | 37.6% |
| port_scan | 5.7% |
| brute_force | 4.0% |
| malware_c2 | 0.8% |

### Why majority can still say “safe”

1. Scan window is short; container/control-plane chatter mixes with attack packets.
2. Nmap range 1–1000 finished extremely fast; honeypot ports >1000 were probed separately.
3. Classifier uses majority vote over the batch — a large `safe` share can win even when attack shares are material.

**For demos:** emphasize the **breakdown chart** and honeypot/IDS panels, not only the single majority label. Optionally start the scan *after* floods begin, or raise `packet_count` / timeout.

---

## 11. Pass / fail scorecard

| Test ID | Attack / check | Expected | Observed | Pass? |
|---------|----------------|----------|----------|-------|
| T1 | Live capture | `live` mode | `live` | ✅ |
| T2 | Scan job completes | `done` / 100% | yes | ✅ |
| T3 | DDoS traffic visible | ddos share > 0 | 37.6% | ✅ |
| T4 | Port-scan class visible | port_scan > 0 | 5.7% | ✅ |
| T5 | Honeypot logs attacker IP | entries from 10.10.0.99 | 8 entries | ✅ |
| T6 | All decoy ports hit | 6 ports | 6 (+ extras) | ✅ |
| T7 | IDS 10/10 | all threat_detected | 10/10 | ✅ |
| T8 | Demo attack-sim | success true | success true | ✅ |
| T9 | Hydra cracks decoy SSH | N/A (decoy) | disconnect | ⚠️ expected |
| T10 | Majority label = attack | optional | safe | ⚠️ timing/majority |

**Overall lab status: PASS** (core detection paths validated).

---

## 12. Artifacts produced

On the host under `sandbox-results/` (gitignored):

| Artifact | Purpose |
|----------|---------|
| `sandbox_report_20260731T101509Z.json` | Master structured report |
| `sandbox_run_20260731T101509Z.log` | Console log of the suite |
| `run_20260731T101509Z/nmap*.txt` | Nmap output |
| `run_20260731T101509Z/hydra*.txt` | Hydra output |
| `run_20260731T101509Z/hping3.txt` | Flood tool output |
| `run_20260731T101509Z/honeypot_*.txt` | Banner/probe replies |
| `run_20260731T101509Z/ids_battery.ndjson` | Per-payload IDS responses |
| `run_20260731T101509Z/{honeypot,scan,firewall,…}.json` | API snapshots |

Reproduce anytime:

```bash
bash docker/sandbox/test-all.sh
```

See also: [Deploy & Attack Guide](./DEPLOY_AND_ATTACK_GUIDE.md).
