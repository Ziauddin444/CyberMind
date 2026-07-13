# Implementation Plan: Finish CyberMind for Professor Demo

## Goal

Finish the project by **reducing scope to 5 working features**, polishing the dashboard, and preparing a live Kali Linux attack demo that proves the system scans real-time network data.

---

## Scope Reduction: What to KEEP vs CUT

### ✅ KEEP (These 5 Features Will Be Demo-Ready)

| # | Feature | Screen | Status | Works? |
|---|---------|--------|--------|--------|
| 1 | **AI Threat Analyzer** — Paste a log/command → IDS engine classifies it | Analyze screen | Backend working | ✅ Yes |
| 2 | **Live Network Scan** — Scapy captures packets → RF model classifies | Analyze screen | Fixed (pcap/live) | ✅ Yes |
| 3 | **Honeypot Decoy Network** — Fake ports trap attackers | Honeypot screen + Dashboard tab | Ports fixed | ✅ Yes |
| 4 | **IP Blocking / Blacklist** — Block malicious IPs | Dashboard quick actions | Backend working | ✅ Yes |
| 5 | **Security Logs** — Scan history + threat timeline | Logs screen | Backend working | ✅ Yes |

### ❌ CUT or SIMPLIFY (Not Working / Not Needed for Demo)

| Feature | Problem | Action |
|---------|---------|--------|
| Fleet Monitor (device ping/netstat) | Shows hardcoded data, `perform_ping_sweep` fails without IPs | **Keep on dashboard but fill with real local data (mac IP)** |
| Phish Sandbox tab | Works but is minor — just URL checking | **Keep as-is, low priority** |
| Kill Switch | Needs sudo/pf firewall — risky to demo | **Keep button but don't demo it** |
| Admin panel | User management — not security-related | **Keep hidden, don't demo** |
| Settings page | Cosmetic only, no persistence | **Keep as-is** |
| Quarantine Device | UI-only, no real backend | **Keep button, don't focus on** |

---

## Step-by-Step Execution Plan

### Phase 1: Fix Core Pipeline (30 min)

#### Step 1.1 — Ensure Scan History is Stored and Displayed
The scan results are logged to SQLite via `_log_scan_to_db()`. Verify the `/api/logs` endpoint returns scan history and the Logs screen populates from it.

#### Step 1.2 — Wire Dashboard Stats to Real Data  
Currently dashboard shows hardcoded numbers (threat count: 2, fleet count: 3, safety score: 98.4%). Update these to pull from actual scan history and honeypot connection counts.

#### Step 1.3 — Fix Live Log Translation Feed
The "LIVE TRANSLATION" panel on dashboard currently shows hardcoded HTML entries. Wire it to show real scan results and honeypot connection events as they happen.

---

### Phase 2: Polish Dashboard (45 min)

#### Step 2.1 — Update Threat Count from Scan History
Make `#threat-count` show the real count of detected threats (non-safe scan results).

#### Step 2.2 — Update Fleet to Show Real Local Machine
Instead of hardcoded "3 devices", detect the actual machine and show it as the one protected device. This is honest and more impressive.

#### Step 2.3 — Update Safety Score from Actual Data
Calculate safety score = (safe scans / total scans) × 100. Show "--" if no scans yet.

#### Step 2.4 — Wire Honeypot Stats to Real Data
Pull from `/api/honeypot/status` to show actual honeypot listener count and connection count.

---

### Phase 3: Kali Linux Attack Demo Setup (45 min)

#### Step 3.1 — Create a Demo Script for the Professor

The demo will follow this sequence on your network:

```
YOUR MAC (CyberMind)              KALI LINUX (Attacker)
──────────────────                ─────────────────────
1. Start CyberMind (sudo)         
2. Dashboard shows "PROTECTED"    
3. Start traffic capture          
                                  4. Run nmap port scan
                                  5. Run hydra SSH brute force
                                  6. Run hping3 DDoS flood
7. Click "Start Scan"             
8. RF model detects attacks →     
   Shows "PORT SCAN" / "BRUTE_FORCE"
9. Show the AI analysis results
10. Block the Kali IP from dashboard
11. Show honeypot captured connections
```

#### Step 3.2 — Create a Kali Attack Script
Write a bash script for the Kali machine that runs multiple attacks against your Mac's IP. The professor can see the attacks being launched from Kali while CyberMind detects them.

#### Step 3.3 — Add a "Demo Mode" Startup 
Create a simple startup script that launches all 3 services (Flask, Node, Frontend) in one command for the demo.

---

### Phase 4: Demo Rehearsal & Final Polish (30 min)

#### Step 4.1 — Test Full Pipeline
- Start CyberMind
- Capture packets during Kali attack  
- Verify scan shows "live" mode + correct threat label
- Verify honeypot catches the connections
- Verify logs screen shows scan history

#### Step 4.2 — Add "System Architecture" Info to Dashboard
Add a small info section showing the 3-layer architecture diagram so the professor can see it's not just a firewall.

---

## Kali Linux Attack Commands (For Your Demo)

You'll need these installed on Kali:
```bash
# From Kali Linux terminal — targeting your Mac's IP
MAC_IP="192.168.x.x"  # your Mac's actual IP

# Attack 1: Port Scan (detected as "port_scan")
nmap -sS -p 1-1000 $MAC_IP

# Attack 2: SSH Brute Force (detected as "brute_force")  
# This will target your honeypot on port 2222
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$MAC_IP:2222 -t 4

# Attack 3: DDoS Simulation (detected as "ddos")
hping3 -S --flood -p 8080 $MAC_IP

# Attack 4: Connect to honeypot directly
nc $MAC_IP 2222    # SSH honeypot
nc $MAC_IP 2323    # Telnet honeypot
nc $MAC_IP 3307    # MySQL honeypot
```

---

## Estimated Timeline

| Phase | Task | Time |
|-------|------|------|
| Phase 1 | Fix core pipeline (scan → logs → dashboard) | 30 min |
| Phase 2 | Polish dashboard with real data | 45 min |
| Phase 3 | Kali attack demo setup + scripts | 45 min |
| Phase 4 | Test & final polish | 30 min |
| **Total** | | **~2.5 hours** |

---

## Open Questions

> [!IMPORTANT]
> **What is your Mac's IP address on the network where you'll demo?** I need this to configure the Kali attack script.

> [!IMPORTANT]  
> **Do you have Kali Linux ready?** Is it on the same network as your Mac? (VMware/VirtualBox or a separate laptop?)

> [!IMPORTANT]
> **When is the demo?** This helps me prioritize what to polish first.
