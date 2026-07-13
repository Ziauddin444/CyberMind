# CyberMind — Professor Demo Script

**Duration:** ~10 minutes  
**Setup:** Mac running CyberMind + Kali Linux on same network

---

## Before the Demo

1. On Mac, open Terminal and run:
   ```bash
   sudo bash demo_launch.sh
   ```
2. Wait for "CyberMind is RUNNING" message
3. Open browser to `http://localhost:5173`
4. Login (default: any credentials that work)
5. Note the Mac's IP shown in the terminal output

---

## Demo Flow

### Step 1 — Show the Dashboard (1 min)

> *"This is CyberMind Sentinel — a 3-layer AI-powered intrusion detection system. The dashboard shows real-time security status."*

- Point to **Safety Score** (pulls from real scan history via Flask SQLite)
- Point to **Threat Count** (live threats detected today)
- Point to **Live Feed** panel on the right — shows real security events
- Point to the Mac IP in the top stats bar

---

### Step 2 — System Architecture (1 min)

> *"CyberMind has three layers:"*

| Layer | Component | What it does |
|-------|-----------|--------------|
| Layer 1 | Scapy Packet Scanner | Captures raw network packets |
| Layer 2 | RF Classifier (sklearn) | Classifies traffic as normal/attack |
| Layer 3 | Ollama Mistral LLM | Translates technical findings to plain English |

---

### Step 3 — Launch Kali Attack (2 min)

> *"Now I'll launch real attacks from Kali Linux. Watch the system detect them."*

**On Kali Linux terminal:**
```bash
export MAC_IP=<the Mac IP from terminal>
bash kali_attack.sh
```

This runs 4 attacks:
1. Nmap port scan → shows as `port_scan`
2. SSH brute force on honeypot → shows as `brute_force`
3. SYN flood → shows as `ddos`
4. Direct honeypot connections → captured by honeypot

While Kali is running, point to the **Live Feed** on the dashboard — blocked IP events will appear in real-time.

---

### Step 4 — Capture & Analyze Traffic (2 min)

> *"Now let's run the AI scanner on the traffic Kali just generated."*

1. Click **Analyze** in the left sidebar
2. Click **START SCAN** (or set packet count to 200 first)
3. Watch the scan phases:
   - "Scapy listener active" — capturing packets
   - "Packets captured — running RF model" — AI classification
4. The result card shows:
   - Attack label (`PORT_SCAN`, `BRUTE_FORCE`, `DDOS`, etc.)
   - Confidence percentage
   - Severity level
   - AI explanation (Ollama Mistral if running, rule-based fallback if not)

> *"The RF model was trained on the NSL-KDD dataset with over 125,000 network flow samples."*

---

### Step 5 — Show Honeypot (1 min)

> *"The honeypot decoy network creates fake services to trap attackers."*

1. Click **Honeypot** in the left sidebar
2. Show the connection count — Kali's probes are logged here
3. Show capture files in the list — each connection saves an evidence file
4. Point to ports: SSH (2222), Telnet (2323), MySQL (3307), HTTP (8080), FTP (2121)

> *"Any attacker connecting to these fake ports gets fingerprinted and their payload is saved as evidence."*

---

### Step 6 — Block the Attacker (1 min)

> *"With one click, we can permanently block the attacker's IP."*

1. Go back to **Dashboard**
2. Find the Kali IP in the **Blocked IPs** panel
3. Or click the **BLOCK IP** button and enter Kali's IP manually
4. Show the IP appears in the blocked list with timestamp

---

### Step 7 — View Security Logs (1 min)

> *"Every scan, every honeypot connection, every blocked IP is logged for forensic analysis."*

1. Click **Logs** in the left sidebar
2. Show the scan history table with:
   - Timestamp
   - Attack type detected
   - Confidence percentage
   - Whether threat was detected
3. The feed auto-refreshes every 3 seconds

---

### Step 8 — AI Threat Translation (1 min)

> *"The AI Analyzer screen lets you paste any log or command and get an analysis."*

1. Click **Analyze** → scroll to **AI Threat Analyzer** section
2. Paste: `nmap -sS -p 1-1000 192.168.1.1`
3. Click **Analyze**
4. Show the classification and plain-English explanation

---

## Key Technical Points to Mention

- **Not simulated:** Real Scapy packet capture, real network traffic from Kali
- **Real ML:** scikit-learn RandomForest trained on NSL-KDD (125K samples, 41 features)
- **3-layer architecture:** Scapy → RF classifier → LLM explanation
- **Honeypot:** TCP socket listeners on standard attack ports
- **Persistence:** SQLite logs every scan; blocklist in JSON
- **Dual backend:** Flask (security ops) + Node.js (auth/user management)

---

## If Something Goes Wrong

| Problem | Fix |
|---------|-----|
| "Simulated mode" warning | Run with `sudo bash demo_launch.sh` |
| No packets detected | Ensure Kali is on same subnet |
| Flask not responding | Check terminal: `python3 backend_flask/run.py` |
| Safety score shows "--" | Run at least one scan first |
| Honeypot shows 0 connections | Run `nc <MAC_IP> 2222` from Kali |
