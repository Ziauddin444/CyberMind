# CyberMind IDS — Standalone Flask Demo

A clean, professor-friendly version of the CyberMind Intrusion Detection System.  
Built with the exact Flask folder structure taught in class.

```
cybermind_demo/
├── app.py              ← Main Flask backend (Layer 2)
├── model.pkl           ← Trained Random Forest model (symlink to data/)
├── requirements.txt    ← Flask, Scapy, scikit-learn, etc.
├── .env.example        ← API key template (copy to .env)
├── static/
│   ├── css/styles.css  ← Vanilla CSS dark UI
│   └── js/main.js      ← Async fetch logic (Layer 1)
├── templates/
│   └── index.html      ← Dashboard (Jinja2 template)
├── services/           ← AI Layer (Layer 3 — no Flask imports)
│   ├── rf_classifier.py   ← Random Forest classifier
│   ├── packet_scanner.py  ← Scapy live capture
│   └── ids_engine.py      ← Signature-based IDS
└── data/
    ├── rf_model.pkl        ← Saved model (auto-trained on first run)
    └── rf_label_encoder.pkl
```

## How to Run (VS Code Terminal)

```bash
# 1. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy environment file
cp .env.example .env

# 4. Start the server
python app.py
```

Open your browser at **http://localhost:5001**

## Three-Layer Architecture

| Layer | What It Does | File |
|-------|-------------|------|
| **Layer 1 — Frontend** | Dashboard UI, fetch() calls, live progress bar | `templates/index.html` + `static/js/main.js` |
| **Layer 2 — Flask Backend** | Routes: `/` `/scan/start` `/scan/status` `/analyze` | `app.py` |
| **Layer 3 — AI Engine** | Scapy capture → Random Forest classification | `services/` |

## Live Scan Flow

```
Browser clicks "START SCAN"
        │
        ▼ POST /scan/start  (returns job_id instantly)
    Flask spawns a background thread
        │
        ├── packet_scanner.py  →  Scapy sniffs N packets
        └── rf_classifier.py   →  Random Forest predicts label
        │
        ▼ GET /scan/status/<job_id>  (browser polls every 1s)
    Progress bar updates live (0% → 100%)
        │
        ▼ Result card renders:
    "🚨 Brute Force DETECTED — HIGH CONFIDENCE"
```

## Attack Types Detected

- ✅ Safe traffic
- 🔴 Brute Force (SSH/RDP)
- 🟠 Port Scan
- 🌹 DDoS / Flood
- 🟣 SQL Injection
- 🟡 Malware C2 Beacon
