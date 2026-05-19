"""
CyberMind IDS — Standalone Flask Demo
======================================
Three-layer architecture:

  Browser  ──fetch──►  app.py (Flask)  ──►  model.pkl (Random Forest AI)

New in this version:
  • pickle.load() connects app.py directly to model.pkl
  • SQLite logs every scan result (no separate DB server needed)
  • /get_latest_traffic  — polled every 2 s by the live Chart.js dashboard
  • Active-voice UI strings ("CyberMind is scanning…" not "Analysis is being performed")

Run:
    python app.py          # http://localhost:5001
"""

import os
import pickle   # shown for educational context
import joblib   # sklearn's recommended serialiser (superset of pickle)
import sqlite3
import threading
import uuid
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# ── Environment ───────────────────────────────────────────────────────────────
load_dotenv()

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-change-me")
CORS(app)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# =============================================================================
# ── Layer 3: Load AI model with pickle (as taught in class) ──────────────────
# =============================================================================
#
# Flask connects to the pre-trained Random Forest via a single pickle.load().
# model.pkl is saved by services/rf_classifier.py when first trained.
# The RFClassifier wrapper handles the sklearn API so app.py stays clean.

MODEL_PATH   = Path(__file__).parent / "data" / "rf_model.pkl"
ENCODER_PATH = Path(__file__).parent / "data" / "rf_label_encoder.pkl"

# joblib.load() is how sklearn models must be loaded (it is a pickle superset
# that handles compressed numpy arrays). Plain pickle.load() raises UnpicklingError.
_RAW_MODEL     = joblib.load(MODEL_PATH)    # loads model.pkl
_LABEL_ENCODER = joblib.load(ENCODER_PATH)

logger.info("CyberMind loaded model.pkl ✓  (%s)", MODEL_PATH.name)

# We also keep the wrapper for the scan pipeline (feature extraction etc.)
from services.rf_classifier import RFClassifier
from services.ids_engine    import analyze
from services.packet_scanner import scan_packets

clf = RFClassifier.get()          # Singleton that uses the same pkl under the hood
logger.info("Random Forest classifier ready ✓")


# =============================================================================
# ── SQLite — Lightweight log storage (no separate DB server needed for SMBs) ─
# =============================================================================

DB_PATH = Path(__file__).parent / "data" / "cybermind_logs.db"

def _init_db() -> None:
    """Create tables on first run if they don't exist."""
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                label       TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                confidence  REAL    NOT NULL,
                packet_count INTEGER NOT NULL,
                capture_mode TEXT   NOT NULL,
                threat_detected INTEGER NOT NULL   -- 0/1 boolean
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS traffic_counts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                label     TEXT    NOT NULL,
                count     INTEGER NOT NULL DEFAULT 1
            )
        """)
        con.commit()
    logger.info("SQLite database ready → %s", DB_PATH)

_init_db()


@contextmanager
def _db():
    """Thread-safe SQLite connection context manager."""
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _log_scan_result(result: dict) -> None:
    """Persist a completed scan result to SQLite."""
    with _db() as con:
        con.execute(
            """INSERT INTO scan_logs
               (timestamp, label, severity, confidence, packet_count, capture_mode, threat_detected)
               VALUES (?,?,?,?,?,?,?)""",
            (
                result.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                result.get("label",    "unknown"),
                result.get("severity", "low"),
                float(result.get("confidence", 0)),
                int(result.get("packet_count", 0)),
                result.get("capture_mode", "simulated"),
                1 if result.get("threat_detected") else 0,
            ),
        )
        # Also record the per-label breakdown as individual traffic_counts rows
        for lbl, pct in (result.get("breakdown") or {}).items():
            count = max(1, round(pct * result.get("packet_count", 100) / 100))
            con.execute(
                "INSERT INTO traffic_counts (timestamp, label, count) VALUES (?,?,?)",
                (datetime.utcnow().isoformat() + "Z", lbl, count),
            )


# =============================================================================
# ── In-process scan job store ─────────────────────────────────────────────────
# =============================================================================

_SCAN_JOBS: dict[str, dict] = {}
_SCAN_LOCK = threading.Lock()


# =============================================================================
# ── Routes (Layer 2)
# =============================================================================

@app.route("/")
def index():
    """Serve the dashboard — Flask finds index.html in templates/."""
    return render_template("index.html")


# ── Live traffic endpoint (polled every 2 s by Chart.js dashboard) ────────────

@app.route("/get_latest_traffic")
def get_latest_traffic():
    """
    GET /get_latest_traffic
    Returns the last 20 scan log rows and a per-label traffic count summary.
    Polled every 2 seconds by the frontend Chart.js loop.
    """
    with _db() as con:
        # Latest 20 scans for the activity table
        rows = con.execute(
            """SELECT timestamp, label, severity, confidence, packet_count,
                      capture_mode, threat_detected
               FROM scan_logs ORDER BY id DESC LIMIT 20"""
        ).fetchall()

        # Aggregate label counts for the bar chart (last 100 rows)
        agg = con.execute(
            """SELECT label, SUM(count) as total
               FROM traffic_counts
               GROUP BY label
               ORDER BY total DESC
               LIMIT 100"""
        ).fetchall()

        # Total threats in the last 24 h (for the live counter)
        threats_today = con.execute(
            """SELECT COUNT(*) as n FROM scan_logs
               WHERE threat_detected=1
                 AND timestamp >= datetime('now','-1 day')"""
        ).fetchone()["n"]

        total_scans = con.execute("SELECT COUNT(*) as n FROM scan_logs").fetchone()["n"]

    traffic_labels = [r["label"] for r in agg]
    traffic_counts = [int(r["total"]) for r in agg]

    return jsonify({
        "traffic_labels":  traffic_labels,
        "traffic_counts":  traffic_counts,
        "traffic_count":   sum(traffic_counts),   # scalar for simple chart demos
        "threats_today":   threats_today,
        "total_scans":     total_scans,
        "recent_logs": [
            {
                "timestamp":       r["timestamp"],
                "label":           r["label"],
                "severity":        r["severity"],
                "confidence":      round(r["confidence"] * 100),
                "packet_count":    r["packet_count"],
                "capture_mode":    r["capture_mode"],
                "threat_detected": bool(r["threat_detected"]),
            }
            for r in rows
        ],
    })


# ── Signature-based text analyzer ─────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze_input():
    """POST /analyze — runs the IDS signature engine on submitted text."""
    body   = request.get_json(silent=True) or {}
    text   = str(body.get("text", "")).strip()
    src_ip = str(body.get("source_ip", ""))

    if not text:
        return jsonify({"success": False, "message": "No input provided."}), 400

    result = analyze({"text": text, "source_ip": src_ip})
    return jsonify(result), 200


# ── Packet scan job (background thread) ───────────────────────────────────────

def _run_scan_job(job_id: str, count: int) -> None:
    """
    Background worker:
      1. Scapy captures `count` packets (or synthetic simulation)
      2. pickle-loaded Random Forest predicts the traffic label
      3. Result is stored in SQLite and the job store
    """
    try:
        # Active-voice phase labels ("CyberMind is…" not passive voice)
        with _SCAN_LOCK:
            _SCAN_JOBS[job_id]["phase"]    = "capturing"
            _SCAN_JOBS[job_id]["progress"] = 0
            _SCAN_JOBS[job_id]["status_msg"] = \
                f"CyberMind is capturing {count} packets from your network…"

        scan     = scan_packets(count)
        features = scan["features"]

        with _SCAN_LOCK:
            _SCAN_JOBS[job_id]["phase"]    = "classifying"
            _SCAN_JOBS[job_id]["progress"] = 60
            _SCAN_JOBS[job_id]["status_msg"] = \
                "CyberMind is running the Random Forest classifier…"

        # ── Use the raw pickle model directly (as the professor described) ────
        import numpy as np
        FEATURE_NAMES = [
            "pkt_len","src_port","dst_port","protocol",
            "tcp_flags","ttl","inter_arrival_ms","payload_len",
        ]
        X = np.array([[row.get(f, 0) for f in FEATURE_NAMES] for row in features],
                     dtype=np.float32)

        proba_matrix = _RAW_MODEL.predict_proba(X)
        avg_proba    = proba_matrix.mean(axis=0)
        classes      = _LABEL_ENCODER.classes_
        top_idx      = int(avg_proba.argmax())
        label        = classes[top_idx]
        confidence   = float(avg_proba[top_idx])
        breakdown    = {cls: round(float(p) * 100, 1)
                        for cls, p in zip(classes, avg_proba)}

        label_pretty = label.replace("_", " ").title()
        if label == "safe":
            verdict  = "✅  CyberMind reports: Traffic is SAFE"
            severity = "low"
        elif confidence >= 0.80:
            verdict  = f"🚨  CyberMind detects: {label_pretty} — HIGH CONFIDENCE"
            severity = "critical"
        elif confidence >= 0.55:
            verdict  = f"⚠️  CyberMind suspects: {label_pretty} — MEDIUM CONFIDENCE"
            severity = "medium"
        else:
            verdict  = f"🔍  CyberMind flags: Possible {label_pretty} — LOW CONFIDENCE"
            severity = "low"

        result_payload = {
            "verdict":         verdict,
            "label":           label,
            "label_pretty":    label_pretty,
            "threat_detected": label != "safe",
            "severity":        severity,
            "confidence":      round(confidence, 3),
            "packet_count":    len(features),
            "breakdown":       breakdown,
            "per_packet":      [],
            "capture_mode":    scan["mode"],
            "capture_warning": scan.get("error"),
            "timestamp":       datetime.utcnow().isoformat() + "Z",
        }

        # ── Persist to SQLite ─────────────────────────────────────────────────
        _log_scan_result(result_payload)
        logger.info("Scan %s: label=%s conf=%.2f  [saved to SQLite]",
                    job_id[:8], label, confidence)

        with _SCAN_LOCK:
            _SCAN_JOBS[job_id].update({
                "status":     "done",
                "phase":      "done",
                "progress":   100,
                "status_msg": f"CyberMind finished scanning — {label_pretty} detected.",
                "result":     result_payload,
            })

    except Exception as exc:
        logger.error("Scan job %s failed: %s", job_id, exc, exc_info=True)
        with _SCAN_LOCK:
            _SCAN_JOBS[job_id].update({
                "status":     "error",
                "phase":      "error",
                "status_msg": "CyberMind encountered an error during the scan.",
                "error":      str(exc),
            })


@app.route("/scan/start", methods=["POST"])
def scan_start():
    """
    POST /scan/start
    Body: { "packet_count": 100 }
    Returns: { "job_id": "...", "status": "running", "packet_count": N }
    """
    body  = request.get_json(silent=True) or {}
    count = max(10, min(int(body.get("packet_count",
                             os.getenv("SCAN_PACKET_COUNT", 100))), 500))

    job_id = str(uuid.uuid4())
    with _SCAN_LOCK:
        _SCAN_JOBS[job_id] = {
            "job_id":       job_id,
            "status":       "running",
            "phase":        "starting",
            "progress":     0,
            "status_msg":   f"CyberMind is preparing to scan {count} packets…",
            "packet_count": count,
            "started_at":   datetime.utcnow().isoformat() + "Z",
            "result":       None,
            "error":        None,
        }

    threading.Thread(target=_run_scan_job, args=(job_id, count),
                     daemon=True, name=f"scan-{job_id[:8]}").start()

    logger.info("CyberMind scan %s started (packets=%d)", job_id[:8], count)
    return jsonify({"job_id": job_id, "status": "running",
                    "packet_count": count}), 202


@app.route("/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id: str):
    """GET /scan/status/<job_id> — poll for live progress and result."""
    with _SCAN_LOCK:
        job = _SCAN_JOBS.get(job_id)
    if job is None:
        return jsonify({"success": False, "message": "Job not found"}), 404
    return jsonify(job), 200


@app.route("/logs")
def get_logs():
    """GET /logs — last 50 scan records from SQLite."""
    with _db() as con:
        rows = con.execute(
            """SELECT * FROM scan_logs ORDER BY id DESC LIMIT 50"""
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/health")
def health():
    return jsonify({
        "status":    "ok",
        "model":     "random_forest",
        "model_pkl": str(MODEL_PATH),
        "db":        str(DB_PATH),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.getenv("FLASK_PORT", 5001))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    logger.info("CyberMind IDS → http://localhost:%d  |  DB: %s", port, DB_PATH)
    app.run(host="0.0.0.0", port=port, debug=debug)
