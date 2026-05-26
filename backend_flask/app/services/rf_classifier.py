"""
CyberMind RF Classifier — Layer 3 (AI Model)
=============================================
Random Forest that classifies network traffic as:
  safe | brute_force | port_scan | ddos | sql_injection | malware_c2

CAPSTONE REQUIREMENT: Trains on NSL-KDD dataset by default
============================================================
This implementation uses the NSL-KDD cybersecurity intrusion detection dataset
(https://www.unb.ca/cic/datasets/nsl-kdd.html) for model training. NSL-KDD provides:
  - Real network traffic data with 41 extracted features
  - ~125k training samples with labeled attack types
  - Industry-standard benchmark for IDS evaluation

To use synthetic data instead (dev/testing), set environment variable:
  export RF_CLASSIFIER_USE_SYNTHETIC=1

Model persistence: On first run, the model is trained and saved as:
  backend_flask/data/rf_model.pkl
Subsequent calls load the pre-trained model.

No Flask imports — pure Python / scikit-learn.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from .nsl_kdd_loader import load_nsl_kdd

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
USE_SYNTHETIC = os.getenv("RF_CLASSIFIER_USE_SYNTHETIC", "0").lower() in ("1", "true")

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
_DATA_DIR = _HERE.parent.parent / "data"       # backend_flask/data/
_MODEL_PATH = _DATA_DIR / "rf_model.pkl"
_ENCODER_PATH = _DATA_DIR / "rf_label_encoder.pkl"

# ── Feature names (must match packet_scanner.py extract_features()) ──────────
FEATURE_NAMES = [
    "pkt_len",          # total packet length in bytes
    "src_port",         # source port (0 if not TCP/UDP)
    "dst_port",         # destination port (0 if not TCP/UDP)
    "protocol",         # 6=TCP, 17=UDP, 1=ICMP, 0=other
    "tcp_flags",        # TCP flags as int (SYN=0x02, ACK=0x10, etc.)
    "ttl",              # Time To Live
    "inter_arrival_ms", # ms since previous packet in stream
    "payload_len",      # raw payload size in bytes
]

# ── Label definitions ─────────────────────────────────────────────────────────
LABELS = ["safe", "brute_force", "port_scan", "ddos", "sql_injection", "malware_c2"]


# =============================================================================
# Synthetic training data generator
# =============================================================================

def _generate_training_data(n_per_class: int = 400) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic but representative packet feature vectors.

    Returns
    -------
    X : ndarray of shape (n_samples, n_features)
    y : ndarray of shape (n_samples,) with string labels
    """
    rng = np.random.default_rng(42)
    X_parts, y_parts = [], []

    def _add(label: str, samples: np.ndarray) -> None:
        X_parts.append(samples)
        y_parts.append(np.full(len(samples), label))

    # ── Safe traffic ──────────────────────────────────────────────────────────
    n = n_per_class
    _add("safe", np.column_stack([
        rng.integers(40, 1500, n),          # pkt_len — normal range
        rng.integers(1024, 65535, n),       # src_port — ephemeral
        rng.choice([80, 443, 53, 8080, 25], n),  # dst_port — web/mail/dns
        rng.choice([6, 17, 1], n),          # protocol TCP/UDP/ICMP
        rng.choice([0x10, 0x18], n),        # flags — ACK, ACK+PSH
        rng.integers(50, 128, n),           # ttl
        rng.integers(20, 500, n),           # inter_arrival_ms — calm
        rng.integers(0, 1400, n),           # payload_len
    ]))

    # ── Brute-force SSH / RDP ─────────────────────────────────────────────────
    _add("brute_force", np.column_stack([
        rng.integers(40, 120, n),           # small packets (auth handshakes)
        rng.integers(1024, 65535, n),       # random src port
        rng.choice([22, 3389, 21, 110, 143], n),   # ssh/rdp/ftp/pop/imap
        np.full(n, 6),                      # always TCP
        rng.choice([0x02, 0x12], n),        # SYN or SYN-ACK
        rng.integers(50, 64, n),            # typical attacker TTL
        rng.integers(1, 15, n),             # very fast inter-arrival
        rng.integers(0, 80, n),             # tiny payloads
    ]))

    # ── Port scan ────────────────────────────────────────────────────────────
    _add("port_scan", np.column_stack([
        rng.integers(40, 60, n),            # minimum-size probe packets
        rng.integers(1024, 65535, n),       # random src
        rng.integers(1, 65535, n),          # sweeping across all ports
        rng.choice([6, 1], n),              # TCP SYN or ICMP
        rng.choice([0x02, 0x00], n),        # SYN or null
        rng.integers(40, 64, n),
        rng.integers(1, 5, n),              # extremely fast
        np.zeros(n),                        # zero payload (SYN only)
    ]))

    # ── DDoS / flood ─────────────────────────────────────────────────────────
    _add("ddos", np.column_stack([
        rng.integers(40, 1500, n),
        rng.integers(1, 65535, n),          # spoofed/random src ports
        rng.choice([80, 443, 53], n),       # targeting public services
        rng.choice([6, 17, 1], n),
        rng.choice([0x02, 0x00], n),
        rng.integers(30, 64, n),            # low TTL (often spoofed)
        rng.integers(0, 2, n),              # sub-millisecond — flood
        rng.integers(0, 1400, n),
    ]))

    # ── SQL injection ────────────────────────────────────────────────────────
    _add("sql_injection", np.column_stack([
        rng.integers(200, 1500, n),         # larger HTTP payloads
        rng.integers(1024, 65535, n),
        rng.choice([80, 443, 8080, 8443], n),
        np.full(n, 6),                      # TCP
        rng.choice([0x18, 0x10], n),        # ACK+PSH (data carrying)
        rng.integers(50, 128, n),
        rng.integers(50, 300, n),
        rng.integers(150, 1400, n),         # hefty payload
    ]))

    # ── Malware C2 ───────────────────────────────────────────────────────────
    _add("malware_c2", np.column_stack([
        rng.integers(60, 800, n),
        rng.integers(1024, 65535, n),
        rng.choice([443, 80, 8443, 4444, 1337, 6666], n),  # suspicious ports
        rng.choice([6, 17], n),
        rng.choice([0x18, 0x10], n),
        rng.integers(40, 128, n),
        rng.integers(5, 100, n),            # periodic beaconing
        rng.integers(20, 700, n),
    ]))

    X = np.vstack(X_parts).astype(np.float32)
    y = np.concatenate(y_parts)
    return X, y


# =============================================================================
# Classifier
# =============================================================================

class RFClassifier:
    """Random Forest–based network traffic classifier."""

    _instance: "RFClassifier | None" = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._model: RandomForestClassifier | None = None
        self._le: LabelEncoder | None = None
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._load_or_train()

    # ── Singleton factory (shared between threads) ────────────────────────────
    @classmethod
    def get(cls) -> "RFClassifier":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Model lifecycle ───────────────────────────────────────────────────────
    def _load_or_train(self) -> None:
        if _MODEL_PATH.exists() and _ENCODER_PATH.exists():
            try:
                self._model = joblib.load(_MODEL_PATH)
                self._le = joblib.load(_ENCODER_PATH)
                logger.info("RF model loaded from %s", _MODEL_PATH)
                return
            except Exception as exc:
                logger.warning("Failed to load model, retraining: %s", exc)

        self._train()

    def _train(self) -> None:
        # NSL-KDD Dataset: 125,973 training samples, 41 network features
        # Attack classes: DoS, Probe, R2L, U2R mapped to our 6-class system
        # Algorithm: Random Forest, 120 trees, max_depth=10
        # Rationale: No deep learning — maintains low CPU footprint for SMBs
        if USE_SYNTHETIC:
            logger.info("Training Random Forest on SYNTHETIC data (dev mode)…")
            X, y = _generate_training_data(n_per_class=500)
        else:
            logger.info("Training Random Forest on NSL-KDD dataset (CAPSTONE)…")
            try:
                # Use NSL-KDD but extract only the 8 packet-compatible features
                X, y = load_nsl_kdd(use_test_set=False, max_samples=None, extract_packet_features=True)
            except Exception as e:
                logger.error(f"Failed to load NSL-KDD, falling back to synthetic data: {e}")
                X, y = _generate_training_data(n_per_class=500)

        self._le = LabelEncoder().fit(LABELS)
        y_enc = self._le.transform(y)

        self._model = RandomForestClassifier(
            n_estimators=120,
            max_depth=15,
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=42,
        )
        self._model.fit(X, y_enc)

        joblib.dump(self._model, _MODEL_PATH)
        joblib.dump(self._le, _ENCODER_PATH)
        logger.info("RF model trained and saved → %s", _MODEL_PATH)

    # ── Public API ────────────────────────────────────────────────────────────
    def predict(self, feature_rows: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Classify a batch of packet feature dicts.

        Parameters
        ----------
        feature_rows : list of dicts, each with keys matching FEATURE_NAMES

        Returns
        -------
        dict with:
            label           str   — dominant traffic classification
            confidence      float — 0–1 confidence of top label
            threat_detected bool
            packet_count    int
            breakdown       dict  — percentage per label
            per_packet      list  — per-packet predictions (truncated to 20)
        """
        if not feature_rows:
            return self._empty_result()

        X = np.array(
            [[row.get(f, 0) for f in FEATURE_NAMES] for row in feature_rows],
            dtype=np.float32,
        )

        proba_matrix = self._model.predict_proba(X)          # (n, n_classes)
        avg_proba = proba_matrix.mean(axis=0)                # average across all packets

        classes = self._le.classes_
        top_idx = int(np.argmax(avg_proba))
        top_label = classes[top_idx]
        top_conf = float(avg_proba[top_idx])

        breakdown = {cls: round(float(p) * 100, 1) for cls, p in zip(classes, avg_proba)}

        # Per-packet labels (capped at 20 for JSON size)
        per_packet_indices = self._model.predict(X[:20])
        per_packet = [{"index": i, "label": classes[idx]}
                      for i, idx in enumerate(per_packet_indices)]

        return {
            "label": top_label,
            "confidence": round(top_conf, 3),
            "threat_detected": top_label != "safe",
            "packet_count": len(feature_rows),
            "breakdown": breakdown,
            "per_packet": per_packet,
        }

    @staticmethod
    def _empty_result() -> dict:
        return {
            "label": "safe",
            "confidence": 0.0,
            "threat_detected": False,
            "packet_count": 0,
            "breakdown": {},
            "per_packet": [],
        }
