"""
NSL-KDD Dataset Loader
======================
Downloads and processes the NSL-KDD cybersecurity intrusion detection dataset
for training the Random Forest classifier.

NSL-KDD: https://www.unb.ca/cic/datasets/nsl-kdd.html
- Real network traffic data with labeled attack types
- 41 features representing network connection attributes
- 4 attack classes: DoS, Probe, R2L, U2R (+ Normal)

This module handles:
  1. Downloading NSL-KDD training/test sets (if not cached)
  2. Parsing the CSV format
  3. Feature extraction and normalization
  4. Mapping to our 6-class label system
"""

import io
import logging
import os
import shutil
import urllib.request
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
_DATA_DIR = _HERE.parent.parent / "data"
_NSL_KDD_DIR = _DATA_DIR / "nsl_kdd"
_TRAIN_CSV = _NSL_KDD_DIR / "KDDTrain+.csv"
_TEST_CSV = _NSL_KDD_DIR / "KDDTest+.csv"

# ── NSL-KDD URLs (Pejman Naseri's mirror is often more reliable) ──────────────
NSL_KDD_URLS = {
    "train": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
    "test": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
}

# ── Original NSL-KDD 41 features (in order from the dataset) ──────────────────
# Note: NSL-KDD CSV has 43 columns: 41 features + attack_type + difficulty_level
NSL_KDD_FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label",              # Attack type (string like "normal", "neptune", etc.)
    "difficulty_level",   # Difficulty rating (integer, not used for training)
]

# ── Categorical columns that need encoding ────────────────────────────────────
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# ── NSL-KDD attack classes to our 6-class label system ──────────────────────
LABEL_MAPPING = {
    "normal": "safe",
    # DoS attacks
    "back": "ddos",
    "land": "ddos",
    "neptune": "ddos",
    "pod": "ddos",
    "smurf": "ddos",
    "teardrop": "ddos",
    # Probe/Reconnaissance
    "ipsweep": "port_scan",
    "nmap": "port_scan",
    "portsweep": "port_scan",
    "satan": "port_scan",
    # R2L (Remote to Local)
    "ftp_write": "brute_force",
    "guess_passwd": "brute_force",
    "imap": "brute_force",
    "phf": "brute_force",
    "pop_3": "brute_force",
    "multihop": "brute_force",
    # U2R (User to Root)
    "buffer_overflow": "malware_c2",
    "loadmodule": "malware_c2",
    "perl": "malware_c2",
    "rootkit": "malware_c2",
    "xlock": "malware_c2",
    "xsnoop": "malware_c2",
}


def _download_nsl_kdd() -> None:
    """Download NSL-KDD dataset if not already cached."""
    _NSL_KDD_DIR.mkdir(parents=True, exist_ok=True)

    for name, url in NSL_KDD_URLS.items():
        csv_path = _TRAIN_CSV if name == "train" else _TEST_CSV
        if csv_path.exists():
            logger.info(f"NSL-KDD {name} set already cached at {csv_path}")
            continue

        logger.info(f"Downloading NSL-KDD {name} set from {url}…")
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read().decode("utf-8")
            # Save as CSV (NSL-KDD URLs return raw data)
            csv_path.write_text(content)
            logger.info(f"Saved {name} set to {csv_path}")
        except Exception as e:
            logger.error(f"Failed to download NSL-KDD {name} set: {e}")
            raise


def load_nsl_kdd(
    use_test_set: bool = False,
    max_samples: Optional[int] = None,
    extract_packet_features: bool = True,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Load and preprocess NSL-KDD dataset.

    Parameters
    ----------
    use_test_set : bool
        If True, load test set; else load training set.
    max_samples : int, optional
        Limit number of samples (useful for testing).
    extract_packet_features : bool
        If True, extract only the 8 features that match packet_scanner.
        If False, use all 41 NSL-KDD features (with one-hot encoding).

    Returns
    -------
    X : ndarray of shape (n_samples, n_features)
        Feature matrix (normalized to 0-1).
    y : ndarray of shape (n_samples,)
        Label array with values from ["safe", "brute_force", "port_scan", "ddos", "sql_injection", "malware_c2"].
    """
    _download_nsl_kdd()

    csv_path = _TEST_CSV if use_test_set else _TRAIN_CSV
    logger.info(f"Loading NSL-KDD from {csv_path}…")

    # Read CSV (no header in original, but we provide column names)
    df = pd.read_csv(csv_path, names=NSL_KDD_FEATURE_NAMES, header=None)

    # Strip whitespace from string columns (pandas 2.1+ compatibility)
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].str.strip()
    
    # Ensure label column is string type before mapping
    df["label"] = df["label"].astype(str).str.lower().map(LABEL_MAPPING).fillna("safe")

    # Drop rows with unmapped labels
    initial_count = len(df)
    df = df[df["label"].isin(["safe", "brute_force", "port_scan", "ddos", "sql_injection", "malware_c2"])]
    dropped = initial_count - len(df)
    if dropped > 0:
        logger.warning(f"Dropped {dropped} rows with unmapped labels")

    if max_samples is not None:
        df = df.iloc[:max_samples]
        logger.info(f"Limited to {max_samples} samples")

    # Extract features and labels
    y = df["label"].values

    # Choose feature extraction strategy
    if extract_packet_features:
        # Extract 8 features compatible with packet_scanner.py:
        # pkt_len, src_port, dst_port, protocol, tcp_flags, ttl, inter_arrival_ms, payload_len
        #
        # NSL-KDD has different features, so we map approximate equivalents:
        # - duration → inter_arrival_ms (time-based)
        # - src_bytes → payload_len (data size)
        # - dst_bytes → pkt_len (packet size)
        # - src_port → src_port (direct)
        # - dst_port → dst_port (direct)
        # - protocol_type → protocol (direct)
        # - logged_in, count → padding (no direct equivalents)
        
        X_df = pd.DataFrame({
            "pkt_len": df.get("dst_bytes", 0),  # Packet size
            "src_port": df.get("src_port", 0),
            "dst_port": df.get("dst_port", 0),
            "protocol": df["protocol_type"].astype(str).map({
                "icmp": 1, "tcp": 6, "udp": 17
            }).fillna(0).astype(float),
            "tcp_flags": df.get("urgent", 0),  # Proxy for TCP flags
            "ttl": df.get("wrong_fragment", 0),  # Not ideal, but filler
            "inter_arrival_ms": df.get("duration", 0),  # Time-based
            "payload_len": df.get("src_bytes", 0),  # Data size
        })
        
        feature_set = "packet_scanner compatible (8 features)"
    else:
        # Use all features with one-hot encoding (original approach)
        X_df = df.drop("label", axis=1).drop("difficulty_level", axis=1)
        
        # One-hot encode categorical columns
        for col in CATEGORICAL_COLS:
            if col in X_df.columns:
                dummies = pd.get_dummies(X_df[col], prefix=col, drop_first=True)
                X_df = X_df.drop(col, axis=1)
                X_df = pd.concat([X_df, dummies], axis=1)
        
        feature_set = f"full NSL-KDD ({X_df.shape[1]} features)"

    # Convert all columns to numeric (handles string representations of numbers)
    for col in X_df.columns:
        X_df[col] = pd.to_numeric(X_df[col], errors='coerce')
    
    # Handle any NaN values from conversion errors by filling with 0
    X_df = X_df.fillna(0)

    # Normalize to [0, 1]
    X = X_df.values.astype(np.float32)
    scaler = MinMaxScaler()
    X = scaler.fit_transform(X).astype(np.float32)

    logger.info(f"Loaded {len(X)} samples with shape {X.shape} ({feature_set})")
    logger.info(f"Label distribution: {pd.Series(y).value_counts().to_dict()}")

    return X, y


if __name__ == "__main__":
    # Test script
    logging.basicConfig(level=logging.INFO)
    X_train, y_train = load_nsl_kdd(use_test_set=False, max_samples=1000)
    print(f"Training set: {X_train.shape}, labels: {np.unique(y_train, return_counts=True)}")
