"""
CyberMind Packet Scanner — Layer 3 (AI Model)
==============================================
Uses Scapy to sniff N packets on the active network interface and
extracts feature vectors compatible with rf_classifier.RFClassifier.

If Scapy is unavailable or the process lacks root permission, the scanner
gracefully falls back to **realistic synthetic traffic simulation** so the
demo always works regardless of environment.

No Flask imports — pure Python.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any

logger = logging.getLogger(__name__)

# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_features(pkt: Any, prev_ts: float) -> dict[str, float]:
    """
    Pull numeric features from a Scapy packet object.
    Works with IP / TCP / UDP / ICMP layers.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # noqa: PLC0415

        pkt_len = len(pkt)
        src_port = dst_port = 0
        tcp_flags = 0
        protocol = 0
        ttl = 64
        payload_len = 0

        if IP in pkt:
            protocol = int(pkt[IP].proto)
            ttl = int(pkt[IP].ttl)
            payload_len = len(bytes(pkt[IP].payload))

        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = int(pkt[TCP].flags)

        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

        inter_ms = round((pkt.time - prev_ts) * 1000, 2) if prev_ts else 0.0

        return {
            "pkt_len":          pkt_len,
            "src_port":         src_port,
            "dst_port":         dst_port,
            "protocol":         protocol,
            "tcp_flags":        tcp_flags,
            "ttl":              ttl,
            "inter_arrival_ms": max(0.0, inter_ms),
            "payload_len":      payload_len,
        }
    except Exception:
        return _zero_features()


def _zero_features() -> dict[str, float]:
    return {k: 0.0 for k in [
        "pkt_len", "src_port", "dst_port", "protocol",
        "tcp_flags", "ttl", "inter_arrival_ms", "payload_len",
    ]}


# ── Synthetic fallback ────────────────────────────────────────────────────────

def _simulate_packet_capture(count: int) -> list[dict[str, float]]:
    """
    Generate realistic synthetic packet features that match real-traffic
    distributions.  Called when Scapy or root access is unavailable.

    The mix is:
        70 % safe web/DNS traffic
        10 % port scan probes
        10 % brute-force SSH
         5 % DDoS flood
         5 % malware C2 beacons
    """
    logger.info("Falling back to synthetic packet simulation (%d packets)", count)
    rng = random.Random(int(time.time()))  # fresh seed each call
    packets: list[dict] = []
    prev_ts = 0.0

    for i in range(count):
        roll = rng.random()
        ts = prev_ts + rng.uniform(0.001, 0.5)

        if roll < 0.70:                       # safe
            pkt = {
                "pkt_len":          rng.randint(40, 1500),
                "src_port":         rng.randint(1024, 65535),
                "dst_port":         rng.choice([80, 443, 53, 8080, 25]),
                "protocol":         rng.choice([6, 17, 1]),
                "tcp_flags":        rng.choice([0x10, 0x18]),
                "ttl":              rng.randint(50, 128),
                "inter_arrival_ms": rng.uniform(20, 500),
                "payload_len":      rng.randint(0, 1400),
            }
        elif roll < 0.80:                     # port scan
            pkt = {
                "pkt_len":          rng.randint(40, 60),
                "src_port":         rng.randint(1024, 65535),
                "dst_port":         rng.randint(1, 65535),
                "protocol":         6,
                "tcp_flags":        0x02,
                "ttl":              rng.randint(40, 64),
                "inter_arrival_ms": rng.uniform(0.5, 5),
                "payload_len":      0,
            }
        elif roll < 0.90:                     # brute force
            pkt = {
                "pkt_len":          rng.randint(40, 120),
                "src_port":         rng.randint(1024, 65535),
                "dst_port":         rng.choice([22, 3389, 21]),
                "protocol":         6,
                "tcp_flags":        rng.choice([0x02, 0x12]),
                "ttl":              rng.randint(50, 64),
                "inter_arrival_ms": rng.uniform(1, 15),
                "payload_len":      rng.randint(0, 80),
            }
        elif roll < 0.95:                     # ddos
            pkt = {
                "pkt_len":          rng.randint(40, 1500),
                "src_port":         rng.randint(1, 65535),
                "dst_port":         rng.choice([80, 443, 53]),
                "protocol":         rng.choice([6, 17, 1]),
                "tcp_flags":        0x02,
                "ttl":              rng.randint(30, 64),
                "inter_arrival_ms": rng.uniform(0.01, 2),
                "payload_len":      rng.randint(0, 1400),
            }
        else:                                 # malware C2
            pkt = {
                "pkt_len":          rng.randint(60, 800),
                "src_port":         rng.randint(1024, 65535),
                "dst_port":         rng.choice([443, 80, 4444, 1337, 6666]),
                "protocol":         6,
                "tcp_flags":        rng.choice([0x18, 0x10]),
                "ttl":              rng.randint(40, 128),
                "inter_arrival_ms": rng.uniform(5, 100),
                "payload_len":      rng.randint(20, 700),
            }

        prev_ts = ts
        packets.append(pkt)

    return packets


# ── Scapy live capture ────────────────────────────────────────────────────────

def _live_capture(count: int, timeout: int = 30) -> list[dict[str, float]]:
    """
    Capture `count` packets using Scapy.
    Raises RuntimeError if Scapy is unavailable or permission denied.
    """
    try:
        from scapy.all import sniff  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("Scapy not installed") from exc

    logger.info("Starting Scapy live capture: %d packets (timeout=%ds)", count, timeout)
    try:
        packets = sniff(count=count, timeout=timeout)
    except PermissionError as exc:
        raise RuntimeError("Root privilege required for packet capture") from exc
    except OSError as exc:
        raise RuntimeError(f"Network interface error: {exc}") from exc

    features: list[dict] = []
    prev_ts: float = 0.0

    for pkt in packets:
        feat = _extract_features(pkt, prev_ts)
        prev_ts = float(getattr(pkt, "time", prev_ts))
        features.append(feat)

    return features


# ── Public entry-point ────────────────────────────────────────────────────────

def scan_packets(count: int = 100) -> dict[str, Any]:
    """
    Capture (or simulate) `count` packets and return raw feature dicts.

    Returns
    -------
    {
        features   : list[dict]   — feature vector per packet
        mode       : str          — 'live' | 'simulated'
        count      : int          — actual packets captured
        error      : str | None   — non-fatal warning if fell back to simulation
    }
    """
    count = max(10, min(count, 500))   # clamp to sane range
    error: str | None = None

    try:
        features = _live_capture(count)
        mode = "live"
    except RuntimeError as exc:
        logger.warning("Live capture failed (%s) — using simulation", exc)
        error = str(exc)
        features = _simulate_packet_capture(count)
        mode = "simulated"

    return {
        "features": features,
        "mode": mode,
        "count": len(features),
        "error": error,
    }
