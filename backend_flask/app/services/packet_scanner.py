"""
CyberMind Packet Scanner — Layer 3 (AI Model)
==============================================
Uses Scapy to sniff packets on ALL active network interfaces and
extracts feature vectors compatible with rf_classifier.RFClassifier.

Interface strategy (macOS):
  - en0   = Wi-Fi / primary LAN (192.168.0.4)
  - bridge0, en1, en2 = UTM virtual bridge interfaces (Kali VM traffic)
  - lo0   = loopback (local self-attacks)
  - We sniff ALL of them concurrently to catch any attack vector.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_features(pkt: Any, prev_ts: float) -> dict[str, float]:
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


# ── Multi-interface live capture ──────────────────────────────────────────────

_INTERFACES_TO_TRY = [
    "en0",      # Primary Wi-Fi / LAN
    "lo0",      # Loopback (local self-attacks)
    "bridge0",  # UTM virtual bridge
    "en1",      # UTM secondary interface
    "en2",      # UTM secondary interface
    "en3",      # Ethernet adapter
    "en4",      # USB Ethernet
]


def _get_active_interfaces() -> list[str]:
    """Return a list of interfaces that exist and are up."""
    try:
        from scapy.all import get_if_list  # noqa: PLC0415
        available = set(get_if_list())
        active = [iface for iface in _INTERFACES_TO_TRY if iface in available]
        logger.info("Active interfaces for capture: %s", active)
        return active if active else ["en0"]
    except Exception:
        return ["en0"]


def _sniff_on_interface(iface: str, count: int, timeout: int,
                        results: list, lock: threading.Lock) -> None:
    """Sniff on a single interface and append packet feature dicts to results."""
    try:
        from scapy.all import sniff  # noqa: PLC0415
        pkts = sniff(iface=iface, count=count, timeout=timeout, store=True)
        if not pkts:
            return

        prev_ts = 0.0
        local_features = []
        for pkt in pkts:
            feat = _extract_features(pkt, prev_ts)
            prev_ts = float(getattr(pkt, "time", prev_ts))
            local_features.append(feat)

        with lock:
            results.extend(local_features)
        logger.info("Interface %s: captured %d packets", iface, len(pkts))
    except Exception as exc:
        logger.debug("Interface %s skipped: %s", iface, exc)


def _measure_packet_rate(sample_secs: float = 2.0) -> float:
    """Return packets/second observed over a short window (used by adaptive drain)."""
    try:
        from scapy.all import sniff  # noqa: PLC0415
        counter = [0]

        def _count(p):  # noqa: ANN001
            counter[0] += 1

        sniff(count=0, timeout=sample_secs, store=False, prn=_count)
        return counter[0] / sample_secs
    except Exception:
        return 0.0


def _live_capture(count: int, timeout: int = 30) -> list[dict[str, float]]:
    """
    Capture live packets with an adaptive pre-drain that waits until the
    kernel buffer is truly clear of attack residue before measuring.
    """
    try:
        from scapy.all import sniff  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("Scapy not installed") from exc

    logger.info("Starting live capture: up to %d pkts, %ds window", count, timeout)

    # ── Adaptive buffer drain ─────────────────────────────────────────────────
    # After hping3/nmap the kernel RST-storm can last 15-30 s.  We drain in
    # 5 s rounds until the packet rate drops below 200 pps (normal LAN idle),
    # capping at 4 rounds (20 s maximum drain time).
    MAX_DRAIN_ROUNDS = 4
    DRAIN_ROUND_SECS = 5.0
    HIGH_RATE_THRESHOLD = 200  # pps — above this we keep draining

    for round_num in range(1, MAX_DRAIN_ROUNDS + 1):
        try:
            rate = _measure_packet_rate(DRAIN_ROUND_SECS)
            logger.info("Drain round %d/%d: %.0f pps", round_num, MAX_DRAIN_ROUNDS, rate)
            if rate < HIGH_RATE_THRESHOLD:
                logger.info("Traffic rate normal — drain complete after %d round(s)", round_num)
                break
            logger.info("Rate still high (%.0f pps) — continuing drain", rate)
        except Exception:
            break  # non-fatal
    # ─────────────────────────────────────────────────────────────────────────

    try:
        packets = sniff(count=count, timeout=timeout, store=True)
    except PermissionError as exc:
        raise RuntimeError("Root privilege required for packet capture") from exc
    except OSError as exc:
        raise RuntimeError(f"Network interface error: {exc}") from exc

    if not packets:
        raise RuntimeError("No packets captured (network may be idle or timeout reached)")

    features: list[dict] = []
    prev_ts: float = 0.0
    for pkt in packets:
        feat = _extract_features(pkt, prev_ts)
        prev_ts = float(getattr(pkt, "time", prev_ts))
        features.append(feat)

    logger.info("Live capture complete: %d packets → %d feature vectors", len(packets), len(features))
    return features

# ── Synthetic fallback ────────────────────────────────────────────────────────

def _simulate_packet_capture(count: int) -> list[dict[str, float]]:
    logger.info("Falling back to synthetic packet simulation (%d packets)", count)
    rng = random.Random(int(time.time()))
    packets: list[dict] = []
    prev_ts = 0.0

    for i in range(count):
        roll = rng.random()
        ts = prev_ts + rng.uniform(0.001, 0.5)

        if roll < 0.70:
            pkt = {"pkt_len": rng.randint(40, 1500), "src_port": rng.randint(1024, 65535),
                   "dst_port": rng.choice([80, 443, 53, 8080, 25]), "protocol": rng.choice([6, 17, 1]),
                   "tcp_flags": rng.choice([0x10, 0x18]), "ttl": rng.randint(50, 128),
                   "inter_arrival_ms": rng.uniform(20, 500), "payload_len": rng.randint(0, 1400)}
        elif roll < 0.80:
            pkt = {"pkt_len": rng.randint(40, 60), "src_port": rng.randint(1024, 65535),
                   "dst_port": rng.randint(1, 65535), "protocol": 6, "tcp_flags": 0x02,
                   "ttl": rng.randint(40, 64), "inter_arrival_ms": rng.uniform(0.5, 5), "payload_len": 0}
        elif roll < 0.90:
            pkt = {"pkt_len": rng.randint(40, 120), "src_port": rng.randint(1024, 65535),
                   "dst_port": rng.choice([22, 3389, 21]), "protocol": 6,
                   "tcp_flags": rng.choice([0x02, 0x12]), "ttl": rng.randint(50, 64),
                   "inter_arrival_ms": rng.uniform(1, 15), "payload_len": rng.randint(0, 80)}
        elif roll < 0.95:
            pkt = {"pkt_len": rng.randint(40, 1500), "src_port": rng.randint(1, 65535),
                   "dst_port": rng.choice([80, 443, 53]), "protocol": rng.choice([6, 17, 1]),
                   "tcp_flags": 0x02, "ttl": rng.randint(30, 64),
                   "inter_arrival_ms": rng.uniform(0.01, 2), "payload_len": rng.randint(0, 1400)}
        else:
            pkt = {"pkt_len": rng.randint(60, 800), "src_port": rng.randint(1024, 65535),
                   "dst_port": rng.choice([443, 80, 4444, 1337, 6666]), "protocol": 6,
                   "tcp_flags": rng.choice([0x18, 0x10]), "ttl": rng.randint(40, 128),
                   "inter_arrival_ms": rng.uniform(5, 100), "payload_len": rng.randint(20, 700)}

        prev_ts = ts
        packets.append(pkt)
    return packets


# ── PCAP file reader (offline analysis) ───────────────────────────────────────

def _read_pcap(pcap_path: str, count: int = 100) -> list[dict[str, float]]:
    try:
        from scapy.all import rdpcap  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("Scapy not installed — cannot read pcap") from exc

    from pathlib import Path
    path = Path(pcap_path)
    if not path.exists():
        raise RuntimeError(f"PCAP file not found: {pcap_path}")

    logger.info("Reading pcap file: %s", pcap_path)
    packets = rdpcap(str(path))
    packets = packets[:count]

    features: list[dict] = []
    prev_ts: float = 0.0
    for pkt in packets:
        feat = _extract_features(pkt, prev_ts)
        prev_ts = float(getattr(pkt, "time", prev_ts))
        features.append(feat)

    logger.info("PCAP read complete: %d packets → %d feature vectors", len(packets), len(features))
    return features


def _find_pcap_file() -> str | None:
    from pathlib import Path
    data_dir = Path(__file__).parent.parent.parent / "data"
    for ext in ("*.pcap", "*.pcapng", "*.cap"):
        files = sorted(data_dir.glob(ext), key=lambda f: f.stat().st_mtime, reverse=True)
        if files:
            return str(files[0])
    return None


# ── Public entry-point ────────────────────────────────────────────────────────

def scan_packets(count: int = 100) -> dict[str, Any]:
    # Respect the caller's packet count; cap at 5000 to stay reasonable
    count = max(50, min(count, 5000))
    error: str | None = None
    pcap_file: str | None = None

    try:
        features = _live_capture(count=count, timeout=max(20, count // 25))
        mode = "live"
    except RuntimeError as exc:
        logger.warning("Live capture failed (%s) — trying pcap fallback", exc)
        error = str(exc)

        pcap_path = _find_pcap_file()
        if pcap_path:
            try:
                features = _read_pcap(pcap_path, count)
                mode = "pcap"
                pcap_file = pcap_path.rsplit("/", 1)[-1]
                error = None
            except RuntimeError as pcap_exc:
                logger.warning("PCAP read failed (%s) — falling back to simulation", pcap_exc)
                error = str(pcap_exc)
                features = _simulate_packet_capture(count)
                mode = "simulated"
        else:
            features = _simulate_packet_capture(count)
            mode = "simulated"

    return {
        "features": features,
        "mode": mode,
        "count": len(features),
        "error": error,
        "pcap_file": pcap_file,
    }