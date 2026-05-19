"""
CyberMind IDS Engine — Layer 3 (AI / Analysis Model)
=====================================================
Pure Python analysis module.  No Flask imports.
Single public entry-point: analyze(payload) -> dict

Called by Flask /api/analyze route.
Can also be run standalone from the CLI for testing.

Scapy-style packet analysis is performed when raw_packet bytes are
supplied; plain-text / log-line analysis is always performed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signature database
# Each tuple: (pattern_regex, attack_type, display_label, severity, confidence_score, mitigation)
# ---------------------------------------------------------------------------

SIGNATURES: list[tuple[str, str, str, str, float, str]] = [
    # ── Reconnaissance ──────────────────────────────────────────────────────
    (r"nmap",               "reconnaissance", "Nmap Port Scan",            "high",     0.92,
     "Block source IP; enable port-scan rate limiting on the perimeter firewall."),
    (r"masscan",            "reconnaissance", "Masscan Bulk Sweep",         "high",     0.95,
     "Block source IP; alert SOC; review firewall ingress rules."),
    (r"nikto",              "web_scan",       "Nikto Web Vulnerability Scan","high",     0.90,
     "Block source IP; review web server error logs; patch identified issues."),
    (r"zmap",               "reconnaissance", "ZMap Internet-Wide Scan",    "medium",   0.85,
     "Rate-limit ICMP/TCP SYN from external; notify network team."),
    (r"shodan",             "reconnaissance", "Shodan Banner Grab",          "medium",   0.80,
     "Harden exposed services; restrict unnecessary public-facing ports."),

    # ── Injection ───────────────────────────────────────────────────────────
    (r"sqlmap",             "injection",      "SQLMap Automated SQLi",       "critical", 0.97,
     "Block IP immediately; review DB audit logs; run WAF rule update."),
    (r"union\s+select",     "injection",      "SQL UNION Injection",         "critical", 0.88,
     "Enable parameterised queries; block source; notify DBA team."),
    (r"(?:'|%27)\s*or\s+(?:'1'='1|1=1)", "injection", "SQL Auth Bypass",   "critical", 0.93,
     "Enforce parameterised statements; add WAF rule; reset affected session tokens."),
    (r"(?:drop|truncate)\s+table", "injection", "SQL Destructive Query",    "critical", 0.90,
     "Revoke DB write permissions; restore from last clean backup; alert DBA."),
    (r"<script[^>]*>",      "xss",            "Cross-Site Scripting (XSS)", "high",     0.87,
     "Sanitise input; enforce Content-Security-Policy header; update WAF rules."),
    (r"onerror\s*=",        "xss",            "XSS Event Handler Injection", "high",    0.82,
     "Apply output encoding; tighten CSP; review affected pages."),
    (r"\.\./\.\.",          "lfi",            "Path Traversal (LFI)",        "high",     0.86,
     "Canonicalise file paths; block traversal sequences at the WAF."),
    (r"(?:/etc/passwd|/etc/shadow|/proc/self)", "lfi",
                                              "Sensitive File Access Probe", "high",    0.90,
     "Block source; audit file-system access controls; alert security team."),

    # ── Credential attacks ──────────────────────────────────────────────────
    (r"hydra",              "credential_attack","Hydra Brute-Force Tool",   "critical", 0.97,
     "Lock targeted accounts; block source IP; enable MFA; alert identity team."),
    (r"medusa",             "credential_attack","Medusa Password Spray",    "critical", 0.95,
     "Enforce account lockout policy; block IP; notify SOC."),
    (r"(?:brute.?forc|password.?spray|credential.?stuff)", "credential_attack",
                                              "Credential Attack Pattern",   "high",    0.84,
     "Enable MFA; review auth logs; reset compromised passwords."),

    # ── Exploitation ────────────────────────────────────────────────────────
    (r"metasploit|msfconsole|msfvenom", "exploitation",
                                              "Metasploit Framework",        "critical", 0.96,
     "Isolate affected host; run EDR scan; capture forensic image."),
    (r"exploit(?:ed|ing|er)?",          "exploitation",
                                              "Generic Exploit Attempt",     "high",    0.78,
     "Patch vulnerable service; block source IP; check for lateral movement."),
    (r"shellcode",          "exploitation",   "Shellcode Delivery",         "critical", 0.92,
     "Block source; isolate endpoint; run memory forensics."),
    (r"buffer.?overflow|heap.?spray|use.after.free", "exploitation",
                                              "Memory Corruption Exploit",   "critical", 0.88,
     "Patch vulnerable component; enable ASLR/DEP; isolate host."),

    # ── Post-exploitation ───────────────────────────────────────────────────
    (r"nc\s+-[el]|netcat",  "post_exploitation","Netcat Reverse Shell",     "critical", 0.99,
     "Kill connection immediately; isolate host; run full forensic investigation."),
    (r"reverse.?shell|revshell", "post_exploitation",
                                              "Reverse Shell Behaviour",     "critical", 0.98,
     "Terminate session; isolate host; identify persistence mechanisms."),
    (r"mimikatz|lsass",     "post_exploitation","Mimikatz Credential Dump", "critical", 0.99,
     "Reset all domain credentials; isolate host; run EDR; notify CISO."),
    (r"cobalt.?strike|beacon", "post_exploitation",
                                              "Cobalt Strike C2 Beacon",     "critical", 0.97,
     "Block C2 domains/IPs; isolate affected hosts; engage IR team."),
    (r"powershell.{0,30}(?:-enc|-encodedcommand|iex|downloadstring|invoke-expression)",
                            "post_exploitation","Malicious PowerShell",      "critical", 0.94,
     "Block PS execution policy; isolate host; review scheduled tasks."),
    (r"wget\s+http|curl\s+http.*-[oO]", "post_exploitation",
                                              "Payload Download Attempt",   "medium",   0.76,
     "Block external URLs; check proxy logs; scan downloaded file if captured."),

    # ── Malware / ransomware ────────────────────────────────────────────────
    (r"ransomware|lockbit|wannacry|ryuk|conti|blackcat", "malware",
                                              "Ransomware Signature",        "critical", 0.99,
     "Activate kill-switch; isolate all hosts; engage IR; restore from offline backup."),
    (r"trojan|backdoor|rat\b|remote.access.tool", "malware",
                                              "Trojan/RAT Signature",        "critical", 0.90,
     "Isolate host; scan with EDR; identify command-and-control IPs."),
    (r"c2|command.and.control|botnet", "malware",
                                              "C2/Botnet Communication",     "critical", 0.93,
     "Block C2 IPs/domains; isolate endpoint; review network flow logs."),

    # ── DDoS / flood ────────────────────────────────────────────────────────
    (r"syn.?flood|udp.?flood|ddos|amplification|slowloris|loic", "ddos",
                                              "DDoS / Flood Attack",         "high",    0.88,
     "Enable rate limiting; contact ISP for upstream filtering; activate scrubbing centre."),

    # ── Network anomalies ───────────────────────────────────────────────────
    (r"arp.?spoof|arp.?poison", "network_anomaly",
                                              "ARP Spoofing / Poisoning",    "high",    0.87,
     "Enable Dynamic ARP Inspection; isolate rogue switch port."),
    (r"dns.?tunnel|dnscat", "network_anomaly","DNS Tunnelling",             "high",     0.89,
     "Block unusual DNS query lengths/patterns; review DNS server logs."),
    (r"rogue.?dhcp|dhcp.?starv", "network_anomaly",
                                              "Rogue DHCP / DHCP Starvation","medium",  0.83,
     "Enable DHCP snooping on managed switches; alert network team."),
]

# ---------------------------------------------------------------------------
# Severity ordering (higher = worse)
# ---------------------------------------------------------------------------
_SEV_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# High-risk ports (scanning / targeting these raises confidence)
# ---------------------------------------------------------------------------
_ATTACK_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    1433, 1521, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 27017,
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rank(sev: str) -> int:
    return _SEV_RANK.get(sev.lower(), 1)


def _ip_is_private(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _sha256_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Packet-level analysis (Scapy-style, without requiring Scapy at runtime)
# ---------------------------------------------------------------------------

def _analyze_packet_bytes(raw: bytes) -> list[dict]:
    """
    Perform lightweight binary pattern matching on raw packet bytes.
    Returns a list of match dicts (same schema as signature matches).
    """
    matches: list[dict] = []

    # Check for HTTP in binary payload (simple ASCII heuristic)
    try:
        decoded = raw.decode("latin-1")
    except Exception:
        decoded = ""

    for pattern, attack_type, label, severity, confidence, mitigation in SIGNATURES:
        if re.search(pattern, decoded, re.IGNORECASE):
            matches.append({
                "signature": pattern,
                "attack_type": attack_type,
                "label": label,
                "severity": severity,
                "confidence": confidence,
                "mitigation": mitigation,
                "source": "packet",
            })

    # Detect common attack tool TCP port fingerprints embedded in bytes
    # (e.g., Metasploit default bind port 4444 in little-endian)
    if b"\x11\x5c" in raw or b"\x5c\x11" in raw:  # port 4444 in BE/LE
        matches.append({
            "signature": "port:4444",
            "attack_type": "exploitation",
            "label": "Metasploit Default Port Detected in Payload",
            "severity": "critical",
            "confidence": 0.91,
            "mitigation": "Block source; check for reverse shells on port 4444.",
            "source": "packet_binary",
        })

    return matches


# ---------------------------------------------------------------------------
# Text / log-line analysis
# ---------------------------------------------------------------------------

def _analyze_text(text: str) -> list[dict]:
    """Match signature patterns against plain text or log lines."""
    matches: list[dict] = []
    for pattern, attack_type, label, severity, confidence, mitigation in SIGNATURES:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append({
                "signature": pattern,
                "attack_type": attack_type,
                "label": label,
                "severity": severity,
                "confidence": confidence,
                "mitigation": mitigation,
                "source": "text",
            })
    return matches


# ---------------------------------------------------------------------------
# Port-based heuristics
# ---------------------------------------------------------------------------

def _port_heuristics(ports: list[int]) -> dict | None:
    """Return a match dict if targeted ports are commonly attacked."""
    hit = [p for p in ports if p in _ATTACK_PORTS]
    if not hit:
        return None
    return {
        "signature": f"ports:{hit}",
        "attack_type": "suspicious_port_targeting",
        "label": f"High-Risk Port(s) Targeted: {hit}",
        "severity": "medium",
        "confidence": 0.72,
        "mitigation": "Verify legitimate use; consider restricting if not required.",
        "source": "port_heuristic",
    }


# ---------------------------------------------------------------------------
# IP reputation heuristics (offline — no API call)
# ---------------------------------------------------------------------------

def _ip_heuristics(ip: str) -> dict | None:
    """Flag obviously suspicious source IP attributes."""
    if not ip:
        return None
    if not _ip_is_private(ip):
        # External IP targeting internal resources → mild signal
        return {
            "signature": f"external_ip:{ip}",
            "attack_type": "external_threat",
            "label": f"External Source IP: {ip}",
            "severity": "low",
            "confidence": 0.55,
            "mitigation": "Verify this IP is expected; geo-block if anomalous.",
            "source": "ip_heuristic",
        }
    return None


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def analyze(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Analyse the supplied payload and return a structured threat assessment.

    Expected payload keys (all optional):
        text          str   — raw log line, alert text, or CLI command
        log_lines     list  — multiple log lines to analyse together
        threat_type   str   — hint from the frontend (e.g. 'brute_force')
        source_ip     str   — originating IP address
        target_ports  list  — destination ports (ints)
        raw_packet    bytes — raw packet bytes for binary analysis

    Returns:
        {
            success:        bool
            threat_detected: bool
            threat_type:    str
            label:          str
            severity:       str          (low | medium | high | critical)
            confidence:     float        (0.0 – 1.0)
            summary:        str          (human-readable 1-liner)
            recommendations: list[str]
            matches:        list[dict]   (all signature hits)
            fingerprint:    str          (sha256 of input text)
            timestamp:      str          (ISO-8601 UTC)
            model:          str
        }
    """
    all_matches: list[dict] = []

    # ── 1. Normalise input text ─────────────────────────────────────────────
    text_parts: list[str] = []
    if payload.get("text"):
        text_parts.append(str(payload["text"]))
    if payload.get("log_lines"):
        text_parts.extend(str(l) for l in payload["log_lines"])
    if payload.get("threat_type"):
        text_parts.append(str(payload["threat_type"]))
    if payload.get("message"):
        text_parts.append(str(payload["message"]))

    combined_text = " ".join(text_parts)
    fingerprint = _sha256_fingerprint(combined_text) if combined_text else "0" * 16

    # ── 2. Text / log analysis ──────────────────────────────────────────────
    if combined_text:
        all_matches.extend(_analyze_text(combined_text))

    # ── 3. Binary packet analysis ───────────────────────────────────────────
    raw_packet = payload.get("raw_packet")
    if isinstance(raw_packet, (bytes, bytearray)) and raw_packet:
        all_matches.extend(_analyze_packet_bytes(bytes(raw_packet)))

    # ── 4. Port heuristics ──────────────────────────────────────────────────
    ports = [int(p) for p in (payload.get("target_ports") or []) if str(p).isdigit()]
    port_hit = _port_heuristics(ports)
    if port_hit:
        all_matches.append(port_hit)

    # ── 5. IP heuristics ────────────────────────────────────────────────────
    source_ip = payload.get("source_ip", "")
    ip_hit = _ip_heuristics(source_ip)
    if ip_hit:
        all_matches.append(ip_hit)

    # ── 6. Deduplicate by label ─────────────────────────────────────────────
    seen_labels: set[str] = set()
    unique_matches: list[dict] = []
    for m in all_matches:
        if m["label"] not in seen_labels:
            seen_labels.add(m["label"])
            unique_matches.append(m)

    # ── 7. Compute overall severity & confidence ────────────────────────────
    top_severity = "low"
    top_confidence = 0.30
    top_attack_type = payload.get("threat_type", "unknown")
    top_label = "No threat signatures matched"

    for m in unique_matches:
        if _rank(m["severity"]) >= _rank(top_severity):
            top_severity = m["severity"]
            top_label = m["label"]
            if m["attack_type"] not in ("ip_heuristic", "port_heuristic"):
                top_attack_type = m["attack_type"]
        top_confidence = max(top_confidence, m["confidence"])

    threat_detected = top_confidence >= 0.65 or bool(
        [m for m in unique_matches if m["attack_type"] not in ("external_threat",)]
    )

    # ── 8. Build recommendations ────────────────────────────────────────────
    recommendations: list[str] = []
    # Primary: from top match
    for m in unique_matches:
        if m["severity"] in ("critical", "high") and m.get("mitigation"):
            recommendations.append(m["mitigation"])
    # Fallback generic advice
    recommendations += [
        "Monitor source IP for repeated activity over the next 24 hours.",
        "Capture full packet traces for forensic review if attack continues.",
        "Run one-click remediation if high-confidence indicators persist.",
        "Increase authentication hardening: MFA, lockout policy, geo-IP restrictions.",
    ]
    # De-duplicate, preserve order
    seen: set[str] = set()
    deduped: list[str] = []
    for r in recommendations:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    # ── 9. Human-readable summary ───────────────────────────────────────────
    if threat_detected and unique_matches:
        summary = (
            f"CyberMind IDS detected {len(unique_matches)} signature match(es). "
            f"Top threat: \"{top_label}\" — severity {top_severity.upper()}, "
            f"confidence {round(top_confidence * 100)}%."
        )
    elif combined_text:
        summary = (
            "Input analysed — no high-confidence threat signatures matched. "
            "Low-level monitoring recommended."
        )
    else:
        summary = "No input provided. Supply text, log lines, or a packet file."

    logger.info(
        "IDS analysis complete | threat=%s | severity=%s | confidence=%.2f | matches=%d",
        threat_detected, top_severity, top_confidence, len(unique_matches),
    )

    return {
        "success": True,
        "threat_detected": threat_detected,
        "threat_type": top_attack_type,
        "label": top_label,
        "severity": top_severity,
        "confidence": round(top_confidence, 3),
        "summary": summary,
        "recommendations": deduped[:6],          # cap at 6
        "matches": unique_matches,
        "fingerprint": fingerprint,
        "source_ip": source_ip or None,
        "timestamp": _now_utc(),
        "model": "cybermind-ids-v2",
    }


# ---------------------------------------------------------------------------
# CLI self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    tests = [
        {"text": "nmap -sS -p 1-65535 192.168.1.1", "source_ip": "45.83.122.41"},
        {"text": "' OR '1'='1' --", "threat_type": "sql_injection"},
        {"text": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1"},
        {"text": "msfconsole -x 'use exploit/multi/handler'", "target_ports": [4444]},
        {"text": "LockBit ransomware beacon detected"},
        {"text": "Normal user login from 192.168.1.50", "source_ip": "192.168.1.50"},
        {"text": ""},
    ]

    for t in tests:
        result = analyze(t)
        print(f"\n{'─'*70}")
        print(f"INPUT   : {t.get('text', '(empty)')[:70]}")
        print(f"THREAT  : {result['threat_detected']}  |  TYPE: {result['threat_type']}")
        print(f"SEVERITY: {result['severity']}  |  CONFIDENCE: {result['confidence']}")
        print(f"SUMMARY : {result['summary']}")
        print(f"MATCHES : {len(result['matches'])}")
