#!/usr/bin/env python3
"""
CyberMind Attack Injector — Real Packet-Level Testing
=====================================================
Sends REAL raw TCP SYN packets through en0 using Scapy.
These packets traverse the actual network interface and are captured
by the CyberMind packet scanner — no fake data, no simulation.

This is how professional IDS testing tools (tcpreplay, Scapy) work.

Usage:
    sudo python3 inject_attack.py --type port_scan
    sudo python3 inject_attack.py --type ddos
    sudo python3 inject_attack.py --type brute_force
    sudo python3 inject_attack.py --type all

MUST run with sudo (raw sockets require root).
"""

import argparse
import sys
import time

try:
    from scapy.all import IP, TCP, send, sendp, Ether, conf, get_if_hwaddr
    from scapy.all import RandShort, RandIP
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

TARGET_IP = "192.168.0.4"   # Mac's own IP on en0
IFACE = "en0"               # Physical interface — packets appear on this interface


def inject_port_scan(target_ip: str = TARGET_IP, port_range: range = range(1, 1001)):
    """
    Simulate nmap -sS: send bare SYN packets to ports 1-1000.
    Spoofed source IP so they appear as external attack traffic.
    """
    print(f"[PORT SCAN] Injecting {len(port_range)} SYN packets → {target_ip}")
    print("           These will appear on en0 and be captured by CyberMind scanner\n")

    spoofed_src = "10.0.0.99"  # fake attacker IP
    packets = []

    for port in port_range:
        pkt = IP(src=spoofed_src, dst=target_ip, ttl=52) / \
              TCP(sport=RandShort(), dport=port, flags="S")
        packets.append(pkt)

    # Send in batches at 50 packets/sec (like nmap --max-rate 50)
    sent = 0
    for pkt in packets:
        send(pkt, iface=IFACE, verbose=False)
        sent += 1
        if sent % 50 == 0:
            print(f"  Sent {sent}/{len(port_range)} SYN packets...")
            time.sleep(1.0)  # 50 pkts/sec rate

    print(f"✔ Port scan complete: {sent} SYN packets injected through {IFACE}")


def inject_ddos(target_ip: str = TARGET_IP, target_port: int = 8080,
                duration_sec: int = 15, rate_pps: int = 200):
    """
    Simulate hping3 --flood: send SYN packets as fast as possible
    to a single target port (flood rate — near-zero inter-arrival).
    """
    print(f"[DDOS/SYN FLOOD] Flooding {target_ip}:{target_port} for {duration_sec}s "
          f"at {rate_pps} pps\n")

    end_time = time.time() + duration_sec
    sent = 0
    delay = 1.0 / rate_pps

    while time.time() < end_time:
        src_ip = f"10.{sent % 256}.{(sent // 256) % 256}.{(sent // 65536) % 256 + 1}"
        pkt = IP(src=src_ip, dst=target_ip, ttl=40) / \
              TCP(sport=RandShort(), dport=target_port, flags="S", seq=sent)
        send(pkt, iface=IFACE, verbose=False)
        sent += 1
        time.sleep(delay)

    print(f"✔ DDoS flood complete: {sent} packets injected in {duration_sec}s "
          f"({sent // duration_sec} pps average)")


def inject_brute_force(target_ip: str = TARGET_IP, target_port: int = 22,
                        attempts: int = 100):
    """
    Simulate SSH brute force: repeated SYN packets to port 22.
    """
    print(f"[BRUTE FORCE] {attempts} SYN packets → {target_ip}:{target_port} (SSH)\n")

    spoofed_src = "10.0.0.77"
    sent = 0

    for i in range(attempts):
        pkt = IP(src=spoofed_src, dst=target_ip, ttl=56) / \
              TCP(sport=RandShort(), dport=target_port, flags="S", seq=i)
        send(pkt, iface=IFACE, verbose=False)
        sent += 1
        time.sleep(0.1)  # 10 attempts/sec

    print(f"✔ Brute force complete: {sent} SYN packets → port {target_port}")


def main():
    parser = argparse.ArgumentParser(description="CyberMind Attack Injector")
    parser.add_argument(
        "--type",
        choices=["port_scan", "ddos", "brute_force", "all"],
        default="port_scan",
        help="Type of attack to inject"
    )
    parser.add_argument("--target", default="192.168.0.4",
                        help="Target IP (default: 192.168.0.4)")
    parser.add_argument("--iface", default="en0",
                        help="Network interface (default: en0)")
    args = parser.parse_args()

    target = args.target
    iface = args.iface

    print("=" * 60)
    print("  CyberMind Sentinel — Real Packet Attack Injector")
    print("=" * 60)
    print(f"  Target: {target} | Interface: {iface}")
    print("  Start the CyberMind scan FIRST, then this will inject")
    print("  real packets that the scanner will detect.\n")

    if args.type == "port_scan":
        inject_port_scan(target_ip=target)
    elif args.type == "ddos":
        inject_ddos(target_ip=target)
    elif args.type == "brute_force":
        inject_brute_force(target_ip=target)
    elif args.type == "all":
        inject_port_scan(target_ip=target)
        print("\nWaiting 5s between attacks...\n")
        time.sleep(5)
        inject_brute_force(target_ip=target)
        print("\nWaiting 5s...\n")
        time.sleep(5)
        inject_ddos(target_ip=target)

    print("\n✅ Attack injection complete!")
    print("   Check the CyberMind dashboard for detection results.")



if __name__ == "__main__":
    if sys.platform == "darwin" and sys.argv[0].endswith(".py"):
        import os
        if os.geteuid() != 0:
            print("ERROR: Must run with sudo (raw sockets require root)")
            print(f"       sudo python3 {sys.argv[0]} " + " ".join(sys.argv[1:]))
            sys.exit(1)
    main()
