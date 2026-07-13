#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  CyberMind — Capture Real Network Traffic for Demo              ║
# ║  This creates a .pcap file that the scanner can analyse         ║
# ║  even WITHOUT sudo on the Flask server.                         ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# USAGE:
#   sudo bash capture_demo_traffic.sh          # Capture 200 packets
#   sudo bash capture_demo_traffic.sh 500      # Capture 500 packets
#
# The .pcap file is saved to backend_flask/data/ where the scanner
# will automatically find it.

set -e

PACKET_COUNT="${1:-200}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/backend_flask/data"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PCAP_FILE="$DATA_DIR/cybermind_capture_${TIMESTAMP}.pcap"

echo "╔══════════════════════════════════════════════════╗"
echo "║  CyberMind — Real Traffic Capture                ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Create data directory if needed
mkdir -p "$DATA_DIR"

# Detect network interface
if [[ "$(uname)" == "Darwin" ]]; then
    IFACE="en0"
else
    IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
fi

echo "📡  Interface:    $IFACE"
echo "📦  Packets:      $PACKET_COUNT"
echo "💾  Output:       $PCAP_FILE"
echo ""
echo "🔄  Capturing... (generate traffic by browsing the web)"
echo ""

# Capture packets using tcpdump
tcpdump -i "$IFACE" -c "$PACKET_COUNT" -w "$PCAP_FILE" 2>/dev/null

echo ""
echo "✅  Capture complete!"
echo "📁  File: $PCAP_FILE"
echo "📊  Size: $(du -h "$PCAP_FILE" | cut -f1)"
echo ""
echo "Now run CyberMind (without sudo) and click 'Start Scan'."
echo "The scanner will automatically detect and analyse this pcap file."
echo ""
echo "To simulate an attack, open another terminal and run:"
echo "  nmap -sS localhost           # port scan"
echo "  nmap -sS -p 1-1000 localhost # aggressive scan"
echo "Then capture again to get attack traffic in the pcap."
