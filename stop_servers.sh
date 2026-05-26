#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# CyberMind Sentinel - 2-Tier IDS - Stop All Servers
# ════════════════════════════════════════════════════════════════════════════

echo "Stopping CyberMind Sentinel servers..."
echo ""

# Kill Flask backend (port 5000)
echo "Stopping Flask Backend (port 5000)..."
lsof -ti:5000 | xargs kill -9 2>/dev/null || true

# Kill Vite dev server if running (port 5173)
echo "Stopping Vite Dev Server (port 5173)..."
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

echo ""
echo "✓ All servers stopped"
echo ""
echo "Open ports:"
lsof -i -P -n | grep LISTEN | grep -E "500[0-9]|517[0-9]" || echo "All target ports are free"
