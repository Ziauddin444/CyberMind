#!/bin/bash

# Start CyberMind Flask Backend Server
cd "$(dirname "$0")" || exit 1

echo "🚀 Starting CyberMind Sentinel Backend..."
./venv/bin/python run.py
