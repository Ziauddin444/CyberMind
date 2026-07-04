#!/bin/bash

# Trap SIGINT (Ctrl+C) and SIGTERM to ensure clean shutdown of all child processes
trap 'echo -e "\nShutting down CyberMind Demo..."; kill $NODE_PID $FLASK_PID $VITE_PID 2>/dev/null; exit 0' SIGINT SIGTERM EXIT

echo "==============================================="
echo "Starting CyberMind Capstone 2 Demo Environment"
echo "==============================================="

echo "[1/3] Starting Node.js Backend (Port 3001)..."
cd backend
npm install --silent
npm run dev &
NODE_PID=$!
cd ..

echo "[2/3] Starting Flask Backend (Port 5000)..."
cd backend_flask
python3 run.py &
FLASK_PID=$!
cd ..

echo "[3/3] Starting Vite Frontend..."
cd frontend
npm install --silent
npm run dev &
VITE_PID=$!
cd ..

echo "==============================================="
echo "✅ CyberMind is fully running!"
echo ""
echo "📱 Frontend:   http://localhost:5173"
echo "🛡️  Flask API:  http://localhost:5000"
echo "⚙️  Node API:   http://localhost:3001"
echo ""
echo "Press Ctrl+C at any time to stop all services."
echo "==============================================="

# Wait indefinitely until interrupted
wait
