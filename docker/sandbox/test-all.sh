#!/usr/bin/env bash
# One-command sandbox bring-up + full attack test + results.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

mkdir -p sandbox-results

echo "==> Building & starting CyberMind lab..."
docker compose -f docker-compose.sandbox.yml up -d --build

echo "==> Waiting for flask health..."
for i in $(seq 1 45); do
  if curl -sf http://localhost:5000/api/health >/dev/null 2>&1; then
    echo "    Flask is up"
    break
  fi
  sleep 2
done

echo "==> Running full attack suite inside attacker container..."
docker compose -f docker-compose.sandbox.yml exec -T attacker \
  bash /attacks/run_attacks.sh

echo ""
echo "Done. Results on host:"
ls -la "$ROOT/sandbox-results" | tail -20
echo ""
echo "Dashboard: http://localhost:5173  (admin / admin123)"
echo "Latest report:"
ls -1t "$ROOT/sandbox-results"/sandbox_report_*.json 2>/dev/null | head -1
