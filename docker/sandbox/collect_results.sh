#!/usr/bin/env bash
# Collect CyberMind state without running attacks (useful mid-demo).
set -uo pipefail

OPS_API="${OPS_API:-http://flask:5000/api}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULTS_DIR/snapshot_${TS}.json"

mkdir -p "$RESULTS_DIR"

get() { curl -sS "${OPS_API}$1" || echo '{}'; }

python3 - <<PY
import json
from datetime import datetime, timezone

state = {
  "generated_at": datetime.now(timezone.utc).isoformat(),
  "honeypot_status": json.loads('''$(get /honeypot/status | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "honeypot_logs": json.loads('''$(get /honeypot/logs | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "honeypot_summary": json.loads('''$(get /honeypot/summary | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "blacklist": json.loads('''$(get /blacklist/status | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "firewall": json.loads('''$(get /firewall/status | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "stats": json.loads('''$(get /stats | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "latest_traffic": json.loads('''$(get /get_latest_traffic | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "logs": json.loads('''$(get /logs | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
  "ollama": json.loads('''$(get /ollama/status | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' 2>/dev/null || echo '{}')'''),
}
with open("$OUT", "w") as f:
    json.dump(state, f, indent=2)
print("$OUT")
PY
