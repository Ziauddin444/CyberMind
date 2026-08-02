# Sandbox Results Index

| Document | Purpose |
|----------|---------|
| **[ATTACK_REPORT.md](./ATTACK_REPORT.md)** | Detailed attack-by-attack report from the 2026-07-31 Docker lab run (timeline, honeypot table, IDS 10/10, RF breakdown, scorecard) |
| **[DEPLOY_AND_ATTACK_GUIDE.md](./DEPLOY_AND_ATTACK_GUIDE.md)** | How to deploy Docker, start scans, run attacks (auto + manual), and read results |
| **[../SANDBOX.md](../SANDBOX.md)** | Architecture / topology overview |

## Quick scorecard (2026-07-31)

| Area | Result |
|------|--------|
| Live packet capture | PASS (`live`) |
| RF scan job | PASS (120 packets) |
| IDS `/api/analyze` | **10 / 10** |
| Honeypot connections | **8** from `10.10.0.99` |
| Demo attack-sim | PASS |
| Hydra vs decoy SSH | Partial (expected for banner honeypot) |

**RF breakdown:** safe 52.0% · ddos 37.6% · port_scan 5.7% · brute_force 4.0% · malware_c2 0.8%

Reproduce:

```bash
bash docker/sandbox/test-all.sh
```
