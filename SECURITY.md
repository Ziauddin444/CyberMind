# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x (latest) | ✅ Yes |
| < 1.0 | ❌ No |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through GitHub Issues.**

Instead, report them via email to: **security@cybermind.local** *(update this with your real contact)*

Please include:
- A description of the vulnerability
- Steps to reproduce it
- The potential impact
- Any suggested fix (optional)

We will acknowledge your report within **48 hours** and provide a detailed response within **7 days**.

## Security Best Practices for Deployment

1. **Change default credentials** immediately after installation
2. **Set a strong `SECRET_KEY`** in `/etc/cybermind/.env` — at least 32 random characters
3. **Run behind a reverse proxy** (nginx/Caddy) with TLS in production
4. **Restrict dashboard access** to your internal network only — do not expose port 5173 publicly
5. **The Flask API (port 5000)** should never be exposed to the internet directly
6. **Run packet capture with minimal privileges** — use `CAP_NET_RAW` capability rather than running as root
7. **Keep dependencies updated** — run `pip install -r requirements.txt --upgrade` monthly
