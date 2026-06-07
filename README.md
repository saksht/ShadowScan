# ShadowScan 🔍

**Intelligent Vulnerability Chaining Engine**

> Built by Akshat Singh | [github.com/saksht](https://github.com/saksht)

ShadowScan is a modular Python web application security scanner that **chains vulnerabilities** — when one module finds something, the chaining engine automatically decides what to test next, just like a human pentester would.

Most scanners fire templates and stop. ShadowScan reasons about findings.

```
recon finds .git exposed
  → exposure scans JS files → finds Sentry DSN + JWT token
    → auth replays token → confirms IDOR on /api/v1/users
      → injection tests all user params → SQLi confirmed
        → LLM analyzes full chain impact → CRITICAL report
```

---

## Features

- **Chaining engine** — `chains/rules.yaml` maps findings → next modules automatically
- **5 attack modules** — Recon, Exposure, Auth, API, Injection
- **7 injection classes** — SQLi (error + blind), SSTI, XSS, LFI, SSRF, CMDi, Open Redirect
- **LLM-augmented reasoning** — Claude API analyzes complex finding chains
- **Burp Suite integration** — `--proxy` flag routes all traffic through Burp
- **Rich terminal output** — color-coded, severity-tagged, chain-aware
- **Dark HTML report** — self-contained, professional, ready for submission

---

## Installation

```bash
git clone https://github.com/saksht/shadowscan
cd shadowscan
pip install -r requirements.txt
```

**Requirements:** Python 3.9+, `requests`, `PyYAML`

---

## Usage

```bash
# Basic scan
python shadowscan.py -t https://target.com

# With LLM chain analysis (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
python shadowscan.py -t https://target.com --llm

# Authenticated scan (cookie/token)
python shadowscan.py -t https://target.com \
  --headers '{"Authorization": "Bearer YOUR_TOKEN"}' \
  --cookies '{"session": "abc123"}'

# Route through Burp Suite
python shadowscan.py -t https://target.com --proxy http://127.0.0.1:8080 -v

# Specific modules only
python shadowscan.py -t https://target.com --modules recon,exposure,injection

# Fast recon only, no report
python shadowscan.py -t https://target.com --modules recon --no-report --delay 0.1
```

---

## Modules

| Module | Coverage |
|--------|----------|
| `recon` | 35+ common paths, tech fingerprinting (15 stacks), JS crawling, OpenAPI/Swagger parsing, git exposure |
| `exposure` | 25+ secret patterns (AWS, Sentry DSN, Mixpanel, JWT, Stripe, GitHub, etc.), CORS misconfig, security headers, error disclosure |
| `auth` | Auth bypass (header manipulation + path normalization), IDOR, user enumeration, rate limit check, JWT algorithm analysis |
| `api` | Unauthenticated REST endpoints, GraphQL introspection + batching, mass assignment, API version downgrade |
| `injection` | SQLi (error-based + time-blind), SSTI, reflected XSS, Open Redirect, Path Traversal/LFI, SSRF (AWS/GCP/Azure), CMDi |

---

## Chaining Engine

Rules in `chains/rules.yaml` define what triggers what:

```yaml
- trigger: unauthenticated_api
  next_modules: [injection, exposure, idor]
  priority: 1
  reason: "Unauthenticated API → inject, check data exposure, test IDOR"

- trigger: secret_exposed
  next_modules: [auth_replay, recon_expand]
  priority: 1
  reason: "Secret found → try using it for auth, expand recon scope"

- trigger: ssrf
  next_modules: [exposure, auth]
  priority: 1
  reason: "SSRF confirmed → fetch internal endpoints for secrets"
```

The engine runs after every module. Findings trigger new modules. Chains fire until the attack surface is exhausted.

---

## LLM Integration

With `--llm`, ShadowScan calls Claude API to:
- Identify non-obvious attack chains across findings
- Suggest highest-impact next probes
- Assess combined severity of chained findings
- Generate the executive summary in the HTML report

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python shadowscan.py -t https://target.com --llm -o report.html
```

---

## Adding Modules

```python
# modules/your_module.py
class YourModule:
    def __init__(self, scanner: Scanner, ctx: ScanContext):
        self.scanner = scanner
        self.ctx = ctx

    def run(self) -> List[Finding]:
        findings = []
        # ... probe logic
        self.ctx.mark_complete("your_module")
        return findings
```

1. Add class to `modules/your_module.py`
2. Register in `MODULE_MAP` in `shadowscan.py`
3. Add trigger rules in `chains/rules.yaml`

---

## Project Structure

```
ShadowScan/
├── shadowscan.py          # Entry point + orchestrator
├── core/
│   ├── scanner.py         # HTTP engine (session, proxy, retry, jitter)
│   ├── context.py         # Shared scan state + finding graph
│   ├── chainer.py         # Rule-based chaining engine
│   └── llm_advisor.py     # Claude API integration
├── modules/
│   ├── recon.py           # Endpoint + tech discovery
│   ├── exposure.py        # Secrets + misconfigurations
│   ├── auth.py            # Auth + IDOR + JWT
│   ├── api.py             # REST + GraphQL
│   └── injection.py       # SQLi, SSTI, XSS, LFI, SSRF, CMDi
├── chains/
│   └── rules.yaml         # Chaining rules
├── output/
│   ├── terminal.py        # Rich CLI output
│   └── reporter.py        # HTML report generator
└── requirements.txt
```

---

## Legal Disclaimer

For **authorized security testing only**. Only use against targets you have explicit written permission to test. The author is not responsible for misuse.

---

## Shadow Project Family

| Tool | Description |
|------|-------------|
| [ShadowC2](https://github.com/saksht/shadowc2) | Custom C2 framework for post-exploitation |
| [ShadowRecon](https://github.com/saksht/shadowrecon) | Modular OSINT and recon framework |
| **ShadowScan** | Intelligent vulnerability chaining engine |
