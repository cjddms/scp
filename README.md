# AI-NAC Security Gateway

Single-file implementation of the AI-NAC core engine (`nac-proxy.py`):

```
Agent Auth -> Protocol Inspector (MCP/A2A) -> Security Analyzers
           -> Risk Engine -> Policy Engine (decision) -> SQLite Logging
```

Plus a FastAPI management API, a single-file admin dashboard, and a mitmproxy
addon for real traffic interception. SQLite DB (`nac.db`) is created
automatically on first run.

## Status

All 9 spec phases implemented and passing `--selftest`:

| Phase | Feature | File |
|---|---|---|
| 1 | Proxy / traffic intercept (mitmproxy addon) | `nac-proxy.py` |
| 2 | Agent auth & registration (X-Agent-ID / X-Agent-Token, hashed) | `nac-proxy.py` |
| 3 | MCP Inspector (JSON-RPC tool/args/target) | `nac-proxy.py` |
| 4 | A2A Inspector (caller/target/skill/payload) | `nac-proxy.py` |
| 5 | Policy Engine — default-deny, explicit DENY > ALLOW > specificity | `nac-proxy.py` |
| 6 | Risk Analysis — rule-based advisory score 0-100 | `nac-proxy.py` |
| 7 | Security Analyzers — tool poisoning, permission abuse, sensitive data, rug pull | `nac-proxy.py` |
| 8 | Logging + Management API (agents/policies/logs/events/risk/decisions) | `nac-proxy.py` |
| 9 | Admin dashboard (no build step) | `dashboard.html` |

## Requirements

- Python 3.10+
- `pip install fastapi uvicorn` (for mode 2)
- `pip install mitmproxy` (for mode 3 only)

On this machine Python is at
`C:\Users\user\AppData\Local\Programs\Python\Python312\python.exe`.
If `python` is not on PATH, either restart the terminal (User PATH already
has it) or use the full path. Examples below use `python`.

```powershell
cd C:\Users\user\Desktop\scp
```

## 1. Self-test (no dependencies)

Checks the whole decision pipeline with assertions.

```powershell
python nac-proxy.py --selftest
# -> nac-proxy selftest: OK (all assertions passed)
```

## 2. Management API (FastAPI)

```powershell
python nac-proxy.py
```

- Dashboard: http://127.0.0.1:8000/  (agents, policies, traffic, events, risk, evaluate — `dashboard.html`, no build step)
- Swagger UI: http://127.0.0.1:8000/docs
- Endpoints: `/api/agents`, `/api/policies`, `/api/logs`, `/api/events`,
  `/api/risk`, `/api/decisions/{request_id}`
- `/api/evaluate` runs the full pipeline on a request you POST, without mitmproxy.

Quick check (server running, second terminal):

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/evaluate `
  -H "Content-Type: application/json" `
  -d '{\"headers\":{},\"body\":{},\"destination\":\"x\"}'
# -> {"decision":"DENY","reason":"missing X-Agent-ID", ...}
```

## 3. Real traffic interception (mitmproxy)

```powershell
pip install mitmproxy
python -m mitmdump -s nac-proxy.py -p 8080
```

Then point the AI Agent's HTTP(S) proxy at `127.0.0.1:8080`.

Every request must carry:

```
X-Agent-ID: agent-001
X-Agent-Token: <token>
```

Default policy is **deny** — register the agent and add an ALLOW policy via
the API (mode 2) first, otherwise every request gets a 403.

### Minimal setup example

```powershell
# register an agent
curl.exe -X POST http://127.0.0.1:8000/api/agents `
  -H "Content-Type: application/json" `
  -d '{\"agent_id\":\"agent-001\",\"agent_name\":\"Test\",\"token\":\"secret\",\"allowed_targets\":\"mcp-search\"}'

# allow it to call the "search" tool on mcp-search
curl.exe -X POST http://127.0.0.1:8000/api/policies `
  -H "Content-Type: application/json" `
  -d '{\"name\":\"allow-search\",\"agent_id\":\"agent-001\",\"protocol\":\"mcp\",\"target\":\"mcp-search\",\"tool\":\"search\",\"action\":\"ALLOW\",\"priority\":10}'
```

## Notes

- `mitmdump` and `python nac-proxy.py` share the same `nac.db`, so agents and
  policies added through the API apply to intercepted traffic immediately.
- The dashboard is one static `dashboard.html` (vanilla JS, no React/Vite build)
  served at `/`; it only calls the `/api` endpoints.
- Out of scope (per spec): test MCP/A2A servers, attack tooling,
  Postgres/Redis/Docker, ML/LLM classification.
