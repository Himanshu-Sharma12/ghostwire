# GhostWire (`gw`) — Project Context & Memory

> **Autonomous Reverse-Engineering Agent for Hidden APIs & Web Traffic**  
> *Repository:* [https://github.com/Himanshu-Sharma12/ghostwire](https://github.com/Himanshu-Sharma12/ghostwire)  
> *Author / Maintainer:* Himanshu Sharma ([@Himanshu-Sharma12](https://github.com/Himanshu-Sharma12))  
> *License:* MIT  
> *Version:* `0.1.0`  
> *Current Status:* Core engine complete, generators complete, live internet e2e tested, packaging configured, git history verified and author-aligned.

---

## 1. Executive Summary & Vision

Developers, security researchers, and QA engineers routinely reverse-engineer web apps, mobile backends, and internal services by recording `.har` traffic in DevTools or Proxies (mitmproxy, Charles, Burp). Historically, turning raw traffic into useful artifacts required tedious manual work:
- Sifting through hundreds of tracking/telemetry requests (Google Analytics, Sentry, Datadog).
- Guessing route parameters (`/users/123` vs `/users/{id}`).
- Manually writing OpenAPI specifications, client SDKs, and mock servers.

**GhostWire (`gw`)** is an autonomous reverse-engineering CLI agent that consumes raw network captures (`.har`), scrubs noise, clusters routes, infers schemas, extracts authentication, and automatically synthesizes:
1. **OpenAPI 3.1.0** specifications (YAML & JSON).
2. **Typed Python SDK** (`httpx`) with automatic auth injection.
3. **Zero-dependency TypeScript SDK** (native `fetch`).
4. **Executable FastAPI Mock Server** with realistic captured fixtures.
5. **Postman Collection v2.1.0** for 1-click team imports.
6. **Live CLI Inspection & Execution** (`gw inspect`, `gw analyze`, `gw mock`, `gw curl`, `gw call`).

---

## 2. System Architecture & Components

```
                Raw .har Capture / Live Traffic
                              │
                              ▼
                   ┌─────────────────────┐
                   │ ghostwire/parser.py │  (HAR JSON parsing & normalization)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ ghostwire/filter.py │  (Scrub 30+ trackers & static assets)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ ghostwire/cluster.py│  (Dynamic path clustering & GraphQL)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ ghostwire/schema.py │  (Recursive schema inference & merge)
                   │  & auth.py          │  (Bearer, Basic, API Keys, Cookies)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ghostwire/analyzer.py│  (Synthesizes DiscoveredEndpoint list)
                   └──────────┬──────────┘
                              │
        ┌──────────────┬──────┴───────┬──────────────┬──────────────┐
        ▼              ▼              ▼              ▼              ▼
  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
  │  OpenAPI  │  │Python SDK │  │  TS SDK   │  │FastAPI    │  │  Postman  │
  │3.1 (JSON/ │  │  (httpx)  │  │  (fetch)  │  │Mock Server│  │Collection │
  │   YAML)   │  │           │  │           │  │           │  │  v2.1.0   │
  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘
```

### Module Breakdown (`ghostwire/`)

| Module | Location | Purpose & Implementation Details |
|---|---|---|
| **Data Models** | `ghostwire/core/models.py` | Pydantic V2 models: `CapturedTransaction`, `DiscoveredEndpoint`, `AuthInfo`, `QueryParamInfo`, `PathClusterResult`. |
| **Noise Scrubber** | `ghostwire/core/filter.py` | Eliminates 30+ trackers (Google Analytics, Sentry, Datadog, Hotjar, Facebook, Segment, TikTok) and static assets (`.png`, `.js`, `.css`, fonts, etc.). |
| **Path Clustering** | `ghostwire/core/cluster.py` | Parameterizes dynamic path segments (Integers, UUIDv4, MongoDB ObjectId, Hex SHAs, ULID, prefixed IDs `ws_123` -> `{workspaceId}`). Contains GraphQL operation decompiler to partition POST `/graphql` into distinct operations. |
| **Schema Inference** | `ghostwire/core/schema.py` | Deep JSON Schema inference; merges multiple request/response observations into unified types; handles query parameter typing and optional fields. |
| **Auth Extraction** | `ghostwire/core/auth.py` | Detects Bearer tokens (JWTs), Basic auth, API keys (`X-Api-Key`, `api_key`), cookies. Masking helper for secure CLI logs. |
| **Pipeline Orchestrator** | `ghostwire/core/analyzer.py` | Coordinates parsing, scrubbing, clustering, schema generation, and returns structured metadata. |
| **CLI & TUI** | `ghostwire/cli.py` | Rich interactive terminal with ASCII banner, tables, spinners, progress meters, and commands: `inspect`, `analyze`, `mock`, `curl`, `call`, `version`. |
| **OpenAPI Generator** | `ghostwire/generators/openapi.py` | Emits OpenAPI 3.1.0 specifications in both `.json` and `.yaml` formats. |
| **Python SDK Generator** | `ghostwire/generators/python_sdk.py` | Creates typed Python client with `httpx`, auto-auth injection, dynamic parameter interpolation, and 204 No-Content handling. |
| **TypeScript SDK Generator** | `ghostwire/generators/typescript_sdk.py` | Emits zero-dependency TypeScript SDK using native `fetch` with full type annotations. |
| **Mock Server Generator** | `ghostwire/generators/mock_server.py` | Synthesizes runnable FastAPI server with CORS, realistic fixtures, and matching route signatures. |
| **Postman Generator** | `ghostwire/generators/postman.py` | Generates official Postman Collection v2.1.0 JSON format with pre-configured auth variables. |

---

## 3. Work Completed To Date

### 1. Codebase Creation
- Built the entire GhostWire engine from scratch in `/Users/hinanshu-sharma/Desktop/aiagent`.
- Configured clean modular architecture with zero circular dependencies.

### 2. Live Internet Testing (Zero Mocks)
- Recorded live traffic capture from `https://dummyjson.com` using `examples/capture_live_traffic.py` -> saved to `examples/live_dummyjson.har`.
- Executed `gw analyze` to generate production client in `live_sdk/`.
- Built and ran `test_live_internet.py` against `https://dummyjson.com` over the public web:
  - `client.get_auth_me()` (Authenticated profile via Bearer JWT) -> **PASS**
  - `client.get_products_by_productId(productId=5)` (Dynamic path lookup) -> **PASS**
  - `client.get_products_search(q='laptop', limit=2)` (Query string parameters) -> **PASS**
  - `client.create_products_add(payload=...)` (POST mutation) -> **PASS**

### 3. Unit Test Suite
- Automated test suite in `tests/test_engine.py`:
  - `test_filter_scrubs_trackers`: Validates tracker elimination.
  - `test_cluster_parameterizes_ids`: Validates UUID, Mongo, and numeric path parameterization.
  - `test_auth_extraction`: Validates Bearer and API Key token detection.
  - `test_schema_inference`: Validates deep dictionary and type inference.
  - `test_full_analyzer_pipeline`: Validates end-to-end pipeline against test HAR fixture.
  - `test_graphql_decompiler`: Validates GraphQL operation extraction.
- Current test status: **100% Passing (6/6 in ~0.04s)**.

### 4. Fixes & Refinements Applied
- **PEP 639 Compliance**: Updated `pyproject.toml` with standard `license = "MIT"` and removed legacy setuptools classifiers.
- **Package Discovery**: Added `[tool.setuptools.packages.find] include = ["ghostwire*"]` to prevent `setuptools` from bundling local test output directories (`my_api`, `live_sdk`).
- **Python Environment Parity**: Installed all dependencies in both local pyenv Python 3.13 and base Conda Python 3.12 environments.
- **Mock Server Serialization**: Replaced raw `json.dumps()` string substitution with `repr()` to fix Python keyword serialization (`true` -> `True`), and added explicit 204 status handling.
- **Dynamic Module Loading**: Replaced dynamic `exec()` in `cli.py mock` with clean `importlib.util.spec_from_file_location`.

### 5. Git & GitHub Configuration
- **Active Account:** `Himanshu-Sharma12` (authenticated via GitHub CLI `gh`).
- **Git User Name:** `Himanshu Sharma`.
- **Git User Email:** `Himanshu-Sharma12@users.noreply.github.com` (configured locally and globally).
- **Git Commit History:** Cleanly rebased all 8 commits with `git rebase --root --exec 'git commit --amend --no-edit --reset-author'` so every commit in history belongs to `Himanshu-Sharma12@users.noreply.github.com`.
- **Remote:** `origin` set to `https://github.com/Himanshu-Sharma12/ghostwire.git`.
- **Branch:** `main` (clean working tree).

---

## 4. Key CLI Commands Reference

```bash
# Inspect any HAR file to view discovered routes and scrubbed noise
gw inspect examples/sample_traffic.har

# Analyze capture and generate all artifacts
gw analyze examples/sample_traffic.har --generate-all --output-dir ./output

# Spin up an instant mock server from a capture
gw mock examples/sample_traffic.har --port 8000

# Print a ready-to-use cURL command with real headers & payload
gw curl examples/sample_traffic.har 0

# Send a real HTTP call directly from the terminal
gw call examples/sample_traffic.har 0
```

---

## 5. Next Steps / Pending Actions

1. **Push to GitHub**:
   ```bash
   gh repo create Himanshu-Sharma12/ghostwire --public --source=. --remote=origin --push
   ```
2. **Verify Remote Display**:
   - Check [https://github.com/Himanshu-Sharma12/ghostwire](https://github.com/Himanshu-Sharma12/ghostwire) to confirm badges, MIT License tag, and author attribution are active.
3. **Community Distribution**:
   - Post on **Hacker News (Show HN)**.
   - Post on **Reddit** (`r/Python`, `r/webscraping`, `r/programming`).
   - Post on **Twitter / X** with an animated demo terminal recording.
