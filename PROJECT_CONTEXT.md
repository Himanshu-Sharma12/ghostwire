# GhostWire (`gw`) — Project Context & Memory

> **Turn browser traffic (HAR) into OpenAPI specs, typed SDKs, mock servers and Postman collections**  
> *Repository:* [https://github.com/Himanshu-Sharma12/ghostwire](https://github.com/Himanshu-Sharma12/ghostwire)  
> *Author / Maintainer:* Himanshu Sharma ([@Himanshu-Sharma12](https://github.com/Himanshu-Sharma12))  
> *License:* MIT  
> *Version:* `0.2.0` (PyPI distribution name `ghostwire-cli`; not yet published)  
> *Current Status:* v0.2.0 hardening complete: secret-safe generators, fixed clustering/GraphQL, batched GraphQL, 60 tests + CI, validated on a real Chrome capture. Not yet pushed to GitHub.

---

## 1. Executive Summary & Vision

Developers, security researchers, and QA engineers routinely reverse-engineer web apps, mobile backends, and internal services by recording `.har` traffic in DevTools or Proxies (mitmproxy, Charles, Burp). Historically, turning raw traffic into useful artifacts required tedious manual work:
- Sifting through hundreds of tracking/telemetry requests (Google Analytics, Sentry, Datadog).
- Guessing route parameters (`/users/123` vs `/users/{id}`).
- Manually writing OpenAPI specifications, client SDKs, and mock servers.

**GhostWire (`gw`)** is an autonomous reverse-engineering CLI agent that consumes raw network captures (`.har`), scrubs noise, clusters routes, infers schemas, extracts authentication, and automatically synthesizes:
1. **OpenAPI 3.1.0** specifications (YAML & JSON).
1. **Typed Python SDK** (`httpx`) with automatic auth injection.
2. **Zero-dependency TypeScript SDK** (native `fetch`).
3. **Executable FastAPI Mock Server** with realistic captured fixtures.
4. **Postman Collection v2.1.0** for 1-click team imports.
5. **Live CLI Inspection & Execution** (`gw inspect`, `gw analyze`, `gw mock`, `gw curl`, `gw call`).

---

## 2. System Architecture & Components

```
                Raw .har Capture / Live Traffic
                              │
                              ▼
                   ┌─────────────────────┐
                   │ core/parser.py      │  (HAR JSON parsing & normalization)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ core/filter.py      │  (Scrub 30+ trackers & static assets)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ core/cluster.py     │  (Dynamic path clustering & GraphQL)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ core/schema.py,     │  (Recursive schema inference & merge)
                   │ auth.py, redact.py  │  (Bearer, Basic, API Keys, Cookies; secret redaction)
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ core/analyzer.py    │  (Synthesizes DiscoveredEndpoint list)
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
| **HAR Parser** | `ghostwire/core/parser.py` | Parses HAR JSON (JSON, form-encoded and base64 bodies) into `CapturedTransaction`s; applies the noise filter. |
| **Data Models** | `ghostwire/core/models.py` | Pydantic V2 models: `CapturedTransaction`, `EndpointModel` (incl. `graphql_operation`), `ParameterModel`, `RequestSchema`, `ResponseSchema`, `AuthInfo`. |
| **Noise Scrubber** | `ghostwire/core/filter.py` | Eliminates 30+ trackers (Google Analytics, Sentry, Datadog, Hotjar, Facebook, Segment, TikTok) and static assets (`.png`, `.js`, `.css`, fonts, etc.). |
| **Path Clustering** | `ghostwire/core/cluster.py` | Parameterizes dynamic path segments (Integers, UUID, MongoDB ObjectId, Hex SHAs, ULID, prefixed IDs `ws_alpha` -> `{workspaceId}`). Prefixed IDs need a digit or a plural parent so `/api/user_profile` stays literal; names are singularized/camelCased (`user-groups` -> `userGroupId`). Clusters by `(method, path, graphql_operation)`. |
| **Secret Redaction** | `ghostwire/core/redact.py` | Masks passwords/tokens/API keys/JWTs in payloads before they reach examples and fixtures (on by default; `--embed-secrets` disables). |
| **Schema Inference** | `ghostwire/core/schema.py` | Deep JSON Schema inference; merges multiple request/response observations into unified types; handles query parameter typing and optional fields. |
| **Auth Extraction** | `ghostwire/core/auth.py` | Detects Bearer tokens (JWTs), Basic auth, API keys, session cookies. Picks the most frequent scheme and its latest token. Masking helper for CLI output. |
| **Pipeline Orchestrator** | `ghostwire/core/analyzer.py` | Coordinates parsing, scrubbing, clustering, schema generation, and returns structured metadata. |
| **CLI & TUI** | `ghostwire/cli.py` | Rich terminal UI with commands `inspect`, `analyze`, `mock`, `curl`, `call`, `version`. `inspect`/`analyze`/`mock` accept several HAR files. |
| **Identifier Naming** | `ghostwire/generators/naming.py` | Converts captured names (`filter[status]`, `from`, `self`) to valid unique Python/TS identifiers. |
| **OpenAPI Generator** | `ghostwire/generators/openapi.py` | Emits OpenAPI 3.1.0 specifications in both `.json` and `.yaml` formats. |
| **Python SDK Generator** | `ghostwire/generators/python_sdk.py` | Typed `httpx` client; credential from `auth_token` arg or env var (`API_TOKEN`, `API_KEY`, `API_SESSION`, …); URL-encoded path params; GraphQL methods take `variables`. |
| **TypeScript SDK Generator** | `ghostwire/generators/typescript_sdk.py` | Emits zero-dependency TypeScript SDK using native `fetch` with full type annotations. |
| **Mock Server Generator** | `ghostwire/generators/mock_server.py` | Runnable FastAPI server with CORS and captured fixtures; static routes registered before parameterized ones; one GraphQL route dispatching by `operationName`; binds 127.0.0.1. |
| **Postman Generator** | `ghostwire/generators/postman.py` | Postman Collection v2.1.0 using an `{{authToken}}` collection variable and `:param` path variables. |

---

## 3. Work Completed To Date

### 1. Codebase Creation
- Built the entire GhostWire engine from scratch.
- Configured clean modular architecture with zero circular dependencies.

### 2. Live Internet Testing (Zero Mocks)
- Recorded live traffic capture from `https://dummyjson.com` using `examples/capture_live_traffic.py` -> saved to `examples/live_dummyjson.har`.
- Executed `gw analyze` to generate production client in `live_sdk/`.
- Built and ran `test_live_internet.py` against `https://dummyjson.com` over the public web:
  - `client.get_auth_me()` (Authenticated profile via Bearer JWT) -> **PASS**
  - `client.get_products_by_productId(productId=5)` (Dynamic path lookup) -> **PASS**
  - `client.get_products_search(q='laptop', limit=2)` (Query string parameters) -> **PASS**
  - `client.create_products_add(payload=...)` (POST mutation) -> **PASS**

### 3. Test Suite (60 tests + 1 opt-in live test)
- `tests/test_engine.py`: filtering, clustering edge cases, schema merging (nullable, number widening, arrays), dominant-auth detection, redaction, GraphQL splitting, multi-HAR merging.
- `tests/test_generators.py`: for every capture (`examples/*.har`, `tests/fixtures/edge_cases.har`) checks no secret is written by default, the Python SDK imports and sends correct requests, the mock server serves fixtures (incl. GraphQL dispatch), the OpenAPI spec passes `openapi-spec-validator`, the Postman collection is consistent, and the TS SDK passes `tsc --strict` (needs Node).
- `tests/test_live.py`: records real dummyjson.com traffic, generates an SDK and calls the live API. Runs only with `GHOSTWIRE_LIVE=1` (replaces the old root-level `test_live_internet.py`).
- Verified passing on Python 3.9, 3.10, 3.12 and 3.13 from a clean (non-editable) install; CI (`.github/workflows/ci.yml`) covers 3.9–3.13.
- Additional verification done outside the suite: a stress HAR of ~30 hostile cases, an independent code review (8 bugs found and fixed), 100 MB captures (2.8 s browsing-style, 5.1 s API-heavy), the TS SDK executed in Node against the generated mock, and a real Chrome capture of lesswrong.com (batched GraphQL split into 6 operations; generated SDK called the live API successfully).
- Personal captures are git-ignored (`*.har` except `examples/` and `tests/fixtures/`).

### 4. Fixes & Refinements Applied
- **PEP 639 Compliance**: Updated `pyproject.toml` with standard `license = "MIT"` and removed legacy setuptools classifiers.
- **Package Discovery**: Added `[tool.setuptools.packages.find] include = ["ghostwire*"]` to prevent `setuptools` from bundling local test output directories (`my_api`, `live_sdk`).
- **Python Environment Parity**: Installed all dependencies in both local pyenv Python 3.13 and base Conda Python 3.12 environments.
- **Mock Server Serialization**: Replaced raw `json.dumps()` string substitution with `repr()` to fix Python keyword serialization (`true` -> `True`), and added explicit 204 status handling.
- **Dynamic Module Loading**: Replaced dynamic `exec()` in `cli.py mock` with clean `importlib.util.spec_from_file_location`.
- **v0.2.0 hardening** (see `CHANGELOG.md`): secret-safe generators, redaction, clustering fixes, real GraphQL endpoints, identifier sanitization, Rich-markup escaping, raw `gw curl` output, `gw call` confirmation, removal of artificial `sleep` delays, honest README, CONTRIBUTING, issue template, CI.

### 5. Git & GitHub Configuration
- **GitHub CLI accounts:** both `Himanshu-Sharma12` and `himanshu-rooman` are logged in to `gh`; check which is active with `gh auth status` and switch with `gh auth switch -u Himanshu-Sharma12` before pushing.
- **Git User Name:** `Himanshu Sharma`.
- **Git User Email:** `Himanshu-Sharma12@users.noreply.github.com` (configured locally and globally).
- **Git Commit History:** Cleanly rebased all commits with `git rebase --root --exec 'git commit --amend --no-edit --reset-author'` so every commit in history belongs to `Himanshu-Sharma12@users.noreply.github.com`.
- **Remote:** `origin` set to `https://github.com/Himanshu-Sharma12/ghostwire.git`.
- **Branch:** `main`.

---

## 4. Key CLI Commands Reference

```bash
# Inspect any HAR file to view discovered routes and scrubbed noise
gw inspect examples/sample_traffic.har

# Analyze one or more captures and generate all artifacts (secrets kept out by default)
gw analyze examples/sample_traffic.har --output-dir ./output
gw analyze a.har b.har -o ./output --embed-secrets   # private use only

# Spin up an instant mock server from a capture
gw mock examples/sample_traffic.har --port 8000

# Print a ready-to-use cURL command with real headers & payload (target = operation ID or path substring)
gw curl examples/sample_traffic.har get_user_me

# Send a real HTTP call directly from the terminal (asks before non-GET; --yes to skip)
gw call examples/sample_traffic.har get_user_me

# Run tests (live test is opt-in)
pytest -q
GHOSTWIRE_LIVE=1 pytest tests/test_live.py
```

---

## 5. Next Steps / Pending Actions

1. **Push to GitHub**: `origin` is already configured, so do not use `gh repo create --remote=origin` (it fails). Instead:
   ```bash
   gh auth switch -u Himanshu-Sharma12
   gh repo view Himanshu-Sharma12/ghostwire || gh repo create Himanshu-Sharma12/ghostwire --public
   git push -u origin main
   ```
   Then check that the CI badge goes green (Python 3.9 is only verified in CI).
2. **Publish to PyPI** as `ghostwire-cli` (`python -m build && twine upload dist/*`), then switch the README install line to `pip install ghostwire-cli`.
3. **Launch assets**: record an asciinema/GIF of `gw inspect` + `gw analyze` + `gw mock` on a real public site and put it at the top of the README; add GitHub topics (`har`, `openapi`, `reverse-engineering`, `sdk-generator`, `mock-server`, `graphql`).
4. **Community distribution**: Show HN, r/Python, r/webscraping, r/programming, X. Lead with the "DevTools HAR → working SDK + mock in one command" demo and the secrets-safe default.
5. **Roadmap**: `gw listen` (CDP live capture), per-host SDKs, typed models (TypedDict / TS interfaces) from inferred schemas.
