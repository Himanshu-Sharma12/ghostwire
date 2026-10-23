# Changelog

## 0.2.0

### Security
- Generated Python/TypeScript SDKs and Postman collections no longer embed the captured token. Credentials come from the `auth_token` argument, an environment variable (`API_TOKEN`, `API_KEY`, `API_SESSION`, …) or the `{{authToken}}` Postman variable. Use `gw analyze --embed-secrets` to opt back in.
- Passwords, tokens, API keys and JWTs are redacted from OpenAPI examples, mock fixtures and Postman bodies: in JSON bodies (including nested lists/objects under secret keys), form and multipart bodies, and query strings.
- `gw mock` and generated mock servers bind to `127.0.0.1` by default (`--host` to change).
- `gw call` asks for confirmation before sending POST/PUT/PATCH/DELETE requests (`--yes` to skip).

### Fixed
- Path clustering no longer treats snake_case words (`/api/user_profile`, `/v1/get_items`) as IDs, and parameter names are singularized correctly (`addresses` → `addressId`, `status` → `statusId`, `user-groups` → `userGroupId`).
- GraphQL operations are real endpoints on the real URL instead of a fake `/graphql?op=Name` path. The mock server dispatches by `operationName`, SDK methods take `variables`, and the OpenAPI spec is valid.
- Query and path parameters such as `filter[status]`, `page.size`, `from` or `self` produce valid Python/TypeScript identifiers, and path values are URL-encoded.
- Mock servers register static routes before parameterized ones (`/users/me` is no longer shadowed by `/users/{userId}`).
- `gw curl` quotes payloads correctly for the shell and prints the full command without truncation.
- Rich markup in captured names (e.g. `[status]`) no longer disappears from CLI tables.
- Unreadable or non-HAR files produce a clear error instead of a Python traceback.
- `gw mock` no longer leaves a temporary folder behind.
- The example dummyjson capture no longer contains a still-valid demo refresh token.
- Form-urlencoded and multipart endpoints are sent with their real encoding by both SDKs, Postman, `gw curl` and `gw call` (OAuth token endpoints work).
- Captures spanning several hosts call each endpoint on its own host (SDKs use absolute URLs; OpenAPI adds per-operation `servers`).
- Generated code stays valid for hostile names: query params like `quote`/`str`, backslashes or `"""` in names, `*/` in paths or GraphQL operation names.
- Anonymous GraphQL queries, GraphQL over GET and `/gql` endpoints are recognised; the mock dispatches GraphQL GET requests.
- `NaN`/`Infinity` in captured JSON become `null` instead of breaking the mock server and OpenAPI JSON.
- Unfinished requests (status 0) and non-HTTP entries (`chrome-extension:`, `data:`) no longer produce bogus responses/endpoints.
- OpenAPI operation IDs are unique; parameter names are always valid identifiers; nullable union schemas validate the data they were inferred from; path parameter types consider every observation.

### Added
- Batched GraphQL (a JSON list of operations, as sent by Apollo's batch link) is split into one endpoint per operation; SDKs, mock, OpenAPI, Postman and `gw curl`/`gw call` use the batched wire format. GraphQL is also recognised by request shape, not only by a `/graphql` URL.
- `gw inspect` shows each endpoint's host and groups the table by host.
- Tracker filtering covers ads, marketing/CRM, consent and session-replay hosts (70 in total), matches hosts by domain suffix, and drops telemetry paths (`/collect`, `/log_event`, `/pixel`, `/api/sentry`, …) on any host. `--domain` overrides the lists.
- Faster on large captures: redaction runs only on values that reach the output, and schema inference samples at most 200 bodies per endpoint (a 116 MB API-heavy capture went from 18 s to 5 s).
- Analyze several HAR files at once: `gw analyze login.har browse.har`.
- Auth detection picks the most-used scheme and its most recent token.
- Schema inference handles nullable fields, integer/number widening and merges array items across elements.
- Basic, custom `Authorization` and cookie auth supported in all generators.
- Test suite covering every generator (Python import + requests, `tsc --strict`, OpenAPI validation, mock server), CI on Python 3.9–3.13, and an opt-in live test against dummyjson.com.

### Changed
- PyPI distribution name is `ghostwire-cli` (`ghostwire` is taken by an unrelated project). The import name and `gw` command are unchanged.
- SDK constructors take `auth_token` (Python) / `authToken` (TypeScript) instead of `token` / `api_key`.

## 0.1.0

- Initial release: HAR parsing, noise filtering, path clustering, schema & auth inference, OpenAPI/Python/TypeScript/mock/Postman generators, and the `inspect`, `analyze`, `mock`, `curl` and `call` commands.
