"""Generated artifacts must be valid, runnable and free of captured secrets."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ghostwire.core.analyzer import ReverseEngineeringEngine
from ghostwire.generators.mock_server import MockServerGenerator
from ghostwire.generators.openapi import OpenApiGenerator
from ghostwire.generators.postman import PostmanCollectionGenerator
from ghostwire.generators.python_sdk import PythonSdkGenerator
from ghostwire.generators.typescript_sdk import TypeScriptSdkGenerator

ROOT = Path(__file__).parent.parent
CAPTURES = [
    ROOT / "examples" / "sample_traffic.har",
    ROOT / "examples" / "live_dummyjson.har",
    ROOT / "tests" / "fixtures" / "edge_cases.har",
]

SECRETS = [
    "user_token_987654",          # sample_traffic.har bearer token
    "s3cr3t-session-value-123",   # edge_cases.har session cookie
    "hunter2",                    # edge_cases.har login password
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI3In0",  # edge_cases.har JWT in response body
    "emilyspass",                 # live_dummyjson.har login password
]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=CAPTURES, ids=lambda p: p.stem)
def analysis(request):
    return ReverseEngineeringEngine().analyze_har(str(request.param))


def generate_all(endpoints, auth, out: Path, embed_secrets: bool = False):
    OpenApiGenerator().export_files(endpoints, auth, out)
    PythonSdkGenerator(embed_secrets=embed_secrets).export_file(endpoints, auth, out)
    TypeScriptSdkGenerator(embed_secrets=embed_secrets).export_file(endpoints, auth, out)
    MockServerGenerator().export_file(endpoints, auth, out)
    PostmanCollectionGenerator(embed_secrets=embed_secrets).export_file(endpoints, auth, out)


def test_no_secrets_written_by_default(analysis, tmp_path):
    endpoints, auth, _ = analysis
    generate_all(endpoints, auth, tmp_path)
    for artifact in tmp_path.iterdir():
        text = artifact.read_text(encoding="utf-8")
        for secret in SECRETS:
            assert secret not in text, f"{secret!r} leaked into {artifact.name}"
        if auth and auth.token_value:
            assert auth.token_value not in text, f"captured credential leaked into {artifact.name}"


def test_embed_secrets_opt_in(tmp_path):
    endpoints, auth, _ = ReverseEngineeringEngine(redact_secrets=False).analyze_har(str(CAPTURES[0]))
    code = PythonSdkGenerator(embed_secrets=True).generate_code(endpoints, auth)
    assert auth.token_value in code


def test_python_sdk_compiles_and_imports(analysis, tmp_path):
    endpoints, auth, _ = analysis
    path = PythonSdkGenerator().export_file(endpoints, auth, tmp_path)
    module = load_module(path, f"gw_client_{tmp_path.name}")
    client = module.ApiClient(auth_token="test-token")
    for ep in endpoints:
        assert any(name.startswith(ep.operation_id) for name in dir(client))
    client.close()


def test_python_sdk_sends_requests(tmp_path, monkeypatch):
    import httpx

    endpoints, auth, _ = ReverseEngineeringEngine().analyze_har(str(CAPTURES[2]))
    module = load_module(PythonSdkGenerator().export_file(endpoints, auth, tmp_path), "gw_client_edge")

    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setenv("API_SESSION", "from-env")
    client = module.ApiClient()
    client.client = httpx.Client(base_url=client.base_url, headers=client.headers, transport=httpx.MockTransport(handler))

    client.get_users_by_userId(userId="a/b")
    assert sent[-1].url.raw_path == b"/api/users/a%2Fb"
    assert sent[-1].headers["cookie"] == "sessionid=from-env"

    client.get_search(filter_status="open", from_="2026", page_size=5, self_=1)
    assert dict(sent[-1].url.params) == {"filter[status]": "open", "from": "2026", "page.size": "5", "self": "1"}

    client.graphql_RenameProject(variables={"id": "p_1", "name": "X"})
    body = json.loads(sent[-1].content)
    assert sent[-1].url.path == "/graphql"
    assert body["operationName"] == "RenameProject"
    assert body["variables"] == {"id": "p_1", "name": "X"}


def test_mock_server_serves_fixtures(tmp_path):
    from fastapi.testclient import TestClient

    endpoints, auth, _ = ReverseEngineeringEngine().analyze_har(str(CAPTURES[2]))
    module = load_module(MockServerGenerator().export_file(endpoints, auth, tmp_path), "gw_mock_edge")
    client = TestClient(module.app)

    # Static route wins over the parameterized one
    assert client.get("/api/users/me").json()["id"] == 7
    assert client.get("/api/users/999").json()["id"] == 42
    assert client.delete("/api/projects/prj_1/members/2").status_code == 204

    # GraphQL is dispatched by operationName, or by the operation in the query text
    viewer = client.post("/graphql", json={"operationName": "GetViewer", "query": "query GetViewer { viewer { id } }"})
    assert viewer.json() == {"data": {"viewer": {"id": "u_1", "name": "Ada"}}}
    teams = client.post("/graphql", json={"query": "query ListTeams { teams { id } }"})
    assert len(teams.json()["data"]["teams"]) == 2
    assert client.post("/graphql", json={"operationName": "Unknown"}).status_code == 400


def test_openapi_spec_is_valid(analysis):
    validator = pytest.importorskip("openapi_spec_validator")
    endpoints, auth, _ = analysis
    spec = OpenApiGenerator().generate_spec(endpoints, auth)
    validator.validate(json.loads(json.dumps(spec)))
    assert all("?" not in path for path in spec["paths"])


def test_openapi_folds_graphql_operations():
    endpoints, auth, _ = ReverseEngineeringEngine().analyze_har(str(CAPTURES[2]))
    operation = OpenApiGenerator().generate_spec(endpoints, auth)["paths"]["/graphql"]["post"]
    assert sorted(operation["x-graphql-operations"]) == ["GetViewer", "ListTeams", "RenameProject"]
    examples = operation["requestBody"]["content"]["application/json"]["examples"]
    assert set(examples) == {"GetViewer", "ListTeams", "RenameProject"}


def test_postman_collection_uses_variables(analysis):
    endpoints, auth, _ = analysis
    collection = PostmanCollectionGenerator().generate_collection(endpoints, auth)
    assert collection["info"]["schema"].endswith("v2.1.0/collection.json")
    for item in collection["item"]:
        url = item["request"]["url"]
        assert "{" not in url["raw"].replace("{{", "").replace("}}", "")
        assert len(url.get("variable", [])) == sum(1 for s in url["path"] if s.startswith(":"))


@pytest.mark.skipif(shutil.which("npx") is None, reason="Node.js is required to type-check the TypeScript SDK")
def test_typescript_sdk_type_checks(analysis, tmp_path):
    endpoints, auth, _ = analysis
    path = TypeScriptSdkGenerator().export_file(endpoints, auth, tmp_path)
    result = subprocess.run(
        ["npx", "--yes", "-p", "typescript@5.6.3", "tsc", "--noEmit", "--strict",
         "--target", "es2020", "--lib", "es2020,dom", str(path)],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_openapi_operation_ids_are_unique_and_graphql_folds_mixed_operations():
    validator = pytest.importorskip("openapi_spec_validator")
    from ghostwire.core.models import CapturedTransaction

    def tx(method, url, body=None):
        return CapturedTransaction(method=method, url=url, status_code=200, request_body=body, response_body={"ok": True})

    endpoints, auth, _ = ReverseEngineeringEngine().analyze_transactions([
        tx("GET", "https://x.dev/api/items"),
        tx("GET", "https://x.dev/items"),
        tx("POST", "https://x.dev/graphql", {"query": "{ anon }"}),
        tx("POST", "https://x.dev/graphql", {"operationName": "Named", "query": "query Named { n }"}),
        tx("POST", "https://x.dev/graphql", {"operationName": "Persisted", "extensions": {"persistedQuery": {"sha256Hash": "a"}}}),
    ])
    spec = OpenApiGenerator().generate_spec(endpoints, auth)
    validator.validate(json.loads(json.dumps(spec)))
    assert sorted(spec["paths"]["/graphql"]["post"]["x-graphql-operations"]) == ["Anonymous", "Named", "Persisted"]


def _tx(method, url, body=None, content_type="application/json", response=None, status=200):
    from ghostwire.core.models import CapturedTransaction
    from urllib.parse import parse_qs, urlparse
    return CapturedTransaction(
        method=method, url=url, status_code=status, request_body=body, request_content_type=content_type,
        response_body={"ok": True} if response is None else response, query_params=parse_qs(urlparse(url).query),
    )


def _all_outputs(endpoints, auth):
    return "\n".join([
        json.dumps(OpenApiGenerator().generate_spec(endpoints, auth)),
        json.dumps(PostmanCollectionGenerator().generate_collection(endpoints, auth)),
        PythonSdkGenerator().generate_code(endpoints, auth),
        TypeScriptSdkGenerator().generate_code(endpoints, auth),
        MockServerGenerator().generate_code(endpoints, auth),
    ])


def test_secrets_in_query_strings_raw_bodies_and_nested_values_are_redacted():
    multipart = '--b\r\nContent-Disposition: form-data; name="password"\r\n\r\nHunter2Secret\r\n--b--'
    endpoints, auth, _ = ReverseEngineeringEngine().analyze_transactions([
        _tx("GET", "https://x.dev/api/items?api_key=SECRETKEY123&access_token=SECRETTOK456&q=1"),
        _tx("POST", "https://x.dev/api/login", multipart, "multipart/form-data; boundary=b"),
        _tx("POST", "https://x.dev/api/keys", {"tokens": ["tokSECRETabc"]},
            response={"apiKeys": [{"name": "ci", "value": "sk_live_SECRET"}]}),
    ])
    output = _all_outputs(endpoints, auth)
    for secret in ["SECRETKEY123", "SECRETTOK456", "Hunter2Secret", "tokSECRETabc", "sk_live_SECRET"]:
        assert secret not in output


def test_generated_code_survives_hostile_names(tmp_path):
    endpoints, auth, _ = ReverseEngineeringEngine().analyze_transactions([
        _tx("GET", "https://x.dev/api/stocks/42?quote=AAPL&str=1"),
        _tx("GET", "https://x.dev/api/items?%5CN=1&a%22%22%22b=2"),
        _tx("GET", "https://x.dev/api/search/*/results"),
        _tx("POST", "https://x.dev/graphql", {"operationName": 'Get*/User"""\\N', "query": "query X { a }"}),
    ])
    for generator, name in [(PythonSdkGenerator(), "client.py"), (MockServerGenerator(), "mock_server.py")]:
        compile(generator.generate_code(endpoints, auth), name, "exec")

    module = load_module(PythonSdkGenerator().export_file(endpoints, auth, tmp_path), "gw_hostile")
    import httpx
    sent = []
    client = module.ApiClient()
    client.client = httpx.Client(base_url=client.base_url, transport=httpx.MockTransport(
        lambda request: (sent.append(request), httpx.Response(200, json={}))[1]))
    client.get_stocks_by_stockId(stockId=42, quote_="AAPL", str_=1)
    assert sent[-1].url.params["quote"] == "AAPL"

    if shutil.which("npx"):
        ts_path = TypeScriptSdkGenerator().export_file(endpoints, auth, tmp_path)
        result = subprocess.run(
            ["npx", "--yes", "-p", "typescript@5.6.3", "tsc", "--noEmit", "--strict",
             "--target", "es2020", "--lib", "es2020,dom", str(ts_path)],
            capture_output=True, text=True, timeout=300,
        )
        assert result.returncode == 0, result.stdout


def test_form_multipart_and_multi_host_requests(tmp_path):
    import httpx

    endpoints, auth, _ = ReverseEngineeringEngine().analyze_transactions([
        _tx("POST", "https://auth.x.dev/oauth/token", {"grant_type": "client_credentials", "scope": "read"},
            "application/x-www-form-urlencoded"),
        _tx("POST", "https://api.x.dev/api/upload", {"title": "a"}, "multipart/form-data; boundary=z"),
        _tx("GET", "https://api.x.dev/api/users"),
    ])
    module = load_module(PythonSdkGenerator().export_file(endpoints, auth, tmp_path), "gw_encodings")
    sent = []
    client = module.ApiClient()
    client.client = httpx.Client(base_url=client.base_url, transport=httpx.MockTransport(
        lambda request: (sent.append(request), httpx.Response(200, json={}))[1]))

    client.create_oauth_token(payload={"grant_type": "client_credentials"})
    assert sent[-1].headers["content-type"] == "application/x-www-form-urlencoded"
    assert sent[-1].content == b"grant_type=client_credentials"

    client.create_upload(payload={"title": "a"})
    assert sent[-1].headers["content-type"].startswith("multipart/form-data")

    client.get_users()
    assert {str(r.url).split("/")[2] for r in sent} == {"auth.x.dev", "api.x.dev"}

    collection = PostmanCollectionGenerator().generate_collection(endpoints, auth)
    modes = {item["request"]["url"]["path"][-1]: item["request"]["body"]["mode"] for item in collection["item"] if "body" in item["request"]}
    assert modes == {"token": "urlencoded", "upload": "formdata"}


def test_mock_dispatches_graphql_get_and_survives_nan(tmp_path):
    from fastapi.testclient import TestClient
    from ghostwire.core.parser import HarParser

    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://x.dev/graphql?query=query%20A%20%7Ba%7D", "headers": []},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                      "content": {"text": '{"data": {"a": 1}}'}}},
        {"request": {"method": "GET", "url": "https://x.dev/api/stats", "headers": []},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                      "content": {"text": '{"ratio": NaN, "max": Infinity}'}}},
    ]}}
    transactions, _ = HarParser().parse_dict(har)
    endpoints, auth, _ = ReverseEngineeringEngine().analyze_transactions(transactions)
    client = TestClient(load_module(MockServerGenerator().export_file(endpoints, auth, tmp_path), "gw_mock_nan").app)
    assert client.get("/graphql", params={"query": "query A {a}"}).json() == {"data": {"a": 1}}
    assert client.get("/api/stats").json() == {"ratio": None, "max": None}


def test_batched_graphql_round_trip(tmp_path):
    import httpx
    from fastapi.testclient import TestClient

    batch = _tx("POST", "https://x.dev/api/streamGraphql", [
        {"operationName": "Feed", "query": "query Feed { feed { id } }", "variables": {}},
        {"operationName": "Bump", "query": "mutation Bump($id: ID) { bump(id: $id) }", "variables": {"id": "1"}},
    ], response=[{"index": 0, "result": {"data": {"feed": [{"id": 1}]}}}, {"index": 1, "result": {"data": {"bump": True}}}])
    endpoints, auth, _ = ReverseEngineeringEngine().analyze_transactions([batch])

    # The mock answers batches in the captured {index, result} style
    mock = TestClient(load_module(MockServerGenerator().export_file(endpoints, auth, tmp_path), "gw_mock_batch").app)
    answer = mock.post("/api/streamGraphql", json=[{"operationName": "Bump"}, {"operationName": "Feed"}]).json()
    assert answer == [{"index": 0, "result": {"data": {"bump": True}}}, {"index": 1, "result": {"data": {"feed": [{"id": 1}]}}}]

    # The SDK sends a one-element batch and unwraps the result
    module = load_module(PythonSdkGenerator().export_file(endpoints, auth, tmp_path), "gw_client_batch")
    sent = []
    client = module.ApiClient()
    client.client = httpx.Client(base_url=client.base_url, transport=httpx.MockTransport(
        lambda request: (sent.append(request), httpx.Response(200, json=[{"index": 0, "result": {"data": {"bump": True}}}]))[1]))
    assert client.graphql_Bump(variables={"id": "9"}) == {"data": {"bump": True}}
    body = json.loads(sent[-1].content)
    assert isinstance(body, list) and body[0]["operationName"] == "Bump" and body[0]["variables"] == {"id": "9"}

    validator = pytest.importorskip("openapi_spec_validator")
    spec = OpenApiGenerator().generate_spec(endpoints, auth)
    validator.validate(json.loads(json.dumps(spec)))
    assert spec["paths"]["/api/streamGraphql"]["post"]["requestBody"]["content"]["application/json"]["schema"]["type"] == "array"
