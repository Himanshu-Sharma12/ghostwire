"""Automated test suite for GhostWire reverse engineering engine."""

from pathlib import Path
import pytest

from ghostwire.core.analyzer import ReverseEngineeringEngine
from ghostwire.core.auth import AuthDetector
from ghostwire.core.cluster import PathClusterer, extract_graphql_operation
from ghostwire.core.filter import NoiseFilter
from ghostwire.core.models import CapturedTransaction
from ghostwire.core.schema import infer_json_schema, merge_schemas
from ghostwire.generators.mock_server import MockServerGenerator
from ghostwire.generators.openapi import OpenApiGenerator
from ghostwire.generators.postman import PostmanCollectionGenerator
from ghostwire.generators.python_sdk import PythonSdkGenerator
from ghostwire.generators.typescript_sdk import TypeScriptSdkGenerator


def test_noise_filter():
    filter_engine = NoiseFilter()
    # Trackers should be rejected
    assert not filter_engine.is_api_transaction("GET", "https://google-analytics.com/collect", 200)
    assert not filter_engine.is_api_transaction("GET", "https://browser.sentry-cdn.com/bundle.js", 200)
    assert not filter_engine.is_api_transaction("GET", "https://example.com/logo.png", 200)
    assert not filter_engine.is_api_transaction("GET", "https://example.com/styles.css", 200)

    # Valid API calls should be kept
    assert filter_engine.is_api_transaction("GET", "https://api.example.com/v1/users", 200, res_content_type="application/json")
    assert filter_engine.is_api_transaction("POST", "https://example.com/api/login", 200, req_content_type="application/json")


def test_path_clustering():
    clusterer = PathClusterer()

    # Numeric ID
    path1, params1 = clusterer.parameterize_path("/api/v1/orders/10928/items")
    assert path1 == "/api/v1/orders/{orderId}/items"
    assert len(params1) == 1
    assert params1[0].name == "orderId"
    assert params1[0].param_type == "integer"

    # UUID
    path2, params2 = clusterer.parameterize_path("/workspaces/a8098c1a-f86e-11da-bd1a-00112444be1e/files")
    assert path2 == "/workspaces/{workspaceId}/files"
    assert len(params2) == 1
    assert params2[0].name == "workspaceId"

    # Prefixed ID (e.g. ws_alpha, usr_102)
    path3, params3 = clusterer.parameterize_path("/workspaces/ws_alpha/projects")
    assert path3 == "/workspaces/{workspaceId}/projects"
    assert len(params3) == 1
    assert params3[0].name == "workspaceId"


def test_schema_inference_and_merge():
    data1 = {"id": 1, "name": "Antigravity", "active": True}
    data2 = {"id": 2, "name": "Agent", "email": "agent@deepmind.com"}

    schema1 = infer_json_schema(data1)
    schema2 = infer_json_schema(data2)
    merged = merge_schemas(schema1, schema2)

    assert merged["type"] == "object"
    assert "id" in merged["properties"]
    assert "name" in merged["properties"]
    assert "email" in merged["properties"]
    # email should be optional because it only appeared in data2
    assert "email" not in merged["required"]
    assert "id" in merged["required"]


def test_auth_detection():
    detector = AuthDetector()
    tx = CapturedTransaction(
        method="GET",
        url="https://api.example.com/data",
        status_code=200,
        request_headers={"authorization": "Bearer sample_token_123456"}
    )
    auth = detector.detect_auth([tx])
    assert auth is not None
    assert auth.auth_type == "bearer"
    assert auth.token_value == "sample_token_123456"
    assert auth.token_preview == "samp...3456"


def test_end_to_end_analysis():
    sample_har = Path(__file__).parent.parent / "examples" / "sample_traffic.har"
    assert sample_har.exists()

    engine = ReverseEngineeringEngine()
    endpoints, auth, stats = engine.analyze_har(str(sample_har))

    assert stats["total_entries"] == 7
    assert stats["discarded_entries"] == 2
    assert len(endpoints) == 5
    assert auth is not None
    assert auth.auth_type == "bearer"

    # Test code generators
    openapi_gen = OpenApiGenerator()
    spec = openapi_gen.generate_spec(endpoints, auth)
    assert spec["openapi"] == "3.1.0"
    assert len(spec["paths"]) > 0

    py_gen = PythonSdkGenerator()
    py_code = py_gen.generate_code(endpoints, auth)
    assert "class ApiClient:" in py_code
    assert "def get_user_me" in py_code

    ts_gen = TypeScriptSdkGenerator()
    ts_code = ts_gen.generate_code(endpoints, auth)
    assert "export class ApiClient" in ts_code

    mock_gen = MockServerGenerator()
    mock_code = mock_gen.generate_code(endpoints, auth)
    assert "app = FastAPI" in mock_code

    postman_gen = PostmanCollectionGenerator(collection_name="Test API")
    coll = postman_gen.generate_collection(endpoints, auth)
    assert coll["info"]["name"] == "Test API"
    assert len(coll["item"]) > 0
    assert coll["auth"]["type"] == "bearer"


def test_graphql_operation_extraction():
    tx = CapturedTransaction(
        method="POST",
        url="https://api.example.com/graphql",
        status_code=200,
        request_body={"operationName": "GetWorkspaceFeed", "query": "query GetWorkspaceFeed { viewer { id } }"}
    )
    op = extract_graphql_operation(tx)
    assert op == "GetWorkspaceFeed"


@pytest.mark.parametrize("raw_path, expected", [
    ("/api/user_profile", "/api/user_profile"),
    ("/api/v1/get_items", "/api/v1/get_items"),
    ("/auth/me", "/auth/me"),
    ("/addresses/42", "/addresses/{addressId}"),
    ("/status/7", "/status/{statusId}"),
    ("/categories/9", "/categories/{categoryId}"),
    ("/user-groups/12", "/user-groups/{userGroupId}"),
    ("/v2/2024/reports", "/v2/{id}/reports"),
    ("/customers/cus_9s6XKz", "/customers/{customerId}"),
    ("/files/deadbeefdeadbeefdeadbeefdeadbeef", "/files/{fileId}"),
])
def test_path_clustering_edge_cases(raw_path, expected):
    path, _ = PathClusterer().parameterize_path(raw_path)
    assert path == expected


def test_schema_merge_nullable_and_numeric_widening():
    merged = merge_schemas(
        infer_json_schema({"count": 1, "nickname": None}),
        infer_json_schema({"count": 2.5, "nickname": "ada"}),
    )
    assert merged["properties"]["count"]["type"] == "number"
    assert merged["properties"]["nickname"]["type"] == ["string", "null"]


def test_schema_array_items_merged_across_elements():
    schema = infer_json_schema([{"id": 1}, {"id": 2, "tags": ["x"]}])
    assert set(schema["items"]["properties"]) == {"id", "tags"}
    assert schema["items"]["required"] == ["id"]


def test_auth_detection_prefers_dominant_scheme_and_latest_token():
    def tx(headers):
        return CapturedTransaction(method="GET", url="https://api.example.com/x", status_code=200, request_headers=headers)

    auth = AuthDetector().detect_auth([
        tx({"x-api-key": "key-only-once"}),
        tx({"authorization": "Bearer first_token_value"}),
        tx({"authorization": "Bearer refreshed_token_value"}),
    ])
    assert auth.auth_type == "bearer"
    assert auth.token_value == "refreshed_token_value"


def test_redaction_masks_secrets_in_payloads():
    from ghostwire.core.redact import REDACTED, redact_value

    redacted = redact_value({
        "username": "ada",
        "password": "hunter2",
        "session": {"accessToken": "abc", "expires": 30},
        "items": [{"api_key": "k"}],
        "jwt_like": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI3In0.c2ln",
    })
    assert redacted["username"] == "ada"
    assert redacted["password"] == REDACTED
    assert redacted["session"] == {"accessToken": REDACTED, "expires": 30}
    assert redacted["items"] == [{"api_key": REDACTED}]
    assert redacted["jwt_like"] == REDACTED


def test_graphql_operations_become_separate_endpoints():
    fixture = Path(__file__).parent / "fixtures" / "edge_cases.har"
    endpoints, auth, _ = ReverseEngineeringEngine().analyze_har(str(fixture))

    graphql = [e for e in endpoints if e.graphql_operation]
    assert {e.graphql_operation for e in graphql} == {"GetViewer", "RenameProject", "ListTeams"}
    assert all(e.path == "/graphql" for e in graphql)
    assert auth.auth_type == "cookie" and auth.cookie_name == "sessionid"


def test_multiple_har_files_are_merged():
    examples = Path(__file__).parent.parent / "examples"
    engine = ReverseEngineeringEngine()
    single, _, _ = engine.analyze_har(str(examples / "sample_traffic.har"))
    merged, _, stats = engine.analyze_har([examples / "sample_traffic.har", examples / "live_dummyjson.har"])
    assert len(merged) > len(single)
    assert stats["total_entries"] == 7 + 5


def test_numeric_parent_segments_give_identifier_safe_names():
    path, params = PathClusterer().parameterize_path("/api/a/1/2/3")
    assert path == "/api/a/{aId}/{id}/{id_1}"
    assert all(p.name[0].isalpha() for p in params)


def test_percent_encoded_segments_are_decoded():
    path, _ = PathClusterer().parameterize_path("/api/caf%C3%A9/menu")
    assert path == "/api/café/menu"


def test_anonymous_and_get_graphql_operations_are_named():
    anonymous = CapturedTransaction(method="POST", url="https://x.dev/graphql", status_code=200, request_body={"query": "{ viewer { id } }"})
    via_get = CapturedTransaction(
        method="GET", url="https://x.dev/gql?operationName=GetQ&query=query%20GetQ%20%7B%20q%20%7D",
        status_code=200, query_params={"operationName": ["GetQ"], "query": ["query GetQ { q }"]},
    )
    assert extract_graphql_operation(anonymous) == "Anonymous"
    assert extract_graphql_operation(via_get) == "GetQ"


def test_unfinished_and_non_http_requests():
    noise = NoiseFilter()
    assert not noise.is_api_transaction("GET", "chrome-extension://abc/api/x", 200, res_content_type="application/json")
    assert not noise.is_api_transaction("GET", "not a url", 200, res_content_type="application/json")

    blocked = CapturedTransaction(method="GET", url="https://x.dev/api/blocked", status_code=0)
    endpoints, _, _ = ReverseEngineeringEngine().analyze_transactions([blocked])
    assert endpoints[0].responses == {}


def test_nullable_union_items_validate_every_observation():
    jsonschema = pytest.importorskip("jsonschema")
    from ghostwire.core.schema import SchemaEngine

    schema = SchemaEngine().build_response_schema([[1], ["a", None], ["a", None]]).schema_dict
    for observed in ([1], ["a", None]):
        jsonschema.validate(observed, schema)


def test_path_parameter_type_considers_every_observation():
    def tx(url):
        return CapturedTransaction(method="GET", url=url, status_code=200, response_body={})

    endpoints, _, _ = ReverseEngineeringEngine().analyze_transactions([
        tx("https://x.dev/api/users/42"),
        tx("https://x.dev/api/users/a8098c1a-f86e-11da-bd1a-00112444be1e"),
    ])
    assert endpoints[0].parameters[0].param_type == "string"


def test_trackers_detected_by_host_suffix_and_path():
    noise = NoiseFilter()
    json_ct = {"res_content_type": "application/json"}
    assert not noise.is_api_transaction("POST", "https://www.google.com/ccm/collect?en=page_view", 200, **json_ct)
    assert not noise.is_api_transaction("POST", "https://www.google.com/rmkt/collect/761131518/", 200, **json_ct)
    assert not noise.is_api_transaction("GET", "https://api.hubapi.com/hs-script-loader-public/v2/config", 200, **json_ct)
    assert not noise.is_api_transaction("POST", "https://www.youtube.com/youtubei/v1/log_event", 200, **json_ct)
    assert not noise.is_api_transaction("POST", "https://www.example.com/api/sentry", 200, **json_ct)
    # Suffix matching: a host merely containing a tracker name is not a tracker
    assert noise.is_api_transaction("GET", "https://notsentry.io.example.com/api/items", 200, **json_ct)
    # An explicit --domain target overrides the tracker lists
    assert NoiseFilter(target_domains={"app.hubspot.com"}).is_api_transaction(
        "GET", "https://app.hubspot.com/api/contacts", 200, **json_ct)


def test_graphql_detected_by_body_shape_but_not_plain_search_queries():
    def tx(body):
        return CapturedTransaction(method="POST", url="https://x.dev/api/stream", status_code=200, request_body=body)

    assert extract_graphql_operation(tx({"operationName": "Feed", "query": "query Feed { feed { id } }"})) == "Feed"
    assert extract_graphql_operation(tx({"query": "laptops", "limit": 10})) is None


def test_batched_graphql_is_split_per_operation():
    batch = CapturedTransaction(
        method="POST", url="https://x.dev/api/streamGraphql", status_code=200,
        request_body=[
            {"operationName": "Feed", "query": "query Feed { feed { id } }", "variables": {}},
            {"operationName": "Bump", "query": "mutation Bump { bump }", "variables": {"id": "1"}},
        ],
        response_body=[{"index": 1, "result": {"data": {"bump": True}}}, {"index": 0, "result": {"data": {"feed": []}}}],
    )
    endpoints, _, _ = ReverseEngineeringEngine().analyze_transactions([batch])
    by_op = {e.graphql_operation: e for e in endpoints}
    assert set(by_op) == {"Feed", "Bump"}
    assert by_op["Bump"].responses[200].example_body == {"data": {"bump": True}}
    assert all(e.graphql_batch == "indexed" for e in endpoints)


@pytest.mark.parametrize("content", ['{bad json', '[1, 2]', '{"log": "x"}', '{"entries": []}'])
def test_cli_reports_unreadable_captures_cleanly(tmp_path, content):
    from typer.testing import CliRunner
    from ghostwire.cli import app

    bad = tmp_path / "bad.har"
    bad.write_text(content)
    result = CliRunner().invoke(app, ["inspect", str(bad)])
    assert result.exit_code == 1
    assert "Could not read capture" in result.output
    assert not isinstance(result.exception, (ValueError, AttributeError))
