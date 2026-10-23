"""Automated test suite for GhostWire reverse engineering engine."""

from pathlib import Path
import pytest

from ghostwire.core.analyzer import ReverseEngineeringEngine
from ghostwire.core.auth import AuthDetector
from ghostwire.core.cluster import PathClusterer, extract_graphql_operation, infer_parameter_name
from ghostwire.core.filter import NoiseFilter
from ghostwire.core.models import CapturedTransaction
from ghostwire.core.parser import HarParser
from ghostwire.core.schema import SchemaEngine, infer_json_schema, merge_schemas
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

