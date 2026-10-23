"""End-to-end test against the real https://dummyjson.com API.
Records fresh traffic, reverse-engineers it, generates an SDK and calls the live service with it.
Skipped unless GHOSTWIRE_LIVE=1, since it needs network access.
"""

import importlib.util
import os
from pathlib import Path

import pytest

from ghostwire.core.analyzer import ReverseEngineeringEngine
from ghostwire.generators.python_sdk import PythonSdkGenerator

pytestmark = pytest.mark.skipif(os.environ.get("GHOSTWIRE_LIVE") != "1", reason="set GHOSTWIRE_LIVE=1 to run live tests")

ROOT = Path(__file__).parent.parent


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_sdk_against_live_api(tmp_path):
    recorder = load_module(ROOT / "examples" / "capture_live_traffic.py", "capture_live_traffic")
    har_path = tmp_path / "live.har"
    recorder.record_live_session(str(har_path))

    endpoints, auth, _ = ReverseEngineeringEngine().analyze_har(str(har_path))
    assert auth is not None and auth.auth_type == "bearer"

    client_module = load_module(PythonSdkGenerator().export_file(endpoints, auth, tmp_path), "live_client")
    with client_module.ApiClient(auth_token=auth.token_value) as client:
        assert client.get_auth_me()["username"] == "emilys"
        assert client.get_products_by_productId(productId=5)["id"] == 5
        assert len(client.get_products_search(q="laptop", limit=2)["products"]) <= 2
        assert client.create_products_add(payload={"title": "GhostWire"})["title"] == "GhostWire"
