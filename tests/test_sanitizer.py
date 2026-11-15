"""Tests for HAR Sanitizer (gw sanitize)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from ghostwire.cli import app
from ghostwire.core.sanitizer import REDACTED, HarSanitizer

runner = CliRunner()


def test_har_sanitizer_masks_secrets():
    raw_har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/login?token=secret_query_token",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer my_super_secret_jwt"},
                            {"name": "Cookie", "value": "session=sess_12345; user=alice"},
                            {"name": "X-API-Key", "value": "api_key_abcdef"},
                            {"name": "Accept", "value": "application/json"},
                        ],
                        "cookies": [
                            {"name": "session", "value": "sess_12345"},
                            {"name": "user", "value": "alice"},
                        ],
                        "queryString": [
                            {"name": "token", "value": "secret_query_token"},
                            {"name": "limit", "value": "10"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({
                                "username": "alice",
                                "password": "SuperSecretPassword123!",
                                "profile": {"apiKey": "nested_secret_key"},
                            }),
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Set-Cookie", "value": "session=new_sess_67890; Path=/; HttpOnly"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "cookies": [
                            {"name": "session", "value": "new_sess_67890"},
                        ],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({
                                "status": "ok",
                                "accessToken": "access_token_xyz987",
                            }),
                        },
                    },
                }
            ],
        }
    }

    sanitizer = HarSanitizer()
    clean_data, stats = sanitizer.sanitize_har(raw_har, filter_noise=False)

    assert stats["total_entries"] == 1
    assert stats["retained_entries"] == 1
    assert stats["headers_masked"] > 0
    assert stats["cookies_masked"] > 0
    assert stats["payloads_sanitized"] > 0

    entry = clean_data["log"]["entries"][0]
    req = entry["request"]
    res = entry["response"]

    # Verify Authorization header
    auth_header = next(h for h in req["headers"] if h["name"].lower() == "authorization")
    assert auth_header["value"] == f"Bearer {REDACTED}"

    # Verify Cookie header
    cookie_header = next(h for h in req["headers"] if h["name"].lower() == "cookie")
    assert cookie_header["value"] == REDACTED

    # Verify non-sensitive header preserved
    accept_header = next(h for h in req["headers"] if h["name"].lower() == "accept")
    assert accept_header["value"] == "application/json"

    # Verify Cookies array
    for c in req["cookies"]:
        assert c["value"] == REDACTED
    for c in res["cookies"]:
        assert c["value"] == REDACTED

    # Verify Query strings
    q_token = next(q for q in req["queryString"] if q["name"] == "token")
    assert q_token["value"] == REDACTED
    q_limit = next(q for q in req["queryString"] if q["name"] == "limit")
    assert q_limit["value"] == "10"

    # Verify URL query param masked
    assert "secret_query_token" not in req["url"]

    # Verify Post Data payload masked
    post_json = json.loads(req["postData"]["text"])
    assert post_json["username"] == "alice"
    assert post_json["password"] == REDACTED
    assert post_json["profile"]["apiKey"] == REDACTED

    # Verify Response Content masked
    res_json = json.loads(res["content"]["text"])
    assert res_json["status"] == "ok"
    assert res_json["accessToken"] == REDACTED


def test_har_sanitizer_filter_noise():
    har_with_noise = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://analytics.google.com/collect"},
                    "response": {"status": 204, "headers": []},
                },
                {
                    "request": {"method": "GET", "url": "https://api.example.com/v1/users"},
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": "[]"},
                    },
                },
            ],
        }
    }

    sanitizer = HarSanitizer()
    clean_data, stats = sanitizer.sanitize_har(har_with_noise, filter_noise=True)

    assert stats["total_entries"] == 2
    assert stats["retained_entries"] == 1
    assert stats["dropped_noise"] == 1
    assert len(clean_data["log"]["entries"]) == 1
    assert "analytics.google.com" not in clean_data["log"]["entries"][0]["request"]["url"]


def test_cli_sanitize_command(tmp_path):
    raw_har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/items?token=secret123",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer test_secret_token"},
                        ],
                    },
                    "response": {"status": 200, "headers": []},
                }
            ],
        }
    }

    in_file = tmp_path / "raw.har"
    out_file = tmp_path / "safe.har"
    in_file.write_text(json.dumps(raw_har), encoding="utf-8")

    result = runner.invoke(app, ["sanitize", str(in_file), "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()

    sanitized = json.loads(out_file.read_text(encoding="utf-8"))
    auth_header = sanitized["log"]["entries"][0]["request"]["headers"][0]["value"]
    assert "test_secret_token" not in auth_header
    assert f"Bearer {REDACTED}" in auth_header
