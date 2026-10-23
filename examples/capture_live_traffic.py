"""Utility to perform real live internet HTTP requests and record them into a standard .har file."""

import json
import time
from pathlib import Path
from urllib.parse import urlparse
import httpx


def record_live_session(output_har_path: str = "examples/live_dummyjson.har"):
    print(f"🌐 Initiating real live HTTP traffic capture across the internet...")
    
    entries = []
    base_url = "https://dummyjson.com"
    client = httpx.Client(base_url=base_url, timeout=15.0)

    def log_exchange(method: str, url: str, req_headers: dict, req_body: any, response: httpx.Response, elapsed_ms: float):
        entry = {
            "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "time": elapsed_ms,
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": [{"name": k, "value": v} for k, v in req_headers.items()],
                "postData": {
                    "mimeType": "application/json",
                    "text": json.dumps(req_body) if req_body is not None else ""
                } if req_body is not None else {}
            },
            "response": {
                "status": response.status_code,
                "headers": [{"name": k, "value": v} for k, v in response.headers.items()],
                "content": {
                    "size": len(response.content),
                    "mimeType": response.headers.get("content-type", "application/json"),
                    "text": response.text
                }
            }
        }
        entries.append(entry)

    # 1. Real Live Call: Login (Auth exchange)
    print("  [1/5] POST /auth/login (Authenticating against live service)...")
    login_payload = {"username": "emilys", "password": "emilyspass", "expiresInMins": 30}
    t0 = time.time()
    res = client.post("/auth/login", json=login_payload)
    t_elapsed = (time.time() - t0) * 1000
    token = res.json().get("accessToken", "")
    log_exchange("POST", f"{base_url}/auth/login", {"Content-Type": "application/json"}, login_payload, res, t_elapsed)

    # 2. Real Live Call: Authenticated Profile with Bearer token
    print("  [2/5] GET /auth/me (Fetching profile with live Bearer token)...")
    auth_headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    t0 = time.time()
    res = client.get("/auth/me", headers=auth_headers)
    t_elapsed = (time.time() - t0) * 1000
    log_exchange("GET", f"{base_url}/auth/me", auth_headers, None, res, t_elapsed)

    # 3. Real Live Call: Query with parameters
    print("  [3/5] GET /products/search?q=phone&limit=3 (Searching live inventory)...")
    t0 = time.time()
    res = client.get("/products/search?q=phone&limit=3", headers=auth_headers)
    t_elapsed = (time.time() - t0) * 1000
    log_exchange("GET", f"{base_url}/products/search?q=phone&limit=3", auth_headers, None, res, t_elapsed)

    # 4. Real Live Call: Fetch single product by ID
    print("  [4/5] GET /products/1 (Fetching product by ID)...")
    t0 = time.time()
    res = client.get("/products/1", headers=auth_headers)
    t_elapsed = (time.time() - t0) * 1000
    log_exchange("GET", f"{base_url}/products/1", auth_headers, None, res, t_elapsed)

    # 5. Real Live Call: Create new product
    print("  [5/5] POST /products/add (Creating new resource on live server)...")
    new_product_payload = {"title": "GhostWire Autonomous Scanner", "category": "software", "price": 99.99}
    t0 = time.time()
    res = client.post("/products/add", json=new_product_payload, headers=auth_headers)
    t_elapsed = (time.time() - t0) * 1000
    log_exchange("POST", f"{base_url}/products/add", {**auth_headers, "Content-Type": "application/json"}, new_product_payload, res, t_elapsed)

    client.close()

    har_document = {
        "log": {
            "version": "1.2",
            "creator": {"name": "GhostWire Live Recorder", "version": "1.0"},
            "entries": entries
        }
    }

    out_file = Path(output_har_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(har_document, f, indent=2)

    print(f"✨ Successfully recorded {len(entries)} real live HTTP exchanges to {out_file}!")


if __name__ == "__main__":
    record_live_session()
