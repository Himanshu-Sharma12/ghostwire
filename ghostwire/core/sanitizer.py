"""HAR Sanitizer module for GhostWire.
Cleans raw HTTP Archive (.har) files by stripping credentials, session cookies,
auth tokens, and sensitive payload data so captures can be safely shared or archived.
"""

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .filter import NoiseFilter
from .redact import REDACTED, is_sensitive_key, redact_text, redact_url, redact_value

SENSITIVE_HEADER_NAMES: Set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-token",
    "x-access-token",
}


class HarSanitizer:
    """Sanitizes HTTP Archive data by redacting secrets, auth tokens, and session data."""

    def __init__(self, target_domains: Optional[Set[str]] = None):
        self.noise_filter = NoiseFilter(target_domains=target_domains)

    def sanitize_har(
        self,
        har_data: Dict[str, Any],
        filter_noise: bool = False,
        target_domains: Optional[Set[str]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """Sanitizes an in-memory HAR dictionary.

        Returns a tuple of (sanitized_har_dict, statistics_dict).
        """
        if not isinstance(har_data, dict) or not isinstance(har_data.get("log"), dict):
            raise ValueError("Invalid HAR format: missing top-level 'log' object")

        clean_har = copy.deepcopy(har_data)
        log = clean_har["log"]
        entries: List[Dict[str, Any]] = log.get("entries", [])

        stats = {
            "total_entries": len(entries),
            "retained_entries": 0,
            "dropped_noise": 0,
            "headers_masked": 0,
            "cookies_masked": 0,
            "payloads_sanitized": 0,
        }

        filter_to_use = (
            NoiseFilter(target_domains=target_domains) if target_domains else self.noise_filter
        )

        sanitized_entries: List[Dict[str, Any]] = []

        for entry in entries:
            req = entry.get("request", {})
            res = entry.get("response", {})
            method = req.get("method", "GET")
            url = req.get("url", "")

            # Optional noise scrubbing
            if filter_noise:
                req_ct = ""
                res_ct = ""
                for h in req.get("headers", []):
                    if h.get("name", "").lower() == "content-type":
                        req_ct = h.get("value", "")
                        break
                for h in res.get("headers", []):
                    if h.get("name", "").lower() == "content-type":
                        res_ct = h.get("value", "")
                        break
                status_code = res.get("status", 200)

                if not filter_to_use.is_api_transaction(
                    method=method,
                    url=url,
                    status_code=status_code,
                    req_content_type=req_ct,
                    res_content_type=res_ct,
                ):
                    stats["dropped_noise"] += 1
                    continue

            # 1. Sanitize Request URL & Query Strings
            if url:
                new_url = redact_url(url)
                if new_url != url:
                    req["url"] = new_url
                    stats["payloads_sanitized"] += 1

            for q in req.get("queryString", []):
                q_name = q.get("name", "")
                if is_sensitive_key(q_name):
                    q["value"] = REDACTED
                    stats["payloads_sanitized"] += 1

            # 2. Sanitize Request Headers
            for h in req.get("headers", []):
                h_name = h.get("name", "").lower()
                h_val = h.get("value", "")
                if h_name in SENSITIVE_HEADER_NAMES or is_sensitive_key(h_name):
                    if h_val.startswith("Bearer "):
                        h["value"] = f"Bearer {REDACTED}"
                    elif h_val.startswith("Basic "):
                        h["value"] = f"Basic {REDACTED}"
                    else:
                        h["value"] = REDACTED
                    stats["headers_masked"] += 1

            # 3. Sanitize Request Cookies
            for c in req.get("cookies", []):
                c["value"] = REDACTED
                stats["cookies_masked"] += 1

            # 4. Sanitize Request Body (postData)
            post_data = req.get("postData")
            if post_data and isinstance(post_data, dict):
                text_body = post_data.get("text")
                if text_body:
                    try:
                        parsed = json.loads(text_body)
                        redacted = redact_value(parsed)
                        post_data["text"] = json.dumps(redacted)
                        stats["payloads_sanitized"] += 1
                    except Exception:
                        redacted_txt = redact_text(text_body)
                        if redacted_txt != text_body:
                            post_data["text"] = redacted_txt
                            stats["payloads_sanitized"] += 1

                for param in post_data.get("params", []):
                    if is_sensitive_key(param.get("name", "")):
                        param["value"] = REDACTED
                        stats["payloads_sanitized"] += 1

            # 5. Sanitize Response Headers
            for h in res.get("headers", []):
                h_name = h.get("name", "").lower()
                if h_name in SENSITIVE_HEADER_NAMES or is_sensitive_key(h_name):
                    h["value"] = REDACTED
                    stats["headers_masked"] += 1

            # 6. Sanitize Response Cookies
            for c in res.get("cookies", []):
                c["value"] = REDACTED
                stats["cookies_masked"] += 1

            # 7. Sanitize Response Content
            content = res.get("content")
            if content and isinstance(content, dict):
                res_text = content.get("text")
                if res_text:
                    try:
                        parsed = json.loads(res_text)
                        redacted = redact_value(parsed)
                        content["text"] = json.dumps(redacted)
                        stats["payloads_sanitized"] += 1
                    except Exception:
                        redacted_txt = redact_text(res_text)
                        if redacted_txt != res_text:
                            content["text"] = redacted_txt
                            stats["payloads_sanitized"] += 1

            sanitized_entries.append(entry)

        log["entries"] = sanitized_entries
        stats["retained_entries"] = len(sanitized_entries)

        return clean_har, stats

    def sanitize_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        filter_noise: bool = False,
        target_domains: Optional[Set[str]] = None,
    ) -> Dict[str, int]:
        """Reads a .har file, sanitizes its entries, and writes the output JSON file."""
        in_p = Path(input_path)
        out_p = Path(output_path)

        if not in_p.exists():
            raise FileNotFoundError(f"Source HAR file not found: {input_path}")

        with open(in_p, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        sanitized_data, stats = self.sanitize_har(
            data, filter_noise=filter_noise, target_domains=target_domains
        )

        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(sanitized_data, f, indent=2)

        return stats
