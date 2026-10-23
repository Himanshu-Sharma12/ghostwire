"""HAR Parser module for GhostWire.
Parses standard HTTP Archive (.har) files and converts them into structured CapturedTransaction models.
"""

import base64
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

from .filter import NoiseFilter
from .models import CapturedTransaction


class HarParser:
    def __init__(self, noise_filter: Optional[NoiseFilter] = None):
        self.noise_filter = noise_filter or NoiseFilter()

    def parse_file(self, file_path: Union[str, Path]) -> Tuple[List[CapturedTransaction], Dict[str, int]]:
        """
        Parses a .har file.
        Returns a tuple of (kept_transactions, statistics_dict).
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"HAR file not found: {file_path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        return self.parse_dict(data)

    def parse_dict(self, data: dict) -> Tuple[List[CapturedTransaction], Dict[str, int]]:
        """Parses a loaded HAR dictionary."""
        entries = data.get("log", {}).get("entries", [])
        total_entries = len(entries)
        kept_transactions: List[CapturedTransaction] = []
        discarded_count = 0

        for entry in entries:
            req = entry.get("request", {})
            res = entry.get("response", {})

            method = req.get("method", "GET").upper()
            url = req.get("url", "")
            status_code = res.get("status", 0)

            # Extract request content-type
            req_headers = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", [])}
            res_headers = {h.get("name", "").lower(): h.get("value", "") for h in res.get("headers", [])}

            req_ct = req_headers.get("content-type", "")
            res_ct = res_headers.get("content-type", "")

            # Filter check
            if not self.noise_filter.is_api_transaction(method, url, status_code, req_ct, res_ct):
                discarded_count += 1
                continue

            # Parse query params
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Parse request body
            request_body = None
            post_data = req.get("postData", {})
            if post_data:
                text_body = post_data.get("text", "")
                if text_body:
                    try:
                        request_body = json.loads(text_body)
                    except Exception:
                        request_body = text_body

            # Parse response body
            response_body = None
            content = res.get("content", {})
            text_res = content.get("text", "")
            if text_res:
                encoding = content.get("encoding", "")
                if encoding == "base64":
                    try:
                        decoded_bytes = base64.b64decode(text_res)
                        text_res = decoded_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                try:
                    response_body = json.loads(text_res)
                except Exception:
                    response_body = text_res

            time_ms = float(entry.get("time", 0.0))

            transaction = CapturedTransaction(
                method=method,
                url=url,
                status_code=status_code,
                request_headers=req_headers,
                request_body=request_body,
                request_content_type=req_ct,
                response_headers=res_headers,
                response_body=response_body,
                response_content_type=res_ct,
                query_params=query_params,
                time_ms=time_ms
            )
            kept_transactions.append(transaction)

        stats = {
            "total_entries": total_entries,
            "kept_entries": len(kept_transactions),
            "discarded_entries": discarded_count
        }
        return kept_transactions, stats
