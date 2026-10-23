"""Authentication detection and extraction module for GhostWire.
Identifies Bearer tokens, Basic Auth, custom API keys, and session cookies.
"""

from typing import Dict, List, Optional
from .models import AuthInfo, CapturedTransaction

KNOWN_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "access-token",
    "token",
    "x-access-token"
}

KNOWN_SESSION_COOKIES = {
    "session",
    "session_id",
    "sessionid",
    "token",
    "jwt",
    "connect.sid",
    "auth_token",
    "phpsessid",
    "jsessionid"
}


def mask_token(token: str) -> str:
    """Masks a sensitive credential for secure terminal display."""
    if len(token) <= 8:
        return "****"
    return f"{token[:4]}...{token[-4:]}"


class AuthDetector:
    def __init__(self):
        pass

    def detect_auth(self, transactions: List[CapturedTransaction]) -> Optional[AuthInfo]:
        """Scans captured transactions to extract the dominant authentication method."""
        for tx in transactions:
            headers = tx.request_headers

            # 1. Check Authorization header
            auth_val = headers.get("authorization", "")
            if auth_val:
                if auth_val.lower().startswith("bearer "):
                    raw_token = auth_val[7:].strip()
                    return AuthInfo(
                        auth_type="bearer",
                        header_name="Authorization",
                        token_preview=mask_token(raw_token),
                        token_value=raw_token
                    )
                elif auth_val.lower().startswith("basic "):
                    raw_token = auth_val[6:].strip()
                    return AuthInfo(
                        auth_type="basic",
                        header_name="Authorization",
                        token_preview=mask_token(raw_token),
                        token_value=raw_token
                    )
                else:
                    return AuthInfo(
                        auth_type="custom",
                        header_name="Authorization",
                        token_preview=mask_token(auth_val),
                        token_value=auth_val
                    )

            # 2. Check known API key headers
            for h_name, h_val in headers.items():
                if h_name in KNOWN_AUTH_HEADERS and h_val:
                    return AuthInfo(
                        auth_type="api_key",
                        header_name=h_name,
                        token_preview=mask_token(h_val),
                        token_value=h_val
                    )

            # 3. Check Cookie headers
            cookie_str = headers.get("cookie", "")
            if cookie_str:
                cookie_parts = [c.strip() for c in cookie_str.split(";")]
                for part in cookie_parts:
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if k.lower() in KNOWN_SESSION_COOKIES and v:
                            return AuthInfo(
                                auth_type="cookie",
                                cookie_name=k,
                                token_preview=mask_token(v),
                                token_value=v
                            )

        return None
