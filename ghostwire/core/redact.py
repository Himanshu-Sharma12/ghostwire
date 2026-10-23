"""Secret redaction module for GhostWire.
Masks credentials and secrets inside captured payloads before they are written into generated artifacts.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

REDACTED = "<redacted>"

# Matches keys such as password, accessToken, refresh_token, client_secret, apiKey, x-api-key
SENSITIVE_KEY_REGEX = re.compile(
    r"(passw(or)?d|passwd|secret|token|api[_\-]?key|private[_\-]?key|credential|authorization|session[_\-]?id|^otp$|^pin$|^cvv$)",
    re.IGNORECASE,
)

# JWTs embedded as plain string values
JWT_REGEX = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")
JWT_ANYWHERE_REGEX = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")

# Secrets inside raw (non-JSON) bodies: multipart parts and key=value pairs
MULTIPART_FIELD_REGEX = re.compile(r'(name="([^"]*)"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([^\r\n]*)')
KEY_VALUE_REGEX = re.compile(r"((?:^|[&;\s?])([A-Za-z0-9_.\-\[\]]+)=)([^&;\s]*)")


def is_sensitive_key(key: str) -> bool:
    return bool(SENSITIVE_KEY_REGEX.search(key))


def _mask_sensitive(value: Any) -> Any:
    """Masks every scalar under a sensitive key, including inside nested lists and objects
    (e.g. {"apiKeys": [{"name": "ci", "value": "sk_live_..."}]})."""
    if isinstance(value, list):
        return [_mask_sensitive(item) for item in value]
    if isinstance(value, dict):
        return {k: _mask_sensitive(v) for k, v in value.items()}
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return REDACTED
    return value


def redact_text(text: str) -> str:
    """Masks secrets in raw bodies: multipart fields, key=value pairs and embedded JWTs."""
    if "=" not in text and "eyJ" not in text:
        return text
    text = MULTIPART_FIELD_REGEX.sub(
        lambda m: m.group(1) + REDACTED if is_sensitive_key(m.group(2)) else m.group(0), text
    )
    text = KEY_VALUE_REGEX.sub(
        lambda m: m.group(1) + REDACTED if is_sensitive_key(m.group(2)) else m.group(0), text
    )
    return JWT_ANYWHERE_REGEX.sub(REDACTED, text)


def redact_value(data: Any) -> Any:
    """Returns a deep copy of a JSON-like value with secret fields and JWT strings masked."""
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            if isinstance(k, str) and is_sensitive_key(k):
                redacted[k] = _mask_sensitive(v)
            else:
                redacted[k] = redact_value(v)
        return redacted
    if isinstance(data, list):
        return [redact_value(item) for item in data]
    if isinstance(data, str):
        return REDACTED if JWT_REGEX.match(data) else redact_text(data)
    return data


def redact_schema(schema: Any, sensitive: bool = False) -> Any:
    """Masks the `example` values inside an inferred JSON Schema, using property names as context."""
    if isinstance(schema, list):
        return [redact_schema(item, sensitive) for item in schema]
    if not isinstance(schema, dict):
        return schema
    redacted = {}
    for key, value in schema.items():
        if key == "example":
            redacted[key] = _mask_sensitive(value) if sensitive else redact_value(value)
        elif key == "properties" and isinstance(value, dict):
            redacted[key] = {
                name: redact_schema(sub, sensitive or is_sensitive_key(name)) for name, sub in value.items()
            }
        elif key in {"items", "oneOf"}:
            redacted[key] = redact_schema(value, sensitive)
        else:
            redacted[key] = value
    return redacted


def redact_url(url: str) -> str:
    """Masks sensitive query parameter values inside a full URL."""
    parsed = urlparse(url)
    if not parsed.query:
        return url
    pairs = [
        (k, REDACTED if is_sensitive_key(k) else redact_value(v))
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(query=urlencode(pairs, safe="<>")))
