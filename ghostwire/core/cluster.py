"""Endpoint clustering and dynamic path parameter inference module for GhostWire.
Transforms variable URLs (e.g. /api/users/42, /orders/uuid-123) into parameterized templates (/api/users/{userId}).
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from .models import CapturedTransaction, ParameterModel

# Regex patterns for dynamic URL tokens
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
MONGO_OBJECT_ID_REGEX = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
INTEGER_ID_REGEX = re.compile(r"^\d+$")
HEX_HASH_REGEX = re.compile(r"^[0-9a-f]{32,64}$", re.IGNORECASE)
PREFIXED_ID_REGEX = re.compile(r"^[a-zA-Z]{2,6}_[a-zA-Z0-9_\-]+$")
ULID_REGEX = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$", re.IGNORECASE)


VERSION_SEGMENT_REGEX = re.compile(r"^v\d+(\.\d+)*$", re.IGNORECASE)
# Segments that are never resource collections, so the value after them gets a generic name
GENERIC_PARENTS = {"", "api", "rest", "rpc", "service", "services"}


def singularize(word: str) -> str:
    """Best-effort English singular form of a collection name (users -> user, addresses -> address)."""
    lower = word.lower()
    if lower.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if lower.endswith(("sses", "xes", "ches", "shes", "zzes", "uses")):
        return word[:-2]
    if lower.endswith(("ss", "us", "is")):
        return word
    if lower.endswith("s") and len(word) > 1:
        return word[:-1]
    return word


def to_camel(segment: str) -> str:
    """Converts a URL segment like 'user-groups' or 'line_items' to camelCase ('userGroups')."""
    parts = [p for p in re.split(r"[^a-zA-Z0-9]+", segment) if p]
    if not parts:
        return ""
    return parts[0][0].lower() + parts[0][1:] + "".join(p[0].upper() + p[1:] for p in parts[1:])


def is_collection_segment(segment: str) -> bool:
    """A plural noun segment (e.g. 'workspaces') usually precedes a resource identifier."""
    return bool(re.match(r"^[a-zA-Z][a-zA-Z_\-]*s$", segment)) and not segment.lower().endswith(("ss", "us", "is"))


def infer_parameter_name(segment: str, previous_segment: str) -> Tuple[bool, str, str]:
    """
    Returns (is_param, param_name, param_type).
    E.g. ('42', 'users') -> (True, 'userId', 'integer')
    E.g. ('ws_alpha', 'workspaces') -> (True, 'workspaceId', 'string')
    E.g. ('user_profile', 'api') -> (False, 'user_profile', 'string')
    """
    generic_parent = previous_segment.lower() in GENERIC_PARENTS or bool(VERSION_SEGMENT_REGEX.match(previous_segment))
    base = "" if generic_parent else to_camel(singularize(previous_segment))
    if base and not base[0].isalpha():
        # Parameter names must be identifiers in every target (FastAPI routes reject '{1Id}')
        base = ""
    base_name = f"{base}Id" if base else "id"

    # UUID
    if UUID_REGEX.match(segment):
        return True, base_name, "string"
    # MongoDB ObjectID or generic Hex Hash (MD5, SHA1, SHA256)
    if MONGO_OBJECT_ID_REGEX.match(segment) or HEX_HASH_REGEX.match(segment):
        return True, base_name, "string"
    # Pure numeric ID
    if INTEGER_ID_REGEX.match(segment):
        return True, base_name, "integer"
    # ULID (must contain a digit so 26-letter words are not mistaken for IDs)
    if ULID_REGEX.match(segment) and any(c.isdigit() for c in segment):
        return True, base_name, "string"
    # Prefixed ID (e.g. ws_alpha, usr_123, cus_998). Snake-case words such as
    # 'user_profile' also match the pattern, so require a digit or a collection parent.
    if PREFIXED_ID_REGEX.match(segment):
        suffix = segment.split("_", 1)[1]
        if any(c.isdigit() for c in suffix) or is_collection_segment(previous_segment):
            if base:
                return True, base_name, "string"
            prefix = segment.split("_")[0]
            return True, f"{prefix}Id", "string"

    return False, segment, "string"


GRAPHQL_DOCUMENT_REGEX = re.compile(r"^\s*(query|mutation|subscription|fragment)\b|^\s*\{")


def looks_like_graphql_request(body: object) -> bool:
    """True for a GraphQL request document ({"query": "query X {...}"} or a persisted-query reference)."""
    if not isinstance(body, dict):
        return False
    query = body.get("query")
    if isinstance(query, str):
        return bool(GRAPHQL_DOCUMENT_REGEX.match(query))
    extensions = body.get("extensions")
    return "operationName" in body and isinstance(extensions, dict) and "persistedQuery" in extensions


def extract_graphql_operation(tx: CapturedTransaction) -> Optional[str]:
    """Detects and extracts GraphQL operation names from JSON body or query params."""
    path = urlparse(tx.url).path.lower().rstrip("/")
    graphql_path = "graphql" in path or path.endswith("/gql")
    if not graphql_path and not looks_like_graphql_request(tx.request_body):
        return None

    # Check request body
    if isinstance(tx.request_body, dict):
        op = tx.request_body.get("operationName")
        if op and isinstance(op, str) and op.strip():
            return op.strip()
        query = tx.request_body.get("query")
        if isinstance(query, str) and query:
            match = re.search(r"(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)", query)
            if match:
                return match.group(1)
            if query.strip():
                return "Anonymous"

    # Check query params
    op_param = tx.query_params.get("operationName")
    if op_param and op_param[0].strip():
        return op_param[0].strip()
    if "query" in tx.query_params and tx.query_params["query"]:
        q_val = tx.query_params["query"][0]
        match = re.search(r"(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)", q_val)
        if match:
            return match.group(1)

    return None


class PathClusterer:
    def __init__(self):
        pass

    def parameterize_path(self, raw_path: str) -> Tuple[str, List[ParameterModel]]:
        """
        Parses a URL path, detects dynamic segments, and generates a normalized template.
        E.g. /api/v1/projects/59/tasks/abc-123 -> /api/v1/projects/{projectId}/tasks/{taskId}
        """
        # Decode percent-escapes (caf%C3%A9 -> café) so templates match what servers route on.
        # Braces, slashes and control characters stay encoded so they can't break templates or generated code.
        segments = []
        for raw_segment in raw_path.strip("/").split("/"):
            decoded = unquote(raw_segment)
            if any(c in decoded for c in "{}/") or not decoded.isprintable():
                decoded = raw_segment.replace("{", "%7B").replace("}", "%7D")
            segments.append(decoded)
        new_segments = []
        path_parameters: List[ParameterModel] = []

        for i, segment in enumerate(segments):
            prev_segment = segments[i - 1] if i > 0 else ""
            is_param, param_name, param_type = infer_parameter_name(segment, prev_segment)

            if is_param:
                # Avoid duplicate param names
                existing_names = {p.name for p in path_parameters}
                final_name = param_name
                counter = 1
                while final_name in existing_names:
                    final_name = f"{param_name}_{counter}"
                    counter += 1

                new_segments.append(f"{{{final_name}}}")
                path_parameters.append(ParameterModel(
                    name=final_name,
                    location="path",
                    param_type=param_type,
                    required=True,
                    example=segment,
                    description=f"Path identifier for {prev_segment or 'resource'}"
                ))
            else:
                new_segments.append(segment)

        normalized_path = "/" + "/".join(new_segments) if new_segments else "/"
        return normalized_path, path_parameters

    def cluster_transactions(
        self, transactions: List[CapturedTransaction]
    ) -> Dict[Tuple[str, str, Optional[str]], List[CapturedTransaction]]:
        """
        Groups transactions by (method, parameterized_path, graphql_operation).
        GraphQL requests sharing one URL are partitioned by operation name.
        """
        clusters: Dict[Tuple[str, str, Optional[str]], List[CapturedTransaction]] = {}

        for tx in transactions:
            parsed = urlparse(tx.url)
            normalized_path, _ = self.parameterize_path(parsed.path)
            key = (tx.method.upper(), normalized_path, extract_graphql_operation(tx))
            clusters.setdefault(key, []).append(tx)

        return clusters
