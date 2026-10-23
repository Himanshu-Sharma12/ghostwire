"""Master Analyzer Engine for GhostWire.
Coordinates parsing, noise filtering, path clustering, schema deduction, and endpoint synthesis.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse

from .auth import AuthDetector
from .cluster import PathClusterer, looks_like_graphql_request
from .filter import NoiseFilter
from .models import AuthInfo, CapturedTransaction, EndpointModel, ParameterModel
from .parser import HarParser
from .redact import REDACTED, is_sensitive_key, redact_schema, redact_url, redact_value
from .schema import SchemaEngine


def generate_operation_id(method: str, path: str, graphql_operation: Optional[str] = None) -> str:
    """
    Generates a clean, idiomatic Python/TypeScript function name.
    E.g. GET /api/v1/users/{userId}/posts -> get_users_by_userId_posts
    E.g. POST /graphql (operation GetWorkspace) -> graphql_GetWorkspace
    """
    if graphql_operation:
        op_clean = re.sub(r"[^a-zA-Z0-9_]", "_", graphql_operation).strip("_")
        return f"graphql_{op_clean}"

    clean_path = re.sub(r"^/api/v\d+/", "", path)
    clean_path = re.sub(r"^/api/", "", clean_path)
    clean_path = re.sub(r"^/v\d+/", "", clean_path)

    segments = [s for s in clean_path.split("/") if s]
    verb_map = {
        "GET": "get",
        "POST": "create",
        "PUT": "update",
        "PATCH": "modify",
        "DELETE": "delete"
    }
    action = verb_map.get(method.upper(), method.lower())

    # Build descriptive words
    parts = [action]
    for seg in segments:
        if seg.startswith("{") and seg.endswith("}"):
            param_name = seg[1:-1]
            parts.append(f"by_{param_name}")
        else:
            cleaned = re.sub(r"[^a-zA-Z0-9]", "_", seg)
            parts.append(cleaned)

    op_id = "_".join(parts)
    # Deduplicate underscores
    op_id = re.sub(r"_+", "_", op_id).strip("_")
    return op_id


def generate_summary(method: str, path: str, op_id: str) -> str:
    """Generates a human-readable title for the endpoint."""
    words = op_id.replace("_", " ").title()
    return f"{words} ({method.upper()})"


def expand_graphql_batches(transactions: List[CapturedTransaction]) -> List[CapturedTransaction]:
    """
    Splits batched GraphQL requests (a JSON list of operations, as sent by Apollo's batch link)
    into one transaction per operation, pairing each with its slice of the batched response.
    """
    expanded: List[CapturedTransaction] = []
    for tx in transactions:
        body = tx.request_body
        if not (isinstance(body, list) and body and all(looks_like_graphql_request(op) for op in body)):
            expanded.append(tx)
            continue

        results = tx.response_body if isinstance(tx.response_body, list) else []
        by_index = {
            item["index"]: item for item in results
            if isinstance(item, dict) and "index" in item and "result" in item
        }
        style = "indexed" if by_index else "plain"
        for i, operation in enumerate(body):
            if by_index:
                item = by_index.get(i)
                result = item["result"] if item else None
            else:
                result = results[i] if i < len(results) else None
            expanded.append(tx.model_copy(update={
                "request_body": operation, "response_body": result, "graphql_batch": style,
            }))
    return expanded


def redact_endpoint(endpoint: EndpointModel) -> None:
    """
    Masks secrets in everything an endpoint exposes to the generators: example URL, query parameter
    examples, example payloads and schema examples. Redacting these few values after inference is far
    cheaper than rewriting every captured body.
    """
    endpoint.original_url = redact_url(endpoint.original_url)
    for param in endpoint.parameters:
        if param.location == "query":
            param.example = REDACTED if is_sensitive_key(param.name) else redact_value(param.example)
    if endpoint.request_body:
        endpoint.request_body.example_payload = redact_value(endpoint.request_body.example_payload)
        endpoint.request_body.schema_dict = redact_schema(endpoint.request_body.schema_dict)
    for response in endpoint.responses.values():
        response.example_body = redact_value(response.example_body)
        response.schema_dict = redact_schema(response.schema_dict)


class ReverseEngineeringEngine:
    def __init__(self, target_domains: Optional[set] = None, redact_secrets: bool = True):
        """
        redact_secrets masks passwords, tokens and API keys inside captured payloads so that
        generated specs, fixtures and examples are safe to share. Detected auth is unaffected.
        """
        self.redact_secrets = redact_secrets
        self.noise_filter = NoiseFilter(target_domains=target_domains)
        self.parser = HarParser(noise_filter=self.noise_filter)
        self.clusterer = PathClusterer()
        self.schema_engine = SchemaEngine()
        self.auth_detector = AuthDetector()

    def analyze_har(
        self, har_paths: Union[str, Path, Sequence[Union[str, Path]]]
    ) -> Tuple[List[EndpointModel], Optional[AuthInfo], Dict[str, int]]:
        """
        Full analysis pipeline on one or more .har files (captures are merged).
        Returns (endpoints, detected_auth, stats).
        """
        if isinstance(har_paths, (str, Path)):
            har_paths = [har_paths]

        transactions: List[CapturedTransaction] = []
        stats: Dict[str, int] = {"total_entries": 0, "kept_entries": 0, "discarded_entries": 0}
        for har_path in har_paths:
            file_transactions, file_stats = self.parser.parse_file(har_path)
            transactions.extend(file_transactions)
            for key in stats:
                stats[key] += file_stats.get(key, 0)

        return self.analyze_transactions(transactions, stats)

    def analyze_transactions(
        self, transactions: List[CapturedTransaction], stats: Optional[Dict[str, int]] = None
    ) -> Tuple[List[EndpointModel], Optional[AuthInfo], Dict[str, int]]:
        """Runs auth detection, clustering and schema inference over parsed transactions."""
        stats = dict(stats or {"total_entries": len(transactions), "kept_entries": len(transactions), "discarded_entries": 0})
        if not transactions:
            return [], None, stats

        # Detect global auth
        global_auth = self.auth_detector.detect_auth(transactions)

        transactions = expand_graphql_batches(transactions)

        # Cluster transactions by (method, path, graphql operation)
        clusters = self.clusterer.cluster_transactions(transactions)

        endpoints: List[EndpointModel] = []

        for (method, path, graphql_operation), tx_list in clusters.items():
            sample_tx = tx_list[0]
            parsed_sample = urlparse(sample_tx.url)
            base_url = f"{parsed_sample.scheme}://{parsed_sample.netloc}"

            # 1. Path parameters (typed as integer only if every observation was numeric)
            _, path_params = self.clusterer.parameterize_path(parsed_sample.path)
            for tx in tx_list[1:]:
                _, observed = self.clusterer.parameterize_path(urlparse(tx.url).path)
                for param, other in zip(path_params, observed):
                    if param.param_type != other.param_type:
                        param.param_type = "string"

            # 2. Query parameters (aggregate across all observations)
            query_params: List[ParameterModel] = []
            seen_query_names = set()
            for tx in tx_list:
                inferred_q_params = self.schema_engine.extract_query_parameters(tx.query_params)
                for qp in inferred_q_params:
                    if qp.name not in seen_query_names:
                        query_params.append(qp)
                        seen_query_names.add(qp.name)

            all_params = path_params + query_params

            # 3. Request body schema
            req_bodies = [tx.request_body for tx in tx_list if tx.request_body is not None]
            req_ct = sample_tx.request_content_type or "application/json"
            request_schema = self.schema_engine.build_request_schema(req_bodies, req_ct)

            # 4. Response schemas grouped by status code
            responses = {}
            status_groups: Dict[int, List[CapturedTransaction]] = {}
            for tx in tx_list:
                # Status 0 means the request never completed (blocked, aborted, CORS failure)
                if tx.status_code >= 100:
                    status_groups.setdefault(tx.status_code, []).append(tx)

            for code, group in status_groups.items():
                res_bodies = [t.response_body for t in group if t.response_body is not None]
                res_ct = group[0].response_content_type or "application/json"
                response_schema = self.schema_engine.build_response_schema(res_bodies, code, res_ct)
                responses[code] = response_schema

            op_id = generate_operation_id(method, path, graphql_operation)
            summary = generate_summary(method, path, op_id)

            endpoint = EndpointModel(
                method=method,
                path=path,
                original_url=sample_tx.url,
                base_url=base_url,
                operation_id=op_id,
                summary=summary,
                description=f"Auto-discovered {method} endpoint reverse-engineered from network traffic.",
                parameters=all_params,
                request_body=request_schema,
                responses=responses,
                auth=global_auth,
                frequency=len(tx_list),
                graphql_operation=graphql_operation,
                graphql_batch=next((tx.graphql_batch for tx in tx_list if tx.graphql_batch), None)
            )
            if self.redact_secrets:
                redact_endpoint(endpoint)
            endpoints.append(endpoint)

        # Sort endpoints by path and method for clean presentation
        endpoints.sort(key=lambda e: (e.path, e.method, e.graphql_operation or ""))
        stats["discovered_endpoints"] = len(endpoints)
        return endpoints, global_auth, stats
