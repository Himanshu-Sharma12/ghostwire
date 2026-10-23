"""Master Analyzer Engine for GhostWire.
Coordinates parsing, noise filtering, path clustering, schema deduction, and endpoint synthesis.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .auth import AuthDetector
from .cluster import PathClusterer
from .filter import NoiseFilter
from .models import AuthInfo, CapturedTransaction, EndpointModel, ParameterModel
from .parser import HarParser
from .schema import SchemaEngine


def generate_operation_id(method: str, path: str) -> str:
    """
    Generates a clean, idiomatic Python/TypeScript function name.
    E.g. GET /api/v1/users/{userId}/posts -> get_user_posts
    """
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


class ReverseEngineeringEngine:
    def __init__(self, target_domains: Optional[set] = None):
        self.noise_filter = NoiseFilter(target_domains=target_domains)
        self.parser = HarParser(noise_filter=self.noise_filter)
        self.clusterer = PathClusterer()
        self.schema_engine = SchemaEngine()
        self.auth_detector = AuthDetector()

    def analyze_har(self, har_path: str) -> Tuple[List[EndpointModel], Optional[AuthInfo], Dict[str, int]]:
        """
        Full analysis pipeline on a .har file.
        Returns (endpoints, detected_auth, stats).
        """
        transactions, stats = self.parser.parse_file(har_path)
        if not transactions:
            return [], None, stats

        # Detect global auth
        global_auth = self.auth_detector.detect_auth(transactions)

        # Cluster transactions by (method, path)
        clusters = self.clusterer.cluster_transactions(transactions)

        endpoints: List[EndpointModel] = []

        for (method, path), tx_list in clusters.items():
            sample_tx = tx_list[0]
            parsed_sample = urlparse(sample_tx.url)
            base_url = f"{parsed_sample.scheme}://{parsed_sample.netloc}"

            # 1. Path parameters
            _, path_params = self.clusterer.parameterize_path(parsed_sample.path)

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
                status_groups.setdefault(tx.status_code, []).append(tx)

            for code, group in status_groups.items():
                res_bodies = [t.response_body for t in group if t.response_body is not None]
                res_ct = group[0].response_content_type or "application/json"
                response_schema = self.schema_engine.build_response_schema(res_bodies, code, res_ct)
                responses[code] = response_schema

            op_id = generate_operation_id(method, path)
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
                frequency=len(tx_list)
            )
            endpoints.append(endpoint)

        # Sort endpoints by path and method for clean presentation
        endpoints.sort(key=lambda e: (e.path, e.method))
        stats["discovered_endpoints"] = len(endpoints)
        return endpoints, global_auth, stats
