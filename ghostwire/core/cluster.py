"""Endpoint clustering and dynamic path parameter inference module for GhostWire.
Transforms variable URLs (e.g. /api/users/42, /orders/uuid-123) into parameterized templates (/api/users/{userId}).
"""

import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from .models import CapturedTransaction, ParameterModel

# Regex patterns for dynamic URL tokens
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
MONGO_OBJECT_ID_REGEX = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
INTEGER_ID_REGEX = re.compile(r"^\d+$")
HEX_HASH_REGEX = re.compile(r"^[0-9a-f]{32,64}$", re.IGNORECASE)


def infer_parameter_name(segment: str, previous_segment: str) -> Tuple[bool, str, str]:
    """
    Returns (is_param, param_name, param_type).
    E.g. ('42', 'users') -> (True, 'userId', 'integer')
    """
    cleaned_prev = re.sub(r"[^a-zA-Z0-9]", "", previous_segment).rstrip("s")
    base_name = f"{cleaned_prev}Id" if cleaned_prev else "id"

    if UUID_REGEX.match(segment):
        return True, base_name, "string"
    if MONGO_OBJECT_ID_REGEX.match(segment) or HEX_HASH_REGEX.match(segment):
        return True, base_name, "string"
    if INTEGER_ID_REGEX.match(segment):
        return True, base_name, "integer"
    return False, segment, "string"


class PathClusterer:
    def __init__(self):
        pass

    def parameterize_path(self, raw_path: str) -> Tuple[str, List[ParameterModel]]:
        """
        Parses a URL path, detects dynamic segments, and generates a normalized template.
        E.g. /api/v1/projects/59/tasks/abc-123 -> /api/v1/projects/{projectId}/tasks/{taskId}
        """
        segments = raw_path.strip("/").split("/")
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

    def cluster_transactions(self, transactions: List[CapturedTransaction]) -> Dict[Tuple[str, str], List[CapturedTransaction]]:
        """
        Groups transactions by (method, parameterized_path).
        """
        clusters: Dict[Tuple[str, str], List[CapturedTransaction]] = {}

        for tx in transactions:
            parsed = urlparse(tx.url)
            normalized_path, _ = self.parameterize_path(parsed.path)
            key = (tx.method.upper(), normalized_path)

            if key not in clusters:
                clusters[key] = []
            clusters[key].append(tx)

        return clusters
