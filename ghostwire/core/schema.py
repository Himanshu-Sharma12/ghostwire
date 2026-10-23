"""Deep JSON Schema inference module for GhostWire.
Generates OpenAPI-compatible schemas and parameter definitions from observed network payloads.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from .models import ParameterModel, RequestSchema, ResponseSchema


def python_type_to_openapi(val: Any) -> Tuple[str, Optional[str]]:
    """Converts a Python value to (openapi_type, openapi_format)."""
    if val is None:
        return "string", None
    if isinstance(val, bool):
        return "boolean", None
    if isinstance(val, int):
        return "integer", "int64"
    if isinstance(val, float):
        return "number", "double"
    if isinstance(val, str):
        # Basic format checks
        if val.startswith("http://") or val.startswith("https://"):
            return "string", "uri"
        if "@" in val and "." in val and " " not in val:
            return "string", "email"
        return "string", None
    if isinstance(val, list):
        return "array", None
    if isinstance(val, dict):
        return "object", None
    return "string", None


def infer_json_schema(data: Any) -> Dict[str, Any]:
    """Recursively generates an OpenAPI 3.1 JSON schema from a sample value."""
    if data is None:
        return {"type": "null"}

    openapi_type, fmt = python_type_to_openapi(data)

    if openapi_type == "object" and isinstance(data, dict):
        properties = {}
        for k, v in data.items():
            properties[k] = infer_json_schema(v)
        schema = {
            "type": "object",
            "properties": properties,
            "required": list(data.keys())
        }
        return schema

    if openapi_type == "array" and isinstance(data, list):
        if not data:
            return {"type": "array", "items": {"type": "string"}}
        # Infer items from the first element or merged
        item_schema = infer_json_schema(data[0])
        return {"type": "array", "items": item_schema}

    schema = {"type": openapi_type}
    if fmt:
        schema["format"] = fmt
    schema["example"] = data
    return schema


def merge_schemas(schema1: Dict[str, Any], schema2: Dict[str, Any]) -> Dict[str, Any]:
    """Merges two OpenAPI schemas observed across multiple responses/requests."""
    if not schema1:
        return schema2
    if not schema2:
        return schema1

    t1 = schema1.get("type")
    t2 = schema2.get("type")

    if t1 != t2:
        # Combined union type
        return {"oneOf": [schema1, schema2]}

    if t1 == "object":
        props1 = schema1.get("properties", {})
        props2 = schema2.get("properties", {})
        merged_props = dict(props1)

        for k, v in props2.items():
            if k in merged_props:
                merged_props[k] = merge_schemas(merged_props[k], v)
            else:
                merged_props[k] = v

        # Required fields are those present in both
        req1 = set(schema1.get("required", []))
        req2 = set(schema2.get("required", []))
        common_required = list(req1.intersection(req2))

        return {
            "type": "object",
            "properties": merged_props,
            "required": common_required
        }

    if t1 == "array":
        items1 = schema1.get("items", {})
        items2 = schema2.get("items", {})
        return {"type": "array", "items": merge_schemas(items1, items2)}

    return schema1


class SchemaEngine:
    def __init__(self):
        pass

    def extract_query_parameters(self, query_dict: Dict[str, List[str]]) -> List[ParameterModel]:
        """Extracts and infers parameter models from captured query strings."""
        params: List[ParameterModel] = []
        for name, values in query_dict.items():
            if not values:
                continue
            example_val = values[0]
            param_type = "string"
            if example_val.isdigit():
                param_type = "integer"
            elif example_val.lower() in {"true", "false"}:
                param_type = "boolean"

            params.append(ParameterModel(
                name=name,
                location="query",
                param_type=param_type,
                required=False,
                example=example_val,
                description=f"Query parameter '{name}'"
            ))
        return params

    def build_request_schema(self, bodies: List[Any], content_type: str = "application/json") -> Optional[RequestSchema]:
        """Infers an aggregated request schema from a list of request bodies."""
        valid_bodies = [b for b in bodies if b is not None]
        if not valid_bodies:
            return None

        merged = {}
        for body in valid_bodies:
            schema = infer_json_schema(body)
            merged = merge_schemas(merged, schema)

        return RequestSchema(
            content_type=content_type or "application/json",
            schema_dict=merged,
            example_payload=valid_bodies[0]
        )

    def build_response_schema(self, bodies: List[Any], status_code: int = 200, 
                              content_type: str = "application/json") -> ResponseSchema:
        """Infers an aggregated response schema from a list of response bodies."""
        valid_bodies = [b for b in bodies if b is not None]
        if not valid_bodies:
            return ResponseSchema(
                status_code=status_code,
                content_type=content_type,
                schema_dict={"type": "string"},
                example_body=""
            )

        merged = {}
        for body in valid_bodies:
            schema = infer_json_schema(body)
            merged = merge_schemas(merged, schema)

        return ResponseSchema(
            status_code=status_code,
            content_type=content_type,
            schema_dict=merged,
            example_body=valid_bodies[0]
        )
