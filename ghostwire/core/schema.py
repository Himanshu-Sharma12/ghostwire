"""Deep JSON Schema inference module for GhostWire.
Generates OpenAPI-compatible schemas and parameter definitions from observed network payloads.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from .models import ParameterModel, RequestSchema, ResponseSchema

# Arrays can hold thousands of records and endpoints thousands of calls; a sample is enough to learn their shape
MAX_ARRAY_ITEMS_SAMPLED = 50
MAX_BODIES_SAMPLED = 200


def sample_evenly(values: List[Any], limit: int = MAX_BODIES_SAMPLED) -> List[Any]:
    """Keeps at most `limit` values spread across the whole list (always including the first)."""
    if len(values) <= limit:
        return values
    step = len(values) / limit
    return [values[int(i * step)] for i in range(limit)]


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
            return {"type": "array", "items": {}}
        # Merge item schemas across the array so optional fields and mixed types are captured
        item_schema: Dict[str, Any] = {}
        for item in data[:MAX_ARRAY_ITEMS_SAMPLED]:
            item_schema = merge_schemas(item_schema, infer_json_schema(item))
        return {"type": "array", "items": item_schema}

    schema = {"type": openapi_type}
    if fmt:
        schema["format"] = fmt
    schema["example"] = data
    return schema


def _schema_types(schema: Dict[str, Any]) -> Set[str]:
    t = schema.get("type")
    if isinstance(t, list):
        return set(t)
    return {t} if t else set()


def _split_null(schema: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Splits a schema into (non-null part or None, whether null is allowed)."""
    types = _schema_types(schema)
    if "null" not in types:
        return schema, False
    rest = sorted(types - {"null"})
    if not rest:
        return None, True
    return {**schema, "type": rest[0] if len(rest) == 1 else rest}, True


def _with_null(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Marks a schema as nullable using the OpenAPI 3.1 type array form."""
    if "oneOf" in schema:
        variants = schema["oneOf"]
        if not any(_schema_types(v) == {"null"} for v in variants):
            return {"oneOf": variants + [{"type": "null"}]}
        return schema
    types = _schema_types(schema)
    if not types or "null" in types:
        return schema
    result = dict(schema)
    result["type"] = sorted(types) + ["null"]
    return result


def _merge_same_kind(schema1: Dict[str, Any], schema2: Dict[str, Any], kind: str) -> Dict[str, Any]:
    if kind == "object":
        props1 = schema1.get("properties", {})
        props2 = schema2.get("properties", {})
        merged_props = dict(props1)

        for k, v in props2.items():
            if k in merged_props:
                merged_props[k] = merge_schemas(merged_props[k], v)
            else:
                merged_props[k] = v

        # Required fields are those present in both, keeping first-seen order
        req2 = set(schema2.get("required", []))
        common_required = [r for r in schema1.get("required", []) if r in req2]

        return {
            "type": "object",
            "properties": merged_props,
            "required": common_required
        }

    if kind == "array":
        return {"type": "array", "items": merge_schemas(schema1.get("items", {}), schema2.get("items", {}))}

    if kind == "number":
        merged = {"type": "number", "format": "double"}
        if "example" in schema1:
            merged["example"] = schema1["example"]
        return merged

    if schema1.get("format") != schema2.get("format"):
        merged = {k: v for k, v in schema1.items() if k != "format"}
        return merged

    return schema1


def _kind(types: Set[str]) -> Optional[str]:
    """Returns the single merge kind for a set of non-null types, widening integer to number."""
    if types <= {"integer", "number"} and types:
        return "number" if "number" in types else "integer"
    if len(types) == 1:
        return next(iter(types))
    return None


def merge_schemas(schema1: Dict[str, Any], schema2: Dict[str, Any]) -> Dict[str, Any]:
    """Merges two OpenAPI schemas observed across multiple responses/requests."""
    if not schema1:
        return schema2
    if not schema2:
        return schema1

    # Union schemas: merge each observation into a compatible variant, or append it.
    # Null is kept as one separate variant so a null value never matches two branches.
    if "oneOf" in schema1 or "oneOf" in schema2:
        variants: List[Dict[str, Any]] = []
        nullable = False
        for incoming in list(schema1.get("oneOf", [schema1])) + list(schema2.get("oneOf", [schema2])):
            core, has_null = _split_null(incoming)
            nullable = nullable or has_null
            if core is None:
                continue
            incoming_kind = _kind(_schema_types(core))
            for i, existing in enumerate(variants):
                existing_kind = _kind(_schema_types(existing))
                if incoming_kind is not None and existing_kind is not None and _kind({incoming_kind, existing_kind}):
                    variants[i] = merge_schemas(existing, core)
                    break
            else:
                variants.append(core)
        if nullable:
            variants.append({"type": "null"})
        return variants[0] if len(variants) == 1 else {"oneOf": variants}

    types1 = _schema_types(schema1)
    types2 = _schema_types(schema2)
    nullable = "null" in types1 or "null" in types2
    core1 = types1 - {"null"}
    core2 = types2 - {"null"}

    if not core1 and not core2:
        return {"type": "null"}
    if not core1:
        return _with_null(schema2)
    if not core2:
        return _with_null(schema1)

    kind1, kind2 = _kind(core1), _kind(core2)
    combined = _kind({kind1, kind2}) if kind1 and kind2 else None
    if combined is None:
        strip = lambda sc: {**sc, "type": sorted(_schema_types(sc) - {"null"})[0]} if "null" in _schema_types(sc) else sc
        merged = {"oneOf": [strip(schema1), strip(schema2)]}
    else:
        s1 = {**schema1, "type": combined}
        s2 = {**schema2, "type": combined}
        merged = _merge_same_kind(s1, s2, combined)

    return _with_null(merged) if nullable else merged


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
        for body in sample_evenly(valid_bodies):
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
        for body in sample_evenly(valid_bodies):
            schema = infer_json_schema(body)
            merged = merge_schemas(merged, schema)

        return ResponseSchema(
            status_code=status_code,
            content_type=content_type,
            schema_dict=merged,
            example_body=valid_bodies[0]
        )
