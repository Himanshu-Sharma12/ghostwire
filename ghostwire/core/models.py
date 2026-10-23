"""Core data models for GhostWire."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParameterModel(BaseModel):
    name: str
    location: str  # 'path', 'query', 'header', 'cookie'
    param_type: str = "string"
    required: bool = False
    example: Optional[Any] = None
    description: Optional[str] = None


class AuthInfo(BaseModel):
    auth_type: str = "none"  # 'bearer', 'basic', 'api_key', 'cookie', 'oauth'
    header_name: Optional[str] = None
    token_preview: Optional[str] = None
    token_value: Optional[str] = None
    cookie_name: Optional[str] = None


class RequestSchema(BaseModel):
    content_type: str = "application/json"
    schema_dict: Dict[str, Any] = Field(default_factory=dict)
    example_payload: Optional[Any] = None


class ResponseSchema(BaseModel):
    status_code: int = 200
    content_type: str = "application/json"
    schema_dict: Dict[str, Any] = Field(default_factory=dict)
    example_body: Optional[Any] = None


class EndpointModel(BaseModel):
    method: str
    path: str
    original_url: str
    base_url: str
    operation_id: str
    summary: str
    description: str = ""
    parameters: List[ParameterModel] = Field(default_factory=list)
    request_body: Optional[RequestSchema] = None
    responses: Dict[int, ResponseSchema] = Field(default_factory=dict)
    auth: Optional[AuthInfo] = None
    frequency: int = 1


class CapturedTransaction(BaseModel):
    method: str
    url: str
    status_code: int
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[Any] = None
    request_content_type: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[Any] = None
    response_content_type: Optional[str] = None
    query_params: Dict[str, List[str]] = Field(default_factory=dict)
    time_ms: float = 0.0
