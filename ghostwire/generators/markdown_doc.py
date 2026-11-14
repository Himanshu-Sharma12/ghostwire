"""Markdown API Reference documentation generator module for GhostWire.
Synthesizes a human-readable API documentation file with endpoint summaries,
schemas, parameter tables, authentication setup, and copy-paste curl snippets.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from ..core.models import AuthInfo, EndpointModel


class MarkdownDocGenerator:
    """Generates clean, human-readable Markdown API reference documentation."""

    def __init__(self, title: str = "API Reference", embed_secrets: bool = False):
        self.title = title
        self.embed_secrets = embed_secrets

    def generate(self, endpoints: List[EndpointModel], auth: Optional[AuthInfo] = None) -> str:
        """Generates the full markdown document string."""
        lines: List[str] = []

        # Title
        lines.append(f"# {self.title}")
        lines.append("")
        lines.append(
            "Auto-generated API Reference produced by [GhostWire](https://github.com/Himanshu-Sharma12/ghostwire) "
            "from captured network traffic."
        )
        lines.append("")

        # Overview
        lines.append("## Overview")
        lines.append("")
        base_urls = sorted(list({ep.base_url for ep in endpoints if ep.base_url}))
        base_urls_str = ", ".join(f"`{u}`" for u in base_urls) if base_urls else "Not specified"
        lines.append(f"- **Total Endpoints:** {len(endpoints)}")
        lines.append(f"- **Base URL(s):** {base_urls_str}")
        lines.append(f"- **Authentication:** {auth.auth_type.upper() if auth else 'None'}")
        lines.append("")

        # Authentication Section
        if auth and auth.auth_type != "none":
            lines.append("## Authentication")
            lines.append("")
            token_display = (
                auth.token_value if (self.embed_secrets and auth.token_value) else "<YOUR_TOKEN_HERE>"
            )
            if auth.auth_type == "bearer":
                lines.append(
                    f"Requests require a Bearer token passed in the `Authorization` header:"
                )
                lines.append("")
                lines.append("```http")
                lines.append(f"Authorization: Bearer {token_display}")
                lines.append("```")
            elif auth.auth_type == "basic":
                lines.append("Requests require HTTP Basic Authentication:")
                lines.append("")
                lines.append("```http")
                lines.append(f"Authorization: Basic {token_display}")
                lines.append("```")
            elif auth.auth_type == "api_key":
                header = auth.header_name or "X-API-Key"
                lines.append(f"Requests require an API key passed in the `{header}` header:")
                lines.append("")
                lines.append("```http")
                lines.append(f"{header}: {token_display}")
                lines.append("```")
            elif auth.auth_type == "cookie":
                cookie_name = auth.cookie_name or "session"
                lines.append(f"Requests require session authentication via Cookie:")
                lines.append("")
                lines.append("```http")
                lines.append(f"Cookie: {cookie_name}={token_display}")
                lines.append("```")
            lines.append("")

        # Endpoints Index Table
        lines.append("## Endpoints Summary")
        lines.append("")
        lines.append("| Method | Path | Summary | Operation ID |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for ep in endpoints:
            summary = ep.summary or ep.description or "-"
            summary_clean = summary.replace("|", "\\|").strip()
            anchor = f"{ep.method.lower()}-{ep.path.lower().replace('/', '').replace('{', '').replace('}', '').replace('_', '-')}"
            lines.append(
                f"| `{ep.method}` | [`{ep.path}`](#{anchor}) | {summary_clean} | `{ep.operation_id}` |"
            )
        lines.append("")

        # Detailed Endpoint Descriptions
        lines.append("## Detailed Endpoints")
        lines.append("")

        for ep in endpoints:
            lines.append(f"### `{ep.method}` {ep.path}")
            lines.append("")
            if ep.summary:
                lines.append(f"**{ep.summary}**")
                lines.append("")
            if ep.description and ep.description != ep.summary:
                lines.append(ep.description)
                lines.append("")

            lines.append(f"- **Operation ID:** `{ep.operation_id}`")
            lines.append(f"- **Base URL:** `{ep.base_url}`")
            lines.append("")

            # Parameters
            if ep.parameters:
                lines.append("#### Parameters")
                lines.append("")
                lines.append("| Name | Location | Type | Required | Description |")
                lines.append("| :--- | :--- | :--- | :--- | :--- |")
                for param in ep.parameters:
                    req_str = "Yes" if param.required else "No"
                    desc = param.description or (f"Example: `{param.example}`" if param.example is not None else "-")
                    desc_clean = str(desc).replace("|", "\\|")
                    lines.append(
                        f"| `{param.name}` | {param.location} | `{param.param_type}` | {req_str} | {desc_clean} |"
                    )
                lines.append("")

            # Request Body
            if ep.request_body and ep.request_body.example_payload is not None:
                lines.append(f"#### Request Body (`{ep.request_body.content_type}`)")
                lines.append("")
                lines.append("```json")
                if isinstance(ep.request_body.example_payload, (dict, list)):
                    lines.append(json.dumps(ep.request_body.example_payload, indent=2))
                else:
                    lines.append(str(ep.request_body.example_payload))
                lines.append("```")
                lines.append("")

            # Responses
            if ep.responses:
                lines.append("#### Responses")
                lines.append("")
                for status_code, resp in sorted(ep.responses.items()):
                    lines.append(f"**Status Code {status_code}** (`{resp.content_type}`)")
                    lines.append("")
                    if resp.example_body is not None:
                        lines.append("```json")
                        if isinstance(resp.example_body, (dict, list)):
                            lines.append(json.dumps(resp.example_body, indent=2))
                        else:
                            lines.append(str(resp.example_body))
                        lines.append("```")
                        lines.append("")

            # Example cURL Snippet
            lines.append("#### Example cURL")
            lines.append("")
            curl_cmd = self._generate_curl_snippet(ep, auth)
            lines.append("```bash")
            lines.append(curl_cmd)
            lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _generate_curl_snippet(self, ep: EndpointModel, auth: Optional[AuthInfo]) -> str:
        """Constructs an executable curl snippet for the endpoint."""
        url = f"{ep.base_url.rstrip('/')}{ep.path}"
        headers: List[str] = []

        # Auth header
        if auth and auth.auth_type != "none":
            tok = auth.token_value if (self.embed_secrets and auth.token_value) else "$AUTH_TOKEN"
            if auth.auth_type == "bearer":
                headers.append(f"-H 'Authorization: Bearer {tok}'")
            elif auth.auth_type == "basic":
                headers.append(f"-H 'Authorization: Basic {tok}'")
            elif auth.auth_type == "api_key":
                h_name = auth.header_name or "X-API-Key"
                headers.append(f"-H '{h_name}: {tok}'")
            elif auth.auth_type == "cookie":
                c_name = auth.cookie_name or "session"
                headers.append(f"-H 'Cookie: {c_name}={tok}'")

        # Query params
        query_params: Dict[str, Any] = {}
        for p in ep.parameters:
            if p.location == "query" and p.example is not None:
                query_params[p.name] = p.example
        if query_params:
            url += f"?{urlencode(query_params)}"

        parts = [f"curl -X {ep.method} '{url}'"]
        for h in headers:
            parts.append(f"  {h}")

        if ep.request_body and ep.request_body.example_payload is not None:
            parts.append(f"  -H 'Content-Type: {ep.request_body.content_type}'")
            if isinstance(ep.request_body.example_payload, (dict, list)):
                body_json = json.dumps(ep.request_body.example_payload)
                parts.append(f"  --data '{body_json}'")
            else:
                parts.append(f"  --data '{ep.request_body.example_payload}'")

        return " \\\n".join(parts)

    def export_file(
        self,
        endpoints: List[EndpointModel],
        auth: Optional[AuthInfo],
        output_dir: Path,
        filename: str = "API_REFERENCE.md",
    ) -> Path:
        """Exports the generated markdown documentation to a file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        content = self.generate(endpoints, auth)
        target_path = output_dir / filename
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
        return target_path
