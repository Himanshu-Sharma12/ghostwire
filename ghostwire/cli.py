"""GhostWire CLI & Terminal UI.
Turns browser traffic (HAR) into OpenAPI specs, SDKs, mock servers and Postman collections.
"""

from pathlib import Path
import json
import shlex
import tempfile
import time
from urllib.parse import urlencode
from typing import Dict, List, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

from . import __version__
from .core.analyzer import ReverseEngineeringEngine
from .core.models import AuthInfo, EndpointModel
from .generators.mock_server import MockServerGenerator
from .generators.openapi import OpenApiGenerator
from .generators.postman import PostmanCollectionGenerator
from .generators.python_sdk import PythonSdkGenerator
from .generators.typescript_sdk import TypeScriptSdkGenerator

app = typer.Typer(
    help="👻 GhostWire — turn browser traffic (HAR) into OpenAPI specs, SDKs, mock servers and Postman collections",
    add_completion=False
)
console = Console()

BANNER = r"""[bold cyan]
   ______  __                 __  _       ___          
  / ____/ / /_  ____   _____ / /_| |     / (_)_____ ___ 
 / / __  / __ \/ __ \ / ___// __/| | /| / / // ___// _ \
/ /_/ / / / / / /_/ /(__  )/ /_  | |/ |/ / // /   /  __/
\____/ /_/ /_/\____//____/ \__/   |__/|__//_//_/    \___/ 
[/bold cyan]
[dim cyan]⚡ Turn browser traffic into OpenAPI specs, SDKs and mock servers[/dim cyan]
[dim]v""" + __version__ + """ | Runs locally | https://github.com/Himanshu-Sharma12/ghostwire[/dim]
"""


def print_banner():
    console.print(BANNER)


def check_files(har_files: List[str]) -> None:
    for har_file in har_files:
        if not Path(har_file).exists():
            console.print(f"[bold red]Error:[/bold red] File not found: [yellow]{har_file}[/yellow]")
            raise typer.Exit(code=1)


def run_analysis(engine: ReverseEngineeringEngine, har_files: List[str]):
    """Runs the engine, turning unreadable or non-HAR input into a clean error instead of a traceback."""
    try:
        return engine.analyze_har(har_files)
    except (ValueError, UnicodeDecodeError) as exc:  # json.JSONDecodeError is a ValueError
        console.print(f"[bold red]Error:[/bold red] Could not read capture: {escape(str(exc))}")
        console.print("[dim]Export it from DevTools → Network → 'Save all as HAR with content'.[/dim]")
        raise typer.Exit(code=1)


def auth_headers(auth: Optional[AuthInfo]) -> Dict[str, str]:
    """Builds the request headers that replay a detected credential."""
    if not auth or not auth.token_value:
        return {}
    if auth.auth_type == "bearer":
        return {"Authorization": f"Bearer {auth.token_value}"}
    if auth.auth_type == "basic":
        return {"Authorization": f"Basic {auth.token_value}"}
    if auth.auth_type == "custom":
        return {"Authorization": auth.token_value}
    if auth.auth_type == "api_key":
        return {auth.header_name or "x-api-key": auth.token_value}
    if auth.auth_type == "cookie":
        return {"Cookie": f"{auth.cookie_name or 'session'}={auth.token_value}"}
    return {}


def request_body_kwargs(ep: EndpointModel) -> Dict[str, object]:
    """httpx keyword arguments that send the captured example body with its original encoding."""
    if not ep.request_body or ep.request_body.example_payload is None:
        return {}
    payload = ep.wire_payload()
    encoding = ep.request_body.encoding
    if encoding == "form" and isinstance(payload, dict):
        return {"data": payload}
    if encoding == "multipart" and isinstance(payload, dict):
        return {"files": {k: (None, str(v)) for k, v in payload.items()}}
    if isinstance(payload, str):
        return {"content": payload}
    return {"json": payload}


def display_path(ep: EndpointModel) -> str:
    if ep.graphql_operation:
        return f"{escape(ep.path)} [magenta]({escape(ep.graphql_operation)})[/magenta]"
    return escape(ep.path)


def find_endpoint(endpoints: List[EndpointModel], target: str) -> EndpointModel:
    """Matches an exact operation ID first, then any operation ID or path containing the target."""
    target_lower = target.lower()
    exact = [e for e in endpoints if e.operation_id.lower() == target_lower]
    matched = exact or [
        e for e in endpoints
        if target_lower in e.operation_id.lower() or target_lower in e.path.lower()
    ]
    if not matched:
        console.print(f"[bold red]Error:[/bold red] No endpoint found matching '[yellow]{target}[/yellow]'.")
        console.print("Available operation IDs:\n  " + "\n  ".join([e.operation_id for e in endpoints]))
        raise typer.Exit(code=1)
    if len(matched) > 1:
        console.print(f"[dim]{len(matched)} endpoints match '{target}', using the first. Pass an exact operation ID to choose:[/dim]")
        for e in matched:
            console.print(f"[dim]  {e.operation_id}[/dim]")
    return matched[0]


def method_color(method: str) -> str:
    m = method.upper()
    if m == "GET":
        return f"[bold green]{m}[/bold green]"
    if m == "POST":
        return f"[bold blue]{m}[/bold blue]"
    if m in {"PUT", "PATCH"}:
        return f"[bold yellow]{m}[/bold yellow]"
    if m == "DELETE":
        return f"[bold red]{m}[/bold red]"
    return f"[bold magenta]{m}[/bold magenta]"


@app.command()
def inspect(
    har_files: List[str] = typer.Argument(..., help="One or more .har HTTP archive capture files"),
    target_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by specific domain (optional)")
):
    """
    🔍 Inspect network capture: cleans noise, identifies endpoints, and displays detected auth.
    """
    print_banner()
    check_files(har_files)

    domains = {target_domain} if target_domain else None
    engine = ReverseEngineeringEngine(target_domains=domains)

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task("Parsing HAR & scrubbing telemetry noise...", total=None)
        endpoints, auth, stats = run_analysis(engine, har_files)

    # Display Metrics Panel
    metrics_table = Table.grid(padding=(0, 2))
    metrics_table.add_column(style="bold cyan")
    metrics_table.add_column()
    metrics_table.add_row("Total Captured Entries:", f"[bold]{stats.get('total_entries', 0)}[/bold]")
    metrics_table.add_row("Scrubbed Noise (Trackers/Assets):", f"[yellow]{stats.get('discarded_entries', 0)}[/yellow]")
    metrics_table.add_row("Discovered API Endpoints:", f"[bold green]{len(endpoints)}[/bold green]")

    auth_desc = "[dim]None Detected[/dim]"
    if auth:
        auth_desc = f"[bold green]{auth.auth_type.upper()}[/bold green] (Token: [cyan]{auth.token_preview}[/cyan])"
    metrics_table.add_row("Detected Authentication:", auth_desc)

    console.print(Panel(metrics_table, title="[bold]📊 Traffic Analysis Summary[/bold]", border_style="cyan"))

    if not endpoints:
        console.print("[yellow]No API endpoints discovered in this capture. Make sure the capture contains JSON/REST traffic.[/yellow]")
        return

    # Endpoints Table
    table = Table(title="🎯 Discovered Endpoints & Parameters", border_style="dim")
    table.add_column("Method", style="bold", width=8)
    table.add_column("Host", style="dim")
    table.add_column("Path", style="bold white")
    table.add_column("Operation ID", style="cyan")
    table.add_column("Parameters", style="green")
    table.add_column("Responses", style="magenta")

    # Group by host so first- and third-party APIs are easy to tell apart
    for ep in sorted(endpoints, key=lambda e: (e.base_url, e.path, e.method)):
        params_str = ", ".join([f"{escape(p.name)} ({p.location})" for p in ep.parameters]) or "[dim]None[/dim]"
        status_codes = ", ".join([str(c) for c in ep.responses.keys()]) or "200"
        table.add_row(
            method_color(ep.method),
            escape(ep.base_url.split("://", 1)[-1]),
            display_path(ep),
            ep.operation_id,
            params_str,
            status_codes
        )

    console.print(table)
    console.print("\n[dim]Run [bold]gw analyze " + " ".join(har_files) + "[/bold] to generate SDKs and OpenAPI spec.[/dim]\n")


@app.command()
def analyze(
    har_files: List[str] = typer.Argument(..., help="One or more .har HTTP archive capture files"),
    output_dir: str = typer.Option("./ghostwire_output", "--output-dir", "-o", help="Directory to save generated code"),
    generate_all: bool = typer.Option(True, "--generate-all", "-a", help="Generate OpenAPI, Python SDK, TypeScript SDK, and Mock Server"),
    target_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by specific domain (optional)"),
    embed_secrets: bool = typer.Option(
        False, "--embed-secrets",
        help="Write the captured token into the SDKs/Postman and keep passwords & tokens in examples. "
             "Off by default so the output is safe to share."
    )
):
    """
    ⚡ Reverse-engineer network traffic and automatically synthesize SDKs, OpenAPI, and Mock API.
    """
    print_banner()
    check_files(har_files)

    domains = {target_domain} if target_domain else None
    engine = ReverseEngineeringEngine(target_domains=domains, redact_secrets=not embed_secrets)
    out_path = Path(output_dir)

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task("Deconstructing API schemas and auth mechanisms...", total=None)
        endpoints, auth, stats = run_analysis(engine, har_files)

    if not endpoints:
        console.print("[bold red]No valid API endpoints discovered.[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"✨ [bold green]Discovered {len(endpoints)} API Endpoints[/bold green] from [bold]{stats.get('total_entries', 0)}[/bold] raw transactions.")
    if auth:
        console.print(f"🔑 [bold green]Auth Extracted:[/bold green] {auth.auth_type.upper()} ({auth.token_preview})")

    out_path.mkdir(parents=True, exist_ok=True)
    generated_files = []

    # 1. OpenAPI Specs
    openapi_gen = OpenApiGenerator(title="Reverse-Engineered API")
    json_path, yaml_path = openapi_gen.export_files(endpoints, auth, out_path)
    generated_files.append((json_path, "OpenAPI 3.1.0 JSON Specification"))
    generated_files.append((yaml_path, "OpenAPI 3.1.0 YAML Specification"))

    # 2. Python SDK
    py_gen = PythonSdkGenerator(embed_secrets=embed_secrets)
    py_path = py_gen.export_file(endpoints, auth, out_path)
    generated_files.append((py_path, "Production Python SDK (httpx + types)"))

    # 3. TypeScript SDK
    ts_gen = TypeScriptSdkGenerator(embed_secrets=embed_secrets)
    ts_path = ts_gen.export_file(endpoints, auth, out_path)
    generated_files.append((ts_path, "Zero-dependency TypeScript SDK (native fetch)"))

    # 4. Mock API Server
    mock_gen = MockServerGenerator()
    mock_path = mock_gen.export_file(endpoints, auth, out_path)
    generated_files.append((mock_path, "Standalone FastAPI Mock Server"))

    # 5. Postman Collection
    postman_gen = PostmanCollectionGenerator(collection_name="Discovered API", embed_secrets=embed_secrets)
    postman_path = postman_gen.export_file(endpoints, auth, out_path)
    generated_files.append((postman_path, "Postman Collection v2.1.0"))

    # Summary Panel
    out_table = Table(title="📦 Generated Code & Artifacts", border_style="cyan")
    out_table.add_column("File", style="bold green")
    out_table.add_column("Description", style="white")

    for f_path, desc in generated_files:
        out_table.add_row(str(f_path.relative_to(Path.cwd()) if f_path.is_relative_to(Path.cwd()) else f_path), desc)

    console.print("\n", out_table, "\n")
    if auth and not embed_secrets:
        from .generators.python_sdk import AUTH_ENV_VARS
        env_var = AUTH_ENV_VARS.get(auth.auth_type)
        if env_var:
            console.print(f"🔒 [bold]Secrets were not written to disk.[/bold] Set [bold]{env_var}[/bold] (Python), pass "
                          "[bold]authToken[/bold] (TypeScript) or fill the [bold]authToken[/bold] Postman variable. "
                          "Use [bold]--embed-secrets[/bold] to embed the captured credential.\n")
    console.print("[bold cyan]🚀 Next Steps:[/bold cyan]")
    console.print(f"  1. Test your Python SDK:      [bold]cd {out_path} && python -c 'from client import ApiClient; api = ApiClient()'[/bold]")
    console.print(f"  2. Run the Local Mock Server: [bold]python {mock_path}[/bold]")
    console.print(f"  3. View OpenAPI in Swagger:   Import [bold]{json_path}[/bold] into Postman or editor.swagger.io\n")


@app.command()
def mock(
    har_files: List[str] = typer.Argument(..., help="One or more .har HTTP archive capture files"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind the mock server"),
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind (use 0.0.0.0 to expose on your network)"),
    target_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by specific domain (optional)")
):
    """
    🎭 Instantly spin up a local mock server using captured payload fixtures.
    """
    print_banner()
    check_files(har_files)

    domains = {target_domain} if target_domain else None
    engine = ReverseEngineeringEngine(target_domains=domains)
    endpoints, auth, _ = run_analysis(engine, har_files)

    if not endpoints:
        console.print("[bold red]No valid API endpoints discovered to mock.[/bold red]")
        raise typer.Exit(code=1)

    import importlib.util
    import uvicorn

    # Generate and load the app; the temporary file is no longer needed once the module is in memory
    with tempfile.TemporaryDirectory(prefix="ghostwire_mock_") as temp_dir:
        mock_file = MockServerGenerator().export_file(endpoints, auth, Path(temp_dir))
        spec = importlib.util.spec_from_file_location("ghostwire_mock_module", str(mock_file.resolve()))
        if not (spec and spec.loader):
            console.print("[bold red]Failed to load generated mock server.[/bold red]")
            raise typer.Exit(code=1)
        mock_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mock_module)

    console.print(f"⚡ Booting mock server with [bold green]{len(endpoints)} endpoints[/bold green] on port [bold cyan]{port}[/bold cyan]...")
    console.print(f"📖 Swagger Docs: [bold underline]http://{host}:{port}/docs[/bold underline]")
    uvicorn.run(getattr(mock_module, "app"), host=host, port=port)


@app.command()
def curl(
    har_file: str = typer.Argument(..., help="Path to .har HTTP archive capture file"),
    target: str = typer.Argument(..., help="Operation ID or path substring to generate cURL for")
):
    """
    📋 Generate an exact, copy-pasteable cURL command for any discovered endpoint.
    """
    print_banner()
    check_files([har_file])

    # Replaying needs the real captured payloads, so redaction is off here
    engine = ReverseEngineeringEngine(redact_secrets=False)
    endpoints, auth, _ = run_analysis(engine, [har_file])
    ep = find_endpoint(endpoints, target)

    curl_parts = [f"curl -X {ep.method.upper()} {shlex.quote(ep.original_url)}"]
    curl_parts.append(f"-H {shlex.quote('Accept: application/json')}")
    for name, value in auth_headers(auth).items():
        curl_parts.append(f"-H {shlex.quote(f'{name}: {value}')}")

    if ep.request_body and ep.request_body.example_payload is not None:
        payload = ep.wire_payload()
        encoding = ep.request_body.encoding
        if encoding == "form" and isinstance(payload, dict):
            curl_parts.append(f"-H {shlex.quote('Content-Type: application/x-www-form-urlencoded')}")
            curl_parts.append(f"-d {shlex.quote(urlencode(payload, doseq=True))}")
        elif encoding == "multipart" and isinstance(payload, dict):
            curl_parts.extend(f"-F {shlex.quote(f'{k}={v}')}" for k, v in payload.items())
        elif isinstance(payload, str):
            curl_parts.append(f"-H {shlex.quote('Content-Type: ' + ep.request_body.content_type)}")
            curl_parts.append(f"--data-binary {shlex.quote(payload)}")
        else:
            curl_parts.append(f"-H {shlex.quote('Content-Type: application/json')}")
            curl_parts.append(f"-d {shlex.quote(json.dumps(payload))}")

    curl_cmd = " \\\n  ".join(curl_parts)
    console.print(f"[bold green]🎯 Matching Endpoint:[/bold green] [bold cyan]{ep.method} {display_path(ep)}[/bold cyan] ({ep.operation_id})")
    console.print("[bold]📋 Generated cURL Command[/bold] [dim](copy-pasteable)[/dim]\n")
    # Printed raw (no panel or wrapping) so long payloads survive copy-paste intact
    console.print(curl_cmd, markup=False, highlight=False, soft_wrap=True)


@app.command()
def call(
    har_file: str = typer.Argument(..., help="Path to .har HTTP archive capture file"),
    target: str = typer.Argument(..., help="Operation ID or path substring to call live"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt for POST/PUT/PATCH/DELETE")
):
    """
    ⚡ Execute a live request against any discovered endpoint directly from your terminal.
    """
    print_banner()
    check_files([har_file])

    import httpx
    # Replaying needs the real captured payloads, so redaction is off here
    engine = ReverseEngineeringEngine(redact_secrets=False)
    endpoints, auth, _ = run_analysis(engine, [har_file])
    ep = find_endpoint(endpoints, target)

    if ep.method.upper() not in {"GET", "HEAD", "OPTIONS"} and not yes:
        typer.confirm(
            f"{ep.method.upper()} {ep.original_url} may change data on the live server. Send it?",
            abort=True
        )

    console.print(f"🚀 Calling live endpoint: [bold cyan]{ep.method} {escape(ep.original_url)}[/bold cyan] ...")

    headers = {"Accept": "application/json", **auth_headers(auth)}
    if ep.request_body and isinstance(ep.request_body.example_payload, str):
        headers["Content-Type"] = ep.request_body.content_type

    try:
        t0 = time.time()
        with httpx.Client(timeout=15.0) as client:
            res = client.request(
                method=ep.method.upper(),
                url=ep.original_url,
                headers=headers,
                **request_body_kwargs(ep)
            )
        elapsed = round((time.time() - t0) * 1000, 2)
        console.print(f"✨ Status: [bold green]{res.status_code}[/bold green] | Time: [cyan]{elapsed}ms[/cyan]")
        try:
            formatted_json = json.dumps(res.json(), indent=2)
            console.print(Syntax(formatted_json, "json", theme="monokai"))
        except Exception:
            console.print(res.text, markup=False)
    except Exception as exc:
        console.print(f"[bold red]Request Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def version():
    """Display GhostWire version."""
    console.print(f"GhostWire [bold cyan]v{__version__}[/bold cyan]")


def main():
    app()


if __name__ == "__main__":
    main()
