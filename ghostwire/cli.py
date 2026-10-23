"""GhostWire CLI & Terminal UI.
The Autonomous Reverse-Engineering Agent for Hidden APIs & Web Traffic.
"""

from pathlib import Path
import sys
import time
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

from . import __version__
from .core.analyzer import ReverseEngineeringEngine
from .generators.mock_server import MockServerGenerator
from .generators.openapi import OpenApiGenerator
from .generators.python_sdk import PythonSdkGenerator
from .generators.typescript_sdk import TypeScriptSdkGenerator

app = typer.Typer(
    help="👻 GhostWire — Autonomous Reverse-Engineering Agent for Hidden APIs & Web Traffic",
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
[dim cyan]⚡ Autonomous Reverse-Engineering Agent for Hidden APIs & Web Traffic[/dim cyan]
[dim]v""" + __version__ + """ | 100% Offline & Free | https://github.com/your-username/ghostwire[/dim]
"""


def print_banner():
    console.print(BANNER)


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
    har_file: str = typer.Argument(..., help="Path to .har HTTP archive capture file"),
    target_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by specific domain (optional)")
):
    """
    🔍 Inspect network capture: cleans noise, identifies endpoints, and displays detected auth.
    """
    print_banner()
    har_path = Path(har_file)
    if not har_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: [yellow]{har_file}[/yellow]")
        raise typer.Exit(code=1)

    domains = {target_domain} if target_domain else None
    engine = ReverseEngineeringEngine(target_domains=domains)

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Parsing HAR & scrubbing telemetry noise...", total=None)
        time.sleep(0.3)
        endpoints, auth, stats = engine.analyze_har(str(har_path))

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
    table.add_column("Path", style="bold white")
    table.add_column("Operation ID", style="cyan")
    table.add_column("Parameters", style="green")
    table.add_column("Responses", style="magenta")

    for ep in endpoints:
        params_str = ", ".join([f"{p.name} ({p.location})" for p in ep.parameters]) or "[dim]None[/dim]"
        status_codes = ", ".join([str(c) for c in ep.responses.keys()]) or "200"
        table.add_row(
            method_color(ep.method),
            ep.path,
            ep.operation_id,
            params_str,
            status_codes
        )

    console.print(table)
    console.print("\n[dim]Run [bold]ghostwire analyze " + har_file + " --generate-all[/bold] to generate SDKs and OpenAPI spec.[/dim]\n")


@app.command()
def analyze(
    har_file: str = typer.Argument(..., help="Path to .har HTTP archive capture file"),
    output_dir: str = typer.Option("./ghostwire_output", "--output-dir", "-o", help="Directory to save generated code"),
    generate_all: bool = typer.Option(True, "--generate-all", "-a", help="Generate OpenAPI, Python SDK, TypeScript SDK, and Mock Server"),
    target_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by specific domain (optional)")
):
    """
    ⚡ Reverse-engineer network traffic and automatically synthesize SDKs, OpenAPI, and Mock API.
    """
    print_banner()
    har_path = Path(har_file)
    if not har_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: [yellow]{har_file}[/yellow]")
        raise typer.Exit(code=1)

    domains = {target_domain} if target_domain else None
    engine = ReverseEngineeringEngine(target_domains=domains)
    out_path = Path(output_dir)

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task("Deconstructing API schemas and auth mechanisms...", total=None)
        time.sleep(0.4)
        endpoints, auth, stats = engine.analyze_har(str(har_path))

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
    py_gen = PythonSdkGenerator()
    py_path = py_gen.export_file(endpoints, auth, out_path)
    generated_files.append((py_path, "Production Python SDK (httpx + types)"))

    # 3. TypeScript SDK
    ts_gen = TypeScriptSdkGenerator()
    ts_path = ts_gen.export_file(endpoints, auth, out_path)
    generated_files.append((ts_path, "Zero-dependency TypeScript SDK (native fetch)"))

    # 4. Mock API Server
    mock_gen = MockServerGenerator()
    mock_path = mock_gen.export_file(endpoints, auth, out_path)
    generated_files.append((mock_path, "Standalone FastAPI Mock Server"))

    # Summary Panel
    out_table = Table(title="📦 Generated Code & Artifacts", border_style="cyan")
    out_table.add_column("File", style="bold green")
    out_table.add_column("Description", style="white")

    for f_path, desc in generated_files:
        out_table.add_row(str(f_path.relative_to(Path.cwd()) if f_path.is_relative_to(Path.cwd()) else f_path), desc)

    console.print("\n", out_table, "\n")
    console.print(f"[bold cyan]🚀 Next Steps:[/bold cyan]")
    console.print(f"  1. Test your Python SDK:      [bold]python -c 'from {out_path.name}.client import ApiClient; api = ApiClient()'[/bold]")
    console.print(f"  2. Run the Local Mock Server: [bold]python {mock_path}[/bold]")
    console.print(f"  3. View OpenAPI in Swagger:   Import [bold]{json_path}[/bold] into Postman or editor.swagger.io\n")


@app.command()
def mock(
    har_file: str = typer.Argument(..., help="Path to .har HTTP archive capture file"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind the mock server"),
    target_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by specific domain (optional)")
):
    """
    🎭 Instantly spin up a local mock server using captured payload fixtures.
    """
    print_banner()
    har_path = Path(har_file)
    if not har_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: [yellow]{har_file}[/yellow]")
        raise typer.Exit(code=1)

    domains = {target_domain} if target_domain else None
    engine = ReverseEngineeringEngine(target_domains=domains)
    endpoints, auth, _ = engine.analyze_har(str(har_path))

    if not endpoints:
        console.print("[bold red]No valid API endpoints discovered to mock.[/bold red]")
        raise typer.Exit(code=1)

    mock_gen = MockServerGenerator()
    temp_dir = Path("./.ghostwire_tmp")
    mock_file = mock_gen.export_file(endpoints, auth, temp_dir)

    console.print(f"⚡ Booting mock server with [bold green]{len(endpoints)} endpoints[/bold green] on port [bold cyan]{port}[/bold cyan]...")
    console.print(f"📖 Swagger Docs: [bold underline]http://localhost:{port}/docs[/bold underline]")

    import uvicorn
    # Load app dynamically
    sys.path.insert(0, str(temp_dir.resolve()))
    import mock_server
    uvicorn.run(mock_server.app, host="0.0.0.0", port=port)


@app.command()
def version():
    """Display GhostWire version."""
    console.print(f"GhostWire [bold cyan]v{__version__}[/bold cyan]")


def main():
    app()


if __name__ == "__main__":
    main()
