from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from core.engine import DetectionModule, Engine, EngineStats, Finding, ScanConfig, ScanResult, Target
from modules.fastjson import FastjsonModule
from modules.ghostscript import GhostscriptModule
from modules.jackson import JacksonDatabindModule
from modules.kibana import KibanaModule
from modules.log4shell import Log4ShellModule
from modules.spring4shell import Spring4ShellModule
from modules.struts2 import Struts2Module
from modules.text4shell import Text4ShellModule
from modules.vm2 import Vm2Module
from ui.renderer import AuroraRenderer, RenderConfig
from utils.helpers import expand_cidr, normalize_url, parse_ports, read_lines

app = typer.Typer(
    add_completion=False,
    help="AURORA — high-confidence reconnaissance for historic Java/Node RCE chains.",
)


_MODULE_NAMES = [
    "spring4shell",
    "log4shell",
    "text4shell",
    "fastjson",
    "jackson",
    "struts2",
    "kibana",
    "ghostscript",
    "vm2",
]
_MODULE_SET = set(_MODULE_NAMES)


def _parse_modules(raw: str | None) -> list[str]:
    if not raw or raw.strip().lower() in {"all", "*"}:
        return list(_MODULE_NAMES)

    selected = [m.strip().lower() for m in raw.split(",") if m.strip()]
    unknown = [m for m in selected if m not in _MODULE_SET]
    if unknown:
        raise typer.BadParameter(f"unknown modules: {', '.join(unknown)}")
    return selected


@app.command()
def scan(
    target: Annotated[
        str | None,
        typer.Argument(
            None,
            help="Target URL (e.g., https://example.com) or hostname. Use -l/--list for many targets.",
        ),
    ] = None,
    list_file: Annotated[
        Path | None,
        typer.Option(
            None,
            "-l",
            "--list",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="File containing targets (one per line).",
        ),
    ] = None,
    cidr: Annotated[
        str | None,
        typer.Option(None, "--cidr", help="CIDR target set (e.g., 10.0.0.0/24)."),
    ] = None,
    ports: Annotated[
        str,
        typer.Option("80,443", "--ports", help="Ports for --cidr mode (e.g., 80,443,8080-8090)."),
    ] = "80,443",
    scheme: Annotated[
        str,
        typer.Option("https", "--scheme", help="URL scheme for host/CIDR targets (http or https)."),
    ] = "https",
    modules: Annotated[
        str | None,
        typer.Option(
            None,
            "--modules",
            help="Comma-separated module list. Default: all.",
        ),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option(200, "--concurrency", min=1, max=10_000, help="Concurrent target workers."),
    ] = 200,
    rate_limit: Annotated[
        float | None,
        typer.Option(None, "--rate-limit", help="Global HTTP request rate limit (req/s)."),
    ] = None,
    stealth: Annotated[
        bool,
        typer.Option(False, "--stealth", help="Stealth mode: randomized delays and jitter."),
    ] = False,
    user_agent: Annotated[
        str | None,
        typer.Option(None, "--user-agent", help="Override User-Agent header."),
    ] = None,
    proxy: Annotated[
        str | None,
        typer.Option(None, "--proxy", help="HTTP(S) proxy URL (e.g., http://127.0.0.1:8080)."),
    ] = None,
    insecure: Annotated[
        bool,
        typer.Option(False, "--insecure", help="Disable TLS verification."),
    ] = False,
    client_cert: Annotated[
        Path | None,
        typer.Option(None, "--client-cert", exists=True, readable=True, help="Client TLS cert (PEM)."),
    ] = None,
    client_key: Annotated[
        Path | None,
        typer.Option(None, "--client-key", exists=True, readable=True, help="Client TLS private key (PEM)."),
    ] = None,
    oast_domain: Annotated[
        str | None,
        typer.Option(
            None,
            "--oast-domain",
            help="Optional OAST domain for Log4Shell/Text4Shell triggers (explicit opt-in).",
        ),
    ] = None,
    output: Annotated[
        str,
        typer.Option(
            "rich",
            "--output",
            help="Report format: rich (default), json, markdown, html.",
        ),
    ] = "rich",
    output_file: Annotated[
        Path | None,
        typer.Option(None, "--output-file", help="Write report to file (default based on format)."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(False, "--verbose", help="Show sub-threshold findings and module errors."),
    ] = False,
) -> None:
    selected_modules = _parse_modules(modules)

    raw_targets: list[str] = []
    if target:
        raw_targets.append(target)
    if list_file:
        raw_targets.extend(read_lines(list_file))
    if cidr:
        port_list = parse_ports(ports)
        raw_targets.extend(expand_cidr(cidr, scheme=scheme, ports=port_list))

    if not raw_targets:
        raise typer.BadParameter("no targets provided")

    urls = [normalize_url(t, default_scheme=scheme) for t in raw_targets]
    deduped = sorted(set(urls))

    module_instances: list[DetectionModule] = []
    for name in selected_modules:
        match name:
            case "spring4shell":
                module_instances.append(Spring4ShellModule())
            case "log4shell":
                module_instances.append(Log4ShellModule(oast_domain=oast_domain))
            case "text4shell":
                module_instances.append(Text4ShellModule(oast_domain=oast_domain))
            case "fastjson":
                module_instances.append(FastjsonModule())
            case "jackson":
                module_instances.append(JacksonDatabindModule())
            case "struts2":
                module_instances.append(Struts2Module())
            case "kibana":
                module_instances.append(KibanaModule())
            case "ghostscript":
                module_instances.append(GhostscriptModule())
            case "vm2":
                module_instances.append(Vm2Module())
            case _:
                raise typer.BadParameter(f"unknown module: {name}")

    renderer = AuroraRenderer(config=RenderConfig(verbose=verbose))
    renderer.startup(total_targets=len(deduped), modules=selected_modules, stealth=stealth)

    async def _run() -> None:
        cfg = ScanConfig(
            concurrency=concurrency,
            rate_limit_rps=rate_limit,
            stealth=stealth,
            proxy=proxy,
            verify_tls=not insecure,
            user_agent=user_agent,
            client_cert=str(client_cert) if client_cert else None,
            client_key=str(client_key) if client_key else None,
            verbose=verbose,
        )

        async def progress_cb(stats: EngineStats, completed: int, total: int) -> None:
            renderer.update_progress(stats, completed, total)

        async def finding_cb(t: Target, f: Finding) -> None:
            renderer.emit_finding(t, f)

        engine = Engine(config=cfg, modules=module_instances, progress_cb=progress_cb, finding_cb=finding_cb)
        try:
            results = await engine.scan([Target(url=u) for u in deduped])
        finally:
            await engine.aclose()

        renderer.final_summary(results)

        fmt = output.lower()
        if fmt == "rich":
            # Only export if operator requests a file.
            if output_file:
                _export(renderer, results, fmt="json", path=output_file)
            return

        path = output_file
        if path is None:
            path = {
                "json": Path("aurora-report.json"),
                "markdown": Path("aurora-report.md"),
                "html": Path("aurora-report.html"),
            }.get(fmt)

        if path is None:
            raise typer.BadParameter(f"unknown output format: {output}")

        _export(renderer, results, fmt=fmt, path=path)
        renderer.console.print(f"[aurora.good]{path}[/] written")

    asyncio.run(_run())


def _export(renderer: AuroraRenderer, results: list[ScanResult], *, fmt: str, path: Path) -> None:
    if fmt == "json":
        renderer.export_json(results, path=path)
    elif fmt == "markdown":
        renderer.export_markdown(results, path=path)
    elif fmt == "html":
        renderer.export_html(results, path=path)
    else:
        raise typer.BadParameter(f"unsupported output format: {fmt}")


if __name__ == "__main__":
    app()
