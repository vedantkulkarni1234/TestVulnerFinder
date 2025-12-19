"""AURORA Conversational Interface - Natural language security scanning.

This provides an interactive, AI-powered chat interface for Aurora that eliminates
the need to remember complex CLI flags. Just describe what you want to scan in plain English.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt

from core.conversational import (
    ConversationContext,
    GeminiConversationalRouter,
    ScanIntent,
)
from core.engine import (
    DetectionModule,
    DistributedQueueConfig,
    Engine,
    EngineStats,
    Finding,
    ScanConfig,
    ScanResult,
    Target,
)
from core.http import WAFBypassConfig
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
from utils.helpers import expand_cidr, normalize_url, parse_ports

app = typer.Typer(
    add_completion=False,
    help="AURORA Conversational Assistant — AI-powered natural language security scanning.",
)

console = Console()

MODULE_MAP = {
    "spring4shell": Spring4ShellModule,
    "log4shell": Log4ShellModule,
    "text4shell": Text4ShellModule,
    "fastjson": FastjsonModule,
    "jackson": JacksonDatabindModule,
    "struts2": Struts2Module,
    "kibana": KibanaModule,
    "ghostscript": GhostscriptModule,
    "vm2": Vm2Module,
}

ALL_MODULES = list(MODULE_MAP.keys())


def get_welcome_message() -> str:
    """Return welcome message for the chat interface."""
    return """
# 🔮 AURORA Conversational Assistant

**Natural language security scanning powered by Gemini 2.5 Flash**

I can help you scan targets for critical RCE vulnerabilities like Log4Shell, Spring4Shell, and more.
Just tell me what you want to do in plain English!

## Example commands:
- *"Scan example.com for Log4Shell"*
- *"Check https://test.com for all vulnerabilities"*
- *"Analyze 192.168.1.0/24 with stealth mode enabled"*
- *"What vulnerabilities can you detect?"*
- *"Enable WAF bypass and scan myapp.example.com"*

## Pro tips:
- Mention specific CVEs or vulnerability names for targeted scanning
- Ask me to enable features like "stealth mode" or "WAF bypass"
- I remember context from our conversation!

**Type 'exit' or 'quit' to leave • Type 'help' for more information**
"""


async def execute_scan_intent(
    intent: ScanIntent,
    context: ConversationContext,
    renderer: AuroraRenderer,
) -> dict[str, object]:
    """Execute a scan based on parsed intent."""
    targets = intent.targets
    if not targets:
        return {"error": "No targets specified", "success": False}

    # Update context
    context.last_targets = targets
    if intent.modules:
        context.last_modules = intent.modules
    context.update_preferences(**intent.options)

    # Determine which modules to use
    selected_modules = intent.modules if intent.modules else ALL_MODULES
    if not selected_modules or "all" in [m.lower() for m in selected_modules]:
        selected_modules = ALL_MODULES

    # Normalize selected module names
    selected_modules = [m.lower().replace("-", "").replace("_", "") for m in selected_modules]
    
    # Build module instances
    module_instances: list[DetectionModule] = []
    oast_domain = "interact.sh" if intent.options.get("enable_oast") else None

    for name in selected_modules:
        # Normalize name
        normalized = name.lower()
        if normalized in MODULE_MAP:
            mod_class = MODULE_MAP[normalized]
            if normalized in ["log4shell", "text4shell"]:
                module_instances.append(mod_class(oast_domain=oast_domain))
            else:
                module_instances.append(mod_class())

    if not module_instances:
        return {"error": f"No valid modules found in: {selected_modules}", "success": False}

    # Expand targets
    expanded_targets: list[str] = []
    for target in targets:
        if intent.options.get("use_cidr") or "/" in target:
            # CIDR expansion
            ports_str = intent.options.get("ports", "80,443")
            port_list = parse_ports(ports_str)
            expanded_targets.extend(expand_cidr(target, scheme="https", ports=port_list))
        else:
            # Regular URL
            expanded_targets.append(normalize_url(target, default_scheme="https"))

    deduped = sorted(set(expanded_targets))

    # Build scan configuration
    waf_cfg = None
    if intent.options.get("enable_waf_bypass"):
        waf_cfg = WAFBypassConfig(enabled=True)

    cfg = ScanConfig(
        concurrency=intent.options.get("concurrency", 200),
        stealth=intent.options.get("enable_stealth", False),
        verbose=True,
        waf_bypass=waf_cfg,
        oast_listener_enabled=intent.options.get("enable_oast", False),
        oast_domain=oast_domain or "interact.sh",
    )

    # Show scan initiation
    console.print(
        Panel(
            f"[cyan]🎯 Scanning {len(deduped)} target(s) with {len(module_instances)} module(s)[/]\n"
            f"[dim]Modules: {', '.join(selected_modules)}[/]",
            title="[bold green]Scan Started[/]",
            border_style="green",
        )
    )

    # Execute scan
    async def progress_cb(stats: EngineStats, completed: int, total: int) -> None:
        renderer.update_progress(stats, completed, total)

    async def finding_cb(t: Target, f: Finding) -> None:
        renderer.emit_finding(t, f)

    engine = Engine(
        config=cfg,
        modules=module_instances,
        progress_cb=progress_cb,
        finding_cb=finding_cb,
    )

    try:
        results = await engine.scan([Target(url=u) for u in deduped])
    finally:
        await engine.aclose()

    renderer.final_summary(results)

    # Generate summary for AI context
    total_findings = sum(len(r.findings) for r in results)
    vuln_counts = {}
    for result in results:
        for finding in result.findings:
            vuln_counts[finding.vulnerability] = vuln_counts.get(finding.vulnerability, 0) + 1

    return {
        "success": True,
        "targets_scanned": len(results),
        "total_findings": total_findings,
        "vulnerabilities": vuln_counts,
        "modules_used": selected_modules,
    }


def handle_help_intent(intent: ScanIntent) -> dict[str, object]:
    """Handle help/capabilities request."""
    detail = intent.options.get("detail_level", "brief")

    if detail == "detailed":
        help_text = """
## AURORA Detection Modules

**Java RCE Vulnerabilities:**
- **Spring4Shell** (CVE-2022-22965): Spring Framework RCE via parameter binding
- **Log4Shell** (CVE-2021-44228): Log4j2 JNDI injection RCE
- **Fastjson**: Fastjson deserialization RCE chains
- **Jackson**: Jackson databind deserialization vulnerabilities
- **Struts2**: Apache Struts2 OGNL injection RCE

**Node.js RCE Vulnerabilities:**
- **VM2**: VM2 sandbox escape vulnerabilities

**Other:**
- **Text4Shell** (CVE-2022-42889): Apache Commons Text variable interpolation RCE
- **Kibana**: Kibana prototype pollution RCE
- **Ghostscript**: Ghostscript sandbox bypass RCE

## Advanced Features

- **Specter WAF Bypass**: Evade web application firewalls with header mutation and request smuggling
- **Sonar OAST Mode**: Out-of-band callback detection for blind vulnerabilities
- **Hive Mind**: Distributed scanning across multiple workers
- **Stealth Mode**: Randomized delays and jitter to avoid detection
"""
    else:
        help_text = """
## Quick Reference

**Available Modules**: spring4shell, log4shell, text4shell, fastjson, jackson, struts2, kibana, ghostscript, vm2

**Features**: WAF bypass, OAST callbacks, stealth mode, distributed scanning

**Examples**:
- "Scan example.com for all vulnerabilities"
- "Check 192.168.1.0/24 for Log4Shell with OAST enabled"
- "Enable stealth mode and scan myapp.com"
"""

    console.print(Markdown(help_text))
    return {"success": True, "action": "help"}


def handle_explain_intent(intent: ScanIntent) -> dict[str, object]:
    """Handle vulnerability explanation request."""
    vuln_name = intent.options.get("vulnerability_name", "").lower()

    explanations = {
        "log4shell": """
## Log4Shell (CVE-2021-44228)

**Severity**: Critical (CVSS 10.0)

Log4Shell is a remote code execution vulnerability in Apache Log4j2, a widely-used Java logging library.
Attackers can trigger JNDI lookups via specially crafted input, leading to arbitrary code execution.

**Impact**: Complete system compromise, data exfiltration, ransomware deployment

**Detection**: Aurora tests for JNDI injection vectors and uses OAST callbacks to confirm exploitation
""",
        "spring4shell": """
## Spring4Shell (CVE-2022-22965)

**Severity**: Critical (CVSS 9.8)

Spring4Shell is an RCE vulnerability in Spring Framework's parameter binding mechanism.
Attackers can access class properties and modify Tomcat logging configuration to inject web shells.

**Impact**: Remote code execution on vulnerable Spring applications

**Detection**: Aurora tests specific parameter binding patterns and web shell injection techniques
""",
        "text4shell": """
## Text4Shell (CVE-2022-42889)

**Severity**: Critical (CVSS 9.8)

Text4Shell is a variable interpolation vulnerability in Apache Commons Text that enables RCE
through DNS, URL, or script lookups.

**Impact**: Remote code execution via arbitrary script execution

**Detection**: Aurora uses OAST callbacks to detect blind exploitation attempts
""",
    }

    explanation = explanations.get(vuln_name)
    if explanation:
        console.print(Markdown(explanation))
        return {"success": True, "vulnerability": vuln_name}
    else:
        console.print(
            f"[yellow]I don't have detailed information about '{vuln_name}'. "
            f"Try asking about: log4shell, spring4shell, text4shell[/]"
        )
        return {"success": False, "vulnerability": vuln_name}


@app.command()
def chat(
    api_key: Annotated[
        str | None,
        typer.Option(
            None,
            "--api-key",
            envvar="GOOGLE_API_KEY",
            help="Google AI API key for Gemini (or set GOOGLE_API_KEY env var)",
        ),
    ] = None,
) -> None:
    """Start an interactive conversational session with AURORA Assistant."""
    # Check for API key
    if not api_key:
        console.print(
            "[bold red]Error:[/] Google AI API key required.\n"
            "Set GOOGLE_API_KEY environment variable or use --api-key flag.\n\n"
            "Get your key at: https://aistudio.google.com/app/apikey"
        )
        raise typer.Exit(1)

    # Initialize
    try:
        router = GeminiConversationalRouter(api_key=api_key)
    except Exception as e:
        console.print(f"[bold red]Failed to initialize Gemini:[/] {e}")
        raise typer.Exit(1)

    context = ConversationContext()
    renderer = AuroraRenderer(config=RenderConfig(verbose=True))

    # Welcome
    console.print(Markdown(get_welcome_message()))

    # Main conversation loop
    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]You[/]")

            if user_input.lower() in ["exit", "quit", "q"]:
                console.print("[bold green]Goodbye![/] Stay secure! 🔒")
                break

            if not user_input.strip():
                continue

            # Parse intent
            try:
                intent = router.parse_intent(user_input, context)
            except Exception as e:
                console.print(f"[bold red]Error parsing request:[/] {e}")
                continue

            context.add_message("user", user_input)

            # Execute action
            result_data = None
            if intent.action == "scan":
                result_data = asyncio.run(execute_scan_intent(intent, context, renderer))
            elif intent.action == "help":
                result_data = handle_help_intent(intent)
            elif intent.action == "explain":
                result_data = handle_explain_intent(intent)
            elif intent.action == "status":
                console.print("[yellow]Scan status tracking coming soon![/]")
                result_data = {"success": True, "message": "Status feature in development"}
            elif intent.action == "configure":
                context.update_preferences(**intent.options)
                console.print("[green]✓[/] Preferences updated!")
                result_data = {"success": True, "preferences": intent.options}
            elif intent.action == "respond":
                # Direct conversational response
                response_text = intent.options.get("response", "I'm not sure how to help with that.")
                console.print(Panel(response_text, title="[bold cyan]Aurora Assistant[/]", border_style="cyan"))
                context.add_message("assistant", response_text)
                continue

            # Generate conversational response
            try:
                response = router.generate_response(user_input, context, result_data)
                console.print(Panel(response, title="[bold cyan]Aurora Assistant[/]", border_style="cyan"))
                context.add_message("assistant", response)
            except Exception as e:
                console.print(f"[dim]Response generation failed: {e}[/]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/]")
            continue
        except Exception as e:
            console.print(f"[bold red]Error:[/] {e}")
            continue


@app.command()
def query(
    message: Annotated[
        str,
        typer.Argument(help="Your natural language request (e.g., 'scan example.com for log4shell')"),
    ],
    api_key: Annotated[
        str | None,
        typer.Option(
            None,
            "--api-key",
            envvar="GOOGLE_API_KEY",
            help="Google AI API key for Gemini",
        ),
    ] = None,
    execute: Annotated[
        bool,
        typer.Option(
            True,
            "--execute/--dry-run",
            help="Execute the scan or just show what would be done",
        ),
    ] = True,
) -> None:
    """Execute a single natural language command (non-interactive mode).

    This is useful for scripting or one-off scans without entering the chat interface.

    Examples:
        aurora-chat query "scan example.com for all vulnerabilities"
        aurora-chat query "check 192.168.1.0/24 for log4shell with stealth mode"
    """
    if not api_key:
        console.print(
            "[bold red]Error:[/] Google AI API key required.\n"
            "Set GOOGLE_API_KEY environment variable or use --api-key flag."
        )
        raise typer.Exit(1)

    try:
        router = GeminiConversationalRouter(api_key=api_key)
        context = ConversationContext()
        intent = router.parse_intent(message, context)

        if not execute:
            console.print(Panel(
                f"[bold]Action:[/] {intent.action}\n"
                f"[bold]Targets:[/] {', '.join(intent.targets) if intent.targets else 'None'}\n"
                f"[bold]Modules:[/] {', '.join(intent.modules) if intent.modules else 'All'}\n"
                f"[bold]Options:[/] {intent.options}",
                title="[yellow]Dry Run - Would Execute[/]",
                border_style="yellow",
            ))
            return

        renderer = AuroraRenderer(config=RenderConfig(verbose=True))

        if intent.action == "scan":
            result_data = asyncio.run(execute_scan_intent(intent, context, renderer))
            if result_data.get("success"):
                console.print("[bold green]✓ Scan completed successfully[/]")
            else:
                console.print(f"[bold red]✗ Scan failed:[/] {result_data.get('error')}")
        elif intent.action == "help":
            handle_help_intent(intent)
        elif intent.action == "explain":
            handle_explain_intent(intent)
        else:
            console.print(f"[yellow]Action '{intent.action}' not supported in query mode[/]")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
