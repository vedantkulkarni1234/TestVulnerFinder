from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from core.engine import EngineStats, Finding, ScanResult, Target
from core.scoring import bar
from ui.banner import banner_large
from ui.theme import AURORA_THEME, ICONS


@dataclass(slots=True)
class RenderConfig:
    verbose: bool = False


class AuroraRenderer:
    def __init__(self, *, config: RenderConfig) -> None:
        self.console = Console(theme=AURORA_THEME)
        self._cfg = config

        self._progress_started = False
        self._progress = Progress(
            TextColumn("[aurora.cyan]AURORA[/]"),
            TextColumn("•"),
            TextColumn("[aurora.subtle]{task.description}[/]"),
            BarColumn(bar_width=34, complete_style="aurora.magenta", finished_style="aurora.good"),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TextColumn("[aurora.subtle]{task.fields[rps]} req/s[/]"),
            console=self.console,
            refresh_per_second=12,
        )
        self._task_id: TaskID | None = None

        self._recent_findings: list[tuple[Target, Finding]] = []

    def startup(self, *, total_targets: int, modules: list[str], stealth: bool) -> None:
        self.console.print(Text(banner_large(), style="aurora.title"))

        cfg_table = Table.grid(padding=(0, 2))
        cfg_table.add_column(justify="right", style="aurora.subtle")
        cfg_table.add_column(style="aurora.cyan")
        cfg_table.add_row("targets", str(total_targets))
        cfg_table.add_row("modules", ", ".join(modules))
        cfg_table.add_row("stealth", "on" if stealth else "off")

        self.console.print(
            Panel(
                cfg_table,
                title=f"{ICONS.target} scan configuration",
                border_style="aurora.magenta",
                box=box.HEAVY,
            )
        )

        self._task_id = self._progress.add_task("scanning", total=total_targets, rps="0.0")
        if not self._progress_started:
            self._progress.start()
            self._progress_started = True

    def update_progress(self, stats: EngineStats, completed: int, total: int) -> None:
        if self._task_id is None:
            return
        self._progress.update(
            self._task_id,
            completed=completed,
            total=total,
            rps=f"{stats.rps():.1f}",
        )

    def emit_finding(self, target: Target, finding: Finding) -> None:
        self._recent_findings.append((target, finding))
        self._recent_findings = self._recent_findings[-5:]

        badge_style = {
            "CONFIRMED": "aurora.bad",
            "HIGHLY_LIKELY": "aurora.warn",
            "POSSIBLE": "aurora.subtle",
        }[finding.tier.value]

        title = Text.assemble(
            (finding.tier.value, badge_style),
            ("  ", ""),
            (finding.vulnerability, "aurora.cyan"),
            ("  ", ""),
            (bar(finding.confidence), "aurora.magenta"),
        )

        body = Table.grid(padding=(0, 1))
        body.add_column(style="aurora.subtle", justify="right")
        body.add_column(style="aurora.title")
        body.add_row("target", target.url)
        body.add_row("module", finding.module)
        if finding.cve:
            body.add_row("cve", finding.cve)
        body.add_row("summary", finding.summary)

        self.console.print(
            Panel(
                body,
                title=title,
                border_style="aurora.magenta",
                box=box.HEAVY,
            )
        )

    def final_summary(self, results: Iterable[ScanResult]) -> None:
        if self._progress_started:
            self._progress.stop()
            self._progress_started = False

        results = list(results)
        by_tier: dict[str, int] = {"CONFIRMED": 0, "HIGHLY_LIKELY": 0, "POSSIBLE": 0}
        total_findings = 0
        for r in results:
            for f in r.findings:
                by_tier[f.tier.value] += 1
                total_findings += 1

        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("tier", style="aurora.subtle")
        table.add_column("count", style="aurora.cyan", justify="right")
        table.add_row("CONFIRMED", str(by_tier["CONFIRMED"]))
        table.add_row("HIGHLY LIKELY", str(by_tier["HIGHLY_LIKELY"]))
        table.add_row("POSSIBLE", str(by_tier["POSSIBLE"]))
        table.add_row("TOTAL", str(total_findings), style="aurora.title")

        self.console.print(
            Panel(
                table,
                title=f"{ICONS.ok} summary",
                border_style="aurora.cyan",
                box=box.HEAVY,
            )
        )

    def export_json(self, results: Iterable[ScanResult], *, path: Path) -> None:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results": [r.as_dict() for r in results],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def export_markdown(self, results: Iterable[ScanResult], *, path: Path) -> None:
        lines: list[str] = []
        lines.append(f"# AURORA Recon Report\n")
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")

        for r in results:
            if not r.findings:
                continue
            lines.append(f"## {r.target.url}\n")
            for f in r.findings:
                cve = f" ({f.cve})" if f.cve else ""
                lines.append(f"- **{f.tier.value}** {f.vulnerability}{cve} — {f.confidence}%")
                lines.append(f"  - {f.summary}")
            lines.append("")

        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    def export_html(self, results: Iterable[ScanResult], *, path: Path) -> None:
        # Minimal HTML export designed for offline sharing.
        body: list[str] = []
        body.append("<html><head><meta charset='utf-8'><title>AURORA Report</title></head><body>")
        body.append(f"<h1>AURORA Recon Report</h1><p>Generated: {datetime.now(timezone.utc).isoformat()}</p>")
        for r in results:
            if not r.findings:
                continue
            body.append(f"<h2>{r.target.url}</h2><ul>")
            for f in r.findings:
                cve = f" ({f.cve})" if f.cve else ""
                body.append(
                    f"<li><strong>{f.tier.value}</strong> {f.vulnerability}{cve} "
                    f"— {f.confidence}%<br/><code>{f.summary}</code></li>"
                )
            body.append("</ul>")
        body.append("</body></html>")
        path.write_text("\n".join(body), encoding="utf-8")

    def dashboard_snapshot(self) -> Panel:
        """Optional dashboard for future Live UI.

        Kept for extensibility; not currently used as the main UI.
        """

        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("target", style="aurora.subtle")
        table.add_column("finding", style="aurora.title")
        table.add_column("tier", style="aurora.magenta")
        table.add_column("confidence", style="aurora.cyan")

        for t, f in reversed(self._recent_findings):
            table.add_row(t.url, f.vulnerability, f.tier.value, bar(f.confidence))

        return Panel(
            Group(Text("recent findings", style="aurora.subtle"), table),
            border_style="aurora.magenta",
            box=box.HEAVY,
        )
