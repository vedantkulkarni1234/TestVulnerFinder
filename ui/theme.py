from __future__ import annotations

from dataclasses import dataclass

from rich.style import Style
from rich.theme import Theme


CYAN = "#00f5ff"
MAGENTA = "#ff00ff"
GREEN = "#39ff14"
RED = "#ff1744"
YELLOW = "#ffe600"
MUTED = "#6b7280"
BG = "#05060a"


AURORA_THEME = Theme(
    {
        "aurora.title": Style(color=CYAN, bold=True),
        "aurora.subtle": Style(color=MUTED),
        "aurora.good": Style(color=GREEN, bold=True),
        "aurora.warn": Style(color=YELLOW, bold=True),
        "aurora.bad": Style(color=RED, bold=True),
        "aurora.magenta": Style(color=MAGENTA, bold=True),
        "aurora.cyan": Style(color=CYAN, bold=True),
        "aurora.dim": Style(color=MUTED, dim=True),
    }
)


@dataclass(frozen=True, slots=True)
class Icons:
    target: str = "◉"
    ok: str = "◆"
    warn: str = "▲"
    bad: str = "■"
    module: str = "⌁"
    evidence: str = "▣"


ICONS = Icons()
