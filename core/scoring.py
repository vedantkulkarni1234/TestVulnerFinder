from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FindingTier(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGHLY_LIKELY = "HIGHLY_LIKELY"
    POSSIBLE = "POSSIBLE"


def tier_for_confidence(confidence: int) -> FindingTier | None:
    if confidence >= 92:
        return FindingTier.CONFIRMED
    if confidence >= 78:
        return FindingTier.HIGHLY_LIKELY
    if confidence >= 55:
        return FindingTier.POSSIBLE
    return None


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    confidence: int
    rationale: list[str]


def clamp_confidence(value: int) -> int:
    return max(0, min(100, value))


def bar(confidence: int, width: int = 12) -> str:
    """Textual progress bar used for logs and JSON."""

    confidence = clamp_confidence(confidence)
    filled = round((confidence / 100) * width)
    return f"{'█' * filled}{'░' * (width - filled)} {confidence:3d}%"
