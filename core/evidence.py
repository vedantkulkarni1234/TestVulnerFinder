from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a signal came from.

    We store enough detail to let an operator reproduce the observation.
    """

    url: str
    method: str
    status_code: int | None
    observed_at: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """Atomic, attributable evidence supporting a signal."""

    kind: str
    summary: str
    provenance: Provenance
    details: Mapping[str, Any] = field(default_factory=dict)

    def stable_id(self) -> str:
        payload = f"{self.kind}|{self.summary}|{self.provenance.url}|{self.provenance.method}|{self.provenance.status_code}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass(slots=True)
class EvidenceStore:
    """Evidence container for a single target scan."""

    items: list[EvidenceItem] = field(default_factory=list)

    def add(self, item: EvidenceItem) -> None:
        self.items.append(item)

    def extend(self, items: list[EvidenceItem]) -> None:
        self.items.extend(items)

    def as_dict(self) -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": it.stable_id(),
                    "kind": it.kind,
                    "summary": it.summary,
                    "provenance": {
                        "url": it.provenance.url,
                        "method": it.provenance.method,
                        "status_code": it.provenance.status_code,
                        "observed_at": it.provenance.observed_at,
                    },
                    "details": dict(it.details),
                }
                for it in self.items
            ]
        }
