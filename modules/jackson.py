from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between


class JacksonDatabindModule:
    name = "jackson"
    vulnerability = "Jackson Databind Polymorphic RCE Family"
    cve = "CVE-2019-12384"

    _JAR_RE = re.compile(r"jackson-databind-(?P<ver>\d+\.\d+\.\d+)")

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        ver = self._detect_version(ctx)
        if ver is None:
            return []

        sem = parse_semver(ver)
        if sem is None:
            return []

        # Conservative historic window: early 2.x lines had repeated gadget-based RCE chains.
        # We only report when we also see live runtime stack identifiers.
        in_historic_range = semver_inclusive_between(sem, low=(2, 0, 0), high=(2, 9, 9))
        if not in_historic_range:
            return []

        if not self._detect_runtime_usage(ctx):
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Jackson Databind version confirmed as {ver}",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"jackson_databind_version": ver},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        ev2 = EvidenceItem(
            kind="fingerprint",
            summary="Jackson databind runtime classes observed in response content",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
        )
        ctx.evidence.add(ev2)
        evidence_ids.append(ev2.stable_id())

        confidence = 78
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Jackson databind stack present with historically vulnerable version",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"Jackson-databind {ver} detected and actively used (stack identifiers observed). "
                    "Multiple historic gadget-based RCE chains exist in this family (incl. CVE-2019-12384). "
                    "No deserialization triggers were tested."
                ),
                evidence_ids=evidence_ids,
            )
        ]

    def _detect_version(self, ctx: TargetContext) -> str | None:
        for obs in ctx.observations.values():
            m = self._JAR_RE.search(obs.body_sample)
            if m:
                return m.group("ver")
        return None

    def _detect_runtime_usage(self, ctx: TargetContext) -> bool:
        needles = (
            "com.fasterxml.jackson.databind",
            "ObjectMapper",
            "jackson.databind",
        )
        for obs in ctx.observations.values():
            s = obs.body_sample
            if any(n in s for n in needles):
                return True
        return False
