from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between


class FastjsonModule:
    name = "fastjson"
    vulnerability = "Fastjson Deserialization RCE Family"
    cve = "CVE-2017-18349"

    _FASTJSON_JAR_RE = re.compile(r"fastjson-(?P<ver>\d+\.\d+\.\d+)")

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        ver = self._detect_fastjson_version(ctx)
        if ver is None:
            return []

        sem = parse_semver(ver)
        if sem is None:
            return []

        # Conservative historic range: many autotype RCE chains existed up to ~1.2.68.
        # We only report if we also observe runtime usage (stack trace / parser classes).
        in_historic_range = semver_inclusive_between(sem, low=(1, 2, 0), high=(1, 2, 68))
        if not in_historic_range:
            return []

        if not self._detect_runtime_usage(ctx):
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Fastjson version confirmed as {ver}",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"fastjson_version": ver},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        ev2 = EvidenceItem(
            kind="fingerprint",
            summary="Fastjson parser/runtime classes observed in response content",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
        )
        ctx.evidence.add(ev2)
        evidence_ids.append(ev2.stable_id())

        confidence = 80
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Fastjson deserialization stack present with historically vulnerable version",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"Fastjson {ver} detected and actively used (parser stack identifiers observed). "
                    "This version family has had multiple autotype deserialization RCE CVEs (incl. CVE-2017-18349). "
                    "No exploit payloads were sent."
                ),
                evidence_ids=evidence_ids,
            )
        ]

    def _detect_fastjson_version(self, ctx: TargetContext) -> str | None:
        for obs in ctx.observations.values():
            m = self._FASTJSON_JAR_RE.search(obs.body_sample)
            if m:
                return m.group("ver")
        return None

    def _detect_runtime_usage(self, ctx: TargetContext) -> bool:
        needles = (
            "com.alibaba.fastjson",
            "DefaultJSONParser",
            "JSON.parseObject",
        )
        for obs in ctx.observations.values():
            s = obs.body_sample
            if any(n in s for n in needles):
                return True
        return False
