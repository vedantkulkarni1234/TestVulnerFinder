from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between


class Struts2Module:
    name = "struts2"
    vulnerability = "Apache Struts 2 Multipart RCE"
    cve = "CVE-2017-5638"

    _JAR_RE = re.compile(r"struts2?-core-(?P<ver>\d+\.\d+\.\d+(?:\.\d+)?)")

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        if "struts" not in ctx.fingerprint.frameworks:
            # Still allow detection if jar evidence exists.
            pass

        ver = self._detect_version(ctx)
        if ver is None:
            return []

        sem = parse_semver(ver)
        if sem is None:
            return []

        # Affected: 2.3.5–2.3.31 and 2.5.0–2.5.10.
        affected = semver_inclusive_between(sem, low=(2, 3, 5), high=(2, 3, 31)) or semver_inclusive_between(
            sem, low=(2, 5, 0), high=(2, 5, 10)
        )
        if not affected:
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Apache Struts 2 core version confirmed as {ver}",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"struts2_version": ver},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        # Optional high-signal probe.
        webconsole = await ctx.http.request("GET", base + "/struts/webconsole.html", evidence=ctx.evidence)
        if webconsole.status_code == 200 and "struts" in webconsole.body_sample.lower():
            ev2 = EvidenceItem(
                kind="fingerprint",
                summary="Struts WebConsole appears accessible",
                provenance=Provenance(
                    url=webconsole.url,
                    method=webconsole.method,
                    status_code=webconsole.status_code,
                ),
            )
            ctx.evidence.add(ev2)
            evidence_ids.append(ev2.stable_id())

        confidence = 82
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Struts 2 version within CVE-2017-5638 affected ranges",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"Apache Struts 2 {ver} detected within CVE-2017-5638 affected ranges. "
                    "This is a recon-only assessment; no OGNL payloads were sent."
                ),
                evidence_ids=evidence_ids,
            )
        ]

    def _detect_version(self, ctx: TargetContext) -> str | None:
        for obs in ctx.observations.values():
            m = self._JAR_RE.search(obs.body_sample)
            if m:
                return m.group("ver")

        # Common error banner.
        for obs in ctx.observations.values():
            s = obs.body_sample
            if "struts" in s.lower() and "version" in s.lower():
                # Best-effort: not extracted.
                continue

        return None
