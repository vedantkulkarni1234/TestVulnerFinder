from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between


class Vm2Module:
    name = "vm2"
    vulnerability = "Node.js vm2 Sandbox Escape"
    cve = "CVE-2023-37466"

    _EXACT_VERSION_RE = re.compile(r"^(?P<ver>\d+\.\d+\.\d+(?:\.\d+)?)$")

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        pkg = await ctx.http.request("GET", base + "/package.json", evidence=ctx.evidence)
        if pkg.status_code != 200:
            return []

        data = pkg.json()
        if not isinstance(data, dict):
            return []

        dep = None
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            val = data.get(section)
            if isinstance(val, dict) and "vm2" in val and isinstance(val["vm2"], str):
                dep = val["vm2"]
                break

        if dep is None:
            return []

        m = self._EXACT_VERSION_RE.match(dep.strip())
        if not m:
            # Avoid false positives: ranges ("^3.9.18") are not definitive.
            return []

        ver = m.group("ver")
        sem = parse_semver(ver)
        if sem is None:
            return []

        # Conservative: treat versions < 3.9.19 as affected.
        affected = semver_inclusive_between(sem, low=(0, 0, 0), high=(3, 9, 18))
        if not affected:
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Exposed package.json pins vm2 to {ver}",
            provenance=Provenance(url=pkg.url, method=pkg.method, status_code=pkg.status_code),
            details={"vm2_version": ver},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        confidence = 78
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="vm2 version pinned within conservative CVE-2023-37466 affected window",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"A publicly accessible package.json pins vm2 to {ver}. "
                    "Versions below 3.9.19 are conservatively treated as affected by CVE-2023-37466."
                ),
                evidence_ids=evidence_ids,
            )
        ]
