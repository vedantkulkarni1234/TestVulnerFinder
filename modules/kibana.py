from __future__ import annotations

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between


class KibanaModule:
    name = "kibana"
    vulnerability = "Kibana Prototype Pollution RCE"
    cve = "CVE-2019-7609"

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        obs = ctx.observations.get("/api/status")
        if obs is None or obs.status_code != 200:
            return []

        data = obs.json()
        if not isinstance(data, dict):
            return []

        version = self._deep_get(data, ["version", "number"])
        if not isinstance(version, str):
            return []

        sem = parse_semver(version)
        if sem is None:
            return []

        # CVE-2019-7609 affected historical ranges include 5.6.0–5.6.14 and 6.0.0–6.6.0.
        affected = semver_inclusive_between(sem, low=(5, 6, 0), high=(5, 6, 14)) or semver_inclusive_between(
            sem, low=(6, 0, 0), high=(6, 6, 0)
        )
        if not affected:
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Kibana version confirmed as {version}",
            provenance=Provenance(url=obs.url, method=obs.method, status_code=obs.status_code),
            details={"kibana_version": version},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        confidence = 88
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Kibana version within CVE-2019-7609 affected ranges",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"Kibana {version} detected via /api/status and falls within CVE-2019-7609 affected ranges. "
                    "No prototype-pollution payloads were sent."
                ),
                evidence_ids=evidence_ids,
            )
        ]

    def _deep_get(self, obj: object, path: list[str]) -> object | None:
        cur: object = obj
        for key in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
        return cur
