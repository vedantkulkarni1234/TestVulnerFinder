from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between
from utils.oast import build_fqdn, generate_token, text4shell_payload


class Text4ShellModule:
    name = "text4shell"
    vulnerability = "Text4Shell"
    cve = "CVE-2022-42889"

    _COMMONS_TEXT_RE = re.compile(r"commons-text-(?P<ver>\d+\.\d+(?:\.\d+)?)")

    def __init__(self, *, oast_domain: str | None) -> None:
        self._oast_domain = oast_domain

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        ver = self._detect_commons_text_version(ctx)
        if ver is None:
            if not self._detect_commons_text_presence(ctx):
                return []

            ev = EvidenceItem(
                kind="version",
                summary="Apache Commons Text observed, but version not confirmed",
                provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            )
            ctx.evidence.add(ev)
            evidence_ids.append(ev.stable_id())

            confidence = 60
            tier = tier_for_confidence(confidence)
            if tier is None:
                return []

            return [
                Finding(
                    module=self.name,
                    vulnerability=self.vulnerability,
                    cve=self.cve,
                    title="Commons Text present (version not confirmed)",
                    confidence=confidence,
                    tier=tier,
                    summary=(
                        "Apache Commons Text usage identifiers observed, but version could not be confirmed. "
                        "CVE-2022-42889 affects 1.5–1.9."
                    ),
                    evidence_ids=evidence_ids,
                )
            ]

        sem = parse_semver(self._normalize(ver))
        if sem is None:
            return []

        vulnerable = semver_inclusive_between(sem, low=(1, 5, 0), high=(1, 9, 0))
        if not vulnerable:
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Apache Commons Text version confirmed as {ver}",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"commons_text_version": ver},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        oast_note: str | None = None
        if self._oast_domain:
            token = generate_token(nbytes=8)
            fqdn = build_fqdn(token, self._oast_domain)
            payload = text4shell_payload(fqdn)

            # Recon-only trigger: very few apps interpolate headers with Commons Text; this is opt-in.
            await ctx.http.request(
                "GET",
                base + "/",
                evidence=ctx.evidence,
                headers={"X-Aurora-Probe": payload},
            )

            ev2 = EvidenceItem(
                kind="behavior",
                summary="Text4Shell OAST trigger header set",
                provenance=Provenance(url=base + "/", method="GET", status_code=None),
                details={"oast_fqdn": fqdn, "header_payload": payload},
            )
            ctx.evidence.add(ev2)
            evidence_ids.append(ev2.stable_id())

            oast_note = f"OAST trigger sent (monitor DNS/HTTP callbacks for: {fqdn})."

        confidence = 82
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        summary = (
            f"Apache Commons Text {ver} detected within CVE-2022-42889 vulnerable range (1.5–1.9). "
            "No interpolation trigger points were discovered; no exploit payloads were sent."
        )
        if oast_note:
            summary += f" {oast_note}"

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Commons Text vulnerable version detected",
                confidence=confidence,
                tier=tier,
                summary=summary,
                evidence_ids=evidence_ids,
            )
        ]

    def _normalize(self, ver: str) -> str:
        parts = ver.split(".")
        if len(parts) == 2:
            return f"{ver}.0"
        return ver

    def _detect_commons_text_presence(self, ctx: TargetContext) -> bool:
        for obs in ctx.observations.values():
            if "org.apache.commons.text" in obs.body_sample or "commons-text" in obs.body_sample:
                return True
        return False

    def _detect_commons_text_version(self, ctx: TargetContext) -> str | None:
        for obs in ctx.observations.values():
            m = self._COMMONS_TEXT_RE.search(obs.body_sample)
            if m:
                return m.group("ver")
        return None
