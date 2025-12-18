from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence


class GhostscriptModule:
    name = "ghostscript"
    vulnerability = "Ghostscript RCE via Image Processing Pipelines"
    cve = "CVE-2018-16509"

    _GS_RE = re.compile(r"ghostscript\s*(?P<ver>\d+\.\d+(?:\.\d+)?)", re.I)
    _IM_RE = re.compile(r"imagemagick\s*(?P<ver>\d+\.\d+(?:\.\d+)?)", re.I)

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        gs_ver = None
        im_ver = None
        for obs in ctx.observations.values():
            if obs.status_code is None:
                continue
            if gs_ver is None:
                m = self._GS_RE.search(obs.body_sample)
                if m:
                    gs_ver = m.group("ver")
            if im_ver is None:
                m = self._IM_RE.search(obs.body_sample)
                if m:
                    im_ver = m.group("ver")

        # Extremely conservative: only report when both are explicitly observable.
        if not gs_ver or not im_ver:
            return []

        ev = EvidenceItem(
            kind="fingerprint",
            summary=f"Image processing toolchain identifiers observed: ImageMagick {im_ver}, Ghostscript {gs_ver}",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"imagemagick_version": im_ver, "ghostscript_version": gs_ver},
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
                title="Image processing toolchain exposure detected",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"ImageMagick {im_ver} and Ghostscript {gs_ver} identifiers were observed in responses. "
                    "This suggests an image processing pipeline where Ghostscript CVEs (incl. CVE-2018-16509) may be relevant. "
                    "No file upload probes were performed."
                ),
                evidence_ids=evidence_ids,
            )
        ]
