from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between
from utils.oast import build_fqdn, generate_token, log4shell_payload


class Log4ShellModule:
    name = "log4shell"
    vulnerability = "Log4Shell"
    cve = "CVE-2021-44228"

    _LOG4J_JAR_RE = re.compile(r"log4j-(?:core|api)-(?P<ver>\d+\.\d+\.\d+)")
    _LOG4J_TEXT_RE = re.compile(r"log4j\s*(?:core|api)?\s*(?P<ver>\d+\.\d+\.\d+)", re.I)

    def __init__(self, *, oast_domain: str | None) -> None:
        self._oast_domain = oast_domain

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        version = self._detect_log4j_version(ctx)
        if version is None:
            # Still allow a conservative "possible" if we see hard log4j package strings.
            if not self._detect_log4j_presence(ctx):
                return []

            ev = EvidenceItem(
                kind="version",
                summary="Log4j package strings observed, but version not confirmed",
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
                    title="Log4j 2 present (version not confirmed)",
                    confidence=confidence,
                    tier=tier,
                    summary=(
                        "Log4j package identifiers were observed in responses. "
                        "Version could not be confirmed; manual review recommended."
                    ),
                    evidence_ids=evidence_ids,
                )
            ]

        sem = parse_semver(version)
        if sem is None:
            return []

        vulnerable_range = semver_inclusive_between(sem, low=(2, 0, 0), high=(2, 14, 1))
        if not vulnerable_range:
            return []

        ev = EvidenceItem(
            kind="version",
            summary=f"Log4j version confirmed as {version}",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"log4j_version": version},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        oast_note: str | None = None
        oast_used = False
        if self._oast_domain:
            token = generate_token(nbytes=8)
            fqdn = build_fqdn(token, self._oast_domain)
            payload = log4shell_payload(fqdn)

            # Recon-only trigger: sent only when operator explicitly opts in.
            await ctx.http.request(
                "GET",
                base + "/",
                evidence=ctx.evidence,
                headers={
                    "User-Agent": payload,
                    "X-Api-Version": payload,
                    "X-Forwarded-For": payload,
                },
            )
            oast_used = True
            oast_note = (
                f"OAST trigger sent (monitor DNS/LDAP callbacks for: {fqdn}). "
                "AURORA does not attempt to exploit or validate execution."
            )

            ev = EvidenceItem(
                kind="behavior",
                summary="Log4Shell OAST trigger header set",
                provenance=Provenance(url=base + "/", method="GET", status_code=None),
                details={"oast_fqdn": fqdn, "header_payload": payload},
            )
            ctx.evidence.add(ev)
            evidence_ids.append(ev.stable_id())

        confidence = 88 if oast_used else 85
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        summary = f"Log4j {version} detected within CVE-2021-44228 vulnerable range (≤ 2.14.1)."
        if oast_note:
            summary += f" {oast_note}"

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Log4j vulnerable version detected",
                confidence=confidence,
                tier=tier,
                summary=summary,
                evidence_ids=evidence_ids,
            )
        ]

    def _detect_log4j_presence(self, ctx: TargetContext) -> bool:
        for obs in ctx.observations.values():
            s = obs.body_sample
            if "org.apache.logging.log4j" in s or "log4j-core" in s:
                return True
        return False

    def _detect_log4j_version(self, ctx: TargetContext) -> str | None:
        for obs in ctx.observations.values():
            for rx in (self._LOG4J_JAR_RE, self._LOG4J_TEXT_RE):
                m = rx.search(obs.body_sample)
                if m:
                    return m.group("ver")
        return None
