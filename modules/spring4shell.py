from __future__ import annotations

import re

from core.engine import Finding, TargetContext
from core.evidence import EvidenceItem, Provenance
from core.scoring import FindingTier, tier_for_confidence
from utils.helpers import parse_semver, semver_inclusive_between


class Spring4ShellModule:
    name = "spring4shell"
    vulnerability = "Spring4Shell"
    cve = "CVE-2022-22965"

    _SPRING_JAR_RE = re.compile(r"spring-(?:webmvc|web|core)-(?P<ver>\d+\.\d+\.\d+)")

    async def run(self, ctx: TargetContext) -> list[Finding]:
        base = ctx.target.url.rstrip("/")
        evidence_ids: list[str] = []

        spring_ver = self._detect_spring_framework_version(ctx)
        if spring_ver is None:
            return []

        sem = parse_semver(spring_ver)
        if sem is None:
            return []

        vulnerable = semver_inclusive_between(sem, low=(5, 3, 0), high=(5, 3, 17)) or semver_inclusive_between(
            sem, low=(5, 2, 0), high=(5, 2, 19)
        )
        if not vulnerable:
            return []

        ev = EvidenceItem(
            kind="precondition",
            summary=f"Spring Framework version {spring_ver} within known vulnerable ranges",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"spring_framework_version": spring_ver},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        jdk_major = self._detect_jdk_major(ctx)
        if jdk_major is None or jdk_major < 9:
            return []

        ev = EvidenceItem(
            kind="precondition",
            summary=f"JDK major version confirmed as {jdk_major} (≥ 9)",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"jdk_major": jdk_major},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        # WAR deployment validation (WEB-INF should exist but be forbidden).
        web_inf = await ctx.http.request("GET", base + "/WEB-INF/web.xml", evidence=ctx.evidence)
        if web_inf.status_code not in {401, 403}:
            return []

        ev = EvidenceItem(
            kind="precondition",
            summary="WAR-like deployment confirmed via protected /WEB-INF/web.xml",
            provenance=Provenance(url=web_inf.url, method=web_inf.method, status_code=web_inf.status_code),
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        # Servlet container validation.
        is_tomcat = "tomcat" in ctx.fingerprint.containers
        if not is_tomcat:
            server = (ctx.fingerprint.server or "").lower()
            is_tomcat = "tomcat" in server or "apache-coyote" in server
        if not is_tomcat:
            return []

        ev = EvidenceItem(
            kind="precondition",
            summary="Apache Tomcat servlet container detected",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
            details={"server": ctx.fingerprint.server},
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        # Binding surface validation: safe probe looking for Spring DataBinder error strings.
        surface = await self._probe_classloader_binding_surface(ctx)
        if not surface:
            return []

        ev = EvidenceItem(
            kind="precondition",
            summary="Data binding surface confirmed (class/module/classLoader path reached Spring binder)",
            provenance=Provenance(url=base, method="EVIDENCE", status_code=None),
        )
        ctx.evidence.add(ev)
        evidence_ids.append(ev.stable_id())

        confidence = 95
        tier = tier_for_confidence(confidence)
        if tier is None:
            return []

        return [
            Finding(
                module=self.name,
                vulnerability=self.vulnerability,
                cve=self.cve,
                title="Spring Framework RCE chain preconditions satisfied",
                confidence=confidence,
                tier=tier,
                summary=(
                    f"All Spring4Shell preconditions independently confirmed: Spring {spring_ver}, "
                    f"JDK {jdk_major}, WAR deployment, Tomcat, binder surface."
                ),
                evidence_ids=evidence_ids,
            )
        ]

    def _detect_spring_framework_version(self, ctx: TargetContext) -> str | None:
        for obs in ctx.observations.values():
            m = self._SPRING_JAR_RE.search(obs.body_sample)
            if m:
                return m.group("ver")

        # Spring Boot actuator sometimes exposes build info.
        for path in ("/actuator/info", "/actuator/env"):
            obs = ctx.observations.get(path)
            if not obs:
                continue
            data = obs.json()
            if not isinstance(data, dict):
                continue
            # Heuristic keys.
            for key in (
                "spring-framework.version",
                "springframework.version",
                "springFrameworkVersion",
            ):
                val = self._deep_get(data, key)
                if isinstance(val, str):
                    return val

        return None

    def _detect_jdk_major(self, ctx: TargetContext) -> int | None:
        for path in ("/actuator/env", "/actuator/info"):
            obs = ctx.observations.get(path)
            if not obs:
                continue
            data = obs.json()
            if not isinstance(data, dict):
                continue

            for key in (
                "java.version",
                "build.java.version",
                "systemProperties.java.version",
            ):
                val = self._deep_get(data, key)
                if isinstance(val, str):
                    return self._parse_java_major(val)

        return None

    async def _probe_classloader_binding_surface(self, ctx: TargetContext) -> bool:
        base = ctx.target.url.rstrip("/")
        probe = await ctx.http.request(
            "POST",
            base + "/",
            evidence=ctx.evidence,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"class.module.classLoader": "1"},
        )

        if probe.status_code not in {400, 422, 500}:
            return False

        s = probe.body_sample.lower()
        return any(
            needle in s
            for needle in (
                "org.springframework.beans",
                "failed to bind",
                "invalid property 'class'",
                "classloader",
            )
        )

    def _parse_java_major(self, raw: str) -> int | None:
        raw = raw.strip()
        if raw.startswith("1."):
            # 1.8.0_292
            parts = raw.split(".")
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
            return None
        major_str = raw.split(".", 1)[0]
        try:
            return int(major_str)
        except ValueError:
            return None

    def _deep_get(self, obj: object, dotted_key: str) -> object | None:
        """Very small helper to pull nested values without bringing in jmespath."""

        cur: object = obj
        for part in dotted_key.split("."):
            if not isinstance(cur, dict):
                return None
            if part not in cur:
                return None
            cur = cur[part]
        return cur
