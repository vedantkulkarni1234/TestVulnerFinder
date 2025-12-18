from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Mapping, Protocol, cast

from core.evidence import EvidenceItem, EvidenceStore, Provenance
from core.fingerprint import Fingerprint, fingerprint_from_observations
from core.http import AuroraHTTPClient, HTTPConfig, HTTPResult, StealthConfig
from core.scoring import FindingTier, tier_for_confidence


@dataclass(frozen=True, slots=True)
class Target:
    url: str


@dataclass(frozen=True, slots=True)
class Finding:
    module: str
    vulnerability: str
    cve: str | None
    title: str
    confidence: int
    tier: FindingTier
    summary: str
    evidence_ids: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "module": self.module,
            "vulnerability": self.vulnerability,
            "cve": self.cve,
            "title": self.title,
            "confidence": self.confidence,
            "tier": self.tier.value,
            "summary": self.summary,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(slots=True)
class TargetContext:
    target: Target
    http: "RequestContext"
    fingerprint: Fingerprint
    evidence: EvidenceStore
    observations: Mapping[str, HTTPResult]


class DetectionModule(Protocol):
    name: str
    cve: str | None
    vulnerability: str

    async def run(self, ctx: TargetContext) -> list[Finding]: ...


@dataclass(frozen=True, slots=True)
class ScanConfig:
    concurrency: int = 200
    rate_limit_rps: float | None = None
    stealth: bool = False
    proxy: str | None = None
    verify_tls: bool = True
    user_agent: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    request_timeout_s: float = 12.0
    verbose: bool = False


@dataclass(slots=True)
class EngineStats:
    started_at: float = field(default_factory=time.time)
    total_requests: int = 0
    completed_targets: int = 0

    def rps(self) -> float:
        elapsed = max(0.001, time.time() - self.started_at)
        return self.total_requests / elapsed


class RateLimiter:
    """Global request rate limiter.

    This is intentionally simple and conservative; the goal is operational safety.
    """

    def __init__(self, rps: float) -> None:
        self._interval = 1.0 / max(0.001, rps)
        self._lock = asyncio.Lock()
        self._next_allowed = time.perf_counter()

    async def wait(self) -> None:
        async with self._lock:
            now = time.perf_counter()
            if now < self._next_allowed:
                await asyncio.sleep(self._next_allowed - now)
            self._next_allowed = max(self._next_allowed + self._interval, time.perf_counter())


@dataclass(slots=True)
class RequestContext:
    client: AuroraHTTPClient
    limiter: RateLimiter | None
    stats: EngineStats

    async def request(
        self,
        method: str,
        url: str,
        *,
        evidence: EvidenceStore,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        data: Mapping[str, str] | bytes | None = None,
        json_body: object | None = None,
    ) -> HTTPResult:
        if self.limiter is not None:
            await self.limiter.wait()
        res = await self.client.request(
            method,
            url,
            evidence=evidence,
            headers=headers,
            params=params,
            data=data,
            json_body=json_body,
        )
        self.stats.total_requests += 1
        return res


@dataclass(slots=True)
class ScanResult:
    target: Target
    fingerprint: Fingerprint
    findings: list[Finding]
    evidence: EvidenceStore

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target.url,
            "fingerprint": {
                "server": self.fingerprint.server,
                "powered_by": self.fingerprint.powered_by,
                "frameworks": sorted(self.fingerprint.frameworks),
                "containers": sorted(self.fingerprint.containers),
                "languages": sorted(self.fingerprint.languages),
                "products": sorted(self.fingerprint.products),
            },
            "findings": [f.as_dict() for f in self.findings],
            "evidence": self.evidence.as_dict(),
        }


ProgressCallback = Callable[[EngineStats, int, int], Awaitable[None]]
FindingCallback = Callable[[Target, Finding], Awaitable[None]]


class Engine:
    def __init__(
        self,
        *,
        config: ScanConfig,
        modules: Iterable[DetectionModule],
        progress_cb: ProgressCallback | None = None,
        finding_cb: FindingCallback | None = None,
    ) -> None:
        self._config = config
        self._modules = list(modules)
        self._progress_cb = progress_cb
        self._finding_cb = finding_cb

        default_ua = HTTPConfig().user_agent
        http_cfg = HTTPConfig(
            timeout=config.request_timeout_s,
            verify_tls=config.verify_tls,
            proxy=config.proxy,
            client_cert=config.client_cert,
            client_key=config.client_key,
            user_agent=config.user_agent or default_ua,
        )
        stealth_cfg = StealthConfig(enabled=config.stealth)
        self._http_client = AuroraHTTPClient(config=http_cfg, stealth=stealth_cfg)

        self._stats = EngineStats()
        self._limiter = RateLimiter(config.rate_limit_rps) if config.rate_limit_rps else None
        self._req_ctx = RequestContext(client=self._http_client, limiter=self._limiter, stats=self._stats)

    async def aclose(self) -> None:
        await self._http_client.aclose()

    async def scan(self, targets: list[Target]) -> list[ScanResult]:
        queue = cast(asyncio.Queue[Target], asyncio.Queue())
        for t in targets:
            queue.put_nowait(t)

        results: list[ScanResult] = []
        results_lock = asyncio.Lock()

        async def worker(worker_id: int) -> None:
            while True:
                try:
                    target = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                res = await self._scan_one(target)
                async with results_lock:
                    results.append(res)

                self._stats.completed_targets += 1
                if self._progress_cb is not None:
                    await self._progress_cb(self._stats, self._stats.completed_targets, len(targets))

                queue.task_done()

        workers = [asyncio.create_task(worker(i)) for i in range(max(1, self._config.concurrency))]
        await asyncio.gather(*workers)

        return results

    async def _scan_one(self, target: Target) -> ScanResult:
        evidence = EvidenceStore()

        observations: dict[str, HTTPResult] = {}
        base = target.url.rstrip("/")

        observations["/"] = await self._req_ctx.request("GET", base + "/", evidence=evidence)
        observations["/robots.txt"] = await self._req_ctx.request(
            "GET", base + "/robots.txt", evidence=evidence
        )

        # High-signal JSON endpoints (safe; no auth bypass attempts).
        observations["/actuator"] = await self._req_ctx.request(
            "GET", base + "/actuator", evidence=evidence
        )
        observations["/actuator/info"] = await self._req_ctx.request(
            "GET", base + "/actuator/info", evidence=evidence
        )
        observations["/actuator/env"] = await self._req_ctx.request(
            "GET", base + "/actuator/env", evidence=evidence
        )
        observations["/api/status"] = await self._req_ctx.request(
            "GET", base + "/api/status", evidence=evidence
        )

        fingerprint = fingerprint_from_observations(observations.values(), evidence=evidence)

        ctx = TargetContext(
            target=target,
            http=self._req_ctx,
            fingerprint=fingerprint,
            evidence=evidence,
            observations=observations,
        )

        findings: list[Finding] = []
        for mod in self._modules:
            try:
                mod_findings = await mod.run(ctx)
            except Exception as exc:  # noqa: BLE001
                if self._config.verbose:
                    evidence.add(
                        EvidenceItem(
                            kind="module_error",
                            summary=f"{mod.name} raised {exc.__class__.__name__}: {exc}",
                            provenance=Provenance(url=target.url, method="MODULE", status_code=None),
                        )
                    )
                continue

            for f in mod_findings:
                tier = tier_for_confidence(f.confidence)
                if tier is None and not self._config.verbose:
                    continue
                findings.append(f)
                if self._finding_cb is not None:
                    await self._finding_cb(target, f)

        # Ensure stable ordering.
        findings.sort(key=lambda x: (-x.confidence, x.vulnerability, x.module))

        return ScanResult(target=target, fingerprint=fingerprint, findings=findings, evidence=evidence)
