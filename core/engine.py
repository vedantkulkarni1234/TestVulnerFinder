from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Mapping, Protocol, cast

from core.evidence import EvidenceItem, EvidenceStore, Provenance
from core.fingerprint import Fingerprint, fingerprint_from_observations
from core.http import AuroraHTTPClient, HTTPConfig, HTTPResult, StealthConfig, WAFBypassConfig
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
class DistributedQueueConfig:
    """Hive Mind distributed scanning configuration."""

    enabled: bool = False
    backend: str = "redis"  # "redis" or "zeromq"
    redis_url: str | None = None
    zeromq_endpoint: str | None = None
    master_mode: bool = False
    worker_mode: bool = False
    queue_name: str = "aurora:scan_queue"
    result_queue_name: str = "aurora:result_queue"
    ttl_seconds: int = 3600


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
    waf_bypass: WAFBypassConfig | None = None
    distributed_queue: DistributedQueueConfig | None = None
    oast_listener_enabled: bool = False
    oast_domain: str | None = None


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
        self._dist_queue: Any = None
        self._oast_listener: Any = None

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
        waf_cfg = config.waf_bypass or WAFBypassConfig()
        self._http_client = AuroraHTTPClient(config=http_cfg, stealth=stealth_cfg, waf_bypass=waf_cfg)

        self._stats = EngineStats()
        self._limiter = RateLimiter(config.rate_limit_rps) if config.rate_limit_rps else None
        self._req_ctx = RequestContext(client=self._http_client, limiter=self._limiter, stats=self._stats)

    async def aclose(self) -> None:
        if self._oast_listener is not None:
            try:
                await self._oast_listener.aclose()
            except Exception:
                pass
        await self._http_client.aclose()

    async def _get_target_from_queue(self, queue: asyncio.Queue[Target] | Any) -> Target | None:
        """Get target from either local or distributed queue."""
        if isinstance(queue, asyncio.Queue):
            try:
                return queue.get_nowait()
            except asyncio.QueueEmpty:
                return None
        else:
            return await queue.get_async()

    async def scan(self, targets: list[Target]) -> list[ScanResult]:
        if self._config.distributed_queue and self._config.distributed_queue.enabled:
            queue = await self._initialize_distributed_queue(targets)
        else:
            queue = cast(asyncio.Queue[Target], asyncio.Queue())
            for t in targets:
                queue.put_nowait(t)

        if self._config.oast_listener_enabled and self._config.oast_domain:
            try:
                from core.oast_listener import OASTListener

                self._oast_listener = OASTListener(domain=self._config.oast_domain)
                await self._oast_listener.initialize()
            except ImportError:
                pass

        results: list[ScanResult] = []
        results_lock = asyncio.Lock()
        total_targets = len(targets)

        async def worker(worker_id: int) -> None:
            while True:
                target = await self._get_target_from_queue(queue)
                if target is None:
                    return

                res = await self._scan_one(target)
                async with results_lock:
                    results.append(res)

                self._stats.completed_targets += 1
                if self._progress_cb is not None:
                    await self._progress_cb(self._stats, self._stats.completed_targets, total_targets)

        workers = [asyncio.create_task(worker(i)) for i in range(max(1, self._config.concurrency))]
        await asyncio.gather(*workers)

        return results

    async def _initialize_distributed_queue(self, targets: list[Target]) -> Any:
        """Initialize distributed queue for Hive Mind scanning."""
        dist_cfg = self._config.distributed_queue
        if dist_cfg is None or not dist_cfg.enabled:
            raise ValueError("Distributed queue not configured")

        if dist_cfg.backend == "redis":
            try:
                import redis.asyncio as redis

                r = await redis.from_url(dist_cfg.redis_url or "redis://localhost:6379")
                for target in targets:
                    await r.rpush(dist_cfg.queue_name, target.url)
                return r
            except ImportError:
                raise ImportError("redis package required for Redis backend")
        elif dist_cfg.backend == "zeromq":
            try:
                import zmq.asyncio

                ctx = zmq.asyncio.Context()
                socket = ctx.socket(zmq.PULL)
                if dist_cfg.worker_mode:
                    socket.connect(dist_cfg.zeromq_endpoint or "tcp://localhost:5555")
                else:
                    socket.bind(dist_cfg.zeromq_endpoint or "tcp://*:5555")
                    for target in targets:
                        await socket.send_string(target.url)
                return socket
            except ImportError:
                raise ImportError("zeromq package required for ZeroMQ backend")
        else:
            raise ValueError(f"Unknown distributed queue backend: {dist_cfg.backend}")

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

        if self._oast_listener is not None:
            callbacks = await self._oast_listener.check_callbacks()
            if callbacks:
                for callback in callbacks:
                    oast_finding = self._create_oast_finding_from_callback(callback, target, evidence)
                    if oast_finding is not None:
                        findings.append(oast_finding)
                        if self._finding_cb is not None:
                            await self._finding_cb(target, oast_finding)

        # Ensure stable ordering.
        findings.sort(key=lambda x: (-x.confidence, x.vulnerability, x.module))

        return ScanResult(target=target, fingerprint=fingerprint, findings=findings, evidence=evidence)

    def _create_oast_finding_from_callback(
        self, callback: dict[str, Any], target: Target, evidence: EvidenceStore
    ) -> Finding | None:
        """Create a Finding from an OAST callback."""
        callback_type = callback.get("type", "unknown")
        interaction = callback.get("interaction", "")

        if "log4shell" in callback_type.lower():
            vulnerability = "Log4Shell"
            cve = "CVE-2021-44228"
        elif "text4shell" in callback_type.lower():
            vulnerability = "Text4Shell"
            cve = "CVE-2022-42889"
        else:
            vulnerability = "OAST Callback Detected"
            cve = None

        ev = EvidenceItem(
            kind="oast_callback",
            summary=f"OAST callback received: {callback_type}",
            provenance=Provenance(url=target.url, method="OAST", status_code=None),
            details={
                "callback_type": callback_type,
                "interaction": interaction,
                "timestamp": callback.get("timestamp", time.time()),
            },
        )
        evidence.add(ev)

        return Finding(
            module="oast_listener",
            vulnerability=vulnerability,
            cve=cve,
            title=f"{vulnerability} OAST Callback - CONFIRMED",
            confidence=95,
            tier=tier_for_confidence(95),
            summary=f"Out-of-band callback confirmed for {vulnerability} (type: {callback_type})",
            evidence_ids=[ev.stable_id()],
        )
