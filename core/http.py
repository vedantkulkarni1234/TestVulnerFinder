from __future__ import annotations

import asyncio
import inspect
import json
import random
import time
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from core.evidence import EvidenceItem, EvidenceStore, Provenance


@dataclass(frozen=True, slots=True)
class HTTPConfig:
    timeout: float = 12.0
    follow_redirects: bool = True
    verify_tls: bool = True
    proxy: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    )
    default_headers: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class StealthConfig:
    enabled: bool = False
    min_delay_s: float = 0.15
    max_delay_s: float = 0.75
    jitter_s: float = 0.25


@dataclass(frozen=True, slots=True)
class HTTPResult:
    url: str
    method: str
    status_code: int | None
    headers: Mapping[str, str]
    body_sample: str
    elapsed_s: float

    def json(self) -> Any | None:
        if not self.body_sample:
            return None
        try:
            return json.loads(self.body_sample)
        except json.JSONDecodeError:
            return None


class AuroraHTTPClient:
    """Thin httpx wrapper with evidence capture.

    This is intentionally non-magical: modules should be explicit about what they request
    and what they consider proof.
    """

    def __init__(
        self,
        *,
        config: HTTPConfig,
        stealth: StealthConfig,
    ) -> None:
        self._config = config
        self._stealth = stealth

        headers: dict[str, str] = {
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        if config.default_headers:
            headers.update(dict(config.default_headers))

        cert: tuple[str, str] | str | None
        if config.client_cert and config.client_key:
            cert = (config.client_cert, config.client_key)
        else:
            cert = config.client_cert

        timeout = httpx.Timeout(config.timeout)

        client_kwargs: dict[str, Any] = {
            "headers": headers,
            "follow_redirects": config.follow_redirects,
            "verify": config.verify_tls,
            "cert": cert,
            "timeout": timeout,
        }

        # httpx has changed proxy configuration across versions.
        if config.proxy:
            try:
                sig = inspect.signature(httpx.AsyncClient)
                if "proxy" in sig.parameters:
                    client_kwargs["proxy"] = config.proxy
                else:
                    client_kwargs["proxies"] = {"http://": config.proxy, "https://": config.proxy}
            except (TypeError, ValueError):
                client_kwargs["proxies"] = {"http://": config.proxy, "https://": config.proxy}

        self._client = httpx.AsyncClient(**client_kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        evidence: EvidenceStore | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        data: Mapping[str, str] | bytes | None = None,
        json_body: Any | None = None,
        max_body_bytes: int = 40_000,
    ) -> HTTPResult:
        if self._stealth.enabled:
            base = random.uniform(self._stealth.min_delay_s, self._stealth.max_delay_s)
            jitter = random.uniform(0, self._stealth.jitter_s)
            await asyncio.sleep(base + jitter)

        started = time.perf_counter()
        status_code: int | None = None
        resp_headers: Mapping[str, str] = {}
        body_sample = ""
        try:
            resp = await self._client.request(
                method,
                url,
                headers=dict(headers) if headers else None,
                params=dict(params) if params else None,
                data=data,
                json=json_body,
            )
            status_code = resp.status_code
            resp_headers = dict(resp.headers)

            content = resp.content[:max_body_bytes]
            try:
                body_sample = content.decode(resp.encoding or "utf-8", errors="replace")
            except LookupError:
                body_sample = content.decode("utf-8", errors="replace")
        except httpx.RequestError as exc:
            body_sample = f"<request_error: {exc.__class__.__name__}: {exc}>"
        finally:
            elapsed = time.perf_counter() - started

        if evidence is not None:
            evidence.add(
                EvidenceItem(
                    kind="http",
                    summary=f"{method.upper()} {url} → {status_code}",
                    provenance=Provenance(url=url, method=method.upper(), status_code=status_code),
                    details={
                        "elapsed_s": round(elapsed, 4),
                        "response_headers": {k: v for k, v in resp_headers.items() if len(v) <= 256},
                        "body_sample": body_sample[:4_000],
                    },
                )
            )

        return HTTPResult(
            url=url,
            method=method.upper(),
            status_code=status_code,
            headers=resp_headers,
            body_sample=body_sample,
            elapsed_s=elapsed,
        )
