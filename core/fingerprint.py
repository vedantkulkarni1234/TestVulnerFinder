from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from core.evidence import EvidenceItem, EvidenceStore, Provenance
from core.http import HTTPResult


_VERSION_RE = re.compile(r"(?P<ver>\d+\.\d+\.\d+(?:[-+~._a-zA-Z0-9]+)?)")


@dataclass(slots=True)
class Fingerprint:
    """Coarse-grained technology fingerprint for a target."""

    server: str | None = None
    powered_by: str | None = None
    frameworks: set[str] = field(default_factory=set)
    containers: set[str] = field(default_factory=set)
    languages: set[str] = field(default_factory=set)
    products: set[str] = field(default_factory=set)


def _header_get(headers: dict[str, str], key: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == key.lower():
            return v
    return None


def fingerprint_from_observations(
    observations: Iterable[HTTPResult],
    *,
    evidence: EvidenceStore,
) -> Fingerprint:
    fp = Fingerprint()

    for obs in observations:
        if obs.status_code is None:
            continue

        server = _header_get(dict(obs.headers), "server")
        if server and not fp.server:
            fp.server = server
            evidence.add(
                EvidenceItem(
                    kind="fingerprint",
                    summary=f"Server header: {server}",
                    provenance=Provenance(url=obs.url, method=obs.method, status_code=obs.status_code),
                )
            )

        powered = _header_get(dict(obs.headers), "x-powered-by")
        if powered and not fp.powered_by:
            fp.powered_by = powered
            evidence.add(
                EvidenceItem(
                    kind="fingerprint",
                    summary=f"X-Powered-By: {powered}",
                    provenance=Provenance(url=obs.url, method=obs.method, status_code=obs.status_code),
                )
            )

        body = obs.body_sample.lower()
        if "spring" in body or "whitelabel error page" in body:
            fp.frameworks.add("spring")
            fp.languages.add("java")
        if "apache tomcat" in body or "apache-coyote" in (server or "").lower():
            fp.containers.add("tomcat")
        if "jetty" in body or "jetty" in (server or "").lower():
            fp.containers.add("jetty")
        if "undertow" in body or "undertow" in (server or "").lower():
            fp.containers.add("undertow")

        if "kibana" in body or _header_get(dict(obs.headers), "kbn-name"):
            fp.products.add("kibana")
            fp.languages.add("node")
        if "express" in (powered or "").lower():
            fp.frameworks.add("express")
            fp.languages.add("node")

        if "struts" in body or "struts problem report" in body:
            fp.frameworks.add("struts")
            fp.languages.add("java")

    return fp


def extract_versions(text: str) -> set[str]:
    """Extract semver-ish strings from an arbitrary blob."""

    return {m.group("ver") for m in _VERSION_RE.finditer(text)}
