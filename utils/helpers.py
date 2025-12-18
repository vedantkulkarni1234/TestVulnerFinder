from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class TargetSpec:
    url: str


def normalize_url(raw: str, *, default_scheme: str = "https") -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"

    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"invalid URL: {raw}")

    base = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        base += parsed.path.rstrip("/")
    return base


def read_lines(path: Path) -> list[str]:
    lines: list[str] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


_PORT_RE = re.compile(r"^\d{1,5}$")


def parse_ports(ports: str) -> list[int]:
    out: list[int] = []
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if not _PORT_RE.match(a) or not _PORT_RE.match(b):
                raise ValueError(f"invalid port range: {part}")
            start, end = int(a), int(b)
            out.extend(range(min(start, end), max(start, end) + 1))
        else:
            if not _PORT_RE.match(part):
                raise ValueError(f"invalid port: {part}")
            out.append(int(part))
    deduped = sorted({p for p in out if 1 <= p <= 65535})
    if not deduped:
        raise ValueError("no valid ports")
    return deduped


def expand_cidr(cidr: str, *, scheme: str, ports: list[int]) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    urls: list[str] = []
    for ip in net.hosts():
        for port in ports:
            host = str(ip)
            if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                urls.append(f"{scheme}://{host}")
            else:
                urls.append(f"{scheme}://{host}:{port}")
    return urls


def parse_semver(v: str) -> tuple[int, ...] | None:
    """Tiny numeric version parser.

    - Accepts 3- or 4-component numeric versions (e.g., 2.5.10.1)
    - Ignores suffixes (e.g., 5.3.17.RELEASE)

    We keep this intentionally small to avoid pulling in heavyweight dependencies.
    """

    raw_parts = re.split(r"[.+_-]", v.strip())
    numeric: list[int] = []
    for part in raw_parts:
        if not part or not part[0].isdigit():
            break
        try:
            numeric.append(int(part))
        except ValueError:
            break
        if len(numeric) >= 4:
            break

    if len(numeric) < 3:
        return None
    return tuple(numeric)


def semver_inclusive_between(
    v: tuple[int, ...],
    *,
    low: tuple[int, ...],
    high: tuple[int, ...],
) -> bool:
    width = max(len(v), len(low), len(high))

    def pad(x: tuple[int, ...]) -> tuple[int, ...]:
        return x + (0,) * (width - len(x))

    return pad(low) <= pad(v) <= pad(high)


def first_present(items: Iterable[str | None]) -> str | None:
    for it in items:
        if it:
            return it
    return None
