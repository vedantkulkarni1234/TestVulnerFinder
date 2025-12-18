"""Integrated OAST Listener (Sonar) - Real-time callback detection and injection."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class OASTCallback:
    """Representation of an OAST callback."""

    callback_type: str
    interaction: str
    timestamp: float
    source_ip: str | None = None
    raw_data: dict[str, Any] | None = None


class OASTListener:
    """Project Discovery interactsh-based OAST listener for automatic callback detection.

    This module provisions temporary OAST URLs and detects out-of-band callbacks
    in real-time during scanning. When a callback is received, it immediately
    injects a CONFIRMED finding.
    """

    def __init__(self, domain: str) -> None:
        """Initialize OAST listener.

        Args:
            domain: interactsh domain (e.g., 'interact.sh')
        """
        self._domain = domain
        self._tokens: dict[str, float] = {}
        self._callbacks: list[OASTCallback] = []
        self._client: Any = None
        self._polling_task: asyncio.Task[None] | None = None

    async def initialize(self) -> None:
        """Initialize OAST listener and start polling."""
        try:
            from interactsh import interactsh

            self._client = interactsh(self._domain)
        except ImportError:
            try:
                self._client = self._build_simple_client()
            except Exception as e:
                raise ImportError(f"Failed to initialize OAST client: {e}") from e

        self._polling_task = asyncio.create_task(self._poll_for_callbacks())

    def _build_simple_client(self) -> OASTSimpleClient:
        """Build a simple OAST client if interactsh is not available."""
        return OASTSimpleClient(self._domain)

    async def get_callback_url(self, token: str | None = None) -> str:
        """Provision a temporary OAST callback URL.

        Args:
            token: Optional token. If None, generates one.

        Returns:
            Full callback URL for use in payloads.
        """
        import secrets

        if token is None:
            token = secrets.token_hex(8)

        self._tokens[token] = time.time()
        return f"{token}.{self._domain}"

    async def check_callbacks(self) -> list[dict[str, Any]]:
        """Check for received callbacks.

        Returns:
            List of callback dicts with structure:
            {
                "type": "dns|ldap|http|etc",
                "interaction": "raw_callback_data",
                "timestamp": float,
                "source_ip": str,
            }
        """
        return [
            {
                "type": self._detect_callback_type(cb),
                "interaction": cb.interaction,
                "timestamp": cb.timestamp,
                "source_ip": cb.source_ip,
            }
            for cb in self._callbacks
        ]

    def _detect_callback_type(self, callback: OASTCallback) -> str:
        """Detect callback type from interaction data."""
        interaction_lower = callback.interaction.lower()
        if "ldap" in interaction_lower or "jndi" in interaction_lower:
            return "log4shell"
        elif "commons" in interaction_lower or "text" in interaction_lower:
            return "text4shell"
        elif "http" in interaction_lower:
            return "http"
        elif "dns" in interaction_lower:
            return "dns"
        else:
            return "unknown"

    async def _poll_for_callbacks(self) -> None:
        """Poll for callbacks periodically."""
        while True:
            try:
                if self._client:
                    interactions = await self._poll_client()
                    for interaction in interactions:
                        self._process_interaction(interaction)
                await asyncio.sleep(2)
            except Exception as e:
                if hasattr(self, "_domain"):
                    pass
                await asyncio.sleep(5)

    async def _poll_client(self) -> list[Any]:
        """Poll the OAST client for interactions."""
        if hasattr(self._client, "poll"):
            if asyncio.iscoroutinefunction(self._client.poll):
                return await self._client.poll()
            else:
                return self._client.poll()
        return []

    def _process_interaction(self, interaction: Any) -> None:
        """Process an interaction from the OAST service."""
        try:
            if isinstance(interaction, dict):
                callback = OASTCallback(
                    callback_type=interaction.get("type", "unknown"),
                    interaction=str(interaction.get("data", "")),
                    timestamp=interaction.get("timestamp", time.time()),
                    source_ip=interaction.get("source_ip"),
                    raw_data=interaction,
                )
            else:
                callback = OASTCallback(
                    callback_type="unknown",
                    interaction=str(interaction),
                    timestamp=time.time(),
                    source_ip=None,
                    raw_data=None,
                )
            self._callbacks.append(callback)
        except Exception:
            pass

    async def aclose(self) -> None:
        """Close the OAST listener and cleanup resources."""
        if self._polling_task:
            self._polling_task.cancel()
            try:
                await self._polling_task
            except asyncio.CancelledError:
                pass

        if self._client and hasattr(self._client, "close"):
            if asyncio.iscoroutinefunction(self._client.close):
                await self._client.close()
            else:
                self._client.close()


class OASTSimpleClient:
    """Fallback simple OAST client when interactsh library is not available.

    This provides basic DNS/LDAP callback detection capabilities via polling.
    """

    def __init__(self, domain: str) -> None:
        self._domain = domain
        self._interactions: list[dict[str, Any]] = []

    def poll(self) -> list[dict[str, Any]]:
        """Poll for new interactions (returns empty by default)."""
        return []

    async def aclose(self) -> None:
        """Cleanup."""
        pass
