"""OIDC discovery: fetch + cache + validate the provider metadata (M10c).

Fetches ``<issuer>/.well-known/openid-configuration`` over the injected httpx
client, extracts the endpoints the flow needs, and enforces the **issuer mix-up
defense**: the discovered ``issuer`` MUST exactly equal the configured issuer.
The document is cached with a TTL so the discovery + JWKS endpoints are not hit on
every login.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx

from .config import OidcProviderConfig, _normalize_issuer
from .errors import OidcAuthError

# How long a fetched discovery document is trusted before re-fetching.
_DISCOVERY_TTL = timedelta(hours=1)
# Bound the discovery/token HTTP so a hung IdP cannot wedge a request worker.
_HTTP_TIMEOUT = 10.0


@dataclass(frozen=True)
class DiscoveryDocument:
    """The provider metadata the authorization-code flow consumes."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


def fetch_discovery(
    config: OidcProviderConfig, http_client: httpx.Client
) -> DiscoveryDocument:
    """Fetch + validate the provider metadata. Any transport/parse error or an
    issuer mismatch raises :class:`OidcAuthError` (generic; never leaks the IdP
    internals)."""
    try:
        response = http_client.get(config.discovery_url, timeout=_HTTP_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcAuthError("oidc discovery failed") from exc

    if not isinstance(data, dict):
        raise OidcAuthError("oidc discovery returned an unexpected document")

    discovered_issuer = data.get("issuer")
    # Issuer mix-up defense: the document's issuer MUST match the configured one.
    if not isinstance(discovered_issuer, str) or _normalize_issuer(
        discovered_issuer
    ) != config.issuer:
        raise OidcAuthError("oidc discovery issuer mismatch")

    try:
        return DiscoveryDocument(
            issuer=config.issuer,
            authorization_endpoint=_require(data, "authorization_endpoint"),
            token_endpoint=_require(data, "token_endpoint"),
            jwks_uri=_require(data, "jwks_uri"),
        )
    except OidcAuthError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise OidcAuthError("oidc discovery document is incomplete") from exc


def _require(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise OidcAuthError(f"oidc discovery missing {key}")
    return value


class DiscoveryCache:
    """A tiny single-issuer TTL cache for the discovery document (the deployment
    federates to exactly one IdP). Not thread-safe by design -- a benign race just
    re-fetches; the document is stable."""

    def __init__(self, ttl: timedelta = _DISCOVERY_TTL) -> None:
        self._ttl = ttl
        self._doc: DiscoveryDocument | None = None
        self._fetched_at: datetime | None = None

    def get(
        self,
        config: OidcProviderConfig,
        http_client: httpx.Client,
        now: datetime,
    ) -> DiscoveryDocument:
        if (
            self._doc is not None
            and self._fetched_at is not None
            and now - self._fetched_at < self._ttl
        ):
            return self._doc
        doc = fetch_discovery(config, http_client)
        self._doc = doc
        self._fetched_at = now
        return doc
