"""OIDC provider configuration (M10c).

A frozen :class:`OidcProviderConfig` describing the one external IdP a deployment
federates to. Built directly by tests; the production app builds one from the
environment via :meth:`OidcProviderConfig.from_env` (absent required vars ->
``None`` -> OIDC is simply not enabled and the endpoints are not mounted).

Secrets discipline (REQ-INV-011): ``client_secret`` is ``repr``-suppressed so
logging the config object never prints it; it is used only as the token-endpoint
client credential and is never logged or returned.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta

# Only asymmetric signature algorithms are ever accepted for an ID token. This is
# the allow-list passed to ``jwt.decode`` -- it structurally rejects ``alg:none``
# AND the HS* symmetric-key-confusion attack (an HS256 token forged with the
# public JWKS key as the HMAC secret has ``alg`` outside this list and is
# rejected). The set is fixed in code, never operator-supplied.
ALLOWED_ID_TOKEN_ALGORITHMS: tuple[str, ...] = (
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
)

# Required OpenID scope; ``email`` is required so the callback can map to a local
# user. Both are force-included so a misconfigured scope string cannot drop them.
_REQUIRED_SCOPES = ("openid", "email")

_DEFAULT_TRANSACTION_TTL = timedelta(minutes=10)
_DEFAULT_LEEWAY = timedelta(seconds=60)


class OidcConfigurationError(ValueError):
    """The OIDC configuration is present but invalid (bad issuer / redirect_uri /
    scopes). A ``ValueError`` so the interface maps it to 400 if it ever surfaces
    on a request path (it normally fails fast at startup)."""


def _normalize_issuer(issuer: str) -> str:
    """Trailing-slash-normalize the issuer for a stable exact comparison (the
    OIDC ``iss`` identifier is compared exactly, but a stray trailing slash in
    config must not cause a false mismatch)."""
    return issuer.rstrip("/")


@dataclass(frozen=True)
class OidcProviderConfig:
    """The single federated IdP for this deployment.

    * ``issuer`` -- the IdP issuer identifier (an ``https`` URL). Discovery is
      fetched from ``<issuer>/.well-known/openid-configuration`` and the
      discovered ``issuer`` MUST equal this value (mix-up defense); the ID token's
      ``iss`` is validated against it too.
    * ``client_id`` / ``client_secret`` -- this deployment's OAuth client
      credentials. ``client_secret`` is ``repr``-suppressed and never logged.
    * ``redirect_uri`` -- the exact callback URL; sent at authorization and
      exact-matched at token exchange.
    * ``scopes`` -- always includes ``openid`` and ``email``.
    * ``allowed_domains`` -- optional email-domain allow-list; when non-empty, a
      verified email outside it is rejected.
    * ``auto_provision`` -- if the verified email has no local user, create one
      (with NO system role and NO membership) when ``True``; otherwise reject.
    """

    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    scopes: tuple[str, ...] = _REQUIRED_SCOPES
    allowed_domains: tuple[str, ...] = ()
    auto_provision: bool = False
    transaction_ttl: timedelta = _DEFAULT_TRANSACTION_TTL
    leeway: timedelta = _DEFAULT_LEEWAY
    allowed_algorithms: tuple[str, ...] = ALLOWED_ID_TOKEN_ALGORITHMS

    def __post_init__(self) -> None:
        if not self.issuer or not self.issuer.startswith(("https://", "http://")):
            raise OidcConfigurationError(
                "issuer must be an absolute http(s) URL"
            )
        # Normalize the issuer in place (frozen dataclass -> object.__setattr__).
        object.__setattr__(self, "issuer", _normalize_issuer(self.issuer))
        if not self.client_id:
            raise OidcConfigurationError("client_id is required")
        if not self.client_secret:
            raise OidcConfigurationError("client_secret is required")
        if not self.redirect_uri or not self.redirect_uri.startswith(
            ("https://", "http://")
        ):
            raise OidcConfigurationError(
                "redirect_uri must be an absolute http(s) URL"
            )
        # Force-include the required scopes (dedup, preserve order).
        merged: list[str] = list(self.scopes)
        for required in _REQUIRED_SCOPES:
            if required not in merged:
                merged.append(required)
        object.__setattr__(self, "scopes", tuple(merged))
        object.__setattr__(
            self,
            "allowed_domains",
            tuple(d.lower() for d in self.allowed_domains if d),
        )
        if self.transaction_ttl <= timedelta(0):
            raise OidcConfigurationError("transaction_ttl must be positive")
        if self.leeway < timedelta(0):
            raise OidcConfigurationError("leeway must not be negative")
        if not self.allowed_algorithms:
            raise OidcConfigurationError("allowed_algorithms must be non-empty")
        if any(alg.upper().startswith("HS") or alg.lower() == "none"
               for alg in self.allowed_algorithms):
            # Defense in depth: a symmetric / none alg in the allow-list would
            # reopen the key-confusion / unsigned-token attacks.
            raise OidcConfigurationError(
                "allowed_algorithms must be asymmetric (never HS* or none)"
            )

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def scope_param(self) -> str:
        return " ".join(self.scopes)

    def domain_allowed(self, email: str) -> bool:
        """True iff ``email``'s domain passes the allow-list (always True when no
        allow-list is configured)."""
        if not self.allowed_domains:
            return True
        _, _, domain = email.rpartition("@")
        return domain.lower() in self.allowed_domains

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None
    ) -> OidcProviderConfig | None:
        """Build the config from the environment, or ``None`` when OIDC is not
        configured (any of the four required vars absent). Raises
        :class:`OidcConfigurationError` when the present values are invalid.

        Vars: ``CTFGEN_OIDC_ISSUER``, ``CTFGEN_OIDC_CLIENT_ID``,
        ``CTFGEN_OIDC_CLIENT_SECRET``, ``CTFGEN_OIDC_REDIRECT_URI`` (all required);
        optional ``CTFGEN_OIDC_SCOPES`` (space-separated, default ``openid
        email``), ``CTFGEN_OIDC_ALLOWED_DOMAINS`` (comma-separated),
        ``CTFGEN_OIDC_AUTO_PROVISION`` (``1``/``true`` to enable)."""
        env = environ if environ is not None else os.environ
        issuer = env.get("CTFGEN_OIDC_ISSUER")
        client_id = env.get("CTFGEN_OIDC_CLIENT_ID")
        client_secret = env.get("CTFGEN_OIDC_CLIENT_SECRET")
        redirect_uri = env.get("CTFGEN_OIDC_REDIRECT_URI")
        if not (issuer and client_id and client_secret and redirect_uri):
            return None
        scopes_raw = env.get("CTFGEN_OIDC_SCOPES", "openid email")
        scopes = tuple(s for s in scopes_raw.split() if s) or _REQUIRED_SCOPES
        domains_raw = env.get("CTFGEN_OIDC_ALLOWED_DOMAINS", "")
        allowed_domains = tuple(
            d.strip() for d in domains_raw.split(",") if d.strip()
        )
        auto_provision = env.get("CTFGEN_OIDC_AUTO_PROVISION", "0").lower() in (
            "1",
            "true",
            "yes",
        )
        return cls(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes,
            allowed_domains=allowed_domains,
            auto_provision=auto_provision,
        )
