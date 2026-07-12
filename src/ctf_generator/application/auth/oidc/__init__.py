"""OIDC/OAuth2 federated-login application layer (M10c).

Implements the OpenID Connect authorization-code + PKCE flow that authenticates a
user at an external IdP and then issues a NORMAL M10a local session -- OIDC is a
login method, not a new bearer type (ADR-008). See :mod:`.service` for the flow,
:mod:`.config` for the provider config, :mod:`.discovery` for provider metadata,
and :mod:`.pkce` for the pure (stdlib-only) PKCE/CSRF helpers.

``OidcService`` / ``AuthorizationRedirect`` pull in ``httpx`` (the ``[api]``
extra), so they are re-exported LAZILY (PEP 562): importing this package -- or the
stdlib-only :mod:`.pkce` / :mod:`.config` submodules -- never requires ``httpx``
or the ``[oidc]`` extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .config import (
    ALLOWED_ID_TOKEN_ALGORITHMS,
    OidcConfigurationError,
    OidcProviderConfig,
)
from .errors import OidcAuthError

if TYPE_CHECKING:  # for type checkers only; not executed at runtime
    from .service import AuthorizationRedirect, OidcService

_LAZY = frozenset({"AuthorizationRedirect", "OidcService"})

__all__ = [
    "ALLOWED_ID_TOKEN_ALGORITHMS",
    "AuthorizationRedirect",
    "OidcAuthError",
    "OidcConfigurationError",
    "OidcProviderConfig",
    "OidcService",
]


def __getattr__(name: str):
    """Lazily resolve the httpx-backed service names (PEP 562) so importing this
    package never requires ``httpx`` / the ``[oidc]`` extra."""
    if name in _LAZY:
        from . import service

        return getattr(service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
