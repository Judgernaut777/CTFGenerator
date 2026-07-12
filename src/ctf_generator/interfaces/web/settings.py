"""Web-UI configuration (M11 slice a).

A frozen dataclass carrying the cookie + CSRF knobs so tests construct it directly
and the production entrypoint builds one from the environment. It holds a
process-lifetime CSRF signing secret and the session cookie name / attributes.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

# The session cookie carrying the opaque M10 session token. httpOnly so JS can
# never read it, Secure so it is only sent over TLS, SameSite=Lax so it rides
# top-level navigations (the login redirect) but not cross-site sub-requests.
SESSION_COOKIE_NAME = "ctfgen_web_session"

# The form field + hidden-input name for the signed CSRF token.
CSRF_FIELD_NAME = "csrf_token"  # noqa: S105 - a field NAME, not a secret value

# Pre-session (login) CSRF: a plain double-submit token. Because no session exists
# yet at the login POST, the session-bound CSRF above cannot protect it, so the
# login form uses a random token echoed in BOTH a cookie and a hidden field.
LOGIN_CSRF_COOKIE_NAME = "ctfgen_web_login_csrf"  # noqa: S105 - a cookie NAME
LOGIN_CSRF_FIELD_NAME = "login_csrf_token"  # noqa: S105 - a field NAME


@dataclass(frozen=True)
class WebSettings:
    """Configuration for the organizer web sub-app."""

    # The mount prefix the sub-app is served under (used to build cookie Path and
    # login-redirect targets). Kept in sync with :func:`mount_web_app`.
    mount_path: str = "/app"
    # The session cookie's ``Secure`` attribute. TRUE by default (production is
    # HTTPS-only); a plain-HTTP local dev deployment may set it False, but the
    # tests exercise the secure path over an https test base_url.
    cookie_secure: bool = True
    cookie_name: str = SESSION_COOKIE_NAME
    # The HMAC key that signs CSRF tokens. Process-lifetime by default (a restart
    # invalidates outstanding CSRF tokens, which is acceptable -- the SESSION
    # survives; the next rendered form carries a fresh valid token). Never logged.
    csrf_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @classmethod
    def from_env(cls) -> WebSettings:
        secret_env = os.environ.get("CTFGEN_WEB_CSRF_SECRET")
        secret = (
            secret_env.encode("utf-8") if secret_env else secrets.token_bytes(32)
        )
        return cls(
            cookie_secure=os.environ.get("CTFGEN_WEB_COOKIE_INSECURE", "0") != "1",
            csrf_secret=secret,
        )
