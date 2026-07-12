"""The ``ctfgen <area> <verb>`` platform dispatcher (M13 slice 13a).

This is the SUPPORTED platform CLI: it talks to the platform HTTP API with a
session bearer token (never the database). Slice 13a ships the ``auth`` area:

* ``ctfgen auth login``  -- authenticate and store a 0600 session (no token echo).
* ``ctfgen auth logout`` -- revoke the session server-side and clear it locally
  (idempotent).
* ``ctfgen auth whoami`` -- show the current principal (subject, roles,
  memberships).

Global options (per verb): ``--api-url`` (env ``CTFGEN_API_URL``, default
``http://127.0.0.1:8000``) and ``--json``. A CI escape-hatch bearer token is read
from ``$CTFGEN_API_TOKEN`` (env ONLY -- there is no ``--token`` flag, because a
token on the command line leaks via ``ps``/shell history, exactly like a
password). The password is likewise taken from ``$CTFGEN_PASSWORD`` or an
interactive ``getpass`` prompt, NEVER a flag, NEVER echoed, NEVER logged.

Origin safety: when a command uses the STORED session token (no
``$CTFGEN_API_TOKEN`` override), an explicit ``--api-url`` that differs from the
origin the session was issued for is REFUSED -- the stored bearer is never sent
to a different host (it would exfiltrate a live credential).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import output
from .client import ApiClient, build_http_client
from .commands import AREA_NAMES, register_all
from .commands._common import add_global_options as _add_global_options
from .commands._common import guard_stored_origin as _guard_stored_origin
from .commands._common import resolve_api_url as _resolve_api_url
from .commands._common import token_override as _token_override
from .config import Session, TokenStore
from .errors import CliError, run

_TOKEN_ENV = "CTFGEN_API_TOKEN"  # noqa: S105 - env var name, not a secret
_PASSWORD_ENV = "CTFGEN_PASSWORD"  # noqa: S105 - env var name, not a secret

# The ``auth`` area (slice 13a) plus every resource area (slice 13b). MUST stay in
# sync with ``entry._PLATFORM_AREAS`` (the first-token dispatch set).
PLATFORM_AREAS = frozenset({"auth"}) | AREA_NAMES


def _store() -> TokenStore:
    return TokenStore()


# -- auth commands -----------------------------------------------------------


def _cmd_login(args: argparse.Namespace) -> int:
    store = _store()
    api_url = _resolve_api_url(args)
    email = args.email or _prompt("Email: ")
    if not email:
        raise CliError("an email is required to log in")
    password = os.environ.get(_PASSWORD_ENV) or getpass.getpass("Password: ")
    if not password:
        raise CliError("a password is required to log in")

    http = build_http_client(api_url)
    try:
        # Login is unauthenticated; a wrong password surfaces as an ApiError
        # (invalid credentials), NOT AuthRequired.
        issued = ApiClient(http, store, api_url).request(
            "POST", "/auth/login",
            json={"email": email, "password": password},
            authed=False,
        )
        token = issued["token"]
        expires_at = issued.get("expires_at")
        # Resolve the real subject via /auth/me using the freshly issued token
        # (an in-memory override -- the session is not persisted until we have
        # the subject).
        me = ApiClient(http, store, api_url, token_override=token).request(
            "GET", "/auth/me"
        )
        subject = me.get("subject", email)
        store.save(
            Session(
                api_url=api_url,
                token=token,
                expires_at=expires_at,
                subject=subject,
            )
        )
    finally:
        http.close()
    # NEVER print the token.
    print(f"logged in to {api_url} as {subject}")
    return 0


def _cmd_logout(args: argparse.Namespace) -> int:
    store = _store()
    stored = store.load()
    override = _token_override(args)
    if stored is None and override is None:
        print("not logged in")
        return 0
    api_url = _resolve_api_url(args, stored=stored)
    # Never ship the stored (still-valid) token to a mismatched --api-url.
    _guard_stored_origin(args, stored, override, api_url)
    http = build_http_client(api_url)
    try:
        client = ApiClient(http, store, api_url, token_override=override)
        try:
            client.request("POST", "/auth/logout")
        except CliError:
            # The token may already be invalid/expired server-side; the local
            # clear below still makes logout effective and idempotent.
            pass
    finally:
        http.close()
    store.clear()
    print("logged out")
    return 0


def _cmd_whoami(args: argparse.Namespace) -> int:
    store = _store()
    stored = store.load()
    override = _token_override(args)
    api_url = _resolve_api_url(args, stored=stored)
    _guard_stored_origin(args, stored, override, api_url)
    http = build_http_client(api_url)
    try:
        client = ApiClient(http, store, api_url, token_override=override)
        me = client.request("GET", "/auth/me")
    finally:
        http.close()
    if args.json:
        output.print_resource(me, as_json=True)
        return 0
    summary = {
        "subject": me.get("subject", ""),
        "system_roles": me.get("system_roles", []),
        "memberships": me.get("memberships", []),
    }
    output.print_resource(summary, as_json=False)
    return 0


def _prompt(label: str) -> str:  # pragma: no cover - interactive
    if not sys.stdin.isatty():
        return ""
    try:
        return input(label).strip()
    except EOFError:
        return ""


# -- parser + entry ----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfgen",
        description="CTFGenerator platform CLI (talks to the platform HTTP API).",
    )
    areas = parser.add_subparsers(dest="area", required=True)

    auth = areas.add_parser("auth", help="Authenticate against the platform API.")
    verbs = auth.add_subparsers(dest="auth_command", required=True)

    login = verbs.add_parser("login", help="Log in and store a session.")
    login.add_argument("--email", default=None, help="Account email (prompted if omitted)")
    _add_global_options(login)
    login.set_defaults(func=_cmd_login)

    logout = verbs.add_parser("logout", help="Revoke and clear the stored session.")
    _add_global_options(logout)
    logout.set_defaults(func=_cmd_logout)

    whoami = verbs.add_parser("whoami", help="Show the current principal.")
    _add_global_options(whoami)
    whoami.set_defaults(func=_cmd_whoami)

    # Resource areas (slice 13b): competition/team/user/challenge-def/...
    register_all(areas)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(lambda: args.func(args))
