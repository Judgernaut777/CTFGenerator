"""``ctfgen-admin`` -- operator bootstrap for the auth plane (M10 slice a).

Solves the chicken-and-egg lockout: the API authenticates every request against
a real credential, so the FIRST admin credential must be seeded out-of-band. This
console entry does exactly that, idempotently, WITHOUT ever embedding a default
password.

    ctfgen-admin bootstrap-admin --email admin@example.com --display-name "Admin"

The password is taken (in priority order) from ``--password``, then the
``CTFGEN_BOOTSTRAP_ADMIN_PASSWORD`` environment variable, then an interactive
prompt (``getpass``, never echoed). The database DSN comes from
``CTFGEN_DATABASE_URL`` (same as the API). Re-running is a safe no-op: it ensures
the user + the ``admin`` system role exist and sets the password ONLY if no
credential exists yet -- it never resets an existing password. No password is
ever logged.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import UTC, datetime

from ctf_generator.application.auth import AuthService
from ctf_generator.infrastructure.database.config import (
    DatabaseConfig,
    DatabaseConfigError,
)
from ctf_generator.infrastructure.database.session import Database

_PASSWORD_ENV = "CTFGEN_BOOTSTRAP_ADMIN_PASSWORD"  # noqa: S105 - env var name


def _resolve_password(explicit: str | None) -> str:
    """Resolve the bootstrap password without ever hardcoding a default.

    Priority: ``--password`` > ``CTFGEN_BOOTSTRAP_ADMIN_PASSWORD`` > interactive
    prompt. Never printed."""
    if explicit:
        return explicit
    from_env = os.environ.get(_PASSWORD_ENV)
    if from_env:
        return from_env
    if not sys.stdin.isatty():  # pragma: no cover - non-interactive guard
        raise SystemExit(
            "no password supplied: pass --password, set "
            f"{_PASSWORD_ENV}, or run interactively"
        )
    return getpass.getpass("New admin password: ")  # pragma: no cover - interactive


def _bootstrap_admin(args: argparse.Namespace) -> int:
    try:
        database = Database(DatabaseConfig.from_env())
    except DatabaseConfigError as exc:
        raise SystemExit(f"database not configured: {exc}") from exc
    try:
        service = AuthService(database)
        password = _resolve_password(args.password)
        created = service.bootstrap_admin(
            email=args.email,
            display_name=args.display_name,
            password=password,
            now=datetime.now(UTC),
        )
    finally:
        database.dispose()
    if created:
        print(f"seeded admin credential for {args.email}")
    else:
        print(
            f"admin {args.email} already has a credential; ensured user + admin "
            "role (password unchanged)"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfgen-admin",
        description="Operator bootstrap for the CTFGenerator control plane.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser(
        "bootstrap-admin",
        help="Idempotently seed the first admin credential + system role.",
    )
    bootstrap.add_argument("--email", required=True)
    bootstrap.add_argument("--display-name", required=True, dest="display_name")
    bootstrap.add_argument(
        "--password",
        default=None,
        help=(
            "Admin password. If omitted, taken from "
            f"{_PASSWORD_ENV} or an interactive prompt. Never a default."
        ),
    )
    bootstrap.set_defaults(func=_bootstrap_admin)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
