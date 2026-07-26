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


_DEFAULT_WORKER_CAPS = (
    "build_challenge",
    "launch_instance",
    "stop_instance",
    "delete_runtime_resources",
)


def _enroll_worker(args: argparse.Namespace) -> int:
    """Register + approve a worker and print its scoped bearer token ONCE.

    Closes the operator gap that otherwise leaves worker enrollment test-only: a
    real deployment needs a way to mint the scoped token the worker host presents
    to the gateway. Registration persists a pending identity; approval flips trust
    and issues the first credential in one unit of work (WorkerEnrollmentService).
    The token is a SECRET shown exactly once on stdout -- store it in the worker
    host's secrets manager (CTFGEN_WORKER_TOKEN); it is never logged."""
    import platform

    from ctf_generator.application.worker_enrollment import WorkerEnrollmentService
    from ctf_generator.domain.execution.models import (
        CREDENTIAL_TOKEN_PREFIX,
        Worker,
    )

    try:
        database = Database(DatabaseConfig.from_env())
    except DatabaseConfigError as exc:
        raise SystemExit(f"database not configured: {exc}") from exc
    architectures = tuple(
        a.strip() for a in (args.architectures or platform.machine()).split(",") if a.strip()
    )
    capabilities = tuple(
        c.strip() for c in args.capabilities.split(",") if c.strip()
    )
    try:
        service = WorkerEnrollmentService(database)
        service.register_worker(
            Worker(
                name=args.name,
                runtime_type=args.runtime_type,
                architectures=architectures,
                capabilities=capabilities,
                capacity=args.capacity,
                version=args.version,
            )
        )
        issued = service.approve_worker(args.name, datetime.now(UTC))
    finally:
        database.dispose()
    token = f"{CREDENTIAL_TOKEN_PREFIX}.{issued.credential_id}.{issued.secret}"
    # The token is printed to STDOUT only (never the logger). Keep it out of shell
    # history / logs on the operator side.
    print(f"enrolled worker {args.name!r} (architectures={','.join(architectures)})")
    print(f"CTFGEN_WORKER_TOKEN={token}")
    print("store this token now; it is shown only once and cannot be recovered.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfgen-admin",
        description="Operator bootstrap for the CTFGenerator control plane.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser(
        "enroll-worker",
        help="Register + approve a worker and print its scoped bearer token once.",
    )
    enroll.add_argument("--name", required=True, help="unique worker name")
    enroll.add_argument(
        "--runtime-type", dest="runtime_type", default="docker-rootless",
        help="engine label (default docker-rootless)",
    )
    enroll.add_argument(
        "--architectures", default=None,
        help="comma-separated (default: this host's machine arch)",
    )
    enroll.add_argument(
        "--capabilities", default=",".join(_DEFAULT_WORKER_CAPS),
        help="comma-separated worker capabilities",
    )
    enroll.add_argument("--capacity", type=int, default=4, help="max concurrent jobs")
    enroll.add_argument("--version", default="1", help="worker build version")
    enroll.set_defaults(func=_enroll_worker)
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
