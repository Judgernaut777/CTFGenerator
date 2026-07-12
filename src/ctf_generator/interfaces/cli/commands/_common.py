"""Shared plumbing for the ``ctfgen <area> <verb>`` platform command groups
(M13 slice 13b).

This module is the SINGLE source of the per-verb wiring every area repeats:

* :func:`add_global_options` -- the ``--api-url`` / ``--json`` options on every
  verb (identical to the ``auth`` area in slice 13a).
* :func:`resolve_api_url` / :func:`token_override` / :func:`guard_stored_origin`
  -- the API-URL resolution + credential-exfiltration guard (a stored session
  bearer is never sent to an origin other than the one it was issued for).
* :func:`open_client` -- a context manager that resolves the target, applies the
  origin guard, builds the injected :class:`httpx.Client`, and yields a ready
  :class:`~..client.ApiClient`, closing the transport on exit.
* :func:`idempotency_key` -- ``--idempotency-key`` if pinned, else a fresh
  ``uuid4`` per invocation (a re-run WITHOUT a pinned key is a NEW request).

``platform.py`` imports the resolution helpers from here so the ``auth`` area and
these areas share one implementation; the command modules import
:func:`open_client` / :func:`add_global_options` / :func:`idempotency_key`.
Nothing here imports ``platform`` -- so there is no import cycle with the
dispatcher that registers the areas.
"""

from __future__ import annotations

import argparse
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from ..client import ApiClient, build_http_client
from ..config import Session, TokenStore
from ..errors import CliError

DEFAULT_API_URL = "http://127.0.0.1:8000"
API_URL_ENV = "CTFGEN_API_URL"
TOKEN_ENV = "CTFGEN_API_TOKEN"  # noqa: S105 - env var name, not a secret


def add_global_options(parser: argparse.ArgumentParser) -> None:
    """Attach the options every platform verb accepts. There is deliberately NO
    ``--token`` flag: a bearer on argv leaks via ``ps`` / shell history; the CI
    escape hatch is the ``CTFGEN_API_TOKEN`` env var only."""
    parser.add_argument(
        "--api-url",
        default=None,
        help=f"Platform API base URL (env {API_URL_ENV}, default {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw JSON instead of a table",
    )


def add_idempotency_option(parser: argparse.ArgumentParser) -> None:
    """Attach ``--idempotency-key`` to a mutating verb whose route honours it."""
    parser.add_argument(
        "--idempotency-key",
        default=None,
        help=(
            "Reuse this key so a retry replays the first result; omitted => a "
            "fresh key per run (a re-run is then a NEW request)"
        ),
    )


def token_override(args: argparse.Namespace) -> str | None:  # noqa: ARG001
    # Env-only (never argv): a CI token supplied out-of-band, bypassing the
    # stored session. Its holder chose the target explicitly -> no origin guard.
    return os.environ.get(TOKEN_ENV)


def resolve_api_url(
    args: argparse.Namespace, *, stored: Session | None = None
) -> str:
    """Resolve the API URL: explicit ``--api-url`` wins, then the stored
    session's origin, then ``$CTFGEN_API_URL``, then the built-in default."""
    if args.api_url:
        return args.api_url.rstrip("/")
    if stored is not None and stored.api_url:
        return stored.api_url.rstrip("/")
    return os.environ.get(API_URL_ENV, DEFAULT_API_URL).rstrip("/")


def guard_stored_origin(
    args: argparse.Namespace,
    stored: Session | None,
    override: str | None,
    api_url: str,
) -> None:
    """Refuse to send the STORED session bearer to an origin other than the one
    it was issued for. Only applies when the stored token is what will be sent
    (no env override) and an explicit ``--api-url`` differs from that origin."""
    if override is not None or stored is None or not args.api_url:
        return
    if api_url.rstrip("/") != (stored.api_url or "").rstrip("/"):
        raise CliError(
            f"the stored session is for {stored.api_url}; refusing to send it to "
            f"{api_url}. Run 'ctfgen auth login --api-url {api_url}' there first, "
            f"or supply {TOKEN_ENV} for that host."
        )


@contextmanager
def open_client(args: argparse.Namespace) -> Iterator[ApiClient]:
    """Yield a ready :class:`ApiClient` for one command invocation, applying the
    origin guard and closing the HTTP transport on exit. ``build_http_client`` is
    referenced through this module so a test can patch it in-process."""
    store = TokenStore()
    stored = store.load()
    override = token_override(args)
    api_url = resolve_api_url(args, stored=stored)
    guard_stored_origin(args, stored, override, api_url)
    http = build_http_client(api_url)
    try:
        yield ApiClient(http, store, api_url, token_override=override)
    finally:
        http.close()


def idempotency_key(args: argparse.Namespace) -> str:
    """The Idempotency-Key to send: the pinned ``--idempotency-key`` if given,
    else a fresh ``uuid4`` for THIS invocation."""
    pinned = getattr(args, "idempotency_key", None)
    return pinned or str(uuid.uuid4())
