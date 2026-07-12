"""Typed CLI errors + the top-level ``run`` wrapper (M13 slice 13a).

The supported platform CLI talks to the PLATFORM HTTP API. Every failure the
user should see is one of these typed errors, so the dispatcher can print a
single clean line to stderr and pick a stable exit code -- NEVER a traceback,
and NEVER the bearer token or the password.

Exit codes (stable, scriptable):

* ``0``  -- success (returned by the commands, not here).
* ``1``  -- a general failure (an :class:`ApiError`, a connection failure, or
  any other :class:`CliError`).
* ``2``  -- a usage error (argparse handles this itself via ``SystemExit(2)``).
* ``3``  -- authentication is required / has expired (:class:`AuthRequired`);
  a distinct code so ``ctfgen ... || [ $? -eq 3 ] && ctfgen login`` scripts work.
"""

from __future__ import annotations

EXIT_GENERAL = 1
EXIT_USAGE = 2
EXIT_AUTH_REQUIRED = 3


class CliError(Exception):
    """Base class for every user-facing CLI failure.

    ``exit_code`` is the process exit status the :func:`run` wrapper returns.
    Subclasses/messages MUST NOT carry a token or a password.
    """

    exit_code = EXIT_GENERAL


class ApiError(CliError):
    """A structured ``ctfgen.error`` envelope returned by the API.

    Carries the machine-readable ``code`` and the ``request_id`` (for support
    correlation) alongside the sanitized ``message`` and HTTP ``status_code``.
    The API guarantees the message/detail never contain secrets; this type only
    ever holds what the envelope carried, so it is safe to print.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int,
        request_id: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.request_id = request_id
        super().__init__(message)

    def __str__(self) -> str:
        parts = [f"{self.message} ({self.code})"]
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        return " ".join(parts)


class ApiUnreachable(CliError):
    """The API could not be reached at all (connection refused / timeout).

    Raised by the client (which knows the configured origin) so the message can
    name the URL the user should check -- e.g. a stopped server or a wrong
    ``--api-url``. Carries no request data.
    """


class AuthRequired(CliError):
    """No usable session: the caller must run ``ctfgen auth login`` first.

    Raised when an authenticated request is rejected (401) and a single silent
    token refresh could not recover it, or when no session is stored at all.
    """

    exit_code = EXIT_AUTH_REQUIRED

    def __init__(self, message: str = "not authenticated -- run: ctfgen auth login") -> None:
        super().__init__(message)


def run(func, *, stderr=None) -> int:
    """Invoke ``func()`` and translate any :class:`CliError` (or a connection
    failure) into a clean one-line stderr message + a stable exit code.

    A traceback, the token, and the password NEVER reach the user here: only the
    typed error's own sanitized ``str()`` is printed. Any UNEXPECTED exception is
    NOT swallowed (it propagates so a real bug surfaces in development / is logged
    by the caller) -- this wrapper is for the known, user-facing failure modes.
    """
    import sys

    stream = stderr if stderr is not None else sys.stderr
    try:
        return int(func())
    except CliError as exc:
        # Covers AuthRequired / ApiError / ApiUnreachable and any other typed
        # CLI failure. Each carries a sanitized str() and its own exit code.
        print(f"error: {exc}", file=stream)
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover - interactive interrupt
        print("aborted", file=stream)
        return EXIT_GENERAL
