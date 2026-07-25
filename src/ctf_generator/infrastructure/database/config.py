"""Database configuration, sourced from the environment.

Secrets (the DSN, which embeds credentials) come from an env var, never a
committed config record -- consistent with docs/security/secret-management.md.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_URL_ENV = "CTFGEN_DATABASE_URL"


class DatabaseConfigError(RuntimeError):
    """Raised when required database configuration is missing."""


@dataclass(frozen=True)
class DatabaseConfig:
    """Connection settings for the control-plane database.

    ``pool_size`` / ``max_overflow`` size the SQLAlchemy ``QueuePool``. The
    library defaults (5 + 10 = 15) starve a multi-threaded API server under load
    -- with ~29 concurrent request threads (a 25-team scoreboard surge) most
    threads block waiting for a CONNECTION before they can even begin work, which
    serializes requests independently of any row/advisory lock. The defaults here
    (20 + 20 = 40 total) comfortably clear that concurrency; both are env-tunable
    for a deployment that sizes them to its PostgreSQL ``max_connections``.
    """

    url: str
    echo: bool = False
    pool_pre_ping: bool = True
    pool_size: int = 20
    max_overflow: int = 20

    @classmethod
    def from_env(cls, env_var: str = DEFAULT_URL_ENV) -> DatabaseConfig:
        url = os.environ.get(env_var)
        if not url:
            raise DatabaseConfigError(
                f"{env_var} is not set; the control plane requires a database DSN"
            )
        return cls(
            url=url,
            echo=os.environ.get("CTFGEN_DB_ECHO") == "1",
            pool_size=_int_env("CTFGEN_DB_POOL_SIZE", 20),
            max_overflow=_int_env("CTFGEN_DB_MAX_OVERFLOW", 20),
        )


def _int_env(name: str, default: int) -> int:
    """A non-negative int from the environment, falling back to ``default`` for an
    unset or malformed value (a misconfigured pool size never crashes startup)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default
