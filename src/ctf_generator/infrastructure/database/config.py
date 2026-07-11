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
    """Connection settings for the control-plane database."""

    url: str
    echo: bool = False
    pool_pre_ping: bool = True

    @classmethod
    def from_env(cls, env_var: str = DEFAULT_URL_ENV) -> "DatabaseConfig":
        url = os.environ.get(env_var)
        if not url:
            raise DatabaseConfigError(
                f"{env_var} is not set; the control plane requires a database DSN"
            )
        return cls(
            url=url,
            echo=os.environ.get("CTFGEN_DB_ECHO") == "1",
        )
