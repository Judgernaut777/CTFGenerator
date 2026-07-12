"""API configuration object.

Framework-light settings for the app factory: metadata, CORS, and rate-limit
knobs. Kept as a frozen dataclass (not env-magic) so tests construct it directly;
the production entrypoint builds one from the environment in :mod:`app`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ApiSettings:
    title: str = "CTFGenerator Control-Plane API"
    version: str = "0.1.0"
    root_path: str = ""
    cors_allow_origins: tuple[str, ...] = field(default_factory=tuple)
    # Rate limiting (token bucket). Disabled by default so the unit/OpenAPI
    # suites and local use are unthrottled; the integration/production configs
    # enable it. ``rate`` is tokens/second, ``burst`` the bucket capacity.
    rate_limit_enabled: bool = False
    rate_limit_rate: float = 10.0
    rate_limit_burst: int = 20
