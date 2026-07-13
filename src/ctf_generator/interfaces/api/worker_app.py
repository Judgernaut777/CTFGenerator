"""Module-level ASGI app for the SEPARATE worker-gateway listener (M18 18a).

``uvicorn ctf_generator.interfaces.api.worker_app:worker_app`` serves ONLY the
worker-facing gateway -- the trust plane a REMOTE worker drives -- on its own
listener, network-isolated from the human control-plane API (``app.py``:``app``).
This is the production-recommended shape: the two disjoint auth planes (human
``Principal`` bearer vs. scoped worker credential) also become two separate
sockets, so a human token can never reach a worker route and vice versa.

Built from the SAME environment pattern as the module-level ``app``: the database
(and thus the durable audit sink) is best-effort/lazy -- a missing DSN yields a
``None`` database so the module still IMPORTS and the process still BOOTS (worker
routes then answer a clean error until the DB is configured), never a crash on
import. ``create_worker_app`` itself is unchanged; this module only supplies the
env-built collaborators, exactly like ``app.py`` does for ``app``.
"""

from __future__ import annotations

import os

from .app import _database_from_env, create_worker_app
from .settings import ApiSettings

# Best-effort database (None when CTFGEN_DATABASE_URL is unset -- import/boot must
# never require a live DB; the worker routes surface a clear error until it is).
_module_database = _database_from_env()

# Rate limiting defaults ON here too (opt-OUT via CTFGEN_API_RATE_LIMIT=0) so the
# shipped worker listener is never unthrottled; trust_forwarded_for follows the
# same trusted-proxy gate as the main app.
worker_app = create_worker_app(
    ApiSettings(
        rate_limit_enabled=os.environ.get("CTFGEN_API_RATE_LIMIT", "1") != "0",
        trust_forwarded_for=os.environ.get("CTFGEN_API_TRUSTED_PROXY", "0") == "1",
    ),
    database=_module_database,
)
