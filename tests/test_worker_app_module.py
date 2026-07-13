"""M18 18a: the module-level ``worker_app`` (separate worker-gateway listener).

Proves, WITHOUT a live database (best-effort/lazy import), that
``ctf_generator.interfaces.api.worker_app:worker_app`` is an ASGI app mounting
ONLY the worker-gateway routes -- no human resource routers (/competitions,
/teams, ...), no /auth -- so a production deployment can serve the worker plane on
its own socket, network-isolated from the human control plane. Also asserts the
main ``app`` is unaffected.

Skips cleanly without the ``[api]`` extra (fastapi/uvicorn), exactly like the
other API-surface tests.

    PYTHONPATH=src:tests python -m unittest test_worker_app_module
"""

from __future__ import annotations

import os
import unittest

try:  # the [api] extra
    import fastapi  # noqa: F401

    _HAVE_API = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _HAVE_API = False


@unittest.skipUnless(_HAVE_API, "requires the [api] extra (fastapi)")
class WorkerAppModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        # Guarantee the LAZY/best-effort DB path: no DSN in the environment, so
        # importing the module must NOT require (or crash on) a live database.
        self._saved = os.environ.pop("CTFGEN_DATABASE_URL", None)

    def tearDown(self) -> None:
        if self._saved is not None:
            os.environ["CTFGEN_DATABASE_URL"] = self._saved

    def _paths(self, app) -> set[str]:
        # This FastAPI version keeps included routers lazily (``_IncludedRouter``
        # wrappers with no flat ``.path``), so enumerate the real operation paths
        # from the generated OpenAPI schema -- the authoritative route surface.
        return set(app.openapi()["paths"])

    def test_worker_app_imports_without_a_database(self) -> None:
        # The import itself must succeed with no DSN configured (lazy/best-effort).
        from ctf_generator.interfaces.api.worker_app import worker_app

        self.assertIsNotNone(worker_app)
        # Its database collaborator resolved to None (not configured) rather than
        # raising -- the boot-without-DB guarantee.
        self.assertIsNone(worker_app.state.database)

    def test_worker_app_mounts_only_the_worker_gateway(self) -> None:
        from ctf_generator.interfaces.api.worker_app import worker_app

        paths = self._paths(worker_app)
        # Assert the FULL route surface is worker-only (minus FastAPI's docs/openapi
        # meta) -- NOT just the /api/v1/-prefixed subset. A human router added at a
        # non-/api/v1 prefix (e.g. /auth or the /app web UI) must ALSO be caught, or
        # a human surface could silently leak onto the network-isolated worker plane.
        _META = ("/api/v1/openapi.json", "/api/v1/docs", "/api/v1/redoc",
                 "/docs", "/redoc", "/openapi.json")
        business = [p for p in paths if p not in _META and not p.startswith("/api/v1/docs")]
        self.assertTrue(business, "expected at least the worker routes")
        for path in business:
            self.assertTrue(
                path.startswith("/api/v1/worker/"),
                f"non-worker route leaked onto the worker app: {path}",
            )
        # And the specific worker verbs exist.
        self.assertIn("/api/v1/worker/auth", paths)
        self.assertIn("/api/v1/worker/jobs/claim", paths)

    def test_worker_app_excludes_human_resource_routers(self) -> None:
        from ctf_generator.interfaces.api.worker_app import worker_app

        paths = self._paths(worker_app)
        for forbidden in (
            "/api/v1/competitions",
            "/api/v1/teams",
            "/api/v1/auth/login",
            "/api/v1/challenge-definitions",
        ):
            self.assertNotIn(
                forbidden,
                paths,
                f"human resource route {forbidden} must NOT be on the worker app",
            )

    def test_main_app_unaffected_and_still_has_resource_routers(self) -> None:
        from ctf_generator.interfaces.api.app import app

        paths = self._paths(app)
        # The main app keeps its human surface AND (for the single-host path) the
        # worker routes -- importing worker_app changes nothing about it.
        self.assertIn("/api/v1/competitions", paths)
        self.assertIn("/api/v1/worker/auth", paths)


if __name__ == "__main__":
    unittest.main()
