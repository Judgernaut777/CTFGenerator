"""The worker-facing, scope-gated surface over the FULL build bundle
(``docs/architecture/build-challenge-worker-pipeline.md``).

Mirrors :class:`~ctf_generator.application.execution.worker_job_service.WorkerJobService`'s
authenticate-then-act shape: a bad/expired/revoked/non-trusted/quarantined
credential fails identically (reuses THE SAME
:class:`~ctf_generator.application.execution.worker_job_service.WorkerAuthenticationError`
class, so the app-wide ``ctfgen.error`` 401 handler -- already registered for
it -- covers this verb with no additional wiring), and the ``artifacts:pull``
scope (reserved in ``VALID_CREDENTIAL_SCOPES`` since M8, previously unwired) is
required.

NOT liveness-gated, matching ``WorkerJobService.complete``/``.fail``: a worker
mid-lease fetching the bundle for a ``build_challenge`` job it already holds
must be accepted regardless of heartbeat age -- refusing it here would strand
the job without ever reaching a queue verb that could report the failure.
Permitted while draining (finish in-flight work), for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ctf_generator.application.authoring.full_bundle import FullBundleService
from ctf_generator.application.execution.worker_job_service import (
    WorkerAuthenticationError,
)
from ctf_generator.application.worker_enrollment import (
    WorkerEnrollmentService,
    require_scope,
)
from ctf_generator.infrastructure.database.session import Database

_ARTIFACTS_PULL_SCOPE = "artifacts:pull"


@dataclass(frozen=True)
class BuildBundleView:
    """The wire-agnostic result of a bundle fetch -- carried into both
    ``LocalControlPlaneClient`` (used directly) and the HTTP response (mapped
    onto bytes + headers by the worker-gateway router). May embed the
    flag/solution -- NEVER log ``data``."""

    data: bytes
    bundle_sha256: str
    spec_sha256: str


class WorkerBuildService:
    """Authenticated, ``artifacts:pull``-scoped worker access to a version's
    FULL buildable bundle. Never reachable without a valid worker credential;
    never exposes anything beyond what :class:`FullBundleService` renders."""

    def __init__(
        self,
        database: Database,
        enrollment: WorkerEnrollmentService,
        *,
        full_bundles: FullBundleService | None = None,
    ) -> None:
        self._enrollment = enrollment
        self._full_bundles = full_bundles if full_bundles is not None else FullBundleService(database)

    def fetch_build_bundle(
        self, token: str, definition_slug: str, version_no: int, now: datetime
    ) -> BuildBundleView:
        """Authenticate ``token``, require ``artifacts:pull``, and render the
        FULL bundle for ``(definition_slug, version_no)``. Raises
        :class:`WorkerAuthenticationError` (401) for a bad credential,
        :class:`~ctf_generator.application.worker_enrollment.ScopeError` (403)
        for a credential missing the scope, and :class:`LookupError` (404) for
        an unknown version -- the same error vocabulary every other worker verb
        uses."""
        auth = self._enrollment.authenticate(token, now)
        if auth is None:
            raise WorkerAuthenticationError("worker authentication failed")
        require_scope(auth, _ARTIFACTS_PULL_SCOPE)
        bundle = self._full_bundles.render(definition_slug, version_no)
        return BuildBundleView(
            data=bundle.data,
            bundle_sha256=bundle.bundle_sha256,
            spec_sha256=bundle.spec_sha256,
        )
