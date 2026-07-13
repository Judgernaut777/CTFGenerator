"""Single-host :class:`~ctf_generator.workers.worker.EvalJobRunner` (M15b).

WORKER-SIDE / EFFECTFUL. This is the effectful arm of a ``run_agent_evaluation``
job. It is the DOCUMENTED single-host path -- the exact analogue of
:class:`~ctf_generator.workers.local_client.LocalControlPlaneClient`: the worker
shares a host AND a database with the control plane, so it can

1. load the published :class:`ChallengeVersion` from the DB,
2. reconstruct the ``ChallengeSpec`` and RENDER the FULL bundle in-process (RENDER
   is pure deterministic TEXT -- ADR-001 permits it on any process, exactly as
   ``BuildMaterializationService`` renders the public bundle), then
3. run ``agent_eval`` against the rendered bundle, which BUILDS and RUNS the
   challenge image via Docker ON THIS HOST (``already_running=False``) and tears
   it down.

DISTRIBUTED DEPENDENCY (honest, not faked). A fully distributed worker -- a
separate host with no control-plane DB credential -- cannot use this runner: it
would need the FULL bundle delivered to it and the challenge image built via the
``build_challenge`` worker pipeline, which is NOT YET BUILT. Until then only the
single-host runner can execute an eval; a networked worker leaves ``eval_runner``
unset and the dispatch reports an advisory "runner not configured" failure. See
``docs/evaluation/eval-worker-limitations.md`` and the ``workers.worker`` module
docstring.

CONTROL-PLANE PURITY. ``agent_eval`` is imported LAZILY inside :meth:`run`, so
merely importing THIS module never pulls the effectful eval engine onto any
import graph -- the ``mcp_server`` import firewall and the domain-boundary tests
stay green regardless of who imports it. The worker (``workers.worker``) never
imports this module at top level either; the single-host wiring constructs it.
"""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

from ctf_generator import generator as _generator_module
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.spec_generator import spec_from_dict


class SingleHostEvalJobRunner:
    """Render a published version's full bundle + run the Docker agent eval.

    ``generator`` is injectable (defaults to the real generator module, whose
    ``create_challenge`` is pure text rendering) so a unit test can supply a
    rendering double; ``base_url``/``timeout_seconds`` tune the Docker leg.
    """

    def __init__(
        self,
        database: Database,
        *,
        generator: object | None = None,
        base_url: str = "http://127.0.0.1:8080",
        timeout_seconds: int = 90,
    ) -> None:
        self._database = database
        self._generator = generator if generator is not None else _generator_module
        self._base_url = base_url
        self._timeout_seconds = timeout_seconds

    def run(
        self,
        *,
        definition_slug: str,
        version_no: int,
        profile: str,
        adversarial: bool,
        now: datetime,
    ):
        # LAZY import: the effectful eval engine (Docker/subprocess/HTTP) is pulled
        # in only when an eval actually runs, never at module import.
        from ctf_generator import agent_eval

        with self._database.session_scope() as session:
            version = SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            )
        if version is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        if version.state != "published":
            raise ValueError(
                f"challenge version {definition_slug!r} v{version_no} is "
                f"{version.state!r}, not published; cannot evaluate"
            )
        spec = spec_from_dict(dict(version.spec))

        with tempfile.TemporaryDirectory(prefix="ctfgen-eval-") as tmp_dir:
            bundle_root = Path(tmp_dir) / "bundle"
            # Render the FULL bundle (NOT stripped to public/): the worker needs
            # private/ + the compose stack to BUILD and RUN the challenge services.
            self._generator.create_challenge(
                output_dir=bundle_root,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                force=True,
                spec=spec,
            )
            if adversarial:
                return agent_eval.run_adversarial_delta(
                    bundle_root,
                    profile,
                    base_url=self._base_url,
                    timeout_seconds=self._timeout_seconds,
                    already_running=False,
                )
            return agent_eval.run_agent_eval(
                bundle_root,
                profile,
                base_url=self._base_url,
                timeout_seconds=self._timeout_seconds,
                already_running=False,
            )
