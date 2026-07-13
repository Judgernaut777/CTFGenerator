"""PostgreSQL integration tests for the EvalResultProjector (M15 slice 15b).

Docker-gated ([db] extra + CTFGEN_TEST_DATABASE_URL); skips cleanly otherwise.

Proves the CONTROL-PLANE fold WITHOUT running any effectful eval:

* a PENDING EvalRun (via ``request_eval``) + its ``run_agent_evaluation`` job
  driven to ``succeeded`` with a SECRET-FREE result -> the projector folds it and
  the EvalRun becomes ``succeeded`` with the advisory subset;
* DEFENSE IN DEPTH: even a (hypothetical) flag planted in the job's result notes
  is ABSENT from the persisted EvalRun (``record_result`` re-sanitizes);
* IDEMPOTENT: a second drain records nothing (the run is terminal);
* a ``failed`` job -> an advisory FAILED EvalRun (the run resolves, not wedged);
* ADVISORY: a folded eval gates NOTHING -- publication still works.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_eval_result_projector_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.application.catalog.publication_service import (
        PublicationService,
    )
    from ctf_generator.application.evaluation import (
        EvalResultProjector,
        EvalRunService,
    )
    from ctf_generator.application.jobs.service import JobService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengePublication,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
    from ctf_generator.infrastructure.database.session import Database

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
_SLUG = "sqli"
_PLANTED_FLAG = "ctf{projector_must_redact_this}"
_CAPS = frozenset({"run_agent_evaluation"})


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


@contextmanager
def _migrated_database():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db
        finally:
            db.dispose()


def _seed_published(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug=_SLUG, title="SQLi")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug=_SLUG,
                version_no=1,
                state="draft",
                family_version="1.0",
                seed="seed-abc",
                spec_sha256="spec-hash-1",
                spec={"title": "SQLi"},
                spec_version="1.0",
                mode="red",
                published_at=None,
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish(_SLUG, 1, _NOW)


def _seed_competition(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id="cup",
                name="Cup",
                start_time=_NOW,
                end_time=_NOW + timedelta(hours=48),
            )
        )


def _drive_job_to_succeeded(db, result_json: dict) -> None:
    """Move the single queued run_agent_evaluation job through the REAL queue
    state machine to ``succeeded`` with ``result_json`` (simulating the worker
    completing it), so the projector finds a genuinely-completed job."""
    now = _NOW + timedelta(minutes=1)
    with db.session_scope() as s:
        lease = SqlAlchemyJobQueue(s).claim("worker-eval", _CAPS, 60, now)
    assert lease is not None
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).start(lease.job.job_id, lease.lease_token, now)
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).complete(
            lease.job.job_id, lease.lease_token, result_json, None, None, now
        )


def _drive_job_to_failed(db) -> None:
    now = _NOW + timedelta(minutes=1)
    with db.session_scope() as s:
        lease = SqlAlchemyJobQueue(s).claim("worker-eval", _CAPS, 60, now)
    assert lease is not None
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).start(lease.job.job_id, lease.lease_token, now)
    with db.session_scope() as s:
        # Permanent (non-retryable) failure -> the job lands 'failed'.
        SqlAlchemyJobQueue(s).fail(
            lease.job.job_id, lease.lease_token, "internal", "boom", False, now
        )


def _cancel_queued_job(db) -> None:
    """Operator-cancel the single queued run_agent_evaluation job (a QUEUED job
    goes straight to the terminal ``cancelled`` status)."""
    now = _NOW + timedelta(minutes=1)
    with db.session_scope() as s:
        job_id = s.execute(
            sa.text("SELECT id FROM jobs WHERE job_type='run_agent_evaluation'")
        ).scalar_one()
        SqlAlchemyJobQueue(s).request_cancel(str(job_id), now)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class EvalResultProjectorTests(unittest.TestCase):
    def _services(self, db):
        eval_runs = EvalRunService(db, jobs=JobService(db))
        projector = EvalResultProjector(eval_runs, JobService(db))
        return eval_runs, projector

    def test_projects_completed_job_onto_eval_run(self) -> None:
        with _migrated_database() as db:
            _seed_published(db)
            eval_runs, projector = self._services(db)
            run, _ = eval_runs.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)

            # The worker-reported secret-free result. We deliberately plant a flag
            # in notes to exercise DEFENSE IN DEPTH (record_result re-sanitizes).
            _drive_job_to_succeeded(
                db,
                {
                    "eval_run_id": run.eval_run_id,
                    "solved": True,
                    "steps": 3,
                    "notes": ["GET /flag -> 200", f"flag found: {_PLANTED_FLAG}"],
                },
            )

            recorded = projector.process_completed_eval_jobs()
            self.assertEqual(recorded, 1)

            folded = eval_runs.get(run.eval_run_id)
            self.assertEqual(folded.status, "succeeded")
            self.assertTrue(folded.solved)
            self.assertEqual(folded.steps, 3)

            # The planted flag is ABSENT from the returned object AND the raw
            # persisted, operator-visible row.
            self.assertNotIn(_PLANTED_FLAG, " ".join(folded.notes))
            with db.session_scope() as s:
                row_notes = str(
                    s.execute(
                        sa.text("SELECT notes FROM eval_runs WHERE id = :i"),
                        {"i": uuid.UUID(run.eval_run_id)},
                    ).scalar_one()
                )
            self.assertNotIn(_PLANTED_FLAG, row_notes)
            self.assertNotIn("projector_must_redact_this", row_notes)

    def test_drain_is_idempotent(self) -> None:
        with _migrated_database() as db:
            _seed_published(db)
            eval_runs, projector = self._services(db)
            run, _ = eval_runs.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            _drive_job_to_succeeded(
                db, {"eval_run_id": run.eval_run_id, "solved": False, "steps": 1}
            )
            self.assertEqual(projector.process_completed_eval_jobs(), 1)
            # Second pass: the run is terminal -> nothing to fold.
            self.assertEqual(projector.process_completed_eval_jobs(), 0)

    def test_job_still_in_flight_is_left_pending(self) -> None:
        with _migrated_database() as db:
            _seed_published(db)
            eval_runs, projector = self._services(db)
            run, _ = eval_runs.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            # Job is still 'queued' -> not projectable.
            self.assertEqual(projector.process_completed_eval_jobs(), 0)
            self.assertEqual(eval_runs.get(run.eval_run_id).status, "pending")

    def test_failed_job_yields_advisory_failed_run(self) -> None:
        with _migrated_database() as db:
            _seed_published(db)
            eval_runs, projector = self._services(db)
            run, _ = eval_runs.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            _drive_job_to_failed(db)
            self.assertEqual(projector.process_completed_eval_jobs(), 1)
            self.assertEqual(eval_runs.get(run.eval_run_id).status, "failed")

    def test_cancelled_job_resolves_run_and_does_not_wedge_pending(self) -> None:
        # An operator-cancelled eval job is TERMINAL; the projector must RESOLVE
        # the run to `failed` rather than skip it -- otherwise the run stays
        # `pending` forever and self-heal can't recover it (the idempotency key
        # collides on the cancelled job, so no fresh job is ever queued).
        with _migrated_database() as db:
            _seed_published(db)
            eval_runs, projector = self._services(db)
            run, _ = eval_runs.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            _cancel_queued_job(db)
            self.assertEqual(projector.process_completed_eval_jobs(), 1)
            self.assertEqual(eval_runs.get(run.eval_run_id).status, "failed")
            # Resolved + terminal -> a re-drain is a no-op (never re-scanned forever).
            self.assertEqual(projector.process_completed_eval_jobs(), 0)

    def test_folded_eval_gates_nothing(self) -> None:
        # ADVISORY: a folded eval (even solved=False, the case a hypothetical gate
        # would block) must not stop publication.
        with _migrated_database() as db:
            _seed_published(db)
            _seed_competition(db)
            eval_runs, projector = self._services(db)
            run, _ = eval_runs.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            _drive_job_to_succeeded(
                db, {"eval_run_id": run.eval_run_id, "solved": False, "steps": 9}
            )
            projector.process_completed_eval_jobs()
            self.assertFalse(eval_runs.get(run.eval_run_id).solved)

            attached = PublicationService(db).attach(
                ChallengePublication(
                    competition_id="cup", definition_slug=_SLUG, version_no=1
                )
            )
            self.assertEqual(attached.definition_slug, _SLUG)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
