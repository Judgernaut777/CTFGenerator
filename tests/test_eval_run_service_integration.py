"""PostgreSQL integration tests for the EvalRunService (M15 slice 15a).

Docker-gated ([db] extra + CTFGEN_TEST_DATABASE_URL); skips cleanly otherwise.

Proves the platform-record contract WITHOUT running any effectful eval:

* ``request_eval`` on a PUBLISHED version creates a PENDING record + enqueues
  exactly ONE ``run_agent_evaluation`` job with a references-only payload;
* re-request is idempotent (same record, no 2nd job);
* a non-published / missing version -> a clear error, nothing enqueued;
* ``record_result`` projects the advisory subset and SANITIZES a planted
  ``ctf{...}`` flag in notes/error (the token is ABSENT from the persisted row);
* a terminal record re-record -> conflict;
* the ADVISORY invariant: a succeeded solved=True run gates NOTHING (publishing
  the version to a competition still works).

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_eval_run_service_integration
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
        EvalResultInput,
        EvalRunConflictError,
        EvalRunService,
        EvalVersionNotPublishedError,
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
_DONE = datetime(2026, 7, 13, 12, 5, tzinfo=UTC)
_SLUG = "sqli"
_FLAG = "ctf{super_secret_flag_do_not_persist}"
# Secrets a worker note/error could carry that the sanitizer MUST redact -- a
# multi-word flag (the old `[^{}\s]` regex missed these), an uppercase FLAG{},
# and a provider API key (an LLM SDK exception repr can embed one).
_FLAG_SPACES = "ctf{multi word flag with spaces}"
_FLAG_UPPER = "FLAG{Another_Secret_One}"
_FAKE_KEY = "sk-ant-api03-DEADBEEFdeadbeef1234567890AbCdEf"  # noqa: S105 - fake fixture


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
            yield db, url
        finally:
            db.dispose()


def _version(state: str) -> ChallengeVersion:
    return ChallengeVersion(
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


def _seed_definition_and_draft(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug=_SLUG, title="SQLi")
        )
        SqlAlchemyChallengeVersionRepository(s).add(_version("draft"))


def _publish(db) -> None:
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


def _service(db) -> EvalRunService:
    return EvalRunService(db, jobs=JobService(db))


def _count_eval_jobs(db) -> int:
    with db.session_scope() as s:
        return s.execute(
            sa.text(
                "SELECT count(*) FROM jobs WHERE job_type='run_agent_evaluation'"
            )
        ).scalar_one()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class EvalRunServiceTests(unittest.TestCase):
    def test_request_creates_pending_and_enqueues_one_job(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            run, created = _service(db).request_eval(
                _SLUG, 1, "writeup_replay", now=_NOW
            )
            self.assertTrue(created)
            self.assertEqual(run.status, "pending")
            self.assertEqual(_count_eval_jobs(db), 1)
            # Payload carries REFERENCES ONLY -- never a flag/seed/secret.
            with db.session_scope() as s:
                payload = s.execute(
                    sa.text(
                        "SELECT payload FROM jobs "
                        "WHERE job_type='run_agent_evaluation'"
                    )
                ).scalar_one()
            self.assertEqual(
                set(payload),
                {"eval_run_id", "definition_slug", "version_no", "profile", "adversarial"},
            )
            self.assertEqual(payload["eval_run_id"], run.eval_run_id)
            self.assertNotIn("seed", payload)
            self.assertNotIn("flag", payload)

    def test_request_is_idempotent(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            first, c1 = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            second, c2 = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            self.assertTrue(c1)
            self.assertFalse(c2)
            self.assertEqual(first.eval_run_id, second.eval_run_id)
            # No duplicate job.
            self.assertEqual(_count_eval_jobs(db), 1)

    def test_adversarial_is_a_distinct_run(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            base, _ = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            adv, created = svc.request_eval(
                _SLUG, 1, "writeup_replay", adversarial=True, now=_NOW
            )
            self.assertTrue(created)
            self.assertNotEqual(base.eval_run_id, adv.eval_run_id)
            self.assertEqual(_count_eval_jobs(db), 2)

    def test_non_published_version_errors_and_enqueues_nothing(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)  # left as draft
            with self.assertRaises(EvalVersionNotPublishedError):
                _service(db).request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            self.assertEqual(_count_eval_jobs(db), 0)

    def test_missing_version_errors_and_enqueues_nothing(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                _service(db).request_eval("ghost", 9, "writeup_replay", now=_NOW)
            self.assertEqual(_count_eval_jobs(db), 0)

    def test_unknown_profile_errors(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            with self.assertRaises(ValueError):
                _service(db).request_eval(_SLUG, 1, "nope", now=_NOW)
            self.assertEqual(_count_eval_jobs(db), 0)

    def test_record_result_sanitizes_planted_flag(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            run, _ = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            # A worker note plants EVERY secret class: a plain flag, a MULTI-WORD
            # flag (spaces -- the old regex missed these), an uppercase FLAG{}, and
            # a provider API key.
            result = EvalResultInput(
                solved=True,
                steps=3,
                success_dropped=False,
                step_delta=1,
                blended_score=71.0,
                notes=(
                    f"found {_FLAG}",
                    f"leaked {_FLAG_SPACES} and {_FLAG_UPPER}",
                    f"client error with {_FAKE_KEY}",
                    "clean note",
                ),
            )
            recorded = svc.record_result(run.eval_run_id, result, _DONE)
            self.assertEqual(recorded.status, "succeeded")
            self.assertTrue(recorded.solved)
            # None of the planted secrets survive in the returned object ...
            joined = " ".join(recorded.notes)
            for secret in (_FLAG, _FLAG_SPACES, _FLAG_UPPER, _FAKE_KEY):
                self.assertNotIn(secret, joined)
            # ... NOR in the raw persisted, operator-visible, backed-up row.
            with db.session_scope() as s:
                row_notes = str(
                    s.execute(
                        sa.text("SELECT notes FROM eval_runs WHERE id = :i"),
                        {"i": uuid.UUID(run.eval_run_id)},
                    ).scalar_one()
                )
            for secret in (_FLAG, _FLAG_SPACES, _FLAG_UPPER, _FAKE_KEY):
                self.assertNotIn(secret, row_notes)

    def test_record_failure_sanitizes_error(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            run, _ = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            recorded = svc.record_result(
                run.eval_run_id,
                EvalResultInput(error=f"crashed after leaking {_FLAG}"),
                _DONE,
            )
            self.assertEqual(recorded.status, "failed")
            self.assertNotIn("ctf{", recorded.error)
            with db.session_scope() as s:
                stored_error = s.execute(
                    sa.text("SELECT error FROM eval_runs WHERE id = :i"),
                    {"i": uuid.UUID(run.eval_run_id)},
                ).scalar_one()
            self.assertNotIn(_FLAG, stored_error)

    def test_terminal_record_re_record_conflicts(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            run, _ = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            svc.record_result(run.eval_run_id, EvalResultInput(solved=True), _DONE)
            with self.assertRaises(EvalRunConflictError):
                svc.record_result(
                    run.eval_run_id, EvalResultInput(solved=False), _DONE
                )

    def test_advisory_run_gates_nothing(self) -> None:
        # The advisory invariant: publication must NOT consult eval state. A
        # solved=True run would SATISFY any hypothetical eval-gate, so it cannot
        # prove the invariant -- use a FAILED (not-solved) eval, the case a gate
        # WOULD block. Publication must still proceed.
        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            _seed_competition(db)
            svc = _service(db)
            run, _ = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            # A NON-passing eval: solved=False (the agent cracked it -> weak).
            svc.record_result(run.eval_run_id, EvalResultInput(solved=False), _DONE)
            self.assertEqual(svc.get(run.eval_run_id).solved, False)
            # Publication proceeds unaffected -- nothing consumes the EvalRun.
            attached = PublicationService(db).attach(
                ChallengePublication(
                    competition_id="cup", definition_slug=_SLUG, version_no=1
                )
            )
            self.assertEqual(attached.definition_slug, _SLUG)

    def test_re_request_reasserts_an_orphaned_job(self) -> None:
        # The row insert and the job enqueue are separate transactions -- a crash
        # AFTER the row commits but BEFORE the enqueue commits leaves a PENDING run
        # with no queued job. Simulate exactly that (the enqueue "crashes"), then
        # prove a later identical request SELF-HEALS by re-asserting the job (not
        # stranding the run forever), with no duplicate.
        from unittest import mock

        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            # First request: the PENDING row commits, then the enqueue crashes.
            with mock.patch.object(
                JobService, "enqueue_idempotent", side_effect=RuntimeError("crash")
            ):
                with self.assertRaises(RuntimeError):
                    svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            # Orphan state: a PENDING run exists but NO job was enqueued.
            self.assertEqual(_count_eval_jobs(db), 0)
            with db.session_scope() as s:
                pending = s.execute(
                    sa.text("SELECT count(*) FROM eval_runs WHERE status='pending'")
                ).scalar_one()
            self.assertEqual(pending, 1)
            # A later identical request finds the pending run and RE-ASSERTS the job.
            again, created2 = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            self.assertFalse(created2)  # the row already existed
            self.assertEqual(again.status, "pending")
            self.assertEqual(_count_eval_jobs(db), 1)  # self-healed, exactly one

    def test_concurrent_create_race_collapses_to_one(self) -> None:
        # Force the IntegrityError recovery branch: patch get_for_version to miss
        # (so request takes the add() path) even though a row already exists ->
        # add() hits the UNIQUE constraint -> the recovery re-fetches the winner
        # and returns it, without a duplicate row or a duplicate job.
        from unittest import mock

        from ctf_generator.infrastructure.database import (
            eval_run_repository as _repo_mod,
        )

        with _migrated_database() as (db, _url):
            _seed_definition_and_draft(db)
            _publish(db)
            svc = _service(db)
            winner, _ = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            self.assertEqual(_count_eval_jobs(db), 1)
            # Blind ONLY the pre-check (1st call -> None, so the request tries to
            # INSERT a rival row and hits the UNIQUE constraint); the recovery's
            # re-fetch (2nd call) returns the real winner.
            with mock.patch.object(
                _repo_mod.SqlAlchemyEvalRunRepository,
                "get_for_version",
                side_effect=[None, winner],
            ):
                loser, created = svc.request_eval(_SLUG, 1, "writeup_replay", now=_NOW)
            self.assertFalse(created)  # recovered, did not create a second row
            self.assertEqual(loser.eval_run_id, winner.eval_run_id)
            with db.session_scope() as s:
                rows = s.execute(
                    sa.text("SELECT count(*) FROM eval_runs")
                ).scalar_one()
            self.assertEqual(rows, 1)
            self.assertEqual(_count_eval_jobs(db), 1)  # no duplicate job


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
