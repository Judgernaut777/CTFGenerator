"""PostgreSQL integration tests for the instance-lifecycle repository (M8 1b).

Docker-gated like the other repository suites; skips cleanly without the db
extra / CTFGEN_TEST_DATABASE_URL so the stdlib host suite stays green.

Proves the load-bearing properties: round-trip of every aggregate, the FULL
transition matrix (legal accepted, illegal rejected as ProgrammingError from the
plpgsql guard), the archived-terminal freeze, append-only immutability on
health_observations / instance_events, and the transactional audit-event append.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_instance_repository_integration
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
    from sqlalchemy.exc import IntegrityError, ProgrammingError

    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.instances.models import (
        LEGAL_INSTANCE_TRANSITIONS,
        VALID_INSTANCE_STATES,
        HealthObservation,
        Instance,
        InstanceCredential,
        InstanceEndpoint,
        RuntimeResource,
        is_legal_instance_transition,
    )
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
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"db extra not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


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


def _seed_parents(db) -> None:
    """Competition + team + published challenge version + trusted worker."""
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id="cup",
                name="Cup",
                start_time=_NOW - timedelta(hours=1),
                end_time=_NOW + timedelta(hours=47),
            )
        )
        SqlAlchemyTeamRepository(s).add(Team("cup", "Red"))
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug="sql", title="SQL")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug="sql",
                version_no=1,
                state="draft",
                family_version="1.0",
                seed="s",
                spec_sha256="h1",
                spec={"t": 1},
                spec_version="1.0",
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, _NOW)
    with db.session_scope() as s:
        reg = SqlAlchemyWorkerRegistry(s)
        reg.add(
            Worker("w1", "docker-rootless", ("x86_64",), ("launch_instance",), 4, "1")
        )
        reg.approve("w1")
        reg.heartbeat("w1", _NOW)


def _new_instance(state: str = "requested", **kw) -> Instance:
    base = dict(
        instance_id=str(uuid.uuid4()),
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        state=state,
    )
    base.update(kw)
    return Instance(**base)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class RoundTripTests(unittest.TestCase):
    def test_instance_round_trip_business_keys(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance(
                assigned_worker="w1",
                image_ref="reg/img@sha256:ab",
                instance_seed="seed-1",
                expires_at=_NOW + timedelta(hours=2),
            )
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            with db.session_scope() as s:
                got = SqlAlchemyInstanceRepository(s).get(inst.instance_id)
            self.assertEqual(got.instance_id, inst.instance_id)
            self.assertEqual(got.competition_id, "cup")
            self.assertEqual(got.team_name, "Red")
            self.assertEqual(got.definition_slug, "sql")
            self.assertEqual(got.version_no, 1)
            self.assertEqual(got.assigned_worker, "w1")
            self.assertEqual(got.image_ref, "reg/img@sha256:ab")
            self.assertEqual(got.instance_seed, "seed-1")
            self.assertEqual(got.state, "requested")
            self.assertEqual(got.desired_state, "active")
            self.assertEqual(got.generation, 1)

    def test_add_writes_creation_event(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            with db.session_scope() as s:
                events = SqlAlchemyInstanceRepository(s).list_events(inst.instance_id)
            self.assertEqual(len(events), 1)
            self.assertIsNone(events[0].from_state)
            self.assertEqual(events[0].to_state, "requested")
            self.assertEqual(events[0].actor, "system")

    def test_duplicate_instance_id_raises_integrity(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyInstanceRepository(s).add(inst, _NOW)

    def test_add_missing_parent_raises_lookup(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyInstanceRepository(s).add(
                        _new_instance(team_name="Ghost"), _NOW
                    )

    def test_endpoint_resource_credential_round_trip(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            iid = inst.instance_id
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                repo.add(inst, _NOW)
                repo.record_endpoint(
                    InstanceEndpoint(
                        instance_id=iid,
                        name="web",
                        host="10.0.0.5",
                        port=8080,
                        protocol="http",
                        url="http://10.0.0.5:8080",
                    )
                )
                repo.record_runtime_resource(
                    RuntimeResource(
                        instance_id=iid,
                        kind="container",
                        external_ref="cid-1",
                        worker="w1",
                    )
                )
                repo.record_credential(
                    InstanceCredential(
                        instance_id=iid,
                        name="access",
                        secret_ref="vault://k/1",  # noqa: S106 - a handle, not a secret
                        scopes=("connect",),
                    )
                )
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                eps = repo.list_endpoints(iid)
                res = repo.list_runtime_resources(iid)
                creds = repo.list_credentials(iid)
            self.assertEqual([e.name for e in eps], ["web"])
            self.assertEqual(eps[0].port, 8080)
            self.assertEqual([r.external_ref for r in res], ["cid-1"])
            self.assertEqual(res[0].worker, "w1")
            self.assertEqual(res[0].state, "active")
            self.assertEqual([c.secret_ref for c in creds], ["vault://k/1"])

    def test_endpoint_upsert_and_delete(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            iid = inst.instance_id
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                repo.add(inst, _NOW)
                repo.record_endpoint(
                    InstanceEndpoint(iid, "web", "h", 80, "http", "http://h")
                )
                repo.record_endpoint(
                    InstanceEndpoint(iid, "web", "h2", 81, "http", "http://h2")
                )
            with db.session_scope() as s:
                eps = SqlAlchemyInstanceRepository(s).list_endpoints(iid)
            self.assertEqual(len(eps), 1)
            self.assertEqual(eps[0].host, "h2")
            with db.session_scope() as s:
                self.assertTrue(
                    SqlAlchemyInstanceRepository(s).delete_endpoint(iid, "web")
                )
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).list_endpoints(iid), []
                )

    def test_observation_round_trip_and_latest(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            iid = inst.instance_id
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                repo.add(inst, _NOW)
                repo.append_observation(
                    HealthObservation(iid, "starting", False, "w1", 1, _NOW)
                )
                repo.append_observation(
                    HealthObservation(
                        iid,
                        "healthy",
                        True,
                        "w1",
                        1,
                        _NOW + timedelta(minutes=1),
                        detail={"probe": "ok"},
                    )
                )
            with db.session_scope() as s:
                latest = SqlAlchemyInstanceRepository(s).latest_observation(iid)
            self.assertEqual(latest.observed_state, "healthy")
            self.assertTrue(latest.healthy)
            self.assertEqual(dict(latest.detail), {"probe": "ok"})
            self.assertEqual(latest.worker, "w1")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class TransitionMatrixTests(unittest.TestCase):
    def test_legal_chain_writes_events(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            iid = inst.instance_id
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            chain = ["queued", "starting", "healthy", "active", "stopping", "stopped"]
            prev = "requested"
            for state in chain:
                with db.session_scope() as s:
                    updated = SqlAlchemyInstanceRepository(s).transition(
                        iid, state, reason="test", actor="system", now=_NOW
                    )
                self.assertEqual(updated.state, state)
                prev = state
            with db.session_scope() as s:
                events = SqlAlchemyInstanceRepository(s).list_events(iid)
            # creation + 6 transitions.
            self.assertEqual(len(events), 1 + len(chain))
            self.assertEqual(events[-1].from_state, "stopping")
            self.assertEqual(events[-1].to_state, "stopped")
            self.assertEqual(prev, "stopped")

    def test_illegal_transition_raises_programming_error(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance()
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    SqlAlchemyInstanceRepository(s).transition(
                        inst.instance_id, "healthy", reason="x", actor="system", now=_NOW
                    )

    def test_archived_is_frozen(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance(state="archived")
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    SqlAlchemyInstanceRepository(s).transition(
                        inst.instance_id, "starting", reason="x", actor="system", now=_NOW
                    )

    def test_self_transition_is_permitted(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            inst = _new_instance(state="active")
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).add(inst, _NOW)
            # NEW.state == OLD.state is a field update the guard permits.
            with db.session_scope() as s:
                got = SqlAlchemyInstanceRepository(s).transition(
                    inst.instance_id, "active", reason="noop", actor="system", now=_NOW
                )
            self.assertEqual(got.state, "active")

    def test_full_matrix_accept_reject(self) -> None:
        # For every (src, dst) pair the DB guard must accept iff the domain
        # constant says it is legal. Each pair uses a fresh instance INSERTed
        # directly in ``src`` (INSERT does not fire the guard); the transition
        # UPDATE does.
        states = sorted(VALID_INSTANCE_STATES)
        with _migrated_database() as db:
            _seed_parents(db)
            for src in states:
                for dst in states:
                    if src == dst:
                        continue
                    inst = _new_instance(state=src)
                    with db.session_scope() as s:
                        SqlAlchemyInstanceRepository(s).add(inst, _NOW)
                    legal = is_legal_instance_transition(src, dst)
                    if legal:
                        with db.session_scope() as s:
                            got = SqlAlchemyInstanceRepository(s).transition(
                                inst.instance_id, dst, reason="m", actor="system", now=_NOW
                            )
                        self.assertEqual(
                            got.state, dst, f"{src}->{dst} should be accepted"
                        )
                    else:
                        with self.assertRaises(
                            ProgrammingError, msg=f"{src}->{dst} should be rejected"
                        ):
                            with db.session_scope() as s:
                                SqlAlchemyInstanceRepository(s).transition(
                                    inst.instance_id,
                                    dst,
                                    reason="m",
                                    actor="system",
                                    now=_NOW,
                                )

    def test_matrix_covers_every_legal_edge(self) -> None:
        # Sanity: the curated matrix test above exercises the domain constant; a
        # cheap cross-check that the constant is non-trivial for each state.
        for src, targets in LEGAL_INSTANCE_TRANSITIONS.items():
            for dst in targets:
                self.assertTrue(is_legal_instance_transition(src, dst))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AppendOnlyTests(unittest.TestCase):
    def _seed_one(self, db):
        inst = _new_instance()
        with db.session_scope() as s:
            repo = SqlAlchemyInstanceRepository(s)
            repo.add(inst, _NOW)
            repo.append_observation(
                HealthObservation(inst.instance_id, "healthy", True, "w1", 1, _NOW)
            )
        return inst.instance_id

    def test_health_observations_immutable(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            self._seed_one(db)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text("UPDATE health_observations SET healthy = false")
                    )
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM health_observations"))
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("TRUNCATE health_observations"))

    def test_instance_events_immutable(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            self._seed_one(db)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("UPDATE instance_events SET reason = 'x'"))
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM instance_events"))
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("TRUNCATE instance_events"))


if __name__ == "__main__":
    unittest.main()
