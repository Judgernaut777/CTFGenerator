"""PostgreSQL integration tests for the instance lifecycle service + reconciler.

Docker-gated; skips cleanly off-Docker. Covers (M8 slice 1b):

* reservation integration -- request reserves keyed ``reservation_id ==
  instance_id``, renew keeps the hold, expire releases it;
* the idempotent re-transition no-op and generation-gating; and
* a convergence test for EACH of the ten reconciler drift cases plus a
  second-pass no-op, driven by a fake ObservedStateSource / WorkerLivenessSource.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_instance_lifecycle_integration
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

    from ctf_generator.application.instances.corrective import build_corrective_job
    from ctf_generator.application.instances.reconciler import InstanceReconciler
    from ctf_generator.application.instances.service import InstanceLifecycleService
    from ctf_generator.application.jobs.service import JobService
    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.instances.models import (
        HealthObservation,
        Instance,
        InstanceEndpoint,
        RuntimeResource,
    )
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        ReservationItem,
        ResourceQuota,
        WorkerRequirements,
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
    from ctf_generator.infrastructure.database.quota_repository import (
        SqlAlchemyQuotaPolicyRepository,
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
_LATER = _NOW + timedelta(hours=2)


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


class _FakeObserved:
    """A canned ObservedStateSource: the fake seam the reconciler folds against
    (a RuntimeBackend query in prod)."""

    def __init__(self) -> None:
        self._obs: dict[str, HealthObservation] = {}

    def set(self, observation: HealthObservation) -> None:
        self._obs[observation.instance_id] = observation

    def latest_observation(self, instance_id: str) -> HealthObservation | None:
        return self._obs.get(instance_id)


class _FakeLiveness:
    def __init__(
        self,
        dispatchable: set[str] | None = None,
        adverse: set[str] | None = None,
    ) -> None:
        self.dispatchable = dispatchable if dispatchable is not None else {"w1"}
        # A GENUINE adverse condition (draining/quarantined/untrusted/gone),
        # distinct from pure heartbeat staleness.
        self.adverse = adverse if adverse is not None else set()

    def is_dispatchable(self, worker_name: str, now: datetime) -> bool:
        return worker_name in self.dispatchable

    def is_adverse(self, worker_name: str, now: datetime) -> bool:
        return worker_name in self.adverse


def _seed_parents(db) -> None:
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
    with db.session_scope() as s:
        SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
            ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", 100)
        )


def _requirements() -> WorkerRequirements:
    return WorkerRequirements(
        architecture="x86_64", required_capabilities=frozenset({"launch_instance"})
    )


def _platform_item(amount: int = 1) -> ReservationItem:
    return ReservationItem("platform", PLATFORM_SCOPE_KEY, "active_instances", amount)


def _seed_instance(
    db,
    *,
    state: str = "active",
    desired: str = "active",
    generation: int = 1,
    assigned: str | None = "w1",
    instance_id: str | None = None,
) -> str:
    iid = instance_id or str(uuid.uuid4())
    inst = Instance(
        instance_id=iid,
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        state=state,
        desired_state=desired,
        generation=generation,
        assigned_worker=assigned,
    )
    with db.session_scope() as s:
        SqlAlchemyInstanceRepository(s).add(inst, _NOW - timedelta(hours=1))
    return iid


def _components(db, observed=None, liveness=None):
    scheduling = SchedulingService(db)
    jobs = JobService(db)
    lifecycle = InstanceLifecycleService(db, scheduling=scheduling, jobs=jobs)
    reconciler = InstanceReconciler(
        db,
        observed_source=observed or _FakeObserved(),
        worker_liveness=liveness or _FakeLiveness(),
        jobs=jobs,
        scheduling=scheduling,
    )
    return scheduling, jobs, lifecycle, reconciler


def _key(iid: str, gen: int, action: str) -> str:
    return f"instance:{iid}:gen{gen}:{action}"


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ReservationIntegrationTests(unittest.TestCase):
    def test_request_reserves_places_and_enqueues_launch(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            scheduling, jobs, lifecycle, _rec = _components(db)
            iid = str(uuid.uuid4())
            placed = lifecycle.request_instance(
                instance_id=iid,
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                requirements=_requirements(),
                pooled_items=(_platform_item(),),
                expires_at=_LATER,
                now=_NOW,
            )
            self.assertEqual(placed.state, "queued")
            self.assertEqual(placed.assigned_worker, "w1")
            # reservation_id == instance_id, held.
            reservation = scheduling.get_reservation(iid)
            self.assertIsNotNone(reservation)
            self.assertEqual(reservation.state, "held")
            self.assertEqual(reservation.reservation_id, iid)
            # launch job enqueued idempotently on gen 1.
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "launch")))

    def test_renew_keeps_hold_then_expire_releases(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            scheduling, jobs, lifecycle, _rec = _components(db)
            iid = str(uuid.uuid4())
            lifecycle.request_instance(
                instance_id=iid,
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                requirements=_requirements(),
                pooled_items=(_platform_item(),),
                expires_at=_NOW - timedelta(minutes=1),  # already stale
                now=_NOW - timedelta(hours=1),
            )
            # Stale at _NOW -> would be swept.
            self.assertIn(iid, scheduling.release_expired(_NOW))
            # Re-reserve a fresh instance and prove renew prevents the sweep.
            iid2 = str(uuid.uuid4())
            lifecycle.request_instance(
                instance_id=iid2,
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                requirements=_requirements(),
                pooled_items=(_platform_item(),),
                expires_at=_NOW - timedelta(minutes=1),
                now=_NOW - timedelta(hours=1),
            )
            lifecycle.renew_lease(iid2, _NOW + timedelta(hours=1), _NOW)
            self.assertNotIn(iid2, scheduling.release_expired(_NOW))
            # Expire releases the hold and enqueues the expire job.
            # Drive to a state expire is legal from (queued->starting->healthy).
            lifecycle.apply_transition(
                iid2, "starting", reason="launch", actor="worker", now=_NOW
            )
            lifecycle.apply_transition(
                iid2, "healthy", reason="up", actor="worker", now=_NOW
            )
            expired = lifecycle.expire(iid2, _NOW)
            self.assertEqual(expired.state, "expired")
            self.assertEqual(scheduling.get_reservation(iid2).state, "released")
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid2, 1, "expire")))

    def test_apply_transition_to_current_state_is_noop(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _sch, _jobs, lifecycle, _rec = _components(db)
            iid = _seed_instance(db, state="active")
            with db.session_scope() as s:
                before = len(SqlAlchemyInstanceRepository(s).list_events(iid))
            got = lifecycle.apply_transition(
                iid, "active", reason="noop", actor="system", now=_NOW
            )
            self.assertEqual(got.state, "active")
            with db.session_scope() as s:
                after = len(SqlAlchemyInstanceRepository(s).list_events(iid))
            self.assertEqual(before, after)  # no event appended

    def test_request_stop_sets_desired_and_enqueues(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _sch, jobs, lifecycle, _rec = _components(db)
            iid = _seed_instance(db, state="active")
            inst = lifecycle.request_stop(iid, _NOW)
            self.assertEqual(inst.desired_state, "stopped")
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "stop")))

    def test_request_reset_bumps_generation_and_enqueues(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _sch, jobs, lifecycle, _rec = _components(db)
            iid = _seed_instance(db, state="active")
            inst = lifecycle.request_reset(iid, _LATER, _NOW)
            self.assertEqual(inst.generation, 2)
            # ONE corrective action per (instance, generation): reset enqueues the
            # SAME 'launch' the reconciler's recovery would, keyed on the new
            # generation, so the two collapse idempotently instead of racing.
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 2, "launch")))

    def test_request_reset_of_released_hold_re_reserves(self) -> None:
        # A reset landing on an instance whose hold was released (e.g. by the
        # expiry sweep) must re-establish quota accounting before relaunching.
        with _migrated_database() as db:
            _seed_parents(db)
            scheduling, jobs, lifecycle, _rec = _components(db)
            iid = str(uuid.uuid4())
            lifecycle.request_instance(
                instance_id=iid,
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                requirements=_requirements(),
                pooled_items=(_platform_item(),),
                expires_at=_LATER,
                now=_NOW,
            )
            self.assertTrue(scheduling.release(iid, _NOW))  # hold released
            self.assertEqual(scheduling.get_reservation(iid).state, "released")
            lifecycle.request_reset(iid, _LATER, _NOW)
            # Re-held (not left released) so the relaunch is quota-accounted.
            self.assertEqual(scheduling.get_reservation(iid).state, "held")
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 2, "launch")))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class GenerationGatingTests(unittest.TestCase):
    def test_stale_generation_observation_does_not_drive_state(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, reconciler = _components(db, observed=observed)
            iid = _seed_instance(db, state="active", generation=2)
            # A HEALTHY observation, but for the OLD generation -> must be ignored.
            observed.set(HealthObservation(iid, "healthy", True, "w1", 1, _NOW))
            actions = reconciler.reconcile_once(_NOW)
            # Treated as absent (no live gen-2 launch job existed): degrade, fence
            # gen 2, and enqueue the fresh-generation (gen 3) launch.
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            self.assertEqual(inst.state, "degraded")
            self.assertEqual(inst.generation, 3)
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 3, "launch")))
            self.assertTrue(any(a.case == "1-missing-container" for a in actions))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ReconcilerDriftCaseTests(unittest.TestCase):
    def _launch_created(self, actions, iid, gen):
        return [
            a
            for a in actions
            if a.action == "launch" and a.idempotency_key == _key(iid, gen, "launch")
        ]

    def test_case1_missing_container(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, rec = _components(db, observed=observed)
            iid = _seed_instance(db, state="active", desired="active")
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            # No live gen-1 launch existed -> degrade, fence to gen 2, relaunch on
            # the FRESH generation (a re-used gen-1 key would collapse to a
            # completed launch and never relaunch).
            self.assertEqual(inst.state, "degraded")
            self.assertEqual(inst.generation, 2)
            launch = self._launch_created(actions, iid, 2)
            self.assertEqual(len(launch), 1)
            self.assertTrue(launch[0].job_created)
            self.assertTrue(any(a.action == "bump_generation" for a in actions))
            # Second pass: the gen-2 launch is now in-flight -> reuse (collapse),
            # no further generation bump.
            actions2 = rec.reconcile_once(_NOW)
            launch2 = self._launch_created(actions2, iid, 2)
            self.assertEqual(len(launch2), 1)
            self.assertFalse(launch2[0].job_created)
            self.assertFalse(any(a.action == "bump_generation" for a in actions2))
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyInstanceRepository(s).get(iid).generation, 2)

    def test_case2_unexpected_container(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, rec = _components(db, observed=observed)
            iid = _seed_instance(db, state="active", desired="stopped")
            observed.set(HealthObservation(iid, "active", True, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW)
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "stop")))
            self.assertTrue(any(a.action == "stop" for a in actions))
            actions2 = rec.reconcile_once(_NOW)
            stop2 = [a for a in actions2 if a.action == "stop"]
            self.assertTrue(stop2 and stop2[0].job_created is False)

    def test_case3_stale_worker(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            liveness = _FakeLiveness(dispatchable=set())  # w1 is NOT dispatchable
            _sch, jobs, _life, rec = _components(
                db, observed=observed, liveness=liveness
            )
            iid = _seed_instance(db, state="active", desired="active", assigned="w1")
            actions = rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            self.assertIsNone(inst.assigned_worker)  # assignment cleared
            self.assertEqual(inst.generation, 2)  # generation bumped
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 2, "launch")))
            self.assertTrue(any(a.case == "3-stale-worker" for a in actions))
            # Second pass: assignment already clear -> case 3 does not re-fire.
            actions2 = rec.reconcile_once(_NOW)
            self.assertFalse(any(a.case == "3-stale-worker" for a in actions2))

    def test_case4_expired_lease_no_double_launch(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, lifecycle, rec = _components(db, observed=observed)
            # A launch job already exists (the reaper requeued it).
            iid = str(uuid.uuid4())
            lifecycle.request_instance(
                instance_id=iid,
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                requirements=_requirements(),
                pooled_items=(_platform_item(),),
                expires_at=_LATER,
                now=_NOW,
            )
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW)
            launch = self._launch_created(actions, iid, 1)
            self.assertEqual(len(launch), 1)
            # The existing (reaper-requeued) launch is NOT doubled.
            self.assertFalse(launch[0].job_created)

    def test_case5_leaked_resource(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _sch, jobs, _life, rec = _components(db)
            # Archived (terminal) instance whose container resource is still active.
            iid = _seed_instance(db, state="archived", desired="deleted")
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).record_runtime_resource(
                    RuntimeResource(iid, "container", "cid-leak", "w1")
                )
            actions = rec.reconcile_once(_NOW)
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "delete")))
            self.assertTrue(any(a.case == "5-leaked-resource" for a in actions))
            with db.session_scope() as s:
                res = SqlAlchemyInstanceRepository(s).list_runtime_resources(iid)
            self.assertEqual(res[0].state, "releasing")
            # Second pass: resource no longer active -> no leak action.
            actions2 = rec.reconcile_once(_NOW)
            self.assertFalse(any(a.case == "5-leaked-resource" for a in actions2))

    def test_case6_failed_acknowledgement(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, _jobs, lifecycle, rec = _components(db, observed=observed)
            # Walk to 'starting' at a past instant so updated_at is old (stuck).
            iid = str(uuid.uuid4())
            _seed_instance(db, state="requested", instance_id=iid, assigned="w1")
            past = _NOW - timedelta(hours=1)
            lifecycle.apply_transition(iid, "queued", reason="q", actor="system", now=past)
            lifecycle.apply_transition(
                iid, "starting", reason="s", actor="system", now=past
            )
            observed.set(HealthObservation(iid, "healthy", True, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW, stuck_after_seconds=300)
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            self.assertEqual(inst.state, "healthy")  # advanced per observation
            self.assertTrue(any(a.case == "6-failed-ack" for a in actions))

    def test_case7_duplicated_launch_collapses(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, rec = _components(db, observed=observed)
            iid = _seed_instance(db, state="active", desired="active")
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            first = rec.reconcile_once(_NOW)
            second = rec.reconcile_once(_NOW)
            # Pass 1 fences to gen 2 and mints the launch; pass 2 finds it
            # in-flight and collapses onto it.
            f = self._launch_created(first, iid, 2)
            s2 = self._launch_created(second, iid, 2)
            self.assertTrue(f and f[0].job_created)
            self.assertTrue(s2 and s2[0].job_created is False)  # duplicate collapses

    def test_case8_partial_reset(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, rec = _components(db, observed=observed)
            # Post-reset: generation 2, its gen-2 launch already queued (as the
            # reset path enqueues), a stale gen-1 resource lingers, nothing up.
            iid = _seed_instance(db, state="starting", desired="active", generation=2)
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                inst = repo.get(iid)
                repo.record_runtime_resource(
                    RuntimeResource(iid, "container", "old-cid", "w1", generation=1)
                )
            jobs.enqueue_idempotent(build_corrective_job(inst, 2, "launch", _NOW), _NOW)
            observed.set(HealthObservation(iid, "absent", False, "w1", 2, _NOW))
            actions = rec.reconcile_once(_NOW)
            # old-gen resource marked releasing + delete enqueued; the in-flight
            # gen-2 launch is REUSED, not bumped to gen 3.
            self.assertTrue(any(a.case == "8-partial-reset" for a in actions))
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 2, "delete")))
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 2, "launch")))
            self.assertFalse(any(a.action == "bump_generation" for a in actions))
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                self.assertEqual(repo.get(iid).generation, 2)
                res = repo.list_runtime_resources(iid)
            self.assertEqual(res[0].state, "releasing")
            # Second pass: no new releasing action (resource already releasing).
            actions2 = rec.reconcile_once(_NOW)
            self.assertFalse(
                any(a.action == "mark_releasing" for a in actions2)
            )

    def test_case9_stopped_still_exposed(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, rec = _components(db, observed=observed)
            iid = _seed_instance(db, state="stopped", desired="stopped")
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                repo.record_endpoint(
                    InstanceEndpoint(iid, "web", "h", 80, "http", "http://h")
                )
                repo.record_runtime_resource(
                    RuntimeResource(iid, "container", "cid-9", "w1")
                )
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW)
            self.assertTrue(any(a.action == "delete_endpoint" for a in actions))
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "delete")))
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                self.assertEqual(repo.list_endpoints(iid), [])
                self.assertEqual(
                    repo.list_runtime_resources(iid)[0].state, "releasing"
                )
            # Second pass: nothing exposed -> no cleanup action for this instance.
            actions2 = rec.reconcile_once(_NOW)
            self.assertFalse(
                any(a.action in ("delete_endpoint", "mark_releasing") for a in actions2)
            )

    def test_case10_orphaned_endpoint(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _sch, _jobs, _life, rec = _components(db)
            iid = _seed_instance(db, state="archived", desired="deleted")
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).record_endpoint(
                    InstanceEndpoint(iid, "web", "h", 80, "http", "http://h")
                )
            actions = rec.reconcile_once(_NOW)
            self.assertTrue(any(a.case == "10-orphan-endpoint" for a in actions))
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).list_endpoints(iid), []
                )

    def test_converged_instance_is_a_noop(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, _jobs, _life, rec = _components(db, observed=observed)
            iid = _seed_instance(db, state="active", desired="active")
            observed.set(HealthObservation(iid, "active", True, "w1", 1, _NOW))
            self.assertEqual(rec.reconcile_once(_NOW), [])


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ReconcilerFixTests(unittest.TestCase):
    """Regression tests for the M8 1b reconciler-safety / lifecycle fixes."""

    def _launch_created(self, actions, iid, gen):
        return [
            a
            for a in actions
            if a.action == "launch" and a.idempotency_key == _key(iid, gen, "launch")
        ]

    # -- M2: a heartbeat blip must not tear down a healthy instance ----------

    def test_heartbeat_blip_does_not_tear_down_healthy(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            # w1 heartbeat-stale (not dispatchable) but NOT adverse.
            liveness = _FakeLiveness(dispatchable=set(), adverse=set())
            _sch, _jobs, _life, rec = _components(
                db, observed=observed, liveness=liveness
            )
            iid = _seed_instance(db, state="active", desired="active", assigned="w1")
            observed.set(HealthObservation(iid, "healthy", True, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            # Healthy + generation-matched: a stale heartbeat alone must NOT
            # evacuate -- no teardown, no generation bump, assignment intact.
            self.assertEqual(inst.state, "active")
            self.assertEqual(inst.generation, 1)
            self.assertIsNotNone(inst.assigned_worker)
            self.assertEqual(actions, [])

    def test_adverse_worker_evacuates_even_if_healthy(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            # w1 dispatchable but ADVERSE (draining/quarantined/untrusted).
            liveness = _FakeLiveness(dispatchable={"w1"}, adverse={"w1"})
            _sch, jobs, _life, rec = _components(
                db, observed=observed, liveness=liveness
            )
            iid = _seed_instance(db, state="active", desired="active", assigned="w1")
            observed.set(HealthObservation(iid, "healthy", True, "w1", 1, _NOW))
            actions = rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            self.assertIsNone(inst.assigned_worker)
            self.assertEqual(inst.generation, 2)
            self.assertTrue(any(a.case == "3-stale-worker" for a in actions))
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 2, "launch")))

    # -- H2: concurrent-pass idempotency via the locked re-check -------------

    def test_stale_worker_corrective_is_concurrency_idempotent(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            liveness = _FakeLiveness(dispatchable=set())  # w1 down
            _sch, _jobs, _life, rec = _components(
                db, observed=observed, liveness=liveness
            )
            iid = _seed_instance(db, state="active", desired="active", assigned="w1")
            # Pass 1 wins the atomic re-check: clears assignment, bumps to gen 2.
            rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            self.assertEqual(inst.generation, 2)
            self.assertIsNone(inst.assigned_worker)
            # A rival pass that observed the STALE (pre-bump) snapshot: the locked
            # precondition refuses to bump/clear a second time.
            self.assertIsNone(rec._fence_stale_worker(iid, "w1", 1, _NOW))
            self.assertIsNone(rec._fence_missing_container(iid, 1, _NOW))
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).generation, 2
                )

    # -- H3 + capacity leak: reconciler stop RELEASES the reservation --------

    def test_reconciler_stop_releases_reservation(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            scheduling, _jobs, lifecycle, rec = _components(db, observed=observed)
            iid = str(uuid.uuid4())
            lifecycle.request_instance(
                instance_id=iid,
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                requirements=_requirements(),
                pooled_items=(_platform_item(),),
                expires_at=_LATER,
                now=_NOW,
            )
            lifecycle.request_stop(iid, _NOW)  # desired stopped
            self.assertEqual(scheduling.get_reservation(iid).state, "held")
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            rec.reconcile_once(_NOW)  # queued -> stopping -> stopped, releases hold
            with db.session_scope() as s:
                inst = SqlAlchemyInstanceRepository(s).get(iid)
            self.assertEqual(inst.state, "stopped")
            self.assertEqual(scheduling.get_reservation(iid).state, "released")

    # -- H4: any early live state drains all the way to stopped --------------

    def test_early_state_drains_to_stopped(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, _jobs, _life, rec = _components(db, observed=observed)
            # 'requested' -> stopping is a newly-legal edge (both matrix + guard).
            iid = _seed_instance(db, state="requested", desired="stopped", assigned="w1")
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).state, "stopped"
                )

    # -- M1 + M5: deleted path, archive only when resources are released -----

    def test_deleted_convergence_and_archive_only_when_released(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, jobs, _life, rec = _components(db, observed=observed)
            iid = _seed_instance(db, state="active", desired="deleted", assigned="w1")
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                repo.record_endpoint(
                    InstanceEndpoint(iid, "web", "h", 80, "http", "http://h")
                )
                repo.record_runtime_resource(
                    RuntimeResource(iid, "container", "cid", "w1")
                )
            # Pass 1: container present -> BOTH stop and delete jobs enqueued.
            observed.set(HealthObservation(iid, "active", True, "w1", 1, _NOW))
            rec.reconcile_once(_NOW)
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "stop")))
            self.assertIsNotNone(jobs.get_by_idempotency_key(_key(iid, 1, "delete")))
            # Pass 2: container gone -> endpoint deleted, resource releasing,
            # drained to stopped; NOT archived while a resource is 'releasing'.
            observed.set(HealthObservation(iid, "absent", False, "w1", 1, _NOW))
            rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                inst = repo.get(iid)
                self.assertEqual(repo.list_endpoints(iid), [])
                res = repo.list_runtime_resources(iid)
            self.assertEqual(inst.state, "stopped")
            self.assertEqual(res[0].state, "releasing")
            # Pass 3: still 'releasing' -> still not archived.
            rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).state, "stopped"
                )
            # Worker confirms release -> archival becomes possible.
            with db.session_scope() as s:
                SqlAlchemyInstanceRepository(s).set_resource_state(
                    iid, "container", "cid", "released", _NOW
                )
            rec.reconcile_once(_NOW)
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).state, "archived"
                )

    # -- L2: a stuck 'ready' instance advances toward healthy ----------------

    def test_failed_ack_advances_ready_toward_healthy(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            observed = _FakeObserved()
            _sch, _jobs, lifecycle, rec = _components(db, observed=observed)
            iid = str(uuid.uuid4())
            _seed_instance(db, state="requested", instance_id=iid, assigned="w1")
            past = _NOW - timedelta(hours=1)
            for state in ("queued", "building", "ready"):
                lifecycle.apply_transition(
                    iid, state, reason="x", actor="system", now=past
                )
            observed.set(HealthObservation(iid, "healthy", True, "w1", 1, _NOW))
            # 'ready' used to stall; now it advances one rung (ready -> starting).
            rec.reconcile_once(_NOW, stuck_after_seconds=300)
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).state, "starting"
                )
            later = _NOW + timedelta(hours=1)
            observed.set(HealthObservation(iid, "healthy", True, "w1", 1, later))
            rec.reconcile_once(later, stuck_after_seconds=300)
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).state, "healthy"
                )


if __name__ == "__main__":
    unittest.main()
