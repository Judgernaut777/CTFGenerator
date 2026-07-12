"""Concrete SQLAlchemy instance-lifecycle repository (M8 slice 1b).

``SqlAlchemyInstanceRepository`` implements the domain ``InstanceRepository``
protocol over the ``instances`` root plus its runtime-fact tables
(``instance_endpoints`` / ``runtime_resources`` / ``instance_credentials``) and
the two append-only streams (``health_observations`` / ``instance_events``),
folding the audit-event append into every ``state`` change the way
``SqlAlchemyJobQueue`` folds ``job_transitions``.

The state machine is enforced by the DB: ``transition`` issues a guarded UPDATE
and the ``instance_transition_guard`` BEFORE UPDATE trigger rejects an illegal
move as ``sqlalchemy.exc.ProgrammingError`` (the plpgsql RAISE), changing
nothing. Every ``state`` change appends an ``InstanceEvent`` in the SAME
transaction.

Takes the caller's Session; FLUSH only, never commit/rollback -- the application
service's ``Database.session_scope()`` is the unit of work. All ``now`` values
are caller-passed (the repository never reads a clock). Domain objects only ever
cross the boundary; ORM rows never escape.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceCredential,
    InstanceEndpoint,
    InstanceEvent,
    RuntimeResource,
)

from . import _resolve
from .mappers import (
    _as_uuid,
    health_observation_from_orm,
    health_observation_to_orm,
    instance_credential_from_orm,
    instance_credential_to_orm,
    instance_endpoint_from_orm,
    instance_endpoint_to_orm,
    instance_event_from_orm,
    instance_event_to_orm,
    instance_from_orm,
    instance_to_orm,
    runtime_resource_from_orm,
    runtime_resource_to_orm,
    to_utc,
)
from .models import HealthObservation as HealthObservationRow
from .models import Instance as InstanceRow
from .models import InstanceCredential as InstanceCredentialRow
from .models import InstanceEndpoint as InstanceEndpointRow
from .models import InstanceEvent as InstanceEventRow
from .models import RuntimeResource as RuntimeResourceRow


class SqlAlchemyInstanceRepository:
    """Durable instance-lifecycle store with a guarded state machine and an
    append-only audit-event stream written in the same transaction as every
    state change."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- helpers -------------------------------------------------------------

    def _locked_row(self, instance_id: str) -> InstanceRow:
        try:
            key = _as_uuid(instance_id)
        except (ValueError, AttributeError, TypeError):
            raise LookupError(f"instance not found: {instance_id!r}") from None
        row = self._session.scalars(
            select(InstanceRow).where(InstanceRow.id == key).with_for_update()
        ).one_or_none()
        if row is None:
            raise LookupError(f"instance not found: {instance_id!r}")
        return row

    def _business_refs(self, row: InstanceRow) -> tuple[str, str, str, int, str | None]:
        competition_slug = _resolve.competition_slug(self._session, row.competition_id)
        team_name = _resolve.team_name(self._session, row.team_id)
        definition_slug, version_no = _resolve.version_business(
            self._session, row.challenge_version_id
        )
        worker_name = _resolve.worker_name_optional(
            self._session, row.assigned_worker_id
        )
        return competition_slug, team_name, definition_slug, version_no, worker_name

    def _to_domain(self, row: InstanceRow) -> Instance:
        comp, team, defn, ver, worker = self._business_refs(row)
        return instance_from_orm(row, comp, team, defn, ver, worker)

    def _append_event(
        self,
        row: InstanceRow,
        from_state: str | None,
        to_state: str,
        *,
        reason: str,
        actor: str,
        now: datetime,
    ) -> None:
        """Append the instance_events row in the same transaction as the state
        change (the transactional, restart-safe audit trail)."""
        event = InstanceEvent(
            instance_id=str(row.id),
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            actor=actor,
            generation=row.generation,
            occurred_at=now,
        )
        self._session.add(instance_event_to_orm(event, row.id))

    # -- root ----------------------------------------------------------------

    def add(self, instance: Instance, now: datetime) -> Instance:
        competition_uuid = _resolve.competition_uuid(
            self._session, instance.competition_id
        )
        team_uuid = _resolve.team_uuid(
            self._session, competition_uuid, instance.team_name
        )
        version_uuid = _resolve.version_uuid(
            self._session, instance.definition_slug, instance.version_no
        )
        worker_uuid = _resolve.worker_uuid_optional(
            self._session, instance.assigned_worker
        )
        row = instance_to_orm(
            instance, competition_uuid, team_uuid, version_uuid, worker_uuid
        )
        self._session.add(row)
        self._session.flush()  # duplicate instance_id -> IntegrityError here
        # Creation event: from_state is None -> the initial state.
        self._append_event(
            row,
            None,
            instance.state,
            reason="created",
            actor="system",
            now=now,
        )
        self._session.flush()
        return self._to_domain(row)

    def get(self, instance_id: str) -> Instance | None:
        try:
            key = _as_uuid(instance_id)
        except (ValueError, AttributeError, TypeError):
            return None
        row = self._session.scalars(
            select(InstanceRow).where(InstanceRow.id == key)
        ).one_or_none()
        return self._to_domain(row) if row is not None else None

    def list_reconcilable(self, limit: int = 500) -> list[Instance]:
        rows = self._session.scalars(
            select(InstanceRow)
            .where(InstanceRow.state != "archived")
            .order_by(InstanceRow.created_at.asc())
            .limit(limit)
        ).all()
        return [self._to_domain(row) for row in rows]

    def list_all(self) -> list[Instance]:
        """Every instance (including archived), stable-sorted by ``(created_at,
        id)`` for the operator list view + cursor pagination. Materializes the
        FULL ordered result set (no cap) so the router's opaque-cursor pagination
        reaches every row -- consistent with the catalog list endpoints. Read-only;
        the API never mutates through this path."""
        rows = self._session.scalars(
            select(InstanceRow)
            .order_by(InstanceRow.created_at.asc(), InstanceRow.id.asc())
        ).all()
        return [self._to_domain(row) for row in rows]

    def list_for_competition(self, competition_id: str) -> list[Instance]:
        """Every instance of one competition, stable-sorted like :meth:`list_all`
        (the FULL ordered result set, no cap). Resolves the competition slug to
        its surrogate key and fails loud (:class:`LookupError`) on an unknown
        competition."""
        competition_uuid = _resolve.competition_uuid(self._session, competition_id)
        rows = self._session.scalars(
            select(InstanceRow)
            .where(InstanceRow.competition_id == competition_uuid)
            .order_by(InstanceRow.created_at.asc(), InstanceRow.id.asc())
        ).all()
        return [self._to_domain(row) for row in rows]

    def transition(
        self,
        instance_id: str,
        to_state: str,
        *,
        reason: str,
        actor: str,
        now: datetime,
    ) -> Instance:
        row = self._locked_row(instance_id)
        from_state = row.state
        # A self-transition is a no-op under the lock: no state write, no audit
        # event (re-applying the same transition is idempotent and never errors,
        # so two racing reconciler passes cannot append a duplicate event). The
        # store's guard makes the same distinction (NEW.state = OLD.state).
        if from_state == to_state:
            return self._to_domain(row)
        row.state = to_state
        row.updated_at = to_utc(now)
        # The guard trigger fires on flush: an illegal move raises
        # ProgrammingError and rolls the whole unit of work back.
        self._session.flush()
        self._append_event(
            row, from_state, to_state, reason=reason, actor=actor, now=now
        )
        self._session.flush()
        return self._to_domain(row)

    def set_desired_state(
        self, instance_id: str, desired_state: str, now: datetime
    ) -> Instance:
        row = self._locked_row(instance_id)
        row.desired_state = desired_state
        row.updated_at = to_utc(now)
        self._session.flush()
        return self._to_domain(row)

    def set_assignment(
        self, instance_id: str, assigned_worker: str | None, now: datetime
    ) -> Instance:
        row = self._locked_row(instance_id)
        row.assigned_worker_id = _resolve.worker_uuid_optional(
            self._session, assigned_worker
        )
        row.updated_at = to_utc(now)
        self._session.flush()
        return self._to_domain(row)

    def bump_generation(self, instance_id: str, now: datetime) -> Instance:
        row = self._locked_row(instance_id)
        row.generation = row.generation + 1
        row.updated_at = to_utc(now)
        self._session.flush()
        return self._to_domain(row)

    def fence_stale_worker(
        self,
        instance_id: str,
        *,
        expected_worker: str,
        expected_generation: int,
        now: datetime,
    ) -> Instance | None:
        """Atomically evacuate an instance off a dead worker: under a row lock,
        clear the assignment and bump the fencing generation -- but ONLY if the
        instance is STILL assigned to ``expected_worker`` at ``expected_generation``
        (the value the reconciler pass observed). Returns the updated instance, or
        ``None`` when a rival pass / operator action already converged (assignment
        cleared or generation advanced), so two concurrent passes produce at most
        one bump + one launch."""
        row = self._locked_row(instance_id)
        current_worker = _resolve.worker_name_optional(
            self._session, row.assigned_worker_id
        )
        if current_worker != expected_worker or row.generation != expected_generation:
            return None
        row.assigned_worker_id = None
        row.generation = row.generation + 1
        row.updated_at = to_utc(now)
        self._session.flush()
        return self._to_domain(row)

    def fence_missing_container(
        self, instance_id: str, *, expected_generation: int, now: datetime
    ) -> Instance | None:
        """Atomically bump the fencing generation for a missing-container
        recovery: under a row lock, increment the generation ONLY if it still
        equals ``expected_generation`` (fencing the dead container's old-gen
        resources). Returns the updated instance, or ``None`` when a rival pass
        already bumped -- so concurrent passes mint exactly one new generation."""
        row = self._locked_row(instance_id)
        if row.generation != expected_generation:
            return None
        row.generation = row.generation + 1
        row.updated_at = to_utc(now)
        self._session.flush()
        return self._to_domain(row)

    def set_runtime_facts(
        self,
        instance_id: str,
        now: datetime,
        *,
        image_ref: str | None = None,
        instance_seed: str | None = None,
        expires_at: datetime | None = None,
    ) -> Instance:
        row = self._locked_row(instance_id)
        if image_ref is not None:
            row.image_ref = image_ref
        if instance_seed is not None:
            row.instance_seed = instance_seed
        if expires_at is not None:
            row.expires_at = to_utc(expires_at)
        row.updated_at = to_utc(now)
        self._session.flush()
        return self._to_domain(row)

    # -- endpoints -----------------------------------------------------------

    def _endpoint_row(
        self, instance_id: str, name: str
    ) -> InstanceEndpointRow | None:
        return self._session.scalars(
            select(InstanceEndpointRow).where(
                InstanceEndpointRow.instance_id == _as_uuid(instance_id),
                InstanceEndpointRow.name == name,
            )
        ).one_or_none()

    def record_endpoint(self, endpoint: InstanceEndpoint) -> None:
        existing = self._endpoint_row(endpoint.instance_id, endpoint.name)
        if existing is None:
            self._session.add(instance_endpoint_to_orm(endpoint))
        else:
            instance_endpoint_to_orm(endpoint, existing)
        self._session.flush()

    def delete_endpoint(self, instance_id: str, name: str) -> bool:
        row = self._endpoint_row(instance_id, name)
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True

    def list_endpoints(self, instance_id: str) -> list[InstanceEndpoint]:
        rows = self._session.scalars(
            select(InstanceEndpointRow)
            .where(InstanceEndpointRow.instance_id == _as_uuid(instance_id))
            .order_by(InstanceEndpointRow.name)
        ).all()
        return [instance_endpoint_from_orm(row) for row in rows]

    # -- runtime resources ---------------------------------------------------

    def _resource_row(
        self, instance_id: str, kind: str, external_ref: str
    ) -> RuntimeResourceRow | None:
        return self._session.scalars(
            select(RuntimeResourceRow).where(
                RuntimeResourceRow.instance_id == _as_uuid(instance_id),
                RuntimeResourceRow.kind == kind,
                RuntimeResourceRow.external_ref == external_ref,
            )
        ).one_or_none()

    def record_runtime_resource(self, resource: RuntimeResource) -> None:
        worker_uuid = _resolve.worker_uuid(self._session, resource.worker)
        existing = self._resource_row(
            resource.instance_id, resource.kind, resource.external_ref
        )
        if existing is None:
            self._session.add(runtime_resource_to_orm(resource, worker_uuid))
        else:
            runtime_resource_to_orm(resource, worker_uuid, existing)
        self._session.flush()

    def set_resource_state(
        self,
        instance_id: str,
        kind: str,
        external_ref: str,
        state: str,
        now: datetime,
    ) -> bool:
        row = self._resource_row(instance_id, kind, external_ref)
        if row is None:
            return False
        row.state = state
        row.updated_at = to_utc(now)
        self._session.flush()
        return True

    def _resource_to_domain(self, row: RuntimeResourceRow) -> RuntimeResource:
        worker_name = _resolve.worker_name(self._session, row.worker_id)
        return runtime_resource_from_orm(row, worker_name)

    def list_runtime_resources(self, instance_id: str) -> list[RuntimeResource]:
        rows = self._session.scalars(
            select(RuntimeResourceRow)
            .where(RuntimeResourceRow.instance_id == _as_uuid(instance_id))
            .order_by(RuntimeResourceRow.kind, RuntimeResourceRow.external_ref)
        ).all()
        return [self._resource_to_domain(row) for row in rows]

    def list_leaked_resources(self, limit: int = 500) -> list[RuntimeResource]:
        rows = self._session.scalars(
            select(RuntimeResourceRow)
            .join(InstanceRow, InstanceRow.id == RuntimeResourceRow.instance_id)
            .where(
                RuntimeResourceRow.state == "active",
                InstanceRow.state == "archived",
            )
            .order_by(RuntimeResourceRow.created_at.asc())
            .limit(limit)
        ).all()
        return [self._resource_to_domain(row) for row in rows]

    def list_orphan_endpoints(self, limit: int = 500) -> list[InstanceEndpoint]:
        rows = self._session.scalars(
            select(InstanceEndpointRow)
            .join(InstanceRow, InstanceRow.id == InstanceEndpointRow.instance_id)
            .where(InstanceRow.state == "archived")
            .order_by(InstanceEndpointRow.created_at.asc())
            .limit(limit)
        ).all()
        return [instance_endpoint_from_orm(row) for row in rows]

    # -- credentials ---------------------------------------------------------

    def _credential_row(
        self, instance_id: str, name: str
    ) -> InstanceCredentialRow | None:
        return self._session.scalars(
            select(InstanceCredentialRow).where(
                InstanceCredentialRow.instance_id == _as_uuid(instance_id),
                InstanceCredentialRow.name == name,
            )
        ).one_or_none()

    def record_credential(self, credential: InstanceCredential) -> None:
        existing = self._credential_row(credential.instance_id, credential.name)
        if existing is None:
            self._session.add(instance_credential_to_orm(credential))
        else:
            instance_credential_to_orm(credential, existing)
        self._session.flush()

    def list_credentials(self, instance_id: str) -> list[InstanceCredential]:
        rows = self._session.scalars(
            select(InstanceCredentialRow)
            .where(InstanceCredentialRow.instance_id == _as_uuid(instance_id))
            .order_by(InstanceCredentialRow.name)
        ).all()
        return [instance_credential_from_orm(row) for row in rows]

    # -- append-only streams -------------------------------------------------

    def append_observation(self, observation: HealthObservation) -> HealthObservation:
        worker_uuid = _resolve.worker_uuid(self._session, observation.worker)
        row = health_observation_to_orm(observation, worker_uuid)
        self._session.add(row)
        self._session.flush()
        return health_observation_from_orm(row, observation.worker)

    def latest_observation(self, instance_id: str) -> HealthObservation | None:
        try:
            key = _as_uuid(instance_id)
        except (ValueError, AttributeError, TypeError):
            return None
        row = self._session.scalars(
            select(HealthObservationRow)
            .where(HealthObservationRow.instance_id == key)
            .order_by(
                HealthObservationRow.observed_at.desc(),
                HealthObservationRow.created_at.desc(),
            )
            .limit(1)
        ).one_or_none()
        if row is None:
            return None
        worker_name = _resolve.worker_name(self._session, row.worker_id)
        return health_observation_from_orm(row, worker_name)

    def list_events(self, instance_id: str) -> list[InstanceEvent]:
        try:
            key = _as_uuid(instance_id)
        except (ValueError, AttributeError, TypeError):
            return []
        rows = self._session.scalars(
            select(InstanceEventRow)
            .where(InstanceEventRow.instance_id == key)
            .order_by(
                InstanceEventRow.occurred_at.asc(), InstanceEventRow.created_at.asc()
            )
        ).all()
        return [instance_event_from_orm(row) for row in rows]
