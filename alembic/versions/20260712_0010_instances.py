"""instances -- instance lifecycle, runtime facts, health & audit (M8 slice 1b)

Creates the instance-lifecycle substrate the reconciler steers:

* ``instances`` -- one row per team/challenge running instance, keyed by ``id``
  (the business ``instance_id``, which is ALSO the quota ``reservation_id``). The
  composite FK ``(team_id, competition_id) -> teams`` guarantees the team belongs
  to the instance's competition (mirrors ``submissions``); ``assigned_worker_id``
  is an optional FK. The ``instance_transition_guard`` BEFORE UPDATE trigger
  (owned here) enforces the legal-transition matrix (mirrors the domain's
  ``LEGAL_INSTANCE_TRANSITIONS`` byte-equivalently), freezes an ``archived`` row
  entirely, and freezes the identity columns after insert.
* ``instance_endpoints`` / ``runtime_resources`` / ``instance_credentials`` --
  mutable runtime-fact tables (published/updated/deleted across relaunch and
  cleanup), so no append-only guard.
* ``health_observations`` -- APPEND-ONLY worker reports (generation-fenced).
* ``instance_events`` -- APPEND-ONLY audit, one row per state change, written in
  the same transaction as the transition.

The two append-only tables reuse the shared ``reject_mutation()`` (created and
owned by ``0004``; reused BY NAME, never redefined -- the 0005/0006/0009 pattern)
for UPDATE/DELETE plus a BEFORE TRUNCATE statement trigger.

All FKs ON DELETE RESTRICT. Constraint/index names mirror the ORM metadata
byte-for-byte (autogenerate-clean); reversible.

Revision ID: 0010_instances
Revises: 0009_scheduling_quotas
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_instances"
down_revision: str | None = "0009_scheduling_quotas"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Sorted renderings of the domain frozensets (VALID_INSTANCE_STATES /
# VALID_DESIRED_STATES / VALID_RUNTIME_RESOURCE_KINDS / VALID_RESOURCE_STATES /
# VALID_OBSERVED_STATES / VALID_EVENT_ACTORS), frozen here so the migration is
# stable even if the domain evolves later.
_STATES = (
    "active",
    "archived",
    "building",
    "degraded",
    "expired",
    "failed",
    "healthy",
    "quarantined",
    "queued",
    "ready",
    "requested",
    "starting",
    "stopped",
    "stopping",
)
_DESIRED = ("active", "deleted", "stopped")
_RESOURCE_KINDS = ("container", "image", "network", "volume")
_RESOURCE_STATES = ("active", "released", "releasing")
_OBSERVED = tuple(sorted(set(_STATES) | {"absent", "gone"}))
_ACTORS = ("operator", "system", "worker")

_STATE_IN = ", ".join(f"'{s}'" for s in _STATES)
_DESIRED_IN = ", ".join(f"'{s}'" for s in _DESIRED)
_RESOURCE_KIND_IN = ", ".join(f"'{k}'" for k in _RESOURCE_KINDS)
_RESOURCE_STATE_IN = ", ".join(f"'{s}'" for s in _RESOURCE_STATES)
_OBSERVED_IN = ", ".join(f"'{s}'" for s in _OBSERVED)
_ACTOR_IN = ", ".join(f"'{a}'" for a in _ACTORS)

# The legal-transition matrix (mirrors domain.instances.models
# .LEGAL_INSTANCE_TRANSITIONS byte-equivalently). A self-transition
# (NEW.state = OLD.state) is a field update (assignment / generation bump /
# runtime facts) and is a no-op; an ``archived`` row is frozen entirely.
_GUARD_FN = """
CREATE OR REPLACE FUNCTION instance_transition_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.id IS DISTINCT FROM NEW.id
     OR OLD.competition_id IS DISTINCT FROM NEW.competition_id
     OR OLD.team_id IS DISTINCT FROM NEW.team_id
     OR OLD.challenge_version_id IS DISTINCT FROM NEW.challenge_version_id
     OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
    RAISE EXCEPTION 'instances: immutable column changed (id=%)', OLD.id;
  END IF;
  IF OLD.state = 'archived' THEN
    RAISE EXCEPTION 'instances: row % is archived (terminal); it is frozen',
      OLD.id;
  END IF;
  IF NEW.state = OLD.state THEN
    RETURN NEW;
  END IF;
  IF (OLD.state = 'requested'
        AND NEW.state IN ('queued', 'failed', 'quarantined', 'stopping'))
     OR (OLD.state = 'queued'
        AND NEW.state IN ('building', 'starting', 'failed', 'quarantined',
                          'stopping'))
     OR (OLD.state = 'building'
        AND NEW.state IN ('ready', 'failed', 'quarantined', 'stopping'))
     OR (OLD.state = 'ready'
        AND NEW.state IN ('starting', 'failed', 'quarantined', 'stopping'))
     OR (OLD.state = 'starting'
        AND NEW.state IN ('healthy', 'failed', 'quarantined', 'stopping'))
     OR (OLD.state = 'healthy'
        AND NEW.state IN ('active', 'degraded', 'stopping', 'expired',
                          'quarantined', 'failed'))
     OR (OLD.state = 'active'
        AND NEW.state IN ('degraded', 'stopping', 'expired', 'quarantined',
                          'failed'))
     OR (OLD.state = 'degraded'
        AND NEW.state IN ('healthy', 'active', 'stopping', 'expired',
                          'quarantined', 'failed'))
     OR (OLD.state = 'stopping'
        AND NEW.state IN ('stopped', 'failed', 'quarantined'))
     OR (OLD.state = 'stopped'
        AND NEW.state IN ('starting', 'archived', 'quarantined'))
     OR (OLD.state = 'expired' AND NEW.state IN ('stopping', 'archived'))
     OR (OLD.state = 'failed'
        AND NEW.state IN ('starting', 'archived', 'quarantined'))
     OR (OLD.state = 'quarantined' AND NEW.state IN ('stopping', 'archived'))
     THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'instances: illegal transition % -> % (id=%)',
    OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "instances",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column(
            "state", sa.Text(), nullable=False, server_default=sa.text("'requested'")
        ),
        sa.Column(
            "desired_state",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column("assigned_worker_id", sa.Uuid(), nullable=True),
        sa.Column(
            "generation", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column("image_ref", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("instance_seed", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_instances"),
        sa.CheckConstraint(
            f"state IN ({_STATE_IN})", name="ck_instances_state_valid"
        ),
        sa.CheckConstraint(
            f"desired_state IN ({_DESIRED_IN})",
            name="ck_instances_desired_state_valid",
        ),
        sa.CheckConstraint(
            "generation >= 1", name="ck_instances_generation_positive"
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_instances_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["team_id", "competition_id"],
            ["teams.id", "teams.competition_id"],
            name="fk_instances_team_id_teams",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_instances_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_worker_id"],
            ["workers.id"],
            name="fk_instances_assigned_worker_id_workers",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_instances_competition_id_team_id",
        "instances",
        ["competition_id", "team_id"],
    )
    op.create_index(
        "ix_instances_challenge_version_id", "instances", ["challenge_version_id"]
    )
    op.create_index(
        "ix_instances_reconcile",
        "instances",
        ["desired_state", "state"],
        postgresql_where=sa.text("state <> 'archived'"),
    )
    op.create_index(
        "ix_instances_assigned_worker_id", "instances", ["assigned_worker_id"]
    )

    op.create_table(
        "instance_endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("instance_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column(
            "internal", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_instance_endpoints"),
        sa.UniqueConstraint(
            "instance_id", "name", name="uq_instance_endpoints_instance_id_name"
        ),
        sa.CheckConstraint(
            "port >= 1 AND port <= 65535", name="ck_instance_endpoints_port_valid"
        ),
        sa.CheckConstraint(
            r"host !~ '^\s*$'", name="ck_instance_endpoints_host_non_empty"
        ),
        sa.CheckConstraint(
            r"protocol !~ '^\s*$'", name="ck_instance_endpoints_protocol_non_empty"
        ),
        sa.CheckConstraint(
            r"url !~ '^\s*$'", name="ck_instance_endpoints_url_non_empty"
        ),
        sa.ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_instance_endpoints_instance_id_instances",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_instance_endpoints_instance_id", "instance_endpoints", ["instance_id"]
    )

    op.create_table(
        "runtime_resources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("instance_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("external_ref", sa.Text(), nullable=False),
        sa.Column("worker_id", sa.Uuid(), nullable=False),
        sa.Column(
            "generation", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column(
            "state", sa.Text(), nullable=False, server_default=sa.text("'active'")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_runtime_resources"),
        sa.UniqueConstraint(
            "instance_id",
            "kind",
            "external_ref",
            name="uq_runtime_resources_instance_id_kind_external_ref",
        ),
        sa.CheckConstraint(
            f"kind IN ({_RESOURCE_KIND_IN})", name="ck_runtime_resources_kind_valid"
        ),
        sa.CheckConstraint(
            f"state IN ({_RESOURCE_STATE_IN})",
            name="ck_runtime_resources_state_valid",
        ),
        sa.CheckConstraint(
            "generation >= 1", name="ck_runtime_resources_generation_positive"
        ),
        sa.ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_runtime_resources_instance_id_instances",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_runtime_resources_worker_id_workers",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_runtime_resources_instance_id", "runtime_resources", ["instance_id"]
    )
    op.create_index(
        "ix_runtime_resources_active",
        "runtime_resources",
        ["state"],
        postgresql_where=sa.text("state = 'active'"),
    )

    op.create_table(
        "instance_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("instance_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column(
            "scopes",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_instance_credentials"),
        sa.UniqueConstraint(
            "instance_id", "name", name="uq_instance_credentials_instance_id_name"
        ),
        sa.CheckConstraint(
            r"secret_ref !~ '^\s*$'",
            name="ck_instance_credentials_secret_ref_non_empty",
        ),
        sa.ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_instance_credentials_instance_id_instances",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_instance_credentials_instance_id",
        "instance_credentials",
        ["instance_id"],
    )

    op.create_table(
        "health_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("instance_id", sa.Uuid(), nullable=False),
        sa.Column("observed_state", sa.Text(), nullable=False),
        sa.Column("healthy", sa.Boolean(), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("worker_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_health_observations"),
        sa.CheckConstraint(
            f"observed_state IN ({_OBSERVED_IN})",
            name="ck_health_observations_observed_state_valid",
        ),
        sa.CheckConstraint(
            "generation >= 1", name="ck_health_observations_generation_positive"
        ),
        sa.ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_health_observations_instance_id_instances",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_health_observations_worker_id_workers",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_health_observations_instance_id_observed_at",
        "health_observations",
        ["instance_id", "observed_at"],
    )

    op.create_table(
        "instance_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("instance_id", sa.Uuid(), nullable=False),
        sa.Column("from_state", sa.Text(), nullable=True),
        sa.Column("to_state", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_instance_events"),
        sa.CheckConstraint(
            f"to_state IN ({_STATE_IN})", name="ck_instance_events_to_state_valid"
        ),
        sa.CheckConstraint(
            f"from_state IS NULL OR from_state IN ({_STATE_IN})",
            name="ck_instance_events_from_state_valid",
        ),
        sa.CheckConstraint(
            f"actor IN ({_ACTOR_IN})", name="ck_instance_events_actor_valid"
        ),
        sa.CheckConstraint(
            "generation >= 1", name="ck_instance_events_generation_positive"
        ),
        sa.ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_instance_events_instance_id_instances",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_instance_events_instance_id_occurred_at",
        "instance_events",
        ["instance_id", "occurred_at"],
    )

    # The instance state-machine guard (owned by 0010; dropped on downgrade).
    op.execute(_GUARD_FN)
    op.execute(
        "CREATE TRIGGER instances_transition_guard "
        "BEFORE UPDATE ON instances "
        "FOR EACH ROW EXECUTE FUNCTION instance_transition_guard();"
    )

    # Append-only enforcement on the two ledgers. reject_mutation() is created
    # and owned by 0004 (which always runs first); reused BY NAME, never
    # redefined (exactly the 0005/0006/0009 pattern).
    op.execute(
        "CREATE TRIGGER health_observations_immutable "
        "BEFORE UPDATE OR DELETE ON health_observations "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER health_observations_no_truncate "
        "BEFORE TRUNCATE ON health_observations "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER instance_events_immutable "
        "BEFORE UPDATE OR DELETE ON instance_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER instance_events_no_truncate "
        "BEFORE TRUNCATE ON instance_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS instance_events_no_truncate ON instance_events;"
    )
    op.execute("DROP TRIGGER IF EXISTS instance_events_immutable ON instance_events;")
    op.execute(
        "DROP TRIGGER IF EXISTS health_observations_no_truncate "
        "ON health_observations;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS health_observations_immutable ON health_observations;"
    )
    op.execute("DROP TRIGGER IF EXISTS instances_transition_guard ON instances;")
    op.execute("DROP FUNCTION IF EXISTS instance_transition_guard();")
    # reject_mutation() is owned by 0004; not dropped here.

    op.drop_index(
        "ix_instance_events_instance_id_occurred_at", table_name="instance_events"
    )
    op.drop_table("instance_events")
    op.drop_index(
        "ix_health_observations_instance_id_observed_at",
        table_name="health_observations",
    )
    op.drop_table("health_observations")
    op.drop_index(
        "ix_instance_credentials_instance_id", table_name="instance_credentials"
    )
    op.drop_table("instance_credentials")
    op.drop_index("ix_runtime_resources_active", table_name="runtime_resources")
    op.drop_index("ix_runtime_resources_instance_id", table_name="runtime_resources")
    op.drop_table("runtime_resources")
    op.drop_index(
        "ix_instance_endpoints_instance_id", table_name="instance_endpoints"
    )
    op.drop_table("instance_endpoints")
    op.drop_index("ix_instances_assigned_worker_id", table_name="instances")
    op.drop_index("ix_instances_reconcile", table_name="instances")
    op.drop_index("ix_instances_challenge_version_id", table_name="instances")
    op.drop_index("ix_instances_competition_id_team_id", table_name="instances")
    op.drop_table("instances")
