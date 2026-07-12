"""scheduling_quotas -- resource quotas, reservations, and worker image cache (M8)

Creates the execution plane's capacity-accounting and scheduling substrate:

* ``resource_quotas`` -- one row per ``(scope_type, scope_key, dimension)`` with
  a ``limit_value`` and a live ``reserved_value`` counter. Mutable (a limit
  adjustment and the reserve/release counter update are legal), so no
  ``reject_mutation``; instead a ``resource_quotas_guard()`` BEFORE DELETE
  trigger (owned here) refuses to drop a row while ``reserved_value > 0``, and a
  ``resource_quotas_within_limit()`` BEFORE UPDATE trigger (also owned here)
  refuses an UPDATE that *raises* ``reserved_value`` above ``limit_value`` while
  leaving grandfathered over-holds after a limit cut alone. The unique
  ``(scope_type, scope_key, dimension)`` is the composite-FK target for
  reservation items; a ceiling dimension's counter is pinned to 0 by CHECK.
* ``quota_reservations`` -- reservation headers keyed by ``reservation_id``
  (equal to the instance business id; a duplicate reserve -> IntegrityError, the
  idempotent re-launch guard). CHECK ties ``state`` to ``released_at``.
* ``quota_reservation_items`` -- append-only per-counter amounts. Immutable via
  the shared ``reject_mutation()`` (created and owned by ``0004``; reused BY
  NAME, never redefined). Composite FK to ``resource_quotas`` guarantees every
  item targets a real quota row.
* ``worker_image_cache`` -- which images a worker has cached (populated by worker
  events in slice 2; slice 1 LEFT JOINs it for scheduler affinity ranking).

All FKs ON DELETE RESTRICT. Constraint/index names mirror the ORM metadata
byte-for-byte (autogenerate-clean); reversible.

Revision ID: 0009_scheduling_quotas
Revises: 0008_score_projection
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_scheduling_quotas"
down_revision: str | None = "0008_score_projection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Sorted renderings of the domain frozensets (VALID_QUOTA_SCOPES /
# VALID_DIMENSIONS / CEILING_DIMENSIONS / VALID_RESERVATION_STATES), frozen here
# so the migration is stable even if the domain evolves later.
_SCOPES = ("challenge", "competition", "platform", "team", "worker")
_DIMENSIONS = (
    "active_instances",
    "build_concurrency",
    "cpu_millis",
    "exposed_ports",
    "max_runtime_seconds",
    "memory_mb",
    "storage_mb",
)
_CEILINGS = ("max_runtime_seconds",)
_STATES = ("held", "released")

_SCOPE_IN = ", ".join(f"'{s}'" for s in _SCOPES)
_DIMENSION_IN = ", ".join(f"'{d}'" for d in _DIMENSIONS)
_CEILING_IN = ", ".join(f"'{d}'" for d in _CEILINGS)
_STATE_IN = ", ".join(f"'{s}'" for s in _STATES)

# Refuses to delete a quota row while capacity is still held against it (a
# mutable-table analogue of the append-only guards). reserved_value is only ever
# 0 for a drained pool, so a delete is safe iff nothing is reserved.
_QUOTA_GUARD_FN = """
CREATE OR REPLACE FUNCTION resource_quotas_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.reserved_value > 0 THEN
    RAISE EXCEPTION
      'resource_quotas: cannot delete a quota with reserved_value > 0 (id=%)',
      OLD.id;
  END IF;
  RETURN OLD;
END $$ LANGUAGE plpgsql;
"""

# Defence-in-depth over the app-level reserve check: reject an UPDATE that
# *raises* reserved_value above limit_value. A blanket CHECK is deliberately
# avoided -- it would break a legitimate limit reduction below current holds
# (grandfathered). This guard only fires when reserved_value is being INCREASED
# past the limit, so a limit cut (reserved unchanged), a release (reserved
# decreasing), and a reconcile restoring the true held sum at/under limit all
# stay legal.
_QUOTA_LIMIT_GUARD_FN = """
CREATE OR REPLACE FUNCTION resource_quotas_within_limit() RETURNS trigger AS $$
BEGIN
  IF NEW.reserved_value > NEW.limit_value
     AND NEW.reserved_value > OLD.reserved_value THEN
    RAISE EXCEPTION
      'resource_quotas: reserved_value % would exceed limit_value % (id=%)',
      NEW.reserved_value, NEW.limit_value, NEW.id;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "resource_quotas",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("scope_key", sa.Text(), nullable=False),
        sa.Column("dimension", sa.Text(), nullable=False),
        sa.Column("limit_value", sa.BigInteger(), nullable=False),
        sa.Column(
            "reserved_value",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_resource_quotas"),
        sa.UniqueConstraint(
            "scope_type", "scope_key", "dimension", name="uq_resource_quotas_scope"
        ),
        sa.CheckConstraint(
            f"scope_type IN ({_SCOPE_IN})", name="ck_resource_quotas_scope_type_valid"
        ),
        sa.CheckConstraint(
            f"dimension IN ({_DIMENSION_IN})", name="ck_resource_quotas_dimension_valid"
        ),
        sa.CheckConstraint(
            "limit_value >= 0", name="ck_resource_quotas_limit_non_negative"
        ),
        sa.CheckConstraint(
            "reserved_value >= 0", name="ck_resource_quotas_reserved_non_negative"
        ),
        sa.CheckConstraint(
            f"dimension NOT IN ({_CEILING_IN}) OR reserved_value = 0",
            name="ck_resource_quotas_ceiling_no_reserve",
        ),
    )
    op.create_index(
        "ix_resource_quotas_scope_type_scope_key",
        "resource_quotas",
        ["scope_type", "scope_key"],
    )

    op.create_table(
        "quota_reservations",
        sa.Column("reservation_id", sa.Uuid(), nullable=False),
        sa.Column("worker_key", sa.Text(), nullable=False),
        sa.Column("competition_key", sa.Text(), nullable=True),
        sa.Column("team_key", sa.Text(), nullable=True),
        sa.Column("challenge_key", sa.Text(), nullable=True),
        sa.Column(
            "state", sa.Text(), nullable=False, server_default=sa.text("'held'")
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("reservation_id", name="pk_quota_reservations"),
        sa.CheckConstraint(
            f"state IN ({_STATE_IN})", name="ck_quota_reservations_state_valid"
        ),
        sa.CheckConstraint(
            "(state = 'released') = (released_at IS NOT NULL)",
            name="ck_quota_reservations_released_state_consistent",
        ),
        sa.CheckConstraint(
            r"worker_key !~ '^\s*$'",
            name="ck_quota_reservations_worker_key_non_empty",
        ),
    )
    op.create_index(
        "ix_quota_reservations_expires_at",
        "quota_reservations",
        ["expires_at"],
        postgresql_where=sa.text("state = 'held'"),
    )
    op.create_index(
        "ix_quota_reservations_worker_key",
        "quota_reservations",
        ["worker_key"],
        postgresql_where=sa.text("state = 'held'"),
    )

    op.create_table(
        "quota_reservation_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("reservation_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("scope_key", sa.Text(), nullable=False),
        sa.Column("dimension", sa.Text(), nullable=False),
        sa.Column("amount", sa.BigInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_quota_reservation_items"),
        sa.UniqueConstraint(
            "reservation_id",
            "scope_type",
            "scope_key",
            "dimension",
            name="uq_quota_reservation_items_reservation",
        ),
        sa.CheckConstraint("amount > 0", name="ck_quota_reservation_items_amount_positive"),
        sa.ForeignKeyConstraint(
            ["reservation_id"],
            ["quota_reservations.reservation_id"],
            name="fk_quota_reservation_items_reservation_id_quota_reservations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scope_type", "scope_key", "dimension"],
            [
                "resource_quotas.scope_type",
                "resource_quotas.scope_key",
                "resource_quotas.dimension",
            ],
            name="fk_quota_reservation_items_scope_resource_quotas",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_quota_reservation_items_scope",
        "quota_reservation_items",
        ["scope_type", "scope_key", "dimension"],
    )

    op.create_table(
        "worker_image_cache",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("worker_id", sa.Uuid(), nullable=False),
        sa.Column("image_ref", sa.Text(), nullable=False),
        sa.Column(
            "cached_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_worker_image_cache"),
        sa.UniqueConstraint(
            "worker_id", "image_ref", name="uq_worker_image_cache_worker_id_image_ref"
        ),
        sa.CheckConstraint(
            r"image_ref !~ '^\s*$'", name="ck_worker_image_cache_image_ref_non_empty"
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_worker_image_cache_worker_id_workers",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_worker_image_cache_image_ref", "worker_image_cache", ["image_ref"]
    )

    # Append-only enforcement on the reservation-item ledger. reject_mutation()
    # is owned by 0004 (which always runs first); reused BY NAME, never
    # redefined (exactly the 0005/0006 pattern).
    op.execute(
        "CREATE TRIGGER quota_reservation_items_immutable "
        "BEFORE UPDATE OR DELETE ON quota_reservation_items "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER quota_reservation_items_no_truncate "
        "BEFORE TRUNCATE ON quota_reservation_items "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )

    # The delete guard on the mutable quota table (owned by this revision).
    op.execute(_QUOTA_GUARD_FN)
    op.execute(
        "CREATE TRIGGER resource_quotas_guard_delete "
        "BEFORE DELETE ON resource_quotas "
        "FOR EACH ROW EXECUTE FUNCTION resource_quotas_guard();"
    )

    # Defence-in-depth: no UPDATE may push reserved_value above limit_value.
    op.execute(_QUOTA_LIMIT_GUARD_FN)
    op.execute(
        "CREATE TRIGGER resource_quotas_within_limit_update "
        "BEFORE UPDATE ON resource_quotas "
        "FOR EACH ROW EXECUTE FUNCTION resource_quotas_within_limit();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS resource_quotas_within_limit_update "
        "ON resource_quotas;"
    )
    op.execute("DROP FUNCTION IF EXISTS resource_quotas_within_limit();")
    op.execute("DROP TRIGGER IF EXISTS resource_quotas_guard_delete ON resource_quotas;")
    op.execute("DROP FUNCTION IF EXISTS resource_quotas_guard();")
    op.execute(
        "DROP TRIGGER IF EXISTS quota_reservation_items_no_truncate "
        "ON quota_reservation_items;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS quota_reservation_items_immutable "
        "ON quota_reservation_items;"
    )
    # reject_mutation() is owned by 0004; not dropped here.

    op.drop_index(
        "ix_worker_image_cache_image_ref", table_name="worker_image_cache"
    )
    op.drop_table("worker_image_cache")
    op.drop_index(
        "ix_quota_reservation_items_scope", table_name="quota_reservation_items"
    )
    op.drop_table("quota_reservation_items")
    op.drop_index(
        "ix_quota_reservations_worker_key", table_name="quota_reservations"
    )
    op.drop_index(
        "ix_quota_reservations_expires_at", table_name="quota_reservations"
    )
    op.drop_table("quota_reservations")
    op.drop_index(
        "ix_resource_quotas_scope_type_scope_key", table_name="resource_quotas"
    )
    op.drop_table("resource_quotas")
