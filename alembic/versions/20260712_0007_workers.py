"""workers -- execution-plane worker identity, trust, and scoped credentials (M7)

Creates:

* ``workers`` -- worker identities keyed by unique ``name``. Trust is a
  3-state axis (``pending``/``trusted``/``revoked``, revoked terminal, CHECK
  ties it to ``revoked_at``); drain and quarantine are orthogonal timestamp
  overlays (CHECK pairs ``quarantined_at`` with ``quarantine_reason``). The
  partial ``ix_workers_dispatch_eligible`` index is the queue's
  eligible-worker scan.
* ``worker_credentials`` -- sha256-at-rest scoped bearer credentials. The
  format CHECK (64 hex chars) makes storing a plaintext ``ctfw1.`` token
  structurally impossible; the partial UNIQUE (one live credential per
  worker) makes rotation race-proof. Near-append-only: DELETE/TRUNCATE hit
  the shared ``reject_mutation()`` (owned by ``0004``, reused BY NAME), and
  the new ``worker_credentials_freeze()`` (owned here) permits exactly one
  UPDATE shape -- the ``revoked_at`` NULL->value stamp with every other
  column unchanged (compared via ``to_jsonb`` minus the stamped key).

All FKs ON DELETE RESTRICT. Names mirror the ORM metadata (autogenerate-clean).

Revision ID: 0007_workers
Revises: 0006_jobs
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_workers"
down_revision: str | None = "0006_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Sorted renderings of the domain frozensets (VALID_TRUST_STATES /
# VALID_RUNTIME_TYPES), frozen here so the migration is stable.
_TRUST_STATES = ("pending", "revoked", "trusted")
_RUNTIME_TYPES = ("buildkit-rootless", "docker-rootless", "podman-rootless")
_TRUST_IN = ", ".join(f"'{s}'" for s in _TRUST_STATES)
_RUNTIME_IN = ", ".join(f"'{r}'" for r in _RUNTIME_TYPES)

# The one legal mutation: stamping revoked_at on a live credential, with every
# other column byte-identical. Comparing to_jsonb(row) minus the stamped key
# freezes all remaining columns at once (including any added later).
_FREEZE_FN = """
CREATE OR REPLACE FUNCTION worker_credentials_freeze() RETURNS trigger AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
     AND (to_jsonb(NEW) - 'revoked_at') = (to_jsonb(OLD) - 'revoked_at') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION
    'worker_credentials permits only the revoked_at NULL->value stamp (id=%)',
    OLD.id;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "workers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("runtime_type", sa.Text(), nullable=False),
        sa.Column("architectures", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("capabilities", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("capacity", sa.Integer(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column(
            "trust_state",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("drain_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_workers"),
        sa.UniqueConstraint("name", name="uq_workers_name"),
        sa.CheckConstraint(r"name !~ '^\s*$'", name="ck_workers_name_non_empty"),
        sa.CheckConstraint(
            f"trust_state IN ({_TRUST_IN})", name="ck_workers_trust_state_valid"
        ),
        sa.CheckConstraint(
            "(trust_state = 'revoked') = (revoked_at IS NOT NULL)",
            name="ck_workers_revoked_state_consistent",
        ),
        sa.CheckConstraint(
            "(quarantined_at IS NULL) = (quarantine_reason IS NULL)",
            name="ck_workers_quarantine_reason_consistent",
        ),
        sa.CheckConstraint(
            f"runtime_type IN ({_RUNTIME_IN})", name="ck_workers_runtime_type_valid"
        ),
        sa.CheckConstraint("capacity >= 1", name="ck_workers_capacity_positive"),
        sa.CheckConstraint(
            "cardinality(architectures) >= 1",
            name="ck_workers_architectures_non_empty",
        ),
        sa.CheckConstraint(
            "cardinality(capabilities) >= 1",
            name="ck_workers_capabilities_non_empty",
        ),
        sa.CheckConstraint(r"version !~ '^\s*$'", name="ck_workers_version_non_empty"),
    )
    op.create_index("ix_workers_trust_state", "workers", ["trust_state"])
    op.create_index(
        "ix_workers_dispatch_eligible",
        "workers",
        ["last_heartbeat_at"],
        postgresql_where=sa.text(
            "trust_state = 'trusted' AND quarantined_at IS NULL "
            "AND drain_requested_at IS NULL"
        ),
    )

    op.create_table(
        "worker_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("worker_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_worker_credentials"),
        sa.UniqueConstraint("token_hash", name="uq_worker_credentials_token_hash"),
        sa.CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_worker_credentials_token_hash_format",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at", name="ck_worker_credentials_expiry_after_issue"
        ),
        sa.CheckConstraint(
            "cardinality(scopes) >= 1", name="ck_worker_credentials_scopes_non_empty"
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_worker_credentials_worker_id_workers",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "uq_worker_credentials_worker_id_active",
        "worker_credentials",
        ["worker_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index(
        "ix_worker_credentials_worker_id", "worker_credentials", ["worker_id"]
    )

    # Near-append-only enforcement. reject_mutation() is owned by 0004 and
    # reused BY NAME; worker_credentials_freeze() is owned by this revision.
    op.execute(_FREEZE_FN)
    op.execute(
        "CREATE TRIGGER worker_credentials_freeze_update "
        "BEFORE UPDATE ON worker_credentials "
        "FOR EACH ROW EXECUTE FUNCTION worker_credentials_freeze();"
    )
    op.execute(
        "CREATE TRIGGER worker_credentials_no_delete "
        "BEFORE DELETE ON worker_credentials "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER worker_credentials_no_truncate "
        "BEFORE TRUNCATE ON worker_credentials "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS worker_credentials_no_truncate ON worker_credentials;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS worker_credentials_no_delete ON worker_credentials;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS worker_credentials_freeze_update ON worker_credentials;"
    )
    op.execute("DROP FUNCTION IF EXISTS worker_credentials_freeze();")
    # reject_mutation() is owned by 0004; not dropped here.

    op.drop_index("ix_worker_credentials_worker_id", table_name="worker_credentials")
    op.drop_index(
        "uq_worker_credentials_worker_id_active", table_name="worker_credentials"
    )
    op.drop_table("worker_credentials")
    op.drop_index("ix_workers_dispatch_eligible", table_name="workers")
    op.drop_index("ix_workers_trust_state", table_name="workers")
    op.drop_table("workers")
