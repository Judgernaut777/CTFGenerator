"""audit_events -- the durable, append-only privileged-action audit trail (M16)

Creates the ``audit_events`` table: the tamper-evident record of WHO did WHAT to
WHICH resource, with what outcome, under which request id, and -- for an admin
override (REQ-INV-009) -- an optional reason. Keyed by the caller-supplied ``id``
(uuid). Indexed on ``actor`` / ``action`` / ``outcome`` / ``occurred_at`` for the
operator query.

SECRET-FREE by construction: every column is a short identifier or sanitized free
text -- there is NO flag/token/password/body column, so a secret cannot be
persisted here. APPEND-ONLY / tamper-evident: the shared ``reject_mutation`` guard
(from 0004) is attached as BEFORE UPDATE OR DELETE + BEFORE TRUNCATE triggers, so
a persisted audit row can never be altered, deleted, or truncated.

Constraint/index/trigger names mirror the ORM metadata NAMING_CONVENTION exactly
(autogenerate-clean); reversible. ``reject_mutation`` is owned by 0004 (created
there, dropped there) -- this migration only attaches/detaches its triggers.

Revision ID: 0014_audit_events
Revises: 0013_eval_runs
Create Date: 2026-07-13
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_audit_events"
down_revision: str | None = "0013_eval_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copy of the domain VALID_AUDIT_OUTCOMES (sorted), matching the ORM CHECK.
_AUDIT_OUTCOMES = ("denied", "error", "success")
_OUTCOME_IN = ", ".join(f"'{o}'" for o in _AUDIT_OUTCOMES)


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.CheckConstraint(
            f"outcome IN ({_OUTCOME_IN})", name="ck_audit_events_outcome_valid"
        ),
    )
    op.create_index("ix_audit_events_actor", "audit_events", ["actor"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_outcome", "audit_events", ["outcome"])
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"])

    # Append-only / tamper-evidence: reject any UPDATE/DELETE/TRUNCATE via the
    # shared reject_mutation() guard owned by 0004.
    op.execute(
        "CREATE TRIGGER audit_events_immutable "
        "BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_truncate "
        "BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;")
    op.execute("DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;")
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.drop_index("ix_audit_events_outcome", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_actor", table_name="audit_events")
    op.drop_table("audit_events")
    # reject_mutation() is owned by 0004; not dropped here.
