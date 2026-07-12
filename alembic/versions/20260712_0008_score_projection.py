"""score projection -- transactional outbox + scoreboard cache (M7)

Resolves the §1 "single-writer ordering" caveat of the persistence design:
``score_events.seq`` allocation order is not commit order under concurrent
writers, so a bare ``seq > cursor`` projector could permanently skip a
late-committing lower seq. The fix is delivery-by-construction:

* ``score_projection_outbox`` -- one work row per score event, inserted by
  the ``score_events_enqueue_projection`` AFTER INSERT trigger (owned here)
  *in the same transaction* as the event, so the row becomes visible at
  exactly the instant the event commits -- regardless of how many higher
  seqs committed first. A committed event can never be skipped: its row is
  deleted only in the transaction that folded it into the projection.
  Deliberately MUTABLE (a work table, not ledger history) -- no
  reject_mutation triggers.
* ``scoreboard_projections`` -- the rebuildable per-competition scoreboard
  cache (§7's ``scoreboard_cache``), stamped with ``as_of_seq`` and written
  only via a monotonic-guarded UPSERT. Never a source of truth.

The upgrade backfills one pending outbox row per pre-existing score event
(idempotent; the first drain refolds each competition once).

Revision ID: 0008_score_projection
Revises: 0007_workers
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_score_projection"
down_revision: str | None = "0007_workers"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ENQUEUE_FN = """
CREATE OR REPLACE FUNCTION score_events_enqueue_projection() RETURNS trigger AS $$
BEGIN
  INSERT INTO score_projection_outbox (seq, competition_id)
  VALUES (NEW.seq, NEW.competition_id);
  RETURN NEW;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "score_projection_outbox",
        sa.Column("seq", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status", sa.Text(), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column(
            "attempts", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("seq", name="pk_score_projection_outbox"),
        sa.CheckConstraint(
            "status IN ('failed', 'pending')",
            name="ck_score_projection_outbox_status_valid",
        ),
        sa.CheckConstraint(
            "attempts >= 0", name="ck_score_projection_outbox_attempts_nonnegative"
        ),
        sa.ForeignKeyConstraint(
            ["seq"],
            ["score_events.seq"],
            name="fk_score_projection_outbox_seq_score_events",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_score_projection_outbox_competition_id_competitions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_score_projection_outbox_pending_seq",
        "score_projection_outbox",
        ["seq"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_score_projection_outbox_competition_id",
        "score_projection_outbox",
        ["competition_id"],
    )

    op.create_table(
        "scoreboard_projections",
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("as_of_seq", sa.BigInteger(), nullable=False),
        sa.Column(
            "entries",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("competition_id", name="pk_scoreboard_projections"),
        sa.CheckConstraint(
            "as_of_seq >= 0", name="ck_scoreboard_projections_as_of_seq_nonnegative"
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_scoreboard_projections_competition_id_competitions",
            ondelete="RESTRICT",
        ),
    )

    # The outbox trigger (owned here). Applies to EVERY writer of
    # score_events automatically -- a future writer cannot forget it.
    op.execute(_ENQUEUE_FN)
    op.execute(
        "CREATE TRIGGER score_events_enqueue_projection "
        "AFTER INSERT ON score_events "
        "FOR EACH ROW EXECUTE FUNCTION score_events_enqueue_projection();"
    )
    # Backfill: pre-existing events each get one pending row (idempotent).
    op.execute(
        "INSERT INTO score_projection_outbox (seq, competition_id) "
        "SELECT seq, competition_id FROM score_events "
        "ON CONFLICT (seq) DO NOTHING;"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS score_events_enqueue_projection ON score_events;"
    )
    op.execute("DROP FUNCTION IF EXISTS score_events_enqueue_projection();")
    op.drop_table("scoreboard_projections")
    op.drop_index(
        "ix_score_projection_outbox_competition_id",
        table_name="score_projection_outbox",
    )
    op.drop_index(
        "ix_score_projection_outbox_pending_seq",
        table_name="score_projection_outbox",
    )
    op.drop_table("score_projection_outbox")
