"""ledger -- submissions, solves, score_events (M6 Epic 3)

Creates the append-only competition ledger (persistence design §6):

* ``submissions``  -- every answer attempt; composite FK guarantees the team is
  in the submission's competition; a 4-col UNIQUE is the composite-FK target for
  solves.
* ``solves``       -- at-most-one accepted result per (competition, team,
  challenge version) via a UNIQUE; a composite FK forces the referenced
  submission to match the whole identity tuple, and a trigger requires it to be
  ``correct``.
* ``score_events`` -- the durable event-sourced ledger; ``seq`` (identity /
  bigserial) supplies the strictly monotonic order the in-process store produced
  with a lock.

All three are append-only: a BEFORE UPDATE OR DELETE trigger (the shared
``reject_mutation`` from ``0004``) plus a BEFORE TRUNCATE guard reject mutation.
All FKs ON DELETE RESTRICT. Names mirror the ORM metadata (autogenerate-clean).

Revision ID: 0005_ledger
Revises: 0004_challenges
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_ledger"
down_revision: str | None = "0004_challenges"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EVENT_TYPES = ("first_blood", "freeze", "revalue", "solve", "submission")
_TYPE_IN = ", ".join(f"'{t}'" for t in _EVENT_TYPES)

# A solve may only reference a CORRECT submission (design §6). The composite FK
# already forces the (competition, team, version) tuple to match; this adds the
# correctness half.
_SOLVE_CORRECT_FN = """
CREATE OR REPLACE FUNCTION solve_requires_correct_submission() RETURNS trigger AS $$
DECLARE is_correct boolean;
BEGIN
  SELECT correct INTO is_correct FROM submissions WHERE id = NEW.submission_id;
  IF is_correct IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'solve must reference a correct submission (id=%)', NEW.submission_id;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
"""

_APPEND_ONLY_TABLES = ("submissions", "solves", "score_events")


def _append_only_triggers(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER {table}_immutable "
        f"BEFORE UPDATE OR DELETE ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        f"CREATE TRIGGER {table}_no_truncate "
        f"BEFORE TRUNCATE ON {table} "
        f"FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def upgrade() -> None:
    op.create_table(
        "submissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correct", sa.Boolean(), nullable=False),
        sa.Column("instance_seed", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_submissions"),
        sa.UniqueConstraint(
            "id",
            "competition_id",
            "team_id",
            "challenge_version_id",
            name="uq_submissions_id_competition_id_team_id_challenge_version_id",
        ),
        sa.ForeignKeyConstraint(
            ["team_id", "competition_id"],
            ["teams.id", "teams.competition_id"],
            name="fk_submissions_team_id_teams",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_submissions_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_submissions_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_submissions_user_id_users",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_submissions_competition_id_team_id_submitted_at",
        "submissions",
        ["competition_id", "team_id", "submitted_at"],
    )
    op.create_index(
        "ix_submissions_challenge_version_id",
        "submissions",
        ["challenge_version_id"],
    )
    op.create_index(
        "ix_submissions_correct",
        "submissions",
        ["competition_id", "challenge_version_id"],
        postgresql_where=sa.text("correct"),
    )

    op.create_table(
        "solves",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("solved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("instance_seed", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_solves"),
        sa.UniqueConstraint(
            "competition_id",
            "team_id",
            "challenge_version_id",
            name="uq_solves_competition_id_team_id_challenge_version_id",
        ),
        sa.UniqueConstraint("submission_id", name="uq_solves_submission_id"),
        sa.ForeignKeyConstraint(
            ["submission_id", "competition_id", "team_id", "challenge_version_id"],
            [
                "submissions.id",
                "submissions.competition_id",
                "submissions.team_id",
                "submissions.challenge_version_id",
            ],
            name="fk_solves_submission_tuple_submissions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_solves_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["teams.id"],
            name="fk_solves_team_id_teams",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_solves_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_solves_competition_id_challenge_version_id_solved_at",
        "solves",
        ["competition_id", "challenge_version_id", "solved_at"],
    )

    op.create_table(
        "score_events",
        sa.Column(
            "seq",
            sa.BigInteger(),
            sa.Identity(always=True),
            nullable=False,
        ),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("ts", sa.Text(), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("submission_id", sa.Uuid(), nullable=True),
        sa.Column("solve_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("seq", name="pk_score_events"),
        sa.CheckConstraint(
            f"type IN ({_TYPE_IN})", name="ck_score_events_type_valid"
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_score_events_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["teams.id"],
            name="fk_score_events_team_id_teams",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_score_events_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name="fk_score_events_submission_id_submissions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["solve_id"],
            ["solves.id"],
            name="fk_score_events_solve_id_solves",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_score_events_competition_id_seq", "score_events", ["competition_id", "seq"]
    )
    op.create_index("ix_score_events_type", "score_events", ["type"])

    # Immutability backstops. reject_mutation() is created and owned by 0004
    # (which always runs first); we reuse it here rather than redefining its body.
    op.execute(_SOLVE_CORRECT_FN)
    for table in _APPEND_ONLY_TABLES:
        _append_only_triggers(table)
    op.execute(
        "CREATE TRIGGER solves_require_correct_submission "
        "BEFORE INSERT ON solves "
        "FOR EACH ROW EXECUTE FUNCTION solve_requires_correct_submission();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS solves_require_correct_submission ON solves;"
    )
    for table in _APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table};")
        op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table};")
    op.execute("DROP FUNCTION IF EXISTS solve_requires_correct_submission();")
    # reject_mutation() is owned by 0004; not dropped here.

    op.drop_index("ix_score_events_type", table_name="score_events")
    op.drop_index("ix_score_events_competition_id_seq", table_name="score_events")
    op.drop_table("score_events")
    op.drop_index(
        "ix_solves_competition_id_challenge_version_id_solved_at", table_name="solves"
    )
    op.drop_table("solves")
    op.drop_index("ix_submissions_correct", table_name="submissions")
    op.drop_index(
        "ix_submissions_challenge_version_id", table_name="submissions"
    )
    op.drop_index(
        "ix_submissions_competition_id_team_id_submitted_at", table_name="submissions"
    )
    op.drop_table("submissions")
