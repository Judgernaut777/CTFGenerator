"""eval_runs -- the agent-evaluation platform record (M15 slice 15a)

Creates the ``eval_runs`` table: the durable, operator-visible record of one
agent-evaluation of a challenge version. A run references the version it
evaluates (``challenge_version_id`` FK, ``ON DELETE RESTRICT``) and is keyed by
the caller-supplied ``id`` (uuid). The dedupe key ``(challenge_version_id,
profile, adversarial)`` is UNIQUE so a re-request collapses to one record --
matching the enqueue idempotency key ``eval:{slug}:v{n}:{profile}:{adversarial}``.

SECRET-FREE by construction: there is NO flag/token/answer column -- only the
advisory outcome subset (solved / steps / success_dropped / step_delta /
blended_score) and sanitized ``notes``/``error`` (references/summaries only).
CHECKs tie those columns to ``status``; the ``eval_run_transition_guard``
BEFORE UPDATE trigger freezes terminal rows and the immutable identity columns
(the application service is the primary guard, this is the backstop).

Not immutable/append-only: status moves (pending/running -> succeeded/failed)
are legitimate UPDATEs, so this table does NOT use the shared ``reject_mutation``
guard; instead a small transition guard forbids leaving a terminal state.

Constraint/index/trigger names mirror the ORM metadata NAMING_CONVENTION exactly
(autogenerate-clean); reversible.

Revision ID: 0013_eval_runs
Revises: 0012_oidc_login_transactions
Create Date: 2026-07-13
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_eval_runs"
down_revision: str | None = "0012_oidc_login_transactions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copies of the domain VALID_* sets (sorted), matching the ORM CHECKs.
_EVAL_PROFILES = ("llm_agent", "one_shot_prompt", "tool_using_agent", "writeup_replay")
_EVAL_STATUSES = ("failed", "pending", "running", "succeeded")
_PROFILE_IN = ", ".join(f"'{p}'" for p in _EVAL_PROFILES)
_STATUS_IN = ", ".join(f"'{s}'" for s in _EVAL_STATUSES)

# BEFORE UPDATE guard: identity columns are immutable; a terminal row is frozen;
# only the legal status transitions are permitted (mirrors the domain's
# LEGAL_EVAL_TRANSITIONS). A self-transition is a no-op field update.
_GUARD_FN = """
CREATE OR REPLACE FUNCTION eval_run_transition_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.id IS DISTINCT FROM NEW.id
     OR OLD.challenge_version_id IS DISTINCT FROM NEW.challenge_version_id
     OR OLD.profile IS DISTINCT FROM NEW.profile
     OR OLD.adversarial IS DISTINCT FROM NEW.adversarial
     OR OLD.requested_at IS DISTINCT FROM NEW.requested_at
     OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
    RAISE EXCEPTION 'eval_runs: immutable column changed (id=%)', OLD.id;
  END IF;
  IF OLD.status IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'eval_runs: row % is % (terminal); it is frozen',
      OLD.id, OLD.status;
  END IF;
  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  IF (OLD.status = 'pending'
        AND NEW.status IN ('running', 'succeeded', 'failed'))
     OR (OLD.status = 'running'
        AND NEW.status IN ('succeeded', 'failed'))
     THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'eval_runs: illegal transition % -> % (id=%)',
    OLD.status, NEW.status, OLD.id;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "eval_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("profile", sa.Text(), nullable=False),
        sa.Column("adversarial", sa.Boolean(), nullable=False),
        sa.Column(
            "status", sa.Text(), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("solved", sa.Boolean(), nullable=True),
        sa.Column("steps", sa.Integer(), nullable=True),
        sa.Column("success_dropped", sa.Boolean(), nullable=True),
        sa.Column("step_delta", sa.Integer(), nullable=True),
        sa.Column("blended_score", sa.Double(), nullable=True),
        sa.Column("notes", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_eval_runs"),
        sa.UniqueConstraint(
            "challenge_version_id",
            "profile",
            "adversarial",
            name="uq_eval_runs_challenge_version_id_profile_adversarial",
        ),
        sa.CheckConstraint(
            f"profile IN ({_PROFILE_IN})", name="ck_eval_runs_profile_valid"
        ),
        sa.CheckConstraint(
            f"status IN ({_STATUS_IN})", name="ck_eval_runs_status_valid"
        ),
        sa.CheckConstraint(
            "steps IS NULL OR steps >= 0", name="ck_eval_runs_steps_non_negative"
        ),
        sa.CheckConstraint(
            "(status IN ('succeeded', 'failed')) = (completed_at IS NOT NULL)",
            name="ck_eval_runs_completed_state_consistent",
        ),
        sa.CheckConstraint(
            "status = 'succeeded' OR (solved IS NULL AND steps IS NULL "
            "AND success_dropped IS NULL AND step_delta IS NULL "
            "AND blended_score IS NULL)",
            name="ck_eval_runs_result_only_when_succeeded",
        ),
        sa.CheckConstraint(
            "(status = 'failed') = (error IS NOT NULL)",
            name="ck_eval_runs_error_only_when_failed",
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_eval_runs_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_eval_runs_challenge_version_id", "eval_runs", ["challenge_version_id"]
    )

    op.execute(_GUARD_FN)
    op.execute(
        "CREATE TRIGGER eval_runs_transition_guard "
        "BEFORE UPDATE ON eval_runs "
        "FOR EACH ROW EXECUTE FUNCTION eval_run_transition_guard();"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS eval_runs_transition_guard ON eval_runs;")
    op.execute("DROP FUNCTION IF EXISTS eval_run_transition_guard();")
    op.drop_index("ix_eval_runs_challenge_version_id", table_name="eval_runs")
    op.drop_table("eval_runs")
