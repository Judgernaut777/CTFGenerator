"""jobs -- durable PostgreSQL job queue (M7, ADR-003)

Creates the execution-plane work queue:

* ``jobs`` -- one row per unit of background work. Claimed via
  ``SELECT ... LIMIT 1 FOR UPDATE SKIP LOCKED`` over the partial
  ``ix_jobs_claim`` index; ``idempotency_key`` UNIQUE is the dedupe business
  key; CHECK constraints tie state to its fields (lease columns iff
  claimed/running, ``finished_at`` iff terminal, ``error_class`` for
  failed/dead_letter). The ``job_transition_guard`` BEFORE UPDATE trigger
  (owned here) enforces the legal-transition matrix, freezes fully-terminal
  rows (dead_letter's one exit is the operator requeue to queued), and
  freezes id/job_type/payload/idempotency_key/created_at after insert.
* ``job_transitions`` -- append-only per-attempt state history, written in
  the same transaction as every state change. Immutability via the shared
  ``reject_mutation()`` (created and owned by ``0004``; reused BY NAME, never
  redefined).

All FKs ON DELETE RESTRICT. Constraint/index names mirror the ORM metadata
byte-for-byte (autogenerate-clean). The transition matrix below is rendered
from the domain's ``LEGAL_JOB_TRANSITIONS`` (an integration test asserts DB
accept/reject matches the domain constant pair-for-pair).

Revision ID: 0006_jobs
Revises: 0005_ledger
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_jobs"
down_revision: str | None = "0005_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Sorted renderings of the domain frozensets (VALID_JOB_TYPES /
# VALID_JOB_STATUSES / VALID_JOB_ERROR_CLASSES / TERMINAL_JOB_STATUSES),
# frozen here so the migration is stable even if the domain evolves later.
_JOB_TYPES = (
    "build_challenge",
    "collect_logs",
    "delete_runtime_resources",
    "expire_instance",
    "launch_instance",
    "reset_instance",
    "restart_instance",
    "run_agent_evaluation",
    "run_health_check",
    "run_intended_solver",
    "stop_instance",
    "validate_challenge",
)
_JOB_STATUSES = (
    "cancelled",
    "claimed",
    "dead_letter",
    "failed",
    "queued",
    "running",
    "succeeded",
)
_ERROR_CLASSES = (
    "cancelled",
    "infrastructure",
    "internal",
    "lease_expired",
    "timeout",
    "transient",
    "validation",
)
_TERMINAL = ("cancelled", "dead_letter", "failed", "succeeded")

_TYPE_IN = ", ".join(f"'{t}'" for t in _JOB_TYPES)
_STATUS_IN = ", ".join(f"'{s}'" for s in _JOB_STATUSES)
_ERROR_IN = ", ".join(f"'{c}'" for c in _ERROR_CLASSES)
_TERMINAL_IN = ", ".join(f"'{s}'" for s in _TERMINAL)

# The legal-transition matrix (mirrors domain.work.models.LEGAL_JOB_TRANSITIONS
# byte-equivalently). Self-transitions are field updates (heartbeat, cancel
# stamp) and are allowed for every non-terminal status; terminal rows are
# frozen except dead_letter -> queued (the operator requeue).
_GUARD_FN = f"""
CREATE OR REPLACE FUNCTION job_transition_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.id IS DISTINCT FROM NEW.id
     OR OLD.job_type IS DISTINCT FROM NEW.job_type
     OR OLD.payload IS DISTINCT FROM NEW.payload
     OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
     OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
    RAISE EXCEPTION 'jobs: immutable column changed (id=%)', OLD.id;
  END IF;
  IF NEW.status = OLD.status THEN
    IF OLD.status IN ({_TERMINAL_IN}) THEN
      RAISE EXCEPTION 'jobs: row % is terminal (%); it is frozen',
        OLD.id, OLD.status;
    END IF;
    RETURN NEW;
  END IF;
  IF (OLD.status = 'queued' AND NEW.status IN ('claimed', 'cancelled'))
     OR (OLD.status = 'claimed'
         AND NEW.status IN ('running', 'queued', 'cancelled', 'dead_letter'))
     OR (OLD.status = 'running'
         AND NEW.status IN ('succeeded', 'failed', 'queued', 'cancelled',
                            'dead_letter'))
     OR (OLD.status = 'dead_letter' AND NEW.status = 'queued') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'jobs: illegal transition % -> % (id=%)',
    OLD.status, NEW.status, OLD.id;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.Text(), nullable=False, server_default=sa.text("'queued'")
        ),
        sa.Column(
            "priority", sa.Integer(), nullable=False, server_default=sa.text("100")
        ),
        sa.Column(
            "payload",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column(
            "required_capabilities",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column(
            "attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "max_attempts", sa.Integer(), nullable=False, server_default=sa.text("3")
        ),
        sa.Column(
            "backoff_base_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("30"),
        ),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_by", sa.Text(), nullable=True),
        sa.Column("lease_token", sa.Uuid(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_class", sa.Text(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("result_json", postgresql.JSONB(), nullable=True),
        sa.Column("result_ref", sa.Text(), nullable=True),
        sa.Column("log_ref", sa.Text(), nullable=True),
        sa.Column("competition_id", sa.Uuid(), nullable=True),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_jobs"),
        sa.UniqueConstraint("idempotency_key", name="uq_jobs_idempotency_key"),
        sa.CheckConstraint(f"job_type IN ({_TYPE_IN})", name="ck_jobs_type_valid"),
        sa.CheckConstraint(f"status IN ({_STATUS_IN})", name="ck_jobs_status_valid"),
        sa.CheckConstraint(
            f"error_class IS NULL OR error_class IN ({_ERROR_IN})",
            name="ck_jobs_error_class_valid",
        ),
        sa.CheckConstraint(
            r"idempotency_key !~ '^\s*$'", name="ck_jobs_idempotency_key_non_empty"
        ),
        sa.CheckConstraint("priority >= 0", name="ck_jobs_priority_non_negative"),
        sa.CheckConstraint("max_attempts >= 1", name="ck_jobs_max_attempts_positive"),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= max_attempts",
            name="ck_jobs_attempts_bounded",
        ),
        sa.CheckConstraint(
            "backoff_base_seconds >= 1", name="ck_jobs_backoff_positive"
        ),
        sa.CheckConstraint(
            "(status IN ('claimed', 'running')) = "
            "(claimed_by IS NOT NULL AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL)",
            name="ck_jobs_lease_state",
        ),
        sa.CheckConstraint(
            "status <> 'running' OR started_at IS NOT NULL",
            name="ck_jobs_running_started",
        ),
        sa.CheckConstraint(
            f"(status IN ({_TERMINAL_IN})) = (finished_at IS NOT NULL)",
            name="ck_jobs_terminal_finished",
        ),
        sa.CheckConstraint(
            "status NOT IN ('dead_letter', 'failed') OR error_class IS NOT NULL",
            name="ck_jobs_failure_classified",
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_jobs_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_jobs_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_jobs_claim",
        "jobs",
        ["priority", "available_at"],
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index(
        "ix_jobs_lease_reap",
        "jobs",
        ["lease_expires_at"],
        postgresql_where=sa.text("status IN ('claimed', 'running')"),
    )
    op.create_index("ix_jobs_competition_id", "jobs", ["competition_id"])

    op.create_table(
        "job_transitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("from_status", sa.Text(), nullable=True),
        sa.Column("to_status", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.Text(), nullable=True),
        sa.Column("error_class", sa.Text(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_job_transitions"),
        sa.CheckConstraint(
            f"to_status IN ({_STATUS_IN})", name="ck_job_transitions_to_status_valid"
        ),
        sa.CheckConstraint(
            f"from_status IS NULL OR from_status IN ({_STATUS_IN})",
            name="ck_job_transitions_from_status_valid",
        ),
        sa.CheckConstraint(
            "attempt >= 0", name="ck_job_transitions_attempt_non_negative"
        ),
        sa.CheckConstraint(
            f"error_class IS NULL OR error_class IN ({_ERROR_IN})",
            name="ck_job_transitions_error_class_valid",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name="fk_job_transitions_job_id_jobs",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_job_transitions_job_id_occurred_at",
        "job_transitions",
        ["job_id", "occurred_at"],
    )

    # The transition guard (owned by 0006; dropped on downgrade).
    op.execute(_GUARD_FN)
    op.execute(
        "CREATE TRIGGER jobs_transition_guard "
        "BEFORE UPDATE ON jobs "
        "FOR EACH ROW EXECUTE FUNCTION job_transition_guard();"
    )
    # Append-only backstops on job_transitions -- reject_mutation() is created
    # and owned by 0004 (which always runs first); reused BY NAME, never
    # redefined (exactly the 0005 pattern).
    op.execute(
        "CREATE TRIGGER job_transitions_immutable "
        "BEFORE UPDATE OR DELETE ON job_transitions "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER job_transitions_no_truncate "
        "BEFORE TRUNCATE ON job_transitions "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS job_transitions_no_truncate ON job_transitions;"
    )
    op.execute("DROP TRIGGER IF EXISTS job_transitions_immutable ON job_transitions;")
    op.execute("DROP TRIGGER IF EXISTS jobs_transition_guard ON jobs;")
    op.execute("DROP FUNCTION IF EXISTS job_transition_guard();")
    # reject_mutation() is owned by 0004; not dropped here.

    op.drop_index("ix_job_transitions_job_id_occurred_at", table_name="job_transitions")
    op.drop_table("job_transitions")
    op.drop_index("ix_jobs_competition_id", table_name="jobs")
    op.drop_index("ix_jobs_lease_reap", table_name="jobs")
    op.drop_index("ix_jobs_claim", table_name="jobs")
    op.drop_table("jobs")
