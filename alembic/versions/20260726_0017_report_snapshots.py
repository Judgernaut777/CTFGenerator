"""report_snapshots -- immutable, append-only report records

Creates the ``report_snapshots`` table (M-reports): one row per FROZEN report
(``validation`` / ``build`` / ``competition_run`` / ``eval``). A report is a
read-only summary computed from already-persisted data; a snapshot archives it as
an auditable record. SECRET-FREE by construction (references/hashes/counts only).
APPEND-ONLY + TAMPER-EVIDENT: the shared ``reject_mutation`` guard (from 0004) is
attached as BEFORE UPDATE OR DELETE + BEFORE TRUNCATE triggers, so a persisted
snapshot can never be altered or deleted. ``report_type`` is CHECK-constrained to
the domain's closed set (rendered from ``VALID_REPORT_TYPES`` so ORM + migration
cannot drift). Names mirror the ORM metadata exactly (autogenerate-clean);
reversible.

Revision ID: 0017_report_snapshots
Revises: 0016_build_stack_images
Create Date: 2026-07-26
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from ctf_generator.domain.reports.models import VALID_REPORT_TYPES

revision: str = "0017_report_snapshots"
down_revision: str | None = "0016_build_stack_images"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REPORT_TYPE_IN_LIST = ", ".join(f"'{t}'" for t in sorted(VALID_REPORT_TYPES))


def upgrade() -> None:
    op.create_table(
        "report_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_type", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("definition_slug", sa.Text(), nullable=True),
        sa.Column("version_no", sa.Integer(), nullable=True),
        sa.Column("competition_id", sa.Text(), nullable=True),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_report_snapshots"),
        sa.CheckConstraint(
            f"report_type IN ({_REPORT_TYPE_IN_LIST})",
            name="ck_report_snapshots_report_type_valid",
        ),
        sa.CheckConstraint(
            r"subject !~ '^\s*$'", name="ck_report_snapshots_subject_non_empty"
        ),
        sa.CheckConstraint(
            r"created_by !~ '^\s*$'",
            name="ck_report_snapshots_created_by_non_empty",
        ),
    )
    op.create_index(
        "ix_report_snapshots_type_subject",
        "report_snapshots",
        ["report_type", "subject"],
    )
    op.create_index(
        "ix_report_snapshots_created_at", "report_snapshots", ["created_at"]
    )

    op.execute(
        "CREATE TRIGGER report_snapshots_immutable "
        "BEFORE UPDATE OR DELETE ON report_snapshots "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER report_snapshots_no_truncate "
        "BEFORE TRUNCATE ON report_snapshots "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS report_snapshots_no_truncate ON report_snapshots;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS report_snapshots_immutable ON report_snapshots;"
    )
    op.drop_index(
        "ix_report_snapshots_created_at", table_name="report_snapshots"
    )
    op.drop_index(
        "ix_report_snapshots_type_subject", table_name="report_snapshots"
    )
    op.drop_table("report_snapshots")
    # reject_mutation() is owned by 0004; not dropped here.
