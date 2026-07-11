"""competitions -- first real aggregate table for the M6 control plane

Creates the ``competitions`` table backing the Competition aggregate. The domain
``CompetitionConfig.competition_id`` maps to the ``slug`` column (the stable
business id); ``id`` is an infrastructure-managed surrogate uuid. ``status``,
``archived_at`` and ``created_at`` are ORM/DB-managed and not surfaced to the
domain. ``default_scoring`` is normalized out to ``competition_challenges`` in a
later step and is NOT stored here.

Constraint names follow the metadata NAMING_CONVENTION in
``infrastructure.database.base`` (ck_%(table_name)s_%(constraint_name)s, etc.)
so autogenerate stays stable against the ORM models.

Revision ID: 0002_competitions
Revises: 0001_baseline
Create Date: 2026-07-11
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_competitions"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "competitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scoring_start_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("freeze_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'draft'"),
        ),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_competitions"),
        sa.UniqueConstraint("slug", name="uq_competitions_slug"),
        sa.CheckConstraint(
            "char_length(name) > 0",
            name="ck_competitions_name_non_empty",
        ),
        sa.CheckConstraint(
            "end_time > start_time",
            name="ck_competitions_end_after_start",
        ),
        sa.CheckConstraint(
            "freeze_time IS NULL OR "
            "(freeze_time >= start_time AND freeze_time <= end_time)",
            name="ck_competitions_freeze_within_bounds",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'scheduled', 'live', 'frozen', 'ended', 'archived')",
            name="ck_competitions_status_valid",
        ),
    )
    op.create_index(
        "ix_competitions_status",
        "competitions",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_competitions_status", table_name="competitions")
    op.drop_table("competitions")
