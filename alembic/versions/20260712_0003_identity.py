"""identity -- users, teams, memberships (M6 Epic 1)

Creates the three Identity aggregate tables backing the domain ``User``,
``Team`` and ``Membership``. Business identity vs. surrogate keys:

* ``users``   -- surrogate ``id``; business key ``email`` (case-insensitive,
  enforced by the functional unique index ``uq_users_email_lower``).
* ``teams``   -- surrogate ``id``; business key ``(competition_id, name)``. The
  extra ``UNIQUE (id, competition_id)`` is the target of the memberships
  composite FK.
* ``memberships`` -- surrogate ``id``; business key ``(user_id, competition_id)``.
  ``team_id`` is nullable (unteamed/staff) and, when set, is constrained to a
  team in the *same* competition via the composite FK
  ``(team_id, competition_id) -> teams(id, competition_id)``.

Constraint/index names mirror the ORM metadata NAMING_CONVENTION exactly
(rendered from the models) so Alembic autogenerate stays clean.

Revision ID: 0003_identity
Revises: 0002_competitions
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_identity"
down_revision: str | None = "0002_competitions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Kept in sync with ctf_generator.domain.identity.models.VALID_ROLES (sorted).
_ROLES = ("admin", "author", "captain", "judge", "observer", "organizer", "player", "support")
_ROLE_IN_LIST = ", ".join(f"'{r}'" for r in _ROLES)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        # Reject empty AND whitespace-only (mirrors the domain's ``.strip()``).
        sa.CheckConstraint(r"email !~ '^\s*$'", name="ck_users_email_non_empty"),
        sa.CheckConstraint(
            r"display_name !~ '^\s*$'", name="ck_users_display_name_non_empty"
        ),
    )
    # Case-insensitive uniqueness -- a functional unique index, not a UNIQUE
    # constraint (Postgres has no case-insensitive UNIQUE short of this).
    op.create_index(
        "uq_users_email_lower",
        "users",
        [sa.text("lower(email)")],
        unique=True,
    )

    op.create_table(
        "teams",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_teams"),
        sa.UniqueConstraint(
            "competition_id", "name", name="uq_teams_competition_id_name"
        ),
        sa.UniqueConstraint("id", "competition_id", name="uq_teams_id_competition_id"),
        sa.CheckConstraint(r"name !~ '^\s*$'", name="ck_teams_name_non_empty"),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_teams_competition_id_competitions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_teams_competition_id", "teams", ["competition_id"], unique=False)

    op.create_table(
        "memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=True),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_memberships"),
        sa.UniqueConstraint(
            "user_id", "competition_id", name="uq_memberships_user_id_competition_id"
        ),
        sa.CheckConstraint(
            f"role IN ({_ROLE_IN_LIST})", name="ck_memberships_role_valid"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_memberships_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_memberships_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        # Cross-table integrity: placed team must belong to the same competition.
        sa.ForeignKeyConstraint(
            ["team_id", "competition_id"],
            ["teams.id", "teams.competition_id"],
            name="fk_memberships_team_id_teams",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_memberships_competition_id_team_id",
        "memberships",
        ["competition_id", "team_id"],
        unique=False,
    )
    op.create_index(
        "ix_memberships_user_id", "memberships", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_memberships_user_id", table_name="memberships")
    op.drop_index(
        "ix_memberships_competition_id_team_id", table_name="memberships"
    )
    op.drop_table("memberships")
    op.drop_index("ix_teams_competition_id", table_name="teams")
    op.drop_table("teams")
    op.drop_index("uq_users_email_lower", table_name="users")
    op.drop_table("users")
