"""SQLAlchemy 2.0 ORM models for the M6 persistence layer.

Infrastructure-only: these types import SQLAlchemy and therefore must never be
imported by the domain. ORM objects never escape this package -- repositories
map them to/from domain aggregates via ``mappers.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ...domain.identity.models import VALID_ROLES
from .base import Base

# Allowed lifecycle states for a competition row. ``status`` is ORM-managed and
# has no domain counterpart; it defaults to 'draft' on insert.
_COMPETITION_STATUSES = ("draft", "scheduled", "live", "frozen", "ended", "archived")

# SQL fragment listing the valid roles for the memberships CHECK constraint.
# Sourced from the domain's VALID_ROLES (single source of truth) and sorted so
# the generated SQL is deterministic and matches the migration byte-for-byte.
_ROLE_IN_LIST = ", ".join(f"'{r}'" for r in sorted(VALID_ROLES))


class Competition(Base):
    """Persistent form of the domain ``CompetitionConfig`` aggregate.

    ``id`` is a surrogate uuid owned by infrastructure and never surfaced to the
    domain; ``slug`` carries the stable business id (domain ``competition_id``).
    ``status``/``archived_at``/``created_at`` are ORM-managed lifecycle columns
    with no domain fields. ``default_scoring`` is intentionally absent -- it is
    normalized into ``competition_challenges`` in a later step.
    """

    __tablename__ = "competitions"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    start_time: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    end_time: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    scoring_start_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    freeze_time: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'draft'"), default="draft"
    )
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint("slug", name="uq_competitions_slug"),
        CheckConstraint("end_time > start_time", name="end_after_start"),
        CheckConstraint(
            "freeze_time IS NULL OR "
            "(freeze_time >= start_time AND freeze_time <= end_time)",
            name="freeze_within_bounds",
        ),
        CheckConstraint("char_length(name) > 0", name="name_non_empty"),
        CheckConstraint(
            "status IN ('draft', 'scheduled', 'live', 'frozen', 'ended', 'archived')",
            name="status_valid",
        ),
        Index("ix_competitions_status", "status"),
    )


class User(Base):
    """Persistent form of the domain ``User`` aggregate.

    ``id`` is a surrogate uuid owned by infrastructure and never surfaced to the
    domain; ``email`` carries the business identity. Uniqueness is enforced
    case-insensitively via a *functional* unique index on ``lower(email)`` (see
    ``__table_args__``), so the plain column is not itself declared UNIQUE.
    ``archived_at`` / ``created_at`` are ORM-managed lifecycle columns with no
    domain fields.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(sa.Text, nullable=False)
    display_name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        # Reject empty AND whitespace-only, mirroring the domain's ``.strip()``
        # rule so the DB is a genuine backstop (``^\s*$`` matches an all-blank
        # string; ``!~`` negates it).
        CheckConstraint(r"email !~ '^\s*$'", name="email_non_empty"),
        CheckConstraint(r"display_name !~ '^\s*$'", name="display_name_non_empty"),
        # Case-insensitive uniqueness. Expressed as a functional index rather
        # than a UNIQUE constraint (Postgres has no case-insensitive UNIQUE
        # short of this). The migration creates the same index by name.
        Index(
            "uq_users_email_lower",
            sa.text("lower(email)"),
            unique=True,
        ),
    )


class Team(Base):
    """Persistent form of the domain ``Team`` aggregate.

    ``id`` is a surrogate uuid; the business identity is ``(competition_id,
    name)``. ``competition_id`` is a uuid FK to ``competitions.id`` (RESTRICT --
    competitions are archived, not deleted). The extra ``UNIQUE (id,
    competition_id)`` exists solely as the *target* of the memberships composite
    FK, which is how "a member's team belongs to the same competition" becomes a
    DB guarantee rather than app logic.
    """

    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("competitions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint("competition_id", "name", name="uq_teams_competition_id_name"),
        # Composite-FK target for memberships(team_id, competition_id).
        UniqueConstraint("id", "competition_id", name="uq_teams_id_competition_id"),
        CheckConstraint(r"name !~ '^\s*$'", name="name_non_empty"),
        Index("ix_teams_competition_id", "competition_id"),
    )


class Membership(Base):
    """Persistent form of the domain ``Membership`` aggregate.

    ``id`` is a surrogate uuid; the business identity is ``(user_id,
    competition_id)`` (UNIQUE). ``role`` is CHECK-constrained to the domain's
    ``VALID_ROLES``. ``team_id`` is nullable (NULL = unteamed/staff) and, when
    present, is validated to belong to ``competition_id`` via a *composite* FK
    to ``teams (id, competition_id)`` -- so a member can never be placed on a
    team from a different competition. ``competition_id`` additionally FKs
    ``competitions.id`` directly, so the unteamed case is still integrity-checked
    (the composite FK is not enforced when ``team_id`` is NULL).
    """

    __tablename__ = "memberships"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("competitions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, nullable=True)
    role: Mapped[str] = mapped_column(sa.Text, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id", "competition_id", name="uq_memberships_user_id_competition_id"
        ),
        # Cross-table integrity: the placed team must belong to the same
        # competition. MATCH SIMPLE -> not enforced when team_id is NULL, which
        # is exactly the unteamed case we want to allow.
        ForeignKeyConstraint(
            ["team_id", "competition_id"],
            ["teams.id", "teams.competition_id"],
            ondelete="RESTRICT",
        ),
        CheckConstraint(f"role IN ({_ROLE_IN_LIST})", name="role_valid"),
        Index(
            "ix_memberships_competition_id_team_id", "competition_id", "team_id"
        ),
        Index("ix_memberships_user_id", "user_id"),
    )
