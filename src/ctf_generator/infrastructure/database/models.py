"""SQLAlchemy 2.0 ORM models for the M6 persistence layer.

Infrastructure-only: these types import SQLAlchemy and therefore must never be
imported by the domain. ORM objects never escape this package -- repositories
map them to/from domain aggregates via ``mappers.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import CheckConstraint, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base

# Allowed lifecycle states for a competition row. ``status`` is ORM-managed and
# has no domain counterpart; it defaults to 'draft' on insert.
_COMPETITION_STATUSES = ("draft", "scheduled", "live", "frozen", "ended", "archived")


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
