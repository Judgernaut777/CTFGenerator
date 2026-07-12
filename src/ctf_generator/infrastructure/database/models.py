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
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ...domain.authoring.models import VALID_DECAY_FUNCTIONS, VALID_VERSION_STATES
from ...domain.identity.models import VALID_ROLES
from .base import Base

# Allowed lifecycle states for a competition row. ``status`` is ORM-managed and
# has no domain counterpart; it defaults to 'draft' on insert.
_COMPETITION_STATUSES = ("draft", "scheduled", "live", "frozen", "ended", "archived")

# SQL fragment listing the valid roles for the memberships CHECK constraint.
# Sourced from the domain's VALID_ROLES (single source of truth) and sorted so
# the generated SQL is deterministic and matches the migration byte-for-byte.
_ROLE_IN_LIST = ", ".join(f"'{r}'" for r in sorted(VALID_ROLES))
# Likewise for challenge-version lifecycle states and scoring decay functions.
_VERSION_STATE_IN_LIST = ", ".join(f"'{s}'" for s in sorted(VALID_VERSION_STATES))
_DECAY_FUNCTION_IN_LIST = ", ".join(f"'{d}'" for d in sorted(VALID_DECAY_FUNCTIONS))


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


class ChallengeDefinition(Base):
    """Persistent form of the domain ``ChallengeDefinition`` -- the stable
    identity of a challenge across edits. ``slug`` is the business id; ``id`` is
    a surrogate uuid never surfaced to the domain. ``family`` is stored as text
    (the family registry is code, validated at the application layer)."""

    __tablename__ = "challenge_definitions"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    family: Mapped[str] = mapped_column(sa.Text, nullable=False)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False)
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint("slug", name="uq_challenge_definitions_slug"),
        CheckConstraint(r"family !~ '^\s*$'", name="family_non_empty"),
        CheckConstraint(r"slug !~ '^\s*$'", name="slug_non_empty"),
        CheckConstraint(r"title !~ '^\s*$'", name="title_non_empty"),
        Index("ix_challenge_definitions_family", "family"),
    )


class ChallengeVersion(Base):
    """Persistent form of the domain ``ChallengeVersion``. Business identity is
    ``(definition_id, version_no)``. ``spec_sha256`` is the authoritative content
    hash; ``spec_json`` is a queryable ``jsonb`` copy. Content columns freeze once
    ``state='published'`` (a trigger is the backstop -- see migration). The
    ``published_state_consistent`` CHECK ties ``state`` to ``published_at``."""

    __tablename__ = "challenge_versions"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    definition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_definitions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version_no: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    state: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'draft'")
    )
    family_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    seed: Mapped[str] = mapped_column(sa.Text, nullable=False)
    mode: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'red'")
    )
    spec_sha256: Mapped[str] = mapped_column(sa.Text, nullable=False)
    spec_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    cve_refs: Mapped[list[str] | None] = mapped_column(ARRAY(sa.Text), nullable=True)
    cve_content_hash: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    spec_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "definition_id", "version_no", name="uq_challenge_versions_definition_id_version_no"
        ),
        UniqueConstraint(
            "definition_id", "spec_sha256", name="uq_challenge_versions_definition_id_spec_sha256"
        ),
        CheckConstraint("version_no >= 1", name="version_no_positive"),
        CheckConstraint(
            f"state IN ({_VERSION_STATE_IN_LIST})", name="state_valid"
        ),
        # published_at is stamped when the version leaves draft and retained
        # through archived, so a version has a timestamp iff it is not a draft.
        CheckConstraint(
            "(state = 'draft') = (published_at IS NULL)",
            name="published_state_consistent",
        ),
        Index("ix_challenge_versions_definition_id_state", "definition_id", "state"),
        Index("ix_challenge_versions_spec_sha256", "spec_sha256"),
    )


class ChallengeBuild(Base):
    """Persistent form of the domain ``ChallengeBuild`` -- the content-addressed,
    insert-only artifact of a version. PK is the content address ``build_sha256``
    (no surrogate). The whole row is insert-only (a trigger is the backstop)."""

    __tablename__ = "challenge_builds"

    build_sha256: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    challenge_version_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    family: Mapped[str] = mapped_column(sa.Text, nullable=False)
    seed: Mapped[str] = mapped_column(sa.Text, nullable=False)
    family_version: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    spec_sha256: Mapped[str] = mapped_column(sa.Text, nullable=False)
    generator_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    manifest_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    storage_uri: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        # NULLS NOT DISTINCT (PG15+) so a NULL family_version still collides --
        # otherwise the "one build per (version, toolchain, seed)" invariant is
        # silently disabled for null-family builds (Postgres default NULLS
        # DISTINCT treats every NULL as unique).
        UniqueConstraint(
            "challenge_version_id",
            "family_version",
            "generator_version",
            "seed",
            name="uq_challenge_builds_version_toolchain_seed",
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_challenge_builds_challenge_version_id", "challenge_version_id"),
    )


class CompetitionChallenge(Base):
    """Persistent form of the domain ``ChallengePublication`` -- a published
    version attached to a competition with its per-competition scoring config
    (the normalized ``ChallengeScoringConfig`` / ``FirstBloodBonusConfig``).
    Business identity is ``(competition_id, challenge_version_id)``."""

    __tablename__ = "competition_challenges"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("competitions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    challenge_version_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    initial_value: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("500")
    )
    minimum_value: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("100")
    )
    decay_function: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'static'")
    )
    decay: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )
    first_blood_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )
    first_blood_bonus_points: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )
    first_blood_bonus_percent: Mapped[float] = mapped_column(
        sa.Double, nullable=False, server_default=sa.text("0")
    )
    archived_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "competition_id",
            "challenge_version_id",
            name="uq_competition_challenges_competition_id_challenge_version_id",
        ),
        CheckConstraint(
            f"decay_function IN ({_DECAY_FUNCTION_IN_LIST})", name="decay_function_valid"
        ),
        CheckConstraint("initial_value >= 0", name="initial_value_non_negative"),
        CheckConstraint(
            "minimum_value <= initial_value", name="minimum_le_initial"
        ),
        CheckConstraint("decay >= 0", name="decay_non_negative"),
        CheckConstraint(
            "first_blood_bonus_points >= 0", name="first_blood_points_non_negative"
        ),
        CheckConstraint(
            "first_blood_bonus_percent >= 0", name="first_blood_percent_non_negative"
        ),
        Index("ix_competition_challenges_competition_id", "competition_id"),
    )
