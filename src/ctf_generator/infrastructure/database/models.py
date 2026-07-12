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
from ...domain.execution.models import VALID_RUNTIME_TYPES, VALID_TRUST_STATES
from ...domain.identity.models import VALID_ROLES
from ...domain.ledger.models import (
    VALID_PROJECTION_TASK_STATUSES,
    VALID_SCORE_EVENT_TYPES,
)
from ...domain.work.models import (
    TERMINAL_JOB_STATUSES,
    VALID_JOB_ERROR_CLASSES,
    VALID_JOB_STATUSES,
    VALID_JOB_TYPES,
)
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
_SCORE_EVENT_TYPE_IN_LIST = ", ".join(
    f"'{t}'" for t in sorted(VALID_SCORE_EVENT_TYPES)
)
# M7: job queue, worker trust, and projection-outbox enumerations -- rendered
# from the domain frozensets (single source of truth) and sorted, so the ORM
# CHECK SQL and the migration SQL cannot drift from the domain or each other.
_JOB_TYPE_IN_LIST = ", ".join(f"'{t}'" for t in sorted(VALID_JOB_TYPES))
_JOB_STATUS_IN_LIST = ", ".join(f"'{s}'" for s in sorted(VALID_JOB_STATUSES))
_JOB_ERROR_CLASS_IN_LIST = ", ".join(
    f"'{c}'" for c in sorted(VALID_JOB_ERROR_CLASSES)
)
_TRUST_STATE_IN_LIST = ", ".join(f"'{s}'" for s in sorted(VALID_TRUST_STATES))
_RUNTIME_TYPE_IN_LIST = ", ".join(f"'{r}'" for r in sorted(VALID_RUNTIME_TYPES))
_PROJECTION_STATUS_IN_LIST = ", ".join(
    f"'{s}'" for s in sorted(VALID_PROJECTION_TASK_STATUSES)
)
_TERMINAL_JOB_STATUS_IN_LIST = ", ".join(
    f"'{s}'" for s in sorted(TERMINAL_JOB_STATUSES)
)


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


class Submission(Base):
    """Persistent form of the domain ``LedgerSubmission`` -- an append-only
    answer attempt. ``id`` is the business ``submission_id``. The composite FK
    ``(team_id, competition_id) -> teams`` guarantees the team belongs to the
    submission's competition; ``UNIQUE (id, competition_id, team_id,
    challenge_version_id)`` is the composite-FK target for ``solves`` (so a solve
    can only reference a submission with a matching tuple). Append-only (a
    trigger is the backstop)."""

    __tablename__ = "submissions"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("competitions.id", ondelete="RESTRICT"), nullable=False
    )
    team_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    challenge_version_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    submitted_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    correct: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    instance_seed: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "id",
            "competition_id",
            "team_id",
            "challenge_version_id",
            name="uq_submissions_id_competition_id_team_id_challenge_version_id",
        ),
        ForeignKeyConstraint(
            ["team_id", "competition_id"],
            ["teams.id", "teams.competition_id"],
            ondelete="RESTRICT",
        ),
        Index(
            "ix_submissions_competition_id_team_id_submitted_at",
            "competition_id",
            "team_id",
            "submitted_at",
        ),
        Index("ix_submissions_challenge_version_id", "challenge_version_id"),
        Index(
            "ix_submissions_correct",
            "competition_id",
            "challenge_version_id",
            postgresql_where=sa.text("correct"),
        ),
    )


class Solve(Base):
    """Persistent form of the domain ``Solve`` -- the at-most-once accepted
    result. ``UNIQUE (competition_id, team_id, challenge_version_id)`` is the
    schema encoding of "one solve per team per challenge per competition";
    ``UNIQUE (submission_id)`` ties one solve to one submission. The composite FK
    to ``submissions`` guarantees the referenced submission matches on
    ``(competition, team, version)``; a trigger additionally requires it to be
    ``correct``. Append-only."""

    __tablename__ = "solves"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("competitions.id", ondelete="RESTRICT"), nullable=False
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("teams.id", ondelete="RESTRICT"), nullable=False
    )
    challenge_version_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    solved_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    instance_seed: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "competition_id",
            "team_id",
            "challenge_version_id",
            name="uq_solves_competition_id_team_id_challenge_version_id",
        ),
        UniqueConstraint("submission_id", name="uq_solves_submission_id"),
        # The referenced submission must match on the whole identity tuple.
        ForeignKeyConstraint(
            ["submission_id", "competition_id", "team_id", "challenge_version_id"],
            [
                "submissions.id",
                "submissions.competition_id",
                "submissions.team_id",
                "submissions.challenge_version_id",
            ],
            ondelete="RESTRICT",
            name="fk_solves_submission_tuple_submissions",
        ),
        Index(
            "ix_solves_competition_id_challenge_version_id_solved_at",
            "competition_id",
            "challenge_version_id",
            "solved_at",
        ),
    )


class ScoreEvent(Base):
    """Persistent form of the domain ``ScoreEvent`` -- the append-only,
    event-sourced ledger. ``seq`` (identity/bigserial) supplies the strictly
    monotonic ordering that the in-process store produced with a lock.
    Append-only (INSERT only; a trigger rejects UPDATE/DELETE)."""

    __tablename__ = "score_events"

    seq: Mapped[int] = mapped_column(
        sa.BigInteger, sa.Identity(always=True), primary_key=True
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("competitions.id", ondelete="RESTRICT"), nullable=False
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("teams.id", ondelete="RESTRICT"), nullable=False
    )
    challenge_version_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    ts: Mapped[str] = mapped_column(sa.Text, nullable=False)
    payload: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'{}'")
    )
    submission_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=True
    )
    solve_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("solves.id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        CheckConstraint(
            f"type IN ({_SCORE_EVENT_TYPE_IN_LIST})", name="type_valid"
        ),
        Index("ix_score_events_competition_id_seq", "competition_id", "seq"),
        Index("ix_score_events_type", "type"),
    )


class Job(Base):
    """Persistent form of the domain ``Job`` -- one durable queue row (ADR-003).

    ``id`` is the business ``job_id`` (caller-supplied uuid, like
    ``submissions.id``); ``idempotency_key`` is the UNIQUE dedupe business key.
    Claiming is ``SELECT ... FOR UPDATE SKIP LOCKED`` over the
    ``ix_jobs_claim`` partial index. The ``job_transition_guard`` BEFORE UPDATE
    trigger (owned by migration 0006) enforces the legal-transition matrix,
    freezes terminal rows, and freezes id/job_type/payload/idempotency_key/
    created_at after insert; the CHECKs below tie state to its fields.
    ``payload``/``result_json``/``error_detail`` carry references and hashes
    only -- never flags, tokens, or credentials.
    """

    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    job_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'queued'"), default="queued"
    )
    priority: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("100")
    )
    payload: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'{}'")
    )
    idempotency_key: Mapped[str] = mapped_column(sa.Text, nullable=False)
    required_capabilities: Mapped[list[str]] = mapped_column(
        ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'::text[]")
    )
    attempt_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )
    max_attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("3")
    )
    backoff_base_seconds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("30")
    )
    available_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    claimed_by: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    lease_token: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    error_class: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    result_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    result_ref: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    log_ref: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    competition_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, ForeignKey("competitions.id", ondelete="RESTRICT"), nullable=True
    )
    challenge_version_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid,
        ForeignKey("challenge_versions.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_jobs_idempotency_key"),
        CheckConstraint(f"job_type IN ({_JOB_TYPE_IN_LIST})", name="type_valid"),
        CheckConstraint(f"status IN ({_JOB_STATUS_IN_LIST})", name="status_valid"),
        CheckConstraint(
            f"error_class IS NULL OR error_class IN ({_JOB_ERROR_CLASS_IN_LIST})",
            name="error_class_valid",
        ),
        CheckConstraint(
            r"idempotency_key !~ '^\s*$'", name="idempotency_key_non_empty"
        ),
        CheckConstraint("priority >= 0", name="priority_non_negative"),
        CheckConstraint("max_attempts >= 1", name="max_attempts_positive"),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= max_attempts",
            name="attempts_bounded",
        ),
        CheckConstraint("backoff_base_seconds >= 1", name="backoff_positive"),
        # A job holds full lease state iff it is claimed/running.
        CheckConstraint(
            "(status IN ('claimed', 'running')) = "
            "(claimed_by IS NOT NULL AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL)",
            name="lease_state",
        ),
        CheckConstraint(
            "status <> 'running' OR started_at IS NOT NULL", name="running_started"
        ),
        CheckConstraint(
            f"(status IN ({_TERMINAL_JOB_STATUS_IN_LIST})) = "
            "(finished_at IS NOT NULL)",
            name="terminal_finished",
        ),
        CheckConstraint(
            "status NOT IN ('dead_letter', 'failed') OR error_class IS NOT NULL",
            name="failure_classified",
        ),
        # The hot claim path: queued jobs by (priority, available_at).
        Index(
            "ix_jobs_claim",
            "priority",
            "available_at",
            postgresql_where=sa.text("status = 'queued'"),
        ),
        # The lease sweeper's scan.
        Index(
            "ix_jobs_lease_reap",
            "lease_expires_at",
            postgresql_where=sa.text("status IN ('claimed', 'running')"),
        ),
        Index("ix_jobs_competition_id", "competition_id"),
    )


class JobTransition(Base):
    """Append-only per-attempt state history for jobs (``from_status IS NULL``
    marks the enqueue). Written in the same transaction as every state change;
    UPDATE/DELETE/TRUNCATE are rejected by the shared ``reject_mutation``
    triggers (function owned by migration 0004, reused by name)."""

    __tablename__ = "job_transitions"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False
    )
    from_status: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    to_status: Mapped[str] = mapped_column(sa.Text, nullable=False)
    attempt: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    worker_id: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    error_class: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        CheckConstraint(
            f"to_status IN ({_JOB_STATUS_IN_LIST})", name="to_status_valid"
        ),
        CheckConstraint(
            f"from_status IS NULL OR from_status IN ({_JOB_STATUS_IN_LIST})",
            name="from_status_valid",
        ),
        CheckConstraint("attempt >= 0", name="attempt_non_negative"),
        CheckConstraint(
            f"error_class IS NULL OR error_class IN ({_JOB_ERROR_CLASS_IN_LIST})",
            name="error_class_valid",
        ),
        Index("ix_job_transitions_job_id_occurred_at", "job_id", "occurred_at"),
    )


class Worker(Base):
    """Persistent form of the domain ``Worker`` -- an execution-plane host
    identity. ``name`` is the business key. Trust is one 3-state axis
    (pending/trusted/revoked); drain and quarantine are orthogonal timestamp
    overlays. The partial ``ix_workers_dispatch_eligible`` index is the queue's
    eligible-worker scan."""

    __tablename__ = "workers"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    runtime_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    architectures: Mapped[list[str]] = mapped_column(ARRAY(sa.Text), nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(ARRAY(sa.Text), nullable=False)
    capacity: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    trust_state: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'pending'"), default="pending"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    drain_requested_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    quarantined_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    quarantine_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint("name", name="uq_workers_name"),
        CheckConstraint(r"name !~ '^\s*$'", name="name_non_empty"),
        CheckConstraint(
            f"trust_state IN ({_TRUST_STATE_IN_LIST})", name="trust_state_valid"
        ),
        CheckConstraint(
            "(trust_state = 'revoked') = (revoked_at IS NOT NULL)",
            name="revoked_state_consistent",
        ),
        CheckConstraint(
            "(quarantined_at IS NULL) = (quarantine_reason IS NULL)",
            name="quarantine_reason_consistent",
        ),
        CheckConstraint(
            f"runtime_type IN ({_RUNTIME_TYPE_IN_LIST})", name="runtime_type_valid"
        ),
        CheckConstraint("capacity >= 1", name="capacity_positive"),
        CheckConstraint(
            "cardinality(architectures) >= 1", name="architectures_non_empty"
        ),
        CheckConstraint(
            "cardinality(capabilities) >= 1", name="capabilities_non_empty"
        ),
        CheckConstraint(r"version !~ '^\s*$'", name="version_non_empty"),
        Index("ix_workers_trust_state", "trust_state"),
        # Dispatch eligibility is the conjunction of all three axes.
        Index(
            "ix_workers_dispatch_eligible",
            "last_heartbeat_at",
            postgresql_where=sa.text(
                "trust_state = 'trusted' AND quarantined_at IS NULL "
                "AND drain_requested_at IS NULL"
            ),
        ),
    )


class WorkerCredential(Base):
    """Persistent form of the domain ``WorkerCredential`` -- a hashed, scoped,
    short-lived bearer credential. ``id`` is the business ``credential_id``.
    Only the sha256 hex of the secret is stored (the format CHECK makes a
    plaintext ``ctfw1.`` token structurally unstorable). Near-append-only: the
    single legal UPDATE is the ``revoked_at`` NULL->value flip (the
    ``worker_credentials_freeze`` trigger, owned by migration 0007, enforces
    it; DELETE/TRUNCATE hit the shared ``reject_mutation``). At most one live
    credential per worker via the partial UNIQUE index."""

    __tablename__ = "worker_credentials"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
    worker_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("workers.id", ondelete="RESTRICT"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(sa.Text), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_worker_credentials_token_hash"),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'", name="token_hash_format"
        ),
        CheckConstraint("expires_at > issued_at", name="expiry_after_issue"),
        CheckConstraint("cardinality(scopes) >= 1", name="scopes_non_empty"),
        # At most one live credential per worker -- rotation is race-proof.
        Index(
            "uq_worker_credentials_worker_id_active",
            "worker_id",
            unique=True,
            postgresql_where=sa.text("revoked_at IS NULL"),
        ),
        Index("ix_worker_credentials_worker_id", "worker_id"),
    )


class ScoreProjectionOutbox(Base):
    """Transactional-outbox work row for the scoreboard projector (M7).

    Rows are inserted by the DB trigger ``score_events_enqueue_projection``
    (migration-owned, like ``reject_mutation``) in the same transaction as
    each ``score_events`` INSERT -- the ORM never inserts them. Deliberately
    MUTABLE (a work table, not ledger history): success deletes the row in the
    same transaction that folded it; failure marks it ``failed`` with a
    sanitized error. ``competition_id`` is denormalized by the trigger so
    claiming/grouping needs no join."""

    __tablename__ = "score_projection_outbox"

    seq: Mapped[int] = mapped_column(
        sa.BigInteger,
        ForeignKey("score_events.seq", ondelete="RESTRICT"),
        primary_key=True,
        autoincrement=False,
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, ForeignKey("competitions.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'pending'")
    )
    attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )
    last_error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        CheckConstraint(
            f"status IN ({_PROJECTION_STATUS_IN_LIST})", name="status_valid"
        ),
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        Index(
            "ix_score_projection_outbox_pending_seq",
            "seq",
            postgresql_where=sa.text("status = 'pending'"),
        ),
        Index("ix_score_projection_outbox_competition_id", "competition_id"),
    )


class ScoreboardProjection(Base):
    """The rebuildable scoreboard cache (design doc §7's ``scoreboard_cache``),
    one row per competition, stamped with ``as_of_seq``. Written only via the
    monotonic-guarded UPSERT; never a source of truth (delete + replay the
    ledger reproduces it). ``entries`` is the rendered public scoreboard --
    team names/points/solve times only, no secrets by content."""

    __tablename__ = "scoreboard_projections"

    competition_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        ForeignKey("competitions.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    as_of_seq: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    entries: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'{}'")
    )
    computed_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        CheckConstraint("as_of_seq >= 0", name="as_of_seq_nonnegative"),
    )
