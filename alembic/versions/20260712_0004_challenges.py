"""challenges -- definitions, versions, builds, competition attach (M6 Epic 2)

Creates the four challenge-authoring aggregate tables and the immutability
backstops from the persistence design (§8):

* ``challenge_definitions`` -- stable challenge identity (business key ``slug``).
* ``challenge_versions``    -- individually-scorable revisions; ``spec_json`` is a
  ``jsonb`` copy, ``spec_sha256`` the authoritative content hash. A BEFORE UPDATE
  trigger freezes content once ``state='published'`` and permits only
  ``published -> archived``.
* ``challenge_builds``      -- content-addressed (PK ``build_sha256``), insert-only;
  a BEFORE UPDATE OR DELETE trigger (generic ``reject_mutation``) rejects edits.
* ``competition_challenges`` -- a published version attached to a competition with
  its per-competition scoring config (normalizes ``ChallengeScoringConfig``).

All FKs are ``ON DELETE RESTRICT``. Constraint/index/trigger names mirror the ORM
metadata (rendered from the models) so Alembic autogenerate stays clean. The CHECK
value-lists (states, decay functions) are frozen literals here (a migration is a
historical snapshot) and are kept in sync with the domain's VALID_* sets.

Revision ID: 0004_challenges
Revises: 0003_identity
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_challenges"
down_revision: str | None = "0003_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copies of the domain VALID_* sets (sorted), matching the ORM CHECKs.
_VERSION_STATES = ("archived", "draft", "published")
_DECAY_FUNCTIONS = ("linear", "logarithmic", "static")
_STATE_IN = ", ".join(f"'{s}'" for s in _VERSION_STATES)
_DECAY_IN = ", ".join(f"'{d}'" for d in _DECAY_FUNCTIONS)

# plpgsql immutability backstops (design §8).
_FREEZE_PUBLISHED_FN = """
CREATE OR REPLACE FUNCTION freeze_published_version() RETURNS trigger AS $$
BEGIN
  -- Guard BOTH published and archived rows: content is frozen from publish
  -- onward and stays frozen through archival, and 'archived' is terminal. Only
  -- guarding 'published' would leave archived rows fully mutable and reversible
  -- (archived -> draft -> re-publish with different content).
  IF OLD.state IN ('published', 'archived') THEN
    IF OLD.state = 'archived' AND NEW.state <> 'archived' THEN
      RAISE EXCEPTION 'archived challenge_version is terminal (cannot move to %)', NEW.state;
    END IF;
    IF NEW.state NOT IN ('published', 'archived') THEN
      RAISE EXCEPTION 'published challenge_version may only move to archived (got %)', NEW.state;
    END IF;
    IF NEW.definition_id <> OLD.definition_id
       OR NEW.version_no <> OLD.version_no
       OR NEW.family_version <> OLD.family_version
       OR NEW.seed <> OLD.seed
       OR NEW.mode <> OLD.mode
       OR NEW.spec_sha256 <> OLD.spec_sha256
       OR NEW.spec_json IS DISTINCT FROM OLD.spec_json
       OR NEW.cve_refs IS DISTINCT FROM OLD.cve_refs
       OR NEW.cve_content_hash IS DISTINCT FROM OLD.cve_content_hash
       OR NEW.spec_version <> OLD.spec_version
       OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
      RAISE EXCEPTION 'published challenge_version content is immutable';
    END IF;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
"""

# Generic append-only guard, reused by later append-only ledgers (Epic 3) via
# CREATE OR REPLACE; owned by this migration.
_REJECT_MUTATION_FN = """
CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'table % is insert-only (% rejected)', TG_TABLE_NAME, TG_OP;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "challenge_definitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("family", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_challenge_definitions"),
        sa.UniqueConstraint("slug", name="uq_challenge_definitions_slug"),
        sa.CheckConstraint(
            r"family !~ '^\s*$'", name="ck_challenge_definitions_family_non_empty"
        ),
        sa.CheckConstraint(
            r"slug !~ '^\s*$'", name="ck_challenge_definitions_slug_non_empty"
        ),
        sa.CheckConstraint(
            r"title !~ '^\s*$'", name="ck_challenge_definitions_title_non_empty"
        ),
    )
    op.create_index(
        "ix_challenge_definitions_family", "challenge_definitions", ["family"]
    )

    op.create_table(
        "challenge_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("definition_id", sa.Uuid(), nullable=False),
        sa.Column("version_no", sa.Integer(), nullable=False),
        sa.Column(
            "state", sa.Text(), nullable=False, server_default=sa.text("'draft'")
        ),
        sa.Column("family_version", sa.Text(), nullable=False),
        sa.Column("seed", sa.Text(), nullable=False),
        sa.Column("mode", sa.Text(), nullable=False, server_default=sa.text("'red'")),
        sa.Column("spec_sha256", sa.Text(), nullable=False),
        sa.Column("spec_json", postgresql.JSONB(), nullable=False),
        sa.Column("cve_refs", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("cve_content_hash", sa.Text(), nullable=True),
        sa.Column("spec_version", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_challenge_versions"),
        sa.UniqueConstraint(
            "definition_id",
            "version_no",
            name="uq_challenge_versions_definition_id_version_no",
        ),
        sa.UniqueConstraint(
            "definition_id",
            "spec_sha256",
            name="uq_challenge_versions_definition_id_spec_sha256",
        ),
        sa.CheckConstraint(
            "version_no >= 1", name="ck_challenge_versions_version_no_positive"
        ),
        sa.CheckConstraint(
            f"state IN ({_STATE_IN})", name="ck_challenge_versions_state_valid"
        ),
        sa.CheckConstraint(
            "(state = 'draft') = (published_at IS NULL)",
            name="ck_challenge_versions_published_state_consistent",
        ),
        sa.ForeignKeyConstraint(
            ["definition_id"],
            ["challenge_definitions.id"],
            name="fk_challenge_versions_definition_id_challenge_definitions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_challenge_versions_spec_sha256", "challenge_versions", ["spec_sha256"]
    )
    op.create_index(
        "ix_challenge_versions_definition_id_state",
        "challenge_versions",
        ["definition_id", "state"],
    )

    op.create_table(
        "challenge_builds",
        sa.Column("build_sha256", sa.Text(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("family", sa.Text(), nullable=False),
        sa.Column("seed", sa.Text(), nullable=False),
        sa.Column("family_version", sa.Text(), nullable=True),
        sa.Column("spec_sha256", sa.Text(), nullable=False),
        sa.Column("generator_version", sa.Text(), nullable=False),
        sa.Column("manifest_json", postgresql.JSONB(), nullable=False),
        sa.Column("storage_uri", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("build_sha256", name="pk_challenge_builds"),
        # NULLS NOT DISTINCT (PG15+) so a NULL family_version still collides.
        sa.UniqueConstraint(
            "challenge_version_id",
            "family_version",
            "generator_version",
            "seed",
            name="uq_challenge_builds_version_toolchain_seed",
            postgresql_nulls_not_distinct=True,
        ),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_challenge_builds_challenge_version_id_challenge_versions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_challenge_builds_challenge_version_id",
        "challenge_builds",
        ["challenge_version_id"],
    )

    op.create_table(
        "competition_challenges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("competition_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column(
            "initial_value",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("500"),
        ),
        sa.Column(
            "minimum_value",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("100"),
        ),
        sa.Column(
            "decay_function",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'static'"),
        ),
        sa.Column("decay", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "first_blood_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "first_blood_bonus_points",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "first_blood_bonus_percent",
            sa.Double(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_competition_challenges"),
        sa.UniqueConstraint(
            "competition_id",
            "challenge_version_id",
            name="uq_competition_challenges_competition_id_challenge_version_id",
        ),
        sa.CheckConstraint(
            f"decay_function IN ({_DECAY_IN})",
            name="ck_competition_challenges_decay_function_valid",
        ),
        sa.CheckConstraint(
            "initial_value >= 0",
            name="ck_competition_challenges_initial_value_non_negative",
        ),
        sa.CheckConstraint(
            "minimum_value <= initial_value",
            name="ck_competition_challenges_minimum_le_initial",
        ),
        sa.CheckConstraint(
            "decay >= 0", name="ck_competition_challenges_decay_non_negative"
        ),
        sa.CheckConstraint(
            "first_blood_bonus_points >= 0",
            name="ck_competition_challenges_first_blood_points_non_negative",
        ),
        sa.CheckConstraint(
            "first_blood_bonus_percent >= 0",
            name="ck_competition_challenges_first_blood_percent_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["competition_id"],
            ["competitions.id"],
            name="fk_competition_challenges_competition_id_competitions",
            ondelete="RESTRICT",
        ),
        # NOTE: SQLAlchemy truncates this long name with a stable hash suffix;
        # mirrored verbatim so autogenerate does not see a rename.
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_competition_challenges_challenge_version_id_challeng_94e7",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_competition_challenges_competition_id",
        "competition_challenges",
        ["competition_id"],
    )

    # Immutability backstops (design §8).
    op.execute(_REJECT_MUTATION_FN)
    op.execute(_FREEZE_PUBLISHED_FN)
    op.execute(
        "CREATE TRIGGER challenge_versions_freeze_published "
        "BEFORE UPDATE ON challenge_versions "
        "FOR EACH ROW EXECUTE FUNCTION freeze_published_version();"
    )
    op.execute(
        "CREATE TRIGGER challenge_builds_immutable "
        "BEFORE UPDATE OR DELETE ON challenge_builds "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    # Row triggers do NOT fire on TRUNCATE, which would otherwise wipe the
    # insert-only build ledger. A statement-level BEFORE TRUNCATE trigger closes
    # that bypass.
    op.execute(
        "CREATE TRIGGER challenge_builds_no_truncate "
        "BEFORE TRUNCATE ON challenge_builds "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS challenge_builds_no_truncate ON challenge_builds;"
    )
    op.execute("DROP TRIGGER IF EXISTS challenge_builds_immutable ON challenge_builds;")
    op.execute(
        "DROP TRIGGER IF EXISTS challenge_versions_freeze_published "
        "ON challenge_versions;"
    )
    # reject_mutation() is shared: later append-only ledgers (Epic 3) attach
    # their own triggers to it via CREATE OR REPLACE. Under Alembic's linear
    # history those revisions are downgraded first, so their triggers are gone
    # before this DROP runs. The DROP has no CASCADE, so it fails loud if any
    # dependent trigger somehow remains rather than silently cascading.
    op.execute("DROP FUNCTION IF EXISTS reject_mutation();")
    op.execute("DROP FUNCTION IF EXISTS freeze_published_version();")

    op.drop_index(
        "ix_competition_challenges_competition_id",
        table_name="competition_challenges",
    )
    op.drop_table("competition_challenges")
    op.drop_index(
        "ix_challenge_builds_challenge_version_id", table_name="challenge_builds"
    )
    op.drop_table("challenge_builds")
    op.drop_index(
        "ix_challenge_versions_definition_id_state", table_name="challenge_versions"
    )
    op.drop_index(
        "ix_challenge_versions_spec_sha256", table_name="challenge_versions"
    )
    op.drop_table("challenge_versions")
    op.drop_index(
        "ix_challenge_definitions_family", table_name="challenge_definitions"
    )
    op.drop_table("challenge_definitions")
