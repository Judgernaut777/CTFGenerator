"""challenge_build_images -- the worker-built image registry (build_challenge slice 2)

Creates the ``challenge_build_images`` table: the append-only mapping from a
``challenge_version`` to the Docker image a worker built from its FULL bundle --
``image_ref`` (the launch reference), ``image_digest`` (the content-addressed
digest the build returned), and ``bundle_sha256`` (the full-bundle content hash
the image was built from). Written at build-job completion time; read at
instance-launch time so a freshly-built instance runs the built image.

SECRET-FREE by construction: every column is a slug/hash/reference/timestamp --
there is NO flag/token/seed column, so a secret cannot be persisted here.
APPEND-ONLY / tamper-evident: the shared ``reject_mutation`` guard (from 0004) is
attached as BEFORE UPDATE OR DELETE + BEFORE TRUNCATE triggers, so a recorded
mapping can never be altered, deleted, or truncated. Uniqueness is keyed on the
DETERMINISTIC ``image_ref`` (which folds in ``bundle_sha256``), so a rebuild of
the same frozen version collapses via ON CONFLICT DO NOTHING at the writer, while
a different build appends a new row (the non-reproducible Docker ``image_digest``
is recorded for provenance only, not the collapse key).

Constraint/index/trigger names mirror the ORM metadata NAMING_CONVENTION exactly
(autogenerate-clean); reversible. ``reject_mutation`` is owned by 0004 (created
there, dropped there) -- this migration only attaches/detaches its triggers.

Revision ID: 0015_challenge_build_images
Revises: 0014_audit_events
Create Date: 2026-07-13
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_challenge_build_images"
down_revision: str | None = "0014_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "challenge_build_images",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("image_ref", sa.Text(), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column("bundle_sha256", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_challenge_build_images"),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_challenge_build_images_challenge_version_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "challenge_version_id",
            "image_ref",
            name="uq_challenge_build_images_challenge_version_id_image_ref",
        ),
        sa.CheckConstraint(
            r"image_ref !~ '^\s*$'",
            name="ck_challenge_build_images_image_ref_non_empty",
        ),
        sa.CheckConstraint(
            r"image_digest !~ '^\s*$'",
            name="ck_challenge_build_images_image_digest_non_empty",
        ),
    )
    op.create_index(
        "ix_challenge_build_images_challenge_version_id",
        "challenge_build_images",
        ["challenge_version_id"],
    )

    # Append-only / tamper-evidence: reject any UPDATE/DELETE/TRUNCATE via the
    # shared reject_mutation() guard owned by 0004.
    op.execute(
        "CREATE TRIGGER challenge_build_images_immutable "
        "BEFORE UPDATE OR DELETE ON challenge_build_images "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER challenge_build_images_no_truncate "
        "BEFORE TRUNCATE ON challenge_build_images "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS challenge_build_images_no_truncate "
        "ON challenge_build_images;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS challenge_build_images_immutable "
        "ON challenge_build_images;"
    )
    op.drop_index(
        "ix_challenge_build_images_challenge_version_id",
        table_name="challenge_build_images",
    )
    op.drop_table("challenge_build_images")
    # reject_mutation() is owned by 0004; not dropped here.
