"""challenge_build_stack_images -- per-service images of a multi-service build

Creates the ``challenge_build_stack_images`` table (build_challenge tail slice C):
one row per compose SERVICE of a multi-service build (``service_name``,
``image_ref``, ``image_digest``, ``bundle_sha256`` grouping all services of one
build, plus the ``depends_on``/``expose`` manifest bits the launch worker needs
once the bundle is gone, and an ``is_primary`` flag). A single-image build records
only ``challenge_build_images``; a stack build records the primary there too
(back-compat) AND one row here per service.

SECRET-FREE by construction (slugs/hashes/refs/service names only). APPEND-ONLY:
the shared ``reject_mutation`` guard (from 0004) is attached as BEFORE UPDATE OR
DELETE + BEFORE TRUNCATE triggers. Uniqueness on the deterministic
``(challenge_version_id, service_name, image_ref)`` collapses a rebuild of the
same frozen version per service via ON CONFLICT at the writer. Names mirror the
ORM metadata exactly (autogenerate-clean); reversible.

Revision ID: 0016_build_stack_images
Revises: 0015_challenge_build_images
Create Date: 2026-07-13
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0016_build_stack_images"
down_revision: str | None = "0015_challenge_build_images"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "challenge_build_stack_images",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("challenge_version_id", sa.Uuid(), nullable=False),
        sa.Column("service_name", sa.Text(), nullable=False),
        sa.Column("image_ref", sa.Text(), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column("bundle_sha256", sa.Text(), nullable=False),
        sa.Column(
            "depends_on",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "expose",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "is_primary",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_challenge_build_stack_images"),
        sa.ForeignKeyConstraint(
            ["challenge_version_id"],
            ["challenge_versions.id"],
            name="fk_challenge_build_stack_images_version",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "challenge_version_id",
            "service_name",
            "image_ref",
            name="uq_challenge_build_stack_images_ver_svc_img",
        ),
        sa.CheckConstraint(
            r"service_name !~ '^\s*$'",
            name="ck_challenge_build_stack_images_service_name_non_empty",
        ),
        sa.CheckConstraint(
            r"image_ref !~ '^\s*$'",
            name="ck_challenge_build_stack_images_image_ref_non_empty",
        ),
        sa.CheckConstraint(
            r"image_digest !~ '^\s*$'",
            name="ck_challenge_build_stack_images_image_digest_non_empty",
        ),
        sa.CheckConstraint(
            r"bundle_sha256 !~ '^\s*$'",
            name="ck_challenge_build_stack_images_bundle_sha256_non_empty",
        ),
    )
    op.create_index(
        "ix_challenge_build_stack_images_version",
        "challenge_build_stack_images",
        ["challenge_version_id"],
    )
    op.create_index(
        "ix_challenge_build_stack_images_bundle",
        "challenge_build_stack_images",
        ["challenge_version_id", "bundle_sha256"],
    )

    op.execute(
        "CREATE TRIGGER challenge_build_stack_images_immutable "
        "BEFORE UPDATE OR DELETE ON challenge_build_stack_images "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER challenge_build_stack_images_no_truncate "
        "BEFORE TRUNCATE ON challenge_build_stack_images "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS challenge_build_stack_images_no_truncate "
        "ON challenge_build_stack_images;"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS challenge_build_stack_images_immutable "
        "ON challenge_build_stack_images;"
    )
    op.drop_index(
        "ix_challenge_build_stack_images_bundle",
        table_name="challenge_build_stack_images",
    )
    op.drop_index(
        "ix_challenge_build_stack_images_version",
        table_name="challenge_build_stack_images",
    )
    op.drop_table("challenge_build_stack_images")
    # reject_mutation() is owned by 0004; not dropped here.
