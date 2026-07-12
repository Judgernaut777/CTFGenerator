"""auth -- local password credentials, server-side sessions, system roles (M10a)

Creates:

* ``auth_credentials`` -- one local password credential per user
  (``UNIQUE (user_id)``). Only the *encoded* password hash is stored (the
  ``password_hash ~ '^\\S+\\$\\S+$'`` CHECK is a backstop against a bare
  plaintext ever landing; full KDF validation is the hasher's). MUTABLE in
  place -- a password change rotates ``password_hash`` + ``updated_at`` (there
  is no history table). FK ``user_id -> users`` ON DELETE RESTRICT.
* ``sessions`` -- server-side sessions keyed by ``token_hash`` (sha256 hex of
  the opaque bearer token; the 64-hex CHECK makes storing a plaintext token
  structurally impossible). Near-append-only: the ``auth_sessions_freeze()``
  trigger permits exactly one UPDATE shape -- the ``revoked_at`` NULL->value
  stamp with every other column unchanged (``to_jsonb`` minus the stamped key);
  DELETE/TRUNCATE hit the shared ``reject_mutation()`` (owned by ``0004``,
  reused BY NAME). ``rotated_from`` self-references the predecessor a refresh
  rotated from. The partial ``ix_sessions_user_id_live`` index scans live
  sessions.
* ``user_system_roles`` -- deployment-global (admin / support) role grants,
  PK ``(user_id, role)`` with a CHECK on the role. Revocable (a plain delete),
  so it carries no freeze trigger.

Constraint/index names mirror the ORM metadata NAMING_CONVENTION exactly
(rendered from the models) so Alembic autogenerate stays clean. All FKs ON
DELETE RESTRICT.

Revision ID: 0011_auth
Revises: 0010_instances
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_auth"
down_revision: str | None = "0010_instances"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Sorted rendering of the domain VALID_SYSTEM_ROLES, frozen here so the
# migration is stable regardless of set iteration order.
_SYSTEM_ROLES = ("admin", "support")
_SYSTEM_ROLE_IN = ", ".join(f"'{r}'" for r in _SYSTEM_ROLES)

# The one legal mutation on ``sessions``: stamping ``revoked_at`` on a live
# session, every other column byte-identical (to_jsonb(row) minus the stamped
# key freezes all remaining columns at once, including any added later).
_FREEZE_FN = """
CREATE OR REPLACE FUNCTION auth_sessions_freeze() RETURNS trigger AS $$
BEGIN
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
     AND (to_jsonb(NEW) - 'revoked_at') = (to_jsonb(OLD) - 'revoked_at') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION
    'sessions permits only the revoked_at NULL->value stamp (id=%)', OLD.id;
END $$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "auth_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_auth_credentials"),
        sa.UniqueConstraint("user_id", name="uq_auth_credentials_user_id"),
        sa.CheckConstraint(
            r"password_hash ~ '^\S+\$\S+$'",
            name="ck_auth_credentials_password_hash_encoded",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at", name="ck_auth_credentials_updated_after_created"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_auth_credentials_user_id_users",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_from", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
        sa.CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'", name="ck_sessions_token_hash_format"
        ),
        sa.CheckConstraint(
            "expires_at > issued_at", name="ck_sessions_expiry_after_issue"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["rotated_from"],
            ["sessions.id"],
            name="fk_sessions_rotated_from_sessions",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_sessions_user_id_live",
        "sessions",
        ["user_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.create_table(
        "user_system_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("user_id", "role", name="pk_user_system_roles"),
        sa.CheckConstraint(
            f"role IN ({_SYSTEM_ROLE_IN})", name="ck_user_system_roles_role_valid"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_system_roles_user_id_users",
            ondelete="RESTRICT",
        ),
    )

    # Near-append-only enforcement on sessions. reject_mutation() is owned by
    # 0004 and reused BY NAME; auth_sessions_freeze() is owned by this revision.
    op.execute(_FREEZE_FN)
    op.execute(
        "CREATE TRIGGER auth_sessions_freeze_update "
        "BEFORE UPDATE ON sessions "
        "FOR EACH ROW EXECUTE FUNCTION auth_sessions_freeze();"
    )
    op.execute(
        "CREATE TRIGGER auth_sessions_no_delete "
        "BEFORE DELETE ON sessions "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation();"
    )
    op.execute(
        "CREATE TRIGGER auth_sessions_no_truncate "
        "BEFORE TRUNCATE ON sessions "
        "FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS auth_sessions_no_truncate ON sessions;")
    op.execute("DROP TRIGGER IF EXISTS auth_sessions_no_delete ON sessions;")
    op.execute("DROP TRIGGER IF EXISTS auth_sessions_freeze_update ON sessions;")
    op.execute("DROP FUNCTION IF EXISTS auth_sessions_freeze();")
    # reject_mutation() is owned by 0004; not dropped here.

    op.drop_table("user_system_roles")
    op.drop_index("ix_sessions_user_id_live", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("auth_credentials")
