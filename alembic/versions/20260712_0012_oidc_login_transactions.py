"""oidc login transactions -- transient pre-auth CSRF/PKCE store (M10c)

Creates:

* ``oidc_login_transactions`` -- a short-lived, one-time-use OIDC
  authorization-code login transaction. Looked up by ``state_hash`` (sha256 hex
  of the anti-forgery state, ``UNIQUE`` + 64-hex CHECK -- so a plaintext state
  can never satisfy the CHECK and be stored by mistake, the exact
  ``sessions.token_hash`` discipline). It binds ``state`` to the ``nonce``
  (ID-token replay defense) and the PKCE ``code_verifier`` (code-interception
  defense) plus the exact ``redirect_uri`` used at authorization.

Unlike the append-only auth aggregates (``sessions`` / audit tables), this table
is transient: rows are DELETED on consume (one-time-use by construction) and
pruned on expiry, so it carries NO freeze trigger and NO FK (it exists before any
user identity is known). Constraint/index names mirror the ORM metadata
NAMING_CONVENTION exactly (autogenerate-clean); reversible.

Revision ID: 0012_oidc_login_transactions
Revises: 0011_auth
Create Date: 2026-07-12
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_oidc_login_transactions"
down_revision: str | None = "0011_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_login_transactions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("code_verifier", sa.Text(), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_oidc_login_transactions"),
        sa.UniqueConstraint(
            "state_hash", name="uq_oidc_login_transactions_state_hash"
        ),
        sa.CheckConstraint(
            "state_hash ~ '^[0-9a-f]{64}$'",
            name="ck_oidc_login_transactions_state_hash_format",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_oidc_login_transactions_expiry_after_created",
        ),
    )


def downgrade() -> None:
    op.drop_table("oidc_login_transactions")
