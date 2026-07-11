"""baseline (empty) -- establishes the alembic_version anchor with no schema yet

Step 2 of M6 is infrastructure only: this migration creates no tables. It exists
so `alembic upgrade head` / `downgrade base` run cleanly and the migration chain
has a root for the first aggregate (Competition) to build on.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-11
"""
from __future__ import annotations

from collections.abc import Sequence

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
