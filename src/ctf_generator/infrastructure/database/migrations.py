"""Migration-head introspection for the readiness probe (M16b).

The readiness check must know whether the DB schema is at the revision the
running code expects. :data:`CODE_MIGRATION_HEAD` is the code-declared head; a
host test (``test_migration_head_matches_script_directory``) asserts it equals
the Alembic ScriptDirectory head so this constant can never silently drift from
the actual migrations. :func:`current_db_revision` reads the applied revision
from ``alembic_version`` and NEVER raises (a missing table / connection error ->
``None`` -> the caller treats the schema as not-at-head).
"""

from __future__ import annotations

import sqlalchemy as sa

#: The Alembic revision the running code expects at head. Kept in lockstep with
#: ``alembic/versions`` by a host drift test.
CODE_MIGRATION_HEAD = "0014_audit_events"


def current_db_revision(database) -> str | None:
    """The single applied Alembic revision in ``alembic_version``, or ``None`` when
    the table is absent / the DB is unreachable / it is ambiguous. Never raises."""
    if database is None:
        return None
    try:
        with database.session_scope() as session:
            return session.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()
    except Exception:
        return None


def migrations_at_head(database) -> bool:
    """True iff the DB's applied revision equals :data:`CODE_MIGRATION_HEAD`."""
    return current_db_revision(database) == CODE_MIGRATION_HEAD
