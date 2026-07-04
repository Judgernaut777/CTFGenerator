"""Durable Postgres-backed event store for real competitions.

Stdlib-only at import time: :mod:`psycopg` is never imported unless a caller
asks :class:`PostgresEventStore` to open its *own* connection from a DSN (the
``[postgres]`` extra). Tests -- and any caller that already manages a pool --
inject a DB-API-ish connection object (see :class:`Connection`/:class:`Cursor`
below) so no real socket or driver is ever required.

Schema (``competition_events``)::

    seq         serial primary key
    ts          text          -- ISO-8601 UTC, matches events.Event.ts format
    type        text
    team_id     text
    challenge_id text
    payload     jsonb

This mirrors :class:`ctf_generator.events.EventStore` so it is a drop-in
replacement for :class:`~ctf_generator.events.InMemoryEventStore` /
:class:`~ctf_generator.events.JsonlEventStore` wherever an ``EventStore`` is
expected (e.g. ``competition_service.CompetitionService``).
"""

from __future__ import annotations

import json
import time
from typing import Any, Protocol

from ctf_generator.events import Clock, Event

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS competition_events (
    seq SERIAL PRIMARY KEY,
    ts TEXT NOT NULL,
    type TEXT NOT NULL,
    team_id TEXT NOT NULL,
    challenge_id TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
)
"""

_INSERT_SQL = """
INSERT INTO competition_events (ts, type, team_id, challenge_id, payload)
VALUES (%s, %s, %s, %s, %s)
RETURNING seq
"""

_SINCE_SQL = """
SELECT seq, ts, type, team_id, challenge_id, payload
FROM competition_events
WHERE seq > %s
ORDER BY seq
"""

_ALL_SQL = """
SELECT seq, ts, type, team_id, challenge_id, payload
FROM competition_events
ORDER BY seq
"""

_LATEST_SEQ_SQL = "SELECT COALESCE(MAX(seq), 0) FROM competition_events"


def _default_clock() -> float:
    return time.time()


def _format_ts(epoch_seconds: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


class Cursor(Protocol):
    """The narrow slice of the DB-API 2.0 cursor protocol this module needs."""

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        ...

    def fetchone(self) -> Any:
        ...

    def fetchall(self) -> Any:
        ...


class Connection(Protocol):
    """The narrow slice of the DB-API 2.0 connection protocol this module
    needs. A real ``psycopg.Connection`` satisfies this; tests supply a
    lightweight fake instead.
    """

    def cursor(self) -> Cursor:
        ...

    def commit(self) -> None:
        ...


def _connect_psycopg(dsn: str) -> Connection:  # pragma: no cover - needs a real server
    try:
        import psycopg
    except ImportError:
        raise RuntimeError(
            "the postgres event store requires the 'psycopg' package; install "
            "it with 'pip install ctf-generator[postgres]'"
        ) from None
    return psycopg.connect(dsn, autocommit=False)


def _row_to_event(row: Any) -> Event:
    seq, ts, type_, team_id, challenge_id, payload = row
    if isinstance(payload, str):
        payload = json.loads(payload)
    return Event(
        seq=seq,
        ts=ts,
        type=type_,
        team_id=team_id,
        challenge_id=challenge_id,
        payload=dict(payload) if payload else {},
    )


class PostgresEventStore:
    """Durable :class:`~ctf_generator.events.EventStore` backed by Postgres.

    Pass an already-open ``connection`` (satisfying the :class:`Connection`
    protocol above) to use an injected/fake connection -- this is the only
    path exercised by tests, and never imports ``psycopg``. If ``connection``
    is omitted, a ``dsn`` must be supplied and a real ``psycopg`` connection
    is opened lazily on first use (requires the ``[postgres]`` extra).
    """

    def __init__(
        self,
        connection: Connection | None = None,
        *,
        dsn: str | None = None,
        clock: Clock | None = None,
    ) -> None:
        if connection is None and dsn is None:
            raise ValueError("PostgresEventStore requires either connection or dsn")
        self._injected_connection = connection
        self._dsn = dsn
        self._clock: Clock = clock or _default_clock
        self._connection: Connection | None = connection

    def _get_connection(self) -> Connection:
        if self._connection is None:
            assert self._dsn is not None
            self._connection = _connect_psycopg(self._dsn)
        return self._connection

    def init_schema(self) -> None:
        """Create the ``competition_events`` table if it does not exist."""
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute(_CREATE_TABLE_SQL)
        connection.commit()

    def append(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> Event:
        payload = dict(payload) if payload else {}
        ts = _format_ts(self._clock())
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute(
            _INSERT_SQL,
            (ts, type, team_id, challenge_id, json.dumps(payload, sort_keys=True)),
        )
        row = cursor.fetchone()
        seq = row[0] if not isinstance(row, dict) else row["seq"]
        connection.commit()
        return Event(
            seq=seq,
            ts=ts,
            type=type,
            team_id=team_id,
            challenge_id=challenge_id,
            payload=payload,
        )

    def since(self, seq: int) -> list[Event]:
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute(_SINCE_SQL, (seq,))
        return [_row_to_event(row) for row in cursor.fetchall()]

    def all(self) -> list[Event]:
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute(_ALL_SQL)
        return [_row_to_event(row) for row in cursor.fetchall()]

    def latest_seq(self) -> int:
        connection = self._get_connection()
        cursor = connection.cursor()
        cursor.execute(_LATEST_SEQ_SQL)
        row = cursor.fetchone()
        if row is None:
            return 0
        return row[0] if not isinstance(row, dict) else row["seq"]
