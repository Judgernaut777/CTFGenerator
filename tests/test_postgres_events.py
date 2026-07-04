from __future__ import annotations

import json
import sys
import unittest

from ctf_generator.events import Event
from ctf_generator.postgres_events import PostgresEventStore


class ScriptedClock:
    """Fake Clock returning scripted timestamps in sequence."""

    def __init__(self, timestamps: list[float]) -> None:
        self._timestamps = list(timestamps)
        self._index = 0

    def __call__(self) -> float:
        value = self._timestamps[self._index]
        self._index += 1
        return value


class FakeCursor:
    """Records every SQL statement executed and returns scripted rows.

    ``rows`` is a mutable in-memory table (list of tuples matching the
    ``competition_events`` column order) shared with the owning
    :class:`FakeConnection`, so INSERT/SELECT behave like a real table
    without touching a real database.
    """

    def __init__(self, connection: "FakeConnection") -> None:
        self._connection = connection
        self.executed: list[tuple[str, tuple]] = []
        self._pending_result: list[tuple] | tuple | None = None

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append((sql, params))
        self._connection.executed.append((sql, params))
        normalized = " ".join(sql.split())

        if normalized.startswith("CREATE TABLE"):
            self._connection.schema_initialized = True
            self._pending_result = None
        elif normalized.startswith("INSERT INTO competition_events"):
            ts, type_, team_id, challenge_id, payload_json = params
            self._connection.next_seq += 1
            seq = self._connection.next_seq
            self._connection.rows.append(
                (seq, ts, type_, team_id, challenge_id, json.loads(payload_json))
            )
            self._pending_result = (seq,)
        elif normalized.startswith("SELECT seq, ts, type, team_id, challenge_id, payload FROM competition_events") and "WHERE seq >" in normalized:
            (since_seq,) = params
            self._pending_result = [row for row in self._connection.rows if row[0] > since_seq]
        elif normalized.startswith("SELECT seq, ts, type, team_id, challenge_id, payload FROM competition_events"):
            self._pending_result = list(self._connection.rows)
        elif normalized.startswith("SELECT COALESCE(MAX(seq), 0)"):
            seqs = [row[0] for row in self._connection.rows]
            self._pending_result = (max(seqs) if seqs else 0,)
        else:
            raise AssertionError(f"FakeCursor got unexpected SQL: {sql!r}")

    def fetchone(self):
        return self._pending_result

    def fetchall(self):
        return list(self._pending_result) if self._pending_result else []


class FakeConnection:
    """Fake DB-API connection: no sockets, no psycopg, just Python lists."""

    def __init__(self) -> None:
        self.rows: list[tuple] = []
        self.next_seq = 0
        self.schema_initialized = False
        self.commits = 0
        self.executed: list[tuple[str, tuple]] = []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1


class PostgresEventStoreTests(unittest.TestCase):
    def test_requires_connection_or_dsn(self) -> None:
        with self.assertRaises(ValueError):
            PostgresEventStore()

    def test_init_schema_issues_create_table(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection)

        store.init_schema()

        self.assertTrue(connection.schema_initialized)
        self.assertEqual(connection.commits, 1)

    def test_append_assigns_monotonic_seq_and_formatted_ts(self) -> None:
        connection = FakeConnection()
        clock = ScriptedClock([1700000000.0, 1700000060.0])
        store = PostgresEventStore(connection=connection, clock=clock)

        first = store.append("team_join", "team-1", "chal-1", payload={"note": "hi"})
        second = store.append("flag_submit", "team-1", "chal-1")

        self.assertEqual(
            first,
            Event(
                seq=1,
                ts="2023-11-14T22:13:20+00:00",
                type="team_join",
                team_id="team-1",
                challenge_id="chal-1",
                payload={"note": "hi"},
            ),
        )
        self.assertEqual(second.seq, 2)
        self.assertEqual(second.ts, "2023-11-14T22:14:20+00:00")
        self.assertEqual(second.payload, {})
        self.assertEqual(connection.commits, 2)

    def test_append_payload_defaults_to_empty_dict_and_is_copied(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0]))
        payload = {"a": 1}

        event = store.append("hint_used", "team-1", "chal-1", payload=payload)
        payload["a"] = 2

        self.assertEqual(event.payload, {"a": 1})

    def test_since_returns_events_after_seq_like_in_memory_store(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0, 1.0, 2.0]))
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")
        store.append("c", "team-1", "chal-1")

        result = store.since(1)

        self.assertEqual([event.seq for event in result], [2, 3])
        self.assertEqual([event.type for event in result], ["b", "c"])

    def test_since_zero_returns_all_events(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0, 1.0]))
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")

        self.assertEqual([event.seq for event in store.since(0)], [1, 2])

    def test_all_returns_every_event_in_order(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0, 1.0]))
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")

        events = store.all()

        self.assertEqual([event.type for event in events], ["a", "b"])

    def test_latest_seq_empty_store_is_zero(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection)

        self.assertEqual(store.latest_seq(), 0)

    def test_latest_seq_after_appends(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0, 1.0, 2.0]))
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")
        store.append("c", "team-1", "chal-1")

        self.assertEqual(store.latest_seq(), 3)

    def test_payload_round_trips_through_json(self) -> None:
        connection = FakeConnection()
        store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0]))
        payload = {"nested": {"x": 1}, "list": [1, 2, 3]}

        event = store.append("flag_submit", "team-1", "chal-1", payload=payload)
        [reloaded] = store.since(0)

        self.assertEqual(event.payload, payload)
        self.assertEqual(reloaded.payload, payload)

    def test_no_psycopg_import_when_connection_is_injected(self) -> None:
        # Ensure psycopg is not importable during this test; if PostgresEventStore
        # tried to import it despite an injected connection, this would raise.
        blocked = object()
        original = sys.modules.get("psycopg", blocked)
        sys.modules["psycopg"] = None  # type: ignore[assignment]
        try:
            connection = FakeConnection()
            store = PostgresEventStore(connection=connection, clock=ScriptedClock([0.0]))
            store.init_schema()
            store.append("team_join", "team-1", "chal-1")
            store.since(0)
            store.all()
            store.latest_seq()
        finally:
            if original is blocked:
                del sys.modules["psycopg"]
            else:
                sys.modules["psycopg"] = original

    def test_dsn_only_defers_connection_until_first_use(self) -> None:
        # Constructing with a dsn (no connection) must not attempt to import
        # or connect eagerly -- only _get_connection() (called from an actual
        # operation) would trigger the lazy psycopg import.
        store = PostgresEventStore(dsn="postgresql://example/db")
        self.assertIsNone(store._connection)


if __name__ == "__main__":
    unittest.main()
