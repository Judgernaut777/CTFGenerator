from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator.events import Event, InMemoryEventStore, JsonlEventStore


class ScriptedClock:
    """Fake Clock returning scripted timestamps in sequence."""

    def __init__(self, timestamps: list[float]) -> None:
        self._timestamps = list(timestamps)
        self._index = 0

    def __call__(self) -> float:
        value = self._timestamps[self._index]
        self._index += 1
        return value


class InMemoryEventStoreTests(unittest.TestCase):
    def test_append_assigns_monotonic_seq_and_formatted_ts(self) -> None:
        clock = ScriptedClock([1700000000.0, 1700000060.0])
        store = InMemoryEventStore(clock=clock)

        first = store.append("team_join", "team-1", "chal-1", payload={"note": "hi"})
        second = store.append("flag_submit", "team-1", "chal-1")

        self.assertEqual(first, Event(
            seq=1,
            ts="2023-11-14T22:13:20+00:00",
            type="team_join",
            team_id="team-1",
            challenge_id="chal-1",
            payload={"note": "hi"},
        ))
        self.assertEqual(second.seq, 2)
        self.assertEqual(second.ts, "2023-11-14T22:14:20+00:00")
        self.assertEqual(second.payload, {})

    def test_append_payload_defaults_to_empty_dict_and_is_copied(self) -> None:
        clock = ScriptedClock([0.0])
        store = InMemoryEventStore(clock=clock)
        payload = {"a": 1}

        event = store.append("hint_used", "team-1", "chal-1", payload=payload)
        payload["a"] = 2

        self.assertEqual(event.payload, {"a": 1})

    def test_since_returns_events_after_seq(self) -> None:
        clock = ScriptedClock([0.0, 1.0, 2.0])
        store = InMemoryEventStore(clock=clock)
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")
        store.append("c", "team-1", "chal-1")

        result = store.since(1)

        self.assertEqual([event.type for event in result], ["b", "c"])

    def test_since_with_latest_seq_returns_empty(self) -> None:
        clock = ScriptedClock([0.0, 1.0])
        store = InMemoryEventStore(clock=clock)
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")

        self.assertEqual(store.since(store.latest_seq()), [])

    def test_all_returns_events_in_append_order(self) -> None:
        clock = ScriptedClock([0.0, 1.0])
        store = InMemoryEventStore(clock=clock)
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")

        self.assertEqual([event.type for event in store.all()], ["a", "b"])

    def test_latest_seq_zero_when_empty(self) -> None:
        store = InMemoryEventStore(clock=ScriptedClock([]))

        self.assertEqual(store.latest_seq(), 0)

    def test_latest_seq_tracks_last_append(self) -> None:
        clock = ScriptedClock([0.0, 1.0, 2.0])
        store = InMemoryEventStore(clock=clock)
        store.append("a", "team-1", "chal-1")
        store.append("b", "team-1", "chal-1")
        store.append("c", "team-1", "chal-1")

        self.assertEqual(store.latest_seq(), 3)

    def test_default_clock_used_when_none_injected(self) -> None:
        store = InMemoryEventStore()

        event = store.append("a", "team-1", "chal-1")

        self.assertIsInstance(event.ts, str)
        self.assertGreater(len(event.ts), 0)


class JsonlEventStoreTests(unittest.TestCase):
    def test_append_persists_to_jsonl_file(self) -> None:
        clock = ScriptedClock([0.0, 1.0])
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.jsonl"
            store = JsonlEventStore(path, clock=clock)

            store.append("team_join", "team-1", "chal-1", payload={"x": 1})
            store.append("flag_submit", "team-1", "chal-1")

            lines = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)

    def test_round_trip_reopen_resumes_seq_and_reads_prior_events(self) -> None:
        clock = ScriptedClock([0.0, 1.0, 2.0])
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.jsonl"

            store = JsonlEventStore(path, clock=clock)
            store.append("team_join", "team-1", "chal-1")
            store.append("flag_submit", "team-1", "chal-1")

            reopened = JsonlEventStore(path, clock=clock)

            self.assertEqual(reopened.latest_seq(), 2)
            self.assertEqual(
                [event.type for event in reopened.all()],
                ["team_join", "flag_submit"],
            )

            third = reopened.append("hint_used", "team-1", "chal-1")
            self.assertEqual(third.seq, 3)
            self.assertEqual(reopened.since(1), [
                reopened.all()[1],
                third,
            ])

    def test_since_and_all_on_freshly_loaded_store(self) -> None:
        clock = ScriptedClock([0.0, 1.0, 2.0])
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.jsonl"
            writer = JsonlEventStore(path, clock=clock)
            writer.append("a", "team-1", "chal-1")
            writer.append("b", "team-1", "chal-1")
            writer.append("c", "team-1", "chal-1")

            reader = JsonlEventStore(path, clock=ScriptedClock([]))

            self.assertEqual(len(reader.all()), 3)
            self.assertEqual([event.type for event in reader.since(1)], ["b", "c"])
            self.assertEqual(reader.latest_seq(), 3)

    def test_creates_parent_directories(self) -> None:
        clock = ScriptedClock([0.0])
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "nested" / "dir" / "events.jsonl"
            store = JsonlEventStore(path, clock=clock)

            store.append("a", "team-1", "chal-1")

            self.assertTrue(path.exists())

    def test_empty_or_missing_file_yields_no_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "does-not-exist.jsonl"
            store = JsonlEventStore(path, clock=ScriptedClock([]))

            self.assertEqual(store.all(), [])
            self.assertEqual(store.latest_seq(), 0)
            self.assertEqual(store.since(0), [])


if __name__ == "__main__":
    unittest.main()
