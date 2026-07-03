"""Append-only competition event log.

Stdlib-only. All external effects (the wall clock) sit behind the injectable
``Clock`` protocol so tests can supply deterministic, scripted timestamps.
Two ``EventStore`` implementations are provided:

* :class:`InMemoryEventStore` -- volatile, process-local, fastest for tests.
* :class:`JsonlEventStore` -- append-only JSONL file persistence, so events
  survive process restarts and can be tailed/replayed externally.

Both assign a strictly monotonic ``seq`` starting at 1, so callers can poll
for new events with :meth:`EventStore.since`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class Event:
    seq: int
    ts: str
    type: str
    team_id: str
    challenge_id: str
    payload: dict = field(default_factory=dict)


class Clock(Protocol):
    def __call__(self) -> float:
        ...


class EventStore(Protocol):
    def append(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> Event:
        ...

    def since(self, seq: int) -> list[Event]:
        ...

    def all(self) -> list[Event]:
        ...

    def latest_seq(self) -> int:
        ...


def _default_clock() -> float:
    return time.time()


def _format_ts(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def _event_to_dict(event: Event) -> dict:
    return {
        "seq": event.seq,
        "ts": event.ts,
        "type": event.type,
        "team_id": event.team_id,
        "challenge_id": event.challenge_id,
        "payload": event.payload,
    }


class InMemoryEventStore:
    """Volatile, process-local event log. Injectable ``Clock`` for tests."""

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or _default_clock
        self._events: list[Event] = []
        self._next_seq = 1

    def append(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> Event:
        event = Event(
            seq=self._next_seq,
            ts=_format_ts(self._clock()),
            type=type,
            team_id=team_id,
            challenge_id=challenge_id,
            payload=dict(payload) if payload else {},
        )
        self._events.append(event)
        self._next_seq += 1
        return event

    def since(self, seq: int) -> list[Event]:
        return [event for event in self._events if event.seq > seq]

    def all(self) -> list[Event]:
        return list(self._events)

    def latest_seq(self) -> int:
        return self._events[-1].seq if self._events else 0


class JsonlEventStore:
    """Append-only JSONL file persistence. Injectable ``Clock`` for tests.

    Existing events are loaded from ``path`` on construction (if present),
    so opening a new store against a file written by a previous instance
    resumes ``seq`` numbering correctly and round-trips prior events.
    """

    def __init__(self, path: Path | str, clock: Clock | None = None) -> None:
        self._path = Path(path)
        self._clock: Clock = clock or _default_clock
        self._events: list[Event] = self._read_existing()
        self._next_seq = self._events[-1].seq + 1 if self._events else 1

    def append(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> Event:
        event = Event(
            seq=self._next_seq,
            ts=_format_ts(self._clock()),
            type=type,
            team_id=team_id,
            challenge_id=challenge_id,
            payload=dict(payload) if payload else {},
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_event_to_dict(event), sort_keys=True))
            handle.write("\n")
        self._events.append(event)
        self._next_seq += 1
        return event

    def since(self, seq: int) -> list[Event]:
        return [event for event in self._events if event.seq > seq]

    def all(self) -> list[Event]:
        return list(self._events)

    def latest_seq(self) -> int:
        return self._events[-1].seq if self._events else 0

    def _read_existing(self) -> list[Event]:
        if not self._path.exists():
            return []
        events: list[Event] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                events.append(Event(**data))
        return events
