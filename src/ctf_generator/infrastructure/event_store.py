"""File-backed competition event store (infrastructure).

Concrete :class:`~ctf_generator.domain.competitions.events.EventStore`
implementation that performs I/O, so it lives outside the domain layer. The
pure event contract (``Event`` / ``Clock`` / ``EventStore``) and the volatile
``InMemoryEventStore`` are defined in
``ctf_generator.domain.competitions.events``.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..domain.competitions.events import (
    Clock,
    Event,
    _default_clock,
    _event_to_dict,
    _format_ts,
)

__all__ = ["JsonlEventStore"]


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
        self._lock = threading.Lock()

    def append(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> Event:
        # Serialize seq assignment *and* the file append so concurrent writers
        # cannot duplicate a ``seq`` or interleave partial JSONL lines.
        with self._lock:
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
