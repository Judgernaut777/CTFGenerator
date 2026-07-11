"""Append-only competition event log -- the pure contract.

Stdlib-only, domain-pure: this module defines the event value type and the
storage abstractions, plus the one volatile implementation that performs no
I/O. All external effects (the wall clock) sit behind the injectable ``Clock``
protocol so tests can supply deterministic, scripted timestamps.

* :class:`Event` -- immutable event value type.
* :class:`Clock` -- injectable time source.
* :class:`EventStore` -- the append-only store protocol.
* :class:`InMemoryEventStore` -- volatile, process-local, fastest for tests
  and the only implementation that is I/O-free (hence domain-pure).

The file-backed :class:`JsonlEventStore` and any database-backed store live in
``ctf_generator.infrastructure`` because they perform I/O; they implement the
:class:`EventStore` protocol defined here.

Every store assigns a strictly monotonic ``seq`` starting at 1, so callers can
poll for new events with :meth:`EventStore.since`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
        self._lock = threading.Lock()

    def append(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> Event:
        # Serialize the read-increment-append so concurrent callers (one
        # thread per connection under ThreadingHTTPServer) cannot collide on
        # ``seq`` -- the monotonicity guarantee callers poll ``since`` against.
        with self._lock:
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
