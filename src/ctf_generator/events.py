"""Compatibility shim for the competition event log.

The pure event contract (:class:`Event`, :class:`Clock`, :class:`EventStore`)
and the volatile :class:`InMemoryEventStore` now live in
``ctf_generator.domain.competitions.events``; the file-backed
:class:`JsonlEventStore` lives in
``ctf_generator.infrastructure.event_store``. This module re-exports them so
existing ``from ctf_generator.events import ...`` / ``from . import events``
call sites keep working unchanged.
"""

from __future__ import annotations

from .domain.competitions.events import (
    Clock,
    Event,
    EventStore,
    InMemoryEventStore,
    _default_clock,
    _event_to_dict,
    _format_ts,
)
from .infrastructure.event_store import JsonlEventStore

__all__ = [
    "Clock",
    "Event",
    "EventStore",
    "InMemoryEventStore",
    "JsonlEventStore",
]
