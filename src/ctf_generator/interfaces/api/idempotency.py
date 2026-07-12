"""``Idempotency-Key`` handling for mutating POSTs (framework-free).

Contract (``docs/api/endpoints.md`` §1.7): the first use of a key processes the
request and stores its response against ``(scope, key, request-fingerprint)``; a
replay with the **same** key and an **identical** body returns the stored
response verbatim; a replay with the same key but a **different** body is a
``409 idempotency_key_reused``.

Slice a ships a pluggable :class:`IdempotencyStore` protocol with an in-memory
implementation -- correct for a single-process deployment and the test suite. The
production form is a durable table with a row lock (so a retry that races the
original is serialized); that lands with real deployment. The store holds only the
request fingerprint (a hash, never the raw body) and the already-sanitized
response envelope -- never secrets.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Protocol

from .exceptions import IdempotencyConflictError


def fingerprint(body: Any) -> str:
    """Stable hash of a request body for same-key/same-body detection."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StoredResponse:
    request_hash: str
    status_code: int
    body: dict[str, Any]
    etag: str | None = None


class IdempotencyStore(Protocol):
    def lookup(self, scope: str, key: str) -> StoredResponse | None: ...

    def save(
        self, scope: str, key: str, response: StoredResponse
    ) -> None: ...


class InMemoryIdempotencyStore:
    """Process-local idempotency store (thread-safe). Not shared across workers;
    a durable table replaces it for multi-process deployment."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], StoredResponse] = {}
        self._lock = threading.Lock()

    def lookup(self, scope: str, key: str) -> StoredResponse | None:
        with self._lock:
            return self._data.get((scope, key))

    def save(self, scope: str, key: str, response: StoredResponse) -> None:
        with self._lock:
            self._data[(scope, key)] = response


def replay_or_conflict(
    store: IdempotencyStore, scope: str, key: str, request_hash: str
) -> StoredResponse | None:
    """Return the stored response to replay for ``(scope, key)``, or ``None`` if
    the key is unseen. Raises :class:`IdempotencyConflictError` when the key was
    used with a different body."""
    stored = store.lookup(scope, key)
    if stored is None:
        return None
    if stored.request_hash != request_hash:
        raise IdempotencyConflictError(
            f"Idempotency-Key {key!r} was already used with a different request body"
        )
    return stored
