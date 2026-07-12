"""Opaque cursor pagination (framework-free).

Forward-only, cursor-based paging over a stable sort key, matching
``docs/api/endpoints.md`` §1.4. A cursor is an opaque base64url token wrapping the
sort key of the last item on the previous page; clients MUST NOT parse or
construct it. The catalog repositories return fully materialized domain lists, so
this helper paginates in memory over a caller-provided, stably-sorted sequence:
it decodes the incoming cursor to find the resume point, slices ``limit`` items,
and encodes the next cursor from the last item's key. (A later slice can push the
same opaque-cursor contract down into keyset SQL without changing the wire shape.)
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MIN_LIMIT = 1

T = TypeVar("T")


class CursorError(ValueError):
    """A supplied cursor is malformed / not a token this server issued."""


def _norm(key: Any) -> Any:
    """Normalize a sort key through the same JSON round-trip the cursor uses, so
    a live item's key compares consistently against a decoded cursor key."""
    return json.loads(json.dumps(key, sort_keys=True, default=str))


def encode_cursor(key: Any) -> str:
    """Encode a JSON-serializable sort key into an opaque token."""
    raw = json.dumps({"k": key}, separators=(",", ":"), default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(token: str) -> Any:
    """Decode an opaque token back to its sort key. Raises :class:`CursorError`
    on anything not produced by :func:`encode_cursor`."""
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + padding)
        obj = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise CursorError(f"invalid cursor: {token!r}") from exc
    if not isinstance(obj, dict) or "k" not in obj:
        raise CursorError(f"invalid cursor: {token!r}")
    return obj["k"]


def clamp_limit(limit: int | None) -> int:
    """Clamp a requested page size into ``[MIN_LIMIT, MAX_LIMIT]``; ``None`` ->
    default."""
    if limit is None:
        return DEFAULT_LIMIT
    return max(MIN_LIMIT, min(MAX_LIMIT, limit))


@dataclass(frozen=True)
class Page(Generic[T]):
    items: list[T]
    next_cursor: str | None


def paginate(
    items: Sequence[T],
    *,
    key: Callable[[T], Any],
    limit: int | None,
    cursor: str | None,
) -> Page[T]:
    """Return one page of ``items``.

    ``items`` MUST already be sorted ascending by ``key`` (ties broken stably by
    the caller's chosen id). ``cursor`` (if given) resumes at the first item whose
    key sorts *strictly after* the cursor's key. Resuming strictly-after (rather
    than by exact-match of the boundary key) is deletion-resilient: if the item
    the cursor points at was removed between page fetches, the tail is still
    returned rather than silently skipped. ``next_cursor`` is set only when more
    items follow.
    """
    size = clamp_limit(limit)
    start = 0
    if cursor is not None:
        # The decoded cursor key is already in normalized (JSON round-trip) form;
        # normalize each item's key the same way so heterogeneous-but-stable keys
        # (str / int) compare consistently with a native ``>``.
        resume_after = decode_cursor(cursor)
        start = len(items)
        for idx, item in enumerate(items):
            if _norm(key(item)) > resume_after:
                start = idx
                break
    window = items[start : start + size]
    next_cursor: str | None = None
    if window and (start + size) < len(items):
        next_cursor = encode_cursor(key(window[-1]))
    return Page(items=list(window), next_cursor=next_cursor)
