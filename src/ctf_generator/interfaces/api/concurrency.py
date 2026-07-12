"""ETag optimistic-concurrency helpers (framework-free).

The slice-a catalog tables (``competitions``, ``teams``,
``challenge_definitions``) carry no monotonic ``version``/``updated_at`` column,
so the ETag is a **content validator**: a stable hash over the concurrency-
relevant representation of the resource. Two reads of an unchanged resource hash
identically; any mutation changes the hash, so a stale ``If-Match`` reliably
yields ``412``. This is a genuine optimistic-concurrency token that needs no
schema migration (a later slice can swap in a row ``version`` column without
changing the wire contract). The precondition is evaluated inside the service's
unit of work (against the freshly-read current aggregate), so the read-check-write
is atomic.

Format: a strong entity-tag -- the hex digest in double quotes, e.g.
``"3f9c...":`` matching ``docs/api/endpoints.md`` §1.8. ``If-Match`` comparison is
tolerant of an optional weak ``W/`` prefix and surrounding quotes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def compute_etag(payload: Mapping[str, Any]) -> str:
    """Return the quoted strong ETag for a resource's concurrency payload."""
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
    return f'"{digest}"'


def _normalize(tag: str) -> str:
    """Strip an optional weak ``W/`` prefix and surrounding double quotes so two
    syntactically different but semantically equal tags compare equal."""
    tag = tag.strip()
    if tag.startswith("W/"):
        tag = tag[2:].strip()
    if len(tag) >= 2 and tag[0] == '"' and tag[-1] == '"':
        tag = tag[1:-1]
    return tag


def etags_match(if_match: str, current_etag: str) -> bool:
    """True iff the client's ``If-Match`` value matches the current ETag. ``*``
    matches any current resource (RFC 9110)."""
    if_match = if_match.strip()
    if if_match == "*":
        return True
    return _normalize(if_match) == _normalize(current_etag)
