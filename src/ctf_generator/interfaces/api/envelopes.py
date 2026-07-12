"""Response-envelope builders (framework-free dict factories).

Every API response body carries a two-field version stamp (``schema`` /
``schema_version``), mirroring ``ctf_generator.schema.stamp`` and the contract in
``docs/api/endpoints.md`` §1.1.

* The **error** envelope reuses the registered ``ctfgen.error`` identifier and its
  current version from :mod:`ctf_generator.schema` -- it is a real, versioned
  contract, not a local invention.
* The **resource / list** envelopes use interface-layer identifiers defined here.
  ``endpoints.md`` marks per-resource identifiers as "TBD: register in
  schema.py"; slice a defines them API-locally (owned by the interface layer) and
  registering them in the shared ``schema.py`` registry is a documented follow-up
  so this milestone does not churn the cross-cutting schema module.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ctf_generator.schema import ERROR_SCHEMA, current_version

# Interface-layer envelope identifiers (see module docstring). Versioned
# independently of the domain artifact schemas; "1.0" is the initial contract.
_API_SCHEMA_VERSION = "1.0"

COMPETITION_SCHEMA = "ctfgen.competition"
COMPETITION_LIST_SCHEMA = "ctfgen.competition-list"
TEAM_SCHEMA = "ctfgen.team"
TEAM_LIST_SCHEMA = "ctfgen.team-list"
CHALLENGE_DEFINITION_SCHEMA = "ctfgen.challenge-definition"
CHALLENGE_DEFINITION_LIST_SCHEMA = "ctfgen.challenge-definition-list"
CHALLENGE_VERSION_SCHEMA = "ctfgen.challenge-version"
CHALLENGE_VERSION_LIST_SCHEMA = "ctfgen.challenge-version-list"


def resource_envelope(schema_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
    """Stamp a single resource body with its schema id/version."""
    return {"schema": schema_id, "schema_version": _API_SCHEMA_VERSION, **dict(body)}


def list_envelope(
    schema_id: str,
    items: Sequence[Mapping[str, Any]],
    *,
    limit: int,
    next_cursor: str | None,
) -> dict[str, Any]:
    """Build the cursor-paginated list envelope (``{schema, schema_version, data,
    page}``)."""
    return {
        "schema": schema_id,
        "schema_version": _API_SCHEMA_VERSION,
        "data": [dict(item) for item in items],
        "page": {
            "limit": limit,
            "next_cursor": next_cursor,
            "has_more": next_cursor is not None,
        },
    }


def error_envelope(
    *,
    code: str,
    message: str,
    request_id: str,
    detail: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build the ``ctfgen.error`` envelope. ``message``/``detail`` must never
    carry secrets (flags, tokens, credentials) -- the handlers that call this pass
    only sanitized text."""
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": request_id,
    }
    if detail:
        error["details"] = detail
    return {
        "schema": ERROR_SCHEMA,
        "schema_version": current_version(ERROR_SCHEMA),
        "error": error,
    }
