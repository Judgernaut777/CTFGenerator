"""Central schema identity, versioning, compatibility, and migration.

Milestone 4 (schema & plugin contracts). Before this module the codebase had
three independent hard-coded ``"1.0"`` constants that no consumer ever read
(risk R-03): stamps, not contracts. This module makes schema versioning real:

* Every serialized artifact carries an explicit **schema identifier** and a
  **semantic version**.
* Loaders call :func:`check_compatible` to reject an unknown **major** version
  (a forward-incompatible document) with a clear error instead of silently
  mis-parsing it.
* :func:`migrate` upgrades an older minor/patch document to the current version
  through a registered migration chain, and stamps the result.

Versioning policy (SemVer-ish, two- or three-part accepted):
* **Major** bump  = breaking change; old readers must refuse (``check_compatible``).
* **Minor** bump  = additive/backward-compatible; old readers ignore new keys,
  new readers migrate old documents forward.
* **Patch** bump  = clarification/no shape change.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Callable

# --- Schema identifiers -------------------------------------------------------
SPEC_SCHEMA = "ctfgen.challenge-spec"
BUILD_MANIFEST_SCHEMA = "ctfgen.build-manifest"
BUILD_MARKER_SCHEMA = "ctfgen.build-marker"
REPORT_SCHEMA = "ctfgen.report"
ERROR_SCHEMA = "ctfgen.error"
FAMILY_METADATA_SCHEMA = "ctfgen.family-metadata"

# --- Current versions ---------------------------------------------------------
# Bump the minor when a schema gains an additive field; bump the major (and add
# a migration) only for a breaking change.
CURRENT_VERSIONS: dict[str, str] = {
    SPEC_SCHEMA: "1.1",  # 1.1 adds the schema id/version stamp itself
    BUILD_MANIFEST_SCHEMA: "1.0",
    BUILD_MARKER_SCHEMA: "1.0",
    REPORT_SCHEMA: "1.0",
    ERROR_SCHEMA: "1.0",
    FAMILY_METADATA_SCHEMA: "1.0",
}


class SchemaError(ValueError):
    """Base class for schema identity/version errors."""


class UnknownSchemaError(SchemaError):
    """The document declares a schema identifier we do not know."""


class IncompatibleSchemaError(SchemaError):
    """The document's major version is not one this generator can read."""


def parse_semver(version: str) -> tuple[int, int, int]:
    """Parse ``"1"``, ``"1.2"`` or ``"1.2.3"`` into a ``(major, minor, patch)``
    tuple. Raises :class:`SchemaError` on anything malformed."""
    if not isinstance(version, str) or not version:
        raise SchemaError(f"missing schema version: {version!r}")
    parts = version.split(".")
    if len(parts) > 3:
        raise SchemaError(f"malformed schema version: {version!r}")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise SchemaError(f"non-numeric schema version: {version!r}") from None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def current_version(schema_id: str) -> str:
    try:
        return CURRENT_VERSIONS[schema_id]
    except KeyError:
        raise UnknownSchemaError(f"unknown schema identifier: {schema_id!r}") from None


def check_compatible(schema_id: str, version: str) -> None:
    """Raise :class:`IncompatibleSchemaError` if ``version``'s major differs
    from the current major for ``schema_id`` (a breaking, forward-incompatible
    change). A newer *minor* is accepted: minor bumps are additive, so an older
    reader parses the fields it knows and ignores the rest."""
    cur_major, _, _ = parse_semver(current_version(schema_id))
    major, _, _ = parse_semver(version)
    if major != cur_major:
        raise IncompatibleSchemaError(
            f"{schema_id}: incompatible major version {version} "
            f"(this generator reads {cur_major}.x)"
        )


# --- Migration registry -------------------------------------------------------
# Keyed by (schema_id, from "major.minor") -> (to_version, migrate_fn). Chains
# apply in sequence until the document reaches the current version.
_MIGRATIONS: dict[tuple[str, str], tuple[str, Callable[[dict], dict]]] = {}


def _minor_key(version: str) -> str:
    major, minor, _ = parse_semver(version)
    return f"{major}.{minor}"


def register_migration(
    schema_id: str, from_version: str, to_version: str, fn: Callable[[dict], dict]
) -> None:
    """Register a migration from ``from_version`` (matched by major.minor) to
    ``to_version`` for ``schema_id``."""
    _MIGRATIONS[(schema_id, _minor_key(from_version))] = (to_version, fn)


def stamp(schema_id: str, data: dict) -> dict:
    """Return ``data`` with ``schema``/``schema_version`` set to current."""
    out = dict(data)
    out["schema"] = schema_id
    out["schema_version"] = current_version(schema_id)
    return out


def migrate(schema_id: str, data: dict) -> dict:
    """Validate and upgrade a loaded document to the current schema version.

    * A document with no version stamp is assumed to be the earliest release
      (``1.0``) -- back-compat for artifacts written before stamping existed.
    * Rejects an incompatible major version.
    * Applies the registered migration chain until current, then re-stamps.
    Does not mutate the input (deep-copied, so a migration that edits a nested
    structure cannot leak back into a caller's original document).
    """
    doc = deepcopy(data)
    declared = doc.get("schema")
    if declared is not None and declared != schema_id:
        raise UnknownSchemaError(
            f"expected schema {schema_id!r} but document declares {declared!r}"
        )
    version = doc.get("schema_version") or "1.0"
    check_compatible(schema_id, version)  # rejects an incompatible major

    cur = current_version(schema_id)
    _, cur_minor, _ = parse_semver(cur)
    _, doc_minor, _ = parse_semver(version)
    if doc_minor > cur_minor:
        # A forward-compatible document from a NEWER generator (same major).
        # Accept as-is, keep its own newer stamp, and let parsing ignore any
        # fields we don't model -- never downgrade its version stamp.
        if declared is None:
            doc["schema"] = schema_id
        return doc

    guard = 0
    while _minor_key(version) != _minor_key(cur):
        step = _MIGRATIONS.get((schema_id, _minor_key(version)))
        if step is None:
            # A gap in the chain: refuse to silently stamp an un-upgraded
            # document as current (that would be data corruption). Every minor
            # bump must register a migration (an identity fn suffices when the
            # change is purely additive).
            raise SchemaError(
                f"no migration registered from {schema_id} {version} toward {cur}"
            )
        to_version, fn = step
        doc = fn(doc)
        # Re-validate after each step so a mis-registered migration whose
        # to_version overshoots the current major/minor is caught, not stamped.
        check_compatible(schema_id, to_version)
        version = to_version
        guard += 1
        if guard > 64:  # pragma: no cover - defensive against a cyclic chain
            raise SchemaError(f"migration chain for {schema_id} did not converge")

    return stamp(schema_id, doc)


# --- Registered migrations ----------------------------------------------------
# challenge-spec 1.0 -> 1.1: purely additive (the stamp itself). No data change.
register_migration(SPEC_SCHEMA, "1.0", "1.1", lambda d: d)
