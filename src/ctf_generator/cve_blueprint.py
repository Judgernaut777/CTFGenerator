"""Turns a bundled/live ``CveRecord`` into a themed ``ChallengeSpec``.

Pure module: no I/O, no randomness, no clock. Every function here is a
deterministic transform of its inputs -- the same ``CveRecord`` + ``base_seed``
always produces byte-identical output, which is required for CTFGenerator's
seed-based reproducibility guarantee.

Two layers:

- ``blueprint_from_cve`` produces a ``CveBlueprint``: the themed, human-facing
  metadata (title/objectives/checkpoints) plus the *intended* family/
  difficulty/mode for a CVE, independent of whether that family has been
  registered with ``families`` yet.
- ``spec_from_cve`` lowers a ``CveBlueprint`` into a full ``models.ChallengeSpec``,
  falling back to the always-registered ``web_business_logic_tenant_export``
  family when the intended family isn't registered yet (families other than
  that one are wired up in Phase 3.5). The CVE-derived category, title,
  objectives, checkpoints, and provenance (``cve_refs``/``cve_content_hash``)
  are preserved even when the family falls back.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from . import families
from .cve_source import CveRecord
from .models import ChallengeSpec

# --- Canonical category -> family map ---------------------------------------
#
# Fixed by design (see project instructions): Phase 3.5 registers exactly
# these family names. Until a given family is registered, spec_from_cve falls
# back to "web_business_logic_tenant_export" so specs stay valid.
CATEGORY_FAMILY_MAP: dict[str, str] = {
    "web": "web_business_logic_tenant_export",
    "scada_ics": "scada_ics_modbus_takeover",
    "network": "network_lateral_pivot",
    "crypto": "crypto_token_forgery",
    "cloud": "cloud_metadata_ssrf",
    "forensics": "forensics_incident_triage",
    "binary": "binary_heap_exploit",
    "mobile": "mobile_insecure_storage",
}

# Family used as the ChallengeSpec.family fallback whenever the intended
# family for a category is not yet registered. Always registered itself.
_FALLBACK_FAMILY = "web_business_logic_tenant_export"

# Categories whose intended family is a defensive ("blue") exercise rather
# than an offensive ("red") one, absent an explicit mode override.
_BLUE_CATEGORIES: frozenset[str] = frozenset({"forensics"})


@dataclass(frozen=True)
class CveBlueprint:
    """Themed, human-facing metadata derived from a single CVE."""

    family: str
    difficulty: str
    mode: str
    cve_id: str
    themed_title: str
    themed_objectives: list[str] = field(default_factory=list)
    themed_checkpoints: list[str] = field(default_factory=list)


def fold_seed(base_seed: str, cve_id: str) -> str:
    """Deterministically combine a generator seed with a CVE id.

    Simple, stable concatenation -- same inputs always produce the same
    string, and distinct CVEs generated from the same ``base_seed`` never
    collide (a CVE id can't itself contain the ``:`` separator).
    """
    return f"{base_seed}:{cve_id}"


def difficulty_from_cvss(score: float) -> str:
    """Map a CVSS base score to a challenge difficulty tier."""
    if score >= 9.0:
        return "hard"
    if score >= 7.0:
        return "medium"
    return "easy"


def content_hash(record: CveRecord) -> str:
    """SHA-256 hex digest over the record's canonical JSON mapping.

    Used for provenance/drift detection: re-generating from the same seed
    later stays byte-identical even if the upstream CVE source changes,
    because the hash locks in the exact record content used at generation
    time (see ``ChallengeSpec.cve_content_hash``).
    """
    canonical = json.dumps(record.to_mapping(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _primary_cwe(record: CveRecord) -> str:
    return record.cwe_ids[0] if record.cwe_ids else "an unclassified weakness"


def _primary_product(record: CveRecord) -> str:
    return record.affected_products[0] if record.affected_products else "the target system"


def _default_mode(record: CveRecord) -> str:
    return "blue" if record.category in _BLUE_CATEGORIES else "red"


def _themed_title(record: CveRecord) -> str:
    return f"{record.cve_id}: {_primary_cwe(record)} in {_primary_product(record)}"


def _themed_objectives(record: CveRecord) -> list[str]:
    cwe = _primary_cwe(record)
    product = _primary_product(record)
    return [
        f"Understand how {cwe} manifests in {product}",
        f"Reproduce the {record.cve_id} vulnerability class ({record.cvss_severity} severity)",
        f"Chain the flaw described in {record.cve_id} into a working exploit path",
        f"Extract the flag by exploiting {product} the way {record.cve_id} was disclosed",
    ]


def _themed_checkpoints(record: CveRecord) -> list[str]:
    cwe = _primary_cwe(record)
    product = _primary_product(record)
    return [
        f"recon identifies {product} as the vulnerable component",
        f"locates the {cwe} weakness referenced by {record.cve_id}",
        "crafts a proof-of-concept trigger for the vulnerability",
        f"escalates the {cwe} flaw into full impact matching {record.cvss_severity} severity",
        f"extracts the flag confirming exploitation of {record.cve_id}",
    ]


def blueprint_from_cve(
    record: CveRecord,
    *,
    base_seed: str,
    family: str | None = None,
    difficulty: str | None = None,
    mode: str | None = None,
    title: str | None = None,
) -> CveBlueprint:
    """Build the themed ``CveBlueprint`` for a CVE record.

    ``base_seed`` is accepted for signature symmetry with ``spec_from_cve``
    (and so future themed variation can key off it) but the returned themed
    text is a pure function of ``record`` alone, so it stays stable across
    reseeding. All resolved fields (``family``, ``difficulty``, ``mode``,
    ``themed_title``) honor an explicit override before falling back to a
    deterministic CVE-derived default.
    """
    del base_seed  # unused today; kept for signature stability, see docstring
    resolved_family = family or CATEGORY_FAMILY_MAP.get(record.category, _FALLBACK_FAMILY)
    resolved_difficulty = difficulty or difficulty_from_cvss(record.cvss_score)
    resolved_mode = mode or _default_mode(record)
    resolved_title = title or _themed_title(record)
    return CveBlueprint(
        family=resolved_family,
        difficulty=resolved_difficulty,
        mode=resolved_mode,
        cve_id=record.cve_id,
        themed_title=resolved_title,
        themed_objectives=_themed_objectives(record),
        themed_checkpoints=_themed_checkpoints(record),
    )


def spec_from_cve(
    record: CveRecord,
    *,
    base_seed: str,
    family: str | None = None,
    difficulty: str | None = None,
    mode: str | None = None,
    title: str | None = None,
) -> ChallengeSpec:
    """Build a ``ChallengeSpec`` grounded in a CVE record.

    Resolves the intended family via ``blueprint_from_cve``, then falls back
    to ``web_business_logic_tenant_export`` if that family isn't registered
    yet (``families.is_registered``) -- keeping the spec valid ahead of
    Phase 3.5 -- while preserving the CVE-derived category, themed title,
    objectives, checkpoints, and provenance fields regardless of fallback.
    """
    blueprint = blueprint_from_cve(
        record,
        base_seed=base_seed,
        family=family,
        difficulty=difficulty,
        mode=mode,
        title=title,
    )
    spec_family = blueprint.family
    if not families.is_registered(spec_family):
        spec_family = _FALLBACK_FAMILY
    # The resolved family (possibly the fallback) may not support the
    # blueprint's intended mode (e.g. a "blue" forensics blueprint falling
    # back to a "red"-only family). Downgrade to a mode the resolved family
    # actually supports so spec_from_cve always yields a spec that
    # validate_spec() accepts, without touching the family's registration.
    resolved_mode = blueprint.mode
    if families.is_registered(spec_family):
        allowed_modes = families.get(spec_family).modes
        if allowed_modes and resolved_mode not in allowed_modes:
            resolved_mode = allowed_modes[0]
    return ChallengeSpec(
        title=blueprint.themed_title,
        category=record.category,
        difficulty=blueprint.difficulty,
        family=spec_family,
        seed=fold_seed(base_seed, record.cve_id),
        learning_objectives=list(blueprint.themed_objectives),
        checkpoints=list(blueprint.themed_checkpoints),
        cve_refs=[record.cve_id],
        cve_content_hash=content_hash(record),
        mode=resolved_mode,
    )
