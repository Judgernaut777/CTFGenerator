"""Challenge authoring DTOs + mappers: challenge *definitions* (stable identity)
and challenge *versions* (immutable-once-published revisions).

Data minimization: list responses carry version *metadata* only; the full ``spec``
payload is returned solely on a single-version GET. The spec echoed back is the
canonical author-supplied content; solver-private artifacts populated by the
generator pipeline are redacted at that layer (deferred to the generation slice)
and are never served here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ctf_generator.domain.answers.models import AnswerSpecError, parse_answer_spec
from ctf_generator.domain.authoring.models import (
    ChallengeDefinition,
    ChallengeVersion,
)

# ---------------------------------------------------------------- definitions


class ChallengeDefinitionCreateRequest(BaseModel):
    family: str = Field(min_length=1)
    slug: str = Field(min_length=1)
    title: str = Field(min_length=1)

    def to_domain(self) -> ChallengeDefinition:
        return ChallengeDefinition(family=self.family, slug=self.slug, title=self.title)


class ChallengeDefinitionPatchRequest(BaseModel):
    """Only ``title`` is mutable (``family``/``slug`` are identity)."""

    title: str | None = Field(default=None, min_length=1)


class ChallengeDefinitionResponse(BaseModel):
    family: str
    slug: str
    title: str


def definition_concurrency_payload(defn: ChallengeDefinition) -> dict[str, Any]:
    return {"family": defn.family, "slug": defn.slug, "title": defn.title}


def definition_to_response(defn: ChallengeDefinition) -> dict[str, Any]:
    return {"family": defn.family, "slug": defn.slug, "title": defn.title}


# ------------------------------------------------------------------- versions


class ChallengeVersionCreateRequest(BaseModel):
    definition_slug: str = Field(min_length=1)
    seed: str = Field(min_length=1)
    family_version: str = Field(min_length=1)
    spec: dict[str, Any] = Field(description="Canonical challenge spec payload")
    spec_version: str | None = Field(
        default=None,
        description="Spec schema version; defaults to the server's current spec schema",
    )
    mode: str = Field(default="red", min_length=1)
    cve_refs: list[str] = Field(default_factory=list)
    cve_content_hash: str | None = None

    @field_validator("spec")
    @classmethod
    def _validate_private_answer_verifier(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Validate private answer data at the authoring boundary only."""
        typed = value.get("answer_verifier")
        if typed is not None:
            try:
                parse_answer_spec(typed)
            except AnswerSpecError as exc:
                raise ValueError("invalid answer_verifier specification") from exc
        return value


class ChallengeVersionResponse(BaseModel):
    definition_slug: str
    version_no: int
    state: str
    seed: str
    family_version: str
    spec_sha256: str
    spec_version: str
    mode: str
    cve_refs: list[str]
    cve_content_hash: str | None = None
    published_at: datetime | None = None
    immutable: bool
    spec: dict[str, Any] | None = None


class ChallengeVersionListItem(BaseModel):
    definition_slug: str
    version_no: int
    state: str
    seed: str
    family_version: str
    spec_sha256: str
    spec_version: str
    mode: str
    published_at: datetime | None = None
    immutable: bool


def version_concurrency_payload(version: ChallengeVersion) -> dict[str, Any]:
    return {
        "definition_slug": version.definition_slug,
        "version_no": version.version_no,
        "state": version.state,
        "spec_sha256": version.spec_sha256,
        "published_at": (version.published_at.isoformat() if version.published_at else None),
    }


def _version_base(version: ChallengeVersion) -> dict[str, Any]:
    return {
        "definition_slug": version.definition_slug,
        "version_no": version.version_no,
        "state": version.state,
        "seed": version.seed,
        "family_version": version.family_version,
        "spec_sha256": version.spec_sha256,
        "spec_version": version.spec_version,
        "mode": version.mode,
        "published_at": (version.published_at.isoformat() if version.published_at else None),
        "immutable": version.state != "draft",
    }


def version_to_list_item(version: ChallengeVersion) -> dict[str, Any]:
    """Metadata-only projection for list responses (no ``spec`` payload)."""
    return _version_base(version)


_PRIVATE_ANSWER_SPEC_KEYS = frozenset({"flag", "answer_derivation", "answer_verifier"})


def _public_spec(spec: dict[str, Any] | Any) -> dict[str, Any]:
    """Remove expected-answer material before any API version projection."""
    return {key: value for key, value in dict(spec).items() if key not in _PRIVATE_ANSWER_SPEC_KEYS}


def version_to_response(version: ChallengeVersion) -> dict[str, Any]:
    """Full public projection, excluding private verifier/expected-answer data."""
    body = _version_base(version)
    body["cve_refs"] = list(version.cve_refs)
    body["cve_content_hash"] = version.cve_content_hash
    body["spec"] = _public_spec(version.spec)
    return body
