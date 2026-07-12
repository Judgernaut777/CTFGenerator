"""Challenge-build DTOs + mappers.

A build is the content-addressed, insert-only artifact of a version, keyed by
``build_sha256``. These read DTOs expose the build's content identity and
provenance (family / generator version / storage reference / manifest). The
``seed`` is a generation input that can influence a flag, so it is NOT surfaced
here -- only the version's ``spec_sha256`` content hash and the manifest
document (references only) are.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.authoring.models import ChallengeBuild


class BuildListItem(BaseModel):
    build_sha256: str
    definition_slug: str
    version_no: int
    family: str
    generator_version: str
    family_version: str | None = None
    spec_sha256: str
    storage_uri: str | None = None


class BuildResponse(BuildListItem):
    manifest: dict[str, Any] = Field(default_factory=dict)


def build_to_list_item(build: ChallengeBuild) -> dict[str, Any]:
    return {
        "build_sha256": build.build_sha256,
        "definition_slug": build.definition_slug,
        "version_no": build.version_no,
        "family": build.family,
        "generator_version": build.generator_version,
        "family_version": build.family_version,
        "spec_sha256": build.spec_sha256,
        "storage_uri": build.storage_uri,
    }


def build_to_response(build: ChallengeBuild) -> dict[str, Any]:
    body = build_to_list_item(build)
    body["manifest"] = dict(build.manifest)
    return body


def build_concurrency_payload(build: ChallengeBuild) -> dict[str, Any]:
    # Builds are content-addressed + insert-only: the hash IS the version.
    return {"build_sha256": build.build_sha256}
