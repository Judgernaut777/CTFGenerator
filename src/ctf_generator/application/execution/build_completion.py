"""Parse a ``build_challenge`` job's completion result (pure, non-fatal).

The worker's ``_do_build_challenge`` reports a result payload of the shape::

    {"definition_slug": str, "version_no": int, "bundle_sha256": str,
     "image_ref": str, "digest": str}

on the completed job. This module extracts the **build outputs** a worker
legitimately produces — the runnable ``image_ref``, its content ``image_digest``,
and the ``bundle_sha256`` it was built from — into a validated
:class:`BuildCompletion`, or ``None`` when the payload carries no built image.

**The version this build targets is NOT taken from here.** The payload's
``definition_slug``/``version_no`` are attacker-influenced (a worker is hostile
input by construction, ADR-001); the authoritative target is the job's own
recorded ``(definition_slug, version_no)``, read by the caller from the job row.
So this parser deliberately ignores the payload's slug/version.

**Non-fatal by construction.** A worker's result payload must never be able to
prevent its own (legitimately completed) job from terminalizing. So parsing
NEVER raises on a malformed payload: a missing/blank ``image_ref`` yields ``None``
(no image side effects), and a malformed sibling field simply degrades that field
to absent rather than throwing out of the completion path.

Pure and host-testable: no DB, no Docker, no logging of the payload. Every field
is a reference or a hash — never a flag, seed, or secret.
"""

from __future__ import annotations

from dataclasses import dataclass


def _nonempty_str(value: object) -> str | None:
    """Return the string iff ``value`` is a non-blank str, else ``None``."""
    if isinstance(value, str) and value.strip():
        return value
    return None


@dataclass(frozen=True)
class BuildCompletion:
    """A build-job completion carrying a runnable image reference.

    ``bundle_sha256`` and ``image_digest`` may be ``None`` when the payload omits
    them (or the build backend returned no digest): the worker-affinity cache
    keys on ``image_ref`` alone and is still written, but the version->image
    registry needs both (its columns are NOT NULL) and is skipped for that
    completion (see :attr:`can_record_image`).
    """

    image_ref: str
    bundle_sha256: str | None = None
    image_digest: str | None = None

    def __post_init__(self) -> None:
        # Defensive: direct construction must still uphold the non-empty invariant
        # the DB CHECK enforces. ``parse_build_completion`` never reaches here with
        # a bad ``image_ref`` (it returns ``None`` first), so this never fires on
        # the completion path.
        if not (isinstance(self.image_ref, str) and self.image_ref.strip()):
            raise ValueError("image_ref must be a non-empty str")

    @property
    def can_record_image(self) -> bool:
        """True iff both the digest and the bundle hash are present, i.e. a
        version->image registry row (whose columns are NOT NULL) can be written
        for this completion."""
        return self.image_digest is not None and self.bundle_sha256 is not None


def parse_build_completion(result_json: dict | None) -> BuildCompletion | None:
    """Interpret a job completion result as a build outcome, or ``None``.

    Returns ``None`` — signalling 'no built image, no image side effects' — when
    ``result_json`` is falsy or carries no non-blank ``image_ref``. Otherwise
    returns a :class:`BuildCompletion` with the reported ``image_ref`` and,
    when present and well-formed, ``bundle_sha256`` and ``image_digest`` (mapped
    from the payload's ``digest``). NEVER raises: a malformed sibling field
    degrades to ``None`` for that field so a bad worker payload cannot veto its
    job's terminalization. The build's TARGET version is resolved by the caller
    from the job, not from this payload."""
    if not result_json:
        return None
    image_ref = _nonempty_str(result_json.get("image_ref"))
    if image_ref is None:
        return None
    return BuildCompletion(
        image_ref=image_ref,
        bundle_sha256=_nonempty_str(result_json.get("bundle_sha256")),
        image_digest=_nonempty_str(result_json.get("digest")),
    )
