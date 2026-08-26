"""Flag verification: candidate normalization + the spec-backed verifier.

The candidate flag is never stored, never logged, and never placed in an
event payload -- it exists transiently in this module and is compared in
constant time (``hmac.compare_digest``) to avoid a timing side channel on the
scoring hot path.
"""

from __future__ import annotations

import hmac

from ctf_generator.domain.answers.models import AnswerSpecError, parse_answer_spec
from ctf_generator.domain.authoring.models import ChallengeVersion
from ctf_generator.domain.ledger.processing import (
    FlagRejectedError,
    FlagUnavailableError,
)
from ctf_generator.families import derive_family_answer
from ctf_generator.families import get as get_family

MAX_CANDIDATE_LENGTH = 4096


def normalize_candidate(candidate: str) -> str:
    """Strip and validate a candidate flag. Rejections carry only the reason,
    never the candidate itself."""
    if not isinstance(candidate, str):
        raise FlagRejectedError("candidate flag must be a string")
    normalized = candidate.strip()
    if not normalized:
        raise FlagRejectedError("candidate flag is empty")
    if len(normalized) > MAX_CANDIDATE_LENGTH:
        raise FlagRejectedError(f"candidate flag exceeds {MAX_CANDIDATE_LENGTH} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in normalized):
        raise FlagRejectedError("candidate flag contains control characters")
    return normalized


class SpecFlagVerifier:
    """Verifies against the expected flag carried in the immutable published
    version's spec mapping (``spec['flag']``).

    Fails loud (:class:`FlagUnavailableError`) when the spec carries no flag
    -- never guesses and never silently records an incorrect submission for
    an organizer-side configuration defect. Families that derive per-instance
    flags from ``instance_seed`` at build time need a different verifier
    behind the same protocol (an M8 slice); this one ignores
    ``instance_seed``.
    """

    def verify(self, version: ChallengeVersion, instance_seed: str | None, candidate: str) -> bool:
        """Verify against private immutable published spec data.

        ``flag`` is retained as the legacy exact, constant-time route. New
        typed verifier data is private authoring data and is deliberately never
        projected by contestant-facing schema mappers.
        """
        derivation = version.spec.get("answer_derivation")
        if derivation is not None:
            if not isinstance(derivation, dict) or not isinstance(derivation.get("family"), str):
                raise FlagUnavailableError("published answer derivation data is malformed")
            if not instance_seed:
                raise FlagUnavailableError("challenge requires a server-issued instance seed")
            try:
                expected = derive_family_answer(
                    get_family(derivation["family"]), dict(version.spec), instance_seed
                )
            except (KeyError, LookupError, ValueError) as exc:
                raise FlagUnavailableError("published answer derivation is unavailable") from exc
            return hmac.compare_digest(expected.encode("utf-8"), candidate.encode("utf-8"))

        typed = version.spec.get("answer_verifier")
        if typed is not None:
            try:
                return parse_answer_spec(typed).matches(candidate)
            except AnswerSpecError as exc:
                raise FlagUnavailableError("published answer verifier data is malformed") from exc
        expected = version.spec.get("flag")
        if not isinstance(expected, str) or not expected.strip():
            raise FlagUnavailableError(
                f"challenge version {version.definition_slug!r} "
                f"v{version.version_no} spec carries no expected flag"
            )
        return hmac.compare_digest(expected.encode("utf-8"), candidate.encode("utf-8"))
