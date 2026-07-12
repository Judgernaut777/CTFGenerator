"""Flag verification: candidate normalization + the spec-backed verifier.

The candidate flag is never stored, never logged, and never placed in an
event payload -- it exists transiently in this module and is compared in
constant time (``hmac.compare_digest``) to avoid a timing side channel on the
scoring hot path.
"""

from __future__ import annotations

import hmac

from ctf_generator.domain.authoring.models import ChallengeVersion
from ctf_generator.domain.ledger.processing import (
    FlagRejectedError,
    FlagUnavailableError,
)

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
        raise FlagRejectedError(
            f"candidate flag exceeds {MAX_CANDIDATE_LENGTH} characters"
        )
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

    def verify(
        self, version: ChallengeVersion, instance_seed: str | None, candidate: str
    ) -> bool:
        expected = version.spec.get("flag")
        if not isinstance(expected, str) or not expected.strip():
            raise FlagUnavailableError(
                f"challenge version {version.definition_slug!r} "
                f"v{version.version_no} spec carries no expected flag"
            )
        return hmac.compare_digest(
            expected.encode("utf-8"), candidate.encode("utf-8")
        )
