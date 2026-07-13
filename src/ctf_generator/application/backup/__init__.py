"""Backup / restore / restore-verification (M17 slice 17a).

The disaster-recovery core. Two POSIX shell scripts (``scripts/backup.sh`` /
``scripts/restore.sh``) capture and reload the platform state; the load-bearing,
testable piece lives here: :mod:`.verify`, a READ-ONLY harness that proves a
*restored* database (and its content-addressed artifact store) is intact and
usable -- correct schema head, an uncorrupted score ledger, a scoreboard
projection derivable from that ledger, and artifact bytes matching their
content address. It is the recovery-drill: green means the restore satisfies
REQ-NFR-006/007 for real, not on paper.

The public names are re-exported lazily (PEP 562) so that
``python -m ctf_generator.application.backup.verify`` can execute the
submodule as ``__main__`` without this package eagerly importing it first.
"""

from __future__ import annotations

__all__ = [
    "CheckResult",
    "RestoreVerificationError",
    "VerificationReport",
    "verify_restore",
]


def __getattr__(name: str):
    if name in __all__:
        from . import verify

        return getattr(verify, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
