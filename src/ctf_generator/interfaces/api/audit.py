"""Audit hook for privileged mutations.

Emits one structured JSON audit record per privileged write --
``actor`` / ``action`` / ``target`` / ``outcome`` / ``request_id`` -- to a
dedicated ``ctfgen.api.audit`` logger. It records WHO did WHAT to WHICH resource
and whether it succeeded; it NEVER records request bodies, flags, tokens,
session keys, or any other secret. The sink is pluggable (a durable audit table
lands with real deployment); slice a logs.
"""

from __future__ import annotations

import json
import logging
from typing import Protocol

from .context import current_request_id

_audit_logger = logging.getLogger("ctfgen.api.audit")


class AuditSink(Protocol):
    def record(self, event: dict[str, str]) -> None: ...


class LoggingAuditSink:
    """Writes each audit record as a single JSON line at INFO."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or _audit_logger

    def record(self, event: dict[str, str]) -> None:
        self._logger.info("audit %s", json.dumps(event, sort_keys=True))


def audit(
    sink: AuditSink,
    *,
    actor: str,
    action: str,
    target: str,
    outcome: str,
) -> None:
    """Emit a privileged-mutation audit record. ``actor`` is the principal
    subject, ``action`` a stable verb (e.g. ``competition.create``), ``target``
    the business id of the affected resource, ``outcome`` ``"success"`` /
    ``"denied"`` / ``"error"``. No secrets are ever passed here."""
    sink.record(
        {
            "actor": actor,
            "action": action,
            "target": target,
            "outcome": outcome,
            "request_id": current_request_id(),
        }
    )
