"""Cross-cutting observability infrastructure (M16).

Structured JSON logging with fail-safe secret redaction (REQ-PLAT-009 /
REQ-INV-011). Pure stdlib; importable without the ``[db]``/``[api]`` extras and
with no dependency on the domain, application, or interface layers, so any
process entry point (API / worker / CLI) can install it.
"""

from __future__ import annotations

from .logging import (
    JsonFormatter,
    SecretRedactionFilter,
    TextFormatter,
    configure_logging,
    make_handler,
)
from .secrets import LOG_SECRET_PATTERNS, redact_text

__all__ = [
    "JsonFormatter",
    "LOG_SECRET_PATTERNS",
    "SecretRedactionFilter",
    "TextFormatter",
    "configure_logging",
    "make_handler",
    "redact_text",
]
