"""Structured JSON logging + a fail-safe secret-redaction filter (M16b).

One :func:`configure_logging` call at a PROCESS ENTRY POINT (the API factory, the
worker ``main``, the CLI ``main``) installs -- on the ``ctfgen`` and
``ctf_generator`` logger trees -- a handler whose formatter renders every record
as a single JSON line and whose filter redacts secrets BEFORE emission, so EVERY
logger in the codebase emits structured, redacted output (not just the two that
historically hand-rolled JSON). Realizes REQ-PLAT-009 (structured JSON logging +
redaction) and REQ-INV-011 (never log secrets).

Design guarantees:

* IDEMPOTENT -- calling it twice does not double-add handlers.
* IMPORT-SAFE -- importing this module configures nothing; only the function
  mutates global logging state, and only entry points call it.
* NEVER RAISES ON A RECORD -- the formatter and the filter each fully guard
  themselves; a redaction/format bug fails safe to a redacted line rather than
  dropping the record or crashing the logging call.
* NO NEW DEPENDENCY -- pure stdlib; importable without the ``[db]``/``[api]``
  extras.

The redaction filter redacts by TWO mechanisms (defence in depth):

1. FIELD NAME -- any structured ``extra`` whose KEY names a secret (``password``,
   ``token``, ``secret``, ``flag``, ``api_key``, ``authorization``, ``dsn``,
   ``database_url``, ``credential``, ``session``, ...) has its value replaced.
2. VALUE SHAPE -- the rendered message and any string extra is scanned for
   secret-shaped spans (flags, ``sk-ant-...`` keys, bearer tokens, Postgres DSNs
   carrying a password, PEM key blocks, worker ``ctfw1.`` credentials) via the
   shared :mod:`ctf_generator.observability.secrets` patterns.

The filter MUTATES the record (collapsing formatted args into a redacted
``msg``), so redaction holds for every downstream handler/formatter, not only
this one.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from collections.abc import Mapping
from datetime import UTC, datetime

from .secrets import LOG_SECRET_PATTERNS, redact_text

_MARK = "_ctfgen_observability"
_REDACTED = "[redacted]"

# The logger trees every ctfgen/ctf_generator logger lives under. Attaching to
# these two (rather than the root) keeps our handler off third-party/root loggers
# and off pytest/unittest's own capture, while still covering every module logger
# (ctfgen.api.*, ctf_generator.worker, ctfgen.cli, ...).
_ROOT_LOGGERS = ("ctfgen", "ctf_generator")

# Attributes the stdlib sets on every LogRecord. Anything ELSE on a record's
# __dict__ is a caller-supplied structured ``extra`` we surface (and redact).
_STANDARD_LOGRECORD_ATTRS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime", "request_id",
    }
)

# Substrings that mark a structured-extra KEY as never-loggable (field-name
# redaction). Substring (not exact) match so ``client_secret`` / ``worker_token``
# / ``database_url`` are all caught; over-redaction of an incidentally-named
# field is the safe direction.
_SENSITIVE_KEY_SUBSTRINGS = (
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
    "authorization", "credential", "session", "dsn", "database_url", "db_url",
    "flag", "private_key", "signing_key", "provider_key", "bearer", "cookie",
)


def _is_sensitive_key(key: str) -> bool:
    """True iff a field name names a secret (substring match, case-insensitive)."""
    lower = key.lower()
    return any(tok in lower for tok in _SENSITIVE_KEY_SUBSTRINGS)


def _request_id(record: logging.LogRecord) -> str:
    """The correlation id for a record: an explicit ``request_id`` extra wins,
    else the current request context, else ``"-"``. Import is deferred so this
    module never imports the API layer at module load."""
    explicit = getattr(record, "request_id", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    try:
        from ctf_generator.interfaces.api.context import current_request_id

        return current_request_id()
    except Exception:  # pragma: no cover - API layer absent (worker/CLI without [api])
        return "-"


class SecretRedactionFilter(logging.Filter):
    """Redact secrets on a record before it is emitted. ALWAYS returns True (never
    drops a line); ANY internal error fails safe to a fully redacted message."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - logging API
        try:
            self._redact(record)
        except Exception:  # pragma: no cover - redaction must never lose the line
            with contextlib.suppress(Exception):
                record.msg = "[redacted: log record suppressed by redaction guard]"
                record.args = ()
        return True

    @classmethod
    def _redact(cls, record: logging.LogRecord) -> None:
        # 1. Structured extras: field-name redaction (top-level AND nested keys),
        #    then value-shape redaction of every string, recursively.
        for key, value in list(record.__dict__.items()):
            if key in _STANDARD_LOGRECORD_ATTRS or key.startswith("_"):
                continue
            if _is_sensitive_key(key):
                record.__dict__[key] = _REDACTED
            else:
                record.__dict__[key] = cls._redact_value(value)
        # 2. Message: render (%-args applied) then value-redact, and collapse the
        #    args in so the redaction holds for EVERY downstream formatter.
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(getattr(record, "msg", ""))
        record.msg = redact_text(rendered, LOG_SECRET_PATTERNS)
        record.args = ()
        # 3. Exception + stack text: an exception's args (an SDK error repr, a
        #    connection error carrying a DSN) are a secret vector too. Render the
        #    traceback ONCE, redact it, cache it on the record, and clear exc_info
        #    so no downstream formatter can re-render the raw (unredacted) trace.
        if record.exc_info:
            try:
                rendered_exc = logging.Formatter().formatException(record.exc_info)
            except Exception:
                rendered_exc = "[redacted: exception]"
            record.exc_text = redact_text(rendered_exc, LOG_SECRET_PATTERNS)
            record.exc_info = None
        if getattr(record, "exc_text", None):
            record.exc_text = redact_text(record.exc_text, LOG_SECRET_PATTERNS)
        if getattr(record, "stack_info", None):
            record.stack_info = redact_text(record.stack_info, LOG_SECRET_PATTERNS)

    @classmethod
    def _redact_value(cls, value: object, depth: int = 0) -> object:
        """Redact a structured-extra value: strings by value-shape, dicts/lists
        recursively (nested sensitive KEYS redacted too), scalars untouched, any
        other object by its redacted repr. Depth-bounded (cycles / deep nesting
        fail safe to a redacted marker)."""
        if depth > 6:
            return _REDACTED
        if isinstance(value, str):
            return redact_text(value)
        if value is None or isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, Mapping):
            out: dict[object, object] = {}
            for k, v in value.items():
                out[k] = _REDACTED if _is_sensitive_key(str(k)) else cls._redact_value(
                    v, depth + 1
                )
            return out
        if isinstance(value, (list, tuple, set)):
            return [cls._redact_value(v, depth + 1) for v in value]
        # A container/object extra could carry a secret in its repr; the formatter
        # would str() it, so redact its string form now.
        return redact_text(repr(value))


class JsonFormatter(logging.Formatter):
    """Render a record as a single JSON line: timestamp (ISO8601 UTC), level,
    logger, message, request_id, plus any structured ``extra`` fields. Never
    raises -- a serialization error falls back to a minimal safe line."""

    def format(self, record: logging.LogRecord) -> str:
        try:
            payload: dict[str, object] = {
                "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "request_id": _request_id(record),
            }
            for key, value in record.__dict__.items():
                if key in _STANDARD_LOGRECORD_ATTRS or key.startswith("_"):
                    continue
                payload[key] = value
            # exc_text is pre-rendered + redacted by SecretRedactionFilter (which
            # clears exc_info). Fall back to a guarded render only if this
            # formatter is used WITHOUT the filter.
            exc_text = getattr(record, "exc_text", None)
            if not exc_text and record.exc_info:
                exc_text = redact_text(
                    self.formatException(record.exc_info), LOG_SECRET_PATTERNS
                )
            if exc_text:
                payload["exc"] = exc_text
            if getattr(record, "stack_info", None):
                payload["stack"] = record.stack_info
            return json.dumps(payload, default=str, sort_keys=True)
        except Exception:  # pragma: no cover - formatting must never crash a log call
            safe = redact_text(str(getattr(record, "msg", "")))
            return json.dumps(
                {"level": "ERROR", "logger": record.name, "message": safe}
            )


class TextFormatter(logging.Formatter):
    """Human-readable dev format carrying the request id. Redaction still runs (the
    filter mutated the record) so this mode is equally secret-free."""

    _FMT = "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"

    def __init__(self) -> None:
        super().__init__(self._FMT)

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "request_id"):
            record.request_id = _request_id(record)
        return super().format(record)


def _json_mode_from_env() -> bool:
    """Default JSON; ``CTFGEN_LOG_FORMAT=text`` opts into the dev text format."""
    return os.environ.get("CTFGEN_LOG_FORMAT", "json").strip().lower() != "text"


def _level_from_env() -> int:
    name = os.environ.get("CTFGEN_LOG_LEVEL", "INFO").strip().upper()
    return getattr(logging, name, logging.INFO)


def make_handler(
    *, stream=None, json_mode: bool = True, level: int = logging.INFO
) -> logging.Handler:
    """Build the observability handler: a stream handler carrying the redaction
    filter and the chosen formatter. Exposed so a test can build the IDENTICAL
    real handler over an in-memory stream (the REQ-INV-011 instrumented sink)."""
    handler = logging.StreamHandler(stream)
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter() if json_mode else TextFormatter())
    handler.addFilter(SecretRedactionFilter())
    setattr(handler, _MARK, True)
    return handler


def configure_logging(
    *,
    json: bool | None = None,
    level: int | None = None,
    stream=None,
    force: bool = False,
) -> logging.Handler:
    """Install structured, redacted logging on the ctfgen/ctf_generator trees.

    Called ONCE per process at an entry point (API factory / worker / CLI).
    Idempotent: a second call leaves the existing handler in place (and only
    refreshes the level) unless ``force`` is set. ``json``/``level`` default from
    the environment (``CTFGEN_LOG_FORMAT`` / ``CTFGEN_LOG_LEVEL``). Returns the
    installed handler.
    """
    json_mode = _json_mode_from_env() if json is None else json
    lvl = _level_from_env() if level is None else level
    handler = make_handler(stream=stream, json_mode=json_mode, level=lvl)
    for name in _ROOT_LOGGERS:
        logger = logging.getLogger(name)
        existing = [h for h in logger.handlers if getattr(h, _MARK, False)]
        if existing and not force:
            logger.setLevel(lvl)
            continue
        for old in existing:
            logger.removeHandler(old)
        logger.addHandler(handler)
        logger.setLevel(lvl)
        # Do NOT propagate to root: the handler here is the sole sink for the tree,
        # so a root basicConfig/lastResort handler cannot double-emit the line.
        logger.propagate = False
    return handler
