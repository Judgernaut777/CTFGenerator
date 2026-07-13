"""Shared secret-shaped-value patterns + a fail-safe text redactor (M16b).

This is the SINGLE source of truth for "what a secret looks like in free text",
reused by the structured-logging redaction filter (:mod:`.logging`) so a secret
can never reach a log line (REQ-INV-011). It is pure stdlib ``re`` -- importable
without the ``[db]``/``[api]`` extras and with NO dependency on the domain,
application, or interface layers -- so any process entry point (API / worker /
CLI) can install it.

Two mechanisms cooperate at the call sites:

* VALUE patterns (here) -- redact a token that is *shaped* like a secret no
  matter which field it appears in (a flag, an ``sk-ant-...`` key, a bearer
  token, a Postgres DSN carrying a password, a PEM private-key block, a worker
  ``ctfw1.`` credential).
* FIELD-NAME redaction (in :mod:`.logging`) -- redact any structured ``extra``
  whose KEY names a secret, even when its value is not self-evidently one.

The M15 evaluation sanitizer (``application/evaluation/service.py``) and the
worker transcript redactor keep their OWN local copies of the flag/key/bearer
subset by deliberate design: those layers must stay self-contained and their
exact behavior is pinned by M15 tests. The subset here is byte-identical to
theirs (:data:`EVAL_SECRET_PATTERNS`) and is a SUPERSET (it adds DSN / PEM /
worker-credential coverage that only matters for logs).
"""

from __future__ import annotations

import re

_REDACTED = "[redacted]"

# --- the M15 eval/worker subset, kept byte-identical -------------------------
# (1) challenge FLAGS -- ctf{...}/FLAG{...}/key{...}, INCLUDING spaces/newlines
#     inside the braces (`[^}]`, so a multi-word flag is caught).
_FLAG_LIKE = re.compile(r"(?i)(?:ctf|flag|key|secret|pass|pwd)\{[^}]{0,400}\}")
# (2) provider API keys / bearer tokens / Authorization headers.
_SK_ANT = re.compile(r"sk-ant-[A-Za-z0-9\-_]{8,}")
_SK_GENERIC = re.compile(r"sk-[A-Za-z0-9]{16,}")
# Hyphen-PREFIXED provider keys: OpenAI project/service-account keys
# (sk-proj-... / sk-svcacct-...) and any sk-<prefix>-<blob> shape -- the hyphen
# after the short prefix breaks the "16+ consecutive alnum" run of _SK_GENERIC,
# so those keys escaped it.
_SK_PREFIXED = re.compile(r"sk-[A-Za-z0-9]{1,20}-[A-Za-z0-9\-_]{12,}")
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{8,}=*")
_AUTHZ = re.compile(r"(?i)authorization[:=]\s*\S+")

#: The pattern tuple used by the M15 eval sanitizer + worker redactor -- imported
#: by both so there is ONE definition. _SK_PREFIXED was added (M16b) to catch
#: sk-proj-/sk-svcacct- keys; it only ever redacts MORE, so the M15 secret-ABSENCE
#: tests are unaffected.
EVAL_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    _FLAG_LIKE,
    _SK_ANT,
    _SK_PREFIXED,
    _SK_GENERIC,
    _BEARER,
    _AUTHZ,
)

# --- logging-only additions --------------------------------------------------
# A DB connection string with an embedded password. A logged SQLAlchemy URL or a
# raw psycopg connection error can carry the DB password, so redact the WHOLE
# DSN (userinfo + host + db). Covers postgres:// / postgresql:// /
# postgresql+psycopg:// etc.
_DSN = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s/@]+@\S+")
# A worker scoped bearer credential (``ctfw1.<id>.<secret>``).
_WORKER_CRED = re.compile(r"\bctfw1\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
# A PEM private-key block (full block first, then a lone header as a fallback so
# a truncated log line still redacts).
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_PEM_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]*KEY-----")
# Contextual key=value / key: value -- redact the VALUE after a secret-NAMED key
# appearing in free TEXT (a log message, a %s arg, an exception traceback). This
# is the only value-shape defence for SHAPELESS secrets -- session tokens, signing
# keys, the public scoreboard token, admin passwords -- which are high-entropy
# blobs / free-form strings with no distinctive shape of their own. It catches the
# common careless-log form ("password=Hunter2", "session: <token>"). RESIDUAL
# LIMITATION (documented): a BARE shapeless secret in free prose with NO key
# context and NO distinctive shape cannot be regexed without unacceptable false
# positives -- for those the guarantees are (a) field-name redaction of structured
# extras (in .logging) and (b) the never-log discipline (the app never logs a raw
# session token / password; they are stored sha256-hashed).
_KV_SECRET = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|session[_-]?token|session|"
    r"api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"signing[_-]?key|scoreboard[_-]?token|public[_-]?token|credential|"
    r"client[_-]?secret|private[_-]?key)"
    r"\b\s*[=:]\s*[^\s,;)\]}\"']+"
)

#: The full pattern set the log redaction filter applies. Order matters only for
#: the PEM pair (block before the lone-header fallback); each pattern otherwise
#: substitutes independently.
LOG_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    _PEM_BLOCK,
    _PEM_HEADER,
    _DSN,
    _WORKER_CRED,
    _KV_SECRET,
    _FLAG_LIKE,
    _SK_ANT,
    _SK_PREFIXED,
    _SK_GENERIC,
    _AUTHZ,
    _BEARER,
)


def redact_text(
    text: str, patterns: tuple[re.Pattern[str], ...] = LOG_SECRET_PATTERNS
) -> str:
    """Return ``text`` with every secret-shaped span replaced by ``[redacted]``.

    Never raises: a non-``str`` input is coerced with ``str()`` and a pattern
    that somehow errors is skipped rather than propagated, so a redaction bug can
    never lose a log line (the caller fails safe)."""
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:  # pragma: no cover - pathological __str__
            return _REDACTED
    for pattern in patterns:
        try:
            text = pattern.sub(_REDACTED, text)
        except Exception:  # pragma: no cover - a regex engine error must not lose the line
            return _REDACTED
    return text
