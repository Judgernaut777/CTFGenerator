"""REQ-INV-011 realized: the structured-logging redaction filter proves NO secret
class reaches an emitted log line (M16b).

This is REQ-INV-011's OWN test: it plants every named secret class through the
REAL logging path (the exact handler ``configure_logging`` installs, over an
in-memory stream) and asserts each is absent from the emitted output while the
record is still emitted (redacted, not dropped). Field-name AND value-pattern
redaction are both proven, the formatter is asserted to emit valid JSON carrying
a ``request_id``, and the filter is proven never to raise on a pathological
record (bytes msg, non-str/None/container extras).

Pure stdlib -- runs on the host gate (no [db]/[api]).
"""

from __future__ import annotations

import io
import json
import logging
import unittest

from ctf_generator.observability import make_handler
from ctf_generator.observability.logging import (
    SecretRedactionFilter,
    configure_logging,
)
from ctf_generator.observability.secrets import redact_text

# One representative planted value per secret class. Each is a DISTINCTIVE token
# so an absence assertion cannot be satisfied by coincidence.
_FLAG_BRACE = "ctf{unique_flag_marker_7f3a}"
_FLAG_MULTIWORD = "FLAG{a multi word secret phrase}"
_SK_ANT = "sk-ant-UNIQUEKEYMARKER123456"  # noqa: S105
_SK_GENERIC = "sk-UNIQUEgenerickey0123456789"  # noqa: S105
_BEARER_TOKEN = "ctfw1.workerid.UNIQUEworkersecret999"  # noqa: S105
_PASSWORD = "UNIQUEpassw0rd_val"  # noqa: S105
_TOKEN = "UNIQUEsession_tok_val"  # noqa: S105
_API_KEY = "sk-ant-UNIQUEextrakey7777"  # noqa: S105
_AUTHZ = "UNIQUEauthzheaderval"  # noqa: S105
_DSN_PW = "UNIQUEdbpw"  # noqa: S105
_DSN = f"postgresql+psycopg://ctfuser:{_DSN_PW}@db-host:5432/ctf"

_ALL_SECRETS = (
    "unique_flag_marker_7f3a",
    "a multi word secret phrase",
    _SK_ANT,
    _SK_GENERIC,
    "UNIQUEworkersecret999",
    _PASSWORD,
    _TOKEN,
    _API_KEY,
    _AUTHZ,
    _DSN_PW,
)


def _sink_logger(stream: io.StringIO, name: str) -> logging.Logger:
    """A logger wired with the REAL observability handler over ``stream``."""
    handler = make_handler(stream=stream, json_mode=True, level=logging.DEBUG)
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger


class SecretAbsenceTests(unittest.TestCase):
    def test_no_secret_class_reaches_the_emitted_output(self) -> None:
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.absence")

        # (a) value-shape secrets in the MESSAGE (incl. %-args).
        log.info("discovered flag %s here", _FLAG_BRACE)
        log.warning("multiword flag in text: %s", _FLAG_MULTIWORD)
        log.error("provider key leaked %s and %s", _SK_ANT, _SK_GENERIC)
        log.info("worker bearer %s", _BEARER_TOKEN)
        log.error("db error connecting to %s", _DSN)
        # (b) FIELD-NAME secrets in structured extras.
        log.info(
            "structured",
            extra={
                "password": _PASSWORD,
                "token": _TOKEN,
                "api_key": _API_KEY,
                "authorization": _AUTHZ,
                "dsn": _DSN,
                "credential": _BEARER_TOKEN,
            },
        )
        # (c) value-shape secret in a non-sensitively-named extra + nested.
        log.info(
            "nested",
            extra={"detail": f"trace {_SK_ANT}", "ctx": {"session": _TOKEN}},
        )

        out = buf.getvalue()
        # POSITIVE CONTROL: the lines were emitted (not dropped).
        self.assertEqual(len(out.strip().splitlines()), 7)
        # Every secret class is absent from the emitted output.
        for secret in _ALL_SECRETS:
            self.assertNotIn(secret, out, f"secret leaked: {secret!r}")
        # The redaction marker IS present (proving redaction, not loss).
        self.assertIn("[redacted]", out)

    def test_exception_traceback_is_redacted(self) -> None:
        # An exception whose message embeds a flag + provider key -- the traceback
        # is a secret vector that record.msg redaction alone would miss.
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.exc")
        try:
            raise RuntimeError(f"sdk error {_SK_ANT} for flag {_FLAG_BRACE}")
        except RuntimeError:
            log.exception("agent eval failed")
        out = buf.getvalue()
        self.assertIn('"exc"', out)  # the traceback WAS emitted
        self.assertNotIn(_SK_ANT, out)
        self.assertNotIn("unique_flag_marker_7f3a", out)
        self.assertIn("[redacted]", out)
        json.loads(out.strip())  # still one valid JSON line

    def test_field_name_and_value_pattern_both_prove_redaction(self) -> None:
        # value-pattern: a secret-SHAPED value under a NON-sensitive key name.
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.valpat")
        log.info("x", extra={"note": f"see {_SK_ANT}"})
        line = json.loads(buf.getvalue().strip())
        self.assertNotIn(_SK_ANT, buf.getvalue())
        self.assertEqual(line["note"], "see [redacted]")

        # field-name: a NON-secret-shaped value under a sensitive key name.
        buf2 = io.StringIO()
        log2 = _sink_logger(buf2, "ctfgen.test.fieldname")
        log2.info("y", extra={"admin_password": "plainish"})
        line2 = json.loads(buf2.getvalue().strip())
        self.assertEqual(line2["admin_password"], "[redacted]")


class ShapelessAndWorkerPathTests(unittest.TestCase):
    def test_shapeless_secrets_in_message_text_are_redacted(self) -> None:
        # Session tokens / passwords / signing keys / the scoreboard token /
        # client_secret have NO distinctive value shape -- a value in a MESSAGE (or
        # %-arg, or traceback) escapes field-name redaction. The contextual
        # key=value / key: value pattern must catch the common careless-log form.
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.shapeless")
        planted = {
            "sess": ("rotated session token=%s done", "SESSt0kBlobUNIQUE12345"),
            "pw": ("login failed password=%s", "PlaintextPwUNIQUE!9"),
            "sign": ("using signing_key: %s now", "SigningKeyBlobUNIQUE777"),
            "sb": ("public scoreboard_token=%s", "SbTokBlobUNIQUE55"),
            "cs": ("oidc client_secret=%s", "ClientSecretUNIQUE33"),
            # sk-proj-/sk-svcacct- provider keys (hyphen-prefixed).
            "proj": ("openai key %s expired", "sk-proj-UNIQUEproj12345_abcDEF"),
        }
        for msg, secret in planted.values():
            log.info(msg, secret)
        out = buf.getvalue()
        for _msg, secret in planted.values():
            self.assertNotIn(secret, out, f"shapeless secret leaked: {secret!r}")

    def test_secret_redacted_on_the_real_worker_logger(self) -> None:
        # The redaction must hold on the WORKER logger, not only synthetic test
        # loggers -- a regression in the worker's configure_logging wiring would
        # otherwise leak a flag / provider key / worker credential in production.
        buf = io.StringIO()
        log = _sink_logger(buf, "ctf_generator.worker")
        log.warning("agent eval failed for %s with %s", _FLAG_BRACE, _SK_ANT)
        try:
            raise RuntimeError("provider error sk-proj-UNIQUEproj999_zz key")
        except RuntimeError:
            log.warning("dispatch error", exc_info=True)
        out = buf.getvalue()
        self.assertNotIn("unique_flag_marker_7f3a", out)
        self.assertNotIn(_SK_ANT, out)
        self.assertNotIn("sk-proj-UNIQUEproj999", out)


class FormatterShapeTests(unittest.TestCase):
    def test_emits_valid_json_with_request_id_and_core_fields(self) -> None:
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.shape")
        log.info("hello")
        record = json.loads(buf.getvalue().strip())
        for key in ("timestamp", "level", "logger", "message", "request_id"):
            self.assertIn(key, record)
        self.assertEqual(record["message"], "hello")
        self.assertEqual(record["logger"], "ctfgen.test.shape")
        self.assertEqual(record["level"], "INFO")
        self.assertEqual(record["request_id"], "-")  # no active request context

    def test_explicit_request_id_extra_is_surfaced(self) -> None:
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.reqid")
        log.info("with id", extra={"request_id": "req_fixed_123"})
        record = json.loads(buf.getvalue().strip())
        self.assertEqual(record["request_id"], "req_fixed_123")


class NeverRaisesTests(unittest.TestCase):
    def test_filter_never_raises_on_pathological_records(self) -> None:
        buf = io.StringIO()
        log = _sink_logger(buf, "ctfgen.test.weird")
        # bytes message, None / non-str / container extras, a bad-__str__ object.
        class _Bad:
            def __str__(self) -> str:  # noqa: D401
                raise RuntimeError("boom")

        log.info(b"bytes message ctf{leak_in_bytes}")
        log.info("none extra", extra={"val": None, "n": 5, "flag_count": 3})
        log.info("obj extra", extra={"weird": _Bad()})
        log.info("list extra", extra={"items": [f"a {_SK_ANT}", 1, None]})
        out = buf.getvalue()
        # No crash: all four lines emitted and JSON-parseable.
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines:
            json.loads(line)
        # Secrets in the pathological records are still absent.
        self.assertNotIn("leak_in_bytes", out)
        self.assertNotIn(_SK_ANT, out)

    def test_filter_direct_never_raises(self) -> None:
        f = SecretRedactionFilter()
        rec = logging.LogRecord(
            "n", logging.INFO, __file__, 1, "msg %s %d", ("only-one-arg",), None
        )
        # Mismatched args would raise in getMessage(); the filter must not propagate.
        self.assertTrue(f.filter(rec))


class ConfigureLoggingTests(unittest.TestCase):
    def test_idempotent_does_not_double_add_handlers(self) -> None:
        configure_logging(json=True, level=logging.INFO, force=True)
        n1 = len(logging.getLogger("ctfgen").handlers)
        configure_logging(json=True, level=logging.INFO)
        n2 = len(logging.getLogger("ctfgen").handlers)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 1)
        # Installed on both package trees.
        self.assertEqual(len(logging.getLogger("ctf_generator").handlers), 1)

    def test_redact_text_helper_is_fail_safe_on_non_str(self) -> None:
        self.assertEqual(redact_text(12345), "12345")
        self.assertNotIn(_SK_ANT, redact_text(f"x {_SK_ANT}"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
