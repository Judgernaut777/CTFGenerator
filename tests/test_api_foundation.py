"""Unit tests for the M9 API foundation ([api] extra, no database required).

Covers the framework-agnostic building blocks and the error-envelope mapping
without touching Postgres: the ``ctfgen.error`` envelope shape, exception ->
status/code mapping, DTO validation, cursor pagination, ETag compute/compare,
idempotency replay/conflict, the ``require_permission`` allow/deny gate, and the
rate-limit 429. These SKIP cleanly when the ``[api]`` extra (FastAPI/Pydantic/
httpx and the SQLAlchemy-backed application layer it transitively imports) is not
installed, exactly like the ``[db]`` integration suites.
"""

from __future__ import annotations

import unittest

try:  # the [api] extra (and the [db] layer it imports) are optional
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from pydantic import BaseModel, ValidationError
    from sqlalchemy.exc import IntegrityError

    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.concurrency import compute_etag, etags_match
    from ctf_generator.interfaces.api.deps import (
        Permission,
        StubAuthenticator,
        principal_for,
        require_permission,
    )
    from ctf_generator.interfaces.api.envelopes import error_envelope
    from ctf_generator.interfaces.api.errors import register_exception_handlers
    from ctf_generator.interfaces.api.exceptions import (
        AuthenticationError,
        AuthorizationError,
        IdempotencyConflictError,
        PreconditionFailedError,
        PreconditionRequiredError,
        RateLimitedError,
        ValidationFailedError,
    )
    from ctf_generator.interfaces.api.idempotency import (
        InMemoryIdempotencyStore,
        StoredResponse,
        fingerprint,
        replay_or_conflict,
    )
    from ctf_generator.interfaces.api.middleware import (
        RequestIDMiddleware,
        TokenBucketLimiter,
    )
    from ctf_generator.interfaces.api.pagination import (
        CursorError,
        decode_cursor,
        encode_cursor,
        paginate,
    )
    from ctf_generator.interfaces.api.schemas.competitions import (
        CompetitionCreateRequest,
    )
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.schema import ERROR_SCHEMA

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - exercised only without the extra
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_SKIP = _IMPORT_ERROR is not None
_REASON = f"[api] extra not importable ({_IMPORT_ERROR})" if _SKIP else ""


@unittest.skipIf(_SKIP, _REASON)
class ErrorEnvelopeTests(unittest.TestCase):
    def test_envelope_shape_is_stamped_ctfgen_error(self) -> None:
        env = error_envelope(code="not_found", message="nope", request_id="req_1")
        self.assertEqual(env["schema"], ERROR_SCHEMA)
        self.assertIn("schema_version", env)
        self.assertEqual(env["error"]["code"], "not_found")
        self.assertEqual(env["error"]["message"], "nope")
        self.assertEqual(env["error"]["request_id"], "req_1")
        self.assertNotIn("details", env["error"])  # omitted when empty

    def test_envelope_details_included_when_present(self) -> None:
        env = error_envelope(
            code="validation_failed",
            message="bad",
            request_id="req_2",
            detail=[{"field": "end_time", "issue": "must be after start_time"}],
        )
        self.assertEqual(env["error"]["details"][0]["field"], "end_time")

    def test_api_error_subclasses_carry_expected_status_and_code(self) -> None:
        cases = [
            (AuthenticationError("x"), 401, "unauthorized"),
            (AuthorizationError("x"), 403, "forbidden"),
            (PreconditionFailedError("x"), 412, "precondition_failed"),
            (PreconditionRequiredError("x"), 428, "precondition_failed"),
            (ValidationFailedError("x"), 422, "validation_failed"),
            (IdempotencyConflictError("x"), 409, "idempotency_key_reused"),
        ]
        for exc, status, code in cases:
            self.assertEqual(exc.status_code, status)
            self.assertEqual(exc.code, code)

    def test_rate_limited_error_carries_retry_after(self) -> None:
        self.assertEqual(RateLimitedError("x", retry_after=7).retry_after, 7)


def _mapping_app() -> FastAPI:
    """A tiny app (no DB, no auth) that raises each mapped exception so the
    handler -> status/code/envelope mapping is exercised end to end."""
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
    register_exception_handlers(app)

    class Body(BaseModel):
        n: int

    @app.get("/lookup")
    def _lookup():
        raise LookupError("missing thing")

    @app.get("/value")
    def _value():
        raise ValueError("bad value")

    @app.get("/integrity")
    def _integrity():
        raise IntegrityError("stmt", {}, Exception("dup"))

    @app.get("/precondition")
    def _precondition():
        raise PreconditionFailedError("stale")

    @app.post("/validate")
    def _validate(body: Body):
        return {"ok": body.n}

    return app


@unittest.skipIf(_SKIP, _REASON)
class ExceptionMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(_mapping_app(), raise_server_exceptions=False)

    def test_lookup_error_maps_to_404(self) -> None:
        r = self.client.get("/lookup")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["error"]["code"], "not_found")
        self.assertEqual(r.json()["schema"], ERROR_SCHEMA)

    def test_value_error_maps_to_400(self) -> None:
        r = self.client.get("/value")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"]["code"], "invalid_request")

    def test_integrity_error_maps_to_409_without_leaking_driver_text(self) -> None:
        r = self.client.get("/integrity")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["error"]["code"], "conflict")
        self.assertNotIn("dup", r.json()["error"]["message"])

    def test_typed_precondition_maps_to_412(self) -> None:
        r = self.client.get("/precondition")
        self.assertEqual(r.status_code, 412)
        self.assertEqual(r.json()["error"]["code"], "precondition_failed")

    def test_request_validation_maps_to_422_envelope_with_details(self) -> None:
        r = self.client.post("/validate", json={"n": "not-an-int"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["error"]["code"], "validation_error")
        self.assertTrue(r.json()["error"]["details"])

    def test_every_error_response_carries_request_id_header(self) -> None:
        r = self.client.get("/lookup", headers={"X-Request-ID": "req_custom"})
        self.assertEqual(r.headers.get("X-Request-ID"), "req_custom")
        self.assertEqual(r.json()["error"]["request_id"], "req_custom")


@unittest.skipIf(_SKIP, _REASON)
class DtoValidationTests(unittest.TestCase):
    def test_valid_competition_request_builds_domain(self) -> None:
        req = CompetitionCreateRequest(
            competition_id="spring",
            name="Spring",
            start_time="2026-06-01T09:00:00Z",
            end_time="2026-06-03T09:00:00Z",
        )
        config = req.to_domain()
        self.assertEqual(config.competition_id, "spring")

    def test_end_before_start_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            CompetitionCreateRequest(
                competition_id="x",
                name="x",
                start_time="2026-06-03T09:00:00Z",
                end_time="2026-06-01T09:00:00Z",
            )

    def test_freeze_outside_window_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            CompetitionCreateRequest(
                competition_id="x",
                name="x",
                start_time="2026-06-01T09:00:00Z",
                end_time="2026-06-03T09:00:00Z",
                freeze_time="2026-07-01T09:00:00Z",
            )


@unittest.skipIf(_SKIP, _REASON)
class PaginationTests(unittest.TestCase):
    def test_cursor_round_trips(self) -> None:
        self.assertEqual(decode_cursor(encode_cursor("comp-b")), "comp-b")

    def test_invalid_cursor_raises(self) -> None:
        with self.assertRaises(CursorError):
            decode_cursor("!!!not-base64!!!")

    def test_paginate_walks_all_items_once(self) -> None:
        items = [f"c{i:02d}" for i in range(5)]
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            page = paginate(items, key=lambda x: x, limit=2, cursor=cursor)
            seen.extend(page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        self.assertEqual(seen, items)

    def test_next_cursor_none_on_final_page(self) -> None:
        page = paginate(["a", "b"], key=lambda x: x, limit=50, cursor=None)
        self.assertIsNone(page.next_cursor)


@unittest.skipIf(_SKIP, _REASON)
class ETagTests(unittest.TestCase):
    def test_same_payload_same_etag(self) -> None:
        a = compute_etag({"name": "x", "v": 1})
        b = compute_etag({"v": 1, "name": "x"})  # key order irrelevant
        self.assertEqual(a, b)

    def test_different_payload_different_etag(self) -> None:
        self.assertNotEqual(
            compute_etag({"name": "x"}), compute_etag({"name": "y"})
        )

    def test_if_match_comparison_tolerates_weak_prefix_and_quotes(self) -> None:
        etag = compute_etag({"name": "x"})
        self.assertTrue(etags_match(etag, etag))
        self.assertTrue(etags_match(f"W/{etag}", etag))
        self.assertTrue(etags_match("*", etag))
        self.assertFalse(etags_match('"stale"', etag))


@unittest.skipIf(_SKIP, _REASON)
class IdempotencyTests(unittest.TestCase):
    def test_replay_returns_stored_response_for_same_body(self) -> None:
        store = InMemoryIdempotencyStore()
        body = {"competition_id": "x"}
        fp = fingerprint(body)
        self.assertIsNone(replay_or_conflict(store, "s", "k1", fp))
        store.save("s", "k1", StoredResponse(fp, 201, {"ok": True}, '"e"'))
        replayed = replay_or_conflict(store, "s", "k1", fp)
        self.assertEqual(replayed.status_code, 201)
        self.assertEqual(replayed.etag, '"e"')

    def test_same_key_different_body_conflicts(self) -> None:
        store = InMemoryIdempotencyStore()
        store.save("s", "k1", StoredResponse(fingerprint({"a": 1}), 201, {}, None))
        with self.assertRaises(IdempotencyConflictError):
            replay_or_conflict(store, "s", "k1", fingerprint({"a": 2}))


@unittest.skipIf(_SKIP, _REASON)
class RequirePermissionTests(unittest.TestCase):
    def test_allows_principal_with_permission(self) -> None:
        dep = require_permission(Permission.COMPETITION_WRITE)
        admin = principal_for("a", {"admin"})
        self.assertIs(dep(principal=admin), admin)

    def test_denies_principal_without_permission(self) -> None:
        dep = require_permission(Permission.COMPETITION_WRITE)
        player = principal_for("p", {"player"})
        with self.assertRaises(AuthorizationError):
            dep(principal=player)

    def test_stub_authenticator_rejects_missing_and_unknown_tokens(self) -> None:
        auth = StubAuthenticator({"good": principal_for("a", {"admin"})})
        self.assertEqual(auth.authenticate("good").subject, "a")
        with self.assertRaises(AuthenticationError):
            auth.authenticate(None)
        with self.assertRaises(AuthenticationError):
            auth.authenticate("bogus")


@unittest.skipIf(_SKIP, _REASON)
class RateLimitTests(unittest.TestCase):
    def test_token_bucket_denies_after_burst(self) -> None:
        limiter = TokenBucketLimiter(rate=0.0001, burst=2)
        self.assertEqual(limiter.check("k")[0], True)
        self.assertEqual(limiter.check("k")[0], True)
        allowed, retry_after = limiter.check("k")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)

    def test_middleware_returns_429_envelope_with_retry_after(self) -> None:
        # The limiter short-circuits before routing/auth, so no DB is needed.
        auth = StubAuthenticator({"t": principal_for("a", {"admin"})})
        app = create_app(
            ApiSettings(),
            database=None,
            authenticator=auth,
            rate_limiter=TokenBucketLimiter(rate=0.0001, burst=1),
        )
        client = TestClient(app, raise_server_exceptions=False)
        first = client.get("/api/v1/competitions", headers={"Authorization": "Bearer t"})
        # first may pass the limiter (then 500 for no-DB) or be allowed; drain it.
        limited = client.get(
            "/api/v1/competitions", headers={"Authorization": "Bearer t"}
        )
        # At least one of the two exhausts the single-token bucket.
        statuses = {first.status_code, limited.status_code}
        self.assertIn(429, statuses)
        r = client.get("/api/v1/competitions", headers={"Authorization": "Bearer t"})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.json()["error"]["code"], "rate_limited")
        self.assertIn("Retry-After", r.headers)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
