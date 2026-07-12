"""PostgreSQL integration tests for the M9a review fixes ([api]+[db], real PG).

Covers the behaviours the slice-a review hardened, end to end against a fresh,
Alembic-migrated throwaway database (same isolation approach as
``test_api_competitions_integration``):

* cursor pagination through the API with no gaps/dupes, plus the FIX-2 regression
  (deleting the exact boundary item between pages must NOT skip the tail);
* ETag lost-update: a second PATCH with a now-stale base ETag -> 412;
* the audit hook fires with exactly ``actor/action/target/outcome/request_id`` and
  no body/secret on a privileged mutation;
* the ``ctfgen.error`` envelope is stamped (schema/schema_version/request_id) on a
  negative path beyond 404 (a 403);
* idempotency scope is principal-scoped: the same ``Idempotency-Key`` under two
  DIFFERENT principals does not collide, while the same principal reusing it with a
  different body -> 409 idempotency_key_reused.

SKIPS cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:  # heavy deps optional; guard so import never fails the host suite
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.models import Competition
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.audit import AuditSink
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.schema import ERROR_SCHEMA

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_ADMIN = "admintoken"  # noqa: S105 - test fixture token, not a real secret
_ADMIN2 = "admintoken2"  # noqa: S105 - test fixture token, not a real secret
_PLAYER = "playertoken"  # noqa: S105 - test fixture token, not a real secret


if _ENABLED:

    class _CapturingAuditSink:
        """Records audit events in memory so a test can assert their shape."""

        def __init__(self) -> None:
            self.events: list[dict[str, str]] = []

        def record(self, event: dict[str, str]) -> None:
            self.events.append(dict(event))

    _: AuditSink = _CapturingAuditSink()  # structural conformance check


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_rev_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


def _authenticator() -> StubAuthenticator:
    return StubAuthenticator(
        {
            _ADMIN: principal_for("admin-one", {"admin"}),
            _ADMIN2: principal_for("admin-two", {"admin"}),
            _PLAYER: principal_for("player-user", {"player"}),
        }
    )


@contextmanager
def _client(*, audit_sink=None):
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(),
                database=db,
                authenticator=_authenticator(),
                audit_sink=audit_sink,
            )
            yield TestClient(app), db
        finally:
            db.dispose()


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _competition_body(cid: str) -> dict:
    return {
        "competition_id": cid,
        "name": f"Comp {cid}",
        "start_time": "2026-06-01T09:00:00Z",
        "end_time": "2026-06-03T09:00:00Z",
    }


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CursorPaginationApiTests(unittest.TestCase):
    def _seed(self, client, n: int) -> list[str]:
        ids = [f"comp-{i:02d}" for i in range(n)]
        for cid in ids:
            r = client.post(
                "/api/v1/competitions", headers=_auth(), json=_competition_body(cid)
            )
            self.assertEqual(r.status_code, 201, r.text)
        return ids

    def test_walk_all_pages_no_gaps_or_dupes(self) -> None:
        with _client() as (client, _db):
            ids = self._seed(client, 7)
            seen: list[str] = []
            url = "/api/v1/competitions?limit=2"
            for _ in range(20):
                r = client.get(url, headers=_auth())
                self.assertEqual(r.status_code, 200, r.text)
                body = r.json()
                seen.extend(c["competition_id"] for c in body["data"])
                cursor = body["page"]["next_cursor"]
                if cursor is None:
                    break
                url = f"/api/v1/competitions?limit=2&cursor={cursor}"
            self.assertEqual(sorted(seen), ids)
            self.assertEqual(len(seen), len(set(seen)))  # no dupes

    def test_boundary_item_deletion_does_not_skip_tail(self) -> None:
        with _client() as (client, db):
            ids = self._seed(client, 5)  # comp-00..comp-04
            r = client.get("/api/v1/competitions?limit=2", headers=_auth())
            self.assertEqual(r.status_code, 200)
            page1 = r.json()
            first_ids = [c["competition_id"] for c in page1["data"]]
            self.assertEqual(first_ids, ["comp-00", "comp-01"])
            boundary = first_ids[-1]  # comp-01, encoded in the cursor
            cursor = page1["page"]["next_cursor"]
            self.assertIsNotNone(cursor)

            # Delete the exact boundary item BEFORE fetching page 2 (concurrent
            # deletion). Resuming strictly-after the cursor must still return the
            # tail rather than skipping it.
            with db.session_scope() as session:
                session.execute(
                    sa.delete(Competition).where(Competition.slug == boundary)
                )

            tail_seen: list[str] = []
            url = f"/api/v1/competitions?limit=2&cursor={cursor}"
            for _ in range(20):
                r = client.get(url, headers=_auth())
                self.assertEqual(r.status_code, 200, r.text)
                body = r.json()
                tail_seen.extend(c["competition_id"] for c in body["data"])
                nxt = body["page"]["next_cursor"]
                if nxt is None:
                    break
                url = f"/api/v1/competitions?limit=2&cursor={nxt}"

            # The tail (comp-02..comp-04) survived the boundary deletion: resuming
            # strictly-after the deleted boundary did NOT skip it. (The old
            # exact-match resume would have returned an empty tail here.)
            self.assertEqual(tail_seen, ["comp-02", "comp-03", "comp-04"])
            self.assertNotIn(boundary, tail_seen)
            # The page-1 items plus the tail cover every non-deleted competition.
            self.assertEqual(
                sorted(set(first_ids) | set(tail_seen)), ids
            )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class EtagLostUpdateApiTests(unittest.TestCase):
    def test_stale_if_match_second_update_is_412(self) -> None:
        with _client() as (client, _db):
            r = client.post(
                "/api/v1/competitions", headers=_auth(),
                json=_competition_body("etag-comp"),
            )
            self.assertEqual(r.status_code, 201, r.text)
            base_etag = r.headers["ETag"]

            ok = client.patch(
                "/api/v1/competitions/etag-comp",
                headers={**_auth(), "If-Match": base_etag},
                json={"name": "first writer wins"},
            )
            self.assertEqual(ok.status_code, 200, ok.text)
            self.assertNotEqual(ok.headers["ETag"], base_etag)

            # A second writer holding the SAME (now stale) base ETag is rejected.
            stale = client.patch(
                "/api/v1/competitions/etag-comp",
                headers={**_auth(), "If-Match": base_etag},
                json={"name": "second writer loses"},
            )
            self.assertEqual(stale.status_code, 412, stale.text)
            self.assertEqual(stale.json()["error"]["code"], "precondition_failed")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WindowInvariantApiTests(unittest.TestCase):
    """The competition timing-window invariant is enforced in the service (not
    the router), so it holds on the PATCH path too and maps to 422."""

    def test_patch_violating_window_is_422_validation_failed(self) -> None:
        with _client() as (client, _db):
            r = client.post(
                "/api/v1/competitions", headers=_auth(),
                json=_competition_body("win-comp"),
            )
            self.assertEqual(r.status_code, 201, r.text)
            etag = r.headers["ETag"]
            # Move end_time before start_time via PATCH -> service rejects it.
            r2 = client.patch(
                "/api/v1/competitions/win-comp",
                headers={**_auth(), "If-Match": etag},
                json={"end_time": "2026-05-01T09:00:00Z"},
            )
            self.assertEqual(r2.status_code, 422, r2.text)
            self.assertEqual(r2.json()["error"]["code"], "validation_failed")
            self.assertTrue(r2.json()["error"]["details"])


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuditAndEnvelopeApiTests(unittest.TestCase):
    def test_audit_hook_fires_with_expected_fields_and_no_secrets(self) -> None:
        sink = _CapturingAuditSink()
        with _client(audit_sink=sink) as (client, _db):
            r = client.post(
                "/api/v1/competitions",
                headers={**_auth(), "X-Request-ID": "req_audit"},
                json=_competition_body("audited"),
            )
            self.assertEqual(r.status_code, 201, r.text)

        self.assertEqual(len(sink.events), 1)
        event = sink.events[0]
        self.assertEqual(
            set(event), {"actor", "action", "target", "outcome", "request_id"}
        )
        self.assertEqual(event["actor"], "admin-one")
        self.assertEqual(event["action"], "competition.create")
        self.assertEqual(event["target"], "audited")
        self.assertEqual(event["outcome"], "success")
        self.assertEqual(event["request_id"], "req_audit")
        # No request body / secret leaks into the audit record.
        for forbidden in ("name", "start_time", "spec", "token", "body"):
            self.assertNotIn(forbidden, event)

    def test_forbidden_path_is_stamped_error_envelope(self) -> None:
        with _client() as (client, _db):
            r = client.post(
                "/api/v1/competitions",
                headers=_auth(_PLAYER),
                json=_competition_body("denied"),
            )
            self.assertEqual(r.status_code, 403)
            body = r.json()
            self.assertEqual(body["schema"], ERROR_SCHEMA)
            self.assertIn("schema_version", body)
            self.assertEqual(body["error"]["code"], "forbidden")
            self.assertIn("request_id", body["error"])
            self.assertTrue(body["error"]["request_id"])


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class IdempotencyScopingApiTests(unittest.TestCase):
    def test_same_key_different_principals_do_not_collide(self) -> None:
        with _client() as (client, _db):
            key = {"Idempotency-Key": "shared-key"}
            # Principal one creates comp "alpha".
            r1 = client.post(
                "/api/v1/competitions",
                headers={**_auth(_ADMIN), **key},
                json=_competition_body("alpha"),
            )
            self.assertEqual(r1.status_code, 201, r1.text)
            # Principal two reuses the SAME key with a DIFFERENT body: with the
            # principal-scoped idempotency key this is its own create (not a
            # cross-principal replay/conflict).
            r2 = client.post(
                "/api/v1/competitions",
                headers={**_auth(_ADMIN2), **key},
                json=_competition_body("beta"),
            )
            self.assertEqual(r2.status_code, 201, r2.text)
            self.assertEqual(r2.json()["competition_id"], "beta")

    def test_same_principal_key_different_body_conflicts(self) -> None:
        with _client() as (client, _db):
            key = {"Idempotency-Key": "reuse-key"}
            r1 = client.post(
                "/api/v1/competitions",
                headers={**_auth(_ADMIN), **key},
                json=_competition_body("gamma"),
            )
            self.assertEqual(r1.status_code, 201, r1.text)
            # Same principal, same key, DIFFERENT body -> 409 idempotency_key_reused.
            other = _competition_body("gamma")
            other["name"] = "changed"
            r2 = client.post(
                "/api/v1/competitions",
                headers={**_auth(_ADMIN), **key},
                json=other,
            )
            self.assertEqual(r2.status_code, 409, r2.text)
            self.assertEqual(
                r2.json()["error"]["code"], "idempotency_key_reused"
            )

    def test_same_principal_key_same_body_replays(self) -> None:
        with _client() as (client, _db):
            key = {"Idempotency-Key": "replay-key"}
            body = _competition_body("delta")
            r1 = client.post(
                "/api/v1/competitions", headers={**_auth(_ADMIN), **key}, json=body
            )
            self.assertEqual(r1.status_code, 201, r1.text)
            r2 = client.post(
                "/api/v1/competitions", headers={**_auth(_ADMIN), **key}, json=body
            )
            self.assertEqual(r2.status_code, 201, r2.text)
            self.assertEqual(
                r2.json()["competition_id"], r1.json()["competition_id"]
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
