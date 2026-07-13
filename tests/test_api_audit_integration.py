"""PostgreSQL integration tests for the M16 audit-read API ([api]+[db]).

Drives real AUDITED privileged operations through the app (a competition create;
a denied privileged read) and asserts they appear in the durable trail via
``GET /audit``:

* an admin/support principal reads the trail (secret-free allowlisted fields
  only), filterable by ``actor`` / ``action`` / ``outcome`` and cursor-paginated;
* a contestant / organizer is DENIED (403) -- the audit trail is a system-wide,
  admin/support-only capability;
* a DENIED privileged attempt (a contestant hitting ``GET /audit``) is itself
  recorded in the trail (the M10b denied path now persists);
* no secret-shaped value ever appears in any response field.

SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_audit_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_ADMIN = "admintoken"  # noqa: S105
_SUPPORT = "supporttoken"  # noqa: S105
_ORGANIZER = "orgtoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105

# The allowlisted, secret-free fields the read API is permitted to surface.
_ALLOWED_FIELDS = {
    "audit_event_id",
    "actor",
    "action",
    "target",
    "outcome",
    "request_id",
    "reason",
    "occurred_at",
}


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_audit_{uuid.uuid4().hex[:12]}"
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
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            _SUPPORT: principal_for(
                "support-user", {"support"}, system_roles={"support"}
            ),
            _ORGANIZER: principal_for(
                "org-user", {"organizer"}, memberships={"c": ("organizer", None)}
            ),
            _PLAYER: principal_for("player-user", {"player"}, team="Red"),
        }
    )


@contextmanager
def _client_and_db():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(ApiSettings(), database=db, authenticator=_authenticator())
            yield TestClient(app, raise_server_exceptions=False), db
        finally:
            db.dispose()


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _competition_body(cid: str = "spring-ctf-2026") -> dict:
    return {
        "competition_id": cid,
        "name": "Spring CTF 2026",
        "start_time": "2026-06-01T09:00:00Z",
        "end_time": "2026-06-03T09:00:00Z",
        "scoring_start_time": "2026-06-01T09:30:00Z",
        "freeze_time": "2026-06-02T09:00:00Z",
    }


def _assert_secret_free(self, event: dict) -> None:
    # Only the allowlisted short-id fields exist on a read row (schema/version
    # keys live on the envelope, not the item).
    self.assertLessEqual(set(event), _ALLOWED_FIELDS)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuditApiIntegrationTests(unittest.TestCase):
    def test_audited_success_appears_and_is_filterable(self) -> None:
        with _client_and_db() as (client, _db):
            created = client.post(
                "/api/v1/competitions", headers=_auth(_ADMIN), json=_competition_body()
            )
            self.assertEqual(created.status_code, 201, created.text)

            listed = client.get("/api/v1/audit", headers=_auth(_ADMIN))
            self.assertEqual(listed.status_code, 200, listed.text)
            body = listed.json()
            self.assertEqual(body["schema"], "ctfgen.audit-event-list")
            actions = [e["action"] for e in body["data"]]
            self.assertIn("competition.create", actions)
            for event in body["data"]:
                _assert_secret_free(self, event)

            # Filter by action.
            only_create = client.get(
                "/api/v1/audit?action=competition.create", headers=_auth(_ADMIN)
            ).json()["data"]
            self.assertTrue(only_create)
            self.assertEqual({e["action"] for e in only_create}, {"competition.create"})
            create_event = only_create[0]
            self.assertEqual(create_event["actor"], "admin-user")
            self.assertEqual(create_event["target"], "spring-ctf-2026")
            self.assertEqual(create_event["outcome"], "success")

            # Filter by actor + outcome.
            by_actor = client.get(
                "/api/v1/audit?actor=admin-user&outcome=success", headers=_auth(_ADMIN)
            )
            self.assertEqual(by_actor.status_code, 200)
            self.assertTrue(
                all(e["actor"] == "admin-user" and e["outcome"] == "success"
                    for e in by_actor.json()["data"])
            )

    def test_support_may_read_but_organizer_and_player_are_denied(self) -> None:
        with _client_and_db() as (client, _db):
            self.assertEqual(
                client.get("/api/v1/audit", headers=_auth(_SUPPORT)).status_code, 200
            )
            self.assertEqual(
                client.get("/api/v1/audit", headers=_auth(_ORGANIZER)).status_code, 403
            )
            self.assertEqual(
                client.get("/api/v1/audit", headers=_auth(_PLAYER)).status_code, 403
            )

    def test_denied_privileged_attempt_is_itself_recorded(self) -> None:
        with _client_and_db() as (client, _db):
            # A contestant's denied read of the audit trail...
            denied = client.get("/api/v1/audit", headers=_auth(_PLAYER))
            self.assertEqual(denied.status_code, 403)
            # ...appears in the trail (outcome=denied), visible to an admin.
            trail = client.get(
                "/api/v1/audit?outcome=denied", headers=_auth(_ADMIN)
            ).json()["data"]
            self.assertTrue(trail, "expected the denied attempt to be recorded")
            denied_targets = {e["target"] for e in trail}
            self.assertIn("/api/v1/audit", denied_targets)
            self.assertTrue(
                any(e["actor"] == "player-user" for e in trail),
                "denied attempt should record the resolved subject",
            )
            for event in trail:
                _assert_secret_free(self, event)

    def test_pagination_walks_without_overlap(self) -> None:
        with _client_and_db() as (client, _db):
            # Generate several audit rows (denied attempts are quick + audited).
            for _ in range(5):
                client.get("/api/v1/audit", headers=_auth(_PLAYER))
            seen: list[str] = []
            url = "/api/v1/audit?limit=2"
            for _ in range(20):  # bounded
                page = client.get(url, headers=_auth(_ADMIN)).json()
                seen.extend(e["audit_event_id"] for e in page["data"])
                nxt = page["page"]["next_cursor"]
                if nxt is None:
                    break
                url = f"/api/v1/audit?limit=2&cursor={nxt}"
            # No id appears twice across pages.
            self.assertEqual(len(seen), len(set(seen)))
            self.assertGreaterEqual(len(seen), 5)

    def test_malformed_filter_is_clean_400_not_500(self) -> None:
        with _client_and_db() as (client, _db):
            bad_outcome = client.get(
                "/api/v1/audit?outcome=bogus", headers=_auth(_ADMIN)
            )
            self.assertEqual(bad_outcome.status_code, 400, bad_outcome.text)
            self.assertEqual(bad_outcome.json()["error"]["code"], "invalid_request")

            bad_time = client.get(
                "/api/v1/audit?since=not-a-date", headers=_auth(_ADMIN)
            )
            self.assertEqual(bad_time.status_code, 400, bad_time.text)

            bad_cursor = client.get(
                "/api/v1/audit?cursor=!!!not-base64!!!", headers=_auth(_ADMIN)
            )
            self.assertEqual(bad_cursor.status_code, 400, bad_cursor.text)

    def test_secret_shaped_target_is_still_just_data(self) -> None:
        # Even if a caller drove an action whose TARGET looked like a secret, the
        # row is a short-id column, not a secret store. We prove the schema records
        # arbitrary target text verbatim with no special field -- there is no
        # flag/token column that could hold (or leak) a real secret. Here a
        # competition id shaped like a token is recorded as an ordinary target.
        with _client_and_db() as (client, _db):
            token_shaped = "flag-a1b2c3d4e5f6a7b8"  # noqa: S105
            created = client.post(
                "/api/v1/competitions",
                headers=_auth(_ADMIN),
                json=_competition_body(cid=token_shaped),
            )
            self.assertEqual(created.status_code, 201, created.text)
            data = client.get(
                "/api/v1/audit?action=competition.create&actor=admin-user",
                headers=_auth(_ADMIN),
            ).json()["data"]
            targets = {e["target"] for e in data}
            self.assertIn(token_shaped, targets)
            for event in data:
                _assert_secret_free(self, event)
                # No response field is named or typed as a secret holder.
                self.assertNotIn("flag", set(event) - {"target"})
                self.assertNotIn("token", event)
                self.assertNotIn("password", event)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
