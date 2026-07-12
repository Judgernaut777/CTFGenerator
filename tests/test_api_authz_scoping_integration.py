"""PostgreSQL integration tests for M10b per-competition tenancy / IDOR scoping.

These are the POINT of the slice. Against real PostgreSQL they prove:

* CROSS-COMPETITION DENIAL: an organizer / contestant whose membership is in
  competition A is 403 on the SAME operation against competition B
  (competition:write, team:write, publication:write, submission:read, scoreboard,
  instance:operate) -- its flat role union no longer leaks authority across
  competitions.
* CROSS-TEAM DENIAL: a player of team Red in competition X cannot read/submit for
  team Blue in X, and cannot act in competition Y at all.
* SYSTEM POSITIVE CONTROL: an admin / support system role CAN act across
  competitions.
* INSTANCE-BY-ID: a caller with instance:operate in A cannot stop/reset/delete an
  instance belonging to B (403), and GET /instances does not leak B's instances to
  an A-only caller.
* DENIED AUDIT: a 403 attempt yields exactly one 'denied' audit record with the
  right actor/target and no secret.

SKIPS cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_authz_scoping_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:  # heavy deps optional; guard so import never fails the host suite
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.domain.authoring.models import ChallengePublication
    from ctf_generator.domain.instances.models import Instance
    from ctf_generator.infrastructure.database.challenge_publication_repository import (
        SqlAlchemyChallengePublicationRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings

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

# Two competitions; principals are scoped to exactly one of them via membership.
_A = "alpha-ctf-2026"
_B = "bravo-ctf-2026"
_SLUG = "sqli-1"
_FLAG = "CTF{scoping-secret-flag}"
_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)

_ADMIN = "admintoken"  # noqa: S105 - test fixture token, not a real secret
_SUPPORT = "supporttoken"  # noqa: S105 - test fixture token, not a real secret
_ORG_A = "orgAtoken"  # noqa: S105 - test fixture token, not a real secret
_ORG_B = "orgBtoken"  # noqa: S105 - test fixture token, not a real secret
_RED_A = "redAtoken"  # noqa: S105 - test fixture token, not a real secret
_RED_B = "redBtoken"  # noqa: S105 - test fixture token, not a real secret


class _RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def record(self, event: dict[str, str]) -> None:
        self.events.append(dict(event))


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_authz_{uuid.uuid4().hex[:12]}"
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
            # An organizer of A has organizer authority ONLY in A (its flat role is
            # still 'organizer', but the scoped check consults its membership).
            _ORG_A: principal_for(
                "org-a", {"organizer"}, memberships={_A: ("organizer", None)}
            ),
            _ORG_B: principal_for(
                "org-b", {"organizer"}, memberships={_B: ("organizer", None)}
            ),
            # Player of team Red in A only, and Red in B only, respectively.
            _RED_A: principal_for(
                "red-a", {"player"}, team="Red",
                memberships={_A: ("player", "Red")},
            ),
            _RED_B: principal_for(
                "red-b", {"player"}, team="Red",
                memberships={_B: ("player", "Red")},
            ),
        }
    )


@contextmanager
def _client_and_db(audit_sink=None):
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _competition_body(cid: str, name: str) -> dict:
    return {
        "competition_id": cid,
        "name": name,
        "start_time": "2026-06-01T09:00:00Z",
        "end_time": "2026-06-03T09:00:00Z",
    }


def _seed_competition(client: TestClient, db: Database, cid: str, name: str) -> None:
    """Competition + Red/Blue teams + the shared challenge attached (all by the
    system admin, which is authorized in every competition)."""
    assert client.post(
        "/api/v1/competitions", headers=_auth(_ADMIN), json=_competition_body(cid, name)
    ).status_code == 201
    for team in ("Red", "Blue"):
        assert client.post(
            "/api/v1/teams",
            headers=_auth(_ADMIN),
            json={"competition_id": cid, "name": team},
        ).status_code == 201
    with db.session_scope() as session:
        SqlAlchemyChallengePublicationRepository(session).add(
            ChallengePublication(competition_id=cid, definition_slug=_SLUG, version_no=1)
        )


def _seed_challenge(client: TestClient) -> None:
    assert client.post(
        "/api/v1/challenge-definitions",
        headers=_auth(_ADMIN),
        json={"family": "web", "slug": _SLUG, "title": "SQLi One"},
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-versions",
        headers=_auth(_ADMIN),
        json={
            "definition_slug": _SLUG,
            "seed": "seed-1",
            "family_version": "1.0.0",
            "spec": {"title": "SQLi One", "flag": _FLAG},
        },
    ).status_code == 201
    assert client.post(
        f"/api/v1/challenge-versions/{_SLUG}/1/publish", headers=_auth(_ADMIN)
    ).status_code == 200


def _seed_both(client: TestClient, db: Database) -> None:
    _seed_challenge(client)
    _seed_competition(client, db, _A, "Alpha CTF")
    _seed_competition(client, db, _B, "Bravo CTF")


def _seed_instance(db: Database, cid: str) -> str:
    """A bare active instance under competition ``cid`` (worker-less)."""
    iid = str(uuid.uuid4())
    with db.session_scope() as s:
        SqlAlchemyInstanceRepository(s).add(
            Instance(
                instance_id=iid,
                competition_id=cid,
                team_name="Red",
                definition_slug=_SLUG,
                version_no=1,
                state="active",
                desired_state="active",
                expires_at=_NOW + timedelta(hours=1),
            ),
            _NOW,
        )
    return iid


def _competition_etag(client: TestClient, cid: str) -> str:
    r = client.get(f"/api/v1/competitions/{cid}", headers=_auth(_ADMIN))
    assert r.status_code == 200, r.text
    return r.headers["ETag"]


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CrossCompetitionDenialTests(unittest.TestCase):
    def test_organizer_of_a_is_denied_every_scoped_write_in_b(self) -> None:
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            etag_b = _competition_etag(client, _B)
            # A submission in B (recorded by the unrestricted admin) for the
            # submission:read cross-competition probe.
            sub = client.post(
                f"/api/v1/competitions/{_B}/submissions",
                headers=_auth(_ADMIN),
                json={"team": "Red", "definition_slug": _SLUG, "version_no": 1,
                      "answer": "nope"},
            )
            self.assertEqual(sub.status_code, 201, sub.text)
            sub_b_id = sub.json()["submission_id"]

            # Each is the SAME operation the organizer performs happily in A, now
            # aimed at B where it holds no membership -> 403 forbidden.
            probes = [
                ("patch", f"/api/v1/competitions/{_B}",
                 {"If-Match": etag_b}, {"name": "hijacked"}),
                ("post", "/api/v1/teams", {}, {"competition_id": _B, "name": "Green"}),
                ("post", f"/api/v1/competitions/{_B}/publications", {},
                 {"definition_slug": _SLUG, "version_no": 1}),
                ("get", f"/api/v1/competitions/{_B}/scoreboard", {}, None),
                ("get", f"/api/v1/competitions/{_B}/scoreboard/lag", {}, None),
                ("get", f"/api/v1/competitions/{_B}/submissions", {}, None),
                ("get", f"/api/v1/submissions/{sub_b_id}", {}, None),
                ("get", f"/api/v1/competitions/{_B}/instances", {}, None),
                ("post", "/api/v1/instances", {},
                 {"competition_id": _B, "team": "Red",
                  "definition_slug": _SLUG, "version_no": 1}),
            ]
            for method, path, extra, body in probes:
                kwargs = {"headers": {**_auth(_ORG_A), **extra}}
                if body is not None:
                    kwargs["json"] = body
                r = getattr(client, method)(path, **kwargs)
                self.assertEqual(r.status_code, 403, f"{method} {path}: {r.text}")
                self.assertEqual(r.json()["error"]["code"], "forbidden")

    def test_organizer_of_a_still_authorized_in_a(self) -> None:
        # Positive control: the SAME organizer succeeds against its OWN competition.
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            self.assertEqual(
                client.get(
                    f"/api/v1/competitions/{_A}/scoreboard", headers=_auth(_ORG_A)
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/api/v1/teams",
                    headers=_auth(_ORG_A),
                    json={"competition_id": _A, "name": "Green"},
                ).status_code,
                201,
            )
            # ...and the organizer of B succeeds in B where A's organizer was denied.
            self.assertEqual(
                client.post(
                    "/api/v1/teams",
                    headers=_auth(_ORG_B),
                    json={"competition_id": _B, "name": "Green"},
                ).status_code,
                201,
            )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CrossTeamAndCrossCompetitionContestantTests(unittest.TestCase):
    def test_red_a_confined_to_red_in_a_and_absent_in_b(self) -> None:
        with _client_and_db() as (client, db):
            _seed_both(client, db)

            # Cross-team within A: Red cannot submit for Blue (403) nor list Blue.
            self.assertEqual(
                client.post(
                    f"/api/v1/competitions/{_A}/submissions",
                    headers=_auth(_RED_A),
                    json={"team": "Blue", "definition_slug": _SLUG,
                          "version_no": 1, "answer": _FLAG},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get(
                    f"/api/v1/competitions/{_A}/submissions?team=Blue",
                    headers=_auth(_RED_A),
                ).status_code,
                403,
            )
            # Own team in A is fine.
            self.assertEqual(
                client.post(
                    f"/api/v1/competitions/{_A}/submissions",
                    headers=_auth(_RED_A),
                    json={"team": "Red", "definition_slug": _SLUG,
                          "version_no": 1, "answer": _FLAG},
                ).status_code,
                201,
            )

            # Cross-competition: Red-of-A has no standing in B at all -> 403 on
            # submit AND list (require_competition_permission denies before tenancy).
            self.assertEqual(
                client.post(
                    f"/api/v1/competitions/{_B}/submissions",
                    headers=_auth(_RED_A),
                    json={"team": "Red", "definition_slug": _SLUG,
                          "version_no": 1, "answer": _FLAG},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get(
                    f"/api/v1/competitions/{_B}/submissions", headers=_auth(_RED_A)
                ).status_code,
                403,
            )

    def test_same_named_team_in_other_competition_does_not_leak(self) -> None:
        # Red-of-B submits in B; Red-of-A (same team NAME, different competition)
        # cannot read B's Red submission by id -> 403 (no submission:read in B).
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            made = client.post(
                f"/api/v1/competitions/{_B}/submissions",
                headers=_auth(_RED_B),
                json={"team": "Red", "definition_slug": _SLUG,
                      "version_no": 1, "answer": "nope"},
            )
            self.assertEqual(made.status_code, 201, made.text)
            b_id = made.json()["submission_id"]
            r = client.get(f"/api/v1/submissions/{b_id}", headers=_auth(_RED_A))
            self.assertEqual(r.status_code, 403, r.text)
            self.assertEqual(r.json()["error"]["code"], "forbidden")
            self.assertNotIn(_FLAG, r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SystemRolePositiveControlTests(unittest.TestCase):
    def test_admin_acts_across_both_competitions(self) -> None:
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            for cid in (_A, _B):
                self.assertEqual(
                    client.get(
                        f"/api/v1/competitions/{cid}/scoreboard", headers=_auth(_ADMIN)
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    client.post(
                        "/api/v1/teams",
                        headers=_auth(_ADMIN),
                        json={"competition_id": cid, "name": "Sys"},
                    ).status_code,
                    201,
                )

    def test_support_reads_scoreboard_lag_in_both(self) -> None:
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            for cid in (_A, _B):
                r = client.get(
                    f"/api/v1/competitions/{cid}/scoreboard/lag", headers=_auth(_SUPPORT)
                )
                self.assertEqual(r.status_code, 200, r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class InstanceByIdScopingTests(unittest.TestCase):
    def test_instance_by_id_actions_resolve_competition_and_deny_cross(self) -> None:
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            iid_b = _seed_instance(db, _B)

            # Org A holds instance:operate in A, NOT in B: every by-id action on an
            # instance that belongs to B is 403.
            for verb in ("stop", "reset", "delete"):
                r = client.post(
                    f"/api/v1/instances/{iid_b}/{verb}", headers=_auth(_ORG_A)
                )
                self.assertEqual(r.status_code, 403, f"{verb}: {r.text}")
                self.assertEqual(r.json()["error"]["code"], "forbidden")
            # GET the B instance by id is likewise denied to the A-only organizer.
            self.assertEqual(
                client.get(
                    f"/api/v1/instances/{iid_b}", headers=_auth(_ORG_A)
                ).status_code,
                403,
            )
            # The organizer of B (rightful owner) CAN stop it.
            self.assertEqual(
                client.post(
                    f"/api/v1/instances/{iid_b}/stop", headers=_auth(_ORG_B)
                ).status_code,
                200,
            )

    def test_global_instance_list_does_not_leak_other_competition(self) -> None:
        with _client_and_db() as (client, db):
            _seed_both(client, db)
            iid_a = _seed_instance(db, _A)
            iid_b = _seed_instance(db, _B)

            # Org A sees ONLY A's instance in the cross-competition operator list.
            org = client.get("/api/v1/instances", headers=_auth(_ORG_A))
            self.assertEqual(org.status_code, 200, org.text)
            ids = {row["instance_id"] for row in org.json()["data"]}
            self.assertIn(iid_a, ids)
            self.assertNotIn(iid_b, ids)

            # The system admin sees both.
            adm = client.get("/api/v1/instances", headers=_auth(_ADMIN))
            adm_ids = {row["instance_id"] for row in adm.json()["data"]}
            self.assertTrue({iid_a, iid_b} <= adm_ids)

            # A contestant (Red of A) holds instance:read nowhere -> 403, not an
            # empty 200 leak.
            self.assertEqual(
                client.get("/api/v1/instances", headers=_auth(_RED_A)).status_code,
                403,
            )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class DeniedAttemptAuditTests(unittest.TestCase):
    def test_denied_privileged_call_emits_one_denied_audit_no_secret(self) -> None:
        sink = _RecordingAuditSink()
        with _client_and_db(audit_sink=sink) as (client, db):
            _seed_both(client, db)
            etag_b = _competition_etag(client, _B)
            before = len(sink.events)
            # Organizer of A tries to hijack competition B: a modelled 403 denial.
            secret_marker = "SECRET-BODY-VALUE-should-not-be-audited"  # noqa: S105
            r = client.patch(
                f"/api/v1/competitions/{_B}",
                headers={**_auth(_ORG_A), "If-Match": etag_b},
                json={"name": secret_marker},
            )
            self.assertEqual(r.status_code, 403, r.text)

            denials = [
                e for e in sink.events[before:] if e.get("outcome") == "denied"
            ]
            self.assertEqual(len(denials), 1, sink.events[before:])
            event = denials[0]
            # Right actor (resolved principal subject) + target (the request PATH).
            self.assertEqual(event["actor"], "org-a")
            self.assertEqual(event["action"], "PATCH")
            self.assertEqual(event["target"], f"/api/v1/competitions/{_B}")
            self.assertEqual(
                set(event), {"actor", "action", "target", "outcome", "request_id"}
            )
            # No secret: neither the bearer token nor the request body is recorded.
            blob = repr(event)
            self.assertNotIn(secret_marker, blob)
            self.assertNotIn(_ORG_A, blob)
            self.assertNotIn("Bearer", blob)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
