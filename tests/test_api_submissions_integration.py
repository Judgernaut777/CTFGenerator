"""PostgreSQL integration tests for the M9 slice-b submissions API + the
scoreboard read-through ([api]+[db], real PG).

Covers the contestant loop end to end against real PostgreSQL:

* a CORRECT answer -> outcome shows solved, and after driving the projector the
  scoreboard GET reflects the solve;
* an INCORRECT answer -> not solved, no scoreboard change;
* an idempotent submit replay returns the same outcome, and the replay is proven
  to short-circuit at the HTTP layer (a single ``submission.create`` audit event);
* the same Idempotency-Key + body across two competitions records two distinct
  submissions (no cross-competition replay);
* a player CANNOT list/read another team's submissions (403 / 404), and a player
  with no team is denied on every path (403 submit / 403 list / 404 read);
* the expected flag never appears in any response body.

SKIPS cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_submissions_integration
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

    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.authoring.models import ChallengePublication
    from ctf_generator.infrastructure.database.challenge_publication_repository import (
        SqlAlchemyChallengePublicationRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
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

_ADMIN = "admintoken"  # noqa: S105 - test fixture token, not a real secret
_RED = "redplayertoken"  # noqa: S105 - test fixture token, not a real secret
_BLUE = "blueplayertoken"  # noqa: S105 - test fixture token, not a real secret
_NOTEAM = "noteamplayertoken"  # noqa: S105 - test fixture token, not a real secret

_FLAG = "CTF{the-secret-flag}"
_CID = "spring-ctf-2026"
_CID_B = "autumn-ctf-2026"
_SLUG = "sqli-1"


class _RecordingAuditSink:
    """An in-memory audit sink so tests can assert exactly which privileged
    actions reached the audit hook (used to prove the HTTP idempotency
    short-circuit happens BEFORE the service, not just the domain PK dedup)."""

    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def record(self, event: dict[str, str]) -> None:
        self.events.append(dict(event))


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_it_{uuid.uuid4().hex[:12]}"
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
            _ADMIN: principal_for("admin-user", {"admin"}),
            _RED: principal_for("red-player", {"player"}, team="Red"),
            _BLUE: principal_for("blue-player", {"player"}, team="Blue"),
            # A contestant with the player role but NOT placed on a team: has the
            # submission permissions, so any denial is the fail-closed tenancy
            # check, not require_permission.
            _NOTEAM: principal_for("no-team-player", {"player"}),
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


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _competition_body() -> dict:
    return {
        "competition_id": _CID,
        "name": "Spring CTF 2026",
        "start_time": "2026-06-01T09:00:00Z",
        "end_time": "2026-06-03T09:00:00Z",
        "scoring_start_time": "2026-06-01T09:30:00Z",
        "freeze_time": "2026-06-02T09:00:00Z",
    }


def _seed(client: TestClient, db: Database) -> None:
    """Competition + Red/Blue teams + a published, attached challenge whose spec
    carries the expected flag."""
    assert client.post(
        "/api/v1/competitions", headers=_auth(), json=_competition_body()
    ).status_code == 201
    for team in ("Red", "Blue"):
        assert client.post(
            "/api/v1/teams",
            headers=_auth(),
            json={"competition_id": _CID, "name": team},
        ).status_code == 201
    assert client.post(
        "/api/v1/challenge-definitions",
        headers=_auth(),
        json={"family": "web", "slug": _SLUG, "title": "SQLi One"},
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-versions",
        headers=_auth(),
        json={
            "definition_slug": _SLUG,
            "seed": "seed-1",
            "family_version": "1.0.0",
            "spec": {"title": "SQLi One", "flag": _FLAG},
        },
    ).status_code == 201
    assert client.post(
        f"/api/v1/challenge-versions/{_SLUG}/1/publish", headers=_auth()
    ).status_code == 200
    # No publication API endpoint yet (M9c) -- attach directly via the repo.
    with db.session_scope() as session:
        SqlAlchemyChallengePublicationRepository(session).add(
            ChallengePublication(
                competition_id=_CID, definition_slug=_SLUG, version_no=1
            )
        )


def _seed_extra_competition(
    client: TestClient, db: Database, cid: str, name: str
) -> None:
    """A SECOND competition + Red/Blue teams, sharing the already-published
    challenge from :func:`_seed` (definition/version are global) by attaching a
    fresh publication for this competition."""
    body = _competition_body()
    body["competition_id"] = cid
    body["name"] = name
    assert client.post(
        "/api/v1/competitions", headers=_auth(), json=body
    ).status_code == 201
    for team in ("Red", "Blue"):
        assert client.post(
            "/api/v1/teams",
            headers=_auth(),
            json={"competition_id": cid, "name": team},
        ).status_code == 201
    with db.session_scope() as session:
        SqlAlchemyChallengePublicationRepository(session).add(
            ChallengePublication(
                competition_id=cid, definition_slug=_SLUG, version_no=1
            )
        )


def _submit(client: TestClient, token: str, answer: str, *, team: str = "Red",
            idem: str | None = None):
    headers = _auth(token)
    if idem is not None:
        headers["Idempotency-Key"] = idem
    return client.post(
        f"/api/v1/competitions/{_CID}/submissions",
        headers=headers,
        json={
            "team": team,
            "definition_slug": _SLUG,
            "version_no": 1,
            "answer": answer,
        },
    )


def _standings(client: TestClient) -> list[dict]:
    r = client.get(f"/api/v1/competitions/{_CID}/scoreboard", headers=_auth())
    assert r.status_code == 200, r.text
    return r.json()["data"]


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SubmissionsApiIntegrationTests(unittest.TestCase):
    def test_correct_answer_solves_and_scoreboard_reflects_it(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)

            r = _submit(client, _RED, _FLAG)
            self.assertEqual(r.status_code, 201, r.text)
            body = r.json()
            self.assertEqual(body["schema"], "ctfgen.submission")
            self.assertTrue(body["correct"])
            self.assertTrue(body["first_solve"])
            self.assertIsNotNone(body["solve"])
            self.assertTrue(body["solve"]["solve_id"])
            self.assertTrue(body["solve"]["solved_at"])
            # The expected flag never leaks into the response body.
            self.assertNotIn(_FLAG, r.text)

            # Scoreboard is empty until the projector folds the solve event.
            self.assertEqual(_standings(client), [])
            ScoreProjector(db).run_until_drained()

            standings = _standings(client)
            self.assertEqual([e["team_id"] for e in standings], ["Red"])
            self.assertEqual(standings[0]["solve_count"], 1)
            self.assertGreater(standings[0]["score"], 0)
            self.assertIsNotNone(standings[0]["last_solve_at"])

    def test_incorrect_answer_does_not_solve_or_move_scoreboard(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            _submit(client, _RED, _FLAG)
            ScoreProjector(db).run_until_drained()
            before = _standings(client)

            r = _submit(client, _RED, "definitely-wrong")
            self.assertEqual(r.status_code, 201, r.text)
            self.assertFalse(r.json()["correct"])
            self.assertFalse(r.json()["first_solve"])
            self.assertIsNone(r.json()["solve"])

            # No solve event emitted -> nothing new to fold -> unchanged.
            ScoreProjector(db).run_until_drained()
            self.assertEqual(_standings(client), before)

    def test_idempotent_replay_returns_same_outcome(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            first = _submit(client, _RED, _FLAG, idem="submit-1")
            self.assertEqual(first.status_code, 201, first.text)
            replay = _submit(client, _RED, _FLAG, idem="submit-1")
            self.assertEqual(replay.status_code, 201, replay.text)
            self.assertEqual(
                replay.json()["submission_id"], first.json()["submission_id"]
            )
            self.assertEqual(replay.json()["solve"], first.json()["solve"])
            # A reused key with a different body -> 409 idempotency_key_reused.
            conflict = client.post(
                f"/api/v1/competitions/{_CID}/submissions",
                headers={**_auth(_RED), "Idempotency-Key": "submit-1"},
                json={
                    "team": "Red",
                    "definition_slug": _SLUG,
                    "version_no": 1,
                    "answer": "other",
                },
            )
            self.assertEqual(conflict.status_code, 409, conflict.text)
            self.assertEqual(
                conflict.json()["error"]["code"], "idempotency_key_reused"
            )

    def test_player_cannot_read_other_teams_submissions(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            # A Blue attempt, created by the unrestricted admin for team Blue.
            blue = _submit(client, _ADMIN, "wrong", team="Blue")
            self.assertEqual(blue.status_code, 201, blue.text)
            blue_id = blue.json()["submission_id"]
            # A Red attempt for contrast.
            _submit(client, _RED, _FLAG)

            # A Red player listing their own team -> only Red rows.
            own = client.get(
                f"/api/v1/competitions/{_CID}/submissions", headers=_auth(_RED)
            )
            self.assertEqual(own.status_code, 200, own.text)
            self.assertTrue(own.json()["data"])
            self.assertTrue(all(s["team"] == "Red" for s in own.json()["data"]))

            # A Red player explicitly asking for Blue -> 403.
            denied = client.get(
                f"/api/v1/competitions/{_CID}/submissions?team=Blue",
                headers=_auth(_RED),
            )
            self.assertEqual(denied.status_code, 403, denied.text)
            self.assertEqual(denied.json()["error"]["code"], "forbidden")

            # A Red player fetching a Blue submission by id -> 404 (no leak).
            cross = client.get(
                f"/api/v1/submissions/{blue_id}", headers=_auth(_RED)
            )
            self.assertEqual(cross.status_code, 404, cross.text)
            self.assertEqual(cross.json()["error"]["code"], "not_found")

            # The owning admin CAN read it, and the flag is never present.
            ok = client.get(f"/api/v1/submissions/{blue_id}", headers=_auth())
            self.assertEqual(ok.status_code, 200, ok.text)
            self.assertNotIn(_FLAG, ok.text)

    def test_submit_to_unknown_challenge_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            r = client.post(
                f"/api/v1/competitions/{_CID}/submissions",
                headers=_auth(_RED),
                json={
                    "team": "Red",
                    "definition_slug": "no-such",
                    "version_no": 1,
                    "answer": "x",
                },
            )
            self.assertEqual(r.status_code, 404, r.text)
            self.assertEqual(r.json()["error"]["code"], "not_found")

    def test_player_cannot_submit_for_another_team(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            r = _submit(client, _RED, _FLAG, team="Blue")
            self.assertEqual(r.status_code, 403, r.text)
            self.assertEqual(r.json()["error"]["code"], "forbidden")

    def test_teamless_player_is_denied_fail_closed(self) -> None:
        # FIX-A regression: a player principal with no team must be denied on
        # EVERY submission path (403 submit, 403 list, 404 cross-read) -- never
        # fall through to "unrestricted" and read/submit for arbitrary teams.
        with _client_and_db() as (client, db):
            _seed(client, db)
            # A real Red submission the teamless player must not be able to reach.
            red = _submit(client, _RED, _FLAG)
            self.assertEqual(red.status_code, 201, red.text)
            red_id = red.json()["submission_id"]

            # POST submit -> 403 (not placed on a team).
            post = _submit(client, _NOTEAM, _FLAG)
            self.assertEqual(post.status_code, 403, post.text)
            self.assertEqual(post.json()["error"]["code"], "forbidden")

            # GET list -> 403 (cannot see any team's rows).
            listing = client.get(
                f"/api/v1/competitions/{_CID}/submissions", headers=_auth(_NOTEAM)
            )
            self.assertEqual(listing.status_code, 403, listing.text)
            self.assertEqual(listing.json()["error"]["code"], "forbidden")

            # GET another team's submission by id -> 404 (never confirm existence).
            cross = client.get(
                f"/api/v1/submissions/{red_id}", headers=_auth(_NOTEAM)
            )
            self.assertEqual(cross.status_code, 404, cross.text)
            self.assertEqual(cross.json()["error"]["code"], "not_found")

            # The expected flag never leaks on any denied path.
            self.assertNotIn(_FLAG, listing.text)
            self.assertNotIn(_FLAG, cross.text)

    def test_cross_competition_idempotency_isolation(self) -> None:
        # FIX-B regression: the SAME principal + SAME Idempotency-Key + identical
        # body POSTed to two DIFFERENT competitions must record two distinct
        # submissions -- B must NOT replay A's stored 201.
        with _client_and_db() as (client, db):
            _seed(client, db)
            _seed_extra_competition(client, db, _CID_B, "Autumn CTF 2026")

            body = {
                "team": "Red",
                "definition_slug": _SLUG,
                "version_no": 1,
                "answer": _FLAG,
            }
            a = client.post(
                f"/api/v1/competitions/{_CID}/submissions",
                headers={**_auth(_RED), "Idempotency-Key": "shared-key"},
                json=body,
            )
            self.assertEqual(a.status_code, 201, a.text)
            b = client.post(
                f"/api/v1/competitions/{_CID_B}/submissions",
                headers={**_auth(_RED), "Idempotency-Key": "shared-key"},
                json=body,
            )
            self.assertEqual(b.status_code, 201, b.text)

            # Two distinct submissions, each under its own competition.
            self.assertNotEqual(
                a.json()["submission_id"], b.json()["submission_id"]
            )
            self.assertEqual(a.json()["competition_id"], _CID)
            self.assertEqual(b.json()["competition_id"], _CID_B)

            # B's row is recorded under competition B (not silently dropped).
            listing = client.get(
                f"/api/v1/competitions/{_CID_B}/submissions", headers=_auth(_RED)
            )
            self.assertEqual(listing.status_code, 200, listing.text)
            self.assertEqual(
                [s["submission_id"] for s in listing.json()["data"]],
                [b.json()["submission_id"]],
            )
            self.assertNotIn(_FLAG, b.text)

    def test_idempotent_replay_is_http_layer_not_pk_dedup(self) -> None:
        # FIX-D: prove the second identical call short-circuits at the HTTP replay
        # layer BEFORE the service -- so only ONE submission.create audit event is
        # emitted for two identical calls. If replay() were removed, the second
        # call would reach the service (and the audit hook) and record twice.
        sink = _RecordingAuditSink()
        with _client_and_db(audit_sink=sink) as (client, db):
            _seed(client, db)
            first = _submit(client, _RED, _FLAG, idem="only-once")
            self.assertEqual(first.status_code, 201, first.text)
            second = _submit(client, _RED, _FLAG, idem="only-once")
            self.assertEqual(second.status_code, 201, second.text)
            self.assertEqual(
                second.json()["submission_id"], first.json()["submission_id"]
            )
            creates = [
                e for e in sink.events if e.get("action") == "submission.create"
            ]
            self.assertEqual(len(creates), 1, sink.events)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
