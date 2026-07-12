"""PostgreSQL integration tests for the M11b organizer TEAM management flows.

Create a team (ok -> 303 + listed; duplicate name -> friendly field error, a 409
re-render NOT a 500); authz scoping (an organizer of A cannot manage B's teams --
existence-hiding 404; a contestant lacking team:write cannot create); CSRF (a POST
without the session-bound token is 403, nothing persisted); a hostile team name is
stored and later rendered ESCAPED; no ``style=`` attribute / no secret leaks. SKIPS
cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_team_write_integration
"""

from __future__ import annotations

import os
import unittest

try:
    import web_support as ws

    from ctf_generator.application.catalog import TeamService

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_SKIP_REASON = (
    f"[api]/[web]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)


def _csrf(client, path):
    r = client.get(path)
    return r, ws.extract_csrf(r.text)


def _team_names(db, competition_id):
    return {t.name for t in TeamService(db).list_for_competition(competition_id)}


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class TeamWriteTests(unittest.TestCase):
    def test_create_team_ok(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/teams")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"csrf_token": token, "name": "Red Team"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            self.assertIn("Red Team", _team_names(db, ws.COMP_A))
            # And it lists on the page.
            page = client.get(f"/app/competitions/{ws.COMP_A}/teams")
            self.assertIn("Red Team", page.text)

    def test_duplicate_team_is_field_error_not_500(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/teams")
            client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"csrf_token": token, "name": "Blue"},
                follow_redirects=False,
            )
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/teams")
            dup = client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"csrf_token": token, "name": "Blue"},
                follow_redirects=False,
            )
            self.assertEqual(dup.status_code, 409, dup.text)
            self.assertIn("already exists", dup.text)
            # Still exactly one Blue.
            self.assertEqual(
                [t.name for t in TeamService(db).list_for_competition(ws.COMP_A)].count("Blue"),
                1,
            )

    def test_blank_name_is_field_error(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/teams")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"csrf_token": token, "name": "   "},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertIn("Required.", resp.text)

    def test_organizer_cannot_manage_other_competition_teams_404(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A, not B
            self.assertEqual(client.get(f"/app/competitions/{ws.COMP_B}/teams").status_code, 404)
            resp = client.post(
                f"/app/competitions/{ws.COMP_B}/teams",
                data={"name": "Intruder"},
                follow_redirects=False,
            )
            self.assertIn(resp.status_code, (404, 403))
            self.assertNotIn("Intruder", _team_names(db, ws.COMP_B))

    def test_contestant_cannot_create_team(self) -> None:
        # EVE is a player of A: she may READ teams (contestant grant) but has no
        # team:write, so a create POST is denied (existence-hiding 404) and nothing
        # persists.
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/teams")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"csrf_token": token or "", "name": "Contestant Team"},
                follow_redirects=False,
            )
            self.assertIn(resp.status_code, (404, 403))
            self.assertNotIn("Contestant Team", _team_names(db, ws.COMP_A))

    def test_create_without_csrf_is_403(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"name": "No CSRF"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertNotIn("No CSRF", _team_names(db, ws.COMP_A))

    def test_hostile_team_name_is_escaped(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/teams")
            payload = "<script>alert('t')</script>"
            client.post(
                f"/app/competitions/{ws.COMP_A}/teams",
                data={"csrf_token": token, "name": payload},
                follow_redirects=False,
            )
            self.assertIn(payload, _team_names(db, ws.COMP_A))  # stored verbatim
            page = client.get(f"/app/competitions/{ws.COMP_A}/teams")
            self.assertNotIn(payload, page.text)  # never rendered raw
            self.assertIn("&lt;script&gt;", page.text)

    def test_no_style_attribute_or_secret_on_teams_page(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            token = ws.session_cookie(client)
            page = client.get(f"/app/competitions/{ws.COMP_A}/teams")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertNotIn("style=", page.text)
            self.assertNotIn(token, page.text)
            self.assertNotIn(ws.PASSWORD, page.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
