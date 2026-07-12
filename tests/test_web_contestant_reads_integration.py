"""PostgreSQL integration tests for the M12a CONTESTANT web read surface.

A player/captain can reach their competitions (``/play``), the per-competition
landing + published catalog, and their OWN-team roster -- and NOTHING more. The
invariants under test:

* a team-scoped contestant sees the published catalog (public metadata) and only
  THEIR team's roster; a planted flag / private spec content NEVER appears on any
  page, and no ``style=`` attribute / session token / password leaks;
* a contestant of COMP_A cannot view COMP_B's play/roster/challenges -- an
  existence-hiding 404 (never a 403 confirming existence);
* a teamless contestant gets a graceful "not on a team" roster (200), never
  another team's data, never a 500;
* ``/play`` lists ONLY the caller's authorized competitions;
* a tenancy-unrestricted organizer may see every team's roster.

SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_contestant_reads_integration
"""

from __future__ import annotations

import os
import unittest

try:
    import web_support as ws

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

# Planted private challenge content that MUST NEVER reach a rendered page.
_FLAG = "FLAG{super-secret-do-not-leak}"
_PRIVATE = "PRIVATE-SCENARIO-SOLUTION-xyz"
_FRANK = "frank@example.com"


def _publish_catalog(db) -> tuple[str, int]:
    """Publish a challenge carrying a planted flag + private spec field, attached
    to COMP_A. The catalog must show only public metadata, never this spec."""
    slug, ver = ws.seed_published_version(
        db,
        "sqli",
        "SQL Injection",
        family="web",
        spec={"title": "SQL Injection", "flag": _FLAG, "solution": _PRIVATE},
    )
    ws.attach_publication(db, ws.COMP_A, slug, ver)
    return slug, ver


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ContestantReadsWebTests(unittest.TestCase):
    def test_team_member_sees_catalog_and_own_roster_without_secrets(self) -> None:
        with ws.web_client() as (client, db, _svc):
            _publish_catalog(db)
            ws.add_team(db, ws.COMP_A, "Red")
            ws.add_team(db, ws.COMP_A, "Blue")
            ws.place_on_team(db, ws.EVE, ws.COMP_A, "Red")  # EVE -> Red
            ws.add_user(db, _FRANK, "Frank")
            ws.place_on_team(db, _FRANK, ws.COMP_A, "Blue")  # Frank -> Blue

            ws.login(client, ws.EVE)

            play = client.get(f"/app/competitions/{ws.COMP_A}/play")
            self.assertEqual(play.status_code, 200, play.text)
            self.assertIn("SQL Injection", play.text)  # catalog title
            self.assertIn("sqli", play.text)  # slug
            self.assertIn("Red", play.text)  # own team surfaced

            challenges = client.get(f"/app/competitions/{ws.COMP_A}/challenges")
            self.assertEqual(challenges.status_code, 200, challenges.text)
            self.assertIn("SQL Injection", challenges.text)

            roster = client.get(f"/app/competitions/{ws.COMP_A}/roster")
            self.assertEqual(roster.status_code, 200, roster.text)
            self.assertIn(ws.EVE, roster.text)  # own-team member shown
            # Fail-closed tenancy: a DIFFERENT team's member is never rendered.
            self.assertNotIn(_FRANK, roster.text)
            # ...and a NULL-team member (organizer ALICE, team_name=None) must be
            # excluded too -- the filter is `== scope.team`, not `in (team, None)`.
            # COMP_A's members are {ALICE(None), EVE(Red), FRANK(Blue)}, so with
            # both ALICE and FRANK absent Red's roster is exactly {EVE}. (EVE's own
            # email also appears once in the nav header, so don't count occurrences.)
            self.assertNotIn(ws.ALICE, roster.text)

            token = ws.session_cookie(client)
            for page in (play, challenges, roster):
                self.assertNotIn(_FLAG, page.text, "flag leaked")
                self.assertNotIn(_PRIVATE, page.text, "private spec leaked")
                self.assertNotIn("style=", page.text, "inline style attr present")
                self.assertNotIn(ws.PASSWORD, page.text)
                if token:
                    self.assertNotIn(token, page.text, "session token leaked")

    def test_catalog_is_isolated_per_competition(self) -> None:
        # A challenge published to COMP_B must NEVER surface in COMP_A's catalog
        # (the per-competition scoping is PublicationService.list_for_competition;
        # a regression returning all publications would leak it cross-competition).
        with ws.web_client() as (client, db, _svc):
            _publish_catalog(db)  # "sqli" / "SQL Injection" -> COMP_A
            other_slug, other_ver = ws.seed_published_version(
                db, "xxe", "XML External Entity", family="web"
            )
            ws.attach_publication(db, ws.COMP_B, other_slug, other_ver)  # -> COMP_B

            ws.place_on_team(db, ws.EVE, ws.COMP_A, None)  # EVE: COMP_A only
            ws.login(client, ws.EVE)

            for path in ("play", "challenges"):
                page = client.get(f"/app/competitions/{ws.COMP_A}/{path}")
                self.assertEqual(page.status_code, 200, page.text)
                self.assertIn("SQL Injection", page.text)  # COMP_A's own
                self.assertNotIn("XML External Entity", page.text)  # COMP_B's, hidden
                self.assertNotIn("xxe", page.text)

    def test_contestant_cannot_view_other_competition_404(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # member of COMP_A only, NOT COMP_B
            for path in ("play", "roster", "challenges"):
                resp = client.get(f"/app/competitions/{ws.COMP_B}/{path}")
                self.assertEqual(
                    resp.status_code, 404, f"{path} should be existence-hiding 404"
                )
                # The generic not-found page must not confirm the competition id.
                self.assertNotIn(ws.COMP_B, resp.text)

    def test_teamless_contestant_gets_friendly_roster_not_500(self) -> None:
        with ws.web_client() as (client, db, _svc):
            # EVE is a teamless player in COMP_A by default (team_name=None).
            ws.add_team(db, ws.COMP_A, "Blue")
            ws.add_user(db, _FRANK, "Frank")
            ws.place_on_team(db, _FRANK, ws.COMP_A, "Blue")

            ws.login(client, ws.EVE)
            roster = client.get(f"/app/competitions/{ws.COMP_A}/roster")
            self.assertEqual(roster.status_code, 200, roster.text)
            self.assertIn("not on a team", roster.text.lower())  # friendly message
            self.assertNotIn(_FRANK, roster.text)  # NOT another team's data
            self.assertNotIn("style=", roster.text)

            # The play page also renders for a teamless contestant (no 500).
            play = client.get(f"/app/competitions/{ws.COMP_A}/play")
            self.assertEqual(play.status_code, 200, play.text)
            self.assertIn("not on a team", play.text.lower())

    def test_play_landing_lists_only_authorized_competitions(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # member of COMP_A only
            resp = client.get("/app/play")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn(ws.COMP_A, resp.text)
            self.assertNotIn(ws.COMP_B, resp.text)  # not a member -> not listed

    def test_unrestricted_organizer_roster_sees_all_teams(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.add_team(db, ws.COMP_A, "Red")
            ws.add_team(db, ws.COMP_A, "Blue")
            ws.place_on_team(db, ws.EVE, ws.COMP_A, "Red")
            ws.add_user(db, _FRANK, "Frank")
            ws.place_on_team(db, _FRANK, ws.COMP_A, "Blue")

            ws.login(client, ws.ALICE)  # organizer of COMP_A: tenancy-unrestricted
            roster = client.get(f"/app/competitions/{ws.COMP_A}/roster")
            self.assertEqual(roster.status_code, 200, roster.text)
            self.assertIn(ws.EVE, roster.text)
            self.assertIn(_FRANK, roster.text)  # sees BOTH teams
            self.assertNotIn("style=", roster.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
