"""PostgreSQL integration tests for the M12b CONTESTANT web WRITE surface.

A player/captain can submit a flag for ONE published challenge and read their OWN
team's submission history -- and nothing more. The invariants under test:

* a team-scoped contestant submitting the CORRECT flag gets a first-solve result
  and the ledger records a solve FOR THEIR TEAM (verified via the query service);
  a WRONG flag is a friendly "incorrect" (no solve, no 500);
* a double-POST of the SAME rendered form (same idempotency nonce) replays onto the
  same submission -- it never creates two rows / two solves;
* a POST without the CSRF token is 403 and records NOTHING;
* TENANCY is structural: there is no team field to tamper, so a contestant only
  ever records under their OWN team, and a COMP_A contestant gets an
  existence-hiding 404 on COMP_B's submit / history routes;
* a teamless contestant gets a friendly "not on a team" submit page + empty
  history -- never a 500, never another team's rows;
* the own-team history shows ONLY the caller's team (a seeded other-team submission
  is absent) and leaks no flag / answer / session token / password / inline style;
* a misconfigured published challenge (spec with NO flag) surfaces a friendly
  "misconfigured" message, never a 500.

SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_contestant_submit_integration
"""

from __future__ import annotations

import os
import re
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

# The known planted flag the SpecFlagVerifier compares against ``spec['flag']``.
_FLAG = "FLAG{web-submit-correct}"
_PRIVATE = "PRIVATE-SCENARIO-SOLUTION-xyz"
_FRANK = "frank@example.com"

_NONCE_RE = re.compile(r'name="idempotency_nonce" value="([^"]+)"')


def _extract_nonce(html: str) -> str | None:
    match = _NONCE_RE.search(html)
    return match.group(1) if match else None


def _seed_flagged(db, *, slug: str = "sqli", title: str = "SQL Injection") -> tuple[str, int]:
    """Publish a challenge carrying the KNOWN flag (+ a planted private field) into
    COMP_A and return ``(slug, version_no)``."""
    s, ver = ws.seed_published_version(
        db, slug, title, family="web",
        spec={"title": title, "flag": _FLAG, "solution": _PRIVATE},
    )
    ws.attach_publication(db, ws.COMP_A, s, ver)
    return s, ver


def _place_eve_on_red(db) -> None:
    ws.add_team(db, ws.COMP_A, "Red")
    ws.add_team(db, ws.COMP_A, "Blue")
    ws.place_on_team(db, ws.EVE, ws.COMP_A, "Red")


def _submit_path(slug: str, ver: int, cid: str | None = None) -> str:
    # Default resolved INSIDE the body -- ``ws`` does not exist when the extras
    # are absent, and a default-argument ``ws.COMP_A`` evaluates at import time.
    if cid is None:
        cid = ws.COMP_A
    return f"/app/competitions/{cid}/challenges/{slug}/{ver}/submit"


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ContestantSubmitWebTests(unittest.TestCase):
    def _open_form(self, client, slug, ver, cid=None):
        """GET the submit form, returning (response, csrf_token, nonce)."""
        resp = client.get(_submit_path(slug, ver, cid))
        return resp, ws.extract_csrf(resp.text), _extract_nonce(resp.text)

    # -- correctness --------------------------------------------------------

    def test_correct_flag_records_first_solve_for_own_team(self) -> None:
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)

            form, csrf, nonce = self._open_form(client, slug, ver)
            self.assertEqual(form.status_code, 200, form.text)
            self.assertIn("Red", form.text)  # team it will be recorded for
            self.assertIsNotNone(csrf)
            self.assertIsNotNone(nonce)

            resp = client.post(
                _submit_path(slug, ver),
                data={"csrf_token": csrf, "idempotency_nonce": nonce, "answer": _FLAG},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("Correct", resp.text)
            self.assertIn("First solve", resp.text)

            # The ledger records exactly one submission for RED, correct, and none
            # for BLUE -- the team was server-derived, never from the request.
            red = ws.team_submissions(db, ws.COMP_A, "Red")
            self.assertEqual(len(red), 1)
            self.assertTrue(red[0].correct)
            self.assertEqual(red[0].team_name, "Red")
            self.assertEqual(ws.team_submissions(db, ws.COMP_A, "Blue"), [])

            # A second correct submission (fresh form -> fresh nonce) proves a Solve
            # persisted: it is now a duplicate, not another first solve.
            form2, csrf2, nonce2 = self._open_form(client, slug, ver)
            dup = client.post(
                _submit_path(slug, ver),
                data={"csrf_token": csrf2, "idempotency_nonce": nonce2, "answer": _FLAG},
            )
            self.assertEqual(dup.status_code, 200, dup.text)
            self.assertIn("already solved", dup.text.lower())
            self.assertNotIn("First solve", dup.text)

    def test_wrong_flag_is_incorrect_not_500(self) -> None:
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)

            _form, csrf, nonce = self._open_form(client, slug, ver)
            resp = client.post(
                _submit_path(slug, ver),
                data={
                    "csrf_token": csrf,
                    "idempotency_nonce": nonce,
                    "answer": "definitely-wrong",
                },
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("Incorrect", resp.text)

            red = ws.team_submissions(db, ws.COMP_A, "Red")
            self.assertEqual(len(red), 1)
            self.assertFalse(red[0].correct)  # recorded, but no solve

    # -- idempotency --------------------------------------------------------

    def test_double_post_same_nonce_replays_once(self) -> None:
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)

            _form, csrf, nonce = self._open_form(client, slug, ver)
            first = client.post(
                _submit_path(slug, ver),
                data={"csrf_token": csrf, "idempotency_nonce": nonce, "answer": _FLAG},
            )
            self.assertEqual(first.status_code, 200, first.text)
            # Resubmit the SAME rendered form (identical nonce), e.g. a refresh.
            second = client.post(
                _submit_path(slug, ver),
                data={"csrf_token": csrf, "idempotency_nonce": nonce, "answer": _FLAG},
            )
            self.assertEqual(second.status_code, 200, second.text)

            # Exactly one submission for Red -- the second POST replayed.
            self.assertEqual(len(ws.team_submissions(db, ws.COMP_A, "Red")), 1)

    # -- CSRF ---------------------------------------------------------------

    def test_post_without_csrf_is_403_and_records_nothing(self) -> None:
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)

            _form, _csrf, nonce = self._open_form(client, slug, ver)
            resp = client.post(
                _submit_path(slug, ver),
                data={"idempotency_nonce": nonce, "answer": _FLAG},  # NO csrf_token
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(ws.team_submissions(db, ws.COMP_A, "Red"), [])

    # -- tenancy: cross-competition existence hiding ------------------------

    def test_cross_competition_submit_and_history_are_404(self) -> None:
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)  # member of COMP_A only, NOT COMP_B

            # GET submit form + history for COMP_B -> existence-hiding 404.
            for path in (
                _submit_path(slug, ver, cid=ws.COMP_B),
                f"/app/competitions/{ws.COMP_B}/submissions",
            ):
                resp = client.get(path)
                self.assertEqual(resp.status_code, 404, f"{path}: {resp.text}")
                self.assertNotIn(ws.COMP_B, resp.text)

            # POST to COMP_B's submit route WITH a valid session CSRF (reused from a
            # COMP_A page, same session) still 404s -- the auth check precedes the
            # body, so nothing is recorded and the competition id is not confirmed.
            _f, csrf, nonce = self._open_form(client, slug, ver)
            resp = client.post(
                _submit_path(slug, ver, cid=ws.COMP_B),
                data={"csrf_token": csrf, "idempotency_nonce": nonce, "answer": _FLAG},
            )
            self.assertEqual(resp.status_code, 404, resp.text)
            self.assertNotIn(ws.COMP_B, resp.text)

    def test_injected_team_form_field_is_ignored(self) -> None:
        # A direct positive guard on the tenancy invariant: the submission team is
        # server-derived from membership and NEVER read from the request. EVE (Red)
        # POSTs an extra team=Blue / team_name=Blue field; it must be ignored -- the
        # attempt records under Red, and Blue stays empty. (A regression like
        # `team = form.get("team", team)` would break this while every other test,
        # none of which sends a team field, still passes.)
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)

            _form, csrf, nonce = self._open_form(client, slug, ver)
            resp = client.post(
                _submit_path(slug, ver),
                data={
                    "csrf_token": csrf,
                    "idempotency_nonce": nonce,
                    "answer": _FLAG,
                    "team": "Blue",  # hostile injected fields -- must be ignored
                    "team_name": "Blue",
                },
            )
            self.assertEqual(resp.status_code, 200, resp.text)

            red = ws.team_submissions(db, ws.COMP_A, "Red")
            self.assertEqual(len(red), 1)
            self.assertEqual(red[0].team_name, "Red")  # recorded under the OWN team
            self.assertEqual(ws.team_submissions(db, ws.COMP_A, "Blue"), [])

    # -- teamless: fail closed ---------------------------------------------

    def test_teamless_contestant_cannot_submit_and_has_empty_history(self) -> None:
        with ws.web_client() as (client, db, _svc):
            # EVE is a teamless player in COMP_A by default (team_name=None).
            slug, ver = _seed_flagged(db)
            ws.login(client, ws.EVE)

            form = client.get(_submit_path(slug, ver))
            self.assertEqual(form.status_code, 200, form.text)
            self.assertIn("not on a team", form.text.lower())
            self.assertNotIn('name="answer"', form.text)  # no submit form rendered

            history = client.get(f"/app/competitions/{ws.COMP_A}/submissions")
            self.assertEqual(history.status_code, 200, history.text)
            self.assertIn("not on a team", history.text.lower())

            # Even a forged POST (session CSRF, fabricated nonce) fails closed to the
            # no-team page -- never a 500, and records nothing anywhere.
            csrf = ws.extract_csrf(form.text)
            resp = client.post(
                _submit_path(slug, ver),
                data={"csrf_token": csrf, "idempotency_nonce": "x", "answer": _FLAG},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("not on a team", resp.text.lower())

    # -- history isolation + no leaks --------------------------------------

    def test_history_shows_only_own_team_and_leaks_nothing(self) -> None:
        with ws.web_client() as (client, db, _svc):
            slug, ver = _seed_flagged(db)  # "sqli" / "SQL Injection" -> COMP_A
            _place_eve_on_red(db)
            # A DIFFERENT challenge that only BLUE submits, so its identity is
            # distinguishable in EVE's Red-only history if a tenancy bug leaked it.
            other_slug, other_ver = ws.seed_published_version(
                db, "xxe", "XML External Entity", family="web",
                spec={"title": "XML External Entity", "flag": _FLAG},
            )
            ws.attach_publication(db, ws.COMP_A, other_slug, other_ver)
            ws.add_user(db, _FRANK, "Frank")
            ws.place_on_team(db, _FRANK, ws.COMP_A, "Blue")
            ws.record_submission(db, ws.COMP_A, "Blue", other_slug, other_ver, _FLAG)

            ws.login(client, ws.EVE)
            # EVE records an (incorrect) attempt for Red so her history is non-empty;
            # the answer string must never appear in the rendered history.
            _f, csrf, nonce = self._open_form(client, slug, ver)
            client.post(
                _submit_path(slug, ver),
                data={
                    "csrf_token": csrf,
                    "idempotency_nonce": nonce,
                    "answer": "eve-red-attempt",
                },
            )

            history = client.get(f"/app/competitions/{ws.COMP_A}/submissions")
            self.assertEqual(history.status_code, 200, history.text)
            self.assertIn("SQL Injection", history.text)  # Red's own challenge
            # Blue's challenge (submitted only by Blue) must be ABSENT.
            self.assertNotIn("XML External Entity", history.text)
            self.assertNotIn("xxe", history.text)
            # No secret / answer / credential leaks.
            self.assertNotIn(_FLAG, history.text)
            self.assertNotIn(_PRIVATE, history.text)
            self.assertNotIn("eve-red-attempt", history.text)  # answer inbound-only
            self.assertNotIn("style=", history.text)
            self.assertNotIn(ws.PASSWORD, history.text)
            token = ws.session_cookie(client)
            if token:
                self.assertNotIn(token, history.text)

    # -- misconfigured challenge -------------------------------------------

    def test_misconfigured_challenge_is_friendly_not_500(self) -> None:
        with ws.web_client() as (client, db, _svc):
            # Published but the spec carries NO flag -> FlagUnavailableError.
            slug, ver = ws.seed_published_version(
                db, "broken", "Broken Challenge", family="web",
                spec={"title": "Broken Challenge"},
            )
            ws.attach_publication(db, ws.COMP_A, slug, ver)
            _place_eve_on_red(db)
            ws.login(client, ws.EVE)

            _f, csrf, nonce = self._open_form(client, slug, ver)
            resp = client.post(
                _submit_path(slug, ver),
                data={"csrf_token": csrf, "idempotency_nonce": nonce, "answer": _FLAG},
            )
            self.assertIn(resp.status_code, (200, 400), resp.text)  # never a 500
            self.assertIn("misconfigured", resp.text.lower())
            # Nothing recorded: the verifier raises BEFORE the attempt is persisted.
            self.assertEqual(ws.team_submissions(db, ws.COMP_A, "Red"), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
