"""PostgreSQL integration tests for the M11b organizer competition WRITE flows.

Create (valid -> 303 + persisted; invalid window -> re-render with the field error,
NOTHING created, input preserved); edit (valid persists; invalid re-renders); authz
(create gated on the flat competition:write -- a contestant is 403; an organizer of
A editing B is an existence-hiding 404); CSRF (a POST without the session-bound
token is 403 and persists nothing). Every rendered page is autoescaped, carries no
``style=`` attribute, and leaks no session token / password. SKIPS cleanly without
the ``[api]``/``[web]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_competition_write_integration

NOTE (membership-on-create): creating a competition does NOT auto-enrol the creator
as an organizer of it -- exactly like the JSON API's flat POST /competitions. So a
non-admin organizer who creates one is redirected (303) to its detail but, having no
membership there, gets the scoped 404 until a membership is granted. Auto-enrolment
belongs with membership management and is deferred (M11c / M12); admin-created
competitions are viewable end-to-end today.
"""

from __future__ import annotations

import os
import unittest

try:
    import web_support as ws

    from ctf_generator.application.catalog import CompetitionService

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


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CompetitionWriteTests(unittest.TestCase):
    # -- create ------------------------------------------------------------

    def test_create_valid_redirects_and_persists(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, "/app/competitions/new")
            resp = client.post(
                "/app/competitions/new",
                data={
                    "csrf_token": token,
                    "competition_id": "gamma-ctf",
                    "name": "Gamma CTF",
                    "start_time": "2026-09-01T10:00",
                    "end_time": "2026-09-03T10:00",
                    "scoring_start_time": "2026-09-01T10:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            self.assertTrue(resp.headers["location"].endswith("/app/competitions/gamma-ctf"))
            stored = CompetitionService(db).get("gamma-ctf")
            self.assertIsNotNone(stored)
            self.assertEqual(stored.name, "Gamma CTF")

    def test_create_invalid_window_rerenders_and_persists_nothing(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, "/app/competitions/new")
            resp = client.post(
                "/app/competitions/new",
                data={
                    "csrf_token": token,
                    "competition_id": "bad-window",
                    "name": "Bad Window",
                    # end BEFORE start -> the window invariant fails.
                    "start_time": "2026-09-05T10:00",
                    "end_time": "2026-09-01T10:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            # Field-level message rendered, input preserved, NO 500, nothing created.
            self.assertIn("must be after start_time", resp.text)
            self.assertIn("bad-window", resp.text)  # entered slug preserved
            self.assertIn("Bad Window", resp.text)  # entered name preserved
            self.assertIsNone(CompetitionService(db).get("bad-window"))

    def test_create_duplicate_id_is_field_error_not_500(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, "/app/competitions/new")
            # COMP_A already exists in the seed.
            resp = client.post(
                "/app/competitions/new",
                data={
                    "csrf_token": token,
                    "competition_id": ws.COMP_A,
                    "name": "Clashing",
                    "start_time": "2026-09-01T10:00",
                    "end_time": "2026-09-03T10:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 409, resp.text)
            self.assertIn("already exists", resp.text)

    # -- edit --------------------------------------------------------------

    def test_edit_valid_update_persists(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/edit")
            self.assertEqual(r.status_code, 200, r.text)
            self.assertIn("Alpha CTF", r.text)  # pre-filled from the current config
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/edit",
                data={
                    "csrf_token": token,
                    "name": "Alpha CTF (renamed)",
                    "start_time": "2026-07-12T12:00",
                    "end_time": "2026-07-14T12:00",
                    "scoring_start_time": "2026-07-12T12:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            self.assertEqual(CompetitionService(db).get(ws.COMP_A).name, "Alpha CTF (renamed)")

    def test_edit_invalid_window_rerenders(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/edit")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/edit",
                data={
                    "csrf_token": token,
                    "name": "Alpha CTF",
                    "start_time": "2026-07-20T12:00",
                    "end_time": "2026-07-14T12:00",  # end before start
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertIn("must be after start_time", resp.text)
            # Unchanged in the store (still the seed name).
            self.assertEqual(CompetitionService(db).get(ws.COMP_A).name, "Alpha CTF")

    # -- authz -------------------------------------------------------------

    def test_contestant_cannot_reach_create(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # player of A -- no competition:write anywhere
            self.assertEqual(client.get("/app/competitions/new").status_code, 403)
            resp = client.post(
                "/app/competitions/new",
                data={
                    "competition_id": "sneaky",
                    "name": "Sneaky",
                    "start_time": "2026-09-01T10:00",
                    "end_time": "2026-09-03T10:00",
                },
                follow_redirects=False,
            )
            # No CSRF present either; but the flat-authz denial is the outer gate.
            self.assertIn(resp.status_code, (403,))
            self.assertIsNone(CompetitionService(db).get("sneaky"))

    def test_unauthenticated_create_redirects_to_login(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            resp = client.get("/app/competitions/new", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/app/login", resp.headers["location"])

    def test_organizer_cannot_edit_other_competition_404(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A, NOT B
            r = client.get(f"/app/competitions/{ws.COMP_B}/edit")
            self.assertEqual(r.status_code, 404, r.text)
            self.assertNotIn("Bravo CTF", r.text)  # existence-hiding: no name leak
            # A truly nonexistent id is the SAME 404.
            self.assertEqual(client.get("/app/competitions/nope/edit").status_code, 404)
            # And a POST is denied identically (nothing mutated).
            resp = client.post(
                f"/app/competitions/{ws.COMP_B}/edit",
                data={
                    "name": "hijacked",
                    "start_time": "2026-07-12T12:00",
                    "end_time": "2026-07-14T12:00",
                },
                follow_redirects=False,
            )
            self.assertIn(resp.status_code, (404, 403))
            self.assertEqual(CompetitionService(db).get(ws.COMP_B).name, "Bravo CTF")

    # -- CSRF --------------------------------------------------------------

    def test_create_without_csrf_is_403_and_persists_nothing(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            resp = client.post(
                "/app/competitions/new",
                data={
                    "competition_id": "no-token",
                    "name": "No Token",
                    "start_time": "2026-09-01T10:00",
                    "end_time": "2026-09-03T10:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertIsNone(CompetitionService(db).get("no-token"))

    def test_edit_without_csrf_is_403(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/edit",
                data={
                    "name": "no-token-edit",
                    "start_time": "2026-07-12T12:00",
                    "end_time": "2026-07-14T12:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(CompetitionService(db).get(ws.COMP_A).name, "Alpha CTF")

    # -- XSS / no-style / no-secret cross-cutting --------------------------

    def test_hostile_name_is_escaped_on_render(self) -> None:
        # DAVE is a system admin (sees every competition), so he can create AND then
        # view the created competition's detail. (An organizer is not auto-enrolled
        # in a competition it creates -- see the module note -- so it would land on a
        # scoped 404; that membership-on-create gap is deferred, not an escaping bug.)
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.DAVE)
            _r, token = _csrf(client, "/app/competitions/new")
            resp = client.post(
                "/app/competitions/new",
                data={
                    "csrf_token": token,
                    "competition_id": "xss-comp",
                    "name": "<script>alert(1)</script>",
                    "start_time": "2026-09-01T10:00",
                    "end_time": "2026-09-03T10:00",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            # Stored verbatim, rendered ESCAPED (the raw tag never appears).
            detail = client.get("/app/competitions/xss-comp")
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertNotIn("<script>alert(1)</script>", detail.text)
            self.assertIn("&lt;script&gt;", detail.text)

    def test_no_style_attribute_and_no_secret_on_write_pages(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            token = ws.session_cookie(client)
            self.assertTrue(token)
            for path in (
                "/app/competitions/new",
                f"/app/competitions/{ws.COMP_A}/edit",
            ):
                page = client.get(path)
                self.assertEqual(page.status_code, 200, page.text)
                body = page.text
                # M11a regression guard: styling lives in the nonce'd <style>, never
                # in a style= attribute (the CSP admits no style attributes).
                self.assertNotIn("style=", body)
                self.assertNotIn(token, body)  # session token never rendered
                self.assertNotIn(ws.PASSWORD, body)
                self.assertNotIn("pbkdf2", body.lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
