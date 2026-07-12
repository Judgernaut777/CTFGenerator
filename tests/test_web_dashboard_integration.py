"""PostgreSQL integration tests for the M11 web read views (authz scoping).

An authenticated organizer sees ONLY its own competitions on /app and
/app/competitions; a system admin sees all; a competition detail the caller is not
authorized for is an existence-hiding 404 page (no existence/flag leak) -- the
SAME M10b scoping as the JSON API, never a weaker UI path. No secret/token appears
in any rendered page. SKIPS cleanly without the extras / CTFGEN_TEST_DATABASE_URL.
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


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebDashboardScopingTests(unittest.TestCase):
    def test_organizer_sees_only_their_competition(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A only
            dash = client.get("/app/")
            self.assertEqual(dash.status_code, 200, dash.text)
            self.assertIn(ws.COMP_A, dash.text)
            self.assertNotIn(ws.COMP_B, dash.text)

            lst = client.get("/app/competitions")
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertIn(ws.COMP_A, lst.text)
            self.assertNotIn(ws.COMP_B, lst.text)

    def test_system_admin_sees_all_competitions(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.DAVE)  # system admin
            lst = client.get("/app/competitions")
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertIn(ws.COMP_A, lst.text)
            self.assertIn(ws.COMP_B, lst.text)

    def test_authorized_detail_renders_config(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            detail = client.get(f"/app/competitions/{ws.COMP_A}")
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertIn("Alpha CTF", detail.text)
            self.assertIn(ws.COMP_A, detail.text)
            self.assertIn("Start", detail.text)  # timing window rendered

    def test_unauthorized_detail_is_existence_hiding_404(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A, NOT B
            # A competition that exists but the caller cannot access must look
            # exactly like one that does not exist: a generic 404 page, no name,
            # no config, no existence oracle.
            r = client.get(f"/app/competitions/{ws.COMP_B}")
            self.assertEqual(r.status_code, 404, r.text)
            self.assertIn("Not found", r.text)
            self.assertNotIn("Bravo CTF", r.text)  # the real name never leaks
            self.assertNotIn("Default scoring", r.text)

            # A truly nonexistent id yields the SAME 404 page (indistinguishable).
            missing = client.get("/app/competitions/does-not-exist")
            self.assertEqual(missing.status_code, 404, missing.text)
            self.assertIn("Not found", missing.text)

    def test_no_secret_or_token_in_any_rendered_page(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.DAVE)  # admin: can see everything
            token = ws.session_cookie(client)
            self.assertTrue(token)
            for path in (
                "/app/",
                "/app/competitions",
                f"/app/competitions/{ws.COMP_A}",
                f"/app/competitions/{ws.COMP_B}",
            ):
                page = client.get(path)
                self.assertEqual(page.status_code, 200, page.text)
                body = page.text
                self.assertNotIn(token, body)
                # No password / hash / credential material renders.
                self.assertNotIn(ws.PASSWORD, body)
                self.assertNotIn("password_hash", body)
                self.assertNotIn("pbkdf2", body.lower())

    def test_promoted_membership_grants_web_visibility(self) -> None:
        # Positive control that scoping is membership-driven: grant Alice a role in
        # B and she now sees B too (proves the earlier hiding was authorization,
        # not a rendering accident).
        with ws.web_client() as (client, db, _svc):
            ws.grant_membership(db, ws.ALICE, ws.COMP_B, "organizer")
            ws.login(client, ws.ALICE)
            lst = client.get("/app/competitions")
            self.assertIn(ws.COMP_A, lst.text)
            self.assertIn(ws.COMP_B, lst.text)
            self.assertEqual(
                client.get(f"/app/competitions/{ws.COMP_B}").status_code, 200
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
