"""PostgreSQL integration tests for the M11b organizer PUBLICATION flows.

Attach a published challenge version to a competition (ok -> 303 + listed; duplicate
-> field error; unknown / malformed version -> field error, never a 500); detach
(ok -> 303 + gone); authz scoping (an organizer of A cannot touch B's publications
-- existence-hiding 404; a contestant lacking publication:read/write is 404); CSRF
(a POST without the session-bound token is 403, nothing persisted); no ``style=``
attribute / no secret leaks. SKIPS cleanly without the extras /
``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_publication_write_integration
"""

from __future__ import annotations

import os
import unittest

try:
    import web_support as ws

    from ctf_generator.application.catalog.publication_service import PublicationService

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


def _pub_slugs(db, competition_id):
    return [p.definition_slug for p in PublicationService(db).list_for_competition(competition_id)]


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class PublicationWriteTests(unittest.TestCase):
    def test_attach_ok_then_detach(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            self.assertEqual(r.status_code, 200, r.text)
            self.assertIn("sqli", r.text)  # the catalog choice is offered

            attach = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"csrf_token": token, "publication_target": "sqli:1"},
                follow_redirects=False,
            )
            self.assertEqual(attach.status_code, 303, attach.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), ["sqli"])

            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            detach = client.post(
                f"/app/competitions/{ws.COMP_A}/publications/detach",
                data={"csrf_token": token, "definition_slug": "sqli", "version_no": "1"},
                follow_redirects=False,
            )
            self.assertEqual(detach.status_code, 303, detach.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), [])

    def test_duplicate_attach_is_field_error(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"csrf_token": token, "publication_target": "sqli:1"},
                follow_redirects=False,
            )
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            dup = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"csrf_token": token, "publication_target": "sqli:1"},
                follow_redirects=False,
            )
            self.assertEqual(dup.status_code, 409, dup.text)
            self.assertIn("already attached", dup.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), ["sqli"])

    def test_unknown_version_is_field_error_not_500(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"csrf_token": token, "publication_target": "sqli:99"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 404, resp.text)
            self.assertIn("was not found", resp.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), [])

    def test_out_of_range_version_is_field_error_not_500(self) -> None:
        # A client-tampered version_no above INT32 must be a field error, never a
        # DB DataError 500 (the "never a 500" invariant).
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={
                    "csrf_token": token,
                    "publication_target": "sqli:999999999999999999999999",
                },
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertIn("Choose a challenge version.", resp.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), [])

    def test_detach_out_of_range_version_is_not_500(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications/detach",
                data={
                    "csrf_token": token,
                    "definition_slug": "sqli",
                    "version_no": "999999999999999999999999",
                },
                follow_redirects=False,
            )
            self.assertNotEqual(resp.status_code, 500, resp.text)
            self.assertEqual(resp.status_code, 404, resp.text)

    def test_malformed_target_is_field_error(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"csrf_token": token, "publication_target": "not-a-pair"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertIn("Choose a challenge version.", resp.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), [])

    def test_organizer_cannot_touch_other_competition_404(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)  # organizer of A, not B
            self.assertEqual(
                client.get(f"/app/competitions/{ws.COMP_B}/publications").status_code, 404
            )
            resp = client.post(
                f"/app/competitions/{ws.COMP_B}/publications",
                data={"publication_target": "sqli:1"},
                follow_redirects=False,
            )
            self.assertIn(resp.status_code, (404, 403))
            self.assertEqual(_pub_slugs(db, ws.COMP_B), [])

    def test_contestant_cannot_view_or_attach(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.EVE)  # player of A: no publication:read/write
            self.assertEqual(
                client.get(f"/app/competitions/{ws.COMP_A}/publications").status_code, 404
            )
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"publication_target": "sqli:1"},
                follow_redirects=False,
            )
            self.assertIn(resp.status_code, (404, 403))
            self.assertEqual(_pub_slugs(db, ws.COMP_A), [])

    def test_attach_without_csrf_is_403(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"publication_target": "sqli:1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), [])

    def test_detach_without_csrf_is_403(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}/publications")
            client.post(
                f"/app/competitions/{ws.COMP_A}/publications",
                data={"csrf_token": token, "publication_target": "sqli:1"},
                follow_redirects=False,
            )
            resp = client.post(
                f"/app/competitions/{ws.COMP_A}/publications/detach",
                data={"definition_slug": "sqli", "version_no": "1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_pub_slugs(db, ws.COMP_A), ["sqli"])  # still attached

    def test_no_style_attribute_or_secret_on_publications_page(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.seed_published_version(db, "sqli", "SQL Injection")
            ws.login(client, ws.ALICE)
            token = ws.session_cookie(client)
            page = client.get(f"/app/competitions/{ws.COMP_A}/publications")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertNotIn("style=", page.text)
            self.assertNotIn(token, page.text)
            self.assertNotIn(ws.PASSWORD, page.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
