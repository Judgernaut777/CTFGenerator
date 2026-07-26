"""PostgreSQL integration tests for the reports organizer web view.

A report page renders read-only summaries of already-stored data and can FREEZE an
immutable snapshot. Authorization mirrors the JSON API exactly: the version-scoped
kinds ride a FLAT authoring permission (an organizer holds it, a contestant does
not -> 403); the competition-run report is competition-scoped on SCOREBOARD_READ
(a cross-competition caller is an existence-hiding 404). No flag/secret is ever
rendered. SKIPS cleanly without the extras / test DB.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_reports_view_integration
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

_FLAG = "CTF{report-page-must-not-render-a-flag}"


def _post_snapshot(client, url: str):
    """POST a freeze with the page's CSRF token, not following the redirect."""
    page = client.get(url)
    token = ws.extract_csrf(page.text)
    return client.post(
        url, data={"csrf_token": token}, follow_redirects=False
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class VersionReportsWebTests(unittest.TestCase):
    def test_organizer_can_view_and_freeze_validation_report(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer -> flat build:read
            slug, vno = ws.seed_published_version(
                db, "sqli", "SQLi", spec={"title": "SQLi", "flag": _FLAG}
            )
            base = f"/app/challenge-definitions/{slug}/versions/{vno}/reports/validation"
            page = client.get(base)
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn("validation report", page.text)
            self.assertIn("No snapshots yet", page.text)

            frozen = _post_snapshot(client, base)
            self.assertEqual(frozen.status_code, 303, frozen.text)

            after = client.get(base)
            self.assertEqual(after.status_code, 200, after.text)
            self.assertIn("Latest snapshot", after.text)
            self.assertIn("error_count", after.text)  # a payload field is rendered
            # The private flag never reaches the page.
            self.assertNotIn("CTF{", after.text)
            self.assertNotIn(_FLAG, after.text)

    def test_build_and_eval_pages_render_for_organizer(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            slug, vno = ws.seed_published_version(db, "web1", "Web One")
            for kind in ("build", "eval"):
                page = client.get(
                    f"/app/challenge-definitions/{slug}/versions/{vno}/reports/{kind}"
                )
                self.assertEqual(page.status_code, 200, page.text)
                self.assertIn(f"{kind} report", page.text)

    def test_contestant_forbidden_on_version_report(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # player: no flat build:read / eval:read
            slug, vno = ws.seed_published_version(db, "sqli", "SQLi")
            for kind in ("validation", "build", "eval"):
                r = client.get(
                    f"/app/challenge-definitions/{slug}/versions/{vno}/reports/{kind}"
                )
                self.assertEqual(r.status_code, 403, r.text)

    def test_freeze_unknown_version_is_404(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            base = "/app/challenge-definitions/nope/versions/1/reports/validation"
            r = _post_snapshot(client, base)
            self.assertEqual(r.status_code, 404, r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CompetitionRunReportWebTests(unittest.TestCase):
    def test_organizer_can_view_and_freeze_run_report(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)  # organizer of COMP_A
            url = f"/app/competitions/{ws.COMP_A}/reports/run"
            page = client.get(url)
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn("Competition run report", page.text)

            frozen = _post_snapshot(client, url)
            self.assertEqual(frozen.status_code, 303, frozen.text)

            after = client.get(url)
            self.assertIn("Latest snapshot", after.text)
            self.assertIn("competition_id", after.text)  # a payload field renders

    def test_contestant_can_read_own_competition_run(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.EVE)  # player of COMP_A: holds scoreboard:read there
            r = client.get(f"/app/competitions/{ws.COMP_A}/reports/run")
            self.assertEqual(r.status_code, 200, r.text)

    def test_cross_competition_caller_is_404(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A, NOT B
            self.assertEqual(
                client.get(f"/app/competitions/{ws.COMP_B}/reports/run").status_code,
                404,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
