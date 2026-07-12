"""PostgreSQL integration tests for the M11c SCOREBOARD organizer view.

Standings render from the read-only projection, competition-scoped SCOREBOARD_READ;
a cross-competition caller is an existence-hiding 404 (never weaker than the API's
scoped check); no flag/secret is ever rendered. A GET never folds the ledger.
SKIPS cleanly without the extras / test DB.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_scoreboard_view_integration
"""

from __future__ import annotations

import os
import unittest

try:
    import web_support as ws

    from ctf_generator.domain.ledger.models import ScoreboardProjectionRecord
    from ctf_generator.infrastructure.database.score_projection_repository import (
        SqlAlchemyScoreboardProjectionRepository,
    )

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

_FLAG = "CTF{scoreboard-must-not-render-a-flag}"


def _seed_standings(db, competition_id: str) -> None:
    with db.session_scope() as s:
        SqlAlchemyScoreboardProjectionRepository(s).upsert(
            ScoreboardProjectionRecord(
                competition_id=competition_id,
                as_of_seq=2,
                entries={
                    "entries": [
                        {
                            "team_id": "Red",
                            "score": 900,
                            "solve_count": 2,
                            "rank": 1,
                            "last_solve_at": "2026-07-12T13:00:00+00:00",
                        },
                        {
                            "team_id": "Blue",
                            "score": 400,
                            "solve_count": 1,
                            "rank": 2,
                            "last_solve_at": "2026-07-12T12:30:00+00:00",
                        },
                    ]
                },
            )
        )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ScoreboardViewWebTests(unittest.TestCase):
    def test_standings_render_scoped(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer of COMP_A
            _seed_standings(db, ws.COMP_A)
            page = client.get(f"/app/competitions/{ws.COMP_A}/scoreboard")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn("Red", page.text)
            self.assertIn("Blue", page.text)
            self.assertIn("900", page.text)
            self.assertNotIn("style=", page.text)
            self.assertNotIn("CTF{", page.text)
            self.assertNotIn(_FLAG, page.text)

    def test_contestant_scoped_read_ok(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # player in COMP_A: SCOREBOARD_READ
            _seed_standings(db, ws.COMP_A)
            page = client.get(f"/app/competitions/{ws.COMP_A}/scoreboard")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn("Red", page.text)

    def test_cross_competition_caller_is_404(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A, NOT B
            _seed_standings(db, ws.COMP_B)
            self.assertEqual(
                client.get(f"/app/competitions/{ws.COMP_B}/scoreboard").status_code,
                404,
            )

    def test_empty_standings_render(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            page = client.get(f"/app/competitions/{ws.COMP_A}/scoreboard")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn("No standings yet", page.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
