#!/usr/bin/env python3
"""In-process capacity / load harness for the control-plane API (M20).

Drives ``create_app`` over a REAL PostgreSQL database through the Starlette
``TestClient`` (a real ASGI transport) from many concurrent OS threads, and
MEASURES:

* (a) submission-processing latency distribution (p50/p95/max) under ``N``
  concurrent submitters (REQ-NFR-005, target < 500 ms server-side);
* (b) scoreboard read latency under that same load (REQ-NFR-004, target < 3 s);
* (c) a launch-success PROXY -- probed, but see the HONEST LIMIT below.

It prints MEASURED percentiles next to the targets. It does NOT pass/fail the
SLOs and it does NOT weaken them: it reports what was measured, truthfully, at
whatever scale you asked for.

HONEST LIMIT (charter §5). This harness measures ONLY what is reachable
IN-PROCESS over one PostgreSQL:

* Submission processing and scoreboard reads ARE exercised end to end against
  real PG (real transactions, the 0008 outbox trigger, the projector fold).
* Instance LAUNCH SUCCESS (REQ-NFR-003, >= 99%) is NOT measured here. A real
  launch needs the M8 desired->observed reconciler driving a real isolated
  worker host that actually starts a container; none of that runs in-process.
  The harness probes only that the instances API surface answers, and reports
  launch success as UNVERIFIED with that reason -- it never fabricates a number.
* The full REQ-NFR-001/002 envelope (25 steady-state teams x 20 live
  challenges on a real multi-host deployment) is a deployment-scale sign-off
  (M21/M22), not an in-process run. Numbers here are a LOWER BOUND / harness
  proof, not the capacity sign-off.

Run (needs the ``[api]`` + ``[db]`` extras and a running PostgreSQL)::

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python scripts/loadtest.py --teams 8 --challenges 4 \\
        --submissions-per-team 25 --readers 3

It creates a throwaway database, migrates it to head, seeds a competition +
teams + published challenges, runs the load, prints the report, and drops the
database.
"""

from __future__ import annotations

import argparse
import math
import os
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field

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

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ADMIN = "admintoken"  # noqa: S105 - harness fixture token, not a real secret
_CID = "loadtest-ctf"


def percentile(values: list[float], p: float) -> float:
    """Linear-interpolated percentile (0<=p<=100). NaN for an empty sample."""
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    rank = (p / 100.0) * (len(s) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (rank - lo)


@dataclass
class LoadResult:
    """The MEASURED outcome of a run -- real numbers only."""

    teams: int
    challenges: int
    submissions_per_team: int
    readers: int
    duration_s: float
    submit_latencies_ms: list[float] = field(default_factory=list)
    scoreboard_latencies_ms: list[float] = field(default_factory=list)
    submit_ok: int = 0
    submit_err: int = 0
    read_ok: int = 0
    read_err: int = 0
    errors: list[str] = field(default_factory=list)
    launch_probe: dict = field(default_factory=dict)

    # -- submission (REQ-NFR-005, target < 500 ms) --------------------------
    @property
    def submit_p50_ms(self) -> float:
        return percentile(self.submit_latencies_ms, 50)

    @property
    def submit_p95_ms(self) -> float:
        return percentile(self.submit_latencies_ms, 95)

    @property
    def submit_max_ms(self) -> float:
        return max(self.submit_latencies_ms) if self.submit_latencies_ms else float("nan")

    # -- scoreboard (REQ-NFR-004, target < 3 s) -----------------------------
    @property
    def scoreboard_p50_ms(self) -> float:
        return percentile(self.scoreboard_latencies_ms, 50)

    @property
    def scoreboard_p95_ms(self) -> float:
        return percentile(self.scoreboard_latencies_ms, 95)

    @property
    def scoreboard_max_ms(self) -> float:
        return (
            max(self.scoreboard_latencies_ms)
            if self.scoreboard_latencies_ms
            else float("nan")
        )

    @property
    def submit_throughput_rps(self) -> float:
        return self.submit_ok / self.duration_s if self.duration_s > 0 else float("nan")


@contextmanager
def _isolated_database(base_url: str):
    """Create a throwaway database, yield its DSN, drop it on exit."""
    base = make_url(base_url)
    name = f"ctfgen_load_{uuid.uuid4().hex[:12]}"
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


def _alembic_config(url: str) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


def _team_token(i: int) -> str:
    return f"team{i}token"


def _team_name(i: int) -> str:
    return f"Team{i}"


def _slug(i: int) -> str:
    return f"chal-{i}"


def _flag(slug: str) -> str:
    return f"CTF{{flag-{slug}}}"


def _expect(response, code: int, what: str) -> None:
    """Fail loudly (not an ``assert``, so it survives ``python -O``) if a seed
    request did not return the expected status."""
    if response.status_code != code:
        raise RuntimeError(
            f"seed step {what!r} expected {code}, got {response.status_code}: "
            f"{response.text[:200]}"
        )


def _authenticator(teams: int) -> StubAuthenticator:
    tokens = {
        _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
    }
    for i in range(teams):
        tokens[_team_token(i)] = principal_for(
            f"player-{i}",
            {"player"},
            team=_team_name(i),
            memberships={_CID: ("player", _team_name(i))},
        )
    return StubAuthenticator(tokens)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed(client: TestClient, db: Database, teams: int, challenges: int) -> None:
    """One competition + ``teams`` teams + ``challenges`` published+attached
    challenges (each with a distinct flag)."""
    _expect(
        client.post(
            "/api/v1/competitions",
            headers=_auth(_ADMIN),
            json={
                "competition_id": _CID,
                "name": "Load Test CTF",
                "start_time": "2026-06-01T09:00:00Z",
                "end_time": "2026-06-03T09:00:00Z",
                "scoring_start_time": "2026-06-01T09:30:00Z",
                "freeze_time": "2026-06-02T09:00:00Z",
            },
        ),
        201,
        "create competition",
    )
    for i in range(teams):
        _expect(
            client.post(
                "/api/v1/teams",
                headers=_auth(_ADMIN),
                json={"competition_id": _CID, "name": _team_name(i)},
            ),
            201,
            f"create team {i}",
        )
    for i in range(challenges):
        slug = _slug(i)
        _expect(
            client.post(
                "/api/v1/challenge-definitions",
                headers=_auth(_ADMIN),
                json={"family": "web", "slug": slug, "title": f"Challenge {i}"},
            ),
            201,
            f"create definition {slug}",
        )
        _expect(
            client.post(
                "/api/v1/challenge-versions",
                headers=_auth(_ADMIN),
                json={
                    "definition_slug": slug,
                    "seed": f"seed-{i}",
                    "family_version": "1.0.0",
                    "spec": {"title": f"Challenge {i}", "flag": _flag(slug)},
                },
            ),
            201,
            f"create version {slug}",
        )
        _expect(
            client.post(
                f"/api/v1/challenge-versions/{slug}/1/publish", headers=_auth(_ADMIN)
            ),
            200,
            f"publish {slug}",
        )
    # No publication API endpoint -- attach directly via the repo (mirrors the
    # existing submissions integration test).
    with db.session_scope() as session:
        repo = SqlAlchemyChallengePublicationRepository(session)
        for i in range(challenges):
            repo.add(
                ChallengePublication(
                    competition_id=_CID, definition_slug=_slug(i), version_no=1
                )
            )


def _submitter(
    app,
    team_index: int,
    challenges: int,
    iterations: int,
    deadline: float | None,
    result: LoadResult,
    lock: threading.Lock,
    rng: random.Random,
) -> None:
    """One concurrent submitter: its OWN TestClient over the shared app, so the
    httpx client is never shared across threads. Measures wall-clock latency per
    ``POST .../submissions`` (the whole server-side attempt->verify->commit)."""
    client = TestClient(app)
    token = _team_token(team_index)
    team = _team_name(team_index)
    n = 0
    while True:
        if deadline is not None:
            if time.monotonic() >= deadline:
                break
        elif n >= iterations:
            break
        n += 1
        slug = _slug(rng.randrange(challenges))
        # ~half correct (exercises first-solve + already-solved), half wrong
        # (exercises the negative verify path). Both are real server work.
        answer = _flag(slug) if rng.random() < 0.5 else f"wrong-{rng.random()}"
        t0 = time.perf_counter()
        try:
            r = client.post(
                f"/api/v1/competitions/{_CID}/submissions",
                headers=_auth(token),
                json={
                    "team": team,
                    "definition_slug": slug,
                    "version_no": 1,
                    "answer": answer,
                },
            )
            dt_ms = (time.perf_counter() - t0) * 1000.0
            ok = r.status_code == 201
            with lock:
                result.submit_latencies_ms.append(dt_ms)
                if ok:
                    result.submit_ok += 1
                else:
                    result.submit_err += 1
                    if len(result.errors) < 20:
                        result.errors.append(f"submit {r.status_code}: {r.text[:160]}")
        except Exception as exc:  # pragma: no cover - surfaced, not swallowed
            with lock:
                result.submit_err += 1
                if len(result.errors) < 20:
                    result.errors.append(f"submit EXC: {type(exc).__name__}: {exc}")


def _reader(
    app, stop: threading.Event, result: LoadResult, lock: threading.Lock
) -> None:
    """A scoreboard reader hammering GET .../scoreboard under load until ``stop``.
    Its OWN TestClient; measures wall-clock read latency (REQ-NFR-004)."""
    client = TestClient(app)
    while not stop.is_set():
        t0 = time.perf_counter()
        try:
            r = client.get(
                f"/api/v1/competitions/{_CID}/scoreboard", headers=_auth(_ADMIN)
            )
            dt_ms = (time.perf_counter() - t0) * 1000.0
            ok = r.status_code == 200
            with lock:
                result.scoreboard_latencies_ms.append(dt_ms)
                if ok:
                    result.read_ok += 1
                else:
                    result.read_err += 1
                    if len(result.errors) < 20:
                        result.errors.append(f"read {r.status_code}: {r.text[:160]}")
        except Exception as exc:  # pragma: no cover - surfaced, not swallowed
            with lock:
                result.read_err += 1
                if len(result.errors) < 20:
                    result.errors.append(f"read EXC: {type(exc).__name__}: {exc}")


def _probe_launch(client: TestClient) -> dict:
    """Probe whether instance-LAUNCH throughput is measurable in-process. It is
    NOT: a real launch needs the M8 reconciler + a real isolated worker host.
    We only confirm the instances API surface answers, then report launch
    success as UNVERIFIED with the reason (never a fabricated >=99%)."""
    reachable = False
    detail = ""
    try:
        r = client.get(
            f"/api/v1/competitions/{_CID}/instances", headers=_auth(_ADMIN)
        )
        # Any structured HTTP answer (even 403/404) proves the surface exists;
        # a 5xx or an exception means the API itself is unhealthy.
        reachable = r.status_code < 500
        detail = f"GET .../instances -> {r.status_code}"
    except Exception as exc:  # pragma: no cover
        detail = f"probe EXC: {type(exc).__name__}: {exc}"
    return {
        "measured": False,
        "api_surface_reachable": reachable,
        "detail": detail,
        "reason": (
            "instance launch success (REQ-NFR-003) is UNVERIFIED in-process: a real "
            "launch needs the M8 desired->observed reconciler driving a real "
            "isolated worker host that starts a container; no worker runs in this "
            "harness. This is a deployment-scale (M21/M22) measurement."
        ),
    }


def run_load(
    *,
    database_url: str,
    teams: int = 8,
    challenges: int = 4,
    submissions_per_team: int = 25,
    readers: int = 3,
    duration_s: float | None = None,
    seed: int = 1234,
    project_after: bool = True,
) -> LoadResult:
    """Run the load against a throwaway DB and return the MEASURED result.

    ``duration_s`` (if set) overrides ``submissions_per_team``: each submitter
    then loops until the deadline instead of a fixed count.
    """
    if teams < 1 or challenges < 1:
        raise ValueError("teams and challenges must both be >= 1")
    result = LoadResult(
        teams=teams,
        challenges=challenges,
        submissions_per_team=submissions_per_team,
        readers=readers,
        duration_s=0.0,
    )
    lock = threading.Lock()
    with _isolated_database(database_url) as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(), database=db, authenticator=_authenticator(teams)
            )
            seed_client = TestClient(app)
            _seed(seed_client, db, teams, challenges)
            result.launch_probe = _probe_launch(seed_client)

            stop = threading.Event()
            deadline = time.monotonic() + duration_s if duration_s else None
            t_start = time.perf_counter()
            reader_pool = ThreadPoolExecutor(max_workers=max(readers, 1))
            reader_futs = [
                reader_pool.submit(_reader, app, stop, result, lock)
                for _ in range(readers)
            ]
            with ThreadPoolExecutor(max_workers=teams) as submit_pool:
                futs = [
                    submit_pool.submit(
                        _submitter,
                        app,
                        i,
                        challenges,
                        submissions_per_team,
                        deadline,
                        result,
                        lock,
                        random.Random(seed + i),  # noqa: S311 - workload mix, not crypto
                    )
                    for i in range(teams)
                ]
                for f in as_completed(futs):
                    f.result()  # re-raise any submitter-thread crash
            stop.set()
            for f in reader_futs:
                f.result()
            reader_pool.shutdown(wait=True)
            result.duration_s = time.perf_counter() - t_start

            if project_after:
                # Fold the solve events so a subsequent scoreboard read is
                # non-empty (proves the write path really produced outbox rows).
                ScoreProjector(db).run_until_drained()
        finally:
            db.dispose()
    return result


def _fmt(v: float) -> str:
    return "n/a" if math.isnan(v) else f"{v:.1f}"


def _verdict(measured: float, target: float) -> str:
    if math.isnan(measured):
        return "no data"
    return "under target" if measured < target else "OVER TARGET"


def print_report(result: LoadResult) -> None:
    out = sys.stdout
    p = out.write
    p("\n=== CTFGenerator capacity harness (in-process, real PG) ===\n")
    p(
        f"config: teams={result.teams} challenges={result.challenges} "
        f"submissions/team={result.submissions_per_team} readers={result.readers}\n"
    )
    p(
        f"wall={result.duration_s:.2f}s  submissions ok={result.submit_ok} "
        f"err={result.submit_err}  scoreboard reads ok={result.read_ok} "
        f"err={result.read_err}\n"
    )
    p(f"submission throughput: {_fmt(result.submit_throughput_rps)} req/s\n\n")

    p("REQ-NFR-005  submission processing   target < 500 ms  (server-side, per submission)\n")
    p(
        f"  p50={_fmt(result.submit_p50_ms)} ms  p95={_fmt(result.submit_p95_ms)} ms  "
        f"max={_fmt(result.submit_max_ms)} ms   "
        f"[p95 {_verdict(result.submit_p95_ms, 500)}]\n\n"
    )
    p("REQ-NFR-004  scoreboard read latency  target < 3000 ms\n")
    p(
        f"  p50={_fmt(result.scoreboard_p50_ms)} ms  p95={_fmt(result.scoreboard_p95_ms)} ms  "
        f"max={_fmt(result.scoreboard_max_ms)} ms   "
        f"[p95 {_verdict(result.scoreboard_p95_ms, 3000)}]\n\n"
    )
    p("REQ-NFR-003  instance launch success  target >= 99%\n")
    p(f"  UNVERIFIED (in-process). {result.launch_probe.get('reason', '')}\n")
    p(f"  probe: {result.launch_probe.get('detail', '')}\n\n")

    p("HONEST LIMIT: measured latencies are in-process over one PostgreSQL at the\n")
    p("scale requested above. They are a LOWER BOUND / harness proof, NOT the full\n")
    p("REQ-NFR-001/002 (25 teams x 20 live challenges) production sign-off, which\n")
    p("needs a real multi-host deployment with launched instances (M21/M22).\n")
    if result.errors:
        p(f"\nfirst errors ({len(result.errors)} shown):\n")
        for e in result.errors:
            p(f"  - {e}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("CTFGEN_TEST_DATABASE_URL"),
        help="PostgreSQL DSN (default: $CTFGEN_TEST_DATABASE_URL). A throwaway DB is "
        "created from it, migrated, seeded, load-tested, then dropped.",
    )
    parser.add_argument("--teams", type=int, default=8)
    parser.add_argument("--challenges", type=int, default=4)
    parser.add_argument("--submissions-per-team", type=int, default=25)
    parser.add_argument("--readers", type=int, default=3)
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="If > 0, each submitter loops for this many seconds instead of a "
        "fixed --submissions-per-team count.",
    )
    parser.add_argument("--seed", type=int, default=1234)
    args = parser.parse_args(argv)

    if not args.database_url:
        parser.error(
            "no database URL: set CTFGEN_TEST_DATABASE_URL or pass --database-url "
            "(needs a running PostgreSQL, e.g. the ctfgen_pg container)."
        )

    result = run_load(
        database_url=args.database_url,
        teams=args.teams,
        challenges=args.challenges,
        submissions_per_team=args.submissions_per_team,
        readers=args.readers,
        duration_s=args.duration or None,
        seed=args.seed,
    )
    print_report(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
