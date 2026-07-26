#!/usr/bin/env python3
"""OUT-OF-PROCESS capacity harness: drive a DEPLOYED control plane over real HTTP.

Unlike ``scripts/loadtest.py`` (in-process ``TestClient`` over one interpreter --
a GIL-bound lower bound), this drives a REAL, already-running deployment over the
network with MULTIPLE OS PROCESSES, so the measured submission/scoreboard latency
reflects the product under genuine concurrency, not a single-interpreter artifact.

It has two phases:

* ``provision`` -- as the admin, over HTTP: one competition, ``--teams`` teams,
  ``--challenges`` published+attached challenges (each with a known flag), one
  player user per team, each granted a player membership (the M-onboarding
  ``PUT .../members/...`` surface). Passwords are set with the operator CLI via
  ``--admin-exec`` (e.g. ``docker compose ... exec -T api ctfgen-admin``), the only
  password-provisioning path. Writes a submitter roster JSON.
* ``load`` -- spawns ``--procs`` worker PROCESSES; each logs its assigned players
  in over HTTP and loops real submissions (half correct / half wrong) for
  ``--duration`` seconds, plus ``--readers`` scoreboard-reader loops. Reports
  server-observed p50/p95/max submission + scoreboard latency and throughput.

Never fabricates a number: launch success (needs a real worker fleet) is out of
scope here and reported as such -- this measures the submission + scoreboard paths.

    python scripts/loadtest_http.py all \\
      --base-url https://localhost --insecure \\
      --admin-email admin@ctf.local --admin-password "$PW" \\
      --admin-exec 'docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T api ctfgen-admin' \\
      --teams 25 --challenges 20 --duration 30 --procs 8 --readers 4
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shlex
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

import httpx

_PW = "loadtest-Player-Pw-9"  # noqa: S105 - shared local test-account password


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    rank = (p / 100.0) * (len(s) - 1)
    lo, hi = math.floor(rank), math.ceil(rank)
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (rank - lo)


def _client(base_url: str, insecure: bool) -> httpx.Client:
    return httpx.Client(base_url=base_url, verify=not insecure, timeout=30.0)


def _login(client: httpx.Client, email: str, password: str) -> str:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()["token"]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _flag(slug: str) -> str:
    return f"CTF{{flag-{slug}}}"


# --------------------------------------------------------------------------- #
# provision
# --------------------------------------------------------------------------- #
def provision(args) -> dict:
    cid = args.competition
    with _client(args.base_url, args.insecure) as c:
        admin = _bearer(_login(c, args.admin_email, args.admin_password))

        def expect(r, code, what):
            if r.status_code != code:
                raise SystemExit(
                    f"provision {what}: expected {code}, got {r.status_code}: {r.text[:200]}"
                )

        expect(
            c.post(
                "/api/v1/competitions",
                headers=admin,
                json={
                    "competition_id": cid,
                    "name": "Capacity Run",
                    "start_time": "2026-06-01T09:00:00Z",
                    "end_time": "2027-06-03T09:00:00Z",
                },
            ),
            201,
            "competition",
        )

        challenges = []
        for i in range(args.challenges):
            # Challenge definitions + users are GLOBAL identities; namespace them by
            # the competition id so repeated runs never collide (409).
            slug = f"{cid}-{i}"
            expect(
                c.post(
                    "/api/v1/challenge-definitions",
                    headers=admin,
                    json={"family": "web", "slug": slug, "title": f"Cap {i}"},
                ),
                201,
                f"def {slug}",
            )
            expect(
                c.post(
                    "/api/v1/challenge-versions",
                    headers=admin,
                    json={
                        "definition_slug": slug,
                        "seed": f"seed-{i}",
                        "family_version": "1.0.0",
                        "spec": {"title": f"Cap {i}", "flag": _flag(slug)},
                    },
                ),
                201,
                f"ver {slug}",
            )
            expect(
                c.post(f"/api/v1/challenge-versions/{slug}/1/publish", headers=admin),
                200,
                f"publish {slug}",
            )
            expect(
                c.post(
                    f"/api/v1/competitions/{cid}/publications",
                    headers=admin,
                    json={"definition_slug": slug, "version_no": 1},
                ),
                201,
                f"attach {slug}",
            )
            challenges.append({"slug": slug, "flag": _flag(slug)})

        submitters = []
        for t in range(args.teams):
            team = f"Team{t}"
            email = f"player{t}@{cid}.local"
            expect(
                c.post("/api/v1/teams", headers=admin, json={"competition_id": cid, "name": team}),
                201,
                f"team {team}",
            )
            expect(
                c.post(
                    "/api/v1/users",
                    headers=admin,
                    json={"email": email, "display_name": f"Player {t}", "role": "player"},
                ),
                201,
                f"user {email}",
            )
            expect(
                c.put(
                    f"/api/v1/competitions/{cid}/members/{email}",
                    headers=admin,
                    json={"role": "player", "team_name": team},
                ),
                200,
                f"member {email}",
            )
            submitters.append({"email": email, "password": _PW, "team": team})

        # Set passwords through the operator CLI (the only provisioning path).
        for s in submitters:
            cmd = shlex.split(args.admin_exec) + [
                "set-password",
                "--email",
                s["email"],
                "--password",
                _PW,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603 - operator-provided admin-exec
            if res.returncode != 0:
                raise SystemExit(f"set-password {s['email']} failed: {res.stderr[:200]}")

    roster = {"competition": cid, "challenges": challenges, "submitters": submitters}
    with open(args.roster, "w") as f:
        json.dump(roster, f)
    print(f"provisioned {args.teams} teams x {args.challenges} challenges -> {args.roster}")
    return roster


# --------------------------------------------------------------------------- #
# load
# --------------------------------------------------------------------------- #
@dataclass
class Shard:
    submit_ms: list[float] = field(default_factory=list)
    scoreboard_ms: list[float] = field(default_factory=list)
    submit_ok: int = 0
    submit_err: int = 0
    read_ok: int = 0
    read_err: int = 0
    errors: list[str] = field(default_factory=list)


def _run_shard(base_url, insecure, cid, submitters, challenges, duration, seed, readers) -> dict:
    rng = random.Random(seed)  # noqa: S311 - workload mix, not crypto
    sh = Shard()
    deadline = time.monotonic() + duration
    with _client(base_url, insecure) as c:
        tokens = {}
        for s in submitters:
            try:
                tokens[s["email"]] = _login(c, s["email"], s["password"])
            except Exception as exc:  # pragma: no cover
                sh.errors.append(f"login {s['email']}: {type(exc).__name__}: {exc}")
        do_read = readers > 0
        read_every = max(1, len(submitters))  # interleave a scoreboard read periodically
        n = 0
        while time.monotonic() < deadline:
            s = submitters[n % len(submitters)]
            n += 1
            tok = tokens.get(s["email"])
            if not tok:
                continue
            ch = challenges[rng.randrange(len(challenges))]
            answer = ch["flag"] if rng.random() < 0.5 else f"wrong-{rng.random()}"
            t0 = time.perf_counter()
            try:
                r = c.post(
                    f"/api/v1/competitions/{cid}/submissions",
                    headers=_bearer(tok),
                    json={
                        "team": s["team"],
                        "definition_slug": ch["slug"],
                        "version_no": 1,
                        "answer": answer,
                    },
                )
                sh.submit_ms.append((time.perf_counter() - t0) * 1000.0)
                if r.status_code == 201:
                    sh.submit_ok += 1
                else:
                    sh.submit_err += 1
                    if len(sh.errors) < 10:
                        sh.errors.append(f"submit {r.status_code}: {r.text[:120]}")
            except Exception as exc:  # pragma: no cover
                sh.submit_err += 1
                if len(sh.errors) < 10:
                    sh.errors.append(f"submit EXC: {type(exc).__name__}: {exc}")
            if do_read and n % read_every == 0:
                t1 = time.perf_counter()
                try:
                    rr = c.get(
                        f"/api/v1/competitions/{cid}/scoreboard",
                        headers=_bearer(tokens[submitters[0]["email"]]),
                    )
                    sh.scoreboard_ms.append((time.perf_counter() - t1) * 1000.0)
                    if rr.status_code == 200:
                        sh.read_ok += 1
                    else:
                        sh.read_err += 1
                except Exception as exc:  # pragma: no cover
                    sh.read_err += 1
                    if len(sh.errors) < 10:
                        sh.errors.append(f"read EXC: {type(exc).__name__}: {exc}")
    return {
        "submit_ms": sh.submit_ms,
        "scoreboard_ms": sh.scoreboard_ms,
        "submit_ok": sh.submit_ok,
        "submit_err": sh.submit_err,
        "read_ok": sh.read_ok,
        "read_err": sh.read_err,
        "errors": sh.errors,
    }


def load(args) -> None:
    with open(args.roster) as f:
        roster = json.load(f)
    cid = roster["competition"]
    challenges = roster["challenges"]
    submitters = roster["submitters"]
    procs = max(1, args.procs)
    # Shard submitters across processes (round-robin).
    shards = [submitters[i::procs] for i in range(procs)]
    shards = [s for s in shards if s]

    t_start = time.perf_counter()
    with ProcessPoolExecutor(max_workers=len(shards)) as pool:
        futs = [
            pool.submit(
                _run_shard,
                args.base_url,
                args.insecure,
                cid,
                shard,
                challenges,
                args.duration,
                1000 + i,
                args.readers,
            )
            for i, shard in enumerate(shards)
        ]
        results = [f.result() for f in futs]
    wall = time.perf_counter() - t_start

    submit_ms = [x for r in results for x in r["submit_ms"]]
    board_ms = [x for r in results for x in r["scoreboard_ms"]]
    submit_ok = sum(r["submit_ok"] for r in results)
    submit_err = sum(r["submit_err"] for r in results)
    read_ok = sum(r["read_ok"] for r in results)
    read_err = sum(r["read_err"] for r in results)
    errors = [e for r in results for e in r["errors"]][:15]

    def fmt(v):
        return "n/a" if math.isnan(v) else f"{v:.1f}"

    def verdict(v, target):
        return "no data" if math.isnan(v) else ("UNDER target" if v < target else "OVER TARGET")

    p = sys.stdout.write
    p("\n=== CTFGenerator OUT-OF-PROCESS capacity (real HTTP, deployed) ===\n")
    p(
        f"procs={len(shards)} submitters={len(submitters)} challenges={len(challenges)} "
        f"duration={args.duration}s readers/proc={args.readers}\n"
    )
    p(
        f"wall={wall:.2f}s  submissions ok={submit_ok} err={submit_err}  "
        f"scoreboard reads ok={read_ok} err={read_err}\n"
    )
    thr = submit_ok / wall if wall > 0 else float("nan")
    p(f"submission throughput: {fmt(thr)} req/s  ({submit_ok + submit_err} attempts)\n\n")
    p("REQ-NFR-005 submission processing  target < 500 ms (end-to-end over TLS)\n")
    p(
        f"  p50={fmt(_percentile(submit_ms, 50))} ms  p95={fmt(_percentile(submit_ms, 95))} ms  "
        f"max={fmt(max(submit_ms) if submit_ms else float('nan'))} ms  "
        f"[p95 {verdict(_percentile(submit_ms, 95), 500)}]\n\n"
    )
    p("REQ-NFR-004 scoreboard read latency  target < 3000 ms\n")
    p(
        f"  p50={fmt(_percentile(board_ms, 50))} ms  p95={fmt(_percentile(board_ms, 95))} ms  "
        f"max={fmt(max(board_ms) if board_ms else float('nan'))} ms  "
        f"[p95 {verdict(_percentile(board_ms, 95), 3000)}]\n\n"
    )
    p("REQ-NFR-003 instance launch success  >= 99%: OUT OF SCOPE here (needs a real\n")
    p("  worker fleet). Measure with a multi-host worker fleet; never fabricated.\n")
    if errors:
        p(f"\nfirst errors ({len(errors)}):\n")
        for e in errors:
            p(f"  - {e}\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("phase", choices=["provision", "load", "all"])
    ap.add_argument("--base-url", default="https://localhost")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verify (local CA)")
    ap.add_argument("--admin-email", default="admin@ctf.local")
    ap.add_argument("--admin-password", default=os.environ.get("CTFGEN_LOADTEST_ADMIN_PW", ""))
    ap.add_argument(
        "--admin-exec",
        default="ctfgen-admin",
        help="prefix to invoke ctfgen-admin (e.g. 'docker compose ... exec -T api ctfgen-admin')",
    )
    ap.add_argument("--competition", default="capacity-run")
    ap.add_argument("--teams", type=int, default=25)
    ap.add_argument("--challenges", type=int, default=20)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--readers", type=int, default=1)
    ap.add_argument("--roster", default="/tmp/ctfgen_cap_roster.json")  # noqa: S108 - scratch roster path, operator-overridable
    args = ap.parse_args(argv)

    if args.phase in ("provision", "all"):
        if not args.admin_password:
            ap.error("--admin-password (or CTFGEN_LOADTEST_ADMIN_PW) required to provision")
        provision(args)
    if args.phase in ("load", "all"):
        load(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
