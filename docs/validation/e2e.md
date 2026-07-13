# Validation: full-stack E2E flow (HTTP edge)

**Artifact:** `tests/test_e2e_flow_integration.py`
**Kind:** PostgreSQL-gated integration test, one ordered scenario.

## The scenario

One test, `HttpEndToEndFlowTests.test_full_contestant_scoring_loop_over_http`,
runs the WHOLE contestant-scoring loop through the HTTP API surface as a single
ordered scenario. It builds `create_app` over a fresh per-test migrated database
(real PostgreSQL) with **real authentication** (`DbAuthenticator` over the
`AuthService`-bootstrapped admin), wraps it in a Starlette `TestClient`, and
speaks the JSON API directly — logging in over `POST /api/v1/auth/login` and
carrying the returned bearer token on every subsequent request, exactly as an
external client would.

Ordered steps, each asserting the status code AND the resulting state read back
over HTTP:

1. organizer logs in (`POST /auth/login`) → `GET /auth/me` confirms the subject;
2. creates a competition (`POST /competitions`) → `GET /competitions/{id}`;
3. creates a team (`POST /teams`) → `GET /teams?competition_id=…`;
4. creates a challenge definition (`POST /challenge-definitions`);
5. creates a challenge version (`POST /challenge-versions`);
6. publishes it (`POST /challenge-versions/{slug}/1/publish`, state `published`);
7. attaches the publication (`POST /competitions/{id}/publications`) → list read;
8. registers a contestant user (`POST /users`);
9. **[places the contestant on the team via services — see gap below]**;
10. contestant logs in → `GET /auth/me` confirms the switched subject;
11. contestant submits the correct flag (`POST /competitions/{id}/submissions`):
    accepted, `first_solve` true, exactly one `solve`;
12. the projector folds the transactional outbox; the competition scoreboard
    (`GET /competitions/{id}/scoreboard`) then ranks the team with `solve_count`
    1 and a positive score.

## What it proves

- The contestant-scoring loop is coherent **end to end across the HTTP edge** —
  not just at the CLI (`test_cli_e2e_integration`) or the submissions router
  (`test_api_submissions_integration`), but as one named scenario where each
  step's persisted effect is visible to the next HTTP read.
- Authentication is real: the organizer and contestant obtain bearer tokens from
  `POST /auth/login` and are authorized by the actual `DbAuthenticator` seam.
- **Invariant — no double solve:** a duplicate correct submission (a genuine
  re-submit, a *distinct* submission id, NOT an idempotency replay) is accepted
  but yields `first_solve` false and a null `solve`. Two correct submissions are
  recorded on the ledger, but they map to a single solve fact.
- **Invariant — scoreboard is append-only-consistent:** re-folding the outbox
  after the duplicate leaves the standings byte-for-byte identical
  (`solve_count` 1, score unchanged).
- **No flag leak on contestant surfaces:** the expected flag never appears in the
  login, submission-outcome, or submission-list response bodies. (The
  *organizer's own* version-create response does echo the authored spec — that is
  the authoring surface the organizer owns, not a contestant disclosure — so the
  leak assertion is applied only to contestant-facing responses.)

## Run command

```
CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \
  PYTHONPATH=src:tests python -m unittest test_e2e_flow_integration
```

Without `CTFGEN_TEST_DATABASE_URL` (or without the `[api]`/`[db]` extras) the test
SKIPS cleanly — it never silently passes.

## Documented-unverified edges (charter §5)

These are boundaries this test deliberately does NOT cross. They are recorded as
UNVERIFIED here rather than by weakening the scenario.

- **No real reverse-proxy / TLS socket.** The Starlette `TestClient` is an
  in-process `httpx.Client` — it invokes the ASGI app directly. This exercises
  the full application + routing + auth + persistence stack, but NOT a real
  network socket, TLS termination, or a production reverse proxy (nginx/Traefik).
  Edge concerns owned by the proxy (TLS, header normalization, request-size
  limits, real client-IP forwarding) are out of scope here.
- **No real distributed worker; the challenge instance is not launched.** The
  loop scores a submitted flag against the published spec; it does NOT build or
  run the challenge *services* on a worker. The `build_challenge` worker pipeline
  is not built — see `docs/evaluation/eval-worker-limitations.md`. A fully
  distributed worker path (separate host, no control-plane DB credential,
  full-bundle delivery + image build) is therefore untested here.
- **Team-membership placement has no HTTP route (product/validation gap).** There
  is no membership-grant / team-placement endpoint on the API surface. Step 9
  seeds the contestant's password credential (`AuthService.set_password`) and
  their player membership on the team directly via the services /
  `SqlAlchemyMembershipRepository`. This is the SAME documented gap noted in
  `test_cli_e2e_integration`. It is recorded as an unfilled product surface, NOT
  worked around by inventing a route. Everything downstream of placement
  (contestant login, submit, solve, scoreboard) still runs entirely over HTTP.
- **Rootless container isolation is host-capability-gated.** This test does not
  launch containers, but for completeness: this host is rootful arm64, so the
  rootless/userns runtime path is capability-gated and documented-unverified in
  `docs/security/runtime-isolation.md`.
