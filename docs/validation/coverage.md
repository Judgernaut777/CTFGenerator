# Test coverage measurement (M20 validation)

Coverage is **measured**, not asserted. Before M20 the suite ran under `unittest`
with no `--cov`/`pytest-cov`, so line/branch coverage of `ctf_generator` was
measured **nowhere**. This adds an honest measurement path:

- `pyproject.toml` `[tool.coverage.run]` / `[tool.coverage.report]` — the config
  (`source = ["ctf_generator"]`, `branch = true`, parallel-mode). Shared by local
  runs and CI so they agree.
- `scripts/coverage.sh` — runs the **full** `unittest` suite under coverage.py,
  combines the parallel data, and prints the TOTAL %.
- `.github/workflows/coverage.yml` — an **informational** CI job (like the
  lint/type/SAST jobs in `pr.yml`): it measures against a real Postgres service
  and uploads the report. It is **not** a merge-blocking gate.
- `[cov]` optional extra — `coverage>=7`, kept out of `dev`/`ci` so the
  stdlib-only unit gate is unchanged.

Coverage **observes** the code under test; it changes no scoring math, no
generator determinism, no golden fixtures, no schemas, no migrations.

## How to run it

Host-only (fast, but **understates** — see below):

```bash
PYTHON=.venv/bin/python3 bash scripts/coverage.sh
```

Full measurement, counting the Postgres integration suites (recommended):

```bash
CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \
  PYTHON=.venv/bin/python3 bash scripts/coverage.sh
```

Add a floor to make it fail below a threshold (used by CI):

```bash
... bash scripts/coverage.sh 50     # exits non-zero if TOTAL < 50%
```

Optional artifacts: `COVERAGE_XML=1` writes `coverage.xml` (Cobertura),
`COVERAGE_HTML=1` writes `htmlcov/`.

## Host-only runs understate coverage

146 test modules exist; **63 of them are gated on `CTFGEN_TEST_DATABASE_URL`**
(the Docker/Postgres integration suites `skipUnless` that env var is set). With no
DB URL those 63 modules skip entirely, so every persistence/repository/API/auth
path they exercise counts as *missed*. Always run with the DB URL set for a
representative number; the CI job wires a `postgres:16` service for exactly this
reason. The Docker-runtime isolation suites additionally need a container engine
and are further gated (rootless is capability-gated on the arm64 host — see
`docs/security/runtime-isolation.md`); paths reachable only through a rootless
runtime remain **UNVERIFIED** by this measurement.

## Current measured total

**UNVERIFIED at authoring time.** The full PG-backed measurement
(`coverage run` over all 146 modules with branch tracing + the 63 integration
suites against `172.20.0.2:5432`) was launched but had **not returned a TOTAL
within the authoring window** — the instrumented full suite is long-running. This
number MUST be populated from a completed run before M20 is signed off:

```bash
CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \
  PYTHON=.venv/bin/python3 bash scripts/coverage.sh | tail -1
```

Record the printed `TOTAL coverage: NN.NN%` here, then set the CI floor
(`scripts/coverage.sh <MIN>` in `coverage.yml`) to at/just-below it.

## Informational floor (provisional)

`.github/workflows/coverage.yml` calls `scripts/coverage.sh 50`. **50 is a
deliberately conservative provisional floor**, not the measured number: with the
real total still UNVERIFIED, a low floor guarantees the job reports the true
percentage without a false FAIL. The job is `continue-on-error`, so even a dip
below the floor is informational, never merge-blocking — a hard coverage gate is
premature (implemented != qualified). Once the measured total above is populated,
raise this floor to at/just-below it in the same commit.

## Thin subsystems (measure, then target)

Ranking below is **provisional** pending the first completed full run; confirm
against `coverage report` (`show_missing = true`) before acting. Structurally
under-exercised areas, by design or by gating:

- **Rootless-runtime / container-escape paths** (`infrastructure/runtime/…`) —
  capability-gated on this host; documented-unverified, not a coverage failure.
- **Networked worker run loop** (`workers/worker.py`) — the long-poll loop is
  driven via a `LocalControlPlaneClient` in tests; the HTTP-transport branches
  count only when the worker/api extras are installed.
- **Legacy stdlib dashboard** (`dashboard_server.py`, `dashboard_ui.py`) — the
  pre-platform dashboard, superseded by the web UI; lightly tested by design.
- **CLI entry shims / `__main__.py`** — thin console-script wiring, driven by the
  subprocess CI tiers rather than the unit suite (`__main__.py` is `omit`-ed).

These are **candidates to raise coverage on**, recorded honestly — not silently
excluded to inflate the number.
