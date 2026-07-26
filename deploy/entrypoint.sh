#!/usr/bin/env bash
#
# deploy/entrypoint.sh -- the control-plane container entrypoint (M18 18a).
#
# MODE=api            (default): apply migrations, THEN serve the human
#                     control-plane ASGI app (interfaces.api.app:app).
# MODE=worker-gateway         : apply migrations, THEN serve ONLY the worker
#                     gateway on its own listener (interfaces.api.worker_app),
#                     the production-recommended separate-listener shape.
#
# MIGRATE-THEN-SERVE, FAIL-CLOSED: `alembic upgrade head` runs FIRST and a
# migration FAILURE ABORTS (set -e) -- the process NEVER execs uvicorn on a
# wrong/behind schema. The /system/ready gate (503 until migrations are at the
# code head) is the backstop, but this entrypoint does not even reach serve on a
# failed upgrade. `alembic upgrade head` is IDEMPOTENT: a re-run already at head
# is a no-op, so restarts/rolling deploys are safe.
#
# NO bootstrap-admin AUTO-RUN: seeding the first admin is a ONE-TIME, first-deploy
# operator step -- run `ctfgen-admin bootstrap-admin` once by hand (it reads
# CTFGEN_BOOTSTRAP_ADMIN_PASSWORD from the env). Auto-seeding on every boot would
# be both wrong (idempotency/racing) and a security smell.
#
# SECRET-FREE: reads CTFGEN_* from the environment only; NEVER echoes the DSN /
# password / any token. The DSN lives solely in CTFGEN_DATABASE_URL (env), never
# in alembic.ini (which stays DSN-less) or on argv.
set -euo pipefail

MODE="${MODE:-api}"
PORT="${PORT:-8000}"
# Number of uvicorn worker PROCESSES. Default 1 (a small/demo deployment). Size it
# up for real concurrency -- one worker serializes CPU-bound request work on the
# GIL. When >1, also cap the PER-WORKER DB pool (CTFGEN_DB_POOL_SIZE /
# CTFGEN_DB_MAX_OVERFLOW) so N workers x pool stays under PostgreSQL
# max_connections. Migrations still run ONCE here before any worker is forked.
API_WORKERS="${CTFGEN_API_WORKERS:-1}"

# A DSN is REQUIRED to migrate + serve real data. Fail loud (never echo it).
if [ -z "${CTFGEN_DATABASE_URL:-}" ]; then
    echo "entrypoint: CTFGEN_DATABASE_URL is not set; the control plane requires a database DSN" >&2
    exit 1
fi

echo "entrypoint: applying database migrations (alembic upgrade head)..." >&2
# alembic reads the DSN from CTFGEN_DATABASE_URL via env.py; it is NEVER in the
# ini. A non-zero exit here aborts the whole script (set -e) -> no serve.
alembic -c alembic.ini upgrade head
echo "entrypoint: migrations at head." >&2

case "$MODE" in
    api)
        echo "entrypoint: serving control-plane API on :${PORT} (workers=${API_WORKERS})" >&2
        exec uvicorn ctf_generator.interfaces.api.app:app \
            --host 0.0.0.0 --port "${PORT}" --workers "${API_WORKERS}"
        ;;
    worker-gateway)
        echo "entrypoint: serving worker gateway on :${PORT} (workers=${API_WORKERS})" >&2
        exec uvicorn ctf_generator.interfaces.api.worker_app:worker_app \
            --host 0.0.0.0 --port "${PORT}" --workers "${API_WORKERS}"
        ;;
    *)
        echo "entrypoint: unknown MODE='${MODE}' (expected api | worker-gateway)" >&2
        exit 1
        ;;
esac
