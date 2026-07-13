#!/usr/bin/env bash
#
# deploy/verify-deploy.sh -- LEAD Docker-verification for M18 18a.
#
# The impl agent CANNOT run docker build; the LEAD runs THIS. It:
#   1. `docker build` the CONTROL-PLANE image from deploy/Dockerfile.api;
#   2. boots it against a THROWAWAY postgres:16 on a private network;
#   3. waits for /system/ready to go GREEN (200) -- i.e. the entrypoint applied
#      migrations (migrate-then-serve) and the DB is up;
#   4. ASSERTS REQ-INV-010 / COMP-015 on the RUNNING control-plane container:
#         (a) NO docker CLI on PATH inside the image, and
#         (b) NO /var/run/docker.sock present.
#      Either failing FAILS LOUD.
#   5. also asserts the container runs as NON-ROOT.
#
# Everything is torn down on exit. No secret is persisted; the throwaway DB
# password is a local, ephemeral literal used ONLY for this test network.
set -euo pipefail

_here="$(cd "$(dirname "$0")" && pwd)"
_root="$(cd "$_here/.." && pwd)"

NET="ctfgen_verify_net_$$"
PG="ctfgen_verify_pg_$$"
API="ctfgen_verify_api_$$"
IMAGE="ctfgen-api-verify:$$"
# Ephemeral, test-only DB password (throwaway network, torn down at exit).
PG_PASS="verify_only_$$"
DSN="postgresql+psycopg://ctfgen:${PG_PASS}@${PG}:5432/ctfgen"

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
    docker rm -f "$API" >/dev/null 2>&1 || true
    docker rm -f "$PG" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== 1. building control-plane image (deploy/Dockerfile.api) =="
docker build -f "$_root/deploy/Dockerfile.api" -t "$IMAGE" "$_root"

echo "== 2. booting throwaway postgres + the API =="
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
    -e POSTGRES_USER=ctfgen -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=ctfgen \
    postgres:16 >/dev/null

# Wait for postgres to accept connections.
for _ in $(seq 1 30); do
    if docker exec "$PG" pg_isready -U ctfgen -d ctfgen >/dev/null 2>&1; then break; fi
    sleep 2
done

docker run -d --name "$API" --network "$NET" \
    -e MODE=api -e PORT=8000 \
    -e CTFGEN_DATABASE_URL="$DSN" \
    -e CTFGEN_ARTIFACT_ROOT=/tmp/ctfgen-artifacts \
    -e CTFGEN_API_RATE_LIMIT=0 \
    "$IMAGE" >/dev/null

echo "== 3. waiting for /system/ready to go GREEN (migrations applied) =="
ready=0
for _ in $(seq 1 45); do
    code="$(docker exec "$API" python -c \
        "import urllib.request,sys
try:
    sys.stdout.write(str(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/system/ready').status))
except Exception as e:
    sys.stdout.write('ERR')" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then ready=1; break; fi
    sleep 2
done
[ "$ready" = "1" ] || { docker logs "$API" >&2 || true; fail "/system/ready never returned 200"; }
pass "/system/ready is GREEN (entrypoint migrated then served)"

echo "== 4. REQ-INV-010: prove the control-plane image is docker-FREE =="
# (a) no docker CLI on PATH inside the container.
if docker exec "$API" sh -c "command -v docker" >/dev/null 2>&1; then
    fail "docker CLI IS present in the control-plane image (REQ-INV-010 violated)"
fi
pass "no docker CLI on PATH in the control-plane image"

# (b) no docker socket present.
if docker exec "$API" sh -c "[ -S /var/run/docker.sock ]" >/dev/null 2>&1; then
    fail "/var/run/docker.sock IS present in the control-plane container (REQ-INV-010 violated)"
fi
pass "no /var/run/docker.sock in the control-plane container"

echo "== 5. non-root runtime user =="
uid="$(docker exec "$API" id -u 2>/dev/null || echo unknown)"
[ "$uid" != "0" ] && [ "$uid" != "unknown" ] || fail "control-plane container runs as root (uid=$uid)"
pass "control-plane runs as non-root (uid=$uid)"

echo
echo "ALL DEPLOY CHECKS PASSED (image builds, migrates, serves ready, docker-FREE, non-root)."
