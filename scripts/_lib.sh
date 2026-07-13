# shellcheck shell=bash
# Shared helpers for backup.sh / restore.sh (M17 slice 17a).
#
# SECRET-FREE: these helpers parse a DSN into the standard libpq PG* environment
# variables (PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE) so the pg tools connect
# WITHOUT any credential on the command line -- the password is never echoed and
# never appears in `ps`/argv. Nothing here prints a password or a DSN.
#
# Sourced, not executed. The sourcing script owns `set -euo pipefail`.

# die MESSAGE... -- fail loud on stderr with a nonzero exit.
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# require_cmd NAME -- ensure a command is on PATH (fail loud otherwise).
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# dsn_parse DSN -- parse a SQLAlchemy/libpq DSN and export the libpq PG* vars.
#
# Accepts postgresql://... and postgresql+psycopg://... (the +driver suffix is
# stripped). Sets PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE. The password is
# assigned to PGPASSWORD only -- never printed. (Percent-encoded userinfo is not
# decoded; the platform DSNs use simple credentials. Document + extend if a
# password needs reserved characters.)
dsn_parse() {
    local url="$1" rest userinfo hostpart hostport query
    [ -n "$url" ] || die "empty DSN"

    # Strip the scheme (postgresql:// or postgresql+psycopg://, etc.).
    case "$url" in
        *://*) rest="${url#*://}" ;;
        *) die "DSN is not a URL (missing ://)" ;;
    esac

    # Split userinfo@host-part.
    case "$rest" in
        *@*)
            userinfo="${rest%%@*}"
            hostpart="${rest#*@}"
            ;;
        *)
            userinfo=""
            hostpart="$rest"
            ;;
    esac

    # user[:password]
    case "$userinfo" in
        *:*)
            PGUSER="${userinfo%%:*}"
            PGPASSWORD="${userinfo#*:}"
            ;;
        *)
            PGUSER="$userinfo"
            PGPASSWORD=""
            ;;
    esac

    # Drop any ?query string, then split host[:port]/dbname.
    hostpart="${hostpart%%\?*}"
    query="${hostpart#*/}"
    case "$hostpart" in
        */*)
            hostport="${hostpart%%/*}"
            PGDATABASE="$query"
            ;;
        *)
            hostport="$hostpart"
            PGDATABASE=""
            ;;
    esac

    # host[:port]
    case "$hostport" in
        *:*)
            PGHOST="${hostport%%:*}"
            PGPORT="${hostport#*:}"
            ;;
        *)
            PGHOST="$hostport"
            PGPORT="5432"
            ;;
    esac

    [ -n "$PGHOST" ] || die "DSN has no host"
    [ -n "$PGUSER" ] || die "DSN has no user"
    export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
}

# Tool binaries are overridable so an operator can point them at container
# tooling. dsn_parse exports the connection as libpq PG* ENV vars, so a
# `docker exec` override MUST forward that env into the container, e.g.:
#   CTFGEN_PG_DUMP="docker exec -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -e PGDATABASE ctfgen_pg_epic1 pg_dump"
# (a bare `docker exec <ctr> pg_dump` drops the host env and connects as the
# container's OS user -> "role \"root\" does not exist"). They default to the
# bare names on PATH (a host with the postgresql-client installed).
: "${CTFGEN_PG_DUMP:=pg_dump}"
: "${CTFGEN_PG_RESTORE:=pg_restore}"
: "${CTFGEN_PSQL:=psql}"
