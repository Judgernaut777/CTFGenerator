#!/usr/bin/env bash
#
# coverage.sh [MIN]  --  measure line+branch coverage of the ctf_generator
# package by running the FULL unittest suite under coverage.py (M20 validation).
#
# This OBSERVES the package; it runs the real tests and reports what fraction of
# `ctf_generator` they exercise. It never mutates the code under test.
#
#   MIN (optional): a percentage floor. When given, the script exits non-zero if
#   the measured TOTAL is below MIN. Omit it to just measure + report.
#
# Environment:
#   CTFGEN_TEST_DATABASE_URL  If set, the Postgres-gated integration suites run
#                             and COUNT toward coverage. Unset -> those tests
#                             skip and the number UNDERSTATES real coverage (see
#                             docs/validation/coverage.md). This script does NOT
#                             set it -- pass it in from the caller / CI service.
#   PYTHON                    Interpreter to use (default: python3). Must have
#                             `coverage` importable, i.e. the [cov] extra.
#   COVERAGE_XML=1            Also write coverage.xml (Cobertura, for CI upload).
#   COVERAGE_HTML=1           Also write htmlcov/ (browsable report).
#
# Config (source/branch/omit/exclude) lives in pyproject.toml [tool.coverage.*]
# so this script and CI agree.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

MIN="${1:-}"
PY="${PYTHON:-python3}"

# The suite is import-path sensitive: package from src/, test helpers from tests/.
export PYTHONPATH="src:tests${PYTHONPATH:+:$PYTHONPATH}"

cov() { "$PY" -m coverage "$@"; }

if [ -n "${CTFGEN_TEST_DATABASE_URL:-}" ]; then
    echo "coverage: CTFGEN_TEST_DATABASE_URL is set -- integration suites WILL run and count." >&2
else
    echo "coverage: CTFGEN_TEST_DATABASE_URL is NOT set -- integration suites will SKIP;" >&2
    echo "          the reported total UNDERSTATES real coverage (docs/validation/coverage.md)." >&2
fi

# Fresh slate: parallel-mode writes .coverage.<host>.<pid> data files.
rm -f .coverage .coverage.* 2>/dev/null || true

# Run the whole suite. A test FAILURE must fail this script (coverage of a broken
# suite is meaningless), so we do not swallow the exit code.
cov run -m unittest discover -s tests -p 'test_*.py'

# Fold the parallel data files into one, then report.
cov combine
cov report

[ "${COVERAGE_XML:-}" = "1" ] && cov xml && echo "coverage: wrote coverage.xml" >&2
[ "${COVERAGE_HTML:-}" = "1" ] && cov html && echo "coverage: wrote htmlcov/index.html" >&2

# The single TOTAL number (coverage.py >= 7 prints just the percentage here).
total="$(cov report --format=total)"
echo "TOTAL coverage: ${total}%"

if [ -n "$MIN" ]; then
    # Integer-compare on the floor of the percentage so "73.42" vs MIN=73 works.
    total_int="${total%.*}"
    if [ "$total_int" -lt "$MIN" ]; then
        echo "coverage: FAIL -- total ${total}% is below the ${MIN}% floor." >&2
        exit 1
    fi
    echo "coverage: OK -- total ${total}% meets the ${MIN}% floor." >&2
fi
