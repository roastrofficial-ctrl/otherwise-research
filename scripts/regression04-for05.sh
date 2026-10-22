#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise05-regression04-$(date +%s)-$$"
export OTHERWISE_04_CLOCK_MODE=test
cleanup() { ./scripts/lab04.sh down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
./scripts/lab04.sh build cli aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results05/regression04-build.txt 2>&1
./scripts/lab04.sh up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results05/regression04-start.txt 2>&1
./scripts/lab04.sh run --rm --no-deps cli > doc/results05/regression04-tests.txt 2>&1
./scripts/lab04.sh run --rm --no-deps cli python scripts/conformance04.py > doc/results05/regression04-conformance.txt 2>&1
