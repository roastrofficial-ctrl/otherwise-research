#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise05-$(date +%s)-$$"
export OTHERWISE_05_CLOCK_MODE=test
mkdir -p doc/results05
lab() { ./scripts/lab05.sh "$@"; }
cleanup() { lab down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
lab build > doc/results05/build.txt 2>&1
lab up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 hostile product-db laravel > doc/results05/start.txt 2>&1
lab run --rm --no-deps cli > doc/results05/tests.txt 2>&1
lab run --rm --no-deps cli cat /recovery/attack-results.json > doc/results05/attacks.json
lab run --rm --no-deps cli python scripts/conformance04.py > doc/results05/conformance04.txt 2>&1
lab run --rm --no-deps cli python scripts/conformance05.py > doc/results05/conformance.txt 2>&1
lab run --rm --no-deps cli python tests05/benchmark.py > doc/results05/performance.json 2>&1
lab run --rm --no-deps cli python tests05/scenario.py before > doc/results05/hostile-lifecycle.txt 2>&1
lab stop laravel hostile product-db >> doc/results05/hostile-lifecycle.txt 2>&1
lab run --rm --no-deps cli python tests05/scenario.py after >> doc/results05/hostile-lifecycle.txt 2>&1
lab stop aw4 >> doc/results05/hostile-lifecycle.txt 2>&1
lab run --rm --no-deps cli python tests05/scenario.py during-restart >> doc/results05/hostile-lifecycle.txt 2>&1
lab start aw4 >> doc/results05/hostile-lifecycle.txt 2>&1
lab run --rm --no-deps cli python tests05/scenario.py after-restart >> doc/results05/hostile-lifecycle.txt 2>&1
printf 'Generation 0.5 complete: doc/results05/\n'
