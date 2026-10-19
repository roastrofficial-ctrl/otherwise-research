#!/bin/sh
# Own project/volumes only; full protocol-only + product + disappearing-SaaS run.
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise04-$(date +%s)-$$"
export OTHERWISE_04_CLOCK_MODE=test
mkdir -p doc/results04
lab() { ./scripts/lab04.sh "$@"; }
cleanup() { lab down -v --remove-orphans > /dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
lab build > doc/results04/build.txt 2>&1
lab up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 protocol-adapter product-db laravel > doc/results04/start.txt 2>&1
lab run --rm --no-deps cli > doc/results04/tests.txt 2>&1
lab run --rm --no-deps cli python scripts/conformance04.py > doc/results04/conformance.txt 2>&1
lab run --rm --no-deps cli python tests04/benchmark.py > doc/results04/performance.json 2>&1
lab run --rm --no-deps cli python tests04/partition.py before > doc/results04/partition.txt 2>&1
witness_container=$(lab ps -q aw4)
docker network disconnect "${COMPOSE_PROJECT_NAME}_protocol" "$witness_container"
lab run --rm --no-deps cli python tests04/partition.py during >> doc/results04/partition.txt 2>&1
docker network connect --alias aw4 "${COMPOSE_PROJECT_NAME}_protocol" "$witness_container"
lab run --rm --no-deps cli python tests04/disappearing.py before > doc/results04/product.txt 2>&1
lab stop laravel product-db protocol-adapter > doc/results04/disappearing-containers.txt 2>&1
lab run --rm --no-deps cli python tests04/disappearing.py after > doc/results04/disappearing.txt 2>&1
lab run --rm --no-deps cli python tests04/process_recovery.py before > doc/results04/process-recovery.txt 2>&1
lab stop aw4 >> doc/results04/process-recovery.txt 2>&1
lab run --rm --no-deps cli python tests04/process_recovery.py during >> doc/results04/process-recovery.txt 2>&1
lab start aw4 >> doc/results04/process-recovery.txt 2>&1
lab run --rm --no-deps cli python tests04/process_recovery.py after >> doc/results04/process-recovery.txt 2>&1
printf 'Generation 0.4 experiments complete. Results: doc/results04/\n'
