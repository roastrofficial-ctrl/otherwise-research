#!/bin/sh
set -eu
mkdir -p doc/results03
# Preserve, and rerun, every previous-generation experiment and successful attack.
./scripts/experiment02.sh > doc/results03/previous-generations.txt 2>&1
export COMPOSE_PROJECT_NAME="otherwise03-$(date +%s)-$$"
export OTHERWISE_03_RW1_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_03_RW2_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_03_RW3_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_03_RK1_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_03_RK2_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_03_RK3_TOKEN="$(openssl rand -hex 32)"
cleanup() { docker compose --profile retained down -v --remove-orphans > /dev/null 2>&1; }
trap cleanup EXIT HUP INT TERM
docker compose --profile retained build
docker compose --profile retained up -d rw1 rw2 rw3 rk1 rk2 rk3
if docker compose --profile retained run -T --rm retained-tests > doc/results03/tests.txt 2>&1; then
 cat doc/results03/tests.txt
else
 cat doc/results03/tests.txt
 docker compose --profile retained logs --no-color > doc/results03/failure-services.txt
 exit 1
fi
docker compose run -T --rm experiment python scripts/conformance03.py > doc/results03/conformance.txt 2>&1
cat doc/results03/conformance.txt
docker compose --profile retained run -T --rm retained-tests python -m Retained.benchmark > doc/results03/performance.json
cat doc/results03/performance.json
