#!/bin/sh
set -eu
mkdir -p doc/results02
# Unique, disposable cluster; never stop or delete another run's volumes.
export COMPOSE_PROJECT_NAME="otherwise02-$(date +%s)-$$"
export OTHERWISE_WITNESS_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_C1_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_C2_TOKEN="$(openssl rand -hex 32)"
export OTHERWISE_C3_TOKEN="$(openssl rand -hex 32)"
cleanup() { docker compose --profile bounded down -v --remove-orphans > /dev/null 2>&1; }
trap cleanup EXIT HUP INT TERM
docker compose --profile bounded build
docker compose run -T --rm experiment > doc/results02/generation01.txt 2>&1
cat doc/results02/generation01.txt
docker compose --profile bounded up -d witness custodian1 custodian2 custodian3 operator
if docker compose --profile bounded run -T --rm bounded-tests > doc/results02/latest-tests.txt 2>&1; then
  cat doc/results02/latest-tests.txt
else
  cat doc/results02/latest-tests.txt
  docker compose --profile bounded logs --no-color > doc/results02/service-failure.txt
  exit 1
fi
docker compose run -T --rm experiment python scripts/conformance02.py > doc/results02/conformance.txt 2>&1
cat doc/results02/conformance.txt
docker compose --profile bounded run -T --rm bounded-tests python -m App.demo02 > doc/results02/demo.txt 2>&1
cat doc/results02/demo.txt
docker compose run -T --rm experiment python -c 'import sys,sqlite3,cryptography,Crypto,subprocess; print(sys.version); print("SQLite",sqlite3.sqlite_version); print("cryptography",cryptography.__version__); print("PyCryptodome",Crypto.__version__); print(subprocess.check_output(["node","--version"]).decode().strip())' > doc/results02/runtime.txt 2>&1
cat doc/results02/runtime.txt
