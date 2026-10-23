#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise06-$(date +%s)-$$"
export OTHERWISE_05_CLOCK_MODE=test
mkdir -p doc/results06
lab() { docker compose --env-file .env05 -f compose05.yaml -f compose06.yaml "$@"; }
cleanup() { lab down -v --remove-orphans > /dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# Existing lab05 bootstrap creates local TLS certificates and .env05 if absent.
if [ ! -f .env05 ]; then ./scripts/lab05.sh config --quiet; fi
if [ ! -f .tls05/ca.pem ]; then
  mkdir -p .tls05
  chmod 700 .tls05
  docker build -f Dockerfile.protocol05 -t otherwise06-tls-setup . > doc/results06/tls-build.txt 2>&1
  docker run --rm --network none -v "$PWD/.tls05:/out" -v "$PWD/scripts/create_tls05.py:/setup.py:ro" otherwise06-tls-setup python /setup.py
fi
lab build cli aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results06/build.txt 2>&1
lab up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results06/start.txt 2>&1
if [ "${1:-}" != --benchmark-only ]; then
if ! lab run --rm --no-deps cli > doc/results06/tests.txt 2>&1; then
  lab logs --no-color > doc/results06/failure-services.txt
  cat doc/results06/tests.txt
  exit 1
fi
lab run --rm --no-deps cli cat /recovery/attacks06.json > doc/results06/attacks.json
lab run --rm --no-deps cli cat /recovery/reference06.json > doc/results06/reference-vector.json
fi
lab run --rm --no-deps cli python tests06/benchmark.py > doc/results06/performance.json
: > doc/results06/physical-storage.jsonl
for role in ak1 ak2 ak3; do
  lab exec -T "$role" python -c 'import json,os,sqlite3; p="/state/custody06.db"; d=sqlite3.connect(p); print(json.dumps({"index":os.environ["INDEX"],"capsules":d.execute("select count(*) from capsules").fetchone()[0],"db_bytes":os.stat(p).st_size,"identity_bytes":os.stat("/state/identity.json").st_size}))' >> doc/results06/physical-storage.jsonl
done
lab run --rm --no-deps cli python scripts/conformance04.py > doc/results06/conformance04.txt
lab run --rm --no-deps cli python tests06/runtime.py > doc/results06/runtime.json
cat doc/results06/tests.txt
