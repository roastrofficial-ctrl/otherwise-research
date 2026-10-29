#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise08-$(date +%s)-$$"
mkdir -p doc/results08
lab() { docker compose --env-file .env05 -f compose08.yaml "$@"; }
cleanup() { lab down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
if [ ! -f .env05 ]; then ./scripts/lab05.sh config --quiet; fi
lab build cli recipient > doc/results08/build.txt 2>&1
if [ ! -f .tls08/ca.pem ]; then
  mkdir -p .tls08
  chmod 700 .tls08
  docker run --rm --network none -v "$PWD/.tls08:/out" -v "$PWD/scripts/create_tls08.py:/setup.py:ro" "${COMPOSE_PROJECT_NAME}-cli" python /setup.py
fi
lab up -d --build aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3 > doc/results08/start.txt 2>&1
if [ "${1:-}" != --benchmark-only ]; then
  if ! lab run --rm --no-deps cli > doc/results08/tests.txt 2>&1; then
    lab logs --no-color > doc/results08/failure-services.txt
    cat doc/results08/tests.txt
    exit 1
  fi
  lab run --rm --no-deps recipient > doc/results08/offline-recipient.json
  lab run --rm --no-deps cli cat /recovery/finality08.json > doc/results08/schedules.json
  lab run --rm --no-deps cli python scripts/conformance08.py > doc/results08/conformance08.txt
  lab run --rm --no-deps cli python tests08/modelcheck.py > doc/results08/modelcheck.json
fi
if [ "${1:-}" = --tests-only ]; then exit 0; fi
lab run --rm --no-deps cli python tests08/benchmark.py > doc/results08/performance.json
 : > doc/results08/storage.jsonl
for role in aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3; do
  lab exec -T "$role" python -c 'import os,json,sqlite3; from pathlib import Path; role=os.environ["DOMAIN"]; names=["available.db","finality08.db"] if role=="witness" else ["custody06.db"]; out={"domain":role,"index":os.environ["INDEX"],"files":{n:Path("/state",n).stat().st_size for n in names}}; p="/state/available.db" if role=="witness" else "/state/custody06.db"; out["capsules"]=sqlite3.connect(p).execute("select count(*) from capsules").fetchone()[0]; print(json.dumps(out))' >> doc/results08/storage.jsonl
done
lab run --rm --no-deps cli python tests06/runtime.py > doc/results08/runtime.json
