#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise07-$(date +%s)-$$"
mkdir -p doc/results07
lab() { docker compose --env-file .env05 -f compose07.yaml "$@"; }
cleanup() { lab down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
if [ ! -f .env05 ]; then ./scripts/lab05.sh config --quiet; fi
lab build cli > doc/results07/build.txt 2>&1
if [ ! -f .tls07/ca.pem ]; then
  mkdir -p .tls07
  chmod 700 .tls07
  docker run --rm --network none -v "$PWD/.tls07:/out" -v "$PWD/scripts/create_tls07.py:/setup.py:ro" "${COMPOSE_PROJECT_NAME}-cli" python /setup.py
fi
lab up -d --build aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3 > doc/results07/start.txt 2>&1
if [ "${1:-}" != --benchmark-only ]; then
if ! lab run --rm --no-deps cli > doc/results07/tests.txt 2>&1; then
  lab logs --no-color > doc/results07/failure-services.txt
  cat doc/results07/tests.txt
  exit 1
fi
lab run --rm --no-deps cli cat /recovery/attacks07.json > doc/results07/attacks.json
lab run --rm --no-deps cli python scripts/conformance04.py > doc/results07/conformance04.txt
lab run --rm --no-deps cli python scripts/conformance07.py > doc/results07/conformance07.txt
fi
lab run --rm --no-deps cli python tests07/benchmark.py > doc/results07/performance.json
: > doc/results07/resources.jsonl
for role in aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3; do
  lab exec -T "$role" python -c 'import os,json,sqlite3; p="/state/custody06.db" if os.environ["DOMAIN"]!="witness" else "/state/available.db"; d=sqlite3.connect(p); print(json.dumps({"domain":os.environ["DOMAIN"],"index":os.environ["INDEX"],"capsules":d.execute("select count(*) from capsules").fetchone()[0],"db_bytes":os.stat(p).st_size,"cpu_stat":open("/sys/fs/cgroup/cpu.stat").read(),"memory_current":open("/sys/fs/cgroup/memory.current").read().strip(),"memory_peak":open("/sys/fs/cgroup/memory.peak").read().strip()}))' >> doc/results07/resources.jsonl
done
if [ "${1:-}" != --benchmark-only ]; then
lab run --rm --no-deps cli python tests07/scenario.py before > doc/results07/recovery.txt
lab stop aw4 >> doc/results07/recovery.txt 2>&1
lab run --rm --no-deps cli python tests07/scenario.py stopped >> doc/results07/recovery.txt
lab start aw4 >> doc/results07/recovery.txt 2>&1
lab run --rm --no-deps cli python tests07/scenario.py repaired >> doc/results07/recovery.txt
fi
lab run --rm --no-deps cli python tests06/runtime.py > doc/results07/runtime.json
cat doc/results07/tests.txt
