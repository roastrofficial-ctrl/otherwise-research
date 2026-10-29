#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise07-baseline-$(date +%s)-$$"
export OTHERWISE_05_CLOCK_MODE=test
export OTHERWISE_06_SUBNET=10.207.8.0/24
config=$(mktemp /tmp/otherwise07-baseline.XXXXXX)
cat > "$config" <<'YAML'
services:
  cli:
    build: {dockerfile: Dockerfile.protocol07}
YAML
lab() { docker compose --env-file .env05 -f compose05.yaml -f compose06.yaml -f "$config" "$@"; }
cleanup() { lab down -v --remove-orphans >/dev/null 2>&1 || true; rm -f "$config"; }
trap cleanup EXIT INT TERM
lab build cli aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results07/baseline-build.txt 2>&1
lab up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results07/baseline-start.txt 2>&1
lab run --rm --no-deps cli python tests07/benchmark.py --baseline06 > doc/results07/baseline-performance.json
: > doc/results07/baseline-resources.jsonl
for role in aw1 aw2 aw3 aw4 ak1 ak2 ak3; do
  lab exec -T "$role" python -c 'import os,json,sqlite3; role=os.environ["ROLE"]; p="/state/custody06.db" if role=="custodian" else "/state/available.db"; d=sqlite3.connect(p); print(json.dumps({"domain":role,"index":os.environ["INDEX"],"capsules":d.execute("select count(*) from capsules").fetchone()[0],"db_bytes":os.stat(p).st_size,"cpu_stat":open("/sys/fs/cgroup/cpu.stat").read(),"memory_current":open("/sys/fs/cgroup/memory.current").read().strip(),"memory_peak":open("/sys/fs/cgroup/memory.peak").read().strip()}))' >> doc/results07/baseline-resources.jsonl
done
