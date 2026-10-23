#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise06-baseline-$(date +%s)-$$"
export OTHERWISE_05_CLOCK_MODE=test
config=$(mktemp /tmp/otherwise06-baseline.XXXXXX)
cat > "$config" <<'YAML'
networks:
  protocol:
    ipam:
      config: [{subnet: 10.206.12.0/24}]
YAML
lab() { docker compose --env-file .env05 -f compose05.yaml -f "$config" "$@"; }
cleanup() { lab down -v --remove-orphans >/dev/null 2>&1 || true; rm -f "$config"; }
trap cleanup EXIT INT TERM
lab build cli aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results06/baseline-build.txt 2>&1
lab up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 > doc/results06/baseline-start.txt 2>&1
lab run --rm --no-deps -v "$PWD/Honest:/otherwise/Honest:ro" -v "$PWD/tests06:/otherwise/tests06:ro" cli python tests06/benchmark.py --baseline > doc/results06/baseline-performance.json

: > doc/results06/baseline-physical-storage.jsonl
for role in ak1 ak2 ak3; do
  lab exec -T "$role" python -c 'import json,os,sqlite3; p="/state/available.db"; d=sqlite3.connect(p); print(json.dumps({"index":os.environ["INDEX"],"capsules":d.execute("select count(*) from capsules").fetchone()[0],"db_bytes":os.stat(p).st_size,"identity_bytes":os.stat("/state/identity.json").st_size}))' >> doc/results06/baseline-physical-storage.jsonl
done
