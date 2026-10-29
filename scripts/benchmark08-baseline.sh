#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="otherwise08-baseline-$(date +%s)-$$"
export OTHERWISE_07_SUBNET=10.208.9.0/24
config=$(mktemp /tmp/otherwise08-baseline.XXXXXX)
cat > "$config" <<'YAML'
services:
  cli:
    build: {dockerfile: Dockerfile.protocol08}
YAML
lab() { docker compose --env-file .env05 -f compose07.yaml -f "$config" "$@"; }
cleanup() { lab down -v --remove-orphans >/dev/null 2>&1 || true; rm -f "$config"; }
trap cleanup EXIT INT TERM
lab build cli aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3 > doc/results08/baseline-build.txt 2>&1
lab up -d aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3 > doc/results08/baseline-start.txt 2>&1
lab run --rm --no-deps cli python tests08/benchmark07.py > doc/results08/baseline-performance.json

: > doc/results08/baseline-storage.jsonl
for role in aw1 aw2 aw3 aw4 ak1 ak2 ak3 aa1 aa2 aa3; do
  lab exec -T "$role" python -c 'import os,json,sqlite3; from pathlib import Path; role=os.environ["DOMAIN"]; n="available.db" if role=="witness" else "custody06.db"; print(json.dumps({"domain":role,"index":os.environ["INDEX"],"files":{n:Path("/state",n).stat().st_size},"capsules":sqlite3.connect("/state/"+n).execute("select count(*) from capsules").fetchone()[0]}))' >> doc/results08/baseline-storage.jsonl
done
