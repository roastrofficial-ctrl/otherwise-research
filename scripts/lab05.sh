#!/bin/sh
# Local laboratory only; secrets generated once in an ignored mode-600 file.
set -eu
: "${COMPOSE_PROJECT_NAME:=otherwise05-secure}"
export COMPOSE_PROJECT_NAME
cd "$(dirname "$0")/.."
if [ ! -f .env05 ]; then
  umask 077
  {
    echo "OTHERWISE_05_FAULT_TOKEN=$(openssl rand -hex 32)"
    echo "OTHERWISE_05_HOSTILE_TOKEN=$(openssl rand -hex 32)"
    echo "OTHERWISE_05_CREATOR_PASSPHRASE=$(openssl rand -hex 32)"
    echo "OTHERWISE_05_DB_PASSWORD=$(openssl rand -hex 32)"
    echo "OTHERWISE_05_APP_KEY=base64:$(openssl rand -base64 32)"
  } > .env05
fi
if [ "${1:-}" = up ] && [ ! -f .tls05/ca.pem ]; then
  mkdir -p .tls05
  chmod 700 .tls05
  docker build -f Dockerfile.protocol05 -t otherwise05-tls-setup . > /tmp/otherwise05-tls-build.log 2>&1
  docker run --rm --network none -v "$PWD/.tls05:/out" -v "$PWD/scripts/create_tls05.py:/setup.py:ro" otherwise05-tls-setup python /setup.py
fi
exec docker compose --env-file .env05 -f compose05.yaml "$@"
