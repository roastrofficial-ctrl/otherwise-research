#!/bin/sh
# Local laboratory only; secrets generated once in an ignored mode-600 file.
set -eu
: "${COMPOSE_PROJECT_NAME:=otherwise04}"
export COMPOSE_PROJECT_NAME
cd "$(dirname "$0")/.."
if [ ! -f .env04 ]; then
  umask 077
  {
    echo "OTHERWISE_04_FAULT_TOKEN=$(openssl rand -hex 32)"
    echo "OTHERWISE_04_DB_PASSWORD=$(openssl rand -hex 32)"
    echo "OTHERWISE_04_APP_KEY=base64:$(openssl rand -base64 32)"
  } > .env04
fi
exec docker compose --env-file .env04 -f compose04.yaml "$@"
