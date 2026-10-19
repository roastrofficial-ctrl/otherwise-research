#!/bin/sh
set -eu
mkdir -p doc/results
docker compose build
if docker compose run -T --rm experiment > doc/results/latest-tests.txt 2>&1; then
  cat doc/results/latest-tests.txt
else
  cat doc/results/latest-tests.txt
  exit 1
fi
docker compose run -T --rm demo > doc/results/latest-demo.txt 2>&1
cat doc/results/latest-demo.txt
