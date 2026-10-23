#!/bin/sh
# Sequential fresh clusters; preserve the full conformance run's test/attack artifacts.
set -eu
cd "$(dirname "$0")/.."
./scripts/experiment06.sh --benchmark-only > doc/results06/performance-run.txt 2>&1
./scripts/benchmark06-baseline.sh >> doc/results06/performance-run.txt 2>&1
