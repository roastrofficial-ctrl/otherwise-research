#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
./scripts/experiment08.sh --benchmark-only > doc/results08/performance-run.txt 2>&1
./scripts/benchmark08-baseline.sh >> doc/results08/performance-run.txt 2>&1
