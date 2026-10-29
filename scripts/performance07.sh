#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
./scripts/experiment07.sh --benchmark-only > doc/results07/performance-run.txt 2>&1
./scripts/benchmark07-baseline.sh >> doc/results07/performance-run.txt 2>&1
