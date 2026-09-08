#!/usr/bin/env bash
# Run the tests with the race detector and enforce a statement-coverage floor.
#
# The floor lives here rather than in CI so that a local run and a CI run
# agree. A gate you cannot reproduce locally is a gate people learn to ignore.
set -euo pipefail

FLOOR="${COVERAGE_FLOOR:-90}"
PROFILE="${COVERAGE_PROFILE:-coverage.out}"

go test -race -covermode=atomic -coverprofile="$PROFILE" ./...

TOTAL="$(go tool cover -func="$PROFILE" | awk '/^total:/ {print $3}' | tr -d '%')"

# Integer arithmetic on tenths of a percent, so the comparison does not depend
# on a locale-sensitive floating point shell.
total_tenths="$(printf '%.1f' "$TOTAL" | tr -d '.')"
floor_tenths="$(printf '%.1f' "$FLOOR" | tr -d '.')"

if [ "$total_tenths" -lt "$floor_tenths" ]; then
  echo "FAIL: statement coverage ${TOTAL}% is below the ${FLOOR}% floor" >&2
  echo "" >&2
  echo "Least covered functions:" >&2
  go tool cover -func="$PROFILE" | grep -v '100.0%' | grep -v '^total:' | sort -k3 -n | head -15 >&2
  exit 1
fi

echo "OK: statement coverage ${TOTAL}% meets the ${FLOOR}% floor"
