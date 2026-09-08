#!/usr/bin/env bash
# Extract audit records from a log stream that also carries diagnostics.
#
# The gate writes audit records to stdout and diagnostics to stderr, which is
# the right split for a terminal and for `docker logs`. It is not the split the
# deployment gets: the awslogs driver collects both into ONE CloudWatch stream,
# so the log an operator actually fetches is interleaved and does not parse as
# one JSON object per line. `egressgate verify` reads it and reports
#
#   chain BROKEN at record 1: could not decode record: invalid character 'l'
#
# where the 'l' is the first letter of a `listening:` startup line. The chain is
# intact; the stream just is not only the chain.
#
# This filter is the documented way to read such a stream. It is deliberately
# not a "quiet mode" in the gate: the diagnostics are worth keeping, and a flag
# that suppressed them would trade a readable log for a verifiable one when you
# can have both.
#
#   aws logs tail /ecs/egress-gate --format short \
#     | scripts/extract-audit.sh \
#     | egressgate verify --audit /dev/stdin
#
# Reads stdin, writes matching records to stdout. Exits 4 if the input held no
# audit records at all, because an empty chain verifies clean and a silent
# extraction would otherwise look like a healthy gate.
set -euo pipefail

# Every record begins `{"seq":` and nothing else does. That is not a guess about
# formatting: audit.Record declares Seq first, Go marshals struct fields in
# declaration order, and the chain hashes that encoding -- so the field order is
# pinned by TestHashIsStable and cannot drift without failing the suite. A log
# line that is not a record cannot begin this way, because the diagnostics are
# slog text.
#
# awslogs and `aws logs tail` may prefix each line with a timestamp, so the
# match is anchored to the record rather than to the start of the line, and the
# prefix is stripped.
count=0
while IFS= read -r line; do
  case "$line" in
    *'{"seq":'*)
      printf '%s\n' "${line#*\{\"seq\":}" | sed 's/^/{"seq":/'
      count=$((count + 1))
      ;;
  esac
done

if [ "$count" -eq 0 ]; then
  echo "extract-audit: no audit records found in input" >&2
  exit 4
fi
