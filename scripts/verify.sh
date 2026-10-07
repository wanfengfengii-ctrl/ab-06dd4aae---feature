#!/bin/sh
# One-shot verification for the fMP4 audit service.
#
#   1. go unit tests          (code tests)
#   2. go vet + go build      (build checks)
#   3. wait for API health
#   4. HTTP smoke: continuous and broken decode timelines
#
# Exit code 0 = all checks passed, non-zero = failure.
set -eu
cd "$(dirname "$0")/.."

echo "[verify] 1/4 unit tests (go test ./...)"
go test -buildvcs=false ./...

echo "[verify] 2/4 build checks (go vet, go build)"
go vet -buildvcs=false ./...
go build -buildvcs=false -o /tmp/fmp4-server ./cmd/server
go build -buildvcs=false -o /tmp/fmp4-smoke ./cmd/smoke

API_URL="${API_URL:-http://api:8080}"
echo "[verify] 3/4 waiting for API health at ${API_URL}/healthz"
i=0
while [ "$i" -lt 60 ]; do
  if wget -q -O /dev/null "${API_URL}/healthz" 2>/dev/null; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$i" -ge 60 ]; then
  echo "[verify] ERROR: API did not become healthy in time" >&2
  exit 1
fi

echo "[verify] 4/4 HTTP smoke tests (continuous + broken timelines)"
/tmp/fmp4-smoke -url "${API_URL}"

echo "[verify] all checks passed"
