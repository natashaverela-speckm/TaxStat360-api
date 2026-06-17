#!/usr/bin/env bash
# Post-deploy smoke check for the taxstat360 API.
#
# A past MFA refactor dropped /aria and /auth/verification-status from the build.
# Deploys are a manual file copy with no CI gate, so the missing routes shipped
# silently (live 404s). Run this AFTER restarting taxstat360.service to confirm
# every critical route is still registered. Exits non-zero if any route 404s, so
# a dropped route fails the deploy loudly instead of reaching users.
#
# Usage:  bash scripts/smoke_check.sh [BASE_URL]
#         BASE_URL defaults to http://127.0.0.1:8000 (run on the EC2 box).
set -u
BASE="${1:-http://127.0.0.1:8000}"
fail=0

check() {
  method="$1"; path="$2"
  if [ "$method" = "POST" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE$path" -H 'Content-Type: application/json' -d '{}')
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path")
  fi
  if [ "$code" = "404" ]; then
    echo "FAIL  $method $path -> 404 (route NOT registered)"
    fail=1
  else
    echo "ok    $method $path -> $code"
  fi
}

# A 404 means the route was dropped. 200/401/403/405 all mean it exists (fine).
check POST "/aria"
check GET "/auth/verification-status?email=probe@example.com"
check GET "/auth/me"
check GET "/records"

if [ "$fail" -ne 0 ]; then
  echo "SMOKE CHECK FAILED: a critical route is missing. Do not treat this deploy as healthy."
  exit 1
fi
echo "SMOKE CHECK PASSED: all critical routes registered."
