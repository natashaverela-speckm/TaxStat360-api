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
#         BASE=https://app.taxstat360.com bash scripts/smoke_check.sh
#         BASE_URL=https://app.taxstat360.com bash scripts/smoke_check.sh
#         The target defaults to http://127.0.0.1:8000 (run on the EC2 box).
# FOURTH READ (14 Sep 2026): the argument form and the env forms are all accepted.
# Previously only $1 was read, so the env form the runbook documents silently fell back
# to localhost — and, once the header check landed, silently skipped it (caught live on
# the 14 Sep deploy). Argument wins, then BASE, then BASE_URL (third pass: the usage line
# said BASE_URL, so that spelling is honored too). A trailing slash is stripped so
# "https://app.taxstat360.com/" does not become ".com//aria".
set -u
BASE="${1:-${BASE:-${BASE_URL:-http://127.0.0.1:8000}}}"
BASE="${BASE%/}"
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
  elif [ "$code" = "000" ]; then
    # Third pass (14 Sep 2026): curl reports 000 when it never got an HTTP answer at all
    # (refused, DNS, TLS, timeout). That used to print as "ok" because it is not a 404.
    echo "FAIL  $method $path -> no HTTP response (connection failed)"
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

# FOURTH READ (14 Sep 2026): the security headers live in nginx, not in the app, so
# nothing in pytest can protect them. Check them at the public edge on every deploy
# (skipped for the default localhost target, which talks to gunicorn directly and
# never sees nginx). Fails on a missing header, a missing includeSubDomains, or a
# version string in Server. See docs/EC2-DEPLOY.md §4b.
case "$BASE" in
  # Anchored: host must be exactly 127.0.0.1 / localhost / [::1] / 0.0.0.0, optionally with a port.
  http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*|http://0.0.0.0|http://0.0.0.0:*|"http://[::1]"|"http://[::1]:"*)
    echo "skip  security-header check (local target bypasses nginx)";;
  *)
    hdrs=$(curl -s -m 10 -D - -o /dev/null "$BASE/auth/me"); rc=$?
    if [ "$rc" -ne 0 ]; then
      # Third pass (14 Sep 2026): one FAIL line for the unreachable edge, not one per header.
      echo "FAIL  could not reach $BASE/auth/me (curl exit $rc) — cannot verify security headers"
      fail=1
      hdrs=""
    fi
    need_header() {
      if [ -z "$hdrs" ]; then return 0; fi
      name="$1"; pattern="$2"
      if printf '%s' "$hdrs" | grep -i "^$name:" | grep -qiE "$pattern"; then
        echo "ok    header $name"
      else
        echo "FAIL  header $name missing or wrong (want /$pattern/)"
        fail=1
      fi
    }
    # HSTS: any max-age of one year (31536000) or more satisfies the policy — a two-year
    # 63072000 must not fail (third-pass review), so the value is compared numerically
    # rather than pattern-matched. includeSubDomains is still required.
    if [ -n "$hdrs" ]; then
      hsts=$(printf '%s' "$hdrs" | grep -i "^strict-transport-security:" | head -n1)
      hsts_age=$(printf '%s' "$hsts" | grep -oiE "max-age=[0-9]+" | head -n1 | cut -d= -f2)
      if [ -n "$hsts_age" ] && [ "$hsts_age" -ge 31536000 ] && printf '%s' "$hsts" | grep -qi "includeSubDomains"; then
        echo "ok    header strict-transport-security (max-age=$hsts_age; includeSubDomains)"
      else
        echo "FAIL  header strict-transport-security missing or wrong (want max-age >= 31536000 and includeSubDomains; got: ${hsts:-<none>})"
        fail=1
      fi
    fi
    need_header "x-frame-options" "DENY"
    need_header "x-content-type-options" "nosniff"
    need_header "referrer-policy" "strict-origin-when-cross-origin"
    need_header "x-permitted-cross-domain-policies" "none"
    if [ -n "$hdrs" ] && printf '%s' "$hdrs" | grep -i "^server:" | grep -qE "[0-9]+\.[0-9]+"; then
      echo "FAIL  Server header advertises a version (set server_tokens off)"
      fail=1
    elif [ -n "$hdrs" ]; then
      echo "ok    Server header carries no version"
    fi
    ;;
esac

if [ "$fail" -ne 0 ]; then
  echo "SMOKE CHECK FAILED: a critical route is missing or a security header is wrong. Do not treat this deploy as healthy."
  exit 1
fi
echo "SMOKE CHECK PASSED: all critical routes registered and security headers present."
