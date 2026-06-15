# Milestone 1 — EC2 backend deploy runbook

Manual deploy for `/home/ubuntu/risk-planner-BE/app/main.py` on the TaxStat360 EC2 instance.
GitHub `taxstat360-api` is the source of truth after each deploy.

## Prerequisites

- AWS Session Manager access to the EC2 instance
- `taxstat360-users` DynamoDB table exists (on-demand, encryption on)
- `taxstat360-records` DynamoDB table exists (PK `userId` String, SK `recordId` Number, on-demand, encryption on)
- EC2 role `TaxStat360-EC2-SSM-Role` has DynamoDB access:
  - **Users:** `GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `Scan`, `DescribeTable` on `taxstat360-users`
  - **Records:** `GetItem`, `PutItem`, `DeleteItem`, `Query`, `DescribeTable` on `taxstat360-records`
- `.env` on server includes `SECRET_KEY`, `SENDGRID_API_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`

## 1. Backup (always first)

```bash
TS=$(date +%Y%m%d_%H%M%S)
sudo mkdir -p /home/ubuntu/backups
sudo cp /home/ubuntu/risk-planner-BE/app/main.py /home/ubuntu/backups/taxstat360_${TS}_main.py
sudo cp /home/ubuntu/risk-planner-BE/users.json /home/ubuntu/backups/taxstat360_${TS}_users.json 2>/dev/null || true
echo "Backup TS=$TS"
```

## 2. Deploy code

**Option A — from GitHub (after merging to `main`):**

```bash
cd /home/ubuntu/risk-planner-BE
sudo -u ubuntu git pull origin main   # only if repo is cloned here; skip if hand-copying
```

**Option B — copy `app/main.py` via Session Manager** (paste or upload), then:

```bash
sudo chown ubuntu:ubuntu /home/ubuntu/risk-planner-BE/app/main.py
```

## 3. Syntax check

```bash
sudo -u ubuntu /home/ubuntu/risk-planner-BE/venv/bin/python3 -m py_compile /home/ubuntu/risk-planner-BE/app/main.py && echo "py_compile OK"
sudo -u ubuntu bash -c 'cd /home/ubuntu/risk-planner-BE && ./venv/bin/python3 -c "from app.main import app; print(\"IMPORT_OK\")"'
```

## 4. Restart service

```bash
sudo systemctl restart taxstat360.service
sleep 2
sudo systemctl is-active taxstat360.service
```

Do **not** leave the service stopped.

## 5. Smoke tests

```bash
# Unauthenticated
curl -s -m 5 -w "\nHTTP %{http_code}\n" "http://127.0.0.1:8000/auth/me"

# Register test user
TS=$(date +%Y%m%d_%H%M%S)
EMAIL="deploytest${TS}@example.com"
curl -s -c /tmp/ts360.txt -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Deploy Test\",\"email\":\"$EMAIL\",\"password\":\"TestPassword123!\",\"plan\":\"starter\"}"
curl -s -b /tmp/ts360.txt "http://127.0.0.1:8000/auth/me"
```

Expected: first call `401`; register `{"ok":true,...}`; `/auth/me` returns email + plan.

### M2 records smoke test (session cookie)

```bash
TS=$(date +%Y%m%d_%H%M%S)
EMAIL="recordtest${TS}@example.com"
PASS="TestPassword123!"

curl -s -c /tmp/ts360.txt -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Record Test\",\"email\":\"$EMAIL\",\"password\":\"$PASS\",\"plan\":\"starter\"}"

curl -s -b /tmp/ts360.txt -X PUT "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d "{\"id\":1234567890,\"name\":\"Test record\",\"savedAt\":\"Jun 15 2026\"}"

curl -s -b /tmp/ts360.txt "http://127.0.0.1:8000/records"
```

Expected: PUT returns the record with `updatedAt`; GET returns a one-item array.

## Milestone 3 — 2FA (TOTP)

### Install Python deps (once per server)

```bash
sudo -u ubuntu /home/ubuntu/risk-planner-BE/venv/bin/pip install pyotp 'qrcode[pil]' cryptography
```

Deploy `app/main.py` from `taxstat360-api` `main` (includes `/auth/mfa/*` and login MFA challenge).

### M3 smoke test (Session Manager)

```bash
# 1) Register + session
TS=$(date +%Y%m%d_%H%M%S)
EMAIL="mfatest${TS}@example.com"
PASS="TestPassword123!"
curl -s -c /tmp/mfa.txt -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"MFA Test\",\"email\":\"$EMAIL\",\"password\":\"$PASS\",\"plan\":\"starter\"}"

# 2) MFA status (should be disabled)
curl -s -b /tmp/mfa.txt "http://127.0.0.1:8000/auth/mfa/status"

# 3) Start setup — copy "secret" from JSON, add to Google Authenticator
curl -s -b /tmp/mfa.txt -X POST "http://127.0.0.1:8000/auth/mfa/setup"

# 4) Verify with 6-digit TOTP code from app (replace CODE)
curl -s -b /tmp/mfa.txt -X POST "http://127.0.0.1:8000/auth/mfa/verify" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'

# 5) Login requires MFA — no session cookie until challenge
curl -s -c /tmp/mfa2.txt -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}"
# Expect: {"mfa_required":true,"login_token":"...","email":"..."}

# 6) Complete challenge (replace LOGIN_TOKEN and CODE)
curl -s -c /tmp/mfa2.txt -X POST "http://127.0.0.1:8000/auth/mfa/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"login_token\":\"LOGIN_TOKEN\",\"code\":\"123456\"}"
```

Frontend: Settings → Enable 2FA (QR scan) → log out → log in → enter TOTP code.

## 6. Sync to GitHub

After a successful deploy, commit the same `app/main.py` to `natashaverela-speckm/taxstat360-api` on `main` (or PR).

## Rollback

```bash
sudo cp /home/ubuntu/backups/taxstat360_YYYYMMDD_HHMMSS_main.py /home/ubuntu/risk-planner-BE/app/main.py
sudo systemctl restart taxstat360.service
```

## Notes

- `ensure_pw.sh` resets `admin@taxstat360.com` in **users.json** only; auth reads **DynamoDB**. Update admin password in DynamoDB separately if needed.
- Frontend (Amplify) auto-deploys from `taxstat360` repo; backend does not.
- Do not commit `.env` or `users.json` to git.
