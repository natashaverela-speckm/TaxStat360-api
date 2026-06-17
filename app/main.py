import json, os, hashlib, secrets, stripe, requests, boto3, time, hmac, bcrypt, base64, io
from datetime import date
from decimal import Decimal
from urllib.parse import quote, unquote

from dotenv import load_dotenv

_env_path = "/home/ubuntu/risk-planner-BE/.env"
if os.path.exists(_env_path):
    load_dotenv(_env_path)
else:
    load_dotenv()

import pyotp
import qrcode
from cryptography.fernet import Fernet

from boto3.dynamodb.conditions import Key
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
if not stripe.api_key:
    raise RuntimeError("STRIPE_SECRET_KEY environment variable not set")

MC_KEY = os.environ.get("MC_KEY", "")
MC_LIST = "f546bd92ac"

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.taxstat360.com",
        "https://taxstat360.com",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "/home/ubuntu/risk-planner-BE/users.json"

# --- M1 AUTH (DynamoDB + bcrypt + session cookie) ---
USERS_TABLE = os.environ.get("USERS_TABLE", "taxstat360-users")
SESSION_COOKIE = "ts360_session"
SESSION_MAX_AGE = 7 * 24 * 3600
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-env")

_ddb = boto3.resource("dynamodb", region_name="us-east-1")
_users_tbl = _ddb.Table(USERS_TABLE)


def _to_ddb(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_ddb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_ddb(v) for v in obj]
    return obj


def _from_ddb(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, dict):
        return {k: _from_ddb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_from_ddb(v) for v in obj]
    return obj


def _norm_email(email):
    return (email or "").strip().lower()


def _hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password, stored):
    if not stored:
        return False
    s = str(stored)
    if s.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode(), s.encode())
        except Exception:
            return False
    if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
        return hashlib.sha256(password.encode()).hexdigest() == s
    return False


def _upgrade_password_hash(password, stored):
    if str(stored).startswith("$2"):
        return str(stored)
    return _hash_password(password)


def _resolve_stored_password(item):
    """Prefer bcrypt over legacy SHA-256 when multiple password fields disagree."""
    candidates = [
        item.get("pw"),
        item.get("password_hash"),
        item.get("password"),
    ]
    for c in candidates:
        if c and str(c).startswith("$2"):
            return str(c)
    for c in candidates:
        if c:
            return str(c)
    return ""


def _strip_legacy_user_fields(item):
    """Remove fields written outside the app (legacy JSON / manual DDB edits)."""
    item.pop("password", None)
    item.pop("mfa_secret", None)
    item.pop("mfa_backup_codes", None)
    return item


def ddb_get_user(email):
    email = _norm_email(email)
    if not email:
        return None
    r = _users_tbl.get_item(Key={"email": email})
    item = r.get("Item")
    if not item:
        return None
    item = _from_ddb(item)
    pw = _resolve_stored_password(item)
    if pw:
        item["pw"] = pw
    return item


def ddb_put_user(email, rec):
    email = _norm_email(email)
    item = dict(rec)
    item["email"] = email
    pw = _resolve_stored_password(item)
    if pw:
        item["pw"] = pw
        item["password_hash"] = pw
    elif "pw" in item:
        item["password_hash"] = item["pw"]
    _strip_legacy_user_fields(item)
    _users_tbl.put_item(Item=_to_ddb(item))


def ddb_user_exists(email):
    return ddb_get_user(email) is not None


def ddb_all_users():
    out = {}
    resp = _users_tbl.scan()
    for item in resp.get("Items", []):
        item = _from_ddb(item)
        em = item.get("email")
        if not em:
            continue
        pw = _resolve_stored_password(item)
        if pw:
            item["pw"] = pw
        out[em] = item
    while "LastEvaluatedKey" in resp:
        resp = _users_tbl.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        for item in resp.get("Items", []):
            item = _from_ddb(item)
            em = item.get("email")
            if not em:
                continue
            pw = _resolve_stored_password(item)
            if pw:
                item["pw"] = pw
            out[em] = item
    return out


def load():
    users = ddb_all_users()
    if users:
        return users
    if os.path.exists(DB):
        return json.load(open(DB))
    return {}


def save(u):
    """Write users to DynamoDB. Prefer ddb_put_user(email, rec) for single-user updates."""
    for email, rec in u.items():
        ddb_put_user(email, rec)


def _ddb_update_user_plan(stripe_customer_id, plan):
    """Update one user's plan without re-writing every account (avoids password clobber)."""
    for email, ud in ddb_all_users().items():
        if ud.get("stripe_customer_id") == stripe_customer_id:
            ud["plan"] = plan
            ddb_put_user(email, ud)
            return email
    return None


def _make_session(email):
    payload = f"{_norm_email(email)}:{int(time.time())}:{secrets.token_hex(16)}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    import base64 as _b64
    return _b64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()


def _verify_session(token):
    if not token:
        return None
    try:
        import base64 as _b64
        raw = _b64.urlsafe_b64decode(token.encode()).decode()
        payload, sig = raw.rsplit(":", 1)
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        email, ts, _ = payload.split(":", 2)
        if int(time.time()) - int(ts) > SESSION_MAX_AGE:
            return None
        return _norm_email(email)
    except Exception:
        return None


def _session_email(request):
    return _verify_session(request.cookies.get(SESSION_COOKIE, ""))


def _set_session_cookie(response, email):
    response.set_cookie(
        key=SESSION_COOKIE,
        value=_make_session(email),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
    )


def _clear_session_cookie(response):
    response.delete_cookie(key=SESSION_COOKIE, path="/")


def _user_public(rec, email):
    return {
        "email": email,
        "plan": rec.get("plan", "starter"),
        "name": rec.get("name", ""),
        "verified": rec.get("verified", False),
        "is_admin": _is_admin(email),
    }


# --- M2 RECORDS (DynamoDB sync) ---
RECORDS_TABLE = os.environ.get("RECORDS_TABLE", "taxstat360-records")
_records_tbl = _ddb.Table(RECORDS_TABLE)


def _require_session_user(request):
    email = _session_email(request)
    if not email:
        raise HTTPException(401, "Not authenticated")
    # A session cookie is a stateless signed token valid for SESSION_MAX_AGE, so a
    # deleted account would otherwise keep access until expiry. Verifying the user
    # still exists is what makes account deletion actually invalidate the session
    # (notably for the admin-deletes-someone-else case). Costs one get_item per
    # authenticated request.
    if not ddb_user_exists(email):
        raise HTTPException(401, "Account no longer exists")
    return email


def _record_from_item(item):
    item = _from_ddb(dict(item))
    rid = item.pop("recordId", item.pop("id", None))
    item.pop("userId", None)
    if rid is not None and "id" not in item:
        item["id"] = rid
    return item


def _ddb_query_records(user_id):
    items = []
    kwargs = {"KeyConditionExpression": Key("userId").eq(user_id)}
    while True:
        resp = _records_tbl.query(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items


# --- M4 ACCOUNT DELETION (admin gate + Stripe teardown + audit log) ---
# Implements the self-service / admin "delete account" flow.
#
# DynamoDB has no SQL-style "begin / commit / rollback" transaction that can span
# an external Stripe call, so we get the same guarantee the request asked for a
# different way: do the Stripe teardown FIRST (the step most likely to fail). If
# Stripe errors hard, we raise before touching DynamoDB, so the account is left
# fully intact (never half-deleted). Only once Stripe has succeeded (or is already
# gone) do we delete the DB rows, which are idempotent and safe to retry. An audit
# row is written before AND after so a failure is never silent.

# Admins are configured by env (comma-separated). Defaults to the support admin.
ADMIN_EMAILS = {
    _norm_email(e)
    for e in os.environ.get("ADMIN_EMAILS", "admin@taxstat360.com").split(",")
    if e.strip()
}


def _is_admin(email):
    return _norm_email(email) in ADMIN_EMAILS


# Audit log lives in its own table so deletion leaves proof (who / which user / when)
# even though all of the user's PII is erased. It deliberately stores no tax data.
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "taxstat360-audit")
_audit_tbl = _ddb.Table(AUDIT_TABLE)


def _ensure_audit_table():
    """Best-effort create-if-missing for the audit table. No-op if it already
    exists; if the IAM role can't create tables, this logs and the operator can
    run scripts/create-audit-table.sh once. Deletion never blocks on this."""
    try:
        _audit_tbl.load()
        return
    except Exception:
        pass
    try:
        _ddb.create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[{"AttributeName": "auditId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "auditId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        _audit_tbl.wait_until_exists()
    except Exception as e:
        print(f"AUDIT table auto-create skipped: {e}", flush=True)


def _write_audit(action, actor_email, target_email, status, detail=None):
    item = {
        "auditId": secrets.token_hex(16),
        "ts": int(time.time()),
        "action": action,
        "actor": _norm_email(actor_email),
        "target": _norm_email(target_email),
        "status": status,  # "started" | "completed" | "failed"
    }
    if detail is not None:
        item["detail"] = str(detail)[:1000]
    try:
        _audit_tbl.put_item(Item=_to_ddb(item))
        return {"ok": True, "auditId": item["auditId"]}
    except Exception as e:
        # Loud, not silent: surfaced in logs and in the API response's audit flag.
        print(f"AUDIT write failed ({status}) target={target_email}: {e}", flush=True)
        return {"ok": False, "error": str(e)}


def _stripe_is_missing(e):
    """True when a Stripe error means the resource is already gone (idempotent)."""
    code = getattr(e, "code", "") or ""
    msg = str(getattr(e, "user_message", "") or e)
    return code == "resource_missing" or "no such" in msg.lower()


def _stripe_teardown(stripe_customer_id):
    """Cancel any non-terminal subscriptions, then delete the customer.
    Idempotent: an already-gone customer/subscription is treated as success.
    A genuine Stripe error (network/auth/etc.) is re-raised so the caller aborts
    BEFORE any DB deletion."""
    result = {
        "customer_id": stripe_customer_id or "",
        "subscriptions_canceled": 0,
        "customer_deleted": False,
        "already_absent": False,
    }
    if not stripe_customer_id:
        result["already_absent"] = True
        return result
    try:
        subs = stripe.Subscription.list(customer=stripe_customer_id, status="all", limit=100)
        for s in subs.auto_paging_iter():
            if s.get("status") in ("canceled", "incomplete_expired"):
                continue
            try:
                stripe.Subscription.cancel(s.get("id"))
                result["subscriptions_canceled"] += 1
            except Exception as e:
                if not _stripe_is_missing(e):
                    raise
    except Exception as e:
        if _stripe_is_missing(e):
            result["already_absent"] = True
            return result
        raise
    try:
        stripe.Customer.delete(stripe_customer_id)
        result["customer_deleted"] = True
    except Exception as e:
        if _stripe_is_missing(e):
            result["already_absent"] = True
        else:
            raise
    return result


def _delete_all_user_records(user_id):
    """Erase every saved tax record for a user. Idempotent (no rows -> 0)."""
    user_id = _norm_email(user_id)
    items = _ddb_query_records(user_id)
    count = 0
    with _records_tbl.batch_writer() as bw:
        for it in items:
            rid = it.get("recordId")
            if rid is None:
                continue
            bw.delete_item(Key={"userId": user_id, "recordId": rid})
            count += 1
    return count


def _delete_user_record(email):
    """Delete the user row. delete_item on an absent key is a no-op (idempotent)."""
    _users_tbl.delete_item(Key={"email": _norm_email(email)})


def _perform_account_deletion(target_email, actor_email):
    """Single source of truth for both the self-delete and admin-delete endpoints.
    Order: Stripe -> records -> user -> audit. Re-runnable; never half-commits the
    DB on a Stripe failure."""
    target_email = _norm_email(target_email)
    actor_email = _norm_email(actor_email)
    if not target_email:
        raise HTTPException(400, "Target email required")
    _ensure_audit_table()
    user = ddb_get_user(target_email)  # may be None on an idempotent re-run
    _write_audit("account.delete", actor_email, target_email, "started")
    try:
        stripe_cid = (user or {}).get("stripe_customer_id", "")
        # 1 + 2. Stripe first: a hard failure here aborts before any DB delete.
        stripe_result = _stripe_teardown(stripe_cid)
        # 3. DB: records first, user row last, so a retry after a partial failure
        #    is always clean (the user row stays the anchor until everything else is gone).
        records_deleted = _delete_all_user_records(target_email)
        _delete_user_record(target_email)
        # 4. Audit: proof of who / which user / when.
        completed = _write_audit(
            "account.delete",
            actor_email,
            target_email,
            "completed",
            detail=f"stripe={stripe_result} records_deleted={records_deleted} existed={user is not None}",
        )
        return {
            "ok": True,
            "deleted": target_email,
            "already_absent": user is None,
            "records_deleted": records_deleted,
            "stripe": stripe_result,
            "audit_logged": bool(completed.get("ok")),
        }
    except HTTPException:
        raise
    except Exception as e:
        # Stripe (or an unexpected DB) failure: record it and surface a clear error.
        # On a Stripe failure no DB rows were touched, so the account is intact.
        _write_audit("account.delete", actor_email, target_email, "failed", detail=str(e))
        raise HTTPException(502, f"Account deletion failed before completion: {e}")


# --- M3 MFA (TOTP + encrypted backup codes) ---
MFA_ISSUER = "TaxStat360"
MFA_LOGIN_TTL = 300
MFA_BACKUP_COUNT = 10


def _mfa_fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    return Fernet(key)


def _mfa_encrypt(plain):
    return _mfa_fernet().encrypt(plain.encode()).decode()


def _mfa_decrypt(enc):
    return _mfa_fernet().decrypt(enc.encode()).decode()


def _get_mfa_secret(x, email=None):
    """Read TOTP secret from encrypted storage, with legacy plaintext fallback."""
    enc = x.get("mfa_secret_enc")
    if enc:
        try:
            return _mfa_decrypt(enc)
        except Exception as e:
            print(f"MFA decrypt failed for {email or '?'}: {e}", flush=True)
    plain = x.get("mfa_secret")
    if plain:
        secret = str(plain)
        try:
            x["mfa_secret_enc"] = _mfa_encrypt(secret)
            x.pop("mfa_secret", None)
            if email:
                ddb_put_user(email, x)
        except Exception as e:
            print(f"MFA legacy migrate failed for {email or '?'}: {e}", flush=True)
        return secret
    return None


def _mfa_qr_data_url(otpauth_uri):
    buf = io.BytesIO()
    qrcode.make(otpauth_uri).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _mfa_new_backup_codes():
    codes = []
    hashes = []
    for _ in range(MFA_BACKUP_COUNT):
        raw = secrets.token_hex(4).upper()
        code = f"{raw[:4]}-{raw[4:]}"
        codes.append(code)
        hashes.append(_hash_password(raw))
    return codes, hashes


def _mfa_verify_totp(secret, code):
    code = (code or "").strip()
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def _mfa_normalize_backup(code):
    return (code or "").replace("-", "").replace(" ", "").upper()


def _mfa_verify_backup(hashes, code):
    norm = _mfa_normalize_backup(code)
    if len(norm) != 8:
        return None
    for i, stored in enumerate(hashes or []):
        if _verify_password(norm, stored):
            return i
    return None


def _complete_login(email, x):
    new_tok = secrets.token_hex(32)
    x["tok"] = new_tok
    x.pop("mfa_login_token", None)
    x.pop("mfa_login_exp", None)
    ddb_put_user(email, x)
    plan = x.get("plan", "starter")
    resp = JSONResponse({"ok": True, "plan": plan, "email": email})
    _set_session_cookie(resp, email)
    return resp


def mc_subscribe(email, name=""):
    try:
        fname = name.split(" ")[0] if name else ""
        lname = " ".join(name.split(" ")[1:]) if name and " " in name else ""
        requests.post(
            f"https://us4.api.mailchimp.com/3.0/lists/{MC_LIST}/members",
            auth=("anystring", MC_KEY),
            json={
                "email_address": email,
                "status": "subscribed",
                "merge_fields": {"FNAME": fname, "LNAME": lname},
            },
            timeout=5,
        )
    except Exception:
        pass


def get_user_from_token(request: Request):
    auth = request.headers.get("authorization", "")
    tok = auth.replace("Bearer ", "").strip()
    if not tok:
        raise HTTPException(status_code=401, detail="Authentication required")
    u = load()
    for email, x in u.items():
        if x.get("tok") == tok:
            return {"email": email, **x}
    raise HTTPException(status_code=401, detail="Invalid or expired token")


PLAN_ORDER = ["starter", "professional", "enterprise"]


def require_plan(minimum: str):
    def checker(user=Depends(get_user_from_token)):
        user_plan = user.get("plan", "starter")
        if PLAN_ORDER.index(user_plan) < PLAN_ORDER.index(minimum):
            raise HTTPException(
                status_code=403,
                detail=f"{minimum.capitalize()} plan required to access this feature",
            )
        return user

    return checker


class Reg(BaseModel):
    name: str
    email: str
    password: str
    plan: str = "starter"
    payment_method_id: str = ""


class Log(BaseModel):
    email: str
    password: str


class Sub(BaseModel):
    email: str
    plan: str
    payment_method_id: str
    billing: str = "monthly"


PRICE_IDS = {
    "starter": {"monthly": "price_1TJmmDGUoj1XrJQjbArxsVDy", "annual": "price_1TO5zWGUoj1XrJQjcWpQmMnC"},
    "professional": {"monthly": "price_1TJmmwGUoj1XrJQjZp897iCJ", "annual": "price_1TO60pGUoj1XrJQjhU4R9yGQ"},
    "enterprise": {"monthly": "price_1TJmnKGUoj1XrJQjfgrOhAlC", "annual": "price_1TO62FGUoj1XrJQjtcbNym1Z"},
}

VALID_PLANS = set(PRICE_IDS.keys())
ALLOWED_PROVIDERS = {"quickbooks", "freshbooks", "xero", "wave"}

FRONTEND_URL = "https://www.taxstat360.com"
RESET_FROM = "noreply@taxstat360.com"
RESET_TTL = 3600
VERIFY_TTL = 86400


class ForgotReq(BaseModel):
    email: str


class ResetReq(BaseModel):
    email: str
    token: str
    new_password: str


class MfaCodeReq(BaseModel):
    code: str


class MfaChallengeReq(BaseModel):
    email: str
    login_token: str
    code: str


class ResendVerify(BaseModel):
    email: str


class ChangeEmailReq(BaseModel):
    email: str
    new_email: str


def _send_verification_email(email, verify_tok):
    verify_url = f"https://app.taxstat360.com/auth/verify-email?token={verify_tok}&email={quote(email)}"
    html = (
        '<div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto;padding:40px 24px">'
        '<h2 style="color:#0D1B3E">Confirm your email</h2>'
        "<p>Thanks for signing up for TaxStat360. Please confirm your email address.</p>"
        f'<p><a href="{verify_url}" style="background:#2563EB;color:#fff;padding:12px 20px;'
        'border-radius:8px;text-decoration:none;display:inline-block">Confirm Email</a></p>'
        '<p style="color:#475569;font-size:13px">If you did not create this account, you can ignore this email.</p>'
        "</div>"
    )
    ses = boto3.client("ses", region_name="us-east-1")
    ses.send_email(
        Source=RESET_FROM,
        Destination={"ToAddresses": [email]},
        Message={"Subject": {"Data": "Confirm your email for TaxStat360"}, "Body": {"Html": {"Data": html}}},
    )


@app.post("/auth/register")
@limiter.limit("3/minute")
def register(r: Reg, request: Request):
    email = _norm_email(r.email)
    if ddb_user_exists(email):
        raise HTTPException(400, "Email already registered")
    plan = r.plan if r.plan in VALID_PLANS else "starter"
    tok = secrets.token_hex(32)
    verify_tok = secrets.token_hex(32)
    rec = {
        "name": r.name,
        "pw": _hash_password(r.password),
        "tok": tok,
        "plan": plan,
        "stripe_customer_id": "",
        "verified": False,
        "verify_tok": verify_tok,
        "verify_exp": int(time.time()) + VERIFY_TTL,
    }
    ddb_put_user(email, rec)
    mc_subscribe(email, r.name)
    try:
        _send_verification_email(email, verify_tok)
    except Exception as e:
        print(f"SES verify error: {e}")
    resp = JSONResponse({"ok": True, "plan": plan, "email": email})
    _set_session_cookie(resp, email)
    return resp


@app.post("/auth/login")
@limiter.limit("5/minute")
def login(r: Log, request: Request):
    email = _norm_email(r.email)
    x = ddb_get_user(email)
    if not x or not _verify_password(r.password, x.get("pw", "")):
        raise HTTPException(401, "Invalid email or password")
    x["pw"] = _upgrade_password_hash(r.password, x.get("pw", ""))
    if x.get("mfa_enabled"):
        login_token = secrets.token_hex(32)
        x["mfa_login_token"] = login_token
        x["mfa_login_exp"] = int(time.time()) + MFA_LOGIN_TTL
        new_tok = secrets.token_hex(32)
        x["tok"] = new_tok
        ddb_put_user(email, x)
        return JSONResponse(
            {"mfa_required": True, "login_token": login_token, "email": email}
        )
    return _complete_login(email, x)


@app.get("/auth/mfa/status")
def mfa_status(request: Request):
    email = _require_session_user(request)
    x = ddb_get_user(email)
    return {"enabled": bool(x and x.get("mfa_enabled"))}


@app.post("/auth/mfa/setup")
def mfa_setup(request: Request):
    email = _require_session_user(request)
    x = ddb_get_user(email)
    if not x:
        raise HTTPException(401, "Not authenticated")
    if x.get("mfa_enabled"):
        raise HTTPException(400, "MFA is already enabled")
    secret = pyotp.random_base32()
    x["mfa_pending_secret_enc"] = _mfa_encrypt(secret)
    ddb_put_user(email, x)
    otpauth = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=MFA_ISSUER)
    return {"qr_code_url": _mfa_qr_data_url(otpauth), "secret": secret}


@app.post("/auth/mfa/verify")
def mfa_verify(r: MfaCodeReq, request: Request):
    email = _require_session_user(request)
    x = ddb_get_user(email)
    if not x or not x.get("mfa_pending_secret_enc"):
        raise HTTPException(400, "MFA setup not started")
    secret = _mfa_decrypt(x["mfa_pending_secret_enc"])
    if not _mfa_verify_totp(secret, r.code):
        raise HTTPException(401, "Invalid code — check your authenticator app and try again")
    codes, hashes = _mfa_new_backup_codes()
    x["mfa_enabled"] = True
    x["mfa_secret_enc"] = x["mfa_pending_secret_enc"]
    x.pop("mfa_pending_secret_enc", None)
    x["mfa_backup_hashes"] = hashes
    ddb_put_user(email, x)
    return {"ok": True, "backup_codes": codes}


@app.post("/auth/mfa/disable")
def mfa_disable(r: MfaCodeReq, request: Request):
    email = _require_session_user(request)
    x = ddb_get_user(email)
    if not x or not x.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled")
    secret = _get_mfa_secret(x, email)
    if not secret:
        raise HTTPException(
            503,
            "Two-factor authentication must be set up again. Contact support to reset MFA on your account.",
        )
    if not _mfa_verify_totp(secret, r.code):
        raise HTTPException(401, "Invalid authentication code")
    x["mfa_enabled"] = False
    x.pop("mfa_secret_enc", None)
    x.pop("mfa_backup_hashes", None)
    x.pop("mfa_pending_secret_enc", None)
    ddb_put_user(email, x)
    return {"ok": True}


@app.post("/auth/mfa/challenge")
@limiter.limit("10/minute")
def mfa_challenge(r: MfaChallengeReq, request: Request):
    email = _norm_email(r.email)
    x = ddb_get_user(email)
    if not x or not x.get("mfa_enabled"):
        raise HTTPException(401, "Invalid or expired login")
    if not x.get("mfa_login_token") or not secrets.compare_digest(
        x.get("mfa_login_token", ""), r.login_token
    ):
        raise HTTPException(401, "Invalid or expired login")
    if int(time.time()) > int(x.get("mfa_login_exp", 0)):
        raise HTTPException(401, "Login expired — please sign in again")
    secret = _get_mfa_secret(x, email)
    if not secret:
        raise HTTPException(
            503,
            "Two-factor authentication must be set up again. Contact support to reset MFA on your account.",
        )
    code = (r.code or "").strip()
    if not _mfa_verify_totp(secret, code):
        idx = _mfa_verify_backup(x.get("mfa_backup_hashes") or [], code)
        if idx is None:
            raise HTTPException(401, "Invalid authentication code")
        hashes = list(x.get("mfa_backup_hashes") or [])
        hashes.pop(idx)
        x["mfa_backup_hashes"] = hashes
    return _complete_login(email, x)


@app.get("/auth/me")
def auth_me(request: Request, token: str = ""):
    email = _session_email(request)
    if email:
        x = ddb_get_user(email)
        if x:
            return _user_public(x, email)
    if token:
        u = load()
        for em, x in u.items():
            if x.get("tok") == token:
                return _user_public(x, em)
    raise HTTPException(401, "Not authenticated")


@app.get("/auth/verification-status")
def verification_status(email: str = ""):
    email = _norm_email(email)
    x = ddb_get_user(email)
    if not x:
        return {"verified": False, "email": email}
    return {"verified": bool(x.get("verified", False)), "email": email}


@app.post("/auth/resend-verification")
def resend_verification(r: ResendVerify):
    email = _norm_email(r.email)
    x = ddb_get_user(email)
    if x:
        verify_tok = secrets.token_hex(32)
        x["verify_tok"] = verify_tok
        x["verify_exp"] = int(time.time()) + VERIFY_TTL
        x["verified"] = x.get("verified", False)
        ddb_put_user(email, x)
        try:
            _send_verification_email(email, verify_tok)
        except Exception as e:
            print("resend verification email failed:", e)
    return {"ok": True}


@app.post("/auth/change-email")
def change_email(r: ChangeEmailReq):
    old = _norm_email(r.email)
    new = _norm_email(r.new_email)
    if not old or not new:
        raise HTTPException(400, "Email required")
    x = ddb_get_user(old)
    if not x:
        raise HTTPException(400, "Account not found")
    if new != old and ddb_user_exists(new):
        raise HTTPException(400, "Email already in use")
    if new != old:
        ddb_put_user(new, x)
        _users_tbl.delete_item(Key={"email": old})
    verify_tok = secrets.token_hex(32)
    x = ddb_get_user(new)
    x["verified"] = False
    x["verify_tok"] = verify_tok
    x["verify_exp"] = int(time.time()) + VERIFY_TTL
    ddb_put_user(new, x)
    try:
        _send_verification_email(new, verify_tok)
    except Exception as e:
        print("change-email verification failed:", e)
    return {"ok": True, "email": new}


@app.post("/auth/logout")
def auth_logout():
    resp = JSONResponse({"ok": True})
    _clear_session_cookie(resp)
    return resp


@app.get("/user/me")
def me(user=Depends(get_user_from_token)):
    return {
        "email": user["email"],
        "plan": user.get("plan", "starter"),
        "name": user.get("name", ""),
        "is_admin": _is_admin(user["email"]),
    }


@app.post("/user/business-info")
def biz(user=Depends(get_user_from_token)):
    return {"status": "saved"}


@app.get("/records")
def list_records(request: Request):
    user_id = _require_session_user(request)
    items = _ddb_query_records(user_id)
    out = [_record_from_item(it) for it in items]
    out.sort(key=lambda r: r.get("updatedAt", r.get("id", 0)), reverse=True)
    return out


@app.put("/records")
async def upsert_record(request: Request):
    user_id = _require_session_user(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "Record must be a JSON object")
    record_id = body.get("id")
    if record_id is None:
        raise HTTPException(400, "Record id is required")
    try:
        record_id = int(record_id)
    except (TypeError, ValueError):
        raise HTTPException(400, "Record id must be a number")
    now = int(time.time())
    updated_at = int(body.get("updatedAt", now) or now)
    item = dict(body)
    item["id"] = record_id
    item["updatedAt"] = updated_at
    item["userId"] = user_id
    item["recordId"] = record_id
    _records_tbl.put_item(Item=_to_ddb(item))
    return _record_from_item(item)


@app.delete("/records/{record_id}")
def delete_record(record_id: int, request: Request):
    user_id = _require_session_user(request)
    existing = _records_tbl.get_item(Key={"userId": user_id, "recordId": record_id}).get("Item")
    if not existing:
        raise HTTPException(404, "Record not found")
    _records_tbl.delete_item(Key={"userId": user_id, "recordId": record_id})
    return {"ok": True}


@app.delete("/account")
def delete_own_account(request: Request):
    """Account owner permanently deletes their own account."""
    email = _require_session_user(request)
    result = _perform_account_deletion(email, actor_email=email)
    resp = JSONResponse(result)
    _clear_session_cookie(resp)  # invalidate this session immediately
    return resp


@app.delete("/admin/users/{target_email}")
def admin_delete_user(target_email: str, request: Request):
    """Admin permanently deletes a specified user (e.g. for a request that arrived
    by email). Everyone who is not an admin is rejected with 403."""
    actor = _require_session_user(request)
    if not _is_admin(actor):
        raise HTTPException(403, "Admin access required")
    target = _norm_email(unquote(target_email))
    if not target:
        raise HTTPException(400, "Target email required")
    if target == _norm_email(actor):
        # Guard: don't let an admin wipe their own account by accident from the
        # admin tool. Self-deletion must go through Settings deliberately.
        raise HTTPException(
            400,
            "Admins can't delete their own account from the admin tool. "
            "Use Settings -> Delete account to remove your own account.",
        )
    result = _perform_account_deletion(target, actor_email=actor)
    return JSONResponse(result)


@app.post("/stripe/setup-intent")
def setup():
    try:
        i = stripe.SetupIntent.create(usage="off_session")
        return {"client_secret": i.client_secret}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/stripe/subscribe")
def subscribe(r: Sub, request: Request):
    try:
        user = {"email": _require_session_user(request)}
        u = load()
        x = u.get(user["email"])
        if not x:
            raise HTTPException(404, "User not found")
        billing = r.billing if r.billing in ["monthly", "annual"] else "monthly"
        plan = r.plan if r.plan in PRICE_IDS else "starter"
        price_id = PRICE_IDS[plan][billing]
        cid = x.get("stripe_customer_id", "")
        if not cid:
            c = stripe.Customer.create(email=user["email"], name=x.get("name", ""))
            cid = c.id
            x["stripe_customer_id"] = cid
        stripe.PaymentMethod.attach(r.payment_method_id, customer=cid)
        stripe.Customer.modify(cid, invoice_settings={"default_payment_method": r.payment_method_id})
        x["plan"] = plan
        x["billing"] = billing
        ddb_put_user(user["email"], x)
        sub = stripe.Subscription.create(
            customer=cid,
            items=[{"price": price_id}],
            trial_period_days=7,
            default_payment_method=r.payment_method_id,
        )
        return {"status": "ok", "customer_id": cid, "subscription_id": sub.id}
    except Exception as e:
        raise HTTPException(400, str(e))


OAUTH = {
    # Production app credentials (must match QUICKBOOKS_CLIENT_SECRET etc. in .env).
    # Prior git client_ids were a different OAuth app registration — token exchange failed.
    "quickbooks": {
        "client_id": os.environ.get(
            "QUICKBOOKS_CLIENT_ID",
            "AB1FhVS3wJV2oOLUXNS8ZlnCHuUFW3XTM20rOydbCln0Pj1vZG",
        ),
        "redirect": "https://app.taxstat360.com/integrations/quickbooks/callback",
        "auth_url": "https://appcenter.intuit.com/app/connect/oauth2",
        "scope": "com.intuit.quickbooks.accounting",
    },
    "freshbooks": {
        "client_id": os.environ.get(
            "FRESHBOOKS_CLIENT_ID",
            "47b688958adf0a8250c4e799d5a258509e5e4f7bdbb7b0940ba2893ce13b7f03",
        ),
        "redirect": "https://app.taxstat360.com/integrations/freshbooks/callback",
        "auth_url": "https://auth.freshbooks.com/oauth/authorize/",
        # user:reports:read required for P&L — must be enabled on the app in FreshBooks Developer.
        "scope": os.environ.get(
            "FRESHBOOKS_SCOPE",
            "user:profile:read user:reports:read",
        ),
    },
    "xero": {
        "client_id": os.environ.get(
            "XERO_CLIENT_ID",
            "B264F13CC72F458AA766E9627ABA95E2",
        ),
        "redirect": "https://app.taxstat360.com/integrations/xero/callback",
        "auth_url": "https://login.xero.com/identity/connect/authorize",
        "scope": os.environ.get(
            "XERO_SCOPE",
            "openid profile email offline_access accounting.reports.profitandloss.read",
        ),
    },
    "wave": {
        "client_id": os.environ.get(
            "WAVE_CLIENT_ID",
            "tV2wa6N3ltIhHVu1S4lgz_CP48xm8loeF4zczbTY",
        ),
        "redirect": "https://app.taxstat360.com/integrations/wave/callback",
        "auth_url": "https://api.waveapps.com/oauth2/authorize/",
        "scope": "account:* business:read",
    },
}

TOKEN_URLS = {
    "quickbooks": "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
    "xero": "https://identity.xero.com/connect/token",
    "wave": "https://api.waveapps.com/oauth2/token/",
    "freshbooks": "https://api.freshbooks.com/auth/oauth/token",
}

OAUTH_SECRET_ENV = {
    "quickbooks": "QUICKBOOKS_CLIENT_SECRET",
    "xero": "XERO_CLIENT_SECRET",
    "wave": "WAVE_CLIENT_SECRET",
    "freshbooks": "FRESHBOOKS_CLIENT_SECRET",
}

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ARIA_MODEL = os.environ.get("ARIA_MODEL", "gpt-4o-mini")
ARIA_SYSTEM = (
    "You are Aria, the TaxStat360 AI tax strategist. Help business owners with federal tax "
    "planning, estimated payments, entity structure, deductions, and compliance-aware guidance. "
    "Be concise, practical, and remind users this is planning guidance—not filing advice. "
    "Never invent user-specific numbers; ask for details when needed."
)


def _oauth_secret(provider):
    env_key = OAUTH_SECRET_ENV.get(provider, "")
    return os.environ.get(env_key, "") if env_key else ""


def _parse_pl_amount(val):
    try:
        s = str(val or "0").replace(",", "").replace("$", "").strip()
        if s.startswith("(") and s.endswith(")"):
            s = "-" + s[1:-1]
        return float(s or 0)
    except (TypeError, ValueError):
        return 0.0


def _pnl_date_range(year=None):
    """Calendar-year P&L window for the selected tax year (full prior years, YTD for current)."""
    today = date.today()
    try:
        y = int(year) if year not in (None, "") else today.year
    except (TypeError, ValueError):
        y = today.year
    start = f"{y}-01-01"
    if y < today.year:
        end = f"{y}-12-31"
    elif y > today.year:
        end = start
    else:
        end = today.isoformat()
    return start, end


def _ytd_range():
    return _pnl_date_range()


def _xero_refresh_access_token(refresh_token):
    if not refresh_token:
        return None
    o = OAUTH["xero"]
    secret = _oauth_secret("xero")
    if not secret:
        return None
    creds = base64.b64encode(f"{o['client_id']}:{secret}".encode()).decode()
    r = requests.post(
        TOKEN_URLS["xero"],
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers={
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=30,
    )
    if not r.ok:
        print(f"xero token refresh: {r.status_code} {r.text[:200]}", flush=True)
        return None
    return r.json().get("access_token")


def _xero_row_amount(cells):
    """First numeric column in a Xero report row (skip label column 0)."""
    if not cells or len(cells) < 2:
        return 0.0
    for cell in cells[1:]:
        val = cell.get("Value")
        if val is not None and str(val).strip() not in ("", "-"):
            return _parse_pl_amount(val)
    return _parse_pl_amount(cells[1].get("Value"))


def _xero_collect_summary_rows(rows, found=None, section=""):
    if found is None:
        found = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        section_title = (row.get("Title") or section or "").strip().lower()
        nested = row.get("Rows")
        if nested:
            _xero_collect_summary_rows(nested, found, section_title)
        rt = str(row.get("RowType", "")).lower()
        cells = row.get("Cells", [])
        if len(cells) < 2:
            continue
        label = str(cells[0].get("Value", "")).strip().lower()
        amt = _xero_row_amount(cells)
        if rt in ("summaryrow", "summary"):
            found[label] = amt
        elif rt == "row" and any(
            k in label for k in ("net profit", "net income", "net loss", "net operating")
        ):
            found[label] = amt
        elif rt == "row" and section_title and amt:
            # Detail line under a named section — keep for fallback totals.
            found[f"{section_title}::{label}"] = amt
    return found


def _parse_xero_pnl(report):
    summaries = _xero_collect_summary_rows(report.get("Rows", []))
    rev = cogs = opex = 0.0
    net = None
    for label, amt in summaries.items():
        if "::" in label:
            continue
        if any(
            k in label
            for k in (
                "total income",
                "total revenue",
                "total trading income",
                "total sales",
                "gross profit",
            )
        ):
            if "expense" not in label and "cost" not in label:
                rev = max(rev, amt)
        elif any(
            k in label
            for k in (
                "total cost of sales",
                "total cogs",
                "cost of goods",
                "cost of sales",
            )
        ):
            cogs += abs(amt)
        elif any(
            k in label
            for k in (
                "total operating expenses",
                "total operating costs",
                "total expenses",
                "total expense",
                "operating expenses",
            )
        ) and "other income" not in label:
            opex = max(opex, abs(amt))
        elif any(k in label for k in ("net profit", "net income", "net loss")):
            net = amt
    exp = cogs + opex
    if net is None and (rev or exp):
        net = rev - exp
    # Fallback: section-scoped detail rows (some orgs omit SummaryRow totals).
    if not rev and not exp and net is None:
        sec_inc = sec_exp = 0.0
        for label, amt in summaries.items():
            if "::" not in label:
                continue
            sec, _ = label.split("::", 1)
            if any(k in sec for k in ("income", "revenue", "sales")):
                sec_inc += amt
            elif any(k in sec for k in ("expense", "cost")):
                sec_exp += abs(amt)
        if sec_inc or sec_exp:
            rev, exp = sec_inc, sec_exp
            net = rev - exp
    if not rev and not exp and net is None and summaries:
        print(
            f"xero pnl unmatched summaries: {list(summaries.keys())[:25]}",
            flush=True,
        )
    return rev, exp, net, summaries


def _parse_qb_pnl(data):
    rev = cogs = opex = other_income = 0.0
    net = None

    def walk(rows):
        nonlocal rev, cogs, opex, other_income, net
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            grp = (row.get("group") or "").lower()
            summary = row.get("Summary", {}).get("ColData", [])
            if len(summary) >= 2:
                name = str(summary[0].get("value", "")).lower()
                amt = _parse_pl_amount(summary[1].get("value"))
                if "net income" in name or "net profit" in name:
                    net = amt
                elif grp == "income" or (
                    "total income" in name and "other" not in name
                ) or "total for income" in name:
                    rev = amt
                elif grp in ("otherincome", "other income") or (
                    "total for other income" in name
                    or ("other income" in name and "total" in name)
                ):
                    other_income = amt
                elif grp in ("cogs", "costofgoodssold") or "cost of goods" in name:
                    cogs = abs(amt)
                elif grp == "expenses" or (
                    "total expenses" in name and "other" not in name
                ) or "total for expenses" in name:
                    opex = abs(amt)
            nested = row.get("Rows", {}).get("Row", [])
            if nested:
                walk(nested if isinstance(nested, list) else [nested])

    top = data.get("Rows", {}).get("Row", [])
    walk(top if isinstance(top, list) else ([top] if top else []))
    rev += other_income
    exp = cogs + opex
    if net is None and (rev or exp):
        net = rev - exp
    return rev, exp, net


def _pnl_result(revenue, expenses, officer_salary=0, net_profit=None):
    rev = float(revenue or 0)
    exp = float(expenses or 0)
    net = float(net_profit) if net_profit is not None else rev - exp
    return {
        "revenue": rev,
        "expenses": exp,
        "net_profit": net,
        "officer_salary": float(officer_salary or 0),
    }


def _fb_pl_amount(pl, *keys):
    """Read FreshBooks P&L nested total.amount (e.g. total_income = Gross Profit)."""
    for key in keys:
        block = pl.get(key) or {}
        total = block.get("total") or {}
        amt = total.get("amount")
        if amt is not None and str(amt).strip() != "":
            try:
                return float(str(amt).replace(",", ""))
            except ValueError:
                continue
    return 0.0


def _freshbooks_token_exchange(o, secret, code):
    """FreshBooks token endpoint — try JSON, form, and Basic auth (API docs vary)."""
    token_url = TOKEN_URLS["freshbooks"]
    payload = {
        "grant_type": "authorization_code",
        "client_id": o["client_id"],
        "client_secret": secret,
        "code": code,
        "redirect_uri": o["redirect"],
    }
    creds = base64.b64encode(f"{o['client_id']}:{secret}".encode()).decode()
    attempts = [
        (
            "json",
            lambda: requests.post(
                token_url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=30,
            ),
        ),
        (
            "form",
            lambda: requests.post(
                token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            ),
        ),
        (
            "basic_form",
            lambda: requests.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": o["redirect"],
                },
                headers={
                    "Authorization": f"Basic {creds}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=30,
            ),
        ),
    ]
    last = None
    for name, req in attempts:
        r = req()
        last = r
        if r.ok:
            print(f"freshbooks token exchange ok via {name}", flush=True)
            return r.json()
        print(f"freshbooks token exchange {name}: {r.status_code} {r.text[:200]}", flush=True)
    if last is not None:
        print(f"oauth token exchange freshbooks: {last.status_code} {last.text[:300]}", flush=True)
    raise HTTPException(400, "OAuth token exchange failed")


def _exchange_oauth_code(provider, code):
    o = OAUTH[provider]
    secret = _oauth_secret(provider)
    if not secret:
        raise HTTPException(500, f"OAuth not configured for {provider}")
    if provider in ("quickbooks", "xero"):
        creds = base64.b64encode(f"{o['client_id']}:{secret}".encode()).decode()
        hdr = {"Authorization": f"Basic {creds}", "Content-Type": "application/x-www-form-urlencoded"}
        body = {"grant_type": "authorization_code", "code": code, "redirect_uri": o["redirect"]}
        r = requests.post(TOKEN_URLS[provider], data=body, headers=hdr, timeout=30)
    elif provider == "wave":
        # Match bak_working: form body, no explicit Content-Type header.
        r = requests.post(
            TOKEN_URLS[provider],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": o["client_id"],
                "client_secret": secret,
                "redirect_uri": o["redirect"],
            },
            timeout=30,
        )
    elif provider == "freshbooks":
        return _freshbooks_token_exchange(o, secret, code)
    else:
        r = requests.post(
            TOKEN_URLS[provider],
            json={
                "grant_type": "authorization_code",
                "client_id": o["client_id"],
                "client_secret": secret,
                "code": code,
                "redirect_uri": o["redirect"],
            },
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    if not r.ok:
        print(f"oauth token exchange {provider}: {r.status_code} {r.text[:300]}", flush=True)
        raise HTTPException(400, "OAuth token exchange failed")
    return r.json()


@app.get("/integrations/{p}/connect")
def connect(p: str, entity: str = "0"):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    o = OAUTH[p]
    state = quote(f"ts360|{entity}")
    return RedirectResponse(
        f"{o['auth_url']}?client_id={o['client_id']}&redirect_uri={quote(o['redirect'])}"
        f"&response_type=code&scope={quote(o['scope'])}&state={state}"
    )


@app.get("/integrations/{p}/callback")
def callback(p: str, code: str = "", state: str = "", realmId: str = "", tenantId: str = ""):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    if not code:
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=missing_code")
    parts = unquote(state or "").split("|")
    entity_idx = parts[-1] if len(parts) > 1 and parts[-1].isdigit() else "0"
    access_token = ""
    refresh_token = ""
    realm_id = realmId or ""
    tenant_id = tenantId or ""
    fb_account_id = ""
    try:
        tok = _exchange_oauth_code(p, code)
        access_token = tok.get("access_token", "")
        refresh_token = tok.get("refresh_token", "")
        if p == "xero" and not tenant_id:
            conn = requests.get(
                "https://api.xero.com/connections",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30,
            )
            if conn.ok:
                connections = conn.json()
                if connections:
                    tenant_id = connections[0].get("tenantId", "")
            else:
                print(
                    f"xero connections: {conn.status_code} {conn.text[:300]}",
                    flush=True,
                )
        elif p == "freshbooks" and access_token:
            me = requests.get(
                "https://api.freshbooks.com/auth/api/v1/users/me",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Api-Version": "alpha",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
            if me.ok:
                fb_account_id = (
                    me.json()
                    .get("response", {})
                    .get("business_memberships", [{}])[0]
                    .get("business", {})
                    .get("account_id", "")
                )
    except HTTPException:
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=token_exchange")
    except Exception as e:
        print(f"oauth callback {p} failed:", e)
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=token_exchange")
    if not access_token:
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=no_token")
    params = [f"{p}=connected", f"entity={entity_idx}", f"{p}_token={quote(access_token)}"]
    if p == "quickbooks":
        params.append(f"qb_token={quote(access_token)}")
        if realm_id:
            params.append(f"realm={quote(realm_id)}")
    elif p == "xero":
        if not tenant_id:
            return RedirectResponse(
                url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=missing_tenant"
            )
        params.append(f"tenant={quote(tenant_id)}")
        if refresh_token:
            params.append(f"xero_refresh={quote(refresh_token)}")
    elif p == "freshbooks" and fb_account_id:
        params.append(f"account={quote(str(fb_account_id))}")
        params.append(f"fb_token={quote(access_token)}")
    return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?" + "&".join(params))


@app.get("/integrations/{p}/data")
def integration_data(
    p: str,
    token: str = "",
    realm: str = "",
    tenant: str = "",
    account: str = "",
    year: str = "",
    refresh_token: str = "",
):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    if not token:
        return {"error": "missing token"}
    start, end = _pnl_date_range(year)
    try:
        if p == "quickbooks":
            if not realm:
                return {"error": "missing realm"}
            r = requests.get(
                f"https://quickbooks.api.intuit.com/v3/company/{realm}/reports/ProfitAndLoss",
                params={
                    "start_date": start,
                    "end_date": end,
                    "accounting_method": os.environ.get("QUICKBOOKS_ACCOUNTING_METHOD", "Cash"),
                },
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=30,
            )
            if not r.ok:
                print(f"quickbooks profitloss: {r.status_code} {r.text[:300]}", flush=True)
                return {"error": "quickbooks report failed"}
            rev, exp, net = _parse_qb_pnl(r.json())
            return _pnl_result(rev, exp, net_profit=net)
        if p == "xero":
            if not tenant:
                return {"error": "missing tenant"}
            access = token
            if refresh_token:
                refreshed = _xero_refresh_access_token(refresh_token)
                if refreshed:
                    access = refreshed
            r = requests.get(
                "https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss",
                params={"fromDate": start, "toDate": end, "standardLayout": "true"},
                headers={
                    "Authorization": f"Bearer {access}",
                    "Xero-tenant-id": tenant,
                    "Accept": "application/json",
                },
                timeout=30,
            )
            if not r.ok:
                print(f"xero profitloss: {r.status_code} {r.text[:300]}", flush=True)
                return {"error": "xero report failed", "status": r.status_code}
            reports = r.json().get("Reports") or []
            if not reports:
                return {"error": "xero report empty"}
            rev, exp, net, summaries = _parse_xero_pnl(reports[0])
            out = _pnl_result(rev, exp, net_profit=net)
            if (
                not rev
                and not exp
                and (net is None or net == 0)
                and summaries
            ):
                out["debug_labels"] = [
                    k for k in summaries.keys() if "::" not in k
                ][:20]
            return out
        if p == "wave":
            q1 = {"query": "{businesses(page:1,pageSize:1){edges{node{id}}}}"}
            br = requests.post(
                "https://gql.waveapps.com/graphql/public",
                json=q1,
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            ).json()
            bid = (
                (br.get("data", {}).get("businesses", {}).get("edges", [{}]) or [{}])[0]
                .get("node", {})
                .get("id", "")
            )
            if not bid:
                return _pnl_result(0, 0)
            q2 = {
                "query": (
                    "{business(id:\"" + bid + "\"){accounts{edges{node{subtype{name}balance}}}}}"
                )
            }
            ar = requests.post(
                "https://gql.waveapps.com/graphql/public",
                json=q2,
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            ).json()
            rev = exp = 0.0
            for e in ar.get("data", {}).get("business", {}).get("accounts", {}).get("edges", []) or []:
                n = e.get("node", {})
                st = n.get("subtype", {}).get("name", "").lower()
                try:
                    bal = float(n.get("balance", 0) or 0)
                except (TypeError, ValueError):
                    bal = 0.0
                if "income" in st or "revenue" in st or "sales" in st:
                    rev += bal
                elif "expense" in st or "cost" in st or "payroll" in st:
                    exp += bal
            return _pnl_result(rev, exp)
        if p == "freshbooks":
            h = {
                "Authorization": f"Bearer {token}",
                "Api-Version": "alpha",
                "Content-Type": "application/json",
            }
            me = requests.get("https://api.freshbooks.com/auth/api/v1/users/me", headers=h, timeout=30).json()
            aid = (
                me.get("response", {})
                .get("business_memberships", [{}])[0]
                .get("business", {})
                .get("account_id", account)
            )
            if not aid:
                return {"error": "missing freshbooks account"}
            r = requests.get(
                f"https://api.freshbooks.com/accounting/account/{aid}/reports/accounting/profitloss"
                f"?start_date={start}&end_date={end}",
                headers=h,
                timeout=30,
            )
            if not r.ok:
                print(f"freshbooks profitloss: {r.status_code} {r.text[:300]}", flush=True)
                return {"error": "freshbooks report failed"}
            pl = r.json().get("response", {}).get("result", {}).get("profitloss", {})
            # FreshBooks labels total_income as "Gross Profit" in the P&L report.
            gross = _fb_pl_amount(pl, "total_income", "gross_profit")
            exp = _fb_pl_amount(pl, "total_expenses", "total_expense")
            net = _fb_pl_amount(pl, "net_profit")
            return _pnl_result(gross, exp, net_profit=net)
    except Exception as e:
        raise HTTPException(500, f"Provider error: {str(e)}")
    raise HTTPException(404)


@app.post("/aria")
async def aria_chat(request: Request):
    email = _require_session_user(request)
    user = ddb_get_user(email) or {}
    plan = user.get("plan", "starter")
    if PLAN_ORDER.index(plan) < PLAN_ORDER.index("professional"):
        raise HTTPException(403, "Professional plan required")
    if not OPENAI_API_KEY:
        raise HTTPException(503, "Aria service unavailable")
    body = await request.json()
    messages = body.get("messages") if isinstance(body, dict) else []
    if not isinstance(messages, list):
        raise HTTPException(400, "messages must be a list")
    payload_messages = [{"role": "system", "content": ARIA_SYSTEM}]
    for m in messages[-20:]:
        if not isinstance(m, dict):
            continue
        role = m.get("role", "user")
        if role not in ("user", "assistant"):
            role = "user"
        content = str(m.get("content", "")).strip()
        if content:
            payload_messages.append({"role": role, "content": content})
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={"model": ARIA_MODEL, "messages": payload_messages, "max_tokens": 900},
            timeout=60,
        )
    except requests.RequestException as e:
        print("aria request failed:", e)
        raise HTTPException(503, "Aria service unavailable")
    if not r.ok:
        print(f"aria openai: {r.status_code} {r.text[:300]}")
        raise HTTPException(503, "Aria service unavailable")
    reply = r.json()["choices"][0]["message"]["content"]
    return {"reply": reply}


WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


@app.get("/auth/verify-email")
def verify_email(token: str = "", email: str = ""):
    email = _norm_email(email)
    x = ddb_get_user(email)
    if (
        not x
        or not x.get("verify_tok")
        or not secrets.compare_digest(x.get("verify_tok", ""), token)
        or x.get("verify_exp", 0) < int(time.time())
    ):
        raise HTTPException(400, "Invalid or expired verification link")
    x["verified"] = True
    x.pop("verify_tok", None)
    x.pop("verify_exp", None)
    ddb_put_user(email, x)
    return RedirectResponse(url="https://www.taxstat360.com/onboarding/entity?verified=true")


@app.post("/auth/forgot-password")
@limiter.limit("3/minute")
def forgot_password(r: ForgotReq, request: Request):
    email = _norm_email(r.email)
    x = ddb_get_user(email)
    if x:
        reset_tok = secrets.token_hex(32)
        x["reset_tok"] = reset_tok
        x["reset_exp"] = int(time.time()) + RESET_TTL
        ddb_put_user(email, x)
        try:
            reset_url = f"{FRONTEND_URL}/reset-password?token={reset_tok}&email={quote(email)}"
            ses = boto3.client("ses", region_name="us-east-1")
            ses.send_email(
                Source=RESET_FROM,
                Destination={"ToAddresses": [email]},
                Message={
                    "Subject": {"Data": "Reset your TaxStat360 password"},
                    "Body": {
                        "Html": {
                            "Data": (
                                '<div style="font-family:-apple-system,sans-serif;max-width:520px;'
                                'margin:0 auto;padding:40px 24px">'
                                '<h2 style="color:#0D1B3E">Reset your password</h2>'
                                '<p>We received a request to reset your TaxStat360 password. '
                                "This link expires in 1 hour.</p>"
                                f'<p><a href="{reset_url}" style="background:#2563EB;color:#fff;'
                                'padding:12px 20px;border-radius:8px;text-decoration:none;'
                                'display:inline-block">Reset Password</a></p>'
                                '<p style="color:#475569;font-size:13px">If you did not request this, '
                                "you can safely ignore this email.</p>"
                                "</div>"
                            )
                        }
                    },
                },
            )
        except Exception as e:
            print("password reset email failed:", e)
    return {"ok": True}


@app.post("/auth/reset-password")
@limiter.limit("5/minute")
def reset_password(r: ResetReq, request: Request):
    email = _norm_email(r.email)
    x = ddb_get_user(email)
    if (
        not x
        or not x.get("reset_tok")
        or not secrets.compare_digest(x.get("reset_tok", ""), r.token)
        or x.get("reset_exp", 0) < int(time.time())
    ):
        raise HTTPException(400, "Invalid or expired reset link")
    if not (12 <= len(r.new_password) <= 128):
        raise HTTPException(400, "Password must be between 12 and 128 characters")
    x["pw"] = _hash_password(r.new_password)
    x.pop("reset_tok", None)
    x.pop("reset_exp", None)
    x["tok"] = secrets.token_hex(32)
    ddb_put_user(email, x)
    return {"ok": True}


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    import json as _json

    try:
        if WEBHOOK_SECRET:
            stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
            event = _json.loads(payload)
        else:
            event = _json.loads(payload)
    except Exception as e:
        raise HTTPException(400, str(e))
    etype = event.get("type", "")
    data = event.get("data", {}).get("object", {})
    cid = data.get("customer", "")
    if etype == "customer.subscription.updated":
        status = data.get("status", "")
        items = data.get("items", {}).get("data", [])
        price_id = items[0].get("price", {}).get("id", "") if items else ""
        new_plan = next((k for k, v in PRICE_IDS.items() if price_id in v.values()), None)
        if status in ("active", "trialing") and new_plan:
            _ddb_update_user_plan(cid, new_plan)
        elif status in ("canceled", "unpaid", "past_due"):
            _ddb_update_user_plan(cid, "starter")
    elif etype == "customer.subscription.deleted":
        _ddb_update_user_plan(cid, "starter")
    elif etype == "invoice.payment_failed":
        for em, ud in ddb_all_users().items():
            if ud.get("stripe_customer_id") == cid:
                print(f"Payment failed for {em}")
                break
    return {"status": "ok"}
