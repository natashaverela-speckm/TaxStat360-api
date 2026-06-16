import json, os, hashlib, secrets, stripe, requests, boto3, time, hmac, bcrypt, base64, io
from decimal import Decimal
from urllib.parse import quote

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
    }


# --- M2 RECORDS (DynamoDB sync) ---
RECORDS_TABLE = os.environ.get("RECORDS_TABLE", "taxstat360-records")
_records_tbl = _ddb.Table(RECORDS_TABLE)


def _require_session_user(request):
    email = _session_email(request)
    if not email:
        raise HTTPException(401, "Not authenticated")
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
    }
    ddb_put_user(email, rec)
    mc_subscribe(email, r.name)
    try:
        ses = boto3.client("ses", region_name="us-east-1")
        verify_url = f"https://app.taxstat360.com/auth/verify-email?token={verify_tok}&email={email}"
        ses.send_email(
            Source="admin@taxstat360.com",
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": "Verify your TaxStat360 email"},
                "Body": {
                    "Html": {
                        "Data": f"""
                    <p>Hi {r.name},</p>
                    <p>Thanks for signing up for TaxStat360. Click below to verify your email address:</p>
                    <p><a href="{verify_url}">Verify my email</a></p>
                    <p>— TaxStat360</p>
                """
                    }
                },
            },
        )
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
    secret = _mfa_decrypt(x["mfa_secret_enc"])
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
    secret = _mfa_decrypt(x["mfa_secret_enc"])
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


@app.post("/auth/logout")
def auth_logout():
    resp = JSONResponse({"ok": True})
    _clear_session_cookie(resp)
    return resp


@app.get("/user/me")
def me(user=Depends(get_user_from_token)):
    return {"email": user["email"], "plan": user.get("plan", "starter"), "name": user.get("name", "")}


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


@app.post("/stripe/setup-intent")
def setup():
    try:
        i = stripe.SetupIntent.create(usage="off_session")
        return {"client_secret": i.client_secret}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/stripe/subscribe")
def subscribe(r: Sub, user=Depends(get_user_from_token)):
    try:
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
    "quickbooks": {
        "client_id": "ABw0WBOceb971XVhquWW9DWJfOHZkF5KjOr8SthaNACDKOILpZ",
        "redirect": "https://app.taxstat360.com/integrations/quickbooks/callback",
        "auth_url": "https://appcenter.intuit.com/connect/oauth2",
        "scope": "com.intuit.quickbooks.accounting",
    },
    "freshbooks": {
        "client_id": "86619f0b77a5405cc791956760108aa8da609558bc4945e596c82adcdcd270c2",
        "redirect": "https://app.taxstat360.com/integrations/freshbooks/callback",
        "auth_url": "https://auth.freshbooks.com/oauth/authorize",
        "scope": "user:profile:read",
    },
    "xero": {
        "client_id": "0921E54B89164E24BA072A0E79741FA5",
        "redirect": "https://app.taxstat360.com/integrations/xero/callback",
        "auth_url": "https://login.xero.com/identity/connect/authorize",
        "scope": "openid profile email",
    },
    "wave": {
        "client_id": "IS3R7n6dQG7IKscrPQSn4afGSJskrnToqpYik7Fp",
        "redirect": "https://app.taxstat360.com/integrations/wave/callback",
        "auth_url": "https://api.waveapps.com/oauth2/authorize",
        "scope": "account:* business:read",
    },
}


@app.get("/integrations/{p}/connect")
def connect(p: str):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    o = OAUTH[p]
    return RedirectResponse(
        f"{o['auth_url']}?client_id={o['client_id']}&redirect_uri={o['redirect']}&response_type=code&scope={o['scope']}&state=ts360"
    )


@app.get("/integrations/{p}/callback")
def callback(p: str, code: str = "", state: str = ""):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    return RedirectResponse(url=f"https://www.taxstat360.com/dashboard?{p}=connected")


WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


@app.get("/auth/verify-email")
def verify_email(token: str = "", email: str = ""):
    email = _norm_email(email)
    x = ddb_get_user(email)
    if not x or x.get("verify_tok") != token:
        raise HTTPException(400, "Invalid or expired verification link")
    x["verified"] = True
    x.pop("verify_tok", None)
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
