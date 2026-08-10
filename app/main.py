import json, logging, os, hashlib, secrets, stripe, requests, boto3, time, hmac, bcrypt, base64, io
# AUDIT F-8c: datetime/timezone/timedelta are needed by _send_trial_confirmation_email()
# to compute the trial-end date. Only `date` was imported; using the others without this
# line raises NameError on every signup.
from datetime import date, datetime, timezone, timedelta
from decimal import Decimal
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import quote, unquote

logger = logging.getLogger("taxstat360")


def _configure_logging():
    """File + stderr logging (restores pre-condense ops visibility)."""
    if logger.handlers:
        return
    log_dir = os.environ.get("LOG_DIR", "/home/ubuntu/risk-planner-BE/logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
        fh = TimedRotatingFileHandler(
            os.path.join(log_dir, "risk_planner.log"),
            when="midnight",
            backupCount=14,
            encoding="utf-8",
        )
        fh.suffix = "%Y%m%d"
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(fh)
    except OSError as e:
        # Local/tests may not have the prod log path — stderr still works.
        logging.basicConfig(level=logging.INFO)
        logger.warning("file logging disabled: %s", e)
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(sh)
    logger.setLevel(logging.INFO)


_configure_logging()

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
# Client-level HTTP timeout (stripe>=11: per-call timeout= is not an HTTP timeout).
try:
    from stripe._http_client import RequestsClient as _StripeRequestsClient
except ImportError:  # older public layout
    from stripe.http_client import RequestsClient as _StripeRequestsClient  # type: ignore

stripe.default_http_client = _StripeRequestsClient(timeout=10)
stripe.max_network_retries = 1

MC_KEY = os.environ.get("MC_KEY", "")
MC_LIST = "f546bd92ac"

# Security (audit P0-#1): Swagger UI and the OpenAPI schema publish the entire API
# surface — including the /admin routes — to anyone who loads them in a browser. They
# are now off unless APP_ENV explicitly opts in. Default is production, i.e. disabled,
# so a missing/typo'd env var fails closed rather than open.
APP_ENV = os.environ.get("APP_ENV", "production").strip().lower()
_DOCS_ENABLED = APP_ENV in ("dev", "development", "local", "test")

app = FastAPI(
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)
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
USERS_STRIPE_CUSTOMER_GSI = os.environ.get(
    "USERS_STRIPE_CUSTOMER_GSI", "stripe_customer_id-index"
)
SESSION_COOKIE = "ts360_session"
SESSION_MAX_AGE = 7 * 24 * 3600


def _resolve_secret_key():
    """Resolve SECRET_KEY, failing closed unconditionally.

    SECURITY FIX (independent review, Aug 2026): SECRET_KEY signs every session
    cookie (_make_session/_verify_session below) and derives the Fernet key that
    encrypts MFA/TOTP secrets (_mfa_fernet). It previously fell back to the
    hardcoded literal "change-me-in-env" — a value visible to anyone who reads
    this public-facing source file. If the real env var were ever missing
    (deploy misconfiguration, a wiped .env, a typo'd key name), the app would
    start normally but sign every session with that known literal: anyone could
    forge a valid ts360_session cookie for any email address, and anyone who
    had already enabled MFA would have a decryptable-by-anyone TOTP secret.
    Mirrors the STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET checks elsewhere in
    this file: fail closed, always, no environment-based carve-out. Local/dev/
    test setups already supply their own value (see tests/conftest.py and
    scripts/qb_pl_migration_diff.py), same as those two keys require today.
    """
    key = os.environ.get("SECRET_KEY", "")
    if not key:
        raise RuntimeError("SECRET_KEY environment variable not set")
    return key


SECRET_KEY = _resolve_secret_key()
# Share session cookie across www/app subdomains; empty in tests/local.
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", ".taxstat360.com")

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
    if not str(item.get("stripe_customer_id") or "").strip():
        item.pop("stripe_customer_id", None)
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


def _ddb_user_from_item(item):
    item = _from_ddb(item)
    em = item.get("email")
    if not em:
        return None, None
    pw = _resolve_stored_password(item)
    if pw:
        item["pw"] = pw
    return em, item


def ddb_find_user_by_stripe_customer_id(stripe_customer_id):
    """O(1) lookup via GSI; scan fallback only when the index is not deployed yet."""
    from botocore.exceptions import ClientError

    cid = (stripe_customer_id or "").strip()
    if not cid:
        return None, None
    if USERS_STRIPE_CUSTOMER_GSI:
        try:
            resp = _users_tbl.query(
                IndexName=USERS_STRIPE_CUSTOMER_GSI,
                KeyConditionExpression=Key("stripe_customer_id").eq(cid),
                Limit=1,
            )
            items = resp.get("Items") or []
            if items:
                return _ddb_user_from_item(items[0])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in ("ValidationException", "ResourceNotFoundException"):
                logger.warning("stripe customer GSI query failed: %s", e)
                raise
            logger.warning(
                "stripe customer GSI %s unavailable (%s); using filtered scan",
                USERS_STRIPE_CUSTOMER_GSI,
                code,
            )
    from boto3.dynamodb.conditions import Attr

    resp = _users_tbl.scan(
        FilterExpression=Attr("stripe_customer_id").eq(cid),
        Limit=1,
    )
    items = resp.get("Items") or []
    if items:
        return _ddb_user_from_item(items[0])
    return None, None


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
    email, ud = ddb_find_user_by_stripe_customer_id(stripe_customer_id)
    if not email or not ud:
        logger.warning(
            "stripe plan update: no user for customer %s (plan=%s)",
            stripe_customer_id,
            plan,
        )
        return None
    ud["plan"] = plan
    ddb_put_user(email, ud)
    return email


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
    email = _verify_session(request.cookies.get(SESSION_COOKIE, ""))
    if email:
        return email
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return _verify_session(auth[7:].strip())
    return None


def _set_session_cookie(response, email, session_value=None):
    val = session_value or _make_session(email)
    kwargs = {
        "key": SESSION_COOKIE,
        "value": val,
        "max_age": SESSION_MAX_AGE,
        "httponly": True,
        "secure": True,
        "samesite": "none",
        "path": "/",
    }
    if SESSION_COOKIE_DOMAIN:
        kwargs["domain"] = SESSION_COOKIE_DOMAIN
    response.set_cookie(**kwargs)


def _clear_session_cookie(response):
    kwargs = {"key": SESSION_COOKIE, "path": "/"}
    if SESSION_COOKIE_DOMAIN:
        kwargs["domain"] = SESSION_COOKIE_DOMAIN
    response.delete_cookie(**kwargs)


def _user_public(rec, email):
    return {
        "email": email,
        "plan": rec.get("plan", "starter"),
        "name": rec.get("name", ""),
        "verified": rec.get("verified", False),
        "is_admin": _is_admin(email),
    }


# --- OBS-5 ALERT RELAY (Phase 2.2c, revised 2.2c-r1, Jul 2026) -----------------
# HISTORY: the first 2.2c relay forwarded to web3forms with a server-held key,
# per the Batch-6 spec. Live testing revealed web3forms REJECTS server-side
# submissions on the free plan ("Use our API in client side ... Pro plan is
# required") — and the relay's original error handling passed that rejection
# through as HTTP 200 {"success": false}, a silent failure. Both problems die
# here: the relay now sends the email ITSELF via SES (the same transport the
# password-reset and verification emails already use, from the same verified
# sender), so there is no third party, no key anywhere, and no plan
# restriction; and any send failure is a loud 502, never a quiet false.
# Field whitelist, caps, subject requirement, and the 5/min/IP limit are
# unchanged from the spec. The D-03 signup-failure alerts and the Landing
# contact form route through here; Reply-To carries the submitter's address
# so the owner can reply directly from the inbox.
# Destination override via env; default matches ADMIN_EMAILS' default (which is
# defined later in this module — do not reference it here at import time).
ALERT_TO_EMAIL = os.environ.get("ALERT_TO_EMAIL", "support@taxstat360.com")
_FORM_RELAY_FIELDS = ("subject", "email", "message", "from_name", "plan", "billing", "status", "detail")
_FORM_RELAY_MAX_LEN = 4000


@app.post("/alerts/form-relay")
@limiter.limit("5/minute")
async def form_relay(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required")
    if not isinstance(body, dict):
        raise HTTPException(400, "JSON object required")
    fields = {}
    for k in _FORM_RELAY_FIELDS:
        v = body.get(k)
        if v is None:
            continue
        fields[k] = str(v)[:_FORM_RELAY_MAX_LEN]
    if not fields.get("subject"):
        raise HTTPException(400, "subject is required")
    lines = [f"{k}: {fields[k]}" for k in _FORM_RELAY_FIELDS if k in fields and k != "subject"]
    text_body = "\n\n".join(lines) if lines else "(no fields provided)"
    reply_to = fields.get("email", "").strip()
    try:
        ses = _mailer()   # AUDIT F-8d: SendGrid, not SES (SES sandbox drops all customer mail)
        kwargs = {
            "Source": RESET_FROM,
            "Destination": {"ToAddresses": [ALERT_TO_EMAIL]},
            "Message": {
                "Subject": {"Data": fields["subject"][:998]},
                "Body": {"Text": {"Data": text_body}},
            },
        }
        if reply_to and "@" in reply_to:
            kwargs["ReplyToAddresses"] = [reply_to]
        ses.send_email(**kwargs)
        return {"success": True}
    except Exception as e:
        # LOUD failure — an owner alert that cannot send must never pretend it did.
        logger.error("form-relay SES send failed: %s", e)
        raise HTTPException(502, "Alert delivery unavailable")


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
    except Exception as e:
        logger.info("audit table load skipped (will try create): %s", e)
    try:
        _ddb.create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[{"AttributeName": "auditId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "auditId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        _audit_tbl.wait_until_exists()
    except Exception as e:
        logger.warning("AUDIT table auto-create skipped: %s", e)


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
        logger.exception("AUDIT write failed (%s) target=%s", status, target_email)
        return {"ok": False, "error": "Audit log write failed"}


def _stripe_get(obj, key, default=None):
    """Read a field from a Stripe SDK object or plain dict (StripeObject has no .get)."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    try:
        val = obj[key]
    except (KeyError, TypeError):
        return default
    return default if val is None else val


def _stripe_is_missing(e):
    """True when a Stripe error means the resource is already gone (idempotent)."""
    code = getattr(e, "code", "") or ""
    msg = str(getattr(e, "user_message", "") or e)
    err = getattr(e, "error", None)
    if isinstance(err, dict):
        code = code or str(err.get("code", "") or "")
        msg = f"{msg} {err.get('message', '')}".strip()
    json_body = getattr(e, "json_body", None) or {}
    if isinstance(json_body, dict):
        err_obj = json_body.get("error") or {}
        if isinstance(err_obj, dict):
            code = code or str(err_obj.get("code", "") or "")
            msg = f"{msg} {err_obj.get('message', '')}".strip()
    if code == "resource_missing":
        return True
    if getattr(e, "http_status", None) == 404:
        return True
    lowered = msg.lower()
    if "no such customer" in lowered or "no such" in lowered:
        return True
    return "has been deleted" in lowered and "customer" in lowered


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
            status = _stripe_get(s, "status")
            if status in ("canceled", "incomplete_expired"):
                continue
            try:
                stripe.Subscription.cancel(_stripe_get(s, "id"))
                result["subscriptions_canceled"] += 1
            except Exception as e:
                if not _stripe_is_missing(e):
                    raise
    except Exception as e:
        if _stripe_is_missing(e):
            logger.info(
                "stripe teardown: customer already absent on subscription.list customer=%s (%s)",
                stripe_customer_id,
                e,
            )
            result["already_absent"] = True
            return result
        logger.warning(
            "stripe teardown: subscription.list failed customer=%s (%s)",
            stripe_customer_id,
            e,
        )
        raise
    try:
        stripe.Customer.delete(stripe_customer_id)
        result["customer_deleted"] = True
    except Exception as e:
        if _stripe_is_missing(e):
            logger.info(
                "stripe teardown: customer already absent on customer.delete customer=%s (%s)",
                stripe_customer_id,
                e,
            )
            result["already_absent"] = True
        else:
            logger.warning(
                "stripe teardown: customer.delete failed customer=%s (%s)",
                stripe_customer_id,
                e,
            )
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
    user_rec = user if isinstance(user, dict) else {}
    logger.info("account.delete started actor=%s target=%s", actor_email, target_email)
    _write_audit("account.delete", actor_email, target_email, "started")
    try:
        stripe_cid = user_rec.get("stripe_customer_id", "") or ""
        # 1 + 2. Stripe first: a hard failure here aborts before any DB delete.
        stripe_result = _stripe_teardown(stripe_cid)
        logger.info(
            "account.delete stripe teardown target=%s result=%s",
            target_email,
            stripe_result,
        )
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
        logger.exception(
            "account.delete failed actor=%s target=%s type=%s",
            actor_email,
            target_email,
            type(e).__name__,
        )
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
            logger.warning("MFA decrypt failed: %s", e)
    plain = x.get("mfa_secret")
    if plain:
        secret = str(plain)
        try:
            x["mfa_secret_enc"] = _mfa_encrypt(secret)
            x.pop("mfa_secret", None)
            if email:
                ddb_put_user(email, x)
        except Exception as e:
            logger.warning("MFA legacy migrate failed: %s", e)
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
    session_token = _make_session(email)
    resp = JSONResponse({
        "ok": True,
        "plan": plan,
        "email": email,
        "access_token": session_token,
    })
    _set_session_cookie(resp, email, session_token)
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
    except Exception as e:
        logger.warning("mailchimp subscribe failed for %s: %s", email, e)


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
    # AUDIT F-8c (Jul 2026): the auto-renewal acknowledgment must state the AMOUNT and
    # CADENCE the customer actually agreed to. The signup page already knows whether they
    # chose monthly or annual; it simply never sent it. Defaults to "monthly" so an older
    # client that omits the field still produces a correct (conservative) email.
    billing: str = "monthly"
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

# --- Integration credentials (audit P0-#1) ------------------------------------
# A QuickBooks/Xero access token — and especially a Xero *refresh* token — is a
# long-lived credential to a customer's accounting system. These are now held
# server-side on the user record and are never sent to, stored by, or accepted
# from the browser. They must not appear in a URL, a redirect, or localStorage.
OAUTH_STATE_MAX_AGE = 600  # 10 minutes: an OAuth round-trip is seconds, not hours


def _integration_creds_get(email, p):
    rec = ddb_get_user(email) or {}
    return dict((rec.get("integrations") or {}).get(p) or {})


def _integration_creds_save(email, p, **fields):
    rec = ddb_get_user(email)
    if not rec:
        return
    integrations = dict(rec.get("integrations") or {})
    creds = dict(integrations.get(p) or {})
    creds.update({k: v for k, v in fields.items() if v is not None})
    creds["updated_at"] = int(time.time())
    integrations[p] = creds
    rec["integrations"] = integrations
    ddb_put_user(email, rec)


def _integration_creds_clear(email, p):
    rec = ddb_get_user(email)
    if not rec:
        return
    integrations = dict(rec.get("integrations") or {})
    integrations.pop(p, None)
    rec["integrations"] = integrations
    ddb_put_user(email, rec)


def _make_oauth_state(email, entity):
    """Signed, short-lived state binding one OAuth round-trip to one user.

    The provider echoes this back to /callback. It is what lets the callback know
    which account to attach the tokens to without trusting anything the browser
    supplies, and the HMAC + timestamp make the flow CSRF-resistant.
    """
    payload = f"{_norm_email(email)}|{entity}|{int(time.time())}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def _verify_oauth_state(state):
    """-> (email, entity_idx), or (None, "0") if the state is absent/forged/stale."""
    if not state:
        return None, "0"
    try:
        raw = base64.urlsafe_b64decode(state.encode()).decode()
        payload, sig = raw.rsplit("|", 1)
        expected = hmac.new(
            SECRET_KEY.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None, "0"
        email, entity, ts = payload.split("|", 2)
        if int(time.time()) - int(ts) > OAUTH_STATE_MAX_AGE:
            return None, "0"
        return _norm_email(email), (entity if entity.isdigit() else "0")
    except Exception:
        return None, "0"

FRONTEND_URL = "https://www.taxstat360.com"
RESET_FROM = "noreply@taxstat360.com"

# ---------------------------------------------------------------------------------
# AUDIT F-8d (Jul 2026) - EMAIL DELIVERY MOVED FROM AWS SES TO SENDGRID.
#
# WHY. Our AWS SES account is in the SANDBOX, which silently discards every message to
# an address that has not been individually verified in the AWS console. Only four
# addresses were verified, so in practice NO customer could ever receive ANY email:
# not the verification link (so they could never activate), not the billing
# acknowledgment, not a password reset (so they could never get back in). Nothing
# bounced and nothing errored - AWS simply dropped them. We requested production
# access and AWS Trust and Safety declined without stating a reason.
#
# SendGrid is already paid for (Essentials, 50k/month) and taxstat360.com is already
# domain-authenticated there, so it can send to anyone today.
#
# HOW. _SendGridMailer is a drop-in stand-in for the boto3 SES client, accepting the
# exact same send_email(**kwargs) shape this file already uses. That is deliberate:
# every existing call site stays byte-for-byte unchanged, so this swap cannot alter
# any email's content - only the pipe it travels down.
#
# REQUIRES: SENDGRID_API_KEY in /etc/environment on the API host (systemd reads it via
# EnvironmentFile). Without it, sends raise and are caught by the callers' try/except.
# ---------------------------------------------------------------------------------

SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"


class _SendGridMailer:
    """Accepts boto3-SES-style send_email(**kwargs); delivers via SendGrid."""

    def send_email(self, **kw):
        api_key = os.environ.get("SENDGRID_API_KEY")
        if not api_key:
            raise RuntimeError("SENDGRID_API_KEY is not set on this host")

        source = kw.get("Source") or RESET_FROM
        to_addrs = (kw.get("Destination") or {}).get("ToAddresses") or []
        if not to_addrs:
            raise RuntimeError("no recipient")

        message = kw.get("Message") or {}
        subject = (message.get("Subject") or {}).get("Data") or ""
        body = message.get("Body") or {}

        # SendGrid requires text/plain BEFORE text/html when both are present.
        content = []
        if "Text" in body:
            content.append({"type": "text/plain", "value": (body["Text"] or {}).get("Data", "")})
        if "Html" in body:
            content.append({"type": "text/html", "value": (body["Html"] or {}).get("Data", "")})
        if not content:
            content = [{"type": "text/plain", "value": ""}]

        payload = {
            "personalizations": [{"to": [{"email": a} for a in to_addrs]}],
            "from": {"email": source, "name": "TaxStat360"},
            "subject": subject,
            "content": content,
        }
        reply_to = kw.get("ReplyToAddresses") or []
        if reply_to:
            payload["reply_to"] = {"email": reply_to[0]}

        r = requests.post(
            SENDGRID_URL,
            json=payload,
            headers={"Authorization": "Bearer " + api_key},
            timeout=15,
        )
        if r.status_code >= 300:
            raise RuntimeError("SendGrid " + str(r.status_code) + ": " + r.text[:300])
        return {"MessageId": r.headers.get("X-Message-Id", "")}


def _mailer():
    """Single place email delivery is chosen. Swap providers here, nowhere else."""
    return _SendGridMailer()
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
    ses = _mailer()   # AUDIT F-8d: SendGrid, not SES (SES sandbox drops all customer mail)
    ses.send_email(
        Source=RESET_FROM,
        Destination={"ToAddresses": [email]},
        Message={"Subject": {"Data": "Confirm your email for TaxStat360"}, "Body": {"Html": {"Data": html}}},
    )


# ---------------------------------------------------------------------------------
# AUDIT F-8c (Jul 2026) - AUTO-RENEWAL ACKNOWLEDGMENT.
#
# The only email sent at signup was "Confirm your email" - a bare token link with no
# billing information in it at all. That is an identity check, not a renewal
# acknowledgment. They are different documents with different jobs.
#
# California's Automatic Renewal Law and the FTC negative-option rule expect the renewal
# terms in a record the customer can RETAIN, stating: (1) that it renews automatically,
# (2) the amount, (3) the frequency, (4) the date of the first charge, and (5) how to
# cancel. The verification email carried none of the five.
#
# WORDING IS DELIBERATELY IDENTICAL to the signup page (frontend constants.js ->
# renewalDisclosure()) and to Terms of Service section 3. Three copies of a promise that
# can drift is exactly how "Cancel in one click" ended up live on a site where
# cancelling took two clicks. If you change one, change all three.
# ---------------------------------------------------------------------------------

TRIAL_DAYS = 7

# Must stay in lockstep with frontend src/constants.js (PLAN_PRICING).
# annual_total = monthly * 10  ("two months free").
PLAN_PRICES = {
    "starter":      {"monthly": 79,  "annual_total": 790,  "label": "Starter"},
    "professional": {"monthly": 149, "annual_total": 1490, "label": "Professional"},
    "enterprise":   {"monthly": 299, "annual_total": 2990, "label": "Enterprise"},
}


def _send_trial_confirmation_email(email, name, plan, billing):
    p = PLAN_PRICES.get(plan, PLAN_PRICES["starter"])
    is_annual = (billing or "monthly").lower() == "annual"
    amount = "$" + format(p["annual_total"] if is_annual else p["monthly"], ",")
    cadence = "every 12 months" if is_annual else "every month"
    end_date = (datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)).strftime("%B %d, %Y").replace(" 0", " ")
    greeting = "Hi " + name + "," if name else "Hi,"

    html = (
        '<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;padding:32px 24px">'
        '<div style="font-weight:800;font-size:20px;color:#0D1B3E;margin-bottom:20px">'
        'TaxStat<span style="color:#2563EB">360</span></div>'
        f'<p style="font-size:15px;color:#0D1B3E">{greeting}</p>'
        f'<p style="font-size:15px;line-height:1.6;color:#334155">Your {TRIAL_DAYS}-day free trial of '
        f'<strong>TaxStat360 {p["label"]}</strong> is active. Here are your billing terms, in '
        'writing, so you have them.</p>'
        '<div style="background:#FFFBEB;border:1px solid #FCD34D;border-radius:10px;padding:16px;margin:18px 0">'
        '<p style="margin:0 0 10px;font-weight:700;font-size:15px;color:#92400E">'
        'Your subscription renews automatically.</p>'
        f'<p style="margin:0;font-size:14px;line-height:1.7;color:#92400E">'
        f'Trial ends: <strong>{end_date}</strong><br>'
        f'You will be charged: <strong>{amount} on {end_date}</strong><br>'
        f'Then: <strong>{amount} {cadence}</strong>, automatically, until you cancel.</p>'
        '<p style="margin:10px 0 0;font-size:13px;color:#92400E">You have not been charged anything yet.</p>'
        '</div>'
        '<p style="font-weight:700;font-size:15px;color:#0D1B3E;margin-bottom:6px">How to cancel</p>'
        f'<p style="font-size:14px;line-height:1.6;color:#334155">Sign in and go to '
        '<strong>Settings &rarr; Manage Billing</strong>. If you cancel before '
        f'<strong>{end_date}</strong>, <strong>you will not be charged at all</strong>. If you '
        'cancel after a billing period has begun, your access continues to the end of that '
        'period and you are not charged again.</p>'
        '<p style="margin:20px 0"><a href="https://www.taxstat360.com/settings" '
        'style="background:#0D1B3E;color:#fff;padding:12px 22px;border-radius:8px;'
        'text-decoration:none;display:inline-block;font-weight:700;font-size:14px">'
        'Manage or cancel your subscription</a></p>'
        '<p style="font-size:12px;color:#64748B;line-height:1.6">No refunds are given for billing '
        'periods already charged, including annual plans. Cancelling stops future renewals; it '
        'does not refund the current period.</p>'
        '<p style="font-size:12px;color:#64748B;line-height:1.6">Questions: '
        '<a href="mailto:support@taxstat360.com" style="color:#2563EB">support@taxstat360.com</a><br>'
        'Full terms: <a href="https://www.taxstat360.com/terms" style="color:#2563EB">'
        'taxstat360.com/terms</a></p>'
        '</div>'
    )
    ses = _mailer()   # AUDIT F-8d: SendGrid, not SES (SES sandbox drops all customer mail)
    ses.send_email(
        Source=RESET_FROM,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your TaxStat360 trial has started - what happens on " + end_date},
            "Body": {"Html": {"Data": html}},
        },
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
        logger.warning("SES verify error: %s", e)
    # AUDIT F-8c: the auto-renewal acknowledgment. Non-fatal by design - a failed email
    # must never roll back a successful signup - but logged at ERROR, not WARNING, because
    # a silently-missing acknowledgment IS the compliance gap this closes.
    try:
        _send_trial_confirmation_email(email, r.name, plan, r.billing)
    except Exception as e:
        logger.error("TRIAL_CONFIRMATION_EMAIL_FAILED email=%s error=%s", email, e)
    session_token = _make_session(email)
    resp = JSONResponse({
        "ok": True,
        "plan": plan,
        "email": email,
        "access_token": session_token,
    })
    _set_session_cookie(resp, email, session_token)
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
def auth_me(request: Request):
    # Audit P0-#1: the `token` query parameter is gone. A credential belongs in the
    # Authorization header or the session cookie, never in a URL where it lands in
    # access logs and browser history. _session_email() already accepts both.
    email = _session_email(request)
    if email:
        x = ddb_get_user(email)
        if x:
            return _user_public(x, email)
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
            logger.warning("resend verification email failed: %s", e)
    return {"ok": True}


@app.post("/auth/change-email")
def change_email(request: Request, r: ChangeEmailReq):
    old = _require_session_user(request)
    new = _norm_email(r.new_email)
    if not new:
        raise HTTPException(400, "New email required")
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
        logger.warning("change-email verification email failed: %s", e)
    resp = JSONResponse({"ok": True, "email": new})
    if new != old:
        _set_session_cookie(resp, new)
    return resp


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


def _check_expected_user(user_id, expected):
    """PHASE 2.2 IDENTITY GUARD (D-1 countermeasure, Jul 2026).

    The July 3 "destroyed siblings" incident was a session identity flip: the
    browser's effective session switched accounts mid-operation (staged
    cookie-Domain change + two logins on one machine), so writes landed in —
    and reads returned — a different userId partition. Nothing was deleted;
    everything was mis-filed and "vanished" from view. The client now pins
    which account it BELIEVES each records request is for (X-Expected-User
    header on GET/DELETE, expectedUser field on PUT); a mismatch fails loudly
    here with a 409 instead of mis-filing silently. Absent pin ⇒ no check
    (older clients keep working)."""
    if expected is None or str(expected).strip() == "":
        return
    if _norm_email(str(expected)) != user_id:
        # PHASE 4 (audit-trail gap found by the Jul-8 forensics drill): an
        # identity mismatch is the exact signature of the D-1 incident class —
        # it deserves a permanent audit row, not just a 409 in an access log.
        _write_audit("identity.mismatch", user_id, _norm_email(str(expected)),
                     "blocked", "expectedUser pin did not match session")
        raise HTTPException(
            409,
            "Session/account mismatch: this browser is signed in as a different "
            "account than this page expects. Reload the page and sign in again.",
        )


@app.get("/records")
def list_records(request: Request):
    user_id = _require_session_user(request)
    _check_expected_user(user_id, request.headers.get("x-expected-user"))
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
    # Identity guard — see _check_expected_user. Popped so the pin is transport
    # metadata, never persisted (writtenBySession/-Ip remain the forensics).
    _check_expected_user(user_id, body.pop("expectedUser", None))
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
    # FINDING 5 FIX: stamp every record write with the raw session token (first 16
    # chars — enough to correlate with server logs, not enough to reuse as a credential)
    # and the originating IP. When an unexplained write appears in DynamoDB, these two
    # fields immediately identify which device/session was responsible without needing
    # to reconstruct the event from access logs.
    raw_session = request.cookies.get(SESSION_COOKIE, "")
    item["writtenBySession"] = raw_session[:16] if raw_session else ""
    item["writtenByIp"] = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
    item["writtenAt"] = now
    _records_tbl.put_item(Item=_to_ddb(item))
    return _record_from_item(item)


@app.delete("/records/{record_id}")
def delete_record(record_id: int, request: Request):
    user_id = _require_session_user(request)
    _check_expected_user(user_id, request.headers.get("x-expected-user"))
    existing = _records_tbl.get_item(Key={"userId": user_id, "recordId": record_id}).get("Item")
    if not existing:
        _write_audit("record.delete", user_id, user_id, "not_found", f"recordId={record_id}")
        raise HTTPException(404, "Record not found")
    _records_tbl.delete_item(Key={"userId": user_id, "recordId": record_id})
    # PHASE 4 (Jul-8 drill): record deletions previously left NO audit entry —
    # only account deletions did — so a "where did my records go?" question
    # cost an hour of forensics instead of one table lookup. The record's name
    # rides in `detail` so the audit row alone answers "what was deleted".
    _write_audit("record.delete", user_id, user_id, "completed",
                 f"recordId={record_id}; name={str(existing.get('name') or '')[:120]}")
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


_STRIPE_CLIENT_MESSAGE = "Payment request could not be completed. Please try again."


def _stripe_route_error(exc, *, context):
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, stripe.error.StripeError):
        logger.warning("%s: %s", context, exc)
        raise HTTPException(400, _STRIPE_CLIENT_MESSAGE)
    logger.exception("%s: unexpected error", context)
    raise HTTPException(500, _STRIPE_CLIENT_MESSAGE)


@app.post("/stripe/setup-intent")
def setup():
    try:
        i = stripe.SetupIntent.create(usage="off_session")
        return {"client_secret": i.client_secret}
    except Exception as e:
        _stripe_route_error(e, context="stripe setup-intent")


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
        existing = stripe.Subscription.list(customer=cid, status="all", limit=10)
        active = None
        for _s in existing.auto_paging_iter():
            if _s.status in ("active", "trialing", "past_due", "unpaid"):
                active = _s
                break
        if active:
            _item_id = active["items"]["data"][0]["id"]
            _proration = "none" if active.status == "trialing" else "always_invoice"
            sub = stripe.Subscription.modify(
                active.id,
                items=[{"id": _item_id, "price": price_id}],
                proration_behavior=_proration,
                default_payment_method=r.payment_method_id,
            )
        else:
            sub = stripe.Subscription.create(
                customer=cid,
                items=[{"price": price_id}],
                trial_period_days=7,
                default_payment_method=r.payment_method_id,
            )
        return {"status": "ok", "customer_id": cid, "subscription_id": sub.id}
    except Exception as e:
        _stripe_route_error(e, context="stripe subscribe")


OAUTH_CLIENT_ID_ENV = {
    "quickbooks": "QUICKBOOKS_CLIENT_ID",
    "freshbooks": "FRESHBOOKS_CLIENT_ID",
    "xero": "XERO_CLIENT_ID",
    "wave": "WAVE_CLIENT_ID",
}

_OAUTH_STATIC = {
    "quickbooks": {
        "redirect": "https://app.taxstat360.com/integrations/quickbooks/callback",
        "auth_url": "https://appcenter.intuit.com/app/connect/oauth2",
        "scope": "com.intuit.quickbooks.accounting",
    },
    "freshbooks": {
        "redirect": "https://app.taxstat360.com/integrations/freshbooks/callback",
        "auth_url": "https://auth.freshbooks.com/oauth/authorize/",
        "scope": os.environ.get(
            "FRESHBOOKS_SCOPE",
            "user:profile:read user:reports:read",
        ),
    },
    "xero": {
        "redirect": "https://app.taxstat360.com/integrations/xero/callback",
        "auth_url": "https://login.xero.com/identity/connect/authorize",
        "scope": os.environ.get(
            "XERO_SCOPE",
            "openid profile email offline_access accounting.reports.profitandloss.read",
        ),
    },
    "wave": {
        "redirect": "https://app.taxstat360.com/integrations/wave/callback",
        "auth_url": "https://api.waveapps.com/oauth2/authorize/",
        "scope": "account:* business:read",
    },
}


def _oauth_config(provider):
    p = (provider or "").lower()
    if p not in _OAUTH_STATIC:
        raise HTTPException(404, "Unknown provider")
    env_key = OAUTH_CLIENT_ID_ENV[p]
    client_id = (os.environ.get(env_key) or "").strip()
    if not client_id:
        logger.error("OAuth client id missing provider=%s env=%s", p, env_key)
        raise HTTPException(503, f"{p} integration is not configured")
    return {**_OAUTH_STATIC[p], "client_id": client_id}

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
# AUDIT N-2 BACKEND FIX (Jul 2026). ARIA_MODEL: gpt-4o-mini has an Oct-2023 training
# cutoff and, before this fix, answered depreciation/limit questions with repealed
# pre-OBBBA law (audit captured "20% bonus depreciation" advice for 2026; correct: 100%,
# permanent). The CURRENT LAW block below makes answers correct regardless of model
# vintage. RECOMMENDATION: also set the ARIA_MODEL env var to a current-generation
# model whose training postdates the OBBBA (July 2025) for better handling of topics
# outside the brief. ANNUAL MAINTENANCE: update the figures below together with the
# frontend TAX_TABLES (src/taxCalc.js) and the Aria.jsx guard facts each January.
ARIA_MODEL = os.environ.get("ARIA_MODEL", "gpt-4o-mini")
ARIA_SYSTEM = (
    "You are Aria, the TaxStat360 AI tax strategist. Help business owners with federal tax "
    "planning, estimated payments, entity structure, deductions, and compliance-aware guidance. "
    "Be concise, practical, and remind users this is planning guidance\u2014not filing advice. "
    "Never invent user-specific numbers; ask for details when needed.\n\n"
    "CURRENT LAW \u2014 AUTHORITATIVE, VERIFIED JULY 2026. Your training data may predate the "
    "One Big Beautiful Bill Act (OBBBA, P.L. 119-21, enacted July 4, 2025). The following is "
    "current law and SUPERSEDES anything you learned in training. Never present pre-OBBBA "
    "rules (e.g., the bonus-depreciation phase-down, TCJA sunsets) as current:\n"
    "\u2022 Bonus depreciation: 100%, PERMANENT (\u00a7168(k), OBBBA \u00a770301) for qualified "
    "property acquired after Jan 19, 2025. The 80/60/40/20% phase-down is repealed for new "
    "acquisitions. Cost-segregation 5/7/15-year property placed in service in 2026 gets 100%.\n"
    "\u2022 \u00a7179: $2.5M limit / $4M phase-out (2025, indexed for 2026).\n"
    "\u2022 2026 figures (Rev. Proc. 2025-32): standard deduction $16,100 single / $32,200 MFJ / "
    "$24,150 HOH; 37% bracket begins at $640,600 single / $768,700 MFJ; long-term capital gains "
    "0% band tops at $49,450 single / $98,900 MFJ, 20% above $545,500 / $613,700.\n"
    "\u2022 \u00a7199A QBI: 20% deduction, PERMANENT (OBBBA); 2026 thresholds $201,775 single / "
    "$403,500 MFJ; $75K/$150K phase-in ranges; $400 minimum deduction; SSTB benefit fully "
    "phased out above threshold + phase-in.\n"
    "\u2022 SALT cap 2026 (OBBBA \u00a770120): $40,400 ($20,200 MFS), reduced by 30% of MAGI over "
    "$505,000 ($252,500 MFS), floor $10,000 ($5,000 MFS). A pass-through entity-level tax "
    "election (PTET) can restore the FEDERAL deduction for state taxes on business income.\n"
    "\u2022 2026 retirement (Notice 2025-67): 401(k) deferral $24,500; \u00a7415(c) limit $72,000; "
    "age-50 catch-up $8,000 (ages 60\u201363: $11,250); IRA $7,500 + $1,100 catch-up; SEP max "
    "$72,000. HSA (Rev. Proc. 2025-19): $4,400 self-only / $8,750 family.\n"
    "\u2022 Child tax credit: $2,200 per child. AMT 2026: exemption $90,100 single / $140,200 "
    "MFJ; phase-out begins $500K / $1M at a 50% rate.\n"
    "\u2022 \u00a7461(l) excess business loss 2026: $256,000 single / $512,000 MFJ (Rev. Proc. "
    "2025-32 \u00a74.31). OBBBA RESET these DOWN from 2025's $313K/$626K \u2014 do not project them "
    "upward from prior years.\n"
    "\u2022 Charitable 2026: itemizers face a 0.5%-of-AGI floor; non-itemizers may deduct up to "
    "$1,000 / $2,000 MFJ (\u00a7170(p)). New \u00a768 (OBBBA \u00a770111): itemized deductions reduced "
    "by 2/37 of the lesser of total itemized deductions or taxable income over the 37% "
    "threshold.\n"
    "\u2022 S corporations: >2% shareholder health premiums are deductible only up to W-2 wages "
    "from the S-corp (\u00a7162(l)(5)(A); Notice 2008-1 requires Box-1 inclusion). Distributions "
    "from an S-corp with C-corp accumulated E&P follow \u00a71368(c): AAA first, then DIVIDENDS to "
    "the extent of E&P, then basis recovery. The \u00a73121(b)(3)(A) FICA exemption for employing "
    "one's under-18 child NEVER applies to a corporation, including an S-corp.\n"
    "\u2022 Real estate: REPS requires BOTH \u00a7469(c)(7)(B) tests (>750 hours AND more than half "
    "of all personal-service hours) plus material participation per rental or the "
    "\u00a71.469-9(g) aggregation election. Short-term rentals averaging 7 days or less per stay "
    "are not \u00a7469(c)(2) rental activities (Reg. \u00a71.469-1T(e)(3)(ii)(A)) \u2014 material "
    "participation alone makes those losses nonpassive.\n"
    "\u2022 Estimated tax: safe harbor is 110% of prior-year tax when prior-year AGI exceeded "
    "$150K ($75K MFS) \u2014 \u00a76654(d)(1)(C)(i); penalties accrue per installment.\n"
    "If a question involves rates, limits, or thresholds NOT listed above, say the figure may "
    "have changed since your training and direct the user to the verified tables in the Tax "
    "Tracker rather than guessing."
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
    o = _oauth_config("xero")
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
        logger.warning("xero token refresh: %s %s", r.status_code, r.text[:200])
        return None
    tok = r.json()
    # Xero rotates the refresh token on every use: the *new* one must be persisted or
    # the connection dies at the next sync. The old code discarded it.
    return {
        "access_token": tok.get("access_token", ""),
        "refresh_token": tok.get("refresh_token", ""),
    }


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
        logger.info("xero pnl unmatched summaries: %s", list(summaries.keys())[:25])
    return rev, exp, net, summaries


def _qb_pl_column_indices(data):
    """Map report Columns metadata to label and amount ColData indices (v1 + v2 safe)."""
    cols = data.get("Columns", {}).get("Column", [])
    if isinstance(cols, dict):
        cols = [cols]
    label_idx = None
    amount_candidates = []
    for i, col in enumerate(cols):
        if not isinstance(col, dict):
            continue
        col_type = (col.get("ColType") or "").lower()
        col_title = (col.get("ColTitle") or "").strip().lower()
        col_key = ""
        for md in col.get("MetaData") or []:
            if isinstance(md, dict) and (md.get("Name") or "").lower() == "colkey":
                col_key = (md.get("Value") or "").lower()
        if col_type == "account" or col_key == "account":
            label_idx = i
        elif col_title in ("", "account") and label_idx is None:
            label_idx = i
        if col_type == "money" or col_key in ("total", "amount", "subt_nat_amount"):
            amount_candidates.append(i)
        elif col_title in ("total", "amount"):
            amount_candidates.append(i)
    if label_idx is None:
        label_idx = 0
    amount_idx = amount_candidates[-1] if amount_candidates else (1 if len(cols) > 1 else 0)
    return label_idx, amount_idx


def _qb_pl_cell(coldata, idx):
    if not coldata or idx is None or idx < 0:
        return {}
    if isinstance(coldata, dict):
        coldata = [coldata]
    if idx >= len(coldata):
        return {}
    cell = coldata[idx]
    return cell if isinstance(cell, dict) else {}


def _qb_pl_row_label_amount(coldata, label_idx, amount_idx):
    """Read label + amount from a Summary/Header/ColData row using column metadata."""
    if not coldata:
        return "", 0.0
    if isinstance(coldata, dict):
        coldata = [coldata]
    label = str(_qb_pl_cell(coldata, label_idx).get("value", "") or "").strip()
    amt = _parse_pl_amount(_qb_pl_cell(coldata, amount_idx).get("value"))
    if amt == 0.0:
        for cell in reversed(coldata):
            if not isinstance(cell, dict):
                continue
            raw = cell.get("value")
            if raw is None or str(raw).strip() in ("", "-"):
                continue
            parsed = _parse_pl_amount(raw)
            if parsed != 0.0:
                amt = parsed
                break
    return label, amt


def _qb_normalize_group(grp):
    return (grp or "").lower().replace(" ", "").replace("_", "")


def _qb_pl_apply_summary(grp, name, amt, bucket):
    """Update rev/cogs/opex/other_income/net from one Summary row."""
    label = (name or "").lower()
    g = _qb_normalize_group(grp)
    if "net income" in label or "net profit" in label or g == "netincome":
        bucket["net"] = amt
    elif g == "income" or (
        "total income" in label and "other" not in label
    ) or "total for income" in label:
        bucket["rev"] = amt
    elif g in ("otherincome",) or (
        "total for other income" in label
        or ("other income" in label and "total" in label)
    ):
        bucket["other_income"] = amt
    elif g in ("cogs", "costofgoodssold") or "cost of goods" in label:
        bucket["cogs"] = abs(amt)
    elif g == "expenses" or (
        "total expenses" in label and "other" not in label
    ) or "total for expenses" in label:
        bucket["opex"] = abs(amt)


def _parse_qb_pnl(data):
    label_idx, amount_idx = _qb_pl_column_indices(data)
    bucket = {"rev": 0.0, "cogs": 0.0, "opex": 0.0, "other_income": 0.0, "net": None}

    def walk(rows):
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            grp = row.get("group") or ""
            summary = row.get("Summary", {}).get("ColData", [])
            if summary:
                name, amt = _qb_pl_row_label_amount(summary, label_idx, amount_idx)
                if name or amt:
                    _qb_pl_apply_summary(grp, name, amt, bucket)
            nested = row.get("Rows", {}).get("Row", [])
            if nested:
                walk(nested if isinstance(nested, list) else [nested])

    top = data.get("Rows", {}).get("Row", [])
    walk(top if isinstance(top, list) else ([top] if top else []))
    rev = bucket["rev"] + bucket["other_income"]
    exp = bucket["cogs"] + bucket["opex"]
    net = bucket["net"]
    if net is None and (rev or exp):
        net = rev - exp
    return rev, exp, net


def _quickbooks_api_base():
    """Production or sandbox QBO API host (sandbox companies need sandbox-quickbooks...)."""
    return os.environ.get("QUICKBOOKS_API_BASE", "https://quickbooks.api.intuit.com").rstrip("/")


def _quickbooks_pl_params(start, end):
    """Query params for QuickBooks ProfitAndLoss (optional migration + minorversion)."""
    params = {
        "start_date": start,
        "end_date": end,
        "accounting_method": os.environ.get("QUICKBOOKS_ACCOUNTING_METHOD", "Cash"),
    }
    minor = (os.environ.get("QUICKBOOKS_MINORVERSION") or "").strip()
    if minor:
        params["minorversion"] = minor
    if os.environ.get("QUICKBOOKS_TESTING_MIGRATION", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        params["testing_migration"] = ""
    return params


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
            logger.info("freshbooks token exchange ok via %s", name)
            return r.json()
        logger.warning("freshbooks token exchange %s: %s %s", name, r.status_code, r.text[:200])
    if last is not None:
        logger.warning(
            "oauth token exchange freshbooks: %s %s",
            last.status_code,
            last.text[:300],
        )
    raise HTTPException(400, "OAuth token exchange failed")


def _exchange_oauth_code(provider, code):
    o = _oauth_config(provider)
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
        logger.warning("oauth token exchange %s: %s %s", provider, r.status_code, r.text[:300])
        raise HTTPException(400, "OAuth token exchange failed")
    return r.json()


@app.get("/integrations/status")
def integration_status(request: Request):
    """Which providers this user has connected.

    The browser no longer holds tokens, so it can no longer infer "connected" from the
    presence of one in localStorage. It asks the server instead. Deliberately returns
    booleans and timestamps only — never the credentials themselves.
    """
    email = _require_session_user(request)
    rec = ddb_get_user(email) or {}
    integrations = rec.get("integrations") or {}
    out = {}
    for provider in sorted(ALLOWED_PROVIDERS):
        creds = integrations.get(provider) or {}
        out[provider] = {
            "connected": bool(creds.get("access_token")),
            "updated_at": creds.get("updated_at"),
        }
    return out


@app.post("/integrations/{p}/disconnect")
def integration_disconnect(request: Request, p: str):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    email = _require_session_user(request)
    _integration_creds_clear(email, p)
    return {"ok": True, "provider": p, "connected": False}


def _oauth_authorize_redirect_url(provider, email, entity="0"):
    o = _oauth_config(provider)
    state = quote(_make_oauth_state(email, entity))
    return (
        f"{o['auth_url']}?client_id={o['client_id']}&redirect_uri={quote(o['redirect'])}"
        f"&response_type=code&scope={quote(o['scope'])}&state={state}"
    )


@app.get("/integrations/{p}/connect-url")
def connect_url(request: Request, p: str, entity: str = "0"):
    """JSON authorize URL for the SPA (Bearer/cookie). Prefer this over /connect
    so Authorization can be attached before leaving the page."""
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    email = _require_session_user(request)
    return {"url": _oauth_authorize_redirect_url(p, email, entity), "provider": p}


@app.get("/integrations/{p}/connect")
def connect(request: Request, p: str, entity: str = "0"):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    # Only a signed-in user may start an OAuth flow: the tokens it yields are stored
    # against their account, so we must know who they are before the round-trip begins.
    email = _require_session_user(request)
    return RedirectResponse(url=_oauth_authorize_redirect_url(p, email, entity))


@app.get("/integrations/{p}/callback")
def callback(p: str, code: str = "", state: str = "", realmId: str = "", tenantId: str = ""):
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    if not code:
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=missing_code")
    # The signed state is the only thing telling us who is connecting. It was minted in
    # /connect for an authenticated user; a forged or stale one is refused outright.
    email, entity_idx = _verify_oauth_state(unquote(state or ""))
    if not email:
        return RedirectResponse(
            url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=invalid_state"
        )
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
                logger.warning("xero connections: %s %s", conn.status_code, conn.text[:300])
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
        logger.exception("oauth callback %s failed", p)
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=token_exchange")
    if not access_token:
        return RedirectResponse(url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=no_token")
    if p == "xero" and not tenant_id:
        return RedirectResponse(
            url=f"{FRONTEND_URL}/calculate-tax?{p}=error&reason=missing_tenant"
        )
    # Audit P0-#1: tokens are persisted against the user and the browser is redirected
    # back with nothing but a "connected" flag. Previously the access token — and the
    # Xero refresh token — travelled in this redirect URL, which put a live credential
    # to the customer's books into the address bar, browser history, and localStorage.
    _integration_creds_save(
        email,
        p,
        access_token=access_token,
        refresh_token=refresh_token,
        realm_id=realm_id,
        tenant_id=tenant_id,
        account_id=str(fb_account_id or ""),
    )
    return RedirectResponse(
        url=f"{FRONTEND_URL}/calculate-tax?{p}=connected&entity={entity_idx}"
    )


@app.get("/integrations/{p}/data")
def integration_data(request: Request, p: str, year: str = ""):
    """Return the connected provider's P&L for `year`.

    Audit P0-#1: this route was previously UNAUTHENTICATED and took the provider access
    token — and the Xero refresh token — as URL query parameters, which made it an open
    proxy into any customer's accounting system for anyone holding a leaked token. It
    now requires a session and loads the credentials from that user's own record, so no
    token appears in a URL, an access log, or the browser.
    """
    if p not in ALLOWED_PROVIDERS:
        raise HTTPException(404)
    email = _require_session_user(request)
    creds = _integration_creds_get(email, p)
    token = creds.get("access_token", "")
    if not token:
        # Natasha launch fix: do not dress missing credentials up as HTTP 200.
        raise HTTPException(401, "missing token")
    realm = creds.get("realm_id", "")
    tenant = creds.get("tenant_id", "")
    account = creds.get("account_id", "")
    refresh_token = creds.get("refresh_token", "")
    start, end = _pnl_date_range(year)
    try:
        if p == "quickbooks":
            if not realm:
                raise HTTPException(400, "missing realm")
            r = requests.get(
                f"{_quickbooks_api_base()}/v3/company/{realm}/reports/ProfitAndLoss",
                params=_quickbooks_pl_params(start, end),
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=30,
            )
            if not r.ok:
                logger.warning("quickbooks profitloss: %s %s", r.status_code, r.text[:300])
                raise HTTPException(502, "quickbooks report failed")
            rev, exp, net = _parse_qb_pnl(r.json())
            return _pnl_result(rev, exp, net_profit=net)
        if p == "xero":
            if not tenant:
                raise HTTPException(400, "missing tenant")
            access = token
            if refresh_token:
                refreshed = _xero_refresh_access_token(refresh_token)
                if refreshed and refreshed.get("access_token"):
                    access = refreshed["access_token"]
                    # Xero rotates refresh tokens; store the new pair or the next sync fails.
                    _integration_creds_save(
                        email,
                        "xero",
                        access_token=access,
                        refresh_token=refreshed.get("refresh_token") or refresh_token,
                        tenant_id=tenant,
                    )
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
                logger.warning("xero profitloss: %s %s", r.status_code, r.text[:300])
                raise HTTPException(502, "xero report failed")
            reports = r.json().get("Reports") or []
            if not reports:
                raise HTTPException(502, "xero report empty")
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
            ) or account
            if not aid:
                raise HTTPException(400, "missing freshbooks account")
            r = requests.get(
                f"https://api.freshbooks.com/accounting/account/{aid}/reports/accounting/profitloss"
                f"?start_date={start}&end_date={end}",
                headers=h,
                timeout=30,
            )
            if not r.ok:
                logger.warning("freshbooks profitloss: %s %s", r.status_code, r.text[:300])
                raise HTTPException(502, "freshbooks report failed")
            pl = r.json().get("response", {}).get("result", {}).get("profitloss", {})
            # FreshBooks labels total_income as "Gross Profit" in the P&L report.
            gross = _fb_pl_amount(pl, "total_income", "gross_profit")
            exp = _fb_pl_amount(pl, "total_expenses", "total_expense")
            net = _fb_pl_amount(pl, "net_profit")
            return _pnl_result(gross, exp, net_profit=net)
    except HTTPException:
        raise
    except Exception:
        logger.exception("integration data provider=%s failed", p)
        raise HTTPException(500, "Provider request failed")
    raise HTTPException(404)

def _require_minimum_plan(request: Request, minimum: str):
    """Session-required plan floor (DynamoDB plan is source of truth)."""
    email = _require_session_user(request)
    user = ddb_get_user(email) or {}
    plan = user.get("plan", "starter")
    try:
        if PLAN_ORDER.index(plan) < PLAN_ORDER.index(minimum):
            raise HTTPException(
                403, f"{minimum.capitalize()} plan required"
            )
    except ValueError:
        raise HTTPException(403, f"{minimum.capitalize()} plan required")
    return email, user, plan


@app.post("/aria")
async def aria_chat(request: Request):
    email, user, plan = _require_minimum_plan(request, "professional")
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
        logger.warning("aria request failed: %s", e)
        raise HTTPException(503, "Aria service unavailable")
    if not r.ok:
        logger.warning("aria openai: %s %s", r.status_code, r.text[:300])
        raise HTTPException(503, "Aria service unavailable")
    reply = r.json()["choices"][0]["message"]["content"]
    return {"reply": reply}


@app.post("/reports/cpa-briefing/authorize")
def authorize_cpa_briefing(request: Request):
    """Enterprise-only gate before CPA Briefing generation.

    The briefing document is assembled client-side from the user's saved
    figures; this endpoint is the server-side entitlement check so a
    Professional account cannot bypass the upsell UI and still generate it.
    """
    email, _user, plan = _require_minimum_plan(request, "enterprise")
    return {"ok": True, "feature": "cpa-briefing", "plan": plan, "email": email}


@app.post("/reports/position-docs/authorize")
def authorize_position_docs(request: Request):
    """Enterprise-only gate for Position Documentation / IRS notice templates."""
    email, _user, plan = _require_minimum_plan(request, "enterprise")
    return {"ok": True, "feature": "position-docs", "plan": plan, "email": email}


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
            ses = _mailer()   # AUDIT F-8d: SendGrid, not SES (SES sandbox drops all customer mail)
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
            logger.warning("password reset email failed: %s", e)
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


def _resolve_webhook_secret():
    """Resolve STRIPE_WEBHOOK_SECRET, failing closed unconditionally.

    SECURITY FIX (independent review, Aug 2026): Stripe's signature is the ONLY
    authentication /stripe/webhook has — it can't carry a session cookie or
    bearer token, since Stripe calls it directly. The endpoint previously did
    `if WEBHOOK_SECRET: verify(...)`, so a missing, mistyped, or not-yet-rotated
    STRIPE_WEBHOOK_SECRET in production silently disabled verification instead
    of blocking startup — anyone could then POST an arbitrary JSON body claiming
    to be e.g. customer.subscription.updated for a known Stripe customer id and
    upgrade that account to a paid plan for free (or cancel one). This mirrors
    the STRIPE_SECRET_KEY check a few lines above in this file: fail closed,
    always, with no environment-based carve-out — exactly like that key,
    local/dev/test setups are expected to supply a real (test-mode) value via
    .env / the test harness, same as STRIPE_SECRET_KEY already requires today.
    """
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        raise RuntimeError("STRIPE_WEBHOOK_SECRET environment variable not set")
    return secret


WEBHOOK_SECRET = _resolve_webhook_secret()


def _process_stripe_webhook_event(event):
    """Apply subscription/plan side effects for a verified Stripe event.

    Defensive against partial / None payloads. A cancellation
    (customer.subscription.deleted) can arrive AFTER the user's DynamoDB
    record was already removed (e.g. account deletion), and some nested
    fields (cancellation_details, items) can be null. Every branch tolerates
    a missing user / missing field, logs, and returns without raising so a
    single event can never 500 and get the endpoint disabled again.
    """
    etype = event.get("type", "")
    data = (event.get("data") or {}).get("object") or {}
    cid = data.get("customer", "") or ""
    if etype == "customer.subscription.updated":
        status = data.get("status", "")
        items = (data.get("items") or {}).get("data") or []
        price_id = (items[0].get("price") or {}).get("id", "") if items else ""
        new_plan = next((k for k, v in PRICE_IDS.items() if price_id in v.values()), None)
        if status in ("active", "trialing") and new_plan:
            _ddb_update_user_plan(cid, new_plan)
        elif status in ("canceled", "unpaid", "past_due"):
            _ddb_update_user_plan(cid, "starter")
    elif etype == "customer.subscription.deleted":
        if not cid:
            logger.info(
                "subscription.deleted with no customer id; nothing to update (event=%s)",
                event.get("id", ""),
            )
            return
        updated = _ddb_update_user_plan(cid, "starter")
        if not updated:
            logger.info(
                "subscription.deleted for already-removed/missing user "
                "(customer=%s); nothing to update",
                cid,
            )
    elif etype == "invoice.payment_failed":
        email, _ = ddb_find_user_by_stripe_customer_id(cid)
        if email:
            logger.warning("invoice.payment_failed for %s (stripe %s)", email, cid)
        else:
            logger.warning("invoice.payment_failed for unknown stripe customer %s", cid)


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    import json as _json

    try:
        if WEBHOOK_SECRET:
            # Verify the signature (raises on tampering / mismatch). We deliberately
            # do NOT use its return value for processing: stripe.Webhook.construct_event
            # returns a StripeObject whose .get() routes through __getattr__ and raises
            # AttributeError on this stripe version. Process a plain dict instead.
            stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
        event = _json.loads(payload)
    except stripe.error.SignatureVerificationError:
        logger.warning("stripe webhook signature verification failed")
        raise HTTPException(400, "Invalid webhook signature")
    except (ValueError, TypeError) as e:
        logger.warning("stripe webhook payload invalid: %s", e)
        raise HTTPException(400, "Invalid webhook payload")
    except HTTPException:
        raise
    except Exception:
        logger.exception("stripe webhook unexpected error")
        raise HTTPException(400, "Invalid webhook payload")
    # event is now a plain dict, so .get() is always safe here and below.
    try:
        _process_stripe_webhook_event(event)
    except Exception:
        logger.exception(
            "stripe webhook processing failed type=%s id=%s",
            event.get("type", "") if isinstance(event, dict) else "",
            event.get("id", "") if isinstance(event, dict) else "",
        )
    return {"status": "ok"}
