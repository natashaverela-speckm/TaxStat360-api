import json,os,hashlib,secrets,stripe,requests,boto3,time
from fastapi import FastAPI,HTTPException,Request,Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
if not stripe.api_key:
    raise RuntimeError("STRIPE_SECRET_KEY environment variable not set")

MC_KEY=os.environ.get("MC_KEY", "")
MC_LIST="f546bd92ac"

app=FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://www.taxstat360.com","https://taxstat360.com"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB="/home/ubuntu/risk-planner-BE/users.json"

def load():
    if os.path.exists(DB):return json.load(open(DB))
    return {}

def save(u):json.dump(u,open(DB,"w"))

def mc_subscribe(email,name=""):
    try:
        fname=name.split(" ")[0] if name else ""
        lname=" ".join(name.split(" ")[1:]) if name and " " in name else ""
        requests.post(f"https://us4.api.mailchimp.com/3.0/lists/{MC_LIST}/members",auth=("anystring",MC_KEY),json={"email_address":email,"status":"subscribed","merge_fields":{"FNAME":fname,"LNAME":lname}},timeout=5)
    except:pass

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
                detail=f"{minimum.capitalize()} plan required to access this feature"
            )
        return user
    return checker

class Reg(BaseModel):
    name:str
    email:str
    password:str
    plan:str="starter"
    payment_method_id:str=""

class Log(BaseModel):
    email:str
    password:str

class Sub(BaseModel):
    email:str
    plan:str
    payment_method_id:str
    billing:str="monthly"

PRICE_IDS={
    "starter":      {"monthly":"price_1TJmmDGUoj1XrJQjbArxsVDy","annual":"price_1TO5zWGUoj1XrJQjcWpQmMnC"},
    "professional": {"monthly":"price_1TJmmwGUoj1XrJQjZp897iCJ","annual":"price_1TO60pGUoj1XrJQjhU4R9yGQ"},
    "enterprise":   {"monthly":"price_1TJmnKGUoj1XrJQjfgrOhAlC","annual":"price_1TO62FGUoj1XrJQjtcbNym1Z"},
}

VALID_PLANS = set(PRICE_IDS.keys())
ALLOWED_PROVIDERS = {"quickbooks","freshbooks","xero","wave"}

@app.post("/auth/register")
@limiter.limit("3/minute")
def register(r:Reg, request:Request):
    u=load()
    if r.email in u:raise HTTPException(400,"Email already registered")
    plan = r.plan if r.plan in VALID_PLANS else "starter"
    tok=secrets.token_hex(32)
    verify_tok=secrets.token_hex(32)
    u[r.email]={"name":r.name,"pw":hashlib.sha256(r.password.encode()).hexdigest(),"tok":tok,"plan":plan,"stripe_customer_id":"","verified":False,"verify_tok":verify_tok}
    save(u)
    mc_subscribe(r.email,r.name)
    # Send verification email
    try:
        ses = boto3.client("ses", region_name="us-east-1")
        verify_url = f"https://app.taxstat360.com/auth/verify-email?token={verify_tok}&email={r.email}"
        ses.send_email(
            Source="admin@taxstat360.com",
            Destination={"ToAddresses": [r.email]},
            Message={
                "Subject": {"Data": "Verify your TaxStat360 email"},
                "Body": {"Html": {"Data": f"""
                    <p>Hi {r.name},</p>
                    <p>Thanks for signing up for TaxStat360. Click below to verify your email address:</p>
                    <p><a href="{verify_url}">Verify my email</a></p>
                    <p>— TaxStat360</p>
                """}}
            }
        )
    except Exception as e:
        print(f"SES verify error: {e}")
    return {"access_token":tok}

@app.post("/auth/login")
@limiter.limit("5/minute")
def login(r:Log, request:Request):
    u=load()
    x=u.get(r.email)
    if not x or x["pw"]!=hashlib.sha256(r.password.encode()).hexdigest():
        raise HTTPException(401,"Invalid email or password")
    # Rotate token on every login — invalidates any previously stolen tokens
    new_tok = secrets.token_hex(32)
    u[r.email]["tok"] = new_tok
    save(u)
    return {"access_token":new_tok,"plan":x.get("plan","starter")}

@app.get("/user/me")
def me(user=Depends(get_user_from_token)):
    return {"email":user["email"],"plan":user.get("plan","starter"),"name":user.get("name","")}

@app.post("/user/business-info")
def biz(user=Depends(get_user_from_token)):
    return {"status":"saved"}

@app.post("/stripe/setup-intent")
def setup():
    try:
        i=stripe.SetupIntent.create(usage="off_session")
        return {"client_secret":i.client_secret}
    except Exception as e:
        raise HTTPException(400,str(e))

@app.post("/stripe/subscribe")
def subscribe(r:Sub, user=Depends(get_user_from_token)):
    try:
        u=load()
        x=u.get(user["email"])
        if not x:raise HTTPException(404,"User not found")
        billing=r.billing if r.billing in ["monthly","annual"] else "monthly"
        plan=r.plan if r.plan in PRICE_IDS else "starter"
        price_id=PRICE_IDS[plan][billing]
        cid=x.get("stripe_customer_id","")
        if not cid:
            c=stripe.Customer.create(email=user["email"],name=x.get("name",""))
            cid=c.id;u[user["email"]]["stripe_customer_id"]=cid
        stripe.PaymentMethod.attach(r.payment_method_id,customer=cid)
        stripe.Customer.modify(cid,invoice_settings={"default_payment_method":r.payment_method_id})
        u[user["email"]]["plan"]=plan;u[user["email"]]["billing"]=billing;save(u)
        sub=stripe.Subscription.create(customer=cid,items=[{"price":price_id}],trial_period_days=7,default_payment_method=r.payment_method_id)
        return {"status":"ok","customer_id":cid,"subscription_id":sub.id}
    except Exception as e:
        raise HTTPException(400,str(e))

OAUTH={
    "quickbooks":  {"client_id":"ABw0WBOceb971XVhquWW9DWJfOHZkF5KjOr8SthaNACDKOILpZ","redirect":"https://app.taxstat360.com/integrations/quickbooks/callback","auth_url":"https://appcenter.intuit.com/connect/oauth2","scope":"com.intuit.quickbooks.accounting"},
    "freshbooks":  {"client_id":"86619f0b77a5405cc791956760108aa8da609558bc4945e596c82adcdcd270c2","redirect":"https://app.taxstat360.com/integrations/freshbooks/callback","auth_url":"https://auth.freshbooks.com/oauth/authorize","scope":"user:profile:read"},
    "xero":        {"client_id":"0921E54B89164E24BA072A0E79741FA5","redirect":"https://app.taxstat360.com/integrations/xero/callback","auth_url":"https://login.xero.com/identity/connect/authorize","scope":"openid profile email"},
    "wave":        {"client_id":"IS3R7n6dQG7IKscrPQSn4afGSJskrnToqpYik7Fp","redirect":"https://app.taxstat360.com/integrations/wave/callback","auth_url":"https://api.waveapps.com/oauth2/authorize","scope":"account:* business:read"},
}

@app.get("/integrations/{p}/connect")
def connect(p:str):
    if p not in ALLOWED_PROVIDERS:raise HTTPException(404)
    o=OAUTH[p]
    return RedirectResponse(f"{o['auth_url']}?client_id={o['client_id']}&redirect_uri={o['redirect']}&response_type=code&scope={o['scope']}&state=ts360")

@app.get("/integrations/{p}/callback")
def callback(p:str,code:str="",state:str=""):
    if p not in ALLOWED_PROVIDERS:raise HTTPException(404)
    return RedirectResponse(url=f"https://www.taxstat360.com/dashboard?{p}=connected")

WEBHOOK_SECRET=os.environ.get("STRIPE_WEBHOOK_SECRET","")


class ForgotPw(BaseModel):
    email: str

class ResetPw(BaseModel):
    email: str
    token: str
    new_password: str


@app.get("/auth/verify-email")
def verify_email(token:str="", email:str=""):
    u=load()
    x=u.get(email)
    if not x or x.get("verify_tok") != token:
        raise HTTPException(400, "Invalid or expired verification link")
    u[email]["verified"] = True
    u[email].pop("verify_tok", None)
    save(u)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="https://www.taxstat360.com/onboarding/entity?verified=true")

@app.post("/auth/forgot-password")
@limiter.limit("3/minute")
def forgot_password(r:ForgotPw, request:Request):
    # SECURITY: always return success to prevent email enumeration
    u=load()
    x=u.get(r.email)
    if x:
        reset_tok = secrets.token_hex(32)
        u[r.email]["reset_tok"] = reset_tok
        u[r.email]["reset_exp"] = int(time.time()) + 3600  # 1 hour
        save(u)
        try:
            ses = boto3.client("ses", region_name="us-east-1")
            reset_url = f"https://www.taxstat360.com/reset-password?token={reset_tok}&email={r.email}"
            ses.send_email(
                Source="admin@taxstat360.com",
                Destination={"ToAddresses": [r.email]},
                Message={
                    "Subject": {"Data": "Reset your TaxStat360 password"},
                    "Body": {"Html": {"Data": f"""
                        <p>Hi,</p>
                        <p>Click the link below to reset your TaxStat360 password. This link expires in 1 hour.</p>
                        <p><a href="{reset_url}">Reset my password</a></p>
                        <p>If you did not request this, ignore this email.</p>
                        <p>— TaxStat360</p>
                    """}}
                }
            )
        except Exception as e:
            print(f"SES error: {e}")
    return {"ok": True, "message": "If that email is registered, a reset link has been sent."}

@app.post("/auth/reset-password")
def reset_password(r:ResetPw):
    u=load()
    x=u.get(r.email)
    if not x:
        raise HTTPException(400, "Invalid or expired reset link")
    if x.get("reset_tok") != r.token:
        raise HTTPException(400, "Invalid or expired reset link")
    if int(time.time()) > x.get("reset_exp", 0):
        raise HTTPException(400, "Reset link has expired — please request a new one")
    # Valid — update password and clear reset token
    u[r.email]["pw"] = hashlib.sha256(r.new_password.encode()).hexdigest()
    u[r.email]["tok"] = secrets.token_hex(32)  # invalidate all sessions
    u[r.email].pop("reset_tok", None)
    u[r.email].pop("reset_exp", None)
    save(u)
    return {"ok": True, "message": "Password updated successfully. Please log in with your new password."}

@app.post("/stripe/webhook")
async def stripe_webhook(request:Request):
    payload=await request.body()
    sig=request.headers.get("stripe-signature","")
    try:
        if WEBHOOK_SECRET:
            event=stripe.Webhook.construct_event(payload,sig,WEBHOOK_SECRET)
        else:
            import json as _json
            event=_json.loads(payload)
    except Exception as e:
        raise HTTPException(400,str(e))
    u=load()
    etype=event.get("type","")
    data=event.get("data",{}).get("object",{})
    cid=data.get("customer","")
    if etype=="customer.subscription.updated":
        status=data.get("status","")
        items=data.get("items",{}).get("data",[])
        price_id=items[0].get("price",{}).get("id","") if items else ""
        new_plan=next((k for k,v in PRICE_IDS.items() if price_id in v.values()),None)
        for email,ud in u.items():
            if ud.get("stripe_customer_id")==cid:
                if status in ("active","trialing") and new_plan:
                    ud["plan"]=new_plan
                elif status in ("canceled","unpaid","past_due"):
                    ud["plan"]="starter"
                break
        save(u)
    elif etype=="customer.subscription.deleted":
        for email,ud in u.items():
            if ud.get("stripe_customer_id")==cid:
                ud["plan"]="starter"
                break
        save(u)
    elif etype=="invoice.payment_failed":
        for email,ud in u.items():
            if ud.get("stripe_customer_id")==cid:
                print(f"Payment failed for {email}")
                break
    return {"status":"ok"}
