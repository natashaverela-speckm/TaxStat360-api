"""Single plan: retired tier names and admin accounts read as 'pro' everywhere."""
import pytest

from tests.test_pdf_text_gate import _session_pro


@pytest.fixture(autouse=True)
def _fresh_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _put(main, email, plan):
    main.ddb_put_user(email, {"name": "T", "pw": main._hash_password("TestPassword12!"), "tok": "tok_" + email, "plan": plan, "verified": True})


@pytest.mark.parametrize("plan", ["professional", "enterprise", "Enterprise", "expert", "elite", "essential", "pro"])
def test_legacy_tier_names_pass_the_paid_gate(client, main, plan):
    email = f"legacy-{plan.lower()}@example.com"
    _put(main, email, plan)
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": "Form 1040 wages 180000 total tax 43199 agi 262000 withheld 20000"})
    assert r.status_code == 200, r.text
    assert main._effective_plan(main.ddb_get_user(email), email) == "pro"


def test_starter_and_unknown_names_stay_refused(client, main):
    for plan in ("starter", "", "free", None):
        email = f"np-{plan or 'none'}@example.com"
        _put(main, email, plan)
        client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
        r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": "Form 1040 wages 180000 total tax 43199"})
        assert r.status_code == 403


def test_admin_account_is_pro_whatever_the_record_says(client, main, monkeypatch):
    email = "admin@taxstat360.com"
    monkeypatch.setattr(main, "ADMIN_EMAILS", {email})
    _put(main, email, "starter")
    assert main._effective_plan(main.ddb_get_user(email), email) == "pro"
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    r = client.get("/me") if any(getattr(rt, "path", "") == "/me" for rt in main.app.routes) else None
    if r is not None and r.status_code == 200:
        assert r.json().get("plan") == "pro"


def test_login_rewrites_a_legacy_plan_to_pro(client, main):
    email = "migrate@example.com"
    _put(main, email, "enterprise")
    r = client.post("/auth/login", json={"email": email, "password": "TestPassword12!"})
    assert r.status_code == 200, r.text
    assert r.json().get("plan") == "pro"
    assert main.ddb_get_user(email)["plan"] == "pro"
