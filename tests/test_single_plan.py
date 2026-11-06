"""PHASE 1b (Nov 2026): one live plan ("pro"), env-driven Stripe prices, paid-plan
gates on Aria and the return extract, and Aria's per-user monthly cap."""
import importlib
import os

import pytest


def _session_user(client, main, email, plan):
    main.ddb_put_user(
        email,
        {
            "name": "Plan Test",
            "pw": main._hash_password("TestPassword12!"),
            "tok": "tok_" + email,
            "plan": plan,
            "verified": True,
        },
    )
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


# ── plan model ───────────────────────────────────────────────────────────────

def test_pro_is_a_valid_plan_name_and_has_prices(main):
    assert "pro" in main.VALID_PLANS
    assert main.PRICE_IDS["pro"] == {"monthly": "price_test_pro_monthly", "annual": "price_test_pro_annual"}
    assert main.PLAN_PRICES["pro"]["label"]
    assert main.PLAN_PRICES["pro"]["annual_total"] > main.PLAN_PRICES["pro"]["monthly"]
    assert main.FULL_ACCESS_PLANS == frozenset({"pro"})
    assert main.VALID_PLANS == {"starter", "pro"}


def test_retired_tiers_are_gone(main):
    # Pre-launch, no subscribers: the three old tiers and their Stripe prices are removed.
    for plan in ("professional", "enterprise"):
        assert plan not in main.PLAN_PRICES
        assert plan not in main.VALID_PLANS
    assert "price_1TJ" not in open(main.__file__).read()


def test_nothing_purchasable_until_price_ids_configured(client, main, monkeypatch):
    # With STRIPE_PRICE_PRO_* unset, PRICE_IDS is empty and subscribe refuses with
    # 503 rather than charging a fallback price.
    monkeypatch.setattr(main, "PRICE_IDS", {})
    _session_user(client, main, "buyer@example.com", "starter")
    r = client.post("/stripe/subscribe", json={"email": "buyer@example.com", "plan": "pro", "payment_method_id": "pm_x", "billing": "annual"})
    assert r.status_code == 503
    assert "not available" in r.json()["detail"]


def test_pro_price_ids_come_from_env(monkeypatch):
    monkeypatch.setenv("STRIPE_PRICE_PRO_MONTHLY", "price_pro_m")
    monkeypatch.setenv("STRIPE_PRICE_PRO_ANNUAL", "price_pro_a")
    monkeypatch.setenv("PRO_PRICE_MONTHLY", "41")
    monkeypatch.setenv("PRO_PRICE_ANNUAL", "411")
    import app.main as m
    m2 = importlib.reload(m)
    try:
        assert m2.PRO_PRICE_CONFIGURED is True
        assert m2.PRICE_IDS["pro"] == {"monthly": "price_pro_m", "annual": "price_pro_a"}
        assert m2.PLAN_PRICES["pro"]["monthly"] == 41
        assert m2.PLAN_PRICES["pro"]["annual_total"] == 411
    finally:
        monkeypatch.setenv("STRIPE_PRICE_PRO_MONTHLY", "price_test_pro_monthly")
        monkeypatch.setenv("STRIPE_PRICE_PRO_ANNUAL", "price_test_pro_annual")
        monkeypatch.delenv("PRO_PRICE_MONTHLY")
        monkeypatch.delenv("PRO_PRICE_ANNUAL")
        importlib.reload(m)


def test_register_accepts_pro_plan_name(client, main):
    r = client.post("/auth/register", json={
        "name": "Pro User", "email": "newpro@example.com",
        "password": "a-valid-password-123", "plan": "pro", "billing": "annual",
    })
    assert r.status_code in (200, 201), r.text
    assert (main.ddb_get_user("newpro@example.com") or {}).get("plan") == "pro"


# ── gates ────────────────────────────────────────────────────────────────────

def test_aria_refuses_starter_and_admits_pro(client, main, monkeypatch):
    monkeypatch.setattr(main, "OPENAI_API_KEY", "")   # 503 after the gate ⇒ the gate passed
    _session_user(client, main, "st@example.com", "starter")
    assert client.post("/aria", json={"messages": []}).status_code == 403
    _session_user(client, main, "pro@example.com", "pro")
    assert client.post("/aria", json={"messages": []}).status_code == 503


def test_extract_refuses_starter_and_admits_pro(client, main):
    _session_user(client, main, "st3@example.com", "starter")
    r = client.post("/extract/tax-1040-carryforward", files={"file": ("x.pdf", b"%PDF-1.4", "application/pdf")})
    assert r.status_code == 403
    _session_user(client, main, "pro3@example.com", "pro")
    r = client.post("/extract/tax-1040-carryforward", files={"file": ("x.pdf", b"%PDF-1.4", "application/pdf")})
    assert r.status_code != 403   # past the plan gate; the PDF gate decides from here


# ── Aria monthly cap ─────────────────────────────────────────────────────────

class _FakeResp:
    ok = True
    status_code = 200
    text = ""
    def json(self):
        return {"choices": [{"message": {"content": "hi"}}]}


def test_aria_cap_counts_and_blocks(client, main, monkeypatch):
    monkeypatch.setattr(main, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(main, "ARIA_MONTHLY_CAP", 2)
    monkeypatch.setattr(main.requests, "post", lambda *a, **k: _FakeResp())
    _session_user(client, main, "cap@example.com", "pro")
    r1 = client.post("/aria", json={"messages": [{"role": "user", "content": "q"}]})
    assert r1.status_code == 200 and r1.json()["usage"] == {"used": 1, "cap": 2}
    r2 = client.post("/aria", json={"messages": [{"role": "user", "content": "q"}]})
    assert r2.status_code == 200 and r2.json()["usage"]["used"] == 2
    r3 = client.post("/aria", json={"messages": [{"role": "user", "content": "q"}]})
    assert r3.status_code == 429
    assert "resets next month" in r3.json()["detail"]
    # the count lives on the user record under the current month only
    u = main.ddb_get_user("cap@example.com")
    assert u["aria_usage"] == {main._aria_month_key(): 2}


def test_aria_cap_disabled_when_zero(client, main, monkeypatch):
    monkeypatch.setattr(main, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(main, "ARIA_MONTHLY_CAP", 0)
    monkeypatch.setattr(main.requests, "post", lambda *a, **k: _FakeResp())
    _session_user(client, main, "nocap@example.com", "pro")
    r = client.post("/aria", json={"messages": [{"role": "user", "content": "q"}]})
    assert r.status_code == 200 and "usage" not in r.json()
