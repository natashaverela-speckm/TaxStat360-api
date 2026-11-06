"""Regression tests for the "fix everything" cleanup round (Aug 2026).

Confirms the removed legacy Bearer-token auth subsystem (get_user_from_token,
require_plan, /user/me, /user/business-info) is actually gone, and that email
fields now reject malformed input at the API boundary (EmailStr).
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def test_user_me_route_no_longer_exists(client, main):
    resp = client.get("/user/me")
    assert resp.status_code == 404


def test_user_business_info_route_no_longer_exists(client, main):
    resp = client.post("/user/business-info")
    assert resp.status_code == 404


def test_get_user_from_token_symbol_removed(main):
    assert not hasattr(main, "get_user_from_token")


def test_require_plan_symbol_removed(main):
    assert not hasattr(main, "require_plan")


def test_single_plan_model(main):
    # PHASE 1b (Nov 2026): one plan. The tiered guard is gone with the tiers.
    assert main.PLAN_ORDER == ["starter", "pro"]
    assert not hasattr(main, "_require_minimum_plan")
    assert not hasattr(main, "LEGACY_PRICE_IDS")


def test_register_rejects_malformed_email(client, main):
    resp = client.post("/auth/register", json={
        "name": "Bad Email", "email": "not-an-email", "password": "a-valid-password-123",
    })
    assert resp.status_code == 422


def test_register_accepts_well_formed_email(client, main):
    resp = client.post("/auth/register", json={
        "name": "Good Email", "email": "good-email@example.com", "password": "a-valid-password-123",
    })
    assert resp.status_code == 200, resp.text
