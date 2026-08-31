"""SECURITY FIX regression tests ("fix everything" round, Aug 2026).

/auth/verification-status and /auth/resend-verification were previously
unrated (enumeration/email-bombing risk); /stripe/setup-intent was previously
unrated too (must stay UNAUTHENTICATED -- it's called before the account
exists, mid sign-up -- but a rate limit closes the abuse vector without
breaking sign-up).
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def test_verification_status_rate_limit_is_20_per_minute(client, main):
    for _ in range(20):
        resp = client.get("/auth/verification-status", params={"email": "nobody@example.com"})
        assert resp.status_code == 200
    resp = client.get("/auth/verification-status", params={"email": "nobody@example.com"})
    assert resp.status_code == 429


def test_resend_verification_rate_limit_is_3_per_minute(client, main):
    for _ in range(3):
        resp = client.post("/auth/resend-verification", json={"email": "nobody@example.com"})
        assert resp.status_code == 200
    resp = client.post("/auth/resend-verification", json={"email": "nobody@example.com"})
    assert resp.status_code == 429


def test_setup_intent_stays_unauthenticated_but_rate_limited(client, main, monkeypatch):
    # Must NOT require a session -- Onboarding.jsx calls this before /auth/register,
    # i.e. before any session cookie exists.
    class _FakeSetupIntent:
        client_secret = "seti_test_secret"

    monkeypatch.setattr(main.stripe.SetupIntent, "create", lambda **kw: _FakeSetupIntent())
    for _ in range(10):
        resp = client.post("/stripe/setup-intent")
        assert resp.status_code == 200
    resp = client.post("/stripe/setup-intent")
    assert resp.status_code == 429
