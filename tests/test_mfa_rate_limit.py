"""SECURITY FIX regression tests (fresh-pass audit, Aug 2026).

/auth/mfa/verify and /auth/mfa/disable checked a 6-digit TOTP code for an
already-authenticated session with no rate limiting — an attacker holding a
stolen session cookie could brute-force the 1,000,000-combination code.
/auth/mfa/challenge (the equivalent check during login) already limited to
10/minute; these tests pin the same limit now applied to verify and disable.
"""
import pyotp
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _login_client(client, main, email="mfa-ratelimit@example.com"):
    main.ddb_put_user(email, {
        "name": "MFA Test", "pw": main._hash_password("a-valid-password-123"),
        "verified": True, "plan": "starter",
    })
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def test_mfa_verify_rate_limit_is_10_per_minute(client, main):
    email = _login_client(client, main)
    secret = pyotp.random_base32()
    x = main.ddb_get_user(email)
    x["mfa_pending_secret_enc"] = main._mfa_encrypt(secret)
    main.ddb_put_user(email, x)

    # Wrong codes deliberately — we're pinning the rate limit, not a successful verify.
    for _ in range(10):
        resp = client.post("/auth/mfa/verify", json={"code": "000000"})
        assert resp.status_code == 401
    resp = client.post("/auth/mfa/verify", json={"code": "000000"})
    assert resp.status_code == 429


def test_mfa_disable_rate_limit_is_10_per_minute(client, main):
    email = _login_client(client, main)
    secret = pyotp.random_base32()
    x = main.ddb_get_user(email)
    x["mfa_enabled"] = True
    x["mfa_secret_enc"] = main._mfa_encrypt(secret)
    main.ddb_put_user(email, x)

    for _ in range(10):
        resp = client.post("/auth/mfa/disable", json={"code": "000000"})
        assert resp.status_code == 401
    resp = client.post("/auth/mfa/disable", json={"code": "000000"})
    assert resp.status_code == 429


def test_mfa_verify_still_succeeds_with_a_correct_code(client, main):
    email = _login_client(client, main, email="mfa-happy-path@example.com")
    secret = pyotp.random_base32()
    x = main.ddb_get_user(email)
    x["mfa_pending_secret_enc"] = main._mfa_encrypt(secret)
    main.ddb_put_user(email, x)

    code = pyotp.TOTP(secret).now()
    resp = client.post("/auth/mfa/verify", json={"code": code})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
