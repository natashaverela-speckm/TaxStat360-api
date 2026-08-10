"""SECURITY FIX regression tests ("fix everything" round, Aug 2026).

/auth/change-email used to require nothing beyond a valid session cookie --
an account-takeover primitive when combined with forgot-password. Now
requires the current password (or the current MFA code, if 2FA is enabled)
before an email change is accepted.
"""
import pyotp
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _login_client(client, main, email, password="a-valid-password-123", **extra):
    rec = {
        "name": "Test", "pw": main._hash_password(password),
        "verified": True, "plan": "starter",
    }
    rec.update(extra)
    main.ddb_put_user(email, rec)
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def test_change_email_without_password_is_rejected(client, main):
    email = _login_client(client, main, "no-pw-reauth@example.com")
    resp = client.post("/auth/change-email", json={"new_email": "new1@example.com"})
    assert resp.status_code == 401
    assert main.ddb_get_user(email) is not None
    assert main.ddb_get_user("new1@example.com") is None


def test_change_email_with_wrong_password_is_rejected(client, main):
    _login_client(client, main, "wrong-pw-reauth@example.com")
    resp = client.post(
        "/auth/change-email",
        json={"new_email": "new2@example.com", "password": "totally-wrong-password"},
    )
    assert resp.status_code == 401


def test_change_email_with_correct_password_succeeds(client, main, monkeypatch):
    monkeypatch.setattr(main, "_send_verification_email", lambda *args: None)
    _login_client(client, main, "correct-pw-reauth@example.com")
    resp = client.post(
        "/auth/change-email",
        json={"new_email": "new3@example.com", "password": "a-valid-password-123"},
    )
    assert resp.status_code == 200, resp.text
    assert main.ddb_get_user("new3@example.com") is not None


def test_change_email_with_mfa_enabled_requires_code_not_password(client, main, monkeypatch):
    monkeypatch.setattr(main, "_send_verification_email", lambda *args: None)
    secret = pyotp.random_base32()
    email = _login_client(
        client, main, "mfa-reauth@example.com",
        mfa_enabled=True, mfa_secret_enc=main._mfa_encrypt(secret),
    )
    # Password alone must NOT be enough once MFA is enabled.
    resp = client.post(
        "/auth/change-email",
        json={"new_email": "new4@example.com", "password": "a-valid-password-123"},
    )
    assert resp.status_code == 401

    code = pyotp.TOTP(secret).now()
    resp2 = client.post(
        "/auth/change-email",
        json={"new_email": "new4@example.com", "mfa_code": code},
    )
    assert resp2.status_code == 200, resp2.text
    assert main.ddb_get_user("new4@example.com") is not None
