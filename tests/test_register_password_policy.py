"""SECURITY FIX regression tests (fresh-pass audit, Aug 2026).

/auth/reset-password has always enforced a 12-128 character password length,
but /auth/register never did — any password, including a 1-character one, was
accepted at signup. These tests pin the new /auth/register check and confirm
it doesn't disturb valid registrations or the reset-password endpoint's
existing behavior.
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    # /auth/register is rate-limited (3/minute) — reset between tests so this
    # file's own requests don't trip the limiter against each other.
    main.limiter.reset()
    yield
    main.limiter.reset()


def _reg_payload(password, email="newuser@example.com"):
    return {
        "name": "New User",
        "email": email,
        "password": password,
        "plan": "starter",
        "billing": "monthly",
    }


def test_register_rejects_password_below_12_chars(client):
    resp = client.post("/auth/register", json=_reg_payload("short1!"))
    assert resp.status_code == 400
    assert "12 and 128" in resp.json()["detail"]


def test_register_rejects_empty_password(client):
    resp = client.post("/auth/register", json=_reg_payload(""))
    assert resp.status_code == 400
    assert "12 and 128" in resp.json()["detail"]


def test_register_rejects_password_above_128_chars(client):
    resp = client.post("/auth/register", json=_reg_payload("a" * 129))
    assert resp.status_code == 400
    assert "12 and 128" in resp.json()["detail"]


def test_register_accepts_password_within_range(client, main):
    resp = client.post("/auth/register", json=_reg_payload("a-valid-password-123"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["email"] == "newuser@example.com"


def test_register_password_check_runs_before_duplicate_email_check(client):
    # A weak password on an email that isn't registered yet should fail on the
    # password rule, not fall through to a different code path.
    resp = client.post("/auth/register", json=_reg_payload("x", email="brandnew@example.com"))
    assert resp.status_code == 400
    assert "12 and 128" in resp.json()["detail"]
