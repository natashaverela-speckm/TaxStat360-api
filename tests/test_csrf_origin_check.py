"""SECURITY FIX regression tests ("fix everything" round, Aug 2026).

_csrf_origin_check (main.py) rejects any cookie-authenticated, state-changing
request whose Origin/Referer isn't one of our own origins -- closing the CSRF
gap on PUT /records, POST /integrations/{p}/disconnect, POST /aria, and any
future mutating route, without needing each one to opt in individually.
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _login_client(client, main, email="csrf-test@example.com"):
    main.ddb_put_user(email, {
        "name": "CSRF Test", "pw": main._hash_password("a-valid-password-123"),
        "verified": True, "plan": "starter",
    })
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def test_put_records_blocked_with_no_origin_or_referer(client, main):
    _login_client(client, main)
    # The conftest `client` fixture defaults to a same-site Origin; explicitly
    # clear it here to simulate the "simple request" CSRF pattern (no
    # preflight-triggering headers) a cross-site attacker would send.
    resp = client.put("/records", json={"id": 1, "name": "r1"}, headers={"origin": "", "referer": ""})
    assert resp.status_code == 403


def test_put_records_blocked_with_foreign_origin(client, main):
    _login_client(client, main)
    resp = client.put("/records", json={"id": 2, "name": "r2"}, headers={"origin": "https://evil.example.com"})
    assert resp.status_code == 403


def test_put_records_allowed_with_our_origin(client, main):
    _login_client(client, main)
    resp = client.put("/records", json={"id": 3, "name": "r3"}, headers={"origin": "https://www.taxstat360.com"})
    assert resp.status_code == 200


def test_put_records_allowed_via_referer_fallback(client, main):
    # Some legitimate clients omit Origin but always send Referer; the check
    # must accept either.
    _login_client(client, main)
    resp = client.put(
        "/records", json={"id": 4, "name": "r4"},
        headers={"origin": "", "referer": "https://taxstat360.com/calculate-tax"},
    )
    assert resp.status_code == 200


def test_integration_disconnect_blocked_cross_site(client, main):
    email = _login_client(client, main, email="csrf-integrations@example.com")
    resp = client.post("/integrations/quickbooks/disconnect", headers={"origin": "https://evil.example.com"})
    assert resp.status_code == 403


def test_get_requests_are_never_csrf_checked(client, main):
    # GET must never be blocked by the CSRF check even with no Origin --
    # it should never mutate state, and legitimate top-level navigations/
    # some clients don't send Origin on GET.
    _login_client(client, main)
    resp = client.get("/records", headers={"origin": "", "referer": ""})
    assert resp.status_code == 200


def test_unauthenticated_requests_are_not_csrf_checked(client, main):
    # No session cookie -> nothing to forge -> the check is a no-op. Login
    # itself must keep working with no Origin (e.g. some non-browser clients).
    resp = client.post(
        "/auth/login", json={"email": "nobody@example.com", "password": "wrong"},
        headers={"origin": "", "referer": ""},
    )
    # 401 (invalid credentials), not 403 (CSRF-blocked) -- proves the CSRF
    # check didn't intercept this unauthenticated request.
    assert resp.status_code == 401
