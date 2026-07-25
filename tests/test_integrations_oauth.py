"""Server-side OAuth token storage for accounting integrations (audit P0-#1)."""
from unittest.mock import patch


def _mk_user(main, email, **extra):
    rec = {
        "name": "Integ Test",
        "pw": main._hash_password("TestPassword123!"),
        "tok": "tok_" + email,
        "plan": "professional",
        "verified": True,
    }
    rec.update(extra)
    main.ddb_put_user(email, rec)


def _auth(client, main, email):
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


def test_connect_url_requires_auth(client):
    r = client.get("/integrations/quickbooks/connect-url")
    assert r.status_code == 401


def test_connect_url_returns_signed_authorize_url(client, main):
    email = "qb-connect@example.com"
    _mk_user(main, email)
    _auth(client, main, email)
    r = client.get("/integrations/quickbooks/connect-url?entity=2")
    assert r.status_code == 200, r.text
    url = r.json()["url"]
    assert "appcenter.intuit.com" in url
    assert "client_id=" in url
    assert "state=" in url


def test_data_missing_token_returns_401(client, main):
    email = "qb-missing@example.com"
    _mk_user(main, email)
    _auth(client, main, email)
    r = client.get("/integrations/quickbooks/data?year=2026")
    assert r.status_code == 401
    assert r.json()["detail"] == "missing token"


def test_callback_persists_token_without_url_leak(client, main, monkeypatch):
    email = "qb-cb@example.com"
    _mk_user(main, email)
    state = main._make_oauth_state(email, "0")

    monkeypatch.setattr(
        main,
        "_exchange_oauth_code",
        lambda p, code: {"access_token": "at_live_test", "refresh_token": "rt_test"},
    )

    r = client.get(
        "/integrations/quickbooks/callback",
        params={"code": "authcode", "state": state, "realmId": "12345"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307)
    loc = r.headers.get("location", "")
    assert "quickbooks=connected" in loc
    assert "at_live_test" not in loc
    assert "token" not in loc.lower()

    creds = main._integration_creds_get(email, "quickbooks")
    assert creds["access_token"] == "at_live_test"
    assert creds["realm_id"] == "12345"

    _auth(client, main, email)
    with patch.object(main, "_parse_qb_pnl", return_value=(1000.0, 400.0, 600.0)):
        with patch.object(main.requests, "get") as get:
            get.return_value.ok = True
            get.return_value.json.return_value = {}
            data = client.get("/integrations/quickbooks/data?year=2026")
    assert data.status_code == 200, data.text
    assert data.json()["revenue"] == 1000.0
