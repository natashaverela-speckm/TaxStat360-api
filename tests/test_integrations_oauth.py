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


def test_connect_unauthenticated_redirects_to_login(client):
    r = client.get("/integrations/quickbooks/connect", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "/login" in r.headers.get("location", "")


def test_status_empty_when_no_tokens(client, main):
    email = "status-empty@example.com"
    _mk_user(main, email)
    _auth(client, main, email)
    r = client.get("/integrations/status")
    assert r.status_code == 200
    body = r.json()
    for p in ("quickbooks", "xero", "wave", "freshbooks"):
        assert body[p]["connected"] is False


def test_callback_persists_token_and_data_uses_session(client, main, monkeypatch):
    email = "qb-cb@example.com"
    _mk_user(main, email)
    state = main._sign_oauth_state(email, "0")

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
    assert "qb_token=" not in loc
    assert "quickbooks_token=" not in loc

    user = main.ddb_get_user(email)
    assert main._provider_connected(user, "quickbooks")
    creds = main._load_provider_creds(user, "quickbooks")
    assert creds["access_token"] == "at_live_test"
    assert creds["realm_id"] == "12345"

    _auth(client, main, email)
    status = client.get("/integrations/status")
    assert status.json()["quickbooks"]["connected"] is True

    with patch.object(main.requests, "get") as get:
        get.return_value.ok = True
        get.return_value.json.return_value = {
            "Rows": {
                "Row": [
                    {
                        "group": "Income",
                        "Summary": {"ColData": [{"value": ""}, {"value": "1000.00"}]},
                    },
                    {
                        "group": "Expenses",
                        "Summary": {"ColData": [{"value": ""}, {"value": "400.00"}]},
                    },
                ]
            }
        }
        # Parser may not use that shape — stub _parse_qb_pnl instead for stability.
    with patch.object(main, "_parse_qb_pnl", return_value=(1000.0, 400.0, 600.0)):
        with patch.object(main.requests, "get") as get:
            get.return_value.ok = True
            get.return_value.json.return_value = {}
            data = client.get("/integrations/quickbooks/data?year=2026")
    assert data.status_code == 200, data.text
    body = data.json()
    assert body["revenue"] == 1000.0
    assert body["expenses"] == 400.0


def test_data_missing_token_returns_401(client, main):
    email = "qb-missing@example.com"
    _mk_user(main, email)
    _auth(client, main, email)
    r = client.get("/integrations/quickbooks/data?year=2026")
    assert r.status_code == 401
    assert r.json()["detail"] == "missing token"


def test_disconnect_clears_token(client, main):
    email = "qb-disc@example.com"
    _mk_user(main, email)
    user = main.ddb_get_user(email)
    main._save_provider_creds(
        email,
        user,
        "quickbooks",
        access_token="at_x",
        realm_id="99",
    )
    _auth(client, main, email)
    assert client.get("/integrations/status").json()["quickbooks"]["connected"] is True
    r = client.post("/integrations/quickbooks/disconnect")
    assert r.status_code == 200
    assert client.get("/integrations/status").json()["quickbooks"]["connected"] is False
    assert client.get("/integrations/quickbooks/data").status_code == 401


def test_callback_bad_state_without_session_errors(client, main, monkeypatch):
    monkeypatch.setattr(
        main,
        "_exchange_oauth_code",
        lambda p, code: {"access_token": "should_not_store"},
    )
    r = client.get(
        "/integrations/quickbooks/callback",
        params={"code": "authcode", "state": "bogus", "realmId": "1"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 307)
    assert "reason=not_authenticated" in r.headers.get("location", "")
