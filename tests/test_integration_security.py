"""Audit P0-#1 — integration credential security.

These tests lock in the fix so the holes cannot be reintroduced:

  1. /docs, /redoc and /openapi.json are not served in production.
  2. /integrations/{p}/data requires a session (it was fully unauthenticated).
  3. /integrations/{p}/data no longer accepts a token via the query string, and
     cannot be driven by one.
  4. The OAuth callback stores tokens server-side and the redirect back to the
     browser carries NO access token and NO refresh token.
  5. The OAuth state is signed: a forged/absent/stale state is refused, so one
     user's callback cannot attach tokens to another user's account.
  6. Provider credentials are never exposed by /integrations/status.
"""
import time
from unittest.mock import patch


def _mk_user(main, email):
    main.ddb_put_user(
        email,
        {
            "name": "Sec Test",
            "pw": main._hash_password("TestPassword123!"),
            "tok": "tok_" + email,
            "plan": "professional",
            "stripe_customer_id": "",
            "verified": True,
        },
    )


def _auth(client, main, email="sec@example.com"):
    _mk_user(main, email)
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


# --------------------------------------------------------------- 1. docs closed
def test_openapi_docs_are_not_served_in_production(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, f"{path} must not be public"


def test_docs_can_be_enabled_for_local_dev(main):
    assert main._DOCS_ENABLED is False, "default env must fail closed (docs off)"


# ------------------------------------------------- 2/3. /data requires a session
def test_integration_data_requires_authentication(client):
    r = client.get("/integrations/quickbooks/data?year=2026")
    assert r.status_code == 401


def test_integration_data_ignores_token_in_query_string(client, main):
    """The pre-fix exploit: pass someone's token in the URL and read their books.

    The parameter is gone, so a caller supplying one is simply missing credentials.
    """
    _auth(client, main)
    r = client.get(
        "/integrations/quickbooks/data"
        "?year=2026&token=stolen-access-token&realm=123&refresh_token=stolen-refresh"
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "missing token"


def test_integration_data_reads_credentials_from_the_user_record(client, main):
    email = _auth(client, main)
    main._integration_creds_save(
        email, "quickbooks", access_token="real-token", realm_id="realm-1"
    )

    with patch.object(main, "requests") as req:
        req.get.return_value.ok = True
        req.get.return_value.json.return_value = {}
        client.get("/integrations/quickbooks/data?year=2026")

    # The token reached QuickBooks in the Authorization header, sourced from the
    # user's record — not from anything the caller supplied.
    _, kwargs = req.get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer real-token"


# -------------------------------------- 4. callback leaks nothing to the browser
def test_oauth_callback_persists_tokens_and_leaks_none_to_the_browser(client, main):
    email = _auth(client, main)
    state = main._make_oauth_state(email, "0")

    with patch.object(main, "_exchange_oauth_code") as ex:
        ex.return_value = {
            "access_token": "ACCESS-SECRET",
            "refresh_token": "REFRESH-SECRET",
        }
        r = client.get(
            f"/integrations/quickbooks/callback?code=abc&state={state}&realmId=r1",
            follow_redirects=False,
        )

    loc = r.headers.get("location", "")
    assert "quickbooks=connected" in loc
    # The whole point: no credential may appear in the redirect URL.
    assert "ACCESS-SECRET" not in loc
    assert "REFRESH-SECRET" not in loc
    assert "token" not in loc.lower()

    creds = main._integration_creds_get(email, "quickbooks")
    assert creds["access_token"] == "ACCESS-SECRET"
    assert creds["refresh_token"] == "REFRESH-SECRET"
    assert creds["realm_id"] == "r1"


# ------------------------------------------------------- 5. state must be signed
def test_oauth_callback_rejects_a_forged_state(client, main):
    _auth(client, main)
    r = client.get(
        "/integrations/quickbooks/callback?code=abc&state=victim@example.com|0|123",
        follow_redirects=False,
    )
    assert "reason=invalid_state" in r.headers.get("location", "")


def test_oauth_callback_rejects_a_missing_state(client, main):
    _auth(client, main)
    r = client.get(
        "/integrations/quickbooks/callback?code=abc", follow_redirects=False
    )
    assert "reason=invalid_state" in r.headers.get("location", "")


def test_oauth_state_expires(main):
    email = "sec@example.com"
    state = main._make_oauth_state(email, "0")
    assert main._verify_oauth_state(state) == (email, "0")

    with patch.object(main.time, "time", return_value=time.time() + main.OAUTH_STATE_MAX_AGE + 60):
        assert main._verify_oauth_state(state) == (None, "0")


def test_oauth_state_is_tamper_evident(main):
    state = main._make_oauth_state("victim@example.com", "0")
    assert main._verify_oauth_state(state + "x") == (None, "0")


# ------------------------------------------------ 6. status exposes no secrets
def test_integration_status_never_returns_credentials(client, main):
    email = _auth(client, main)
    main._integration_creds_save(
        email, "xero", access_token="ACCESS-SECRET", refresh_token="REFRESH-SECRET"
    )

    r = client.get("/integrations/status")
    assert r.status_code == 200
    body = r.json()
    assert body["xero"]["connected"] is True
    assert body["quickbooks"]["connected"] is False
    assert "ACCESS-SECRET" not in r.text
    assert "REFRESH-SECRET" not in r.text


def test_integration_status_requires_authentication(client):
    assert client.get("/integrations/status").status_code == 401


def test_disconnect_clears_stored_credentials(client, main):
    email = _auth(client, main)
    main._integration_creds_save(email, "xero", access_token="ACCESS-SECRET")

    r = client.post("/integrations/xero/disconnect")
    assert r.status_code == 200
    assert main._integration_creds_get(email, "xero") == {}


# ------------------------------------- /auth/me no longer takes a URL credential
def test_auth_me_rejects_token_in_query_string(client, main):
    email = "sec@example.com"
    _mk_user(main, email)
    # The pre-fix call shape: /auth/me?token=<session token>. The param is gone, so
    # with no cookie and no header this is simply unauthenticated.
    r = client.get("/auth/me?token=tok_" + email)
    assert r.status_code == 401
