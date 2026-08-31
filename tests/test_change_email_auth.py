"""S1 — change-email must bind to the session, not the request body."""


def _mk_user(main, email, **extra):
    rec = {
        "name": "Test",
        "pw": main._hash_password("pw123456"),
        "tok": "tok_" + email,
        "plan": "starter",
        "stripe_customer_id": "",
        "verified": True,
    }
    rec.update(extra)
    main.ddb_put_user(email, rec)


def _auth(client, main, email):
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


def test_change_email_requires_session(client, main):
    r = client.post("/auth/change-email", json={"new_email": "new@example.com"})
    assert r.status_code == 401, r.text


def test_change_email_ignores_body_email_cross_account(client, main, monkeypatch):
    """Session identity wins; a body email for another account must not be honored."""
    user_a = "owner@example.com"
    user_b = "victim@example.com"
    _mk_user(main, user_a)
    _mk_user(main, user_b)
    _auth(client, main, user_a)
    monkeypatch.setattr(main, "_send_verification_email", lambda *args: None)

    # SECURITY FIX (fresh-pass audit, Aug 2026): change-email now requires
    # re-proof of the current credential -- see change_email() in main.py.
    # user_a's password is "pw123456" (set by _mk_user's default).
    r = client.post(
        "/auth/change-email",
        json={"email": user_b, "new_email": "new@example.com", "password": "pw123456"},
    )
    assert r.status_code == 200, r.text
    assert main.ddb_get_user(user_b) is not None
    assert main.ddb_get_user(user_a) is None
    assert main.ddb_get_user("new@example.com") is not None


def test_change_email_own_account_reverifies_and_refreshes_session(client, main, monkeypatch):
    old = "user@example.com"
    new = "newaddr@example.com"
    _mk_user(main, old)
    _auth(client, main, old)
    monkeypatch.setattr(main, "_send_verification_email", lambda *args: None)

    # SECURITY FIX (fresh-pass audit, Aug 2026): re-proof required -- see above.
    r = client.post("/auth/change-email", json={"new_email": new, "password": "pw123456"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["email"] == new

    moved = main.ddb_get_user(new)
    assert moved is not None
    assert moved.get("verified") is False
    assert moved.get("verify_tok")
    assert main.ddb_get_user(old) is None

    # Session cookie is re-issued for the new address (secure cookie; set explicitly for TestClient).
    new_session = r.cookies.get(main.SESSION_COOKIE)
    assert new_session
    client.cookies.set(main.SESSION_COOKIE, new_session)
    me = client.get("/auth/me")
    assert me.status_code == 200, me.text
    assert me.json()["email"] == new
