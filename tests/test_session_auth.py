"""Session cookie + Bearer token auth for /auth/me and login."""


def test_login_returns_access_token_and_auth_me_accepts_bearer(client, main):
    email = "session@example.com"
    main.ddb_put_user(email, {
        "name": "Session Test",
        "pw": main._hash_password("TestPassword12!"),
        "tok": "legacy",
        "plan": "enterprise",
        "verified": True,
    })

    r = client.post(
        "/auth/login",
        json={"email": email, "password": "TestPassword12!"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get("access_token")
    assert data.get("plan") == "enterprise"

    # Bearer fallback when cookie is not sent (cross-origin SPA case).
    client.cookies.clear()
    me = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["plan"] == "enterprise"
    assert me.json()["email"] == email


def test_auth_me_401_without_credential(client, main):
    assert client.get("/auth/me").status_code == 401
