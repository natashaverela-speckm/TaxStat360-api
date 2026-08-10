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


# ─── Fail-closed SECRET_KEY (security fix, Aug 2026) ──────────────────────────
# Regression guard: SECRET_KEY signs every session cookie (_make_session /
# _verify_session) and derives the Fernet key that encrypts MFA/TOTP secrets
# (_mfa_fernet). A missing env var must block startup instead of silently
# falling back to the hardcoded "change-me-in-env" literal — see the module
# comment above `_resolve_secret_key` in app/main.py for the full rationale.
# Unconditional, same as STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET: no
# environment-based carve-out. The test harness (conftest.py) supplies a
# dummy SECRET_KEY up front, same as it already does for the other two.


def test_missing_secret_key_raises(main, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    import pytest as _pytest

    with _pytest.raises(RuntimeError, match="SECRET_KEY"):
        main._resolve_secret_key()


def test_blank_secret_key_raises(main, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "")
    import pytest as _pytest

    with _pytest.raises(RuntimeError, match="SECRET_KEY"):
        main._resolve_secret_key()


def test_present_secret_key_is_returned(main, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "a-real-secret")
    assert main._resolve_secret_key() == "a-real-secret"


def test_module_level_secret_key_matches_test_harness_value(main):
    """conftest.py sets SECRET_KEY before app.main is imported, so the
    module-level SECRET_KEY populated at import time should reflect it —
    confirms the fail-closed check runs at import, not just when called
    directly."""
    assert main.SECRET_KEY == "test-secret"


def test_secret_key_no_longer_falls_back_to_known_literal(main):
    """The old insecure default must not still be reachable anywhere a real
    key was expected — pins the fix so it can't silently regress."""
    assert main.SECRET_KEY != "change-me-in-env"
