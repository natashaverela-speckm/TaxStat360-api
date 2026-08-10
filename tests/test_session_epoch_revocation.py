"""H-1 (fresh-pass audit, Aug 2026) — password reset must revoke existing
sessions.

Contract: every session token embeds the user's session_epoch at issue time
(_make_session). Resetting a password bumps session_epoch (reset_password),
so any token issued before the reset stops validating the moment the epoch
changes -- closing the gap where a stolen session survived its own
account's password reset."""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _register_and_login(client, main, email="epoch-test@example.com", password="TestPassword12!"):
    main.ddb_put_user(email, {
        "name": "Epoch Test",
        "pw": main._hash_password(password),
        "plan": "starter",
        "verified": True,
        "session_epoch": 0,
    })
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_old_session_rejected_after_password_reset(client, main):
    email = "epoch-reset@example.com"
    old_password = "TestPassword12!"
    token = _register_and_login(client, main, email, old_password)

    # The token is valid before any reset.
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == email

    # Directly bump session_epoch the same way reset_password does, instead of
    # exercising the full email-token reset flow (which needs a real mailer).
    rec = main.ddb_get_user(email)
    rec["session_epoch"] = int(rec.get("session_epoch", 0)) + 1
    main.ddb_put_user(email, rec)

    # The pre-reset token must now be dead.
    me2 = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me2.status_code == 401, me2.text


def test_reset_password_endpoint_bumps_epoch_and_kills_old_sessions(client, main):
    email = "epoch-full-flow@example.com"
    old_password = "TestPassword12!"
    new_password = "BrandNewPassword99!"
    token = _register_and_login(client, main, email, old_password)

    rec = main.ddb_get_user(email)
    assert int(rec.get("session_epoch", 0)) == 0
    reset_tok = "a" * 64
    rec["reset_tok"] = reset_tok
    rec["reset_exp"] = int(__import__("time").time()) + 3600
    main.ddb_put_user(email, rec)

    r = client.post(
        "/auth/reset-password",
        json={"email": email, "token": reset_tok, "new_password": new_password},
    )
    assert r.status_code == 200, r.text

    updated = main.ddb_get_user(email)
    assert int(updated.get("session_epoch", 0)) == 1

    # The session token issued before the reset must no longer authenticate.
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 401, me.text

    # A fresh login with the NEW password gets a token that works.
    login2 = client.post("/auth/login", json={"email": email, "password": new_password})
    assert login2.status_code == 200
    new_token = login2.json()["access_token"]
    me2 = client.get("/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me2.status_code == 200
    assert me2.json()["email"] == email


def test_legacy_three_part_session_token_still_works_pre_reset(client, main):
    """Sessions issued by the OLD format (email:ts:nonce, no embedded epoch)
    must keep working immediately after this fix ships -- they're treated as
    epoch 0, matching every account's epoch until that account's first reset."""
    import base64
    import hmac
    import hashlib
    import secrets
    import time as _time

    email = "legacy-token@example.com"
    main.ddb_put_user(email, {
        "name": "Legacy",
        "pw": main._hash_password("TestPassword12!"),
        "plan": "starter",
        "verified": True,
        "session_epoch": 0,
    })
    payload = f"{email}:{int(_time.time())}:{secrets.token_hex(16)}"
    sig = hmac.new(main.SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    legacy_token = base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {legacy_token}"})
    assert me.status_code == 200, me.text
    assert me.json()["email"] == email

    # Once the epoch bumps (any reset), the legacy-format token must also die.
    rec = main.ddb_get_user(email)
    rec["session_epoch"] = 1
    main.ddb_put_user(email, rec)
    me2 = client.get("/auth/me", headers={"Authorization": f"Bearer {legacy_token}"})
    assert me2.status_code == 401
