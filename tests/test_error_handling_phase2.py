"""Phase 2 (F7/F8) — error-handling and OAuth env characterization tests."""
from unittest.mock import patch

import stripe


def _mk_user(main, email):
    main.ddb_put_user(
        email,
        {
            "name": "Phase2 Test",
            "pw": main._hash_password("TestPassword123!"),
            "tok": "tok_" + email,
            "plan": "starter",
            "stripe_customer_id": "",
            "verified": True,
        },
    )


def _auth(client, main, email):
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


def test_subscribe_missing_user_returns_404_not_400(client, main):
    """HTTPException(404) must not be swallowed by a broad except -> 400."""
    email = "missing-user-404@test.com"
    _mk_user(main, email)
    _auth(client, main, email)
    with patch("app.main.load", return_value={}):
        r = client.post(
            "/stripe/subscribe",
            json={
                "email": email,
                "plan": "professional",
                "payment_method_id": "pm_card_visa",
                "billing": "monthly",
            },
        )
    assert r.status_code == 404, r.text
    assert r.json()["detail"] == "User not found"


def test_subscribe_stripe_error_does_not_leak_exception_text(client, main):
    email = "stripe-err@test.com"
    _mk_user(main, email)
    _auth(client, main, email)
    with patch("app.main.stripe.PaymentMethod.attach") as attach:
        attach.side_effect = stripe.error.CardError(
            message="Your card was declined.",
            param="number",
            code="card_declined",
        )
        r = client.post(
            "/stripe/subscribe",
            json={
                "email": email,
                "plan": "professional",
                "payment_method_id": "pm_card_visa",
                "billing": "monthly",
            },
        )
    assert r.status_code == 400
    body = r.json()["detail"]
    assert "declined" not in body.lower()
    assert body == "Payment request could not be completed. Please try again."


def test_setup_intent_stripe_error_uses_generic_message(client):
    with patch("app.main.stripe.SetupIntent.create") as create:
        create.side_effect = stripe.error.InvalidRequestError("bad request", param="x")
        r = client.post("/stripe/setup-intent")
    assert r.status_code == 400
    assert r.json()["detail"] == "Payment request could not be completed. Please try again."
    assert "bad request" not in r.json()["detail"]


def test_webhook_invalid_signature_generic_message(client):
    with patch("app.main.WEBHOOK_SECRET", "whsec_test"):
        with patch("app.main.stripe.Webhook.construct_event") as construct:
            construct.side_effect = stripe.error.SignatureVerificationError(
                "bad sig", sig_header="t=1"
            )
            r = client.post(
                "/stripe/webhook",
                data=b"{}",
                headers={"stripe-signature": "t=1,v1=bad"},
            )
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid webhook signature"
    assert "bad sig" not in r.json()["detail"]


def test_oauth_connect_requires_env_client_id(client, monkeypatch):
    monkeypatch.delenv("QUICKBOOKS_CLIENT_ID", raising=False)
    r = client.get("/integrations/quickbooks/connect", follow_redirects=False)
    assert r.status_code == 503
    assert "not configured" in r.json()["detail"].lower()


def test_oauth_connect_uses_env_client_id(client):
    r = client.get("/integrations/quickbooks/connect", follow_redirects=False)
    assert r.status_code in (302, 307)
    loc = r.headers.get("location", "")
    assert "client_id=qb-test-client-id" in loc
    assert "AB1FhVS3wJV2oOLUXNS8ZlnCHuUFW3XTM20rOydbCln0Pj1vZG" not in loc
