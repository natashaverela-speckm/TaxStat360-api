"""Stripe webhook — always 200 after verify, direct customer lookup (no full-table scan)."""
import json
from unittest.mock import patch

import pytest


def _mk_user(main, email, **extra):
    rec = {
        "name": "Webhook Test",
        "pw": main._hash_password("pw123456"),
        "tok": "tok_" + email,
        "plan": "starter",
        "stripe_customer_id": "",
    }
    rec.update(extra)
    main.ddb_put_user(email, rec)


def _webhook_event(etype, customer, **obj_extra):
    obj = {"customer": customer, **obj_extra}
    return {
        "id": "evt_test",
        "type": etype,
        "data": {"object": obj},
    }


def test_subscription_updated_sets_plan_via_gsi(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    _mk_user(main, "sub@example.com", stripe_customer_id="cus_webhook_1", plan="starter")
    pro_monthly = main.PRICE_IDS["professional"]["monthly"]
    event = _webhook_event(
        "customer.subscription.updated",
        "cus_webhook_1",
        status="active",
        items={"data": [{"price": {"id": pro_monthly}}]},
    )
    r = client.post(
        "/stripe/webhook",
        content=json.dumps(event),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert main.ddb_get_user("sub@example.com")["plan"] == "professional"


def test_subscription_deleted_downgrades_to_starter(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    _mk_user(
        main,
        "gone@example.com",
        stripe_customer_id="cus_webhook_2",
        plan="enterprise",
    )
    event = _webhook_event("customer.subscription.deleted", "cus_webhook_2")
    r = client.post("/stripe/webhook", content=json.dumps(event))
    assert r.status_code == 200
    assert main.ddb_get_user("gone@example.com")["plan"] == "starter"


def test_webhook_with_secret_processes_payload_not_stripe_object(client, main, monkeypatch):
    """With a webhook secret set, we must process the plain-dict payload, not the
    StripeObject from construct_event (whose .get() raises AttributeError)."""
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "whsec_test")

    class _GetHostile:
        # Mimics stripe StripeObject: attribute access for "get" raises.
        def get(self, *a, **k):
            raise AttributeError("get")

    monkeypatch.setattr(
        main.stripe.Webhook, "construct_event", lambda *a, **k: _GetHostile()
    )
    _mk_user(main, "sec@example.com", stripe_customer_id="cus_sec", plan="enterprise")
    event = _webhook_event("customer.subscription.deleted", "cus_sec")
    r = client.post(
        "/stripe/webhook",
        content=json.dumps(event),
        headers={"Stripe-Signature": "t=1,v1=deadbeef"},
    )
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert main.ddb_get_user("sec@example.com")["plan"] == "starter"


def test_webhook_bad_signature_returns_400(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "whsec_test")

    def _raise(*a, **k):
        raise main.stripe.error.SignatureVerificationError("bad", "sig")

    monkeypatch.setattr(main.stripe.Webhook, "construct_event", _raise)
    event = _webhook_event("customer.subscription.deleted", "cus_x")
    r = client.post(
        "/stripe/webhook",
        content=json.dumps(event),
        headers={"Stripe-Signature": "t=1,v1=bad"},
    )
    assert r.status_code == 400


def test_subscription_deleted_missing_user_returns_200(client, main, monkeypatch):
    """Cancellation after the account was already deleted must not 500."""
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    # No user with this customer id exists (record already removed).
    event = _webhook_event("customer.subscription.deleted", "cus_ghost")
    r = client.post("/stripe/webhook", content=json.dumps(event))
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_subscription_deleted_null_data_object_returns_200(client, main, monkeypatch):
    """A malformed cancellation payload (null data/object) must not 500."""
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    event = {"id": "evt_null", "type": "customer.subscription.deleted", "data": None}
    r = client.post("/stripe/webhook", content=json.dumps(event))
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_processing_failure_still_returns_200(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    _mk_user(main, "fail@example.com", stripe_customer_id="cus_webhook_3")
    event = _webhook_event(
        "customer.subscription.deleted",
        "cus_webhook_3",
    )

    def _boom(*_a, **_k):
        raise RuntimeError("simulated DynamoDB throttle")

    monkeypatch.setattr(main, "_ddb_update_user_plan", _boom)
    r = client.post("/stripe/webhook", content=json.dumps(event))
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert main.ddb_get_user("fail@example.com")["plan"] == "starter"


def test_plan_update_uses_gsi_not_full_scan(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    _mk_user(main, "gsi@example.com", stripe_customer_id="cus_gsi", plan="starter")

    with patch.object(main, "ddb_all_users") as scan:
        main._ddb_update_user_plan("cus_gsi", "professional")
        scan.assert_not_called()

    assert main.ddb_get_user("gsi@example.com")["plan"] == "professional"


def test_invoice_payment_failed_returns_200(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_SECRET", "")
    _mk_user(main, "inv@example.com", stripe_customer_id="cus_inv")
    event = _webhook_event("invoice.payment_failed", "cus_inv")
    with patch.object(main, "ddb_all_users") as scan:
        r = client.post("/stripe/webhook", content=json.dumps(event))
        scan.assert_not_called()
    assert r.status_code == 200
