"""Account-deletion endpoint tests.

Covers the four required cases:
  1. owner self-delete
  2. admin deletes a user
  3. non-admin is blocked (403)
  4. idempotent: Stripe customer already gone -> still succeeds
Plus a guard test: an admin can't delete itself via the admin route.
"""


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
    """Attach a valid session cookie for `email` to the test client."""
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


def _put_record(main, email, rid):
    main._records_tbl.put_item(
        Item={"userId": main._norm_email(email), "recordId": rid, "id": rid, "name": "rec"}
    )


def _audits_for(main, email):
    items = main._audit_tbl.scan().get("Items", [])
    return [a for a in items if a.get("target") == main._norm_email(email)]


# 1 ---------------------------------------------------------------------------
def test_owner_self_delete(client, main):
    email = "owner@example.com"
    _mk_user(main, email)
    _put_record(main, email, 1)
    _put_record(main, email, 2)
    _auth(client, main, email)

    r = client.delete("/account")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["deleted"] == email
    assert body["records_deleted"] == 2

    # User and records are gone.
    assert main.ddb_get_user(email) is None
    assert main._ddb_query_records(email) == []

    # Audit trail has a completed entry.
    audits = _audits_for(main, email)
    assert any(a["status"] == "completed" for a in audits)

    # The response clears the session cookie (Set-Cookie with an expiry/empty value).
    set_cookie = r.headers.get("set-cookie", "")
    assert main.SESSION_COOKIE in set_cookie
    assert ('Max-Age=0' in set_cookie) or ('max-age=0' in set_cookie) or (f'{main.SESSION_COOKIE}=;' in set_cookie) or (f'{main.SESSION_COOKIE}=""' in set_cookie)


# 2 ---------------------------------------------------------------------------
def test_admin_deletes_user(client, main):
    admin = "admin@taxstat360.com"
    victim = "victim@example.com"
    _mk_user(main, admin)
    _mk_user(main, victim)
    _put_record(main, victim, 7)
    _auth(client, main, admin)

    r = client.delete(f"/admin/users/{victim}")
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] == victim

    assert main.ddb_get_user(victim) is None
    assert main._ddb_query_records(victim) == []
    # The admin's own account is untouched.
    assert main.ddb_get_user(admin) is not None


# 3 ---------------------------------------------------------------------------
def test_non_admin_blocked(client, main):
    user = "user@example.com"
    victim = "victim@example.com"
    _mk_user(main, user)
    _mk_user(main, victim)
    _auth(client, main, user)

    r = client.delete(f"/admin/users/{victim}")
    assert r.status_code == 403, r.text
    # Victim must still exist.
    assert main.ddb_get_user(victim) is not None


# 4 ---------------------------------------------------------------------------
def test_idempotent_stripe_already_gone(client, main, monkeypatch):
    email = "gone@example.com"
    _mk_user(main, email, stripe_customer_id="cus_missing")
    _auth(client, main, email)

    class _Missing(Exception):
        code = "resource_missing"

    def _raise_missing(*a, **k):
        raise _Missing("No such customer: cus_missing")

    monkeypatch.setattr(main.stripe.Subscription, "list", _raise_missing)
    monkeypatch.setattr(main.stripe.Customer, "delete", _raise_missing)

    r = client.delete("/account")
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert main.ddb_get_user(email) is None


def test_delete_when_stripe_customer_manually_removed(client, main, monkeypatch):
    """DB still has stripe_customer_id but customer was deleted in Stripe Dashboard."""
    import stripe

    email = "stripe-gone@example.com"
    _mk_user(main, email, stripe_customer_id="cus_deleted_in_dashboard")
    _auth(client, main, email)

    def _list_deleted_customer(*a, **k):
        raise stripe.error.InvalidRequestError(
            "No such customer: 'cus_deleted_in_dashboard'",
            param="customer",
            http_status=404,
        )

    delete_called = []

    def _customer_delete(cid):
        delete_called.append(cid)
        raise stripe.error.InvalidRequestError(
            "No such customer: 'cus_deleted_in_dashboard'",
            param="id",
            code="resource_missing",
            http_status=404,
        )

    monkeypatch.setattr(main.stripe.Subscription, "list", _list_deleted_customer)
    monkeypatch.setattr(main.stripe.Customer, "delete", _customer_delete)

    r = client.delete("/account")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["stripe"]["already_absent"] is True
    assert main.ddb_get_user(email) is None
    assert delete_called == []  # list short-circuits; nothing to cancel


def test_delete_cancels_subscriptions_returned_as_stripe_objects(client, main, monkeypatch):
    """Stripe SDK returns StripeObject instances (no .get); teardown must not raise AttributeError."""
    import stripe

    email = "subowner@example.com"
    cus = "cus_with_subs"
    _mk_user(main, email, stripe_customer_id=cus)
    _auth(client, main, email)

    sub_active = stripe.StripeObject.construct_from(
        {"id": "sub_active", "status": "active"}, "sk_test"
    )
    sub_canceled = stripe.StripeObject.construct_from(
        {"id": "sub_old", "status": "canceled"}, "sk_test"
    )

    class _Page:
        def auto_paging_iter(self):
            yield sub_active
            yield sub_canceled

    canceled = []

    monkeypatch.setattr(main.stripe.Subscription, "list", lambda *a, **k: _Page())
    monkeypatch.setattr(
        main.stripe.Subscription,
        "cancel",
        lambda sub_id: canceled.append(sub_id) or stripe.StripeObject.construct_from(
            {"id": sub_id, "status": "canceled"}, "sk_test"
        ),
    )
    monkeypatch.setattr(
        main.stripe.Customer,
        "delete",
        lambda cid: stripe.StripeObject.construct_from({"id": cid, "deleted": True}, "sk_test"),
    )

    r = client.delete("/account")
    assert r.status_code == 200, r.text
    assert canceled == ["sub_active"]
    assert r.json()["stripe"]["subscriptions_canceled"] == 1
    assert main.ddb_get_user(email) is None


# guard ----------------------------------------------------------------------
def test_admin_cannot_self_delete_via_admin_route(client, main):
    admin = "admin@taxstat360.com"
    _mk_user(main, admin)
    _auth(client, main, admin)

    r = client.delete(f"/admin/users/{admin}")
    assert r.status_code == 400, r.text
    assert main.ddb_get_user(admin) is not None
