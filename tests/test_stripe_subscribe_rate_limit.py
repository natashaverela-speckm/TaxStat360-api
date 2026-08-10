"""M-1/M-2 (fresh-pass audit, Aug 2026): /stripe/subscribe previously had no
rate limit (M-1) and looked its user up via load()/full-table-scan instead of
the O(1) ddb_get_user(email) every other authenticated route uses (M-2).
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _mk_user(main, email):
    main.ddb_put_user(email, {
        "name": "Sub Test",
        "pw": main._hash_password("TestPassword12!"),
        "plan": "starter",
        "stripe_customer_id": "cus_existing",
        "verified": True,
    })


def _auth(client, main, email):
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


class _FakePaymentMethod:
    @staticmethod
    def attach(pm_id, customer):
        return None


class _FakeCustomer:
    @staticmethod
    def modify(cid, **kw):
        return None


class _FakeSubList:
    def auto_paging_iter(self):
        return iter([])


class _FakeSub:
    id = "sub_test123"


def test_subscribe_rate_limit_is_10_per_minute(client, main, monkeypatch):
    email = "subscribe-rate-limit@example.com"
    _mk_user(main, email)
    _auth(client, main, email)

    monkeypatch.setattr(main.stripe.PaymentMethod, "attach", _FakePaymentMethod.attach)
    monkeypatch.setattr(main.stripe.Customer, "modify", _FakeCustomer.modify)
    monkeypatch.setattr(main.stripe.Subscription, "list", lambda **kw: _FakeSubList())
    monkeypatch.setattr(main.stripe.Subscription, "create", lambda **kw: _FakeSub())

    body = {
        "email": email,
        "plan": "professional",
        "payment_method_id": "pm_card_visa",
        "billing": "monthly",
    }
    for _ in range(10):
        resp = client.post("/stripe/subscribe", json=body)
        assert resp.status_code == 200, resp.text
    resp = client.post("/stripe/subscribe", json=body)
    assert resp.status_code == 429


def test_subscribe_uses_o1_lookup_not_full_table_scan(client, main, monkeypatch):
    """Regression guard for M-2: subscribe() must resolve the user via
    ddb_get_user(email), never via load()/ddb_all_users() (a full scan)."""
    email = "subscribe-o1-lookup@example.com"
    _mk_user(main, email)
    _auth(client, main, email)

    monkeypatch.setattr(main.stripe.PaymentMethod, "attach", _FakePaymentMethod.attach)
    monkeypatch.setattr(main.stripe.Customer, "modify", _FakeCustomer.modify)
    monkeypatch.setattr(main.stripe.Subscription, "list", lambda **kw: _FakeSubList())
    monkeypatch.setattr(main.stripe.Subscription, "create", lambda **kw: _FakeSub())

    scan_calls = {"n": 0}
    real_all_users = main.ddb_all_users

    def _counting_all_users():
        scan_calls["n"] += 1
        return real_all_users()

    monkeypatch.setattr(main, "ddb_all_users", _counting_all_users)

    resp = client.post("/stripe/subscribe", json={
        "email": email,
        "plan": "professional",
        "payment_method_id": "pm_card_visa",
        "billing": "monthly",
    })
    assert resp.status_code == 200, resp.text
    assert scan_calls["n"] == 0, "subscribe() must not call ddb_all_users()/load() (full table scan)"
