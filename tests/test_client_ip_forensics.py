"""SECURITY FIX regression tests (fresh-pass audit, Aug 2026).

writtenByIp (the forensic IP stamp on record writes) used to take the
client-supplied X-Forwarded-For header verbatim, which a client can spoof by
sending any value it likes. _client_ip() now trusts only the last hop in the
X-Forwarded-For chain (the one a single trusted reverse proxy appends itself)
and falls back to the raw socket address. This is forensic-only — nothing in
the app gates access on writtenByIp — so these tests just pin the new logic.
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _login_client(client, main, email="ip-forensics@example.com"):
    main.ddb_put_user(email, {
        "name": "IP Test", "pw": main._hash_password("a-valid-password-123"),
        "verified": True, "plan": "starter",
    })
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def test_client_ip_uses_last_hop_not_client_supplied_first_hop(client, main):
    _login_client(client, main)
    # A client can prepend anything it wants; only the last hop (appended by
    # the trusted proxy) should be trusted and recorded.
    resp = client.put("/records", json={"id": 1, "name": "r1"}, headers={
        "x-forwarded-for": "9.9.9.9-spoofed, 203.0.113.7",
    })
    assert resp.status_code == 200
    items = main._ddb_query_records("ip-forensics@example.com")
    assert items[0]["writtenByIp"] == "203.0.113.7"


def test_client_ip_falls_back_to_socket_address_without_header(client, main):
    _login_client(client, main, email="ip-fallback@example.com")
    resp = client.put("/records", json={"id": 2, "name": "r2"})
    assert resp.status_code == 200
    items = main._ddb_query_records("ip-fallback@example.com")
    # TestClient's synthetic socket address — just confirms it's non-empty and
    # not a client-controlled header value.
    assert items[0]["writtenByIp"]


def test_client_ip_helper_directly(main):
    class _Req:
        def __init__(self, xff, client_host="1.2.3.4"):
            self.headers = {"x-forwarded-for": xff} if xff else {}
            self.client = type("C", (), {"host": client_host})()

    assert main._client_ip(_Req("198.51.100.4")) == "198.51.100.4"
    assert main._client_ip(_Req("fake, 198.51.100.5, 198.51.100.6")) == "198.51.100.6"
    assert main._client_ip(_Req("")) == "1.2.3.4"
