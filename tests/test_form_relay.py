"""OBS-5 form-key relay (Phase 2.2c) — the web3forms key leaves the bundle.

The relay must: hold the key server-side, whitelist and length-cap fields,
require a subject, fail LOUDLY when unconfigured (owner alerts must never be
silently dropped — the D-03 signup-failure alerts route through here), carry
a timeout on the upstream call, and rate-limit per the KNOWN_LIMITATIONS spec.
"""


import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    # slowapi's in-memory counter spans the test module; the relay's 5/min
    # limit is itself under test below, so isolate every test.
    main.limiter.reset()
    yield
    main.limiter.reset()


class _FakeResp:
    def __init__(self, success=True, ok=True):
        self._s, self.ok = success, ok
    def json(self):
        return {"success": self._s}


def test_relay_attaches_key_whitelists_and_caps_fields(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEB3FORMS_ACCESS_KEY", "srv-key-123")
    sent = {}
    def fake_post(url, json=None, headers=None, timeout=None):
        sent.update({"url": url, "payload": json, "timeout": timeout})
        return _FakeResp(True)
    monkeypatch.setattr(main.requests, "post", fake_post)

    r = client.post("/alerts/form-relay", json={
        "subject": "TaxStat360 ALERT: subscription setup failed at signup",
        "email": "user@example.com",
        "detail": "x" * 9000,
        "access_key": "attacker-supplied",   # must be ignored
        "not_a_field": "dropped",
    })
    assert r.status_code == 200 and r.json() == {"success": True}
    assert sent["url"] == "https://api.web3forms.com/submit"
    assert sent["payload"]["access_key"] == "srv-key-123", "server key wins; client cannot supply one"
    assert "not_a_field" not in sent["payload"]
    assert len(sent["payload"]["detail"]) == 4000, "fields are length-capped"
    assert sent["timeout"] == 10


def test_relay_requires_subject_and_json(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEB3FORMS_ACCESS_KEY", "srv-key-123")
    assert client.post("/alerts/form-relay", json={"email": "a@b.com"}).status_code == 400
    assert client.post("/alerts/form-relay", content=b"not json",
                       headers={"Content-Type": "application/json"}).status_code == 400


def test_relay_unconfigured_is_a_loud_503(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEB3FORMS_ACCESS_KEY", "")
    r = client.post("/alerts/form-relay", json={"subject": "s"})
    assert r.status_code == 503


def test_relay_upstream_failure_is_502_and_success_false_passes_through(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEB3FORMS_ACCESS_KEY", "srv-key-123")
    monkeypatch.setattr(main.requests, "post",
                        lambda *a, **k: (_ for _ in ()).throw(main.requests.RequestException("down")))
    assert client.post("/alerts/form-relay", json={"subject": "s"}).status_code == 502

    monkeypatch.setattr(main.requests, "post", lambda *a, **k: _FakeResp(False))
    r = client.post("/alerts/form-relay", json={"subject": "s"})
    assert r.status_code == 200 and r.json() == {"success": False}


def test_relay_rate_limit_is_5_per_minute_per_spec(client, main, monkeypatch):
    monkeypatch.setattr(main, "WEB3FORMS_ACCESS_KEY", "srv-key-123")
    monkeypatch.setattr(main.requests, "post", lambda *a, **k: _FakeResp(True))
    for i in range(5):
        assert client.post("/alerts/form-relay", json={"subject": f"s{i}"}).status_code == 200
    assert client.post("/alerts/form-relay", json={"subject": "s6"}).status_code == 429, \
        "KNOWN_LIMITATIONS spec: 5/min/IP — the sixth request must be limited"
