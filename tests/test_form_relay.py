"""OBS-5 alert relay (Phase 2.2c-r1) — SES direct-send, no third party, no key.

History: the first relay forwarded to web3forms; live testing revealed their
free plan rejects server-side submissions, and the rejection was passed
through as HTTP 200 {"success": false} — a silent failure. These tests pin
the revision: the relay emails the owner directly via SES (the transport the
reset/verify emails already use), field rules and the 5/min/IP limit are
unchanged, and any send failure is a LOUD 502 — an owner alert must never
pretend it was delivered.
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


class _FakeSES:
    def __init__(self, fail=False):
        self.fail, self.sent = fail, []
    def send_email(self, **kwargs):
        if self.fail:
            raise RuntimeError("SES down")
        self.sent.append(kwargs)
        return {"MessageId": "test"}


def _patch_ses(main, monkeypatch, fake):
    # The mailer was migrated from boto3 SES to _SendGridMailer (see _mailer()); patching
    # boto3.client no longer intercepts delivery, so these tests were silently exercising
    # the real SendGrid path and 502-ing without a key. Patch the single mailer seam
    # instead — the endpoint builds SES-style kwargs that _FakeSES records unchanged.
    monkeypatch.setattr(main, "_mailer", lambda: fake)
    return fake


def test_relay_sends_via_ses_with_whitelist_caps_and_reply_to(client, main, monkeypatch):
    ses = _patch_ses(main, monkeypatch, _FakeSES())
    r = client.post("/alerts/form-relay", json={
        "subject": "TaxStat360 [General Question] — Jane",
        "email": "jane@example.com",
        "message": "Hello!",
        "detail": "x" * 9000,
        "not_a_field": "dropped",
        "access_key": "legacy-client-noise",   # ignored: no key exists anywhere now
    })
    assert r.status_code == 200 and r.json() == {"success": True}
    assert len(ses.sent) == 1
    sent = ses.sent[0]
    assert sent["Source"] == main.RESET_FROM
    assert sent["Destination"]["ToAddresses"] == [main.ALERT_TO_EMAIL]
    assert sent["ReplyToAddresses"] == ["jane@example.com"], "owner can reply straight to the submitter"
    body = sent["Message"]["Body"]["Text"]["Data"]
    assert "Hello!" in body and "not_a_field" not in body and "legacy-client-noise" not in body
    assert len([ln for ln in body.split("\n\n") if ln.startswith("detail: ")][0]) == len("detail: ") + 4000


def test_relay_requires_subject_and_json(client, main, monkeypatch):
    _patch_ses(main, monkeypatch, _FakeSES())
    assert client.post("/alerts/form-relay", json={"email": "a@b.com"}).status_code == 400
    assert client.post("/alerts/form-relay", content=b"not json",
                       headers={"Content-Type": "application/json"}).status_code == 400


def test_relay_send_failure_is_a_loud_502_never_a_quiet_false(client, main, monkeypatch):
    _patch_ses(main, monkeypatch, _FakeSES(fail=True))
    r = client.post("/alerts/form-relay", json={"subject": "s"})
    assert r.status_code == 502


def test_relay_omits_reply_to_when_no_valid_email(client, main, monkeypatch):
    ses = _patch_ses(main, monkeypatch, _FakeSES())
    assert client.post("/alerts/form-relay", json={"subject": "s", "email": "not-an-email"}).status_code == 200
    assert "ReplyToAddresses" not in ses.sent[0]


def test_relay_rate_limit_is_5_per_minute_per_spec(client, main, monkeypatch):
    _patch_ses(main, monkeypatch, _FakeSES())
    for i in range(5):
        assert client.post("/alerts/form-relay", json={"subject": f"s{i}"}).status_code == 200
    assert client.post("/alerts/form-relay", json={"subject": "s6"}).status_code == 429
