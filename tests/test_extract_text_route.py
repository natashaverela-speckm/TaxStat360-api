"""PHASE 2 (Prior-Year Review): /extract/tax-1040-text.

The browser masks SSNs and sends only the text layer; the PDF never arrives.
The server masks again, refuses anything that survives, and otherwise behaves
exactly like the file route (paid plan, stub when the live flag is off, native
extractor when it is on).
"""
import pytest

from tests.test_pdf_text_gate import _session_pro


@pytest.fixture(autouse=True)
def _fresh_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()

CLEAN = "SYNTHETIC Form 1040 2025 Wages 180000 Federal income tax withheld 20000 Adjusted gross income 262000 Total tax 43199"
MASKED = "Your social security number XXX-XX-XXXX Spouse XXX-XX-XXXX " + CLEAN


def test_requires_paid_plan(client, main):
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": CLEAN})
    assert r.status_code in (401, 403)


def test_masked_text_hits_the_stub_when_live_is_off(client, main, monkeypatch):
    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", False)
    _session_pro(client, main)
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": MASKED})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["profile"] == "tax-1040-review"
    assert body["evidence"]["retained"] is False


def test_server_masks_again_and_never_sends_an_ssn(client, main, monkeypatch):
    """A browser that skipped masking still cannot leak an SSN to the provider."""
    import app.tax_extract as tx

    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", True)
    monkeypatch.setattr(main, "TAX_EXTRACT_PROVIDER", "openai")
    monkeypatch.setattr(main, "OPENAI_API_KEY", "sk-test")
    sent = {}

    def fake(text, profile, *, api_key, model, post=None, timeout=90):
        sent["text"] = text
        return {"ok": True, "profile": profile, "fields": {k: None for k in tx.field_keys(profile)}, "confidence": {},
                "warnings": [], "evidence": {"retained": False, "deletedAfterProcessing": True, "retention": "delete-after-processing"},
                "providerMeta": {"provider": "openai", "fieldsFound": 0}}

    monkeypatch.setattr(tx, "extract_fields_from_text", fake)
    _session_pro(client, main)
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": "SSN 219-09-9999 " + CLEAN})
    assert r.status_code == 200, r.text
    assert "219-09-9999" not in sent["text"]
    assert "XXX-XX-XXXX" in sent["text"]


def test_image_only_empty_and_oversize_are_refused(client, main):
    _session_pro(client, main)
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": "   "})
    assert r.status_code == 400
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": "a b c"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "IMAGE_ONLY_PDF"
    r = client.post("/extract/tax-1040-text", json={"profile": "tax-1040-review", "text": "x" * (main.TAX_1040_MAX_TEXT_CHARS + 1)})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "FILE_TOO_LARGE"
    r = client.post("/extract/tax-1040-text", json={"profile": "bogus", "text": CLEAN})
    assert r.status_code == 400


# ── PHASE 2b: entity returns ──────────────────────────────────────────────────

def test_entity_profiles_are_registered_and_schema_strict(main):
    import app.tax_extract as tx

    for profile in ("tax-1120s-review", "tax-1065-review"):
        assert profile in main.EXTRACT_PROFILES
        keys = tx.field_keys(profile)
        assert len(keys) == len(set(keys))
        s = tx._json_schema(profile)
        assert set(s["schema"]["properties"]["fields"]["required"]) == set(keys)
        prompt = tx._system_prompt(profile)
        for k in keys:
            assert k in prompt
    assert "1120-S" in tx._system_prompt("tax-1120s-review")
    assert "1065" in tx._system_prompt("tax-1065-review")
    assert "officerCompensation" in tx.field_keys("tax-1120s-review")
    assert "guaranteedPayments" in tx.field_keys("tax-1065-review")


@pytest.mark.parametrize("profile,fixture_key", [("tax-1120s-review", "officerCompensation"), ("tax-1065-review", "guaranteedPayments")])
def test_entity_stub_returns_fixture_when_hinted_else_nulls(client, main, monkeypatch, profile, fixture_key):
    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", False)
    _session_pro(client, main)
    r = client.post("/extract/tax-1040-text", json={"profile": profile, "text": MASKED, "fixture": "fixture-tax-1120s-smoke.pdf"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["profile"] == profile and body["fields"][fixture_key] not in (None, 0)
    assert body["evidence"]["retained"] is False
    r = client.post("/extract/tax-1040-text", json={"profile": profile, "text": MASKED})
    assert r.status_code == 200, r.text
    assert r.json()["fields"][fixture_key] is None


def test_scorp_fixture_agrees_with_the_1040_fixture(main):
    assert main._TAX_1120S_FIXTURE_FIELDS["ordinaryBusinessIncome"] == main._TAX_REVIEW_FIXTURE_FIELDS["k1ScorpOrdinary"]
    assert main._TAX_1120S_FIXTURE_FIELDS["officerCompensation"] == main._TAX_REVIEW_FIXTURE_FIELDS["officerW2"]
