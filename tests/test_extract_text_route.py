"""PHASE 2 (Prior-Year Review): /extract/tax-1040-text.

The browser masks SSNs and sends only the text layer; the PDF never arrives.
The server masks again, refuses anything that survives, and otherwise behaves
exactly like the file route (paid plan, stub when the live flag is off, native
extractor when it is on).
"""
import pytest

from tests.test_pdf_text_gate import _session_pro

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
