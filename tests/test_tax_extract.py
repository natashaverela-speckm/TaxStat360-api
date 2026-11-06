"""PHASE 2 option B: the TaxStat360-native return extractor (app/tax_extract.py)
and its wiring into /extract/tax-1040-carryforward."""
import json

import pytest

from app import tax_extract as tx


class _Resp:
    def __init__(self, status=200, content=None, text=""):
        self.status_code = status
        self.ok = status < 400
        self.text = text
        self._content = content

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


def _model_answer(fields, confidence=None):
    conf = {k: 1.0 for k in fields}
    if confidence:
        conf.update(confidence)
    return json.dumps({"fields": fields, "confidence": conf})


SAMPLE_TEXT = (
    "Form 1040 2025 U.S. Individual Income Tax Return Married filing jointly "
    "1a Total amount from Form(s) W-2 180,000 11 Adjusted gross income 262,000 "
    "24 Total tax 43,199 Schedule E rents received 42,000 depreciation 28,000 "
    "Schedule K-1 (Form 1120-S) 1 Ordinary business income 113,880 "
) * 3


# ── contracts ────────────────────────────────────────────────────────────────

def test_review_profile_keys_match_main_contract(main):
    assert tx.field_keys("tax-1040-review") == main.TAX_1040_REVIEW_FIELD_KEYS


def test_carryforward_profile_keys_match_stub(main):
    assert set(tx.field_keys("tax-1040-carryforward")) == set(main._TAX_FIXTURE_FIELDS)


def test_schema_is_strict_and_nullable():
    s = tx._json_schema("tax-1040-review")
    assert s["strict"] is True
    props = s["schema"]["properties"]["fields"]["properties"]
    assert props["w2Wages"]["type"] == ["number", "null"]
    assert props["shortTermRental"]["type"] == ["boolean", "null"]
    assert set(s["schema"]["properties"]["fields"]["required"]) == set(tx.field_keys("tax-1040-review"))


def test_prompt_names_every_field_and_forbids_identifiers():
    p = tx._system_prompt("tax-1040-review")
    for k in tx.field_keys("tax-1040-review"):
        assert k in p
    assert "Do not include names, addresses, or identification numbers" in p
    assert "Never estimate" in p


def test_filing_status_is_decided_by_a_mark_or_the_standard_deduction_not_the_label():
    p = tx._system_prompt("tax-1040-review")
    assert "do not pick a status just because its label appears" in p
    assert "15,750 = single" in p and "23,625 = hoh" in p and "21,900 = hoh" in p
    assert "[checked:" in p


# ── privacy ──────────────────────────────────────────────────────────────────

def test_prepare_text_masks_ssns_and_caps_length():
    text = "Your social security number 123-45-6789 appears here. " + "x" * (tx.MAX_TEXT_CHARS + 500)
    out = tx.prepare_text(text)
    assert "123-45-6789" not in out
    assert "XXX-XX-XXXX" in out
    assert len(out) <= tx.MAX_TEXT_CHARS


def test_only_masked_text_is_sent_never_bytes():
    sent = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        sent["url"] = url
        sent["json"] = json
        sent["headers"] = headers
        return _Resp(content=_model_answer({k: None for k in tx.field_keys("tax-1040-review")}))

    tx.extract_fields_from_text("SSN 123-45-6789 " + SAMPLE_TEXT, "tax-1040-review", api_key="sk-x", model="m", post=fake_post)
    user_msg = sent["json"]["messages"][1]["content"]
    assert "123-45-6789" not in user_msg
    assert sent["json"]["response_format"]["type"] == "json_schema"
    assert sent["json"]["temperature"] == 0
    assert sent["json"]["store"] is False   # never stored in the org's dashboard logs
    assert sent["headers"]["Authorization"] == "Bearer sk-x"
    assert sent["url"] == tx.OPENAI_CHAT_URL


# ── parsing ──────────────────────────────────────────────────────────────────

def test_happy_path_returns_the_edge_envelope_with_confidence():
    answer = {k: None for k in tx.field_keys("tax-1040-review")}
    answer.update({"taxYear": 2025, "filingStatus": "MFJ", "w2Wages": "180,000", "k1ScorpOrdinary": 113880, "shortTermRental": "false", "schedCNet": -4200.5})
    r = tx.extract_fields_from_text(SAMPLE_TEXT, "tax-1040-review", api_key="k", model="m",
                                    post=lambda *a, **k: _Resp(content=_model_answer(answer, {"k1ScorpOrdinary": 0.4})))
    assert r["ok"] is True and r["profile"] == "tax-1040-review"
    f, c = r["fields"], r["confidence"]
    assert f["taxYear"] == 2025
    assert f["filingStatus"] == "mfj"              # lower-cased
    assert f["w2Wages"] == 180000.0                # commas stripped
    assert f["schedCNet"] == -4200.5               # losses negative
    assert f["shortTermRental"] is False
    assert f["schedERent"] is None and c["schedERent"] == 0.0
    assert c["k1ScorpOrdinary"] == 0.4
    assert r["evidence"] == {"retained": False, "deletedAfterProcessing": True, "retention": "delete-after-processing"}
    assert r["providerMeta"]["provider"] == "openai" and r["providerMeta"]["fieldsFound"] == 6


def test_bad_enum_and_garbage_values_become_null():
    answer = {k: None for k in tx.field_keys("tax-1040-review")}
    answer.update({"filingStatus": "married", "w2Wages": "lots", "dependents": "two"})
    r = tx.extract_fields_from_text(SAMPLE_TEXT, "tax-1040-review", api_key="k", model="m", post=lambda *a, **k: _Resp(content=_model_answer(answer)))
    assert r["fields"]["filingStatus"] is None and r["confidence"]["filingStatus"] == 0.0
    assert r["fields"]["w2Wages"] is None
    assert r["fields"]["dependents"] is None
    assert any("No figures were recognised" in w for w in r["warnings"])


@pytest.mark.parametrize("resp", [
    _Resp(status=500, text="boom"),
    _Resp(content="not json"),
    _Resp(content=json.dumps({"nope": 1})),
])
def test_provider_failures_raise_extract_error(resp):
    with pytest.raises(tx.ExtractError):
        tx.extract_fields_from_text(SAMPLE_TEXT, "tax-1040-review", api_key="k", model="m", post=lambda *a, **k: resp)


def test_network_failure_and_missing_key():
    import requests
    def boom(*a, **k):
        raise requests.ConnectionError("down")
    with pytest.raises(tx.ExtractError):
        tx.extract_fields_from_text(SAMPLE_TEXT, "tax-1040-review", api_key="k", model="m", post=boom)
    with pytest.raises(tx.ExtractError):
        tx.extract_fields_from_text(SAMPLE_TEXT, "tax-1040-review", api_key="", model="m")
    with pytest.raises(tx.ExtractError):
        tx.extract_fields_from_text("short", "tax-1040-review", api_key="k", model="m")


# ── endpoint wiring ──────────────────────────────────────────────────────────

def _pro(client, main, email="native@example.com"):
    main.ddb_put_user(email, {"name": "N", "pw": main._hash_password("TestPassword12!"), "tok": "t", "plan": "pro", "verified": True})
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


def _text_pdf_bytes():
    # a minimal text-layer PDF the server gate accepts (>= 40 alphanumerics, no SSN)
    from pypdf import PdfWriter
    import io
    w = PdfWriter()
    w.add_blank_page(width=612, height=792)
    buf = io.BytesIO(); w.write(buf)
    return buf.getvalue()


def test_endpoint_defaults_to_native_provider_and_stays_on_stub_until_live(client, main, monkeypatch):
    assert main.TAX_EXTRACT_PROVIDER == "openai"
    monkeypatch.setattr(main, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", False)
    _pro(client, main)
    calls = []
    monkeypatch.setattr(main.requests, "post", lambda *a, **k: calls.append(1))
    from app import pdf_text_gate
    monkeypatch.setattr(pdf_text_gate, "extract_pdf_text_layer", lambda raw: SAMPLE_TEXT)
    r = client.post("/extract/tax-1040-carryforward", files={"file": ("fixture-tax-1040-smoke.pdf", _text_pdf_bytes(), "application/pdf")}, data={"profile": "tax-1040-review"})
    assert r.status_code == 200
    assert r.json()["providerMeta"]["provider"] == "stub"
    assert calls == []   # nothing left the box


def test_endpoint_native_live_path_returns_model_fields(client, main, monkeypatch):
    monkeypatch.setattr(main, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", True)
    monkeypatch.setattr(main, "TAX_EXTRACT_PROVIDER", "openai")
    _pro(client, main, "live@example.com")
    from app import pdf_text_gate
    monkeypatch.setattr(pdf_text_gate, "extract_pdf_text_layer", lambda raw: SAMPLE_TEXT)
    answer = {k: None for k in tx.field_keys("tax-1040-review")}
    answer.update({"taxYear": 2025, "totalTax": 43199})
    import app.tax_extract as mod
    monkeypatch.setattr(mod.requests, "post", lambda *a, **k: _Resp(content=_model_answer(answer)))
    r = client.post("/extract/tax-1040-carryforward", files={"file": ("return.pdf", _text_pdf_bytes(), "application/pdf")}, data={"profile": "tax-1040-review"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["providerMeta"]["provider"] == "openai"
    assert body["fields"]["totalTax"] == 43199
    assert body["evidence"]["retained"] is False


def test_endpoint_native_failure_is_a_503_not_a_leak(client, main, monkeypatch):
    monkeypatch.setattr(main, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", True)
    _pro(client, main, "fail@example.com")
    from app import pdf_text_gate
    monkeypatch.setattr(pdf_text_gate, "extract_pdf_text_layer", lambda raw: SAMPLE_TEXT)
    import app.tax_extract as mod
    monkeypatch.setattr(mod.requests, "post", lambda *a, **k: _Resp(status=500, text="secret upstream detail"))
    r = client.post("/extract/tax-1040-carryforward", files={"file": ("return.pdf", _text_pdf_bytes(), "application/pdf")}, data={"profile": "tax-1040-review"})
    assert r.status_code == 503
    assert "secret upstream detail" not in r.text


def test_parentheses_and_trailing_minus_are_losses():
    assert tx._parse_amount("(12,345)") == -12345.0
    assert tx._parse_amount("-12,345") == -12345.0
    assert tx._parse_amount("12,345-") == -12345.0
    assert tx._parse_amount("$12,345") == 12345.0
    assert tx._parse_amount(-5) == -5.0
    answer = {k: None for k in tx.field_keys("tax-1040-review")}
    answer.update({"k1ScorpOrdinary": "(48,210)", "schedCNet": "(1,000)"})
    r = tx.extract_fields_from_text(SAMPLE_TEXT, "tax-1040-review", api_key="k", model="m",
                                    post=lambda *a, **k: _Resp(content=_model_answer(answer)))
    assert r["fields"]["k1ScorpOrdinary"] == -48210.0
    assert r["fields"]["schedCNet"] == -1000.0
    assert "parentheses" in tx._system_prompt("tax-1040-review")
