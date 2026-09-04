"""characterization — twin of taxstat360/src/lib/ssnRedact.test.js."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.ssn_redact import (
    SSN_REDACTION_MASK,
    TEXT_PDF_ALNUM_THRESHOLD,
    assert_no_ssn_remaining,
    classify_text_layer,
    count_alphanumeric,
    detect_ssn_like,
    has_ssn_like,
    redact_ssn_in_text,
)

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    PdfReader = None  # type: ignore[misc, assignment]

CLEAN_BODY = """SYNTHETIC FIXTURE — NOT A REAL TAX RETURN
Form 1040 U.S. Individual Income Tax Return (test)
Name: Test Taxpayer
EIN for Schedule C example: 12-3456789
Prior-year AGI (line 11): 142000
Prior-year federal tax (line 24): 18750
Form 8582 unallowed loss: 12500
Schedule D short-term capital loss carryover: 1500
Schedule D long-term capital loss carryover: 8000
Form 8995 QBI loss carryforward: 4500
NOL carryforward: none
"""

SSN_BODY = """SYNTHETIC FIXTURE — NOT A REAL TAX RETURN
Form 1040 U.S. Individual Income Tax Return (test)
Name: Test Taxpayer
Social security number: 219-09-9999
SSN (no dashes): 219099999
EIN for Schedule C example: 12-3456789
Prior-year AGI (line 11): 142000
Prior-year federal tax (line 24): 18750
Form 8582 unallowed loss: 12500
"""

# Prefer Natasha workspace fixtures; fall back if API repo is checked out alone.
_FIXTURE_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "taxstat360" / "fixtures" / "text-pdf-gate",
    Path("/Users/nimralatif/Desktop/upwork/Natasha/taxstat360/fixtures/text-pdf-gate"),
]


def _fixture_dir() -> Path | None:
    for p in _FIXTURE_CANDIDATES:
        if p.is_dir() and (p / "fixture-tax-1040-text-clean.pdf").exists():
            return p
    return None


def _pdf_text(path: Path) -> str:
    assert PdfReader is not None
    reader = PdfReader(str(path))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def test_threshold_and_classify():
    assert TEXT_PDF_ALNUM_THRESHOLD == 40
    assert classify_text_layer(CLEAN_BODY) == "text"
    assert classify_text_layer("") == "image-only"
    assert classify_text_layer("abc") == "image-only"
    assert count_alphanumeric(CLEAN_BODY) >= 40


def test_dashed_ssn_detected():
    hits = detect_ssn_like("SSN 219-09-9999 on form")
    assert len(hits) == 1
    assert hits[0]["kind"] == "dashed"
    assert hits[0]["value"] == "219-09-9999"
    assert has_ssn_like("SSN 219-09-9999 on form") is True


def test_spaced_ssn_detected():
    hits = detect_ssn_like("Social Security Number 219 09 9999")
    assert len(hits) == 1
    assert hits[0]["kind"] == "spaced"


def test_undashed_needs_context():
    assert detect_ssn_like("Account 219099999 balance") == []
    hits = detect_ssn_like("Social security number: 219099999")
    assert len(hits) == 1
    assert hits[0]["kind"] == "undashed"


def test_ein_not_ssn():
    assert detect_ssn_like("EIN for Schedule C example: 12-3456789") == []
    assert has_ssn_like(CLEAN_BODY) is False


def test_already_masked_ignored():
    assert detect_ssn_like("SSN XXX-XX-XXXX") == []
    assert detect_ssn_like("SSN ***-**-****") == []
    assert detect_ssn_like("SSN ###-##-####") == []


def test_fixture_strings_redact_clean():
    hits = detect_ssn_like(SSN_BODY)
    assert len(hits) >= 2
    assert any(h["kind"] == "dashed" for h in hits)
    assert any(h["kind"] == "undashed" for h in hits)

    redacted = redact_ssn_in_text(SSN_BODY)
    assert redacted["redacted_count"] == len(hits)
    assert "219-09-9999" not in redacted["text"]
    assert "219099999" not in redacted["text"]
    assert all(s == SSN_REDACTION_MASK for s in redacted["samples_masked"])
    assert assert_no_ssn_remaining(redacted["text"]) is True


def test_clean_body_no_redaction():
    redacted = redact_ssn_in_text(CLEAN_BODY)
    assert redacted["redacted_count"] == 0
    assert redacted["text"] == CLEAN_BODY
    assert assert_no_ssn_remaining(CLEAN_BODY) is True


def test_samples_masked_have_no_digits():
    redacted = redact_ssn_in_text("Social security number: 219-09-9999")
    assert not any(ch.isdigit() for ch in "".join(redacted["samples_masked"]))


@pytest.mark.skipif(PdfReader is None, reason="pypdf not installed")
@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_real_pdf_fixtures_match_acceptance():
    root = _fixture_dir()
    assert root is not None

    clean = _pdf_text(root / "fixture-tax-1040-text-clean.pdf")
    with_ssn = _pdf_text(root / "fixture-tax-1040-text-with-ssn.pdf")
    image_only = _pdf_text(root / "fixture-tax-1040-image-only.pdf")
    mixed = _pdf_text(root / "fixture-tax-1040-mixed.pdf")

    assert classify_text_layer(clean) == "text"
    assert has_ssn_like(clean) is False

    assert classify_text_layer(with_ssn) == "text"
    assert has_ssn_like(with_ssn) is True
    redacted = redact_ssn_in_text(with_ssn)
    assert assert_no_ssn_remaining(redacted["text"]) is True
    assert "219-09-9999" not in redacted["text"]

    assert classify_text_layer(image_only) == "image-only"
    assert has_ssn_like(image_only) is False

    assert classify_text_layer(mixed) == "text"
    assert has_ssn_like(mixed) is False
