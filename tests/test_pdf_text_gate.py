"""Phase 3 — server text-PDF gate (unit + extract route)."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.pdf_text_gate import (
    GATE_CODES,
    extract_pdf_text_layer,
    gate_tax_1040_pdf_bytes,
    is_pdf_upload,
)

_FIXTURE_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "taxstat360" / "fixtures" / "text-pdf-gate",
    Path("/Users/nimralatif/Desktop/upwork/Natasha/taxstat360/fixtures/text-pdf-gate"),
]


def _fixture_dir() -> Path | None:
    for p in _FIXTURE_CANDIDATES:
        if p.is_dir() and (p / "fixture-tax-1040-text-clean.pdf").exists():
            return p
    return None


def _session_pro(client, main, email="pro-extract@example.com"):
    main.ddb_put_user(
        email,
        {
            "name": "Extract Pro",
            "pw": main._hash_password("TestPassword12!"),
            "tok": "tok_" + email,
            "plan": "professional",
            "verified": True,
        },
    )
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def test_is_pdf_upload_magic_and_name():
    assert is_pdf_upload(b"%PDF-1.4\n", filename="x.bin", content_type="") is True
    assert is_pdf_upload(b"not-pdf", filename="x.pdf", content_type="") is True
    assert is_pdf_upload(b"not-pdf", filename="x.png", content_type="image/png") is False


def test_gate_rejects_non_pdf():
    res = gate_tax_1040_pdf_bytes(b"hello", filename="scan.png", content_type="image/png")
    assert res["ok"] is False
    assert res["code"] == GATE_CODES["UNSUPPORTED_FILE_TYPE"]


def test_gate_image_only_and_ssn_with_injected_text():
    image = gate_tax_1040_pdf_bytes(
        b"%PDF-1.4",
        filename="image.pdf",
        extract_text=lambda _raw: "",
    )
    assert image["ok"] is False
    assert image["code"] == GATE_CODES["IMAGE_ONLY_PDF"]

    ssn = gate_tax_1040_pdf_bytes(
        b"%PDF-1.4",
        filename="ssn.pdf",
        extract_text=lambda _raw: "Social security number: 219-09-9999 AGI 142000 federal tax",
    )
    assert ssn["ok"] is False
    assert ssn["code"] == GATE_CODES["SSN_DETECTED"]

    clean = gate_tax_1040_pdf_bytes(
        b"%PDF-1.4",
        filename="clean.pdf",
        extract_text=lambda _raw: (
            "SYNTHETIC FIXTURE Form 1040 EIN 12-3456789 Prior-year AGI 142000 federal tax 18750"
        ),
    )
    assert clean["ok"] is True
    assert clean["alnum"] >= 40


def test_gate_unreadable():
    res = gate_tax_1040_pdf_bytes(
        b"%PDF-1.4",
        filename="bad.pdf",
        extract_text=lambda _raw: (_ for _ in ()).throw(ValueError("boom")),
    )
    assert res["ok"] is False
    assert res["code"] == GATE_CODES["PDF_UNREADABLE"]


@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_gate_real_fixtures():
    root = _fixture_dir()
    assert root is not None

    clean = (root / "fixture-tax-1040-text-clean.pdf").read_bytes()
    with_ssn = (root / "fixture-tax-1040-text-with-ssn.pdf").read_bytes()
    image = (root / "fixture-tax-1040-image-only.pdf").read_bytes()
    mixed = (root / "fixture-tax-1040-mixed.pdf").read_bytes()

    assert extract_pdf_text_layer(clean)
    assert gate_tax_1040_pdf_bytes(clean, filename="fixture-tax-1040-text-clean.pdf")["ok"] is True

    blocked = gate_tax_1040_pdf_bytes(with_ssn, filename="fixture-tax-1040-text-with-ssn.pdf")
    assert blocked["ok"] is False
    assert blocked["code"] == GATE_CODES["SSN_DETECTED"]

    img = gate_tax_1040_pdf_bytes(image, filename="fixture-tax-1040-image-only.pdf")
    assert img["ok"] is False
    assert img["code"] == GATE_CODES["IMAGE_ONLY_PDF"]

    assert gate_tax_1040_pdf_bytes(mixed, filename="fixture-tax-1040-mixed.pdf")["ok"] is True


@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_extract_route_clean_stub_ok(client, main, monkeypatch):
    monkeypatch.setattr(main, "EXTRACT_SERVICE_KEY", "")
    _session_pro(client, main)
    root = _fixture_dir()
    path = root / "fixture-tax-1040-smoke.pdf"
    r = client.post(
        "/extract/tax-1040-carryforward",
        files={"file": ("fixture-tax-1040-smoke.pdf", path.read_bytes(), "application/pdf")},
        data={"profile": "tax-1040-carryforward"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True
    assert body["fields"]["priorYearAGI"] == 142000
    assert body["evidence"]["retained"] is False
    assert body["evidence"]["deletedAfterProcessing"] is True


@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_extract_route_image_only_400(client, main, monkeypatch):
    monkeypatch.setattr(main, "EXTRACT_SERVICE_KEY", "")
    _session_pro(client, main)
    root = _fixture_dir()
    path = root / "fixture-tax-1040-image-only.pdf"
    r = client.post(
        "/extract/tax-1040-carryforward",
        files={"file": ("fixture-tax-1040-image-only.pdf", path.read_bytes(), "application/pdf")},
        data={"profile": "tax-1040-carryforward"},
    )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["code"] == GATE_CODES["IMAGE_ONLY_PDF"]
    assert "scanned" in detail["message"].lower() or "image-only" in detail["message"].lower()


@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_extract_route_ssn_400(client, main, monkeypatch):
    monkeypatch.setattr(main, "EXTRACT_SERVICE_KEY", "")
    _session_pro(client, main)
    root = _fixture_dir()
    path = root / "fixture-tax-1040-text-with-ssn.pdf"
    r = client.post(
        "/extract/tax-1040-carryforward",
        files={"file": ("fixture-tax-1040-text-with-ssn.pdf", path.read_bytes(), "application/pdf")},
        data={"profile": "tax-1040-carryforward"},
    )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["code"] == GATE_CODES["SSN_DETECTED"]
    # Never echo raw SSN digits in the API error payload.
    assert "219" not in detail["message"]


def test_extract_route_requires_professional(client, main, monkeypatch):
    monkeypatch.setattr(main, "EXTRACT_SERVICE_KEY", "")
    main.ddb_put_user(
        "starter@example.com",
        {
            "name": "Starter",
            "pw": main._hash_password("TestPassword12!"),
            "tok": "tok_starter",
            "plan": "starter",
            "verified": True,
        },
    )
    client.cookies.set(main.SESSION_COOKIE, main._make_session("starter@example.com"))
    r = client.post(
        "/extract/tax-1040-carryforward",
        files={"file": ("x.pdf", b"%PDF-1.4\n", "application/pdf")},
        data={"profile": "tax-1040-carryforward"},
    )
    assert r.status_code == 403


@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_extract_stays_stub_when_service_key_set_but_live_flag_off(client, main, monkeypatch):
    """Phase 6 ZDR gate: Remy EXTRACT_SERVICE_KEY must not force live tax extract."""
    monkeypatch.setattr(main, "EXTRACT_SERVICE_KEY", "fake-service-key")
    monkeypatch.setattr(main, "TAX_1040_LIVE_EXTRACT_ENABLED", False)
    called = {"n": 0}

    def _boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("must not proxy tax PDF without TAX_1040_LIVE_EXTRACT")

    monkeypatch.setattr(main.requests, "post", _boom)
    _session_pro(client, main, "stub-gate@example.com")
    root = _fixture_dir()
    path = root / "fixture-tax-1040-smoke.pdf"
    r = client.post(
        "/extract/tax-1040-carryforward",
        files={"file": ("fixture-tax-1040-smoke.pdf", path.read_bytes(), "application/pdf")},
        data={"profile": "tax-1040-carryforward"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["providerMeta"]["provider"] == "stub"
    assert called["n"] == 0
    assert "TAX_1040_LIVE_EXTRACT" in " ".join(body.get("warnings") or [])


@pytest.mark.skipif(_fixture_dir() is None, reason="text-pdf-gate fixtures not on disk")
def test_extract_rejects_oversize(client, main, monkeypatch):
    monkeypatch.setattr(main, "EXTRACT_SERVICE_KEY", "")
    monkeypatch.setattr(main, "TAX_1040_MAX_UPLOAD_BYTES", 100)
    _session_pro(client, main, "bigfile@example.com")
    root = _fixture_dir()
    path = root / "fixture-tax-1040-smoke.pdf"
    assert path.stat().st_size > 100
    r = client.post(
        "/extract/tax-1040-carryforward",
        files={"file": ("fixture-tax-1040-smoke.pdf", path.read_bytes(), "application/pdf")},
        data={"profile": "tax-1040-carryforward"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "FILE_TOO_LARGE"
