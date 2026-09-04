"""Server-side text-PDF gate for tax-1040 extract (Phase 3).

Twin of taxstat360/src/lib/pdfTextGate.js — Option C (block SSN / image-only).
Uses pypdf for text-layer extract (no OCR). Never log raw SSN or return text.
"""
from __future__ import annotations

from io import BytesIO
from typing import Any, TypedDict

from pypdf import PdfReader

from app.ssn_redact import classify_text_layer, count_alphanumeric, has_ssn_like

GATE_CODES = {
    "UNSUPPORTED_FILE_TYPE": "UNSUPPORTED_FILE_TYPE",
    "PDF_UNREADABLE": "PDF_UNREADABLE",
    "IMAGE_ONLY_PDF": "IMAGE_ONLY_PDF",
    "SSN_DETECTED": "SSN_DETECTED",
}

GATE_MESSAGES = {
    GATE_CODES["UNSUPPORTED_FILE_TYPE"]: (
        "Please upload a text PDF of last year’s Form 1040 "
        "(PDF only for now — images and scans are not supported yet)."
    ),
    GATE_CODES["PDF_UNREADABLE"]: (
        "We could not read that PDF. Try a different export, or enter carryforwards manually."
    ),
    GATE_CODES["IMAGE_ONLY_PDF"]: (
        "This looks like a scanned or image-only PDF. Text-PDF upload only for now — "
        "enter amounts manually, or upload a PDF with a selectable text layer."
    ),
    GATE_CODES["SSN_DETECTED"]: (
        "This PDF still contains a Social Security number in its text. "
        "Remove or mask the SSN on the return (or upload a redacted copy), then try again. "
        "Nothing was uploaded."
    ),
}


class GateOk(TypedDict):
    ok: bool
    text: str
    alnum: int


class GateFail(TypedDict):
    ok: bool
    code: str
    message: str
    alnum: int


def is_pdf_upload(raw: bytes, filename: str | None = None, content_type: str | None = None) -> bool:
    if raw[:4] == b"%PDF":
        return True
    ctype = (content_type or "").lower()
    if ctype in ("application/pdf", "application/x-pdf"):
        return True
    name = (filename or "").lower()
    return name.endswith(".pdf")


def extract_pdf_text_layer(raw: bytes) -> str:
    """Extract concatenated text layer from PDF bytes (no OCR)."""
    reader = PdfReader(BytesIO(raw))
    parts: list[str] = []
    for page in reader.pages:
        parts.append(page.extract_text() or "")
    return "\n".join(parts)


def gate_tax_1040_pdf_bytes(
    raw: bytes,
    *,
    filename: str | None = None,
    content_type: str | None = None,
    extract_text: Any | None = None,
) -> GateOk | GateFail:
    """
    Gate inbound tax-1040 upload bytes before stub/proxy.

    extract_text: optional callable(raw: bytes) -> str for unit tests.
    """
    if not is_pdf_upload(raw, filename=filename, content_type=content_type):
        return {
            "ok": False,
            "code": GATE_CODES["UNSUPPORTED_FILE_TYPE"],
            "message": GATE_MESSAGES[GATE_CODES["UNSUPPORTED_FILE_TYPE"]],
            "alnum": 0,
        }

    try:
        if extract_text is not None:
            text = extract_text(raw)
        else:
            text = extract_pdf_text_layer(raw)
    except Exception:
        return {
            "ok": False,
            "code": GATE_CODES["PDF_UNREADABLE"],
            "message": GATE_MESSAGES[GATE_CODES["PDF_UNREADABLE"]],
            "alnum": 0,
        }

    alnum = count_alphanumeric(text)
    if classify_text_layer(text) == "image-only":
        return {
            "ok": False,
            "code": GATE_CODES["IMAGE_ONLY_PDF"],
            "message": GATE_MESSAGES[GATE_CODES["IMAGE_ONLY_PDF"]],
            "alnum": alnum,
        }

    if has_ssn_like(text):
        return {
            "ok": False,
            "code": GATE_CODES["SSN_DETECTED"],
            "message": GATE_MESSAGES[GATE_CODES["SSN_DETECTED"]],
            "alnum": alnum,
        }

    return {"ok": True, "text": text, "alnum": alnum}
