"""Pure SSN detect / redact helpers for the TaxStat360 text-PDF gate.

Twin of taxstat360/src/lib/ssnRedact.js — keep behavior in sync (Phase 0 lock).

Never log raw match["value"] outside tests. samples_masked are already masked.
"""
from __future__ import annotations

import re
from typing import Literal, TypedDict

TEXT_PDF_ALNUM_THRESHOLD = 40
SSN_REDACTION_MASK = "XXX-XX-XXXX"

_DASHED_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SPACED_RE = re.compile(r"\b\d{3}\s\d{2}\s\d{4}\b")
_UNDASHED_RE = re.compile(r"\b\d{9}\b")
_EIN_RE = re.compile(r"^\d{2}-\d{7}$")
_SSN_CONTEXT_RE = re.compile(r"\b(ssn|social\s+security(\s+number)?)\b", re.I)
# Chars before a candidate undashed match to search for SSN labels.
_CONTEXT_WINDOW = 80

_MASKED_PATTERNS = (
    re.compile(r"^X{3}-X{2}-X{4}$", re.I),
    re.compile(r"^\*{3}-\*{2}-\*{4}$"),
    re.compile(r"^#{3}-#{2}-#{4}$"),
    re.compile(r"^X{9}$", re.I),
    re.compile(r"^\*{9}$"),
    re.compile(r"^#{9}$"),
)


class SsnMatch(TypedDict):
    start: int
    end: int
    kind: Literal["dashed", "spaced", "undashed"]
    value: str


class RedactResult(TypedDict):
    text: str
    redacted_count: int
    samples_masked: list[str]


def count_alphanumeric(text: str | None) -> int:
    if not text:
        return 0
    return sum(1 for ch in text if ch.isalnum())


def classify_text_layer(
    text: str | None, threshold: int = TEXT_PDF_ALNUM_THRESHOLD
) -> Literal["text", "image-only"]:
    return "text" if count_alphanumeric(text) >= threshold else "image-only"


def _looks_already_masked(value: str) -> bool:
    v = value.strip()
    return any(p.match(v) for p in _MASKED_PATTERNS)


def _has_ssn_context_near(text: str, start: int) -> bool:
    window = text[max(0, start - _CONTEXT_WINDOW) : start]
    return bool(_SSN_CONTEXT_RE.search(window))


def detect_ssn_like(text: str | None) -> list[SsnMatch]:
    if not text:
        return []
    src = str(text)
    matches: list[SsnMatch] = []

    for kind, pattern in (("dashed", _DASHED_RE), ("spaced", _SPACED_RE)):
        for m in pattern.finditer(src):
            value = m.group(0)
            if _EIN_RE.match(value) or _looks_already_masked(value):
                continue
            matches.append(
                {
                    "start": m.start(),
                    "end": m.end(),
                    "kind": kind,  # type: ignore[typeddict-item]
                    "value": value,
                }
            )

    for m in _UNDASHED_RE.finditer(src):
        value = m.group(0)
        if _looks_already_masked(value):
            continue
        if not _has_ssn_context_near(src, m.start()):
            continue
        matches.append(
            {
                "start": m.start(),
                "end": m.end(),
                "kind": "undashed",
                "value": value,
            }
        )

    matches.sort(key=lambda h: (h["start"], -(h["end"] - h["start"])))
    deduped: list[SsnMatch] = []
    last_end = -1
    for hit in matches:
        if hit["start"] < last_end:
            continue
        deduped.append(hit)
        last_end = hit["end"]
    return deduped


def has_ssn_like(text: str | None) -> bool:
    return bool(detect_ssn_like(text))


def redact_ssn_in_text(text: str | None) -> RedactResult:
    src = "" if text is None else str(text)
    hits = detect_ssn_like(src)
    if not hits:
        return {"text": src, "redacted_count": 0, "samples_masked": []}

    out = src
    samples_masked: list[str] = []
    for hit in reversed(hits):
        out = out[: hit["start"]] + SSN_REDACTION_MASK + out[hit["end"] :]
        samples_masked.append(SSN_REDACTION_MASK)
    samples_masked.reverse()
    return {
        "text": out,
        "redacted_count": len(hits),
        "samples_masked": samples_masked,
    }


def assert_no_ssn_remaining(text: str | None) -> bool:
    return not has_ssn_like(text)
