"""
TaxStat360-native prior-year return extraction (PHASE 2, option B — Nov 2026).

Reads the figures the Prior-Year Review needs out of the TEXT LAYER of a Form 1040
package by asking an OpenAI model for a strictly-typed JSON object, one key per
review field, with a per-field confidence. This replaces the shared RepsRecord
Edge Function for TaxStat360's tax uploads so that tax documents never touch
RepsRecord's infrastructure.

Privacy contract (same as the Edge Function path, enforced here):
  * only the text layer is sent — never the PDF bytes;
  * SSN-like strings are masked before anything leaves the box, and the request is
    refused if any survive masking;
  * nothing is written to disk or to the database by this module — the caller keeps
    the returned figures only;
  * the call is made with the account's OpenAI API key; the operator must hold
    zero-data-retention terms for that key before TAX_1040_LIVE_EXTRACT is set
    (see main.py) — this module does not and cannot verify that.

Pure w.r.t. the app: no FastAPI, no DynamoDB. `post` is injectable for tests.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

import requests

from app.ssn_redact import redact_ssn_in_text, assert_no_ssn_remaining

logger = logging.getLogger("taxstat360.tax_extract")

OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"

# Keep the prompt within a sane budget: a 1040 package's text layer is usually
# 20–60k characters; anything past this is almost always state forms and
# worksheets that carry nothing the review needs.
MAX_TEXT_CHARS = 120_000

# ── Field contracts ────────────────────────────────────────────────────────────
# Mirrors main.py TAX_1040_REVIEW_FIELD_KEYS / frontend TAX_1040_REVIEW_FIELDS.
# (name, json type, where it comes from) — the "where" goes into the prompt so the
# model reads the right line instead of guessing.
REVIEW_FIELDS: list[tuple[str, str, str]] = [
    ("taxYear", "integer", "the tax year printed at the top of Form 1040"),
    ("filingStatus", "string", "Form 1040 filing status box: one of single, mfj, mfs, hoh, qss"),
    ("dependents", "integer", "number of dependents listed on Form 1040 who are under 17 (child tax credit box checked); 0 if none"),
    ("w2Wages", "number", "Form 1040 line 1a (or line 1z), total wages"),
    ("w2Withheld", "number", "Form 1040 line 25a, federal income tax withheld from W-2s"),
    ("officerW2", "number", "wages on a W-2 whose employer is the taxpayer's own S corporation (an S corporation whose K-1 is in the package); null if no S-Corp K-1 is present"),
    ("schedCGross", "number", "Schedule C line 1 gross receipts (sum if several Schedules C)"),
    ("schedCNet", "number", "Schedule C line 31 net profit or loss (sum if several; losses negative)"),
    ("k1ScorpOrdinary", "number", "Schedule K-1 (Form 1120-S) box 1 ordinary business income, summed across S-Corp K-1s"),
    ("k1PartnershipOrdinary", "number", "Schedule K-1 (Form 1065) box 1 ordinary business income, summed across partnership K-1s"),
    ("schedEPropertyCount", "integer", "number of rental properties listed on Schedule E Part I"),
    ("schedERent", "number", "Schedule E line 3 rents received, all properties"),
    ("schedEExpenses", "number", "Schedule E total expenses (line 20) MINUS depreciation (line 18), all properties"),
    ("schedEDepreciation", "number", "Schedule E line 18 depreciation, all properties"),
    ("rentalBuildingBasis", "number", "depreciable basis of the rental buildings from the depreciation schedule or Form 4562, summed; null if not shown"),
    ("shortTermRental", "boolean", "true only if the package states an average rental period of 7 days or less for a property; otherwise false"),
    ("depreciationTotal", "number", "Form 4562 line 22 total depreciation"),
    ("sec179", "number", "Form 4562 line 12 section 179 expense deduction"),
    ("qbiDeduction", "number", "Form 1040 line 13 qualified business income deduction"),
    ("selfEmpRetirement", "number", "Schedule 1 line 16 self-employed SEP, SIMPLE and qualified plans"),
    ("hsaDeduction", "number", "Schedule 1 line 13 health savings account deduction"),
    ("selfEmpHealthIns", "number", "Schedule 1 line 17 self-employed health insurance deduction"),
    ("homeOfficeClaimed", "boolean", "true if Form 8829 is present or Schedule C line 30 is non-zero"),
    ("agi", "number", "Form 1040 line 11 adjusted gross income"),
    ("totalTax", "number", "Form 1040 line 24 total tax"),
    ("estimatedPaymentsMade", "number", "Form 1040 line 26 estimated tax payments"),
    ("underpaymentPenalty", "number", "Form 1040 line 38 estimated tax penalty"),
    ("priorPassiveLossCarryforward", "number", "Form 8582 unallowed loss carried to next year"),
    ("capLossCarryforwardST", "number", "Schedule D short-term capital loss carryover to next year"),
    ("capLossCarryforwardLT", "number", "Schedule D long-term capital loss carryover to next year"),
    ("nolCarryforward", "number", "net operating loss carryforward shown on an NOL statement"),
    ("priorYearQBILoss", "number", "Form 8995 line 3 qualified business net loss carryforward"),
]

CARRYFORWARD_FIELDS: list[tuple[str, str, str]] = [
    ("priorPassiveLossCarryforward", "number", "Form 8582 unallowed loss carried to next year"),
    ("priorSuspendedLoss", "number", "suspended loss from Form 8582 worksheet, if separately shown"),
    ("capLossCarryforwardST", "number", "Schedule D short-term capital loss carryover to next year"),
    ("capLossCarryforwardLT", "number", "Schedule D long-term capital loss carryover to next year"),
    ("nolCarryforward", "number", "net operating loss carryforward shown on an NOL statement"),
    ("priorYearQBILoss", "number", "Form 8995 line 3 qualified business net loss carryforward"),
    ("priorYearTax", "number", "Form 1040 line 24 total tax"),
    ("priorYearAGI", "number", "Form 1040 line 11 adjusted gross income"),
]

PROFILES: dict[str, list[tuple[str, str, str]]] = {
    "tax-1040-review": REVIEW_FIELDS,
    "tax-1040-carryforward": CARRYFORWARD_FIELDS,
}


def field_keys(profile: str) -> list[str]:
    return [k for k, _t, _d in PROFILES[profile]]


def _json_schema(profile: str) -> dict[str, Any]:
    """Strict schema: every key present, value typed or null, plus a confidence map."""
    props: dict[str, Any] = {}
    conf: dict[str, Any] = {}
    for key, typ, _desc in PROFILES[profile]:
        props[key] = {"type": [typ, "null"]}
        conf[key] = {"type": "number"}
    keys = field_keys(profile)
    return {
        "name": "tax_return_fields",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "fields": {"type": "object", "additionalProperties": False, "properties": props, "required": keys},
                "confidence": {"type": "object", "additionalProperties": False, "properties": conf, "required": keys},
            },
            "required": ["fields", "confidence"],
        },
    }


def _system_prompt(profile: str) -> str:
    lines = "\n".join(f"- {k} ({t}): {d}" for k, t, d in PROFILES[profile])
    return (
        "You read the text layer of a United States federal individual income tax return "
        "(Form 1040 package) and return the figures asked for as JSON. Rules:\n"
        "1. Use only what the document states. If a figure is not present, return null for it "
        "and a confidence of 0. Never estimate, derive, or carry a figure from one line to another "
        "unless the field definition says to sum or subtract.\n"
        "2. Amounts are plain numbers in dollars (no commas, no $). Losses and negative lines are negative.\n"
        "3. confidence is 0 to 1 per field: 1 when the line is unambiguous, lower when the text layer "
        "is garbled, the line is inferred from context, or several candidates exist.\n"
        "4. Return nothing but the JSON object. Do not include names, addresses, or identification numbers.\n"
        f"Fields:\n{lines}"
    )


class ExtractError(Exception):
    """Raised for any failure the caller should surface as 'extract unavailable'."""


def prepare_text(text: str) -> str:
    """Mask SSN-like strings, refuse if any remain, and cap the length."""
    masked = redact_ssn_in_text(text or "")["text"]
    if not assert_no_ssn_remaining(masked):
        raise ExtractError("A Social Security number survived masking; the document was not sent.")
    if len(masked) > MAX_TEXT_CHARS:
        masked = masked[:MAX_TEXT_CHARS]
    return masked


def _coerce(profile: str, fields: dict[str, Any], confidence: dict[str, Any]) -> tuple[dict, dict]:
    out_f: dict[str, Any] = {}
    out_c: dict[str, float] = {}
    for key, typ, _d in PROFILES[profile]:
        v = fields.get(key)
        try:
            if v is None or v == "":
                out_f[key] = None
            elif typ == "number":
                out_f[key] = float(str(v).replace(",", "").replace("$", ""))
            elif typ == "integer":
                out_f[key] = int(float(str(v)))
            elif typ == "boolean":
                out_f[key] = bool(v) if isinstance(v, bool) else str(v).strip().lower() in ("true", "yes", "1")
            else:
                out_f[key] = str(v).strip().lower() or None
        except (TypeError, ValueError):
            out_f[key] = None
        c = confidence.get(key, 0)
        try:
            c = float(c)
        except (TypeError, ValueError):
            c = 0.0
        out_c[key] = 0.0 if out_f[key] is None else max(0.0, min(1.0, c))
    if "filingStatus" in out_f and out_f["filingStatus"] not in (None, "single", "mfj", "mfs", "hoh", "qss"):
        out_f["filingStatus"] = None
        out_c["filingStatus"] = 0.0
    return out_f, out_c


def extract_fields_from_text(
    text: str,
    profile: str,
    *,
    api_key: str,
    model: str,
    post: Callable[..., Any] | None = None,
    timeout: int = 90,
) -> dict[str, Any]:
    """
    Returns the same envelope the Edge Function path returns:
      {ok, profile, fields, confidence, warnings, providerMeta, evidence}
    Raises ExtractError on any failure (the caller maps it to 503).
    """
    if profile not in PROFILES:
        raise ExtractError(f"Unknown profile {profile!r}")
    if not api_key:
        raise ExtractError("OPENAI_API_KEY is not configured")
    body = prepare_text(text)
    if len(body.strip()) < 40:
        raise ExtractError("The document has no readable text to extract from")

    payload = {
        "model": model,
        "temperature": 0,
        # Never let OpenAI keep this request in the organization's dashboard logs,
        # whatever the org-level "API call logging" setting says.
        "store": False,
        "messages": [
            {"role": "system", "content": _system_prompt(profile)},
            {"role": "user", "content": body},
        ],
        "response_format": {"type": "json_schema", "json_schema": _json_schema(profile)},
    }
    try:
        r = (post or requests.post)(   # resolved at call time so tests and ops can swap it
            OPENAI_CHAT_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=timeout,
        )
    except requests.RequestException as e:  # network, timeout
        logger.warning("tax extract request failed: %s", e)
        raise ExtractError("Extract service unreachable") from e
    if not getattr(r, "ok", False):
        logger.warning("tax extract openai: %s %s", getattr(r, "status_code", "?"), str(getattr(r, "text", ""))[:300])
        raise ExtractError("Extract service error")
    try:
        content = r.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("fields"), dict):
            raise ValueError("no fields object in model output")
        fields, confidence = _coerce(profile, parsed["fields"], parsed.get("confidence") or {})
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as e:
        logger.warning("tax extract: unparseable model output (%s)", e)
        raise ExtractError("Extract returned an unreadable result") from e

    found = sum(1 for v in fields.values() if v is not None)
    warnings = [
        "Figures were read from the document's text layer by a language model. Review every one before relying on it.",
        "Tax PDF is not stored (delete-after-processing).",
    ]
    if found == 0:
        warnings.append("No figures were recognised. Check that this is the federal return, not a state return or a transmittal page.")
    return {
        "ok": True,
        "profile": profile,
        "fields": fields,
        "confidence": confidence,
        "warnings": warnings,
        "providerMeta": {"provider": "openai", "model": model, "fieldsFound": found},
        "evidence": {"retained": False, "deletedAfterProcessing": True, "retention": "delete-after-processing"},
    }
