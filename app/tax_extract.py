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
MAX_TEXT_CHARS = 280_000

# ── Field contracts ────────────────────────────────────────────────────────────
# Mirrors main.py TAX_1040_REVIEW_FIELD_KEYS / frontend TAX_1040_REVIEW_FIELDS.
# (name, json type, where it comes from) — the "where" goes into the prompt so the
# model reads the right line instead of guessing.
REVIEW_FIELDS: list[tuple[str, str, str]] = [
    ("taxYear", "integer", "the tax year printed at the top of Form 1040"),
    ("filingStatus", "string", "Form 1040 filing status, one of single, mfj, mfs, hoh, qss. The text layer usually lists ALL five labels whether or not their box is checked, so do not pick a status just because its label appears. Decide from (a) an explicit mark next to one label (X, check, 'checked', or a '[checked: ...]' note), or (b) the standard deduction on Form 1040 line 12: 2025 returns 15,750 = single or mfs, 31,500 = mfj or qss, 23,625 = hoh; 2024 returns 14,600 = single or mfs, 29,200 = mfj or qss, 21,900 = hoh (a larger amount means an additional age/blind deduction was added to one of these). A spouse name or a second SSN line means mfj. If (a) and (b) disagree or neither is available, choose by (b) and set confidence to 0.4 or lower"),
    ("dependents", "integer", "number of dependents listed on Form 1040 who are under 17 (child tax credit box checked); 0 if none"),
    ("w2Wages", "number", "Form 1040 line 1a (or line 1z), total wages"),
    ("w2Withheld", "number", "Form 1040 line 25d, total federal income tax withheld (W-2, 1099 and other forms)"),
    ("officerW2", "number", "wages on a W-2 whose employer is the taxpayer's own S corporation (an S corporation whose K-1 is in the package); null if no S-Corp K-1 is present"),
    ("schedCGross", "number", "Schedule C line 1 gross receipts (sum if several Schedules C)"),
    ("schedCNet", "number", "Schedule C line 31 net profit or loss (sum if several; losses negative)"),
    ("k1ScorpOrdinary", "number", "Schedule K-1 (Form 1120-S) box 1 ordinary business income (loss), summed across S-Corp K-1s; a loss, printed in parentheses or with a minus sign, is negative. If only Schedule E Part II line 28 is available: column (k) is income (positive) and columns (g) and (i) are LOSSES, so an amount in column (i) must be returned as a negative number even though it is printed without a sign. Never Schedule E line 32, 41 or 43, which combine other items"),
    ("k1PartnershipOrdinary", "number", "Schedule K-1 (Form 1065) box 1 ordinary business income (loss), summed across partnership K-1s, or Schedule E Part II line 28 rows marked P in column (b) (columns (g)/(i) are losses, negative). Null when the only K-1 is from an S corporation (an S in column (b)); never copy the S-Corp figure here"),
    ("interestIncome", "number", "Form 1040 line 2b taxable interest"),
    ("dividends", "number", "Form 1040 line 3b ordinary dividends"),
    ("qualifiedDividends", "number", "Form 1040 line 3a qualified dividends"),
    ("capitalGain", "number", "Form 1040 line 7a capital gain or (loss); a loss is negative"),
    ("unrecaptured1250Gain", "number", "Schedule D line 19 unrecaptured section 1250 gain (also the Unrecaptured Section 1250 Gain Worksheet total); null if Schedule D line 19 is blank"),
    ("gain4797", "number", "Schedule 1 line 4 other gains or (losses) from Form 4797; a loss is negative"),
    ("otherIncome", "number", "the sum of Form 1040 lines 4b, 5b and 6b (taxable IRA, pension and social security) plus Schedule 1 lines 1, 2a, 6, 7 and 9; exclude Schedule 1 lines 3, 4 and 5 which are captured elsewhere"),
    ("schedEPropertyCount", "integer", "number of rental properties listed on Schedule E Part I"),
    ("schedERent", "number", "Schedule E line 23a, total rents received for all properties (the sum of line 3 across every property column and page)"),
    ("schedEExpenses", "number", "Schedule E line 23e total expenses MINUS line 23d depreciation, all properties (lines 5 through 17 and 19 summed across every property)"),
    ("schedEDepreciation", "number", "Schedule E line 23d, total depreciation (line 18) for all properties"),
    ("rentalBuildingBasis", "number", "depreciable basis of the rental buildings from the depreciation schedule or Form 4562, summed; null if not shown"),
    ("shortTermRental", "boolean", "true only if the package states an average rental period of 7 days or less for a property; otherwise false"),
    ("realEstateProfessional", "boolean", "true if the rental losses were deducted in full as nonpassive because the taxpayer is a real estate professional: Schedule E line 43 (reconciliation for real estate professionals) has an amount, or Schedule E Part I losses flow to line 26 in full with no Form 8582 in the package, or the occupation reads real estate professional. False when Form 8582 limits the rental loss"),
    ("depreciationTotal", "number", "Form 4562 line 22 total depreciation, SUMMED across every Form 4562 in the package (tax software prints one per property or activity)"),
    ("sec179", "number", "Form 4562 line 12 section 179 expense deduction"),
    ("qbiDeduction", "number", "Form 1040 line 13 qualified business income deduction"),
    ("selfEmpRetirement", "number", "Schedule 1 line 16 self-employed SEP, SIMPLE and qualified plans"),
    ("hsaDeduction", "number", "Schedule 1 line 13 health savings account deduction"),
    ("selfEmpHealthIns", "number", "Schedule 1 line 17 self-employed health insurance deduction"),
    ("itemizedDeductions", "number", "Schedule A line 17 total itemized deductions, only when Schedule A is in the package and Form 1040 line 12e equals it; null when the standard deduction was taken"),
    ("homeOfficeClaimed", "boolean", "true if Form 8829 is present or Schedule C line 30 is non-zero"),
    ("agi", "number", "Form 1040 line 11 adjusted gross income"),
    ("totalTax", "number", "Form 1040 line 24 total tax, the sum of lines 22 and 23. Not line 16 (income tax before credits and other taxes)"),
    ("estimatedPaymentsMade", "number", "Form 1040 line 26 estimated tax payments"),
    ("underpaymentPenalty", "number", "Form 1040 line 38 estimated tax penalty"),
    ("priorPassiveLossCarryforward", "number", "Form 8582 unallowed passive losses carried to next year (Form 8582 worksheet or Part VII), only when Form 8582 is in the package. Null when there is no Form 8582, for example a real estate professional whose rental losses are nonpassive. Never Schedule E line 22, 25, 26 or 43"),
    ("capLossCarryforwardST", "number", "Schedule D short-term capital loss carryover to next year"),
    ("capLossCarryforwardLT", "number", "Schedule D long-term capital loss carryover to next year"),
    ("nolCarryforward", "number", "net operating loss carryforward shown on an NOL statement"),
    ("priorYearQBILoss", "number", "the qualified business (loss) carryforward TO next year: Form 8995 line 16 (or Form 8995-A line 40), also shown on the carryover worksheet as QBI loss carryover. Not Form 8995 line 3, which is the carryforward from the prior year"),
]

CARRYFORWARD_FIELDS: list[tuple[str, str, str]] = [
    ("priorPassiveLossCarryforward", "number", "Form 8582 unallowed passive losses carried to next year (Form 8582 worksheet or Part VII), only when Form 8582 is in the package. Null when there is no Form 8582, for example a real estate professional whose rental losses are nonpassive. Never Schedule E line 22, 25, 26 or 43"),
    ("priorSuspendedLoss", "number", "suspended loss from Form 8582 worksheet, if separately shown"),
    ("capLossCarryforwardST", "number", "Schedule D short-term capital loss carryover to next year"),
    ("capLossCarryforwardLT", "number", "Schedule D long-term capital loss carryover to next year"),
    ("nolCarryforward", "number", "net operating loss carryforward shown on an NOL statement"),
    ("priorYearQBILoss", "number", "the qualified business (loss) carryforward TO next year: Form 8995 line 16 (or Form 8995-A line 40), also shown on the carryover worksheet as QBI loss carryover. Not Form 8995 line 3, which is the carryforward from the prior year"),
    ("priorYearTax", "number", "Form 1040 line 24 total tax"),
    ("priorYearAGI", "number", "Form 1040 line 11 adjusted gross income"),
]

# ── Entity returns (PHASE 2b) ──────────────────────────────────────────────────
# An S-Corp or partnership owner's strategy lives on the entity return, not the
# 1040: officer pay vs. distributions, what the entity already deducts, and what
# Form 4562 shows was placed in service. Same privacy contract; EINs are fine,
# SSNs are masked by the same path, and no names are asked for.
SCORP_FIELDS: list[tuple[str, str, str]] = [
    ("taxYear", "integer", "the tax year printed at the top of Form 1120-S"),
    ("shareholderCount", "integer", "Form 1120-S item I, number of shareholders (or the number of Schedules K-1 attached)"),
    ("grossReceipts", "number", "Form 1120-S line 1a gross receipts or sales"),
    ("totalIncome", "number", "Form 1120-S line 6 total income"),
    ("officerCompensation", "number", "Form 1120-S line 7 compensation of officers (Form 1125-E total)"),
    ("salariesWages", "number", "Form 1120-S line 8 salaries and wages, excluding officers"),
    ("rentsPaid", "number", "Form 1120-S line 11 rents"),
    ("taxesAndLicenses", "number", "Form 1120-S line 12 taxes and licenses"),
    ("depreciation", "number", "Form 1120-S line 14 depreciation"),
    ("sec179", "number", "Schedule K line 11 section 179 deduction (or Form 4562 line 12)"),
    ("bonusDepreciation", "number", "Form 4562 line 14 special depreciation allowance; null if Form 4562 is not in the package"),
    ("pensionProfitSharing", "number", "Form 1120-S line 17 pension, profit-sharing, etc., plans"),
    ("employeeBenefits", "number", "Form 1120-S line 18 employee benefit programs"),
    ("otherDeductions", "number", "Form 1120-S line 19 other deductions"),
    ("totalDeductions", "number", "Form 1120-S line 20 total deductions"),
    ("ordinaryBusinessIncome", "number", "Form 1120-S line 21 ordinary business income or loss (losses negative)"),
    ("shareholderHealthIns", "number", "health insurance premiums for more-than-2% shareholders that were INCLUDED IN OFFICER WAGES and deducted, from Schedule K-1 box 17 code AD or a wages statement; null if not shown. Do not use a Schedule M-1 or M-2 nondeductible line for this field"),
    ("nondeductibleExpenses", "number", "Schedule K-1 box 16 code C nondeductible expenses (also Schedule M-1 line 3 or Schedule M-2 line 5 other reductions), total; null if none"),
    ("nondeductibleHealthIns", "number", "the health, medical or life insurance portion of the nondeductible expenses, from the Schedule M-1 line 3 or M-2 line 5 statement (a line such as 'Health and Life Insurance'); null if there is no such line"),
    ("distributions", "number", "Schedule K line 16d distributions (or Schedule M-2 distributions), total to all shareholders"),
    ("loansToShareholders", "number", "Schedule L line 7 loans to shareholders, end of year"),
    ("loansFromShareholders", "number", "Schedule L line 19 loans from shareholders, end of year"),
    ("totalAssets", "number", "Schedule L line 15 total assets, end of year; null if Schedule L is not completed"),
    ("vehicleOrTravel", "number", "the sum of any 'auto', 'vehicle', 'travel' or 'meals' lines on the other-deductions statement; null if no such statement"),
    ("homeOfficeOrAccountablePlan", "boolean", "true if the other-deductions statement shows a line for office-in-home, accountable plan, or employee expense reimbursement"),
]

PARTNERSHIP_FIELDS: list[tuple[str, str, str]] = [
    ("taxYear", "integer", "the tax year printed at the top of Form 1065"),
    ("partnerCount", "integer", "Form 1065 item I, number of Schedules K-1 attached"),
    ("grossReceipts", "number", "Form 1065 line 1a gross receipts or sales"),
    ("totalIncome", "number", "Form 1065 line 8 total income"),
    ("guaranteedPayments", "number", "Form 1065 line 10 guaranteed payments to partners"),
    ("salariesWages", "number", "Form 1065 line 9 salaries and wages, other than to partners"),
    ("rentsPaid", "number", "Form 1065 line 13 rent"),
    ("taxesAndLicenses", "number", "Form 1065 line 14 taxes and licenses"),
    ("depreciation", "number", "Form 1065 line 16c depreciation"),
    ("sec179", "number", "Schedule K line 12 section 179 deduction (or Form 4562 line 12)"),
    ("bonusDepreciation", "number", "Form 4562 line 14 special depreciation allowance; null if Form 4562 is not in the package"),
    ("retirementPlans", "number", "Form 1065 line 18 retirement plans, etc."),
    ("employeeBenefits", "number", "Form 1065 line 19 employee benefit programs"),
    ("otherDeductions", "number", "Form 1065 line 20 other deductions"),
    ("totalDeductions", "number", "Form 1065 line 21 total deductions"),
    ("ordinaryBusinessIncome", "number", "Form 1065 line 22 ordinary business income or loss (losses negative)"),
    ("netRentalRealEstate", "number", "Schedule K line 2 net rental real estate income or loss (Form 8825); null if none"),
    ("selfEmploymentEarnings", "number", "Schedule K line 14a net earnings from self-employment"),
    ("distributions", "number", "Schedule K line 19a distributions of cash and marketable securities"),
    ("totalAssets", "number", "Schedule L line 14 total assets, end of year; null if Schedule L is not completed"),
    ("vehicleOrTravel", "number", "the sum of any 'auto', 'vehicle', 'travel' or 'meals' lines on the other-deductions statement; null if no such statement"),
]

CCORP_FIELDS: list[tuple[str, str, str]] = [
    ("taxYear", "integer", "the tax year printed at the top of Form 1120"),
    ("grossReceipts", "number", "Form 1120 line 1a gross receipts or sales"),
    ("totalIncome", "number", "Form 1120 line 11 total income"),
    ("officerCompensation", "number", "Form 1120 line 12 compensation of officers (Form 1125-E total)"),
    ("salariesWages", "number", "Form 1120 line 13 salaries and wages, excluding officers"),
    ("rentsPaid", "number", "Form 1120 line 16 rents"),
    ("taxesAndLicenses", "number", "Form 1120 line 17 taxes and licenses"),
    ("charitableContributions", "number", "Form 1120 line 19 charitable contributions"),
    ("depreciation", "number", "Form 1120 line 20 depreciation"),
    ("sec179", "number", "Form 4562 line 12 section 179 expense deduction; null if Form 4562 is not in the package"),
    ("bonusDepreciation", "number", "Form 4562 line 14 special depreciation allowance; null if Form 4562 is not in the package"),
    ("pensionProfitSharing", "number", "Form 1120 line 23 pension, profit-sharing, etc., plans"),
    ("employeeBenefits", "number", "Form 1120 line 24 employee benefit programs"),
    ("otherDeductions", "number", "Form 1120 line 26 other deductions"),
    ("totalDeductions", "number", "Form 1120 line 27 total deductions"),
    ("taxableIncome", "number", "Form 1120 line 30 taxable income (losses negative)"),
    ("totalTax", "number", "Form 1120 line 31 total tax"),
    ("dividendsPaid", "number", "Schedule M-2 line 5 distributions (cash dividends paid to shareholders); null if Schedule M-2 is not completed"),
    ("loansToShareholders", "number", "Schedule L line 7 loans to shareholders, end of year"),
    ("loansFromShareholders", "number", "Schedule L line 19 loans from shareholders, end of year"),
    ("retainedEarnings", "number", "Schedule L line 25 retained earnings, end of year"),
    ("totalAssets", "number", "Schedule L line 15 total assets, end of year; null if Schedule L is not completed"),
    ("vehicleOrTravel", "number", "the sum of any 'auto', 'vehicle', 'travel' or 'meals' lines on the other-deductions statement; null if no such statement"),
    ("homeOfficeOrAccountablePlan", "boolean", "true if the other-deductions statement shows a line for office-in-home, accountable plan, or employee expense reimbursement"),
]

# ── Profit & loss export (simple flow) ────────────────────────────────────────
# A P&L exported from QuickBooks, Xero, Wave or FreshBooks, read so the member
# never types the numbers. Totals only; no customer or vendor names are asked for.
PNL_FIELDS: list[tuple[str, str, str]] = [
    ("periodLabel", "string", "the reporting period printed under the report title, as written (for example 'January 1 - October 31, 2026'); null if not shown"),
    ("periodYear", "integer", "the calendar year the period ends in"),
    ("totalIncome", "number", "Total Income / Total Revenue / Total Sales line (before cost of goods sold)"),
    ("costOfGoodsSold", "number", "Total Cost of Goods Sold / Cost of Sales; null if the report has no such section"),
    ("grossProfit", "number", "Gross Profit line; null if not shown"),
    ("totalExpenses", "number", "Total Expenses / Total Operating Expenses line (all expenses below gross profit, including payroll)"),
    ("officerCompensation", "number", "officer compensation / owner salary / shareholder wages line, if any; null if no such line"),
    ("wagesOther", "number", "other payroll wages or salaries lines (not officers), summed; null if none"),
    ("payrollTaxes", "number", "payroll tax expense lines, summed; null if none"),
    ("depreciation", "number", "depreciation expense line; null if none"),
    ("rentExpense", "number", "rent or lease expense line; null if none"),
    ("interestExpense", "number", "interest expense line; null if none"),
    ("otherIncome", "number", "Total Other Income line (the section below Net Operating Income: affiliate income, interest, other income); null if the report has no such section"),
    ("otherExpenses", "number", "Total Other Expenses line (the section below Net Operating Income); null if the report has no such section"),
    ("netOperatingIncome", "number", "Net Operating Income line, before other income and other expenses; null if not shown"),
    ("netIncome", "number", "the final Net Income / Net Profit line at the bottom of the report, after other income and other expenses (losses negative)"),
]

PROFILES: dict[str, list[tuple[str, str, str]]] = {
    "tax-1040-review": REVIEW_FIELDS,
    "tax-1040-carryforward": CARRYFORWARD_FIELDS,
    "tax-1120s-review": SCORP_FIELDS,
    "tax-1065-review": PARTNERSHIP_FIELDS,
    "tax-1120-review": CCORP_FIELDS,
    "pnl-summary": PNL_FIELDS,
}

_DOCUMENT_KIND = {
    "tax-1040-review": "United States federal individual income tax return (Form 1040 package)",
    "tax-1040-carryforward": "United States federal individual income tax return (Form 1040 package)",
    "tax-1120s-review": "United States S corporation income tax return (Form 1120-S package with Schedules K, K-1, L, M-2 and Form 4562)",
    "tax-1065-review": "United States partnership return of income (Form 1065 package with Schedules K, K-1, L and Form 4562)",
    "tax-1120-review": "United States corporation income tax return (Form 1120 package with Schedules L, M-1, M-2, Form 1125-E and Form 4562)",
    "pnl-summary": "profit and loss statement exported from accounting software such as QuickBooks, Xero, Wave or FreshBooks",
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
    kind = _DOCUMENT_KIND.get(profile, "United States federal tax return")
    return (
        f"You read the text layer of a {kind} and return the figures asked for as JSON. Rules:\n"
        "1. Use only what the document states. If a figure is not present, return null for it "
        "and a confidence of 0. Never estimate, derive, or carry a figure from one line to another "
        "unless the field definition says to sum or subtract.\n"
        "2. Amounts are plain numbers in dollars (no commas, no $). Losses and negative lines are negative: "
        "an amount printed in parentheses such as (12,345), with a leading minus, or on a line whose label says "
        "'loss' when the loss column is filled, is returned as a negative number. Schedule K-1 box 1 and "
        "Schedule C line 31 are the usual cases.\n"
        "3. confidence is 0 to 1 per field: 1 when the line is unambiguous, lower when the text layer "
        "is garbled, the line is inferred from context, or several candidates exist.\n"
        "4. Return nothing but the JSON object. Do not include names, addresses, or identification numbers.\n"
        "5. Checkboxes: a label appearing in the text does not mean its box is checked. Only a mark "
        "beside the label, a '[checked: ...]' note, or a figure elsewhere on the return that implies it counts.\n"
        "6. One figure belongs to one field. Never place the same amount in two fields that describe "
        "different things (for example an S-Corp K-1 and a partnership K-1); when a figure fits only one, the other is null.\n"
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


def _parse_amount(v: Any) -> float:
    """'12,345' → 12345.0; '(12,345)' and '-12,345' and '12,345-' → -12345.0; '$' ignored."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    t = str(v).strip().replace(",", "").replace("$", "").replace(" ", "")
    neg = False
    if t.startswith("(") and t.endswith(")"):
        neg, t = True, t[1:-1]
    if t.endswith("-"):
        neg, t = True, t[:-1]
    if t.startswith("-"):
        neg, t = (not neg) if neg else True, t[1:]
    n = float(t)
    return -n if neg else n


def _coerce(profile: str, fields: dict[str, Any], confidence: dict[str, Any]) -> tuple[dict, dict]:
    out_f: dict[str, Any] = {}
    out_c: dict[str, float] = {}
    for key, typ, _d in PROFILES[profile]:
        v = fields.get(key)
        try:
            if v is None or v == "":
                out_f[key] = None
            elif typ == "number":
                out_f[key] = _parse_amount(v)
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
