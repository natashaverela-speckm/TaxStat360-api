"""AUDIT N-2 BACKEND FIX (Jul 2026): pin the current-law brief in ARIA_SYSTEM.

The Aria model previously answered with repealed pre-OBBBA law (captured live:
"20% bonus depreciation" for 2026). These tests fail if the brief is removed or
if an annual update misses a key figure. ANNUAL MAINTENANCE: when TAX_TABLES in
the frontend change each January, update ARIA_SYSTEM and these markers together.
"""
from app.main import ARIA_SYSTEM


def test_brief_present_and_supersedes_training():
    assert "CURRENT LAW" in ARIA_SYSTEM
    assert "SUPERSEDES" in ARIA_SYSTEM


def test_bonus_depreciation_is_obbba_current():
    assert "100%" in ARIA_SYSTEM
    assert "Jan 19, 2025" in ARIA_SYSTEM
    assert "phase-down is repealed" in ARIA_SYSTEM


def test_2026_figures_pinned():
    # The figures most likely to be silently wrong in a stale model — and the
    # ones this audit found wrong elsewhere in the product.
    for marker in (
        "$256,000",   # §461(l) single — OBBBA reset DOWN (Rev. Proc. 2025-32 §4.31)
        "$512,000",   # §461(l) MFJ
        "$40,400",    # SALT cap (OBBBA §70120)
        "$505,000",   # SALT phase-down threshold
        "$24,500",    # 401(k) deferral (Notice 2025-67)
        "$16,100",    # standard deduction single (Rev. Proc. 2025-32)
        "$640,600",   # 37% bracket start single
        "$2,200",     # child tax credit
    ):
        assert marker in ARIA_SYSTEM, marker


def test_niche_scorp_and_real_estate_rules_present():
    assert "\u00a71368(c)" in ARIA_SYSTEM          # E&P dividend ordering
    assert "\u00a7162(l)(5)(A)" in ARIA_SYSTEM      # SEHI wage cap
    assert "NEVER applies to a corporation" in ARIA_SYSTEM  # hire-your-children FICA
    assert "750 hours" in ARIA_SYSTEM               # REPS
    assert "7 days" in ARIA_SYSTEM                  # STR exception


def test_unknown_figures_deferred_to_tax_tracker():
    assert "Tax Tracker" in ARIA_SYSTEM


# FOURTH READ (14 Sep 2026): the server-side copy of the frontend GROUNDING RULES.
# The 12 Sep closeout relied on the frontend sending the rules with every turn; this
# pins a backend copy so a client that omits them still gets a grounded model.

def test_grounding_rules_present_server_side():
    assert "GROUNDING RULES" in ARIA_SYSTEM
    for n in range(1, 12):
        assert f"\n{n}. " in ARIA_SYSTEM, f"rule {n} missing"


def test_no_arithmetic_and_no_memory_figures():
    assert "Do NOT perform tax arithmetic" in ARIA_SYSTEM
    assert "from memory" in ARIA_SYSTEM


def test_fabricated_authority_rule():
    # 11 Sep HARD FAIL: the model summarised a court case that does not exist.
    assert "cannot confirm what that authority says" in ARIA_SYSTEM
    assert "Never state what a court held" in ARIA_SYSTEM


def test_rule_7_carve_out_names_the_rules_that_cite_authorities():
    # Third pass (14 Sep 2026): rule 9 names §163(j), §531, §541, §168(k) and §179. Without
    # the carve-out, rule 7 ("do NOT characterise ANY legal authority ... unless its text is
    # in the message") contradicts rule 9's instruction to say those items are not modeled.
    assert "in rules 8 and 9 of this message may be relied on" in ARIA_SYSTEM


def test_nonexistent_rule_is_named_as_nonexistent():
    assert "SAY IT DOES NOT EXIST" in ARIA_SYSTEM
    assert "no percentage safe harbour" in ARIA_SYSTEM
    assert "§1.162-7" in ARIA_SYSTEM


def test_not_modeled_list_covers_the_limitations_page():
    # Mirrors the FAQ "What does TaxStat360 not calculate?" and closes the D3 wobble
    # ("I cannot confirm whether any deduction for your age was applied").
    for marker in (
        "DOES NOT MODEL",
        "senior deduction",
        "NEVER applied",
        "not that you cannot confirm",
        "tips, overtime or car-loan interest",
        "§163(j)",
        "§531",
        "§541",
        "NOT capped",
    ):
        assert marker in ARIA_SYSTEM, marker


def test_no_audit_framing_rule():
    assert "audit risk" in ARIA_SYSTEM
    assert "never use those phrases" in ARIA_SYSTEM


def test_why_questions_answered_only_from_limitation_lines():
    assert "limitation lines" in ARIA_SYSTEM
    assert "Tax Waterfall" in ARIA_SYSTEM


def test_prompt_stays_within_a_sane_token_budget():
    # Guard against the brief growing until it crowds out the 900-token reply budget.
    assert len(ARIA_SYSTEM) < 12000
