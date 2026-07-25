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
