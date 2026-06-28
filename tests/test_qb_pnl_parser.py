"""QuickBooks ProfitAndLoss parser — legacy (v1) and modernized (v2) fixtures."""
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    with open(FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize(
    "fixture,rev,exp,net",
    [
        ("qb_pl_v1.json", 155000.0, 75000.0, 80000.0),
        ("qb_pl_v2.json", 155000.0, 75000.0, 80000.0),
    ],
)
def test_parse_qb_pnl_v1_and_v2_match(main, fixture, rev, exp, net):
    data = _load(fixture)
    got_rev, got_exp, got_net = main._parse_qb_pnl(data)
    assert got_rev == rev
    assert got_exp == exp
    assert got_net == net


def test_v1_and_v2_fixtures_produce_identical_totals(main):
    v1 = main._parse_qb_pnl(_load("qb_pl_v1.json"))
    v2 = main._parse_qb_pnl(_load("qb_pl_v2.json"))
    assert v1 == v2


def test_pnl_result_shape(main):
    out = main._pnl_result(100, 40, net_profit=60)
    assert out == {
        "revenue": 100.0,
        "expenses": 40.0,
        "net_profit": 60.0,
        "officer_salary": 0.0,
    }


def test_quickbooks_pl_params_migration_flag(main, monkeypatch):
    monkeypatch.delenv("QUICKBOOKS_TESTING_MIGRATION", raising=False)
    monkeypatch.delenv("QUICKBOOKS_MINORVERSION", raising=False)
    base = main._quickbooks_pl_params("2025-01-01", "2025-12-31")
    assert "testing_migration" not in base
    assert base["accounting_method"] == "Cash"

    monkeypatch.setenv("QUICKBOOKS_TESTING_MIGRATION", "1")
    monkeypatch.setenv("QUICKBOOKS_MINORVERSION", "75")
    mig = main._quickbooks_pl_params("2025-01-01", "2025-12-31")
    assert mig["testing_migration"] == ""
    assert mig["minorversion"] == "75"
