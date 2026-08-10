#!/usr/bin/env python3
"""Compare QuickBooks P&L parser output: legacy vs testing_migration response.

Usage (from taxstat360-api repo root, with a valid sandbox access token):

  export QB_REALM_ID='1234567890'
  export QB_ACCESS_TOKEN='eyJ...'
  export QB_YEAR='2025'   # optional tax year

  python3 scripts/qb_pl_migration_diff.py

Optional:
  QUICKBOOKS_ACCOUNTING_METHOD=Accrual
  QUICKBOOKS_MINORVERSION=75
  QUICKBOOKS_API_BASE=https://sandbox-quickbooks.api.intuit.com  # sandbox companies

Writes qb_pl_legacy.json and qb_pl_modernized.json in the current directory.
Exits 0 when revenue/expenses/net_profit match; 1 when they differ.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _bootstrap_env() -> None:
    """app.main requires Stripe + table env at import; use dummies for this CLI tool."""
    os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_dummy")
    os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_local_diff_script")
    os.environ.setdefault("SECRET_KEY", "local-diff-script")
    os.environ.setdefault("USERS_TABLE", "taxstat360-users")
    os.environ.setdefault("RECORDS_TABLE", "taxstat360-records")
    os.environ.setdefault("LOG_DIR", "/tmp/taxstat360-logs")
    os.environ.setdefault("QUICKBOOKS_CLIENT_ID", "local")
    os.environ.setdefault("QUICKBOOKS_CLIENT_SECRET", "local")


_bootstrap_env()

from app.main import (  # noqa: E402
    _parse_qb_pnl,
    _pnl_date_range,
    _pnl_result,
    _quickbooks_api_base,
    _quickbooks_pl_params,
)


def _clean_token(raw: str) -> str:
    """Strip whitespace; reject truncated copy-paste from DevTools (… in the middle)."""
    tok = (raw or "").strip().strip("'\"")
    if not tok:
        return ""
    if "\u2026" in tok or "…" in tok:
        raise SystemExit(
            "QB_ACCESS_TOKEN looks truncated (contains '…'). "
            "Do not copy from console summary — use Network tab or:\n"
            "  copy(localStorage.getItem('ts360_quickbooks_token'))"
        )
    if any(ord(c) > 127 for c in tok):
        raise SystemExit(
            "QB_ACCESS_TOKEN contains non-ASCII characters. "
            "Copy the full token only (no smart quotes or ellipsis)."
        )
    return tok


def _qb_api_bases() -> list[str]:
    """Hosts to try — explicit QUICKBOOKS_API_BASE, else production then sandbox."""
    explicit = os.environ.get("QUICKBOOKS_API_BASE", "").strip()
    if explicit:
        return [explicit.rstrip("/")]
    return [
        _quickbooks_api_base(),
        "https://sandbox-quickbooks.api.intuit.com",
    ]


def _fetch(realm: str, token: str, year: str | None, migration: bool) -> tuple[dict, dict]:
    start, end = _pnl_date_range(year)
    params = _quickbooks_pl_params(start, end)
    if migration:
        params = dict(params)
        params["testing_migration"] = ""
    elif "testing_migration" in params:
        params = {k: v for k, v in params.items() if k != "testing_migration"}

    last_body = ""
    for base in _qb_api_bases():
        r = requests.get(
            f"{base}/v3/company/{realm}/reports/ProfitAndLoss",
            params=params,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=60,
        )
        if r.ok:
            data = r.json()
            rev, exp, net = _parse_qb_pnl(data)
            parsed = _pnl_result(rev, exp, net_profit=net)
            if base != _qb_api_bases()[0]:
                print(f"Note: QuickBooks API succeeded via {base}", file=sys.stderr)
            return data, parsed
        last_body = r.text[:500]
        if r.status_code != 401 or len(_qb_api_bases()) == 1:
            break

    hint = (
        "\n\n401 tips: (1) token expires in ~60 min — run copy(localStorage.getItem('ts360_quickbooks_token')) "
        "then export QB_ACCESS_TOKEN=\"$(pbpaste)\" immediately; "
        "(2) sandbox companies need QUICKBOOKS_API_BASE=https://sandbox-quickbooks.api.intuit.com"
    )
    raise SystemExit(f"QuickBooks API error 401: {last_body}{hint}")


def main() -> int:
    realm = os.environ.get("QB_REALM_ID", "").strip()
    token = _clean_token(os.environ.get("QB_ACCESS_TOKEN", ""))
    year = os.environ.get("QB_YEAR", "").strip() or None
    if not realm or not token:
        print("Set QB_REALM_ID and QB_ACCESS_TOKEN", file=sys.stderr)
        return 2

    legacy_raw, legacy_parsed = _fetch(realm, token, year, migration=False)
    modern_raw, modern_parsed = _fetch(realm, token, year, migration=True)

    Path("qb_pl_legacy.json").write_text(json.dumps(legacy_raw, indent=2), encoding="utf-8")
    Path("qb_pl_modernized.json").write_text(
        json.dumps(modern_raw, indent=2), encoding="utf-8"
    )

    print("Legacy parsed:", json.dumps(legacy_parsed, indent=2))
    print("Modernized parsed:", json.dumps(modern_parsed, indent=2))

    keys = ("revenue", "expenses", "net_profit")
    match = all(legacy_parsed[k] == modern_parsed[k] for k in keys)
    if match:
        print("OK — parser totals match for legacy vs testing_migration")
        return 0
    print("MISMATCH — review qb_pl_legacy.json vs qb_pl_modernized.json")
    for k in keys:
        if legacy_parsed[k] != modern_parsed[k]:
            print(f"  {k}: legacy={legacy_parsed[k]} modernized={modern_parsed[k]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
