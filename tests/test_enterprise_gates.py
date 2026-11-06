"""Report gates (CPA Briefing + Position Documentation).

PHASE 1b (single plan, Nov 2026): these were Enterprise-only. TaxStat360 now has
one plan, "pro": it passes; "starter" (no subscription) and no session are refused.
Retired tier names are just unknown plans and are refused too.
"""


def _session_user(client, main, email, plan="professional"):
    main.ddb_put_user(
        email,
        {
            "name": "Gate Test",
            "pw": main._hash_password("TestPassword12!"),
            "tok": "tok_" + email,
            "plan": plan,
            "verified": True,
        },
    )
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))


def test_cpa_briefing_authorize_requires_auth(client, main):
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 401


def test_cpa_briefing_authorize_blocks_starter(client, main):
    _session_user(client, main, "st@example.com", plan="starter")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 403
    assert "plan" in (r.json().get("detail") or "").lower()


def test_cpa_briefing_authorize_reads_retired_tiers_as_pro(client, main):
    # Accounts created under the old tiers (staff accounts among them) are the one
    # plan now; the stored name is rewritten on their next login.
    for tier in ("professional", "enterprise"):
        _session_user(client, main, f"{tier}@example.com", plan=tier)
        r = client.post("/reports/cpa-briefing/authorize")
        assert r.status_code == 200
        assert r.json()["plan"] == "pro"


def test_cpa_briefing_authorize_allows_pro(client, main):
    _session_user(client, main, "pro1@example.com", plan="pro")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["feature"] == "cpa-briefing"
    assert r.json()["plan"] == "pro"


def test_position_docs_authorize_blocks_starter_allows_pro(client, main):
    _session_user(client, main, "st2@example.com", plan="starter")
    assert client.post("/reports/position-docs/authorize").status_code == 403
    _session_user(client, main, "pro2@example.com", plan="pro")
    assert client.post("/reports/position-docs/authorize").status_code == 200


def test_cpa_briefing_route_registered(client):
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code != 404
