"""Report gates (CPA Briefing + Position Documentation).

PHASE 1b (single plan, Nov 2026): these were Enterprise-only. TaxStat360 now has
one plan, so the gate is "any paid plan": pro / professional / enterprise pass,
starter (the lapsed-subscription fallback) and no session are refused.
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


def test_cpa_briefing_authorize_allows_professional_now(client, main):
    _session_user(client, main, "pro@example.com", plan="professional")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 200
    assert r.json()["plan"] == "professional"


def test_cpa_briefing_authorize_allows_enterprise(client, main):
    _session_user(client, main, "ent@example.com", plan="enterprise")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["feature"] == "cpa-briefing"
    assert r.json()["plan"] == "enterprise"


def test_cpa_briefing_authorize_allows_pro(client, main):
    _session_user(client, main, "pro1@example.com", plan="pro")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 200
    assert r.json()["plan"] == "pro"


def test_position_docs_authorize_blocks_starter_allows_pro(client, main):
    _session_user(client, main, "st2@example.com", plan="starter")
    assert client.post("/reports/position-docs/authorize").status_code == 403
    _session_user(client, main, "pro2@example.com", plan="pro")
    assert client.post("/reports/position-docs/authorize").status_code == 200


def test_cpa_briefing_route_registered(client):
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code != 404
