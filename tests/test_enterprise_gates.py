"""Enterprise-only report gates (CPA Briefing + Position Documentation)."""


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


def test_cpa_briefing_authorize_blocks_professional(client, main):
    _session_user(client, main, "pro@example.com", plan="professional")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 403
    assert "Enterprise" in (r.json().get("detail") or "")


def test_cpa_briefing_authorize_allows_enterprise(client, main):
    _session_user(client, main, "ent@example.com", plan="enterprise")
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["feature"] == "cpa-briefing"
    assert r.json()["plan"] == "enterprise"


def test_position_docs_authorize_blocks_professional(client, main):
    _session_user(client, main, "pro2@example.com", plan="professional")
    r = client.post("/reports/position-docs/authorize")
    assert r.status_code == 403


def test_cpa_briefing_route_registered(client):
    r = client.post("/reports/cpa-briefing/authorize")
    assert r.status_code != 404
