"""Route-registration regression guard.

A past MFA refactor dropped /aria and /auth/verification-status from the build,
and because backend deploys are a manual file copy with no CI gate, the missing
routes shipped silently (live 404s). These tests fail loudly if any critical
route stops being registered, so that regression cannot ship unnoticed again.

A 404 means the path is not registered. 401/403/405 mean it IS registered but
gated or method-restricted (which is fine). So for auth-gated routes we assert
"not 404"; for the public verification-status route we assert an exact 200.
"""


def test_aria_route_registered(client):
    # Unauthenticated -> 401 (registered, auth required). 404 would mean dropped.
    r = client.post("/aria", json={"messages": []})
    assert r.status_code != 404, "/aria route is missing (dropped from the build)"
    assert r.status_code == 401, r.text


def test_verification_status_route_registered(client):
    # Drives the "confirm your email" banner; must stay registered.
    r = client.get("/auth/verification-status")
    assert r.status_code != 404, "/auth/verification-status route is missing"
    assert r.status_code == 200, r.text


def test_core_routes_registered(client):
    # Sanity controls: prove the app, auth, and routing table are intact.
    for method, path in (("GET", "/auth/me"), ("GET", "/records")):
        r = client.request(method, path)
        assert r.status_code != 404, f"{method} {path} route is missing (dropped)"
