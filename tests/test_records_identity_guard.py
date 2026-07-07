"""PHASE 2.2 IDENTITY GUARD (D-1 countermeasure) — /records account pinning.

The July 3 incident: a session identity flip mid-save filed records under a
different userId partition, which from the client looked like sibling
destruction (root-caused July 7; nothing was ever deleted). These tests pin
the countermeasure: the client states which account it believes each records
request is for; a mismatch is a loud 409, never a silent mis-file. An absent
pin keeps working (older clients / curl)."""


def _login(client, main, email="guard@example.com"):
    # House auth pattern (see test_change_email_auth.py): set the signed session
    # cookie directly — version-proof against TestClient Set-Cookie handling.
    main.ddb_put_user(email, {
        "name": "Guard Test",
        "pw": main._hash_password("TestPassword12!"),
        "verified": True,
        "plan": "starter",
    })
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def test_put_with_matching_expected_user_succeeds_and_pin_is_not_persisted(client, main):
    email = _login(client, main)
    r = client.put("/records", json={"id": 111, "name": "pinned save", "expectedUser": email})
    assert r.status_code == 200
    listing = client.get("/records").json()
    rec = next(x for x in listing if x["id"] == 111)
    assert "expectedUser" not in rec, "the pin is transport metadata, never stored"


def test_put_with_mismatched_expected_user_is_409_and_writes_nothing(client, main):
    _login(client, main)
    r = client.put("/records", json={"id": 222, "name": "wrong-account save",
                                     "expectedUser": "someoneelse@example.com"})
    assert r.status_code == 409
    assert "mismatch" in r.json()["detail"].lower()
    assert all(x["id"] != 222 for x in client.get("/records").json()), \
        "a 409 must reject BEFORE any write reaches the table"


def test_expected_user_comparison_is_normalized(client, main):
    email = _login(client, main, email="cased@example.com")
    # Casing/whitespace differences are not identity flips — _norm_email governs.
    r = client.put("/records", json={"id": 333, "expectedUser": "  Cased@Example.COM "})
    assert r.status_code == 200


def test_get_and_delete_honor_the_expected_user_header(client, main):
    email = _login(client, main)
    assert client.put("/records", json={"id": 444, "expectedUser": email}).status_code == 200

    ok = client.get("/records", headers={"X-Expected-User": email})
    assert ok.status_code == 200

    flipped = client.get("/records", headers={"X-Expected-User": "other@example.com"})
    assert flipped.status_code == 409

    del_flipped = client.delete("/records/444", headers={"X-Expected-User": "other@example.com"})
    assert del_flipped.status_code == 409
    assert any(x["id"] == 444 for x in client.get("/records").json()), \
        "a flipped DELETE must not remove the record"

    del_ok = client.delete("/records/444", headers={"X-Expected-User": email})
    assert del_ok.status_code == 200


def test_absent_pin_is_backward_compatible(client, main):
    _login(client, main)
    assert client.put("/records", json={"id": 555}).status_code == 200
    assert client.get("/records").status_code == 200
    assert client.delete("/records/555").status_code == 200
