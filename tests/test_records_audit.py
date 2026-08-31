"""PHASE 4 — record-operation audit trail (the gap the Jul-8 drill exposed).

Contract: deleting a record writes a `record.delete` audit row carrying the
recordId AND the record's name (so the audit row alone answers "what was
deleted, by whom, when"); a 409 identity mismatch writes `identity.mismatch`.
Account deletions already had their trail; records now match."""
import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limit(main):
    main.limiter.reset()
    yield
    main.limiter.reset()


def _login(client, main, email="audit-test@example.com"):
    main.ddb_put_user(email, {"name": "A", "pw": main._hash_password("TestPassword12!"),
                              "verified": True, "plan": "starter"})
    client.cookies.set(main.SESSION_COOKIE, main._make_session(email))
    return email


def _audit_rows(main, action):
    rows = main._audit_tbl.scan().get("Items", [])
    return [r for r in rows if r.get("action") == action]


def test_delete_writes_audit_row_with_record_name(client, main):
    email = _login(client, main)
    client.put("/records", json={"id": 777, "name": "Q3 Planning Draft", "expectedUser": email})
    before = len(_audit_rows(main, "record.delete"))
    assert client.delete("/records/777").status_code == 200
    rows = _audit_rows(main, "record.delete")
    assert len(rows) == before + 1
    row = sorted(rows, key=lambda r: r["ts"])[-1]
    assert row["actor"] == email and row["status"] == "completed"
    assert "recordId=777" in row["detail"] and "Q3 Planning Draft" in row["detail"]


def test_delete_of_missing_record_audits_not_found(client, main):
    _login(client, main)
    assert client.delete("/records/999999").status_code == 404
    row = sorted(_audit_rows(main, "record.delete"), key=lambda r: r["ts"])[-1]
    assert row["status"] == "not_found"


def test_identity_mismatch_writes_its_own_audit_signature(client, main):
    email = _login(client, main)
    r = client.put("/records", json={"id": 1, "expectedUser": "intruder@example.com"})
    assert r.status_code == 409
    rows = _audit_rows(main, "identity.mismatch")
    assert rows, "the D-1 signature must leave a permanent trail"
    row = sorted(rows, key=lambda r: r["ts"])[-1]
    assert row["actor"] == email and row["target"] == "intruder@example.com"
    assert row["status"] == "blocked"


# M-3 (fresh-pass audit, Aug 2026) -------------------------------------------
def test_record_delete_audit_row_carries_source_ip(client, main):
    email = _login(client, main, "ip-record-audit@example.com")
    client.put("/records", json={"id": 42, "name": "IP test", "expectedUser": email})
    r = client.delete("/records/42", headers={"x-forwarded-for": "203.0.113.9, 10.0.0.2"})
    assert r.status_code == 200
    row = sorted(_audit_rows(main, "record.delete"), key=lambda r: r["ts"])[-1]
    assert row["ip"] == "10.0.0.2"


def test_identity_mismatch_audit_row_carries_source_ip(client, main):
    _login(client, main, "ip-mismatch-audit@example.com")
    r = client.put(
        "/records",
        json={"id": 1, "expectedUser": "intruder@example.com"},
        headers={"x-forwarded-for": "203.0.113.11, 10.0.0.3"},
    )
    assert r.status_code == 409
    row = sorted(_audit_rows(main, "identity.mismatch"), key=lambda r: r["ts"])[-1]
    assert row["ip"] == "10.0.0.3"
