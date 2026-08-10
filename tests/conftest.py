"""Test harness for the account-deletion endpoints.

Uses moto to mock DynamoDB so no real AWS is touched, and sets all the env vars
app.main reads at import time (Stripe key, table names, admin list, secret).
Stripe network calls are avoided because test users have no stripe_customer_id
unless a test sets one and stubs Stripe explicitly.
"""
import os

os.environ.update(
    {
        "STRIPE_SECRET_KEY": "sk_test_dummy",
        "STRIPE_WEBHOOK_SECRET": "whsec_test_dummy",
        "SECRET_KEY": "test-secret",
        "USERS_TABLE": "test-users",
        "RECORDS_TABLE": "test-records",
        "AUDIT_TABLE": "test-audit",
        "ADMIN_EMAILS": "admin@taxstat360.com",
        "QUICKBOOKS_CLIENT_ID": "qb-test-client-id",
        "FRESHBOOKS_CLIENT_ID": "fb-test-client-id",
        "XERO_CLIENT_ID": "xero-test-client-id",
        "WAVE_CLIENT_ID": "wave-test-client-id",
        "QUICKBOOKS_CLIENT_SECRET": "qb-test-secret",
        "FRESHBOOKS_CLIENT_SECRET": "fb-test-secret",
        "XERO_CLIENT_SECRET": "xero-test-secret",
        "WAVE_CLIENT_SECRET": "wave-test-secret",
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "LOG_DIR": "/tmp/taxstat360-test-logs",
        "SESSION_COOKIE_DOMAIN": "",
    }
)

import boto3
import pytest
from moto import mock_aws

_mock = mock_aws()


def _create_tables():
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    existing = {t.name for t in ddb.tables.all()}
    if "test-users" not in existing:
        ddb.create_table(
            TableName="test-users",
            KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "email", "AttributeType": "S"},
                {"AttributeName": "stripe_customer_id", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "stripe_customer_id-index",
                    "KeySchema": [
                        {"AttributeName": "stripe_customer_id", "KeyType": "HASH"}
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
    if "test-records" not in existing:
        ddb.create_table(
            TableName="test-records",
            KeySchema=[
                {"AttributeName": "userId", "KeyType": "HASH"},
                {"AttributeName": "recordId", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "userId", "AttributeType": "S"},
                {"AttributeName": "recordId", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
    if "test-audit" not in existing:
        ddb.create_table(
            TableName="test-audit",
            KeySchema=[{"AttributeName": "auditId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "auditId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )


@pytest.fixture(scope="session", autouse=True)
def _aws():
    _mock.start()
    _create_tables()
    yield
    _mock.stop()


@pytest.fixture(autouse=True)
def _clean_tables():
    """Empty every table before each test so they run independently."""
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    for name, keys in [
        ("test-users", ["email"]),
        ("test-records", ["userId", "recordId"]),
        ("test-audit", ["auditId"]),
    ]:
        t = ddb.Table(name)
        items = t.scan().get("Items", [])
        with t.batch_writer() as bw:
            for it in items:
                bw.delete_item(Key={k: it[k] for k in keys})
    yield


@pytest.fixture
def main():
    import app.main as m

    return m


@pytest.fixture
def client(main):
    from fastapi.testclient import TestClient

    return TestClient(main.app)
