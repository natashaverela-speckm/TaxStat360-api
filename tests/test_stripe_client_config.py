"""Stripe client must use HTTP timeouts (not per-call timeout= kwargs)."""


def test_stripe_default_http_client_has_timeout(main):
    client = main.stripe.default_http_client
    assert client is not None
    assert getattr(client, "_timeout", None) == 10


def test_stripe_max_network_retries_bounded(main):
    assert main.stripe.max_network_retries == 1
