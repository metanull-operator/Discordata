"""Shared fixtures for the Discordata test suite.

discordata.py reads its configuration from environment variables when it is
imported, and refuses to import without WEBHOOK_SECRET and DISCORD_WEBHOOK_URL.
The variables are set here, before any test module imports the app.
"""

import hashlib
import hmac
import ipaddress
import json
import os

import pytest
from flask.testing import FlaskClient

TEST_ENV = {
    "WEBHOOK_SECRET": "test-webhook-secret",
    "DISCORD_WEBHOOK_URL": "https://discord.example.test/api/webhooks/123/abc",
    "SUMSUB_SECRET_KEY": "test-sumsub-secret",
    "SUMSUB_APP_TOKEN": "test-sumsub-token",
    "ALLOWED_IPS": "0.0.0.0/0",
}

for _key, _value in TEST_ENV.items():
    os.environ.setdefault(_key, _value)

import discordata  # noqa: E402  (must come after the environment is set)


def sign(body: bytes, secret: str = TEST_ENV["WEBHOOK_SECRET"]) -> str:
    """Return the x-payload-digest value Sumsub would send for this body."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def app_module(monkeypatch):
    """The discordata module, with its secrets pinned to known test values."""
    monkeypatch.setattr(discordata, "WEBHOOK_SECRET", TEST_ENV["WEBHOOK_SECRET"])
    monkeypatch.setattr(discordata, "DISCORD_WEBHOOK_URL", TEST_ENV["DISCORD_WEBHOOK_URL"])
    monkeypatch.setattr(discordata, "SUMSUB_SECRET_KEY", TEST_ENV["SUMSUB_SECRET_KEY"])
    monkeypatch.setattr(discordata, "SUMSUB_APP_TOKEN", TEST_ENV["SUMSUB_APP_TOKEN"])
    monkeypatch.setattr(discordata, "allowed_ips", [ipaddress.ip_network("0.0.0.0/0")])
    discordata.app.config.update(TESTING=True)
    return discordata


class HttpsClient(FlaskClient):
    """A test client that talks HTTPS by default, so Talisman doesn't redirect requests."""

    def open(self, *args, **kwargs):
        kwargs.setdefault("base_url", "https://localhost")
        return super().open(*args, **kwargs)


@pytest.fixture
def client(app_module, monkeypatch):
    monkeypatch.setattr(app_module.app, "test_client_class", HttpsClient)
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture
def post_webhook(client):
    """POST a payload to /webhook, signed correctly unless told otherwise."""

    def _post(payload, *, signature=None, raw=None, remote_addr="127.0.0.1", headers=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        request_headers = {"Content-Type": "application/json"}
        if signature is not False:
            request_headers[discordata.HMAC_HEADER_NAME] = signature or sign(body)
        request_headers.update(headers or {})
        return client.post(
            "/webhook",
            data=body,
            headers=request_headers,
            environ_overrides={"REMOTE_ADDR": remote_addr},
        )

    return _post


@pytest.fixture
def reviewed_green():
    """A Sumsub applicantReviewed webhook with a GREEN review answer."""
    return {
        "applicantId": "5cb56e8e0a975a35f333cb83",
        "inspectionId": "5cb56e8e0a975a35f333cb84",
        "correlationId": "req-a260b669-4f14-4bb5-a4c5-ac0218acb9a4",
        "externalUserId": "externalUserId",
        "levelName": "basic-kyc-level",
        "type": "applicantReviewed",
        "reviewResult": {"reviewAnswer": "GREEN"},
        "reviewStatus": "completed",
        "createdAtMs": "2020-02-21 13:23:19.321",
    }


@pytest.fixture
def applicant_data():
    """Applicant data as returned by the Sumsub /resources/applicants/{id}/one API."""
    return {
        "id": "5cb56e8e0a975a35f333cb83",
        "questionnaires": [
            {"id": "somethingElse", "sections": {}},
            {
                "id": "web3Identity",
                "sections": {
                    "identity": {"items": {"walletAddress": {"value": "0xABCDEF0123456789"}}},
                    "proofOfOwnership": {"items": {"signatureHash": {"value": "0xSIGNATURE"}}},
                },
            },
        ],
    }
