"""Shared fixtures for the Discordata test suite.

discordata.py reads its configuration from environment variables and the
command line when it is imported, and refuses to import without WEBHOOK_SECRET
and DISCORD_WEBHOOK_URL. Both are set here, before any test module imports it.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import sys

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

# discordata parses sys.argv at import; keep pytest's own arguments away from it.
_saved_argv = sys.argv
sys.argv = ["discordata.py"]
try:
    import discordata  # noqa: E402  (must come after the environment is set)
finally:
    sys.argv = _saved_argv

# The signature from the Safe wallet that prompted EIP-1271 support (mainnet Safe 1.4.1).
SAFE_ADDRESS = "0x79bE272CDf0d15C7F27891229b14E7C5EcfaA269"
SAFE_OWNER = "0x394070A6D1cB8E1848321cF20b7b7A640D39A5FC"
SAFE_MESSAGE = "I/we agree to the Terms of Service of the SSV Network published on ssv.network (FA4GA7)"
SAFE_SIGNATURE = (
    "0x4aa11fa30f43f273b7308b4018dad1b02f7f8c2253f0c238f789454cd46dd425"
    "621f655027bee843f4a60c1989060c9d9d9ac3a8303f6a9a9db2489c7946fe881b"
)
# Safe 1.4.1 domainSeparator() for SAFE_ADDRESS on chain 1.
SAFE_DOMAIN_SEPARATOR = "0x5cf48034454d8bda0b292c525d1a34064fd59644022627c61a82b383b996500c"


def sign(body: bytes, secret: str = TEST_ENV["WEBHOOK_SECRET"]) -> str:
    """Return the x-payload-digest value Sumsub would send for this body."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def app_module(monkeypatch):
    """The discordata module, with its secrets and settings pinned to known test values."""
    monkeypatch.setattr(discordata, "WEBHOOK_SECRET", TEST_ENV["WEBHOOK_SECRET"])
    monkeypatch.setattr(discordata, "DISCORD_WEBHOOK_URL", TEST_ENV["DISCORD_WEBHOOK_URL"])
    monkeypatch.setattr(discordata, "SUMSUB_SECRET_KEY", TEST_ENV["SUMSUB_SECRET_KEY"])
    monkeypatch.setattr(discordata, "SUMSUB_APP_TOKEN", TEST_ENV["SUMSUB_APP_TOKEN"])
    monkeypatch.setattr(discordata, "allowed_ips", [ipaddress.ip_network("0.0.0.0/0")])
    monkeypatch.setattr(discordata, "signature_message", SAFE_MESSAGE)
    monkeypatch.setattr(discordata, "eth_rpc_url", None)
    monkeypatch.setattr(discordata, "contract_wallet_policy", "strict")
    monkeypatch.setattr(discordata, "acceptable_risk_score", 20)
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


def make_applicant_data(wallet_address, signature, program="voProgramParticipant"):
    """Applicant data as returned by the Sumsub /resources/applicants/{id}/one API."""
    return {
        "id": "5cb56e8e0a975a35f333cb83",
        "questionnaires": [
            {"id": "somethingElse", "sections": {}},
            {
                "id": "web3Identity",
                "sections": {
                    "identity": {"items": {"walletAddress": {"value": wallet_address}}},
                    "program": {"items": {"programParticipation": {"value": program}}},
                    "proofOfOwnership": {"items": {"signatureHash": {"value": signature}}},
                },
            },
        ],
    }


@pytest.fixture
def eoa():
    """A throwaway EOA key and its personal_sign signature of SAFE_MESSAGE."""
    from eth_account import Account
    from eth_account.messages import encode_defunct

    account = Account.from_key("0x" + "11" * 32)
    signed = Account.sign_message(encode_defunct(text=SAFE_MESSAGE), private_key=account.key)
    return {"address": account.address, "signature": "0x" + bytes(signed.signature).hex(), "key": account.key}


@pytest.fixture
def applicant_data(eoa):
    return make_applicant_data(eoa["address"], eoa["signature"])
