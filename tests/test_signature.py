"""verify_signature: HMAC-SHA256 check of the x-payload-digest header."""

import pytest

from tests.conftest import sign

BODY = b'{"applicantId": "abc", "type": "applicantReviewed"}'


def _verify(app_module, body, headers):
    with app_module.app.test_request_context("/webhook", method="POST", data=body, headers=headers):
        from flask import request

        return app_module.verify_signature(request)


def test_valid_signature_is_accepted(app_module):
    assert _verify(app_module, BODY, {app_module.HMAC_HEADER_NAME: sign(BODY)}) is True


def test_missing_signature_header_is_rejected(app_module):
    assert _verify(app_module, BODY, {}) is False


def test_empty_signature_header_is_rejected(app_module):
    assert _verify(app_module, BODY, {app_module.HMAC_HEADER_NAME: ""}) is False


def test_signature_made_with_another_secret_is_rejected(app_module):
    assert _verify(app_module, BODY, {app_module.HMAC_HEADER_NAME: sign(BODY, "wrong-secret")}) is False


def test_signature_of_a_different_body_is_rejected(app_module):
    tampered = BODY.replace(b"abc", b"xyz")
    assert _verify(app_module, tampered, {app_module.HMAC_HEADER_NAME: sign(BODY)}) is False


def test_header_name_is_case_insensitive(app_module):
    assert _verify(app_module, BODY, {"X-Payload-Digest": sign(BODY)}) is True


@pytest.mark.parametrize("bad", ["not-hex", sign(BODY).upper(), sign(BODY)[:-1]])
def test_malformed_signatures_are_rejected(app_module, bad):
    assert _verify(app_module, BODY, {app_module.HMAC_HEADER_NAME: bad}) is False


def test_signature_uses_the_configured_secret(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "WEBHOOK_SECRET", "rotated-secret")
    assert _verify(app_module, BODY, {app_module.HMAC_HEADER_NAME: sign(BODY)}) is False
    assert _verify(app_module, BODY, {app_module.HMAC_HEADER_NAME: sign(BODY, "rotated-secret")}) is True
