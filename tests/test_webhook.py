"""End-to-end behaviour of POST /webhook, with Sumsub and Discord stubbed out."""

import json

import pytest

from tests.conftest import sign


@pytest.fixture
def calls(app_module, monkeypatch, applicant_data):
    """Stub the two outbound calls and record what they were called with."""
    recorded = {"sumsub": [], "discord": []}

    def fake_get_applicant_data(applicant_id):
        recorded["sumsub"].append(applicant_id)
        return applicant_data

    def fake_send_to_discord(message):
        recorded["discord"].append(message)

    monkeypatch.setattr(app_module, "get_applicant_data", fake_get_applicant_data)
    monkeypatch.setattr(app_module, "send_to_discord", fake_send_to_discord)
    return recorded


def test_green_review_is_published_to_discord(post_webhook, reviewed_green, calls):
    response = post_webhook(reviewed_green)

    assert response.status_code == 200
    assert response.data == b""
    assert calls["sumsub"] == [reviewed_green["applicantId"]]
    assert len(calls["discord"]) == 1
    message = calls["discord"][0]
    assert "**Event Type:** applicantReviewed" in message
    assert "**Wallet Address:** 0xABCDEF0123456789" in message
    assert "**Signature Hash:** 0xSIGNATURE" in message


def test_missing_signature_is_rejected(post_webhook, reviewed_green, calls):
    response = post_webhook(reviewed_green, signature=False)
    assert response.status_code == 400
    assert b"Invalid signature" in response.data
    assert calls == {"sumsub": [], "discord": []}


def test_wrong_signature_is_rejected(post_webhook, reviewed_green, calls):
    response = post_webhook(reviewed_green, signature="0" * 64)
    assert response.status_code == 400
    assert calls == {"sumsub": [], "discord": []}


def test_invalid_signature_is_logged(post_webhook, reviewed_green, calls, caplog):
    with caplog.at_level("WARNING"):
        post_webhook(reviewed_green, signature="0" * 64)
    assert "Invalid signature from IP: 127.0.0.1" in caplog.text


def test_invalid_json_is_rejected(post_webhook, calls):
    response = post_webhook(None, raw=b"{not json")
    assert response.status_code == 400
    assert b"Invalid JSON payload" in response.data


def test_wrong_content_type_is_rejected_as_invalid_json(post_webhook, reviewed_green, calls):
    response = post_webhook(reviewed_green, headers={"Content-Type": "text/plain"})
    assert response.status_code == 400
    assert b"Invalid JSON payload" in response.data


@pytest.mark.parametrize("applicant_id", [None, ""])
def test_missing_applicant_id_is_rejected(post_webhook, reviewed_green, calls, applicant_id):
    reviewed_green["applicantId"] = applicant_id
    response = post_webhook(reviewed_green)
    assert response.status_code == 400
    assert b"Missing applicantId" in response.data


def test_absent_applicant_id_is_rejected(post_webhook, reviewed_green, calls):
    del reviewed_green["applicantId"]
    assert post_webhook(reviewed_green).status_code == 400


@pytest.mark.parametrize("event_type", ["applicantCreated", "applicantPending", "applicantOnHold", None])
def test_other_event_types_are_acknowledged_but_skipped(post_webhook, reviewed_green, calls, event_type):
    if event_type is None:
        del reviewed_green["type"]
    else:
        reviewed_green["type"] = event_type
    response = post_webhook(reviewed_green)
    assert response.status_code == 200
    assert calls == {"sumsub": [], "discord": []}


@pytest.mark.parametrize("answer", ["RED", "YELLOW", None])
def test_non_green_reviews_are_acknowledged_but_skipped(post_webhook, reviewed_green, calls, answer):
    reviewed_green["reviewResult"] = {"reviewAnswer": answer}
    response = post_webhook(reviewed_green)
    assert response.status_code == 200
    assert calls == {"sumsub": [], "discord": []}


def test_missing_review_result_is_skipped(post_webhook, reviewed_green, calls):
    del reviewed_green["reviewResult"]
    assert post_webhook(reviewed_green).status_code == 200
    assert calls["discord"] == []


def test_empty_allowed_event_types_lets_every_type_through(
    app_module, post_webhook, reviewed_green, calls, monkeypatch
):
    monkeypatch.setattr(app_module, "ALLOWED_EVENT_TYPES", [])
    reviewed_green["type"] = "applicantCreated"
    assert post_webhook(reviewed_green).status_code == 200
    assert len(calls["discord"]) == 1


def test_empty_allowed_review_answers_lets_every_answer_through(
    app_module, post_webhook, reviewed_green, calls, monkeypatch
):
    monkeypatch.setattr(app_module, "ALLOWED_REVIEW_ANSWERS", [])
    reviewed_green["reviewResult"]["reviewAnswer"] = "RED"
    assert post_webhook(reviewed_green).status_code == 200
    assert len(calls["discord"]) == 1


def test_sumsub_failure_returns_500_and_skips_discord(app_module, post_webhook, reviewed_green, calls, monkeypatch):
    def boom(_applicant_id):
        raise RuntimeError("sumsub down")

    monkeypatch.setattr(app_module, "get_applicant_data", boom)
    response = post_webhook(reviewed_green)
    assert response.status_code == 500
    assert b"Error retrieving applicant data" in response.data
    assert calls["discord"] == []


def test_discord_failure_returns_500(app_module, post_webhook, reviewed_green, calls, monkeypatch):
    def boom(_message):
        raise RuntimeError("discord down")

    monkeypatch.setattr(app_module, "send_to_discord", boom)
    response = post_webhook(reviewed_green)
    assert response.status_code == 500
    assert b"Failed to send message to Discord" in response.data


def test_signature_covers_the_exact_bytes_received(post_webhook, reviewed_green, calls):
    # Same JSON, different whitespace: the signature must be over the raw body.
    compact = json.dumps(reviewed_green, separators=(",", ":")).encode()
    pretty = json.dumps(reviewed_green, indent=2).encode()

    assert post_webhook(None, raw=pretty, signature=sign(compact)).status_code == 400
    assert post_webhook(None, raw=pretty, signature=sign(pretty)).status_code == 200


@pytest.mark.xfail(strict=True, reason="Known bug: a JSON body that isn't an object crashes the handler with a 500")
@pytest.mark.parametrize("body", [b"null", b"[]", b'"text"', b"42"])
def test_non_object_json_is_rejected_with_400(post_webhook, calls, body):
    assert post_webhook(None, raw=body).status_code == 400
