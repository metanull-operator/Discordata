"""Discord message formatting and delivery."""

import json
import re

import responses

DISCORD_URL = "https://discord.example.test/api/webhooks/123/abc"


def test_format_message_contains_wallet_signature_and_event(app_module, reviewed_green, applicant_data):
    message = app_module.format_message(reviewed_green, applicant_data)

    assert message.startswith("**Event Type:** applicantReviewed\n")
    assert re.search(r"\*\*Timestamp:\*\* \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", message)
    assert "**Wallet Address:** 0xABCDEF0123456789" in message
    assert "**Signature Hash:** 0xSIGNATURE" in message
    assert message.endswith(f"```json\n{json.dumps(reviewed_green, indent=4)}\n```")


def test_format_message_defaults_when_questionnaire_missing(app_module, reviewed_green):
    message = app_module.format_message(reviewed_green, {"questionnaires": [{"id": "other"}]})
    assert "**Wallet Address:** N/A" in message
    assert "**Signature Hash:** N/A" in message


def test_format_message_defaults_when_no_questionnaires(app_module, reviewed_green):
    message = app_module.format_message(reviewed_green, {})
    assert "**Wallet Address:** N/A" in message


def test_format_message_defaults_when_items_missing(app_module, reviewed_green):
    app_data = {"questionnaires": [{"id": "web3Identity", "sections": {"identity": {"items": {}}}}]}
    message = app_module.format_message(reviewed_green, app_data)
    assert "**Wallet Address:** N/A" in message
    assert "**Signature Hash:** N/A" in message


def test_format_message_unknown_event_type(app_module):
    message = app_module.format_message({"applicantId": "a"}, {})
    assert message.startswith("**Event Type:** Unknown Event")


@responses.activate
def test_send_to_discord_posts_json_content(app_module):
    responses.post(DISCORD_URL, status=204)

    app_module.send_to_discord("hello")

    sent = responses.calls[0].request
    assert json.loads(sent.body) == {"content": "hello"}
    assert sent.headers["Content-Type"] == "application/json"


@responses.activate
def test_send_to_discord_logs_non_204_responses(app_module, caplog):
    responses.post(DISCORD_URL, status=400, body="message too long")

    with caplog.at_level("ERROR"):
        app_module.send_to_discord("hello")  # Current behaviour: logs, doesn't raise.

    assert "Failed to send message to Discord: message too long" in caplog.text
