"""POST /webhook: request validation and filtering before work is handed to a thread."""

import json

import pytest

from tests.conftest import sign


@pytest.fixture
def started(app_module, monkeypatch):
    """Record the background jobs the handler starts instead of running them."""
    jobs = []

    class FakeThread:
        def __init__(self, target, args=()):
            self.target, self.args = target, args

        def start(self):
            jobs.append((self.target, self.args))

    monkeypatch.setattr(app_module.threading, "Thread", FakeThread)
    return jobs


def test_green_review_is_handed_to_a_background_job(app_module, post_webhook, reviewed_green, started):
    response = post_webhook(reviewed_green)

    assert response.status_code == 200
    assert response.data == b""
    assert started == [(app_module.process_webhook_data, (reviewed_green["applicantId"], reviewed_green))]


def test_red_review_is_also_processed(app_module, post_webhook, reviewed_green, started):
    reviewed_green["reviewResult"] = {"reviewAnswer": "RED"}
    assert post_webhook(reviewed_green).status_code == 200
    assert len(started) == 1


def test_missing_signature_is_rejected(post_webhook, reviewed_green, started):
    response = post_webhook(reviewed_green, signature=False)
    assert response.status_code == 400
    assert b"Invalid signature" in response.data
    assert started == []


def test_wrong_signature_is_rejected(post_webhook, reviewed_green, started):
    assert post_webhook(reviewed_green, signature="0" * 64).status_code == 400
    assert started == []


def test_invalid_signature_is_logged(post_webhook, reviewed_green, started, caplog):
    with caplog.at_level("WARNING"):
        post_webhook(reviewed_green, signature="0" * 64)
    assert "Invalid signature from IP: 127.0.0.1" in caplog.text


def test_invalid_json_is_rejected(post_webhook, started):
    response = post_webhook(None, raw=b"{not json")
    assert response.status_code == 400
    assert b"Invalid JSON payload" in response.data


@pytest.mark.parametrize("applicant_id", [None, ""])
def test_missing_applicant_id_is_rejected(post_webhook, reviewed_green, started, applicant_id):
    reviewed_green["applicantId"] = applicant_id
    response = post_webhook(reviewed_green)
    assert response.status_code == 400
    assert b"Missing applicantId" in response.data
    assert started == []


@pytest.mark.parametrize("event_type", ["applicantCreated", "applicantPending", "applicantOnHold", None])
def test_other_event_types_are_acknowledged_but_skipped(post_webhook, reviewed_green, started, event_type):
    if event_type is None:
        del reviewed_green["type"]
    else:
        reviewed_green["type"] = event_type
    assert post_webhook(reviewed_green).status_code == 200
    assert started == []


def test_ubo_level_is_skipped(post_webhook, reviewed_green, started):
    reviewed_green["levelName"] = "ubo-basic-kyc-level"
    assert post_webhook(reviewed_green).status_code == 200
    assert started == []


@pytest.mark.parametrize("answer", ["YELLOW", None])
def test_other_review_answers_are_acknowledged_but_skipped(post_webhook, reviewed_green, started, answer):
    reviewed_green["reviewResult"] = {"reviewAnswer": answer}
    assert post_webhook(reviewed_green).status_code == 200
    assert started == []


def test_signature_covers_the_exact_bytes_received(post_webhook, reviewed_green, started):
    compact = json.dumps(reviewed_green, separators=(",", ":")).encode()
    pretty = json.dumps(reviewed_green, indent=2).encode()

    assert post_webhook(None, raw=pretty, signature=sign(compact)).status_code == 400
    assert post_webhook(None, raw=pretty, signature=sign(pretty)).status_code == 200
