"""Sumsub wallet risk scoring (KYT), applicant tags and Discord delivery."""

import json

import pytest
import responses

APPLICANT_ID = "5cb56e8e0a975a35f333cb83"
WALLET = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
SUBMIT_URL = f"https://api.sumsub.com/resources/applicants/{APPLICANT_ID}/kyt/txns/-/data"
TAGS_URL = f"https://api.sumsub.com/resources/applicants/{APPLICANT_ID}/tags/add"


@pytest.fixture
def no_sleep(app_module, monkeypatch):
    monkeypatch.setattr(app_module.time, "sleep", lambda seconds: None)


@responses.activate
def test_submit_address_request_sends_a_signed_kyt_transaction(app_module):
    responses.post(SUBMIT_URL, json={"id": "txn"})

    txn_id = app_module.submit_address_request(APPLICANT_ID, WALLET)

    assert len(txn_id) == 20
    sent = responses.calls[0].request
    body = json.loads(sent.body)
    assert body["txnId"] == txn_id
    assert body["counterparty"]["paymentMethod"] == {"type": "crypto", "accountId": WALLET}
    assert body["info"]["currencyCode"] == "ETH"
    assert "X-App-Access-Sig" in sent.headers


@responses.activate
def test_submit_address_request_returns_none_on_error(app_module):
    responses.post(SUBMIT_URL, status=400, json={"error": "bad"})
    assert app_module.submit_address_request(APPLICANT_ID, WALLET) is None


@responses.activate
def test_submit_address_request_returns_none_on_bad_json(app_module):
    responses.post(SUBMIT_URL, body="not json")
    assert app_module.submit_address_request(APPLICANT_ID, WALLET) is None


def _poll_url(txn_id):
    return f"https://api.sumsub.com/resources/kyt/txns/-;data.txnId={txn_id}/one"


@responses.activate
def test_poll_returns_the_score_once_ready(app_module, no_sleep):
    url = _poll_url("abc")
    responses.get(url, json={"scoringResult": {}})
    responses.get(url, status=500, body="hiccup")
    responses.get(url, body="not json")
    responses.get(url, json={"scoringResult": {"score": 7}})

    assert app_module.poll_address_score("abc", max_retries=5, delay=0) == 7
    assert len(responses.calls) == 4


@responses.activate
def test_poll_gives_up_after_max_retries(app_module, no_sleep, caplog):
    responses.get(_poll_url("abc"), json={"scoringResult": {}})
    with caplog.at_level("ERROR"):
        assert app_module.poll_address_score("abc", max_retries=3, delay=0) is None
    assert len(responses.calls) == 3
    assert "Max polling attempts reached" in caplog.text


def test_get_address_score_submits_then_polls(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "submit_address_request", lambda applicant_id, wallet: "txn-1")
    monkeypatch.setattr(app_module, "poll_address_score", lambda txn_id: 12 if txn_id == "txn-1" else None)
    assert app_module.get_address_score(APPLICANT_ID, WALLET) == 12


def test_get_address_score_is_none_when_submit_fails(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "submit_address_request", lambda applicant_id, wallet: None)
    assert app_module.get_address_score(APPLICANT_ID, WALLET) is None


@responses.activate
def test_add_custom_tags_posts_the_tag_list(app_module):
    responses.post(TAGS_URL, json=["Verified Wallet"])
    assert app_module.add_custom_tags(APPLICANT_ID, ["Verified Wallet"]) == ["Verified Wallet"]
    assert json.loads(responses.calls[0].request.body) == ["Verified Wallet"]


@responses.activate
@pytest.mark.parametrize(("kwargs", "expected"), [({"status": 403, "json": {}}, None), ({"body": "nope"}, None)])
def test_add_custom_tags_returns_none_on_failure(app_module, kwargs, expected):
    responses.post(TAGS_URL, **kwargs)
    assert app_module.add_custom_tags(APPLICANT_ID, ["x"]) is expected


@responses.activate
def test_send_to_discord_posts_the_message(app_module):
    responses.post(app_module.DISCORD_WEBHOOK_URL, status=204)
    app_module.send_to_discord("hello")
    assert json.loads(responses.calls[0].request.body) == {"content": "hello"}


@responses.activate
def test_send_to_discord_logs_rejections(app_module, caplog):
    responses.post(app_module.DISCORD_WEBHOOK_URL, status=400, body="bad message")
    with caplog.at_level("ERROR"):
        app_module.send_to_discord("hello")
    assert "Failed to send message to Discord: bad message" in caplog.text
