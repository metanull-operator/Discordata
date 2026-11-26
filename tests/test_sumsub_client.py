"""Outbound Sumsub API calls: request signing and get_applicant_data."""

import hashlib
import hmac

import pytest
import requests
import responses

APPLICANT_ID = "5cb56e8e0a975a35f333cb83"
APPLICANT_URL = f"https://api.sumsub.com/resources/applicants/{APPLICANT_ID}/one"


def _expected_sig(secret, ts, method, path, body=b""):
    message = str(ts).encode() + method.encode() + path.encode() + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def test_sign_request_sets_sumsub_auth_headers(app_module, monkeypatch):
    monkeypatch.setattr(app_module.time, "time", lambda: 1_700_000_000)
    prepared = app_module.sign_request(requests.Request("GET", APPLICANT_URL))

    path = f"/resources/applicants/{APPLICANT_ID}/one"
    assert prepared.headers["X-App-Token"] == "test-sumsub-token"
    assert prepared.headers["X-App-Access-Ts"] == "1700000000"
    assert prepared.headers["X-App-Access-Sig"] == _expected_sig("test-sumsub-secret", 1_700_000_000, "GET", path)


def test_sign_request_includes_query_string_and_body(app_module, monkeypatch):
    monkeypatch.setattr(app_module.time, "time", lambda: 1_700_000_000)
    req = requests.Request("post", "https://api.sumsub.com/resources/x?a=1", data="payload")
    prepared = app_module.sign_request(req)

    expected = _expected_sig("test-sumsub-secret", 1_700_000_000, "POST", "/resources/x?a=1", b"payload")
    assert prepared.headers["X-App-Access-Sig"] == expected


def test_sign_request_handles_bytes_body(app_module, monkeypatch):
    monkeypatch.setattr(app_module.time, "time", lambda: 1_700_000_000)
    req = requests.Request("POST", "https://api.sumsub.com/resources/x", data=b"raw-bytes")
    prepared = app_module.sign_request(req)

    expected = _expected_sig("test-sumsub-secret", 1_700_000_000, "POST", "/resources/x", b"raw-bytes")
    assert prepared.headers["X-App-Access-Sig"] == expected


@responses.activate
def test_get_applicant_data_returns_parsed_json(app_module, applicant_data):
    responses.get(APPLICANT_URL, json=applicant_data)

    assert app_module.get_applicant_data(APPLICANT_ID) == applicant_data
    sent = responses.calls[0].request
    assert sent.headers["X-App-Token"] == "test-sumsub-token"
    assert "X-App-Access-Sig" in sent.headers
    assert "X-App-Access-Ts" in sent.headers


@responses.activate
@pytest.mark.parametrize("status", [401, 404, 500])
def test_get_applicant_data_raises_on_http_errors(app_module, status):
    responses.get(APPLICANT_URL, status=status, json={"error": "nope"})
    with pytest.raises(requests.exceptions.HTTPError):
        app_module.get_applicant_data(APPLICANT_ID)


@responses.activate
def test_get_applicant_data_raises_on_timeout(app_module, caplog):
    responses.get(APPLICANT_URL, body=requests.exceptions.Timeout("slow"))
    with caplog.at_level("ERROR"), pytest.raises(requests.exceptions.Timeout):
        app_module.get_applicant_data(APPLICANT_ID)
    assert "timed out" in caplog.text


@responses.activate
def test_get_applicant_data_raises_on_connection_error(app_module):
    responses.get(APPLICANT_URL, body=requests.exceptions.ConnectionError("down"))
    with pytest.raises(requests.exceptions.ConnectionError):
        app_module.get_applicant_data(APPLICANT_ID)


def test_get_applicant_data_uses_request_timeout(app_module, monkeypatch, applicant_data):
    seen = {}

    def fake_send(self, prepared, **kwargs):
        seen.update(kwargs)
        response = requests.Response()
        response.status_code = 200
        response._content = b"{}"
        return response

    monkeypatch.setattr(requests.Session, "send", fake_send)
    app_module.get_applicant_data(APPLICANT_ID)
    assert seen["timeout"] == app_module.REQUEST_TIMEOUT
