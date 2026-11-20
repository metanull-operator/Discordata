"""Talisman: HTTPS enforcement and security headers."""


def test_plain_http_is_redirected_to_https(app_module):
    with app_module.app.test_client() as plain:
        response = plain.post("/webhook", base_url="http://localhost")
    assert response.status_code in (301, 302)
    assert response.headers["Location"].startswith("https://")


def test_forwarded_https_is_not_redirected(app_module):
    with app_module.app.test_client() as plain:
        response = plain.post("/webhook", base_url="http://localhost", headers={"X-Forwarded-Proto": "https"})
    # Not a redirect: the handler ran and rejected the unsigned request.
    assert response.status_code == 400


def test_security_headers_are_set(post_webhook, reviewed_green):
    response = post_webhook({"type": "applicantCreated", "applicantId": "a"})
    headers = response.headers
    assert response.status_code == 200
    assert "max-age=" in headers["Strict-Transport-Security"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_security_headers_are_set_on_errors_too(post_webhook, reviewed_green):
    response = post_webhook(reviewed_green, signature="bad")
    assert response.status_code == 400
    assert "Strict-Transport-Security" in response.headers
    assert "Content-Security-Policy" in response.headers


def test_only_post_is_allowed_on_webhook(client):
    assert client.get("/webhook").status_code == 405


def test_unknown_route_is_404(client):
    assert client.get("/nope").status_code == 404
