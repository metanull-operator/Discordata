"""IP allow-listing: is_ip_allowed and the before_request hook that enforces it."""

import ipaddress

import pytest


@pytest.fixture
def restrict(app_module, monkeypatch):
    def _restrict(*networks):
        monkeypatch.setattr(app_module, "allowed_ips", [ipaddress.ip_network(n) for n in networks])

    return _restrict


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("192.168.1.1", True),
        ("10.0.0.0", True),
        ("10.0.0.255", True),
        ("10.0.1.0", False),
        ("192.168.1.2", False),
        ("8.8.8.8", False),
    ],
)
def test_is_ip_allowed_matches_hosts_and_networks(app_module, restrict, ip, expected):
    restrict("192.168.1.1", "10.0.0.0/24")
    assert app_module.is_ip_allowed(ip) is expected


def test_default_allow_all_accepts_any_ipv4(app_module):
    assert app_module.is_ip_allowed("203.0.113.7") is True


def test_ipv6_client_is_not_in_ipv4_allow_list(app_module, restrict):
    restrict("0.0.0.0/0")
    assert app_module.is_ip_allowed("2001:db8::1") is False


def test_ipv6_networks_can_be_allowed(app_module, restrict):
    restrict("2001:db8::/32")
    assert app_module.is_ip_allowed("2001:db8::1") is True


def test_invalid_ip_raises(app_module):
    with pytest.raises(ValueError):
        app_module.is_ip_allowed("not-an-ip")


def test_disallowed_ip_gets_403_before_signature_check(post_webhook, restrict, reviewed_green):
    restrict("10.0.0.0/24")
    response = post_webhook(reviewed_green, signature=False, remote_addr="192.0.2.10")
    assert response.status_code == 403


def test_disallowed_ip_is_blocked_on_every_route(client, restrict):
    restrict("10.0.0.0/24")
    response = client.get("/", environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
    assert response.status_code == 403


def test_disallowed_ip_is_logged(post_webhook, restrict, reviewed_green, caplog):
    restrict("10.0.0.0/24")
    with caplog.at_level("WARNING"):
        post_webhook(reviewed_green, remote_addr="192.0.2.10")
    assert "Unauthorized access attempt from IP: 192.0.2.10" in caplog.text


def test_allowed_ip_reaches_the_handler(post_webhook, restrict, reviewed_green):
    restrict("10.0.0.0/24")
    # Reaches the handler, which then rejects the missing signature with 400, not 403.
    response = post_webhook(reviewed_green, signature=False, remote_addr="10.0.0.5")
    assert response.status_code == 400
