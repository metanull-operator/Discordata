"""process_webhook_data and format_message: Hash Status, tags, risk score and the Discord message.

The Discord message format is fixed by the client: Hash Status is a plain pass/fail, with no extra lines.
"""

import pytest
import responses

import signature_verification as sv
from tests.conftest import SAFE_ADDRESS, SAFE_SIGNATURE, make_applicant_data
from tests.fake_chain import RPC_URL
from tests.test_signature_verification import safe_chain

CHECK = "✅"
CROSS = "❌"
EXTRA_LINES = ("Wallet Type", "Hash Detail", "⚠")


@pytest.fixture
def world(app_module, monkeypatch, applicant_data):
    """Stub Sumsub and Discord, and record what the processing step did."""
    state = {"applicant": applicant_data, "score": 5, "tags": [], "scored": [], "discord": []}

    monkeypatch.setattr(app_module, "get_applicant_data", lambda applicant_id: state["applicant"])

    def fake_score(applicant_id, wallet_address):
        state["scored"].append(wallet_address)
        return state["score"]

    monkeypatch.setattr(app_module, "get_address_score", fake_score)
    monkeypatch.setattr(app_module, "add_custom_tags", lambda applicant_id, tags: state["tags"].extend(tags))
    monkeypatch.setattr(app_module, "send_to_discord", lambda message: state["discord"].append(message))
    return state


def run(app_module, reviewed_green):
    app_module.process_webhook_data(reviewed_green["applicantId"], reviewed_green)


def hash_line(message):
    return next(line for line in message.splitlines() if line.startswith("**Hash Status:**"))


def test_valid_eoa_signature(app_module, world, reviewed_green, eoa):
    run(app_module, reviewed_green)

    (message,) = world["discord"]
    assert hash_line(message).endswith(CHECK)
    assert f"Wallet Address: {eoa['address']}" in message
    assert "Program: Verified Operator Program" in message.replace("**", "")
    assert world["scored"] == [eoa["address"]]
    assert world["tags"] == ["Verified Wallet"]
    assert "Risk Score: 5" in message


def test_high_risk_score_gets_no_verified_tag(app_module, world, reviewed_green):
    world["score"] = 21
    run(app_module, reviewed_green)
    assert world["tags"] == []
    assert ":red_circle:" in world["discord"][0]


def test_missing_risk_score_still_sends_the_message(app_module, world, reviewed_green):
    """Regression: a None score used to raise in the <= comparison, so no Discord message went out."""
    world["score"] = None
    run(app_module, reviewed_green)
    assert len(world["discord"]) == 1
    assert world["tags"] == []


def test_invalid_signature_is_tagged_and_not_scored(app_module, world, reviewed_green, eoa):
    world["applicant"] = make_applicant_data("0x" + "12" * 20, eoa["signature"])
    run(app_module, reviewed_green)

    (message,) = world["discord"]
    assert hash_line(message).endswith(CROSS)
    assert world["tags"] == ["Invalid Hash"]
    assert world["scored"] == []


def test_check_detail_goes_to_the_log_not_discord(app_module, world, reviewed_green, monkeypatch, caplog):
    result = sv.SignatureResult(sv.INVALID, sv.WALLET_CONTRACT, "Contract wallet rejected the signature (EIP-1271)")
    monkeypatch.setattr(app_module.signature_verification, "verify_wallet_signature", lambda *a, **k: result)
    with caplog.at_level("INFO"):
        run(app_module, reviewed_green)

    (message,) = world["discord"]
    assert hash_line(message).endswith(CROSS)
    assert "Contract wallet rejected the signature" in caplog.text
    assert not any(extra in message for extra in EXTRA_LINES)


def test_settings_are_passed_to_the_verifier(app_module, world, reviewed_green, monkeypatch):
    seen = {}

    def fake_verify(message, signature, address, rpc_url=None, policy=None):
        seen.update(message=message, signature=signature, address=address, rpc_url=rpc_url, policy=policy)
        return sv.SignatureResult(sv.VALID, sv.WALLET_EOA, "ok")

    monkeypatch.setattr(app_module, "eth_rpc_url", "https://node.example/")
    monkeypatch.setattr(app_module, "contract_wallet_policy", "strict")
    monkeypatch.setattr(app_module.signature_verification, "verify_wallet_signature", fake_verify)
    run(app_module, reviewed_green)

    assert seen["rpc_url"] == "https://node.example/"
    assert seen["policy"] == "strict"
    assert seen["message"] == app_module.signature_message


@pytest.mark.parametrize(("policy", "icon", "tags"), [
    ("strict", CROSS, ["Invalid Hash"]),
    ("single_owner", CROSS, ["Invalid Hash"]),
    ("any_owner", CHECK, ["Verified Wallet"]),
])
def test_reported_safe_end_to_end(app_module, world, reviewed_green, monkeypatch, policy, icon, tags):
    """The reported Safe, owner-signed, against a fake node where its threshold is 2."""
    world["applicant"] = make_applicant_data(SAFE_ADDRESS, SAFE_SIGNATURE)
    monkeypatch.setattr(app_module, "eth_rpc_url", RPC_URL)
    monkeypatch.setattr(app_module, "contract_wallet_policy", policy)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        safe_chain(eip1271_valid=False, threshold=2).install(rsps)
        run(app_module, reviewed_green)

    assert hash_line(world["discord"][0]).endswith(icon)
    assert not any(extra in world["discord"][0] for extra in EXTRA_LINES)
    assert world["tags"] == tags


def test_reported_safe_with_threshold_one_is_valid(app_module, world, reviewed_green, monkeypatch):
    world["applicant"] = make_applicant_data(SAFE_ADDRESS, SAFE_SIGNATURE)
    monkeypatch.setattr(app_module, "eth_rpc_url", RPC_URL)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        safe_chain(eip1271_valid=True, threshold=1).install(rsps)
        run(app_module, reviewed_green)

    message = world["discord"][0]
    assert hash_line(message).endswith(CHECK)
    assert world["tags"] == ["Verified Wallet"]


def test_reported_safe_without_rpc_is_still_invalid(app_module, world, reviewed_green):
    """Unchanged behaviour when ETH_RPC_URL is not set."""
    world["applicant"] = make_applicant_data(SAFE_ADDRESS, SAFE_SIGNATURE)
    run(app_module, reviewed_green)
    message = world["discord"][0]
    assert hash_line(message).endswith(CROSS)


def test_no_signature_message_configured_behaves_as_before(app_module, world, reviewed_green, monkeypatch):
    """Existing behaviour, kept: without SIGNATURE_MESSAGE the hash shows as failed and is tagged."""
    monkeypatch.setattr(app_module, "signature_message", None)
    run(app_module, reviewed_green)
    message = world["discord"][0]
    assert hash_line(message).endswith(CROSS)
    assert world["tags"] == ["Invalid Hash"]


def test_missing_signature_is_invalid(app_module, world, reviewed_green, eoa):
    world["applicant"] = make_applicant_data(eoa["address"], None)
    run(app_module, reviewed_green)
    message = world["discord"][0]
    assert hash_line(message).endswith(CROSS)
    assert world["tags"] == ["Invalid Hash"]


def test_red_review_has_no_hash_status_and_no_tags(app_module, world, reviewed_green):
    reviewed_green["reviewResult"] = {"reviewAnswer": "RED"}
    run(app_module, reviewed_green)
    message = world["discord"][0]
    assert hash_line(message).endswith("N/A")
    assert world["tags"] == []
    assert world["scored"] == []


def test_missing_web3_questionnaire_sends_message_without_wallet(app_module, world, reviewed_green):
    world["applicant"] = {"id": "x", "questionnaires": []}
    run(app_module, reviewed_green)
    message = world["discord"][0]
    assert "Wallet Address: N/A" in message
    assert world["tags"] == []


def test_errors_are_logged_not_raised(app_module, world, reviewed_green, monkeypatch, caplog):
    def boom(applicant_id):
        raise RuntimeError("sumsub down")

    monkeypatch.setattr(app_module, "get_applicant_data", boom)
    with caplog.at_level("ERROR"):
        run(app_module, reviewed_green)
    assert "sumsub down" in caplog.text
    assert world["discord"] == []


@pytest.mark.parametrize(("valid", "icon"), [(True, CHECK), (False, CROSS)])
def test_format_message_is_unchanged(app_module, monkeypatch, valid, icon):
    """The exact message the client signed off on: no new lines, Hash Status is only a check or a cross."""
    class FixedTime:
        @staticmethod
        def utcnow():
            import datetime
            return datetime.datetime(2026, 1, 2, 3, 4, 5)

    monkeypatch.setattr(app_module, "datetime", FixedTime)
    message = app_module.format_message("app-1", "applicantReviewed", "GREEN", SAFE_ADDRESS, valid, 3,
                                        "grantsProgramParticipant")
    assert message == (
        "### New Applicant Status\n"
        "**Program:** Grants Program\n"
        "**Review Status:** :white_check_mark:\n"
        f"**Hash Status:**     {icon}\n"
        "**Risk Score:**        :green_circle:\n"
        "\n**Event:**\n"
        "Applicant ID: app-1\n"
        "Timestamp: 2026-01-02 03:04:05 UTC\n"
        "Event Type: applicantReviewed\n"
        "\n**Wallet:**\n"
        f"Wallet Address: {SAFE_ADDRESS}\n"
        "Risk Score: 3\n"
    )
