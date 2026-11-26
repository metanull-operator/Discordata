"""signature_verification: EOA and smart contract wallet (EIP-1271 / Safe) signature checks."""

import logging

import pytest
import requests
import responses
from eth_abi import decode, encode
from eth_account import Account
from eth_utils import keccak

import signature_verification as sv
from tests.conftest import (
    SAFE_ADDRESS,
    SAFE_DOMAIN_SEPARATOR,
    SAFE_MESSAGE,
    SAFE_OWNER,
    SAFE_SIGNATURE,
)
from tests.fake_chain import RPC_URL, REVERT, FakeChain

SAFE_CODE = bytes.fromhex("6080")  # any non-empty code marks a contract
MAGIC = bytes.fromhex("1626ba7e") + b"\x00" * 28


def word(value, abi_type="uint256"):
    return encode([abi_type], [value])


def safe_chain(*, eip1271_valid, threshold=1, owners=(SAFE_OWNER,), domain_separator=SAFE_DOMAIN_SEPARATOR):
    """A fake chain holding one Safe at SAFE_ADDRESS."""
    owners_lower = {o.lower() for o in owners}

    def is_valid_signature(data):
        if eip1271_valid is REVERT:
            return REVERT
        return MAGIC if eip1271_valid else b"\x00" * 32

    def is_owner(data):
        (owner,) = decode(["address"], data[4:])
        return word(owner.lower() in owners_lower, "bool")

    calls = {
        (SAFE_ADDRESS, "1626ba7e"): is_valid_signature,
        (SAFE_ADDRESS, "e75235b8"): lambda data: word(threshold),
        (SAFE_ADDRESS, "2f54bf6e"): is_owner,
    }
    if domain_separator is not None:
        calls[(SAFE_ADDRESS, "f698da25")] = lambda data: bytes.fromhex(domain_separator[2:])
    return FakeChain(code={SAFE_ADDRESS: SAFE_CODE}, calls=calls)


@pytest.fixture
def rsps():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


def check(signature=SAFE_SIGNATURE, address=SAFE_ADDRESS, message=SAFE_MESSAGE, **kwargs):
    kwargs.setdefault("rpc_url", RPC_URL)
    return sv.verify_wallet_signature(message, signature, address, **kwargs)


# --- Plain wallets (EOA) -----------------------------------------------------------------


def test_eoa_signature_is_valid_without_any_rpc(eoa, rsps):
    result = check(eoa["signature"], eoa["address"])
    assert result == sv.SignatureResult(sv.VALID, sv.WALLET_EOA, "Signed by the wallet's key")
    assert len(rsps.calls) == 0


@pytest.mark.parametrize("variant", ["lower", "upper", "padded"])
def test_eoa_address_case_and_whitespace_do_not_matter(eoa, variant):
    address = eoa["address"]
    address = {"lower": "0x" + address[2:].lower(), "upper": "0x" + address[2:].upper(),
               "padded": "  " + address + "\n"}[variant]
    assert check(eoa["signature"], address, rpc_url=None).status == sv.VALID


def test_eoa_signature_without_0x_prefix_is_accepted(eoa):
    assert check(eoa["signature"][2:], eoa["address"], rpc_url=None).status == sv.VALID


def test_eoa_signature_of_another_message_is_invalid_offline(eoa):
    result = check(eoa["signature"], eoa["address"], message=SAFE_MESSAGE + " ", rpc_url=None)
    assert result.status == sv.INVALID
    assert "ETH_RPC_URL not set" in result.detail


def test_eoa_signature_of_another_message_is_invalid_with_rpc(eoa, rsps):
    chain = FakeChain()
    chain.install(rsps)
    result = check(eoa["signature"], eoa["address"], message="something else")
    assert result == sv.SignatureResult(sv.INVALID, sv.WALLET_EOA, "Not signed by the wallet's key")
    assert chain.methods() == ["eth_getCode"]


def test_signature_from_another_key_is_invalid(eoa):
    other = Account.from_key("0x" + "22" * 32).address
    assert check(eoa["signature"], other, rpc_url=None).status == sv.INVALID


@pytest.mark.parametrize(
    ("signature", "address"),
    [("0xnothex", None), ("", None), ("0x1234", None), (None, "0x1234"), (None, "not-an-address")],
)
def test_malformed_input_is_invalid_and_never_raises(eoa, signature, address):
    signature = eoa["signature"] if signature is None else signature
    address = eoa["address"] if address is None else address
    result = check(signature, address, rpc_url=None)
    assert result.status == sv.INVALID


def test_unknown_policy_is_rejected(eoa):
    with pytest.raises(ValueError, match="Unknown contract wallet policy"):
        check(eoa["signature"], eoa["address"], policy="yolo")


# --- The reported Safe -------------------------------------------------------------------


def test_reported_safe_signature_fails_plain_recovery():
    """The bug: a plain personal_sign recovery of the Safe's signature gives an unrelated address."""
    signer = sv.recover_eoa_signer(SAFE_MESSAGE, bytes.fromhex(SAFE_SIGNATURE[2:]))
    assert signer is not None
    assert signer.lower() != SAFE_ADDRESS.lower()


def test_reported_safe_signature_was_made_by_its_owner():
    """Offline: the signature recovers to the Safe's owner once wrapped the way Safe wraps it."""
    message_hash = sv.safe_message_hash(bytes.fromhex(SAFE_DOMAIN_SEPARATOR[2:]), sv.eip191_hash(SAFE_MESSAGE))
    assert sv.safe_owner_signers(bytes.fromhex(SAFE_SIGNATURE[2:]), message_hash) == [SAFE_OWNER]


def test_safe_domain_separator_matches_safe_1_4_1_formula():
    typehash = bytes.fromhex("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218")
    expected = keccak(encode(["bytes32", "uint256", "address"], [typehash, 1, SAFE_ADDRESS]))
    assert "0x" + expected.hex() == SAFE_DOMAIN_SEPARATOR


@pytest.mark.parametrize("policy", ["strict", "any_owner"])
def test_safe_passing_eip1271_is_valid(rsps, policy):
    safe_chain(eip1271_valid=True).install(rsps)
    result = check(policy=policy)
    assert result == sv.SignatureResult(sv.VALID, sv.WALLET_CONTRACT, "Contract wallet signature valid (EIP-1271)")


def test_eip1271_call_carries_the_personal_sign_hash_and_raw_signature(rsps):
    chain = safe_chain(eip1271_valid=True)
    chain.install(rsps)
    check(policy="strict")

    call = next(r for r in chain.requests if r["method"] == "eth_call")
    data = bytes.fromhex(call["params"][0]["data"][2:])
    assert call["params"][0]["to"] == SAFE_ADDRESS
    assert data[:4] == bytes.fromhex("1626ba7e")
    data_hash, signature = decode(["bytes32", "bytes"], data[4:])
    assert data_hash == sv.eip191_hash(SAFE_MESSAGE)
    assert signature == bytes.fromhex(SAFE_SIGNATURE[2:])


def test_eip191_hash_is_the_personal_sign_digest():
    prefixed = b"\x19Ethereum Signed Message:\n" + str(len(SAFE_MESSAGE)).encode() + SAFE_MESSAGE.encode()
    assert sv.eip191_hash(SAFE_MESSAGE) == keccak(prefixed)


@pytest.mark.parametrize("eip1271_valid", [False, REVERT])
@pytest.mark.parametrize(
    ("policy", "expected"),
    [("strict", sv.INVALID), ("any_owner", sv.VALID), ("single_owner", sv.INVALID)],
)
def test_owner_signed_but_threshold_not_met(rsps, eip1271_valid, policy, expected):
    safe_chain(eip1271_valid=eip1271_valid, threshold=2).install(rsps)
    result = check(policy=policy)
    assert result.status == expected
    assert result.wallet_type == sv.WALLET_CONTRACT
    if expected != sv.INVALID:
        assert result.detail == "Signed by 1 Safe owner(s); Safe threshold is 2"


@pytest.mark.parametrize("policy", ["strict", "any_owner"])
def test_signer_who_is_not_an_owner_is_invalid(rsps, policy):
    safe_chain(eip1271_valid=False, owners=("0x" + "ab" * 20,)).install(rsps)
    result = check(policy=policy)
    assert result == sv.SignatureResult(
        sv.INVALID, sv.WALLET_CONTRACT, "Contract wallet rejected the signature (EIP-1271)"
    )


def test_strict_policy_makes_no_owner_lookups(rsps):
    chain = safe_chain(eip1271_valid=False)
    chain.install(rsps)
    assert check(policy="strict").status == sv.INVALID
    selectors = [r["params"][0]["data"][2:10] for r in chain.requests if r["method"] == "eth_call"]
    assert selectors == ["1626ba7e"]


@pytest.mark.parametrize(("threshold", "expected"), [(1, sv.VALID), (2, sv.INVALID)])
def test_single_owner_policy_requires_threshold_one(rsps, threshold, expected):
    safe_chain(eip1271_valid=True, threshold=threshold).install(rsps)
    result = check(policy="single_owner")
    assert result.status == expected
    if expected == sv.INVALID:
        assert result.detail == "Contract wallet signature valid, but threshold is 2 (policy needs 1)"


def test_contract_that_is_not_a_safe_is_invalid_under_any_owner(rsps):
    """A contract with no domainSeparator()/isOwner() and a failing EIP-1271 check."""
    chain = FakeChain(code={SAFE_ADDRESS: SAFE_CODE}, calls={(SAFE_ADDRESS, "1626ba7e"): lambda d: REVERT})
    chain.install(rsps)
    assert check(policy="any_owner").status == sv.INVALID


def test_contract_without_get_threshold_reports_unknown_threshold(rsps):
    chain = safe_chain(eip1271_valid=False)
    del chain.calls[(SAFE_ADDRESS.lower(), "e75235b8")]
    chain.install(rsps)
    result = check(policy="any_owner")
    assert result.detail == "Signed by 1 Safe owner(s); Safe threshold is unknown"


# --- Safe signature encodings ------------------------------------------------------------


def _owner_part(key, message_hash, eth_sign=False):
    if eth_sign:
        digest = keccak(b"\x19Ethereum Signed Message:\n32" + message_hash)
        signed = Account._sign_hash(digest, key)
        v = signed.v + 4
    else:
        signed = Account._sign_hash(message_hash, key)
        v = signed.v
    return signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + bytes([v])


def test_eth_sign_style_owner_signatures_are_recognised():
    key = "0x" + "33" * 32
    message_hash = keccak(b"some safe message hash")
    part = _owner_part(key, message_hash, eth_sign=True)
    assert part[64] in (31, 32)
    assert sv.safe_owner_signers(part, message_hash) == [Account.from_key(key).address]


def test_contract_and_approved_hash_parts_are_skipped():
    key = "0x" + "44" * 32
    message_hash = keccak(b"another hash")
    contract_part = b"\x00" * 64 + b"\x00"
    approved_part = b"\x00" * 64 + b"\x01"
    signature = contract_part + _owner_part(key, message_hash) + approved_part
    assert sv.safe_owner_signers(signature, message_hash) == [Account.from_key(key).address]


def test_two_owner_signatures_are_counted(rsps):
    keys = ["0x" + "55" * 32, "0x" + "66" * 32]
    owners = tuple(Account.from_key(k).address for k in keys)
    message_hash = sv.safe_message_hash(bytes.fromhex(SAFE_DOMAIN_SEPARATOR[2:]), sv.eip191_hash(SAFE_MESSAGE))
    signature = b"".join(_owner_part(k, message_hash) for k in keys)
    # The same owner twice counts once.
    signature += _owner_part(keys[0], message_hash)
    safe_chain(eip1271_valid=False, threshold=3, owners=owners).install(rsps)

    result = check(signature="0x" + signature.hex(), policy="any_owner")
    assert result.status == sv.VALID
    assert result.detail == "Signed by 2 Safe owner(s); Safe threshold is 3"


# --- RPC failures ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        {"body": requests.exceptions.ConnectionError("down")},
        {"body": requests.exceptions.Timeout("slow")},
        {"status": 502, "body": "bad gateway"},
        {"json": {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "header not found"}}},
        {"json": {"jsonrpc": "2.0", "id": 1}},
        {"json": ["not", "an", "object"]},
        {"json": {"jsonrpc": "2.0", "id": 1, "result": "nothex"}},
        {"body": "not json"},
    ],
)
def test_rpc_failure_means_invalid(rsps, failure):
    rsps.add(responses.POST, RPC_URL, **failure)
    result = check(policy="strict")
    assert result == sv.SignatureResult(sv.INVALID, sv.WALLET_UNKNOWN, "Could not verify: Ethereum RPC unavailable")


def test_rpc_failure_during_eth_call_means_invalid(rsps):
    rsps.add(responses.POST, RPC_URL, json={"jsonrpc": "2.0", "id": 1, "result": "0x6080"})
    rsps.add(responses.POST, RPC_URL, json={"jsonrpc": "2.0", "id": 2, "error": {"code": -32603, "message": "boom"}})
    assert check(policy="strict").status == sv.INVALID


def test_rpc_url_is_not_written_to_the_log(rsps, caplog):
    secret_url = RPC_URL + "v3/SECRET-API-KEY"
    rsps.add(responses.POST, secret_url, body=requests.exceptions.ConnectionError(f"cannot reach {secret_url}"))
    with caplog.at_level(logging.DEBUG):
        result = check(rpc_url=secret_url)
    assert result.status == sv.INVALID
    assert "SECRET-API-KEY" not in caplog.text


def test_rpc_calls_use_a_timeout(monkeypatch):
    seen = {}

    def fake_post(self, url, json=None, timeout=None):
        seen["timeout"] = timeout
        raise requests.exceptions.Timeout()

    monkeypatch.setattr(requests.Session, "post", fake_post)
    check()
    assert seen["timeout"] == sv.RPC_TIMEOUT


@pytest.mark.parametrize("message", [SAFE_MESSAGE, "", "naïve ✓ multi-byte", "line one\nline two"])
def test_eip191_hash_matches_eth_account(message):
    from eth_account.messages import _hash_eip191_message, encode_defunct

    assert sv.eip191_hash(message) == bytes(_hash_eip191_message(encode_defunct(text=message)))


# --- Review findings ---------------------------------------------------------------------


def test_contract_that_echoes_calldata_is_not_valid(rsps):
    """Regression: calldata starts with the magic value, so a 4-byte comparison let echoing contracts pass."""
    chain = FakeChain(code={SAFE_ADDRESS: SAFE_CODE}, calls={(SAFE_ADDRESS, "1626ba7e"): lambda data: data})
    chain.install(rsps)
    result = check(signature="0x" + "00" * 65, policy="strict")
    assert result.status == sv.INVALID


@pytest.mark.parametrize("returned", [bytes.fromhex("1626ba7e"), bytes.fromhex("1626ba7e") + b"\x01" * 28])
def test_short_or_dirty_magic_value_is_not_valid(rsps, returned):
    chain = FakeChain(code={SAFE_ADDRESS: SAFE_CODE}, calls={(SAFE_ADDRESS, "1626ba7e"): lambda data: returned})
    chain.install(rsps)
    assert check(policy="strict").status == sv.INVALID


@pytest.mark.parametrize(("value", "expected"), [
    ("strict", "strict"), ("Strict", "strict"), (" any_owner\n", "any_owner"), ("SINGLE_OWNER", "single_owner"),
])
def test_policy_names_are_normalised(value, expected):
    assert sv.normalise_policy(value) == expected


@pytest.mark.parametrize("value", ["", None, "any-owner", "owner_review", "manual", "yolo"])
def test_unknown_policy_names_are_refused(value):
    with pytest.raises(ValueError, match="Unknown contract wallet policy"):
        sv.normalise_policy(value)


def _revert_then(rsps, error, status=200):
    """eth_getCode says contract; the isValidSignature eth_call fails with this error."""
    rsps.add(responses.POST, RPC_URL, json={"jsonrpc": "2.0", "id": 1, "result": "0x6080"})
    rsps.add(responses.POST, RPC_URL, status=status, json={"jsonrpc": "2.0", "id": 2, "error": error})


@pytest.mark.parametrize(("error", "status"), [
    ({"code": -32015, "message": "VM execution error.", "data": "revert"}, 200),  # older Nethermind
    ({"code": -32000, "message": "execution reverted"}, 200),
    ({"code": 3, "message": "execution reverted", "data": "0x"}, 500),  # gateway with an HTTP error status
])
def test_revert_shapes_are_read_as_revert(rsps, error, status):
    _revert_then(rsps, error, status)
    result = check(policy="strict")
    assert result.status == sv.INVALID
    assert result.wallet_type == sv.WALLET_CONTRACT


def test_owner_lookups_are_capped(rsps):
    keys = ["0x" + f"{i:02x}" * 32 for i in range(1, 15)]
    owners = tuple(Account.from_key(k).address for k in keys)
    message_hash = sv.safe_message_hash(bytes.fromhex(SAFE_DOMAIN_SEPARATOR[2:]), sv.eip191_hash(SAFE_MESSAGE))
    signature = b"".join(_owner_part(k, message_hash) for k in keys)
    assert len(sv.safe_owner_signers(signature, message_hash)) == sv.MAX_SIGNATURE_PARTS

    chain = safe_chain(eip1271_valid=False, threshold=14, owners=owners)
    chain.install(rsps)
    result = check(signature="0x" + signature.hex(), policy="any_owner")
    assert result.detail == f"Signed by {sv.MAX_SIGNATURE_PARTS} Safe owner(s); Safe threshold is 14"
    calls = [r for r in chain.requests if r["method"] == "eth_call"]
    is_owner_calls = [r for r in calls if r["params"][0]["data"][2:10] == "2f54bf6e"]
    assert len(is_owner_calls) == sv.MAX_SIGNATURE_PARTS
