"""Wallet signature verification for Discordata.

Checks that a wallet signed SIGNATURE_MESSAGE with EIP-191 ``personal_sign``.

Plain wallets (EOAs) are checked offline by recovering the signer's address.
Smart contract wallets such as Safe cannot be checked that way: the contract
holds no key, its owners sign a wrapped hash, and the contract decides whether
the signatures are good enough (EIP-1271 ``isValidSignature``). For those, an
Ethereum JSON-RPC endpoint (``ETH_RPC_URL``) is needed, and
``CONTRACT_WALLET_POLICY`` decides what counts as valid.

Policies for contract wallets (see README for the trade-offs):

``strict``        Valid only if the wallet's own EIP-1271 check passes. For a
                  Safe, that means the signatures meet the Safe's threshold.
                  This is the default.
``any_owner``     Valid if the EIP-1271 check passes or at least one Safe owner
                  signed, whatever the threshold.
``single_owner``  Valid only if the EIP-1271 check passes and the Safe's
                  threshold is 1.

The result is pass/fail only. Anything that cannot be confirmed, including an
unreachable RPC endpoint, is INVALID. The reason is logged, never sent to Discord.
"""

import logging
from dataclasses import dataclass

import requests
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address

logger = logging.getLogger(__name__)

VALID = "valid"
INVALID = "invalid"

POLICY_STRICT = "strict"
POLICY_ANY_OWNER = "any_owner"
POLICY_SINGLE_OWNER = "single_owner"
POLICIES = (POLICY_STRICT, POLICY_ANY_OWNER, POLICY_SINGLE_OWNER)
DEFAULT_POLICY = POLICY_STRICT

WALLET_EOA = "EOA"
WALLET_CONTRACT = "Smart contract"
WALLET_UNKNOWN = "Unknown"

RPC_TIMEOUT = 10  # seconds per JSON-RPC call
MAX_SIGNATURE_PARTS = 10  # Safe signature parts examined for owners; each distinct signer costs one eth_call

# Function selectors: first 4 bytes of keccak256 of the signature.
EIP1271_MAGIC_VALUE = bytes.fromhex("1626ba7e")  # isValidSignature(bytes32,bytes)
SELECTOR_IS_VALID_SIGNATURE = EIP1271_MAGIC_VALUE
# The full 32-byte return word a passing isValidSignature gives: bytes4 magic, left-aligned, zero padded.
# Comparing the whole word (as OpenZeppelin's SignatureChecker does) rejects contracts that echo calldata,
# whose first 4 bytes are the same selector.
EIP1271_MAGIC_WORD = EIP1271_MAGIC_VALUE + b"\x00" * 28
SELECTOR_IS_OWNER = bytes.fromhex("2f54bf6e")  # isOwner(address)
SELECTOR_GET_THRESHOLD = bytes.fromhex("e75235b8")  # getThreshold()
SELECTOR_DOMAIN_SEPARATOR = bytes.fromhex("f698da25")  # domainSeparator()

# keccak256("SafeMessage(bytes message)"), from Safe's CompatibilityFallbackHandler.
SAFE_MSG_TYPEHASH = bytes.fromhex("60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca")


@dataclass(frozen=True)
class SignatureResult:
    status: str  # VALID or INVALID
    wallet_type: str  # WALLET_EOA, WALLET_CONTRACT or WALLET_UNKNOWN
    detail: str  # One line for the log; never shown in Discord

    @property
    def is_valid(self):
        return self.status == VALID


class RpcError(Exception):
    """The JSON-RPC endpoint could not be reached or returned an error."""


class CallReverted(Exception):
    """An eth_call reverted, e.g. the contract does not implement the function."""


class EthRpc:
    """Just enough Ethereum JSON-RPC for signature checks, over plain requests."""

    def __init__(self, url, timeout=RPC_TIMEOUT, session=None):
        self.url = url
        self.timeout = timeout
        self.session = session or requests.Session()
        self._next_id = 0

    def _request(self, method, params):
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        try:
            response = self.session.post(self.url, json=payload, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            # Only the exception type: its text can include the URL, and RPC URLs often carry an API key.
            raise RpcError(f"{method} failed: {type(e).__name__}") from e
        try:
            body = response.json()
        except ValueError:
            body = None
        # Some gateways send a JSON-RPC error (e.g. a revert) with an HTTP error status: read it first.
        if not (isinstance(body, dict) and "error" in body):
            if not response.ok:
                raise RpcError(f"{method} failed: HTTP {response.status_code}")
            if body is None:
                raise RpcError(f"{method} returned a response that is not JSON")

        if not isinstance(body, dict):
            raise RpcError(f"{method} returned an unexpected response")
        if "error" in body:
            error = body["error"] or {}
            message = str(error.get("message", error)) if isinstance(error, dict) else str(error)
            data = str(error.get("data", "")) if isinstance(error, dict) else ""
            # Nodes report a reverted eth_call as an error. Geth uses code 3; others use -32000 or
            # -32015 with "revert" in the message, or (older Nethermind) in the data field.
            if method == "eth_call" and (
                (isinstance(error, dict) and error.get("code") == 3)
                or "revert" in message.lower()
                or "revert" in data.lower()
            ):
                raise CallReverted(message)
            raise RpcError(f"{method} returned an error: {message}")
        if "result" not in body:
            raise RpcError(f"{method} returned no result")
        return body["result"]

    def get_code(self, address):
        return _hex_to_bytes(self._request("eth_getCode", [address, "latest"]))

    def call(self, to, data):
        return _hex_to_bytes(self._request("eth_call", [{"to": to, "data": "0x" + data.hex()}, "latest"]))


def _hex_to_bytes(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RpcError(f"expected a hex string, got {value!r}")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as e:
        raise RpcError(f"invalid hex string {value!r}") from e


def _signature_bytes(signature):
    text = signature.strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    return bytes.fromhex(text)


def recover_eoa_signer(message, signature):
    """Address that signed message with personal_sign, or None if it can't be recovered."""
    try:
        return Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception as e:  # malformed signatures raise several different exception types
        logger.debug(f"EOA recovery failed: {e}")
        return None


def eip191_hash(message):
    """The hash personal_sign signs, which a contract wallet's isValidSignature receives."""
    data = message.encode("utf-8")
    return keccak(b"\x19Ethereum Signed Message:\n" + str(len(data)).encode() + data)


def safe_message_hash(domain_separator, data_hash):
    """The hash Safe owners sign for isValidSignature(bytes32 data_hash, ...)."""
    message = abi_encode(["bytes32"], [data_hash])
    struct_hash = keccak(abi_encode(["bytes32", "bytes32"], [SAFE_MSG_TYPEHASH, keccak(message)]))
    return keccak(b"\x19\x01" + domain_separator + struct_hash)


def safe_owner_signers(signature, message_hash):
    """Addresses recovered from the ECDSA parts of a Safe signature.

    A Safe signature is one or more 65-byte {r}{s}{v} parts. v = 27/28 is an
    owner's signature over message_hash; v = 31/32 is an eth_sign signature over
    it. v = 0 (contract owner) and v = 1 (pre-approved hash) carry no ECDSA
    signature and are skipped here; the EIP-1271 check still covers them.
    """
    signers = []
    usable = min(len(signature) // 65, MAX_SIGNATURE_PARTS) * 65
    for offset in range(0, usable, 65):
        part = signature[offset:offset + 65]
        r, s, v = part[:32], part[32:64], part[64]
        if v in (27, 28):
            signed_hash = message_hash
        elif v in (31, 32):
            signed_hash = keccak(b"\x19Ethereum Signed Message:\n32" + message_hash)
            v -= 4
        else:
            continue
        try:
            signers.append(Account._recover_hash(signed_hash, vrs=(v, int.from_bytes(r, "big"),
                                                                    int.from_bytes(s, "big"))))
        except Exception as e:
            logger.debug(f"Could not recover Safe owner signature at offset {offset}: {e}")
    return signers


def _eip1271_is_valid(rpc, address, data_hash, signature):
    data = SELECTOR_IS_VALID_SIGNATURE + abi_encode(["bytes32", "bytes"], [data_hash, signature])
    try:
        result = rpc.call(address, data)
    except CallReverted as e:
        logger.debug(f"isValidSignature reverted for {address}: {e}")
        return False
    return len(result) >= 32 and result[:32] == EIP1271_MAGIC_WORD


def _safe_threshold(rpc, address):
    """The Safe's threshold, or None if the contract has no getThreshold()."""
    try:
        result = rpc.call(address, SELECTOR_GET_THRESHOLD)
    except CallReverted:
        return None
    try:
        return abi_decode(["uint256"], result)[0]
    except Exception:
        return None


def _safe_owners_who_signed(rpc, address, data_hash, signature):
    """Distinct Safe owners whose ECDSA signatures are in signature, or None if not a Safe."""
    try:
        result = rpc.call(address, SELECTOR_DOMAIN_SEPARATOR)
    except CallReverted:
        return None
    try:
        domain_separator = abi_decode(["bytes32"], result)[0]
    except Exception:
        return None

    owners = []
    for signer in safe_owner_signers(signature, safe_message_hash(domain_separator, data_hash)):
        if signer in owners:
            continue
        try:
            result = rpc.call(address, SELECTOR_IS_OWNER + abi_encode(["address"], [signer]))
        except CallReverted:
            return None
        try:
            is_owner = abi_decode(["bool"], result)[0]
        except Exception:
            return None
        if is_owner:
            owners.append(signer)
    return owners


def normalise_policy(value):
    """CONTRACT_WALLET_POLICY as given (any case, stray spaces), or ValueError if it is not a known policy."""
    policy = (value or "").strip().lower()
    if policy not in POLICIES:
        raise ValueError(f"Unknown contract wallet policy {value!r}; expected one of {', '.join(POLICIES)}")
    return policy


def verify_wallet_signature(message, signature, wallet_address, rpc_url=None, policy=DEFAULT_POLICY):
    """Check that wallet_address signed message. Never raises; returns a SignatureResult."""
    if policy not in POLICIES:
        raise ValueError(f"Unknown contract wallet policy {policy!r}; expected one of {', '.join(POLICIES)}")

    try:
        wallet = to_checksum_address(wallet_address.strip())
        signature_bytes = _signature_bytes(signature)
    except Exception as e:
        logger.warning(f"Unusable wallet address or signature: {e}")
        return SignatureResult(INVALID, WALLET_UNKNOWN, "Wallet address or signature is malformed")

    signer = recover_eoa_signer(message, signature_bytes)
    if signer is not None and signer.lower() == wallet.lower():
        return SignatureResult(VALID, WALLET_EOA, "Signed by the wallet's key")

    if not rpc_url:
        return SignatureResult(INVALID, WALLET_UNKNOWN,
                               "Not signed by this address's key (contract wallets not checked: ETH_RPC_URL not set)")

    rpc = EthRpc(rpc_url)
    try:
        if not rpc.get_code(wallet):
            return SignatureResult(INVALID, WALLET_EOA, "Not signed by the wallet's key")

        data_hash = eip191_hash(message)
        contract_valid = _eip1271_is_valid(rpc, wallet, data_hash, signature_bytes)

        if contract_valid:
            if policy == POLICY_SINGLE_OWNER:
                threshold = _safe_threshold(rpc, wallet)
                if threshold != 1:
                    shown = "unknown" if threshold is None else threshold
                    detail = f"Contract wallet signature valid, but threshold is {shown} (policy needs 1)"
                    return SignatureResult(INVALID, WALLET_CONTRACT, detail)
            return SignatureResult(VALID, WALLET_CONTRACT, "Contract wallet signature valid (EIP-1271)")

        if policy == POLICY_ANY_OWNER:
            owners = _safe_owners_who_signed(rpc, wallet, data_hash, signature_bytes)
            if owners:
                threshold = _safe_threshold(rpc, wallet)
                shown = "unknown" if threshold is None else threshold
                detail = f"Signed by {len(owners)} Safe owner(s); Safe threshold is {shown}"
                return SignatureResult(VALID, WALLET_CONTRACT, detail)

        return SignatureResult(INVALID, WALLET_CONTRACT, "Contract wallet rejected the signature (EIP-1271)")
    except RpcError as e:
        logger.error(f"Could not verify signature for {wallet} over RPC: {e}")
        return SignatureResult(INVALID, WALLET_UNKNOWN, "Could not verify: Ethereum RPC unavailable")
