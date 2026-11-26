"""A fake Ethereum JSON-RPC node for tests, served through the `responses` library."""

import json

import responses

RPC_URL = "https://rpc.example.test/"

REVERT = object()  # return this from a handler to make the eth_call revert


class FakeChain:
    """Answers eth_getCode and eth_call for a few addresses.

    code:  {address: bytes} for contracts; any other address has no code.
    calls: {(address, selector_hex): handler}; handler(calldata_bytes) returns bytes or REVERT.
    """

    def __init__(self, code=None, calls=None):
        self.code = {k.lower(): v for k, v in (code or {}).items()}
        self.calls = {(a.lower(), s): h for (a, s), h in (calls or {}).items()}
        self.requests = []

    def install(self, rsps):
        rsps.add_callback(responses.POST, RPC_URL, callback=self._callback, content_type="application/json")

    def methods(self):
        return [r["method"] for r in self.requests]

    def _callback(self, request):
        body = json.loads(request.body)
        self.requests.append(body)
        method, params, req_id = body["method"], body["params"], body["id"]

        if method == "eth_getCode":
            code = self.code.get(params[0].lower(), b"")
            return 200, {}, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": "0x" + code.hex()})

        if method == "eth_call":
            to = params[0]["to"].lower()
            data = bytes.fromhex(params[0]["data"][2:])
            handler = self.calls.get((to, data[:4].hex()))
            result = REVERT if handler is None else handler(data)
            if result is REVERT:
                error = {"code": 3, "message": "execution reverted"}
                return 200, {}, json.dumps({"jsonrpc": "2.0", "id": req_id, "error": error})
            return 200, {}, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": "0x" + result.hex()})

        error = {"code": -32601, "message": "method not found"}
        return 200, {}, json.dumps({"jsonrpc": "2.0", "id": req_id, "error": error})
