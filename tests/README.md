# Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest                  # run the suite
pytest --cov            # with coverage (fails under 90%)
ruff check .            # lint
```

No secrets or network access are needed. `conftest.py` sets dummy values for
`WEBHOOK_SECRET`, `DISCORD_WEBHOOK_URL` and the Sumsub keys, and clears the
command line, before the app is imported. Sumsub and Discord calls are stubbed
or mocked with `responses`, and Ethereum RPC calls go to `fake_chain.py`.

| File | Covers |
| --- | --- |
| `test_signature_verification.py` | Wallet signature checks: EOAs, Safe / EIP-1271, every `CONTRACT_WALLET_POLICY`, RPC failures. Uses the real Safe signature from the Hash Status ❌ report. |
| `test_processing.py` | `process_webhook_data` and `format_message`: Hash Status ✅ / ❌, Sumsub tags, risk score, and that the Discord message format is unchanged |
| `test_webhook.py` | `POST /webhook`: HMAC check, filtering by event type, level and review answer, handing work to the background thread |
| `test_sumsub_kyt.py` | Wallet risk score submit and polling, applicant tags, Discord delivery |
| `test_sumsub_client.py` | Sumsub request signing and `get_applicant_data` |
| `test_config.py` | Startup settings (`CONTRACT_WALLET_POLICY`, `ETH_RPC_URL`, `SIGNATURE_MESSAGE`), run in a fresh interpreter |
| `test_signature.py` | `x-payload-digest` HMAC verification |
| `test_ip_filter.py` | `ALLOWED_IPS` matching and the 403 before-request hook |
| `test_security_headers.py` | Talisman HTTPS redirect and security headers |

CI (`.github/workflows/ci.yml`) runs lint, this suite on Python 3.9 (the
Dockerfile's version) to 3.13, and a Docker build that starts the image with a
self-signed certificate and sends it signed and unsigned webhooks.
