# Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest                  # run the suite
pytest --cov            # with coverage (fails under 90%)
ruff check .            # lint
```

No secrets or network access are needed. `conftest.py` sets dummy values for
`WEBHOOK_SECRET`, `DISCORD_WEBHOOK_URL` and the Sumsub keys before the app is
imported, and the Sumsub and Discord calls are stubbed or mocked with `responses`.

| File | Covers |
| --- | --- |
| `test_webhook.py` | `POST /webhook` end to end: filtering by event type and review answer, error paths |
| `test_signature.py` | `x-payload-digest` HMAC verification |
| `test_ip_filter.py` | `ALLOWED_IPS` matching and the 403 before-request hook |
| `test_security_headers.py` | Talisman HTTPS redirect and security headers |
| `test_sumsub_client.py` | Sumsub request signing and `get_applicant_data` |
| `test_discord.py` | Discord message formatting and delivery |
| `test_config.py` | Import-time environment handling (runs the app in a fresh interpreter) |
| `test_server.py` | Gunicorn wrapper, command-line arguments and the `__main__` entry point |

`test_non_object_json_is_rejected_with_400` is marked `xfail(strict=True)`: a JSON
body such as `null` or `[]` currently crashes the handler with a 500. Once that is
fixed the test will start passing, and strict mode will fail it until the marker
is removed.

CI (`.github/workflows/ci.yml`) runs lint, this suite on Python 3.10 to 3.13, and
a Docker build that starts the image under Gunicorn with a self-signed
certificate and sends it signed and unsigned webhooks.
