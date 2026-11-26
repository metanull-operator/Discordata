# Discordata
Discordata is a bridge between incoming Sumsub KYC provider webhook
requests and outgoing Discord webhook requests. Each time a
webhook request is received, Discordata requests additional applicant data via an API call to Sumsub, requests Ethereum address risk score via an API call to Sumsub, optionally verifies an Ethereum digital signature, formats a
message, and sends the message via the Discord webhook URL.

Discord data can be run as a standalone application or as a
docker container. 

By default Discordata will listen on port `1276` for requests
to the `webhook` endpoint. Port 1276 must be opened and forwarded
to Discordata. The URL to the webhook endpoint must be provided to
the KYC provider. For example, `http://XXX.XXX.XXX.XXX:1276/webhook/`.

## Clone the Repository

Clone the Discordata github repository:

```console
git clone https://github.com/metanull-operator/discordata.git
```

Change directory into the Discordata repository:

```console
cd discordata
```

## Generate Certificate

If you want to use a self-signed certificate, generate the certificate and key.
Adjust `-days` to the appropriate length of time your certificate should be valid.

```console
cd certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
cd ..
```

## Environment Variables

### Required Environment Variables

Two environment variables are required to be exported to Discordata in order to run:

- `WEBHOOK_SECRET` - A shared secret for secure
  communication with the KYC provider. Provided by the KYC provider.
- `DISCORD_WEBHOOK_URL` - The URL for the Discord webhook to be 
  used to send messages to Discord. This can be provided by the
  administrators of the Discord server.
- `SUBSUM_SECRET_KEY` - Secret key required to access Sumsub API.
- `SUMSUB_APP_TOKEN` - App token required to access Sumsub API.

### Optional Environment Variables

Two additional environment variables may be set to modify default behaviors:

- `ALLOWED_IPS` - Comma-delimited list of remote IP addresses or subnets
  from which requests will be accepted. Defaults to `0.0.0.0`, all remote IP addresses.
- `PORT` - Port on which Discordata will listen. For Docker containers,
  this is the internal port on which Discordata is listening. The
  external port can be adjusted with the `-p` flag on the run
  command. Defaults to `1276`.
- `HOST` - The network interface to which Discordata should bind and listen for requests. Defaults to `0.0.0.0`, all network interfaces.
- `CERT_PATH` - Path to the SSL cerificate file.
- `KEY_PATH` - Path to the SSL key file.
- `LOG_LEVEL` - Level of log messages to output. Allowed values: `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. Defaults to `INFO`.
- `SIGNATURE_MESSAGE` - The message to be signed by the applicant's Ethereum address. Used to verify the signature. Signature verification is skipped if this value is not present.
- `ETH_RPC_URL` - Ethereum mainnet JSON-RPC URL, for example your own execution client (`http://127.0.0.1:8545`). Needed to check signatures from smart contract wallets such as Safe. Without it, only plain wallet (EOA) signatures can pass, and every smart contract wallet shows ❌.
- `CONTRACT_WALLET_POLICY` - How smart contract wallet signatures are judged. One of `strict`, `any_owner` or `single_owner`. Defaults to `strict`. See [Smart contract wallets](#smart-contract-wallets-safe).
- `ACCEPTABLE_RISK_SCORE` - The maximum risk score allowed to pass the Ethereum address risk review. All scores less than or equal to this value pass the review. Defaults to `20`.
- `POLLING_MAX_RETRIES` - Maximum number of attempts to retrieve the Ethereum address risk score. Defaults to `10`.
- `POLLING_DELAY` - The number of seconds between attempts to retrieve the Ethereum address risk score. Defaults to  `5`.

### Set Environment Variables in .env

Copy `.env.sample` to `.env` and modify the values of the variables to 
suit your environment.

```console
cp .env.sample .env
```

Both examples of running the application below rely on
a `.env` environment variable file, but other methods of setting
the environment variables may be used.

## Run as Docker Container

### Build the Docker Image

```console
docker build -t discordata .
```

### Run Docker Container

Run the following docker command, making the appropriate substitutions:

- Substitute `<PATH_TO_REPO>` with the absolute path to your Discordata repository'
- Change the external container port 1276 with another port, if necessary.
  For example `-p 5000:1276`.

```console
docker run \
    -p 1276:1276 \
    --env-file .env \
    --name discordata \
    -v <PATH_TO_REPO>/certs/cert.pem:/certs/cert.pem \
    -v <PATH_TO_REPO>/certs/key.pem:/certs/key.pem \
    discordata
```

Otherwise, place your organization's `cert.pem` and `key.pem` file in the `certs/` directory.

## Standalone

### Install Python Packages

```console
pip3 install -r requirements.txt
```

### Run discordata.sh

```console
WEBHOOK_SECRET="webhook secret" DISCORD_WEBHOOK_URL="discord webhook url" SUMSUB_SECRET_KEY="sumsub secret key" SUMSUB_APP_TOKEN="sumsub app token" ./discordata.sh --cert certs/cert.pem --key certs/key.pem --signature-message "Sign this message"
```

## Hash Status

When a review is GREEN, the Discord message shows whether the applicant's wallet signed `SIGNATURE_MESSAGE`:

| Hash Status | Meaning | Sumsub tag |
| --- | --- | --- |
| ✅ | Signature is valid. The wallet risk score is then requested. | `Verified Wallet` if the risk score is at or below `ACCEPTABLE_RISK_SCORE` |
| ❌ | Signature is not valid, there was no signature to check, or it could not be confirmed (for example the RPC was unreachable). | `Invalid Hash` |

The message format is fixed: Hash Status is only ✅ or ❌. The reason for each result is written to the log at
`INFO` level, for example `Signature check for 0x…: invalid (Smart contract: Contract wallet rejected the signature (EIP-1271))`.

## Smart contract wallets (Safe)

A Safe has no private key. Its owners sign a wrapped version of the message, and the Safe contract decides
whether those signatures are enough (EIP-1271 `isValidSignature`). A plain signature check can never pass for a
Safe, so Discordata asks the contract over `ETH_RPC_URL`. `CONTRACT_WALLET_POLICY` sets the rule:

| Policy | ✅ when | Use it if |
| --- | --- | --- |
| `strict` (default) | The Safe accepts the signature (its threshold is met). | You want the same rule wallets, dapps and Etherscan use. |
| `any_owner` | The Safe accepts it, or any one owner signed. | One owner's signature is enough proof of control for you. |
| `single_owner` | The Safe accepts it and its threshold is 1. | You only want Safes that one person fully controls. |

Everything else is ❌, including when `ETH_RPC_URL` is unreachable.

Plain wallets (EOAs) are checked offline and are not affected by the policy. Only Ethereum mainnet is checked.

