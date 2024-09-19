import hmac
import hashlib
import json
import requests
import logging
import http.client as http_client
import os
import argparse

# Enable logging for requests and urllib3
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

# Get Quadrata webhook secret from environment variable
QUADRATA_WEBHOOK_SECRET = os.environ.get('QUADRATA_WEBHOOK_SECRET')

# Check if the secret is provided
if not QUADRATA_WEBHOOK_SECRET:
    raise Exception("Missing QUADRATA_WEBHOOK_SECRET environment variable")

# Set up argument parser for cert paths
parser = argparse.ArgumentParser(description='Send mock webhook requests to a specified URL.')
parser.add_argument('--cert', type=str, default=os.environ.get('CERT_PATH', 'certs/cert.pem'), help='Path to the SSL certificate for verification')
parser.add_argument('--url', type=str, default='https://localhost:1276/webhook', help='The Discordata webhook URL to send the mock data to')
args = parser.parse_args()

def generate_mock_data():
    """Generate mock webhook data per Quadrata's webhook specifications."""
    return {
      "attributes": {
        "AML": { "status": "READY", "verifiedAt": 1703207512 },
        "COUNTRY": { "status": "IN_REVIEW", "verifiedAt": 1703207483 },
        "DID": { "status": "IN_REVIEW", "verifiedAt": 1703207483 }
      },
      "eventId": "447849bc-db53-4b8d-b9ba-dbfec82839e4",
      "nonce": "3a186e5f",
      "timestamp": 1703207849,
      "type": "ONBOARDING",
      "walletAddresses": [
        "0xB343DB0FAB970eca78422505A82294304cE8c3eb"
      ]
    }

def create_signature(secret, data):
    """Generate HMAC SHA256 signature for the request."""
    return hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def send_mock_webhook(url, cert_path=None):
    """Send a mock webhook request to the given URL with detailed logging."""
    data = generate_mock_data()
    payload = json.dumps(data)

    # Create a signature header
    signature = create_signature(QUADRATA_WEBHOOK_SECRET, payload)
    headers = {
        'Content-Type': 'application/json',
        'Quadrata-Signature': signature
    }

    response = requests.post(url, headers=headers, data=payload)

    if response.status_code == 200:
        print('Mock webhook sent successfully.')
    else:
        print(f'Failed to send mock webhook: {response.status_code} {response.text}')


if __name__ == '__main__':
    send_mock_webhook(args.url, cert_path=args.cert)
