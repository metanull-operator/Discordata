import sys
import hmac
import hashlib
import json
import requests

# Replace with your Quadrata webhook secret
QUADRATA_WEBHOOK_SECRET = 'your_quadrata_webhook_secret'


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


def send_mock_webhook(url):
    """Send a mock webhook request to the given URL."""
    data = generate_mock_data()
    payload = json.dumps(data)

    # Create a signature header
    signature = create_signature(QUADRATA_WEBHOOK_SECRET, payload)
    headers = {
        'Content-Type': 'application/json',
        'Quadrata-Signature': signature
    }

    # Send the POST request
    response = requests.post(url, headers=headers, data=payload)

    if response.status_code == 200:
        print('Mock webhook sent successfully.')
    else:
        print(f'Failed to send mock webhook: {response.status_code} {response.text}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python mock_webhook.py <webhook_url>")
        sys.exit(1)

    webhook_url = sys.argv[1]
    send_mock_webhook(webhook_url)
