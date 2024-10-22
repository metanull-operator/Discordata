import hmac
import hashlib
import json
import requests
import logging
import http.client as http_client
import os
import argparse

HMAC_HEADER_NAME = 'x-payload-digest'

# Enable logging for requests and urllib3
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

# Get webhook secret from environment variable
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')

# Check if the secret is provided
if not WEBHOOK_SECRET:
    raise Exception("Missing WEBHOOK_SECRET environment variable")

parser = argparse.ArgumentParser(description='Send mock webhook requests to a specified URL.')
parser.add_argument('--url', type=str, default='https://localhost:1276/webhook', help='The Discordata webhook URL to send the mock data to')
args = parser.parse_args()

def generate_mock_data():
    """Generate mock webhook data per Sumsub's webhook specifications."""
    return {
        "applicantId": "5c9e177b0a975a6eeccf5960",
        "inspectionId": "5c9e177b0a975a6eeccf5961",
        "correlationId": "req-63f92830-4d68-4eee-98d5-875d53a12258",
        "levelName": "basic-kyc-level",
        "externalUserId": "12672",
        "type": "applicantCreated",
        "sandboxMode": "false",
        "reviewStatus": "init",
        "createdAtMs": "2020-02-21 13:23:19.002",
        "clientId": "coolClientId"
    }

def create_signature(secret, data):
    """Generate HMAC SHA256 signature for the request."""
    return hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def send_mock_webhook(url):
    """Send a mock webhook request to the given URL with detailed logging."""
    data = generate_mock_data()
    payload = json.dumps(data)

    # Create a signature header
    signature = create_signature(WEBHOOK_SECRET, payload)
    headers = {
        'Content-Type': 'application/json',
        HMAC_HEADER_NAME: signature
    }

    try:
        # Send POST request with SSL verification (remove `verify=False`)
        response = requests.post(url, headers=headers, data=payload)

        if response.status_code == 200:
            print('Mock webhook sent successfully.')
        else:
            print(f'Failed to send mock webhook: {response.status_code} {response.text}')
    except requests.exceptions.SSLError as ssl_err:
        print(f'SSL error occurred: {ssl_err}')
    except Exception as e:
        print(f'An error occurred: {e}')


if __name__ == '__main__':
    send_mock_webhook(args.url)