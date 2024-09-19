from flask import Flask, request, abort
import hmac
import hashlib
import json
import requests
from datetime import datetime
import os
import argparse

app = Flask(__name__)

# Get secrets and configuration from environment variables
QUADRATA_WEBHOOK_SECRET = os.environ.get('QUADRATA_WEBHOOK_SECRET')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')

# Check that the secrets are provided
if not QUADRATA_WEBHOOK_SECRET or not DISCORD_WEBHOOK_URL:
    raise Exception("Missing QUADRATA_WEBHOOK_SECRET or DISCORD_WEBHOOK_URL environment variables")

def verify_quadrata_signature(request):
    """Verify the Quadrata webhook request signature."""
    signature = request.headers.get('Quadrata-Signature')
    if not signature:
        return False

    # Compute HMAC SHA256 signature
    computed_signature = hmac.new(
        QUADRATA_WEBHOOK_SECRET.encode(),
        request.data,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed_signature, signature)

@app.route('/webhook', methods=['POST'])
def webhook_listener():
    """Endpoint to receive webhook data from Quadrata."""
    # Verify the request signature
    if not verify_quadrata_signature(request):
        abort(400, 'Invalid signature')

    # Parse the JSON payload
    try:
        data = request.get_json()
    except Exception:
        abort(400, 'Invalid JSON payload')

    # Process the data and create a human-friendly message
    message = format_message(data)

    # Send the message to Discord
    send_to_discord(message)

    return '', 200

def format_message(data):
    """Format the webhook data into a human-friendly Discord message."""
    event_type = data.get('type', 'Unknown Event')
    event_id = data.get('eventId', 'N/A')
    nonce = data.get('nonce', 'N/A')
    timestamp = data.get('timestamp', 'N/A')

    # Convert Unix timestamp to human-readable format
    if isinstance(timestamp, int):
        readable_timestamp = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    else:
        readable_timestamp = 'N/A'

    wallet_addresses = data.get('walletAddresses', [])
    wallet_addresses_str = ', '.join(wallet_addresses) if wallet_addresses else 'N/A'

    attributes = data.get('attributes', {})
    attributes_info = ''
    for attr_name, attr_data in attributes.items():
        status = attr_data.get('status', 'N/A')
        verified_at = attr_data.get('verifiedAt', 'N/A')
        if isinstance(verified_at, int):
            verified_at_str = datetime.utcfromtimestamp(verified_at).strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            verified_at_str = 'N/A'
        attributes_info += f"**{attr_name}**:\n- Status: {status}\n- Verified At: {verified_at_str}\n"

    # Create a formatted message
    message = (
        f"**Event Type:** {event_type}\n"
        f"**Event ID:** {event_id}\n"
        f"**Nonce:** {nonce}\n"
        f"**Timestamp:** {readable_timestamp}\n"
        f"**Wallet Addresses:** {wallet_addresses_str}\n\n"
        f"**Attributes:**\n{attributes_info}"
    )
    return message

def send_to_discord(message):
    """Send the formatted message to Discord via webhook."""
    payload = {
        'content': message
    }
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(DISCORD_WEBHOOK_URL, json=payload, headers=headers)
    if response.status_code != 204:
        print('Failed to send message to Discord:', response.text)

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run the Discordata Flask application.')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='The IP address to bind to.')
    parser.add_argument('--port', type=int, default=1276, help='The port number to listen on.')
    args = parser.parse_args()

    # Run the Flask app with the provided host and port
    app.run(host=args.host, port=args.port)
