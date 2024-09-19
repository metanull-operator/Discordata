from flask import Flask, request, abort
import hmac
import hashlib
from flask_talisman import Talisman
import json
import requests
from datetime import datetime
import os
import ipaddress
import logging

app = Flask(__name__)
Talisman(app)  # Adds HTTPS and security headers

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG
logger = logging.getLogger('werkzeug')  # Get the default Flask logger
logger.setLevel(logging.DEBUG)

# Get secrets and configuration from environment variables
QUADRATA_WEBHOOK_SECRET = os.environ.get('QUADRATA_WEBHOOK_SECRET')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')
PORT = int(os.environ.get('PORT', 1276))
HOST = os.environ.get('HOST', '0.0.0.0')

# Get allowed IPs from environment variable
# Example format: "192.168.1.1,10.0.0.0/24"
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '0.0.0.0/0')  # Allow all by default

# Parse allowed IPs into a list of ipaddress objects
allowed_ips = [ipaddress.ip_network(ip.strip()) for ip in ALLOWED_IPS.split(',') if ip.strip()]

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

def is_ip_allowed(ip):
    """Check if the provided IP address is allowed."""
    ip_addr = ipaddress.ip_address(ip)
    return any(ip_addr in network for network in allowed_ips)

@app.before_request
def limit_remote_addr():
    """Filter requests based on client IP address."""
    client_ip = request.remote_addr
    if not is_ip_allowed(client_ip):
        # Log unauthorized access attempts
        logger.warning(f"Unauthorized access attempt from IP: {client_ip}")
        # Drop the request immediately with a 403 Forbidden status
        abort(403, description="Forbidden: Access is denied.")

@app.route('/webhook', methods=['POST'])
def webhook_listener():
    """Endpoint to receive webhook data from Quadrata."""
    # Log the incoming request details
    logger.debug(f"Received request from {request.remote_addr}")
    logger.debug(f"Headers: {request.headers}")
    logger.debug(f"Body: {request.data}")

    # Verify the request signature
    if not verify_quadrata_signature(request):
        logger.warning(f"Invalid signature from IP: {request.remote_addr}")
        abort(400, 'Invalid signature')

    # Parse the JSON payload
    try:
        data = request.get_json()
    except Exception:
        logger.error("Invalid JSON payload")
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
        logger.error(f'Failed to send message to Discord: {response.text}')

if __name__ == '__main__':
    # Run the Flask app with the environment variable configurations
    app.run(ssl_context=('certs/cert.pem', 'certs/key.pem'), host=HOST, port=PORT)
