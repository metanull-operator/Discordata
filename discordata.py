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
import time
import argparse

HMAC_HEADER_NAME = 'x-payload-digest'
SUMSUB_BASE_URL = "https://api.sumsub.com"

REQUEST_TIMEOUT = 60

app = Flask(__name__)
Talisman(app)  # Adds HTTPS and security headers

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG
logger = logging.getLogger('werkzeug')  # Get the default Flask logger
logger.setLevel(logging.DEBUG)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Run the Discordata Flask application.')
parser.add_argument('--host', type=str, default=os.environ.get('HOST', '0.0.0.0'),
                    help='The IP address to bind to (default: from HOST env var or 0.0.0.0)')
parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 1276)),
                    help='The port number to listen on (default: from PORT env var or 1276)')
parser.add_argument('--cert', type=str, default=os.environ.get('CERT_PATH', 'certs/cert.pem'),
                    help='Path to the SSL certificate file (default: from CERT_PATH env var)')
parser.add_argument('--key', type=str, default=os.environ.get('KEY_PATH', 'certs/key.pem'),
                    help='Path to the SSL key file (default: from KEY_PATH env var)')
args = parser.parse_args()

# Use command-line arguments or environment variables for configurations
host = args.host
port = args.port
cert_path = args.cert
key_path = args.key

# Get secrets from environment variables
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')
SUMSUB_SECRET_KEY = os.environ.get('SUMSUB_SECRET_KEY')
SUMSUB_APP_TOKEN = os.environ.get('SUMSUB_APP_TOKEN')

# Get allowed IPs from environment variable
# Example format: "192.168.1.1,10.0.0.0/24"
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '0.0.0.0/0')  # Allow all by default

# Parse allowed IPs into a list of ipaddress objects
allowed_ips = [ipaddress.ip_network(ip.strip()) for ip in ALLOWED_IPS.split(',') if ip.strip()]

# Check that the secrets are provided
if not WEBHOOK_SECRET or not DISCORD_WEBHOOK_URL:
    raise Exception("Missing WEBHOOK_SECRET or DISCORD_WEBHOOK_URL environment variables")

def verify_signature(request):
    """Verify the webhook request signature."""
    signature = request.headers.get(HMAC_HEADER_NAME)
    if not signature:
        return False

    # Compute HMAC SHA256 signature
    computed_signature = hmac.new(
        WEBHOOK_SECRET.encode(),
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
    """Endpoint to receive webhook data."""
    # Log the incoming request details
    logger.debug(f"Received request from {request.remote_addr}")
    logger.debug(f"Headers: {request.headers}")
    logger.debug(f"Body: {request.data}")

    # Verify the request signature
    if not verify_signature(request):
        logger.warning(f"Invalid signature from IP: {request.remote_addr}")
        abort(400, 'Invalid signature')

    # Parse the JSON payload
    try:
        data = request.get_json()
    except Exception as e:
        logger.error(f"Invalid JSON payload: {e}")
        abort(400, 'Invalid JSON payload')

    # Check if the applicantId exists in the parsed data
    applicant_id = data.get('applicantId')
    if not applicant_id:
        logger.error("Missing applicantId in the request data")
        abort(400, 'Missing applicantId')

    # Get applicant data with error handling
    try:
        app_data = get_applicant_data(applicant_id)
    except Exception as e:
        logger.error(f"Failed to retrieve applicant data for ID {applicant_id}: {e}")
        abort(500, 'Error retrieving applicant data')

    # Process the data and create a human-friendly message
    message = format_message(data, app_data)

    # Send the message to Discord
    try:
        send_to_discord(message)
    except Exception as e:
        logger.error(f"Failed to send message to Discord: {e}")
        abort(500, 'Failed to send message to Discord')

    return '', 200


def get_applicant_data(app_id):
    """Retrieve applicant data from the external API."""
    url = SUMSUB_BASE_URL + '/resources/applicants/' + app_id + '/one'

    try:
        # Sign the request
        signed_req = sign_request(requests.Request('GET', url))

        # Send the request and handle possible network issues
        session = requests.Session()
        response = session.send(signed_req, timeout=REQUEST_TIMEOUT)

        # Check for successful response
        response.raise_for_status()

        # Return parsed JSON if the response is valid
        return response.json()
    except requests.exceptions.Timeout:
        logger.error(f"Request timed out while retrieving data for applicant ID {app_id}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Error occurred while retrieving data for applicant ID {app_id}: {e}")
        raise


def format_message(data, app_data):
    """Format the webhook data into a human-friendly Discord message."""
    event_type = data.get('type', 'Unknown Event')

    # Get the current date and time in the format YYYY-MM-DD HH:mm:ss
    current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # Convert the entire data dictionary to a human-friendly JSON string
    formatted_event = json.dumps(data, indent=4)

    logger.info(json.dumps(app_data, indent=4))

    company_name = (app_data.get('info', {})
                             .get('companyInfo', {})
                             .get('companyName', 'Unknown Company'))

    # Create a formatted message with the event type, timestamp, and pretty-printed JSON
    message = (
        f"**Company Name:** {company_name}\n"
        f"**Event Type:** {event_type}\n"
        f"**Timestamp:** {current_time} UTC\n"
        f"**Event Data:**\n```json\n{formatted_event}\n```"
    )

    return message

def sign_request(request):
    prep_req = request.prepare()

    now = int(time.time())
    method = request.method.upper()
    path_url = prep_req.path_url

    body = b'' if prep_req.body is None else prep_req.body
    if type(body) == str:
        body = body.encode('utf-8')

    data = str(now).encode('utf-8') + method.encode('utf-8') + path_url.encode('utf-8') + body

    signature = hmac.new(
        SUMSUB_SECRET_KEY.encode('utf-8'),
        data,
        digestmod=hashlib.sha256
    )

    prep_req.headers['X-App-Token'] = SUMSUB_APP_TOKEN
    prep_req.headers['X-App-Access-Ts'] = str(now)
    prep_req.headers['X-App-Access-Sig'] = signature.hexdigest()

    return prep_req

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
    # Run the Flask app with command-line arguments or environment variable configurations
    app.run(ssl_context=(cert_path, key_path), host=host, port=port)