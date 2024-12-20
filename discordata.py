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
from eth_account.messages import encode_defunct
from eth_account import Account
import threading
import random
import string

HMAC_HEADER_NAME = 'x-payload-digest'
SUMSUB_BASE_URL = "https://api.sumsub.com"

REQUEST_TIMEOUT = 60

# List of event types to publish to Discord
ALLOWED_EVENT_TYPES = [
    "applicantReviewed"
]

ALLOWED_REVIEW_ANSWERS = [
    "GREEN",
    "RED"
]

PROGRAM_PARTICIPATION_LOOKUP = {
    "grantsProgramParticipant": "Grants Program",
    "voProgramParticipant": "Verified Operator Program",
    "serviceProviderParticipant": "Service Provider",
    "communityProgramParticipant": "Community Program (CAP, Divers)",
    "otherParticipant": "Other"
}

app = Flask(__name__)
Talisman(app)  # Adds HTTPS and security headers

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Run the Discordata Flask application.')
parser.add_argument('--host', type=str, default=os.environ.get('HOST', '0.0.0.0'),
                    help='The network interface to bind to and listen for requests on (default: from HOST env var or 0.0.0.0)')
parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 1276)),
                    help='The port number to listen on (default: from PORT env var or 1276)')
parser.add_argument('--cert', type=str, default=os.environ.get('CERT_PATH', 'certs/cert.pem'),
                    help='Path to the SSL certificate file (default: from CERT_PATH env var)')
parser.add_argument('--key', type=str, default=os.environ.get('KEY_PATH', 'certs/key.pem'),
                    help='Path to the SSL key file (default: from KEY_PATH env var)')
parser.add_argument('--log-level', type=str, default=os.environ.get('LOG_LEVEL', 'INFO').upper(),
                    choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                    help='Set the log level (default: from LOG_LEVEL env var or INFO)')
parser.add_argument('--signature-message', type=str, default=os.environ.get('SIGNATURE_MESSAGE', None),
                    help='Message that must be signed by the owner address. Maybe be omitted to turn off signature checking.')
parser.add_argument('--acceptable-risk-score', type=int, default=os.environ.get('ACCEPTABLE_RISK_SCORE', 20),
                    help='Minimum address risk score required')
parser.add_argument('--polling-max-retries', type=int, default=os.environ.get('POLLING_MAX_RETRIES', 10),
                    help='Maximum number of polling requests for address score before quitting')
parser.add_argument('--polling-delay', type=int, default=os.environ.get('POLLING_DELAY', 5),
                    help='Number of seconds between polling retries')
args = parser.parse_args()

# Use command-line arguments or environment variables for configurations
host = args.host
port = args.port
cert_path = args.cert
key_path = args.key
log_level = args.log_level
signature_message = args.signature_message
polling_max_retries = args.polling_max_retries
polling_delay = args.polling_delay
acceptable_risk_score = args.acceptable_risk_score

# Configure logging
logging.basicConfig(level=log_level)
logger = logging.getLogger('werkzeug')  # Get the default Flask logger
logger.setLevel(log_level)

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


def generate_unique_id(length=20):
    """Generate a unique ID similar to the examples."""
    characters = string.ascii_lowercase + string.digits  # Lowercase letters and digits
    return ''.join(random.choices(characters, k=length))


@app.route('/webhook', methods=['POST'])
def webhook_listener():
    """Endpoint to receive webhook data."""
    logger.info(f"Received request from {request.remote_addr}")
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

    applicant_id = data.get('applicantId')
    logger.info(f"Applicant ID: {applicant_id}")
    if not applicant_id:
        logger.error("Missing applicantId in the request data")
        abort(400, 'Missing applicantId')

    # Check if the event type is allowed for processing
    event_type = data.get('type', 'Unknown Event')
    if ALLOWED_EVENT_TYPES and event_type not in ALLOWED_EVENT_TYPES:
        logger.info(f"Skipping event of type '{event_type}' for applicant ID {applicant_id}")
        return '', 200  # Exit early if event type is not in the allowed list

    # Check if the event type is allowed for processing
    level_name = data.get('levelName')
    if level_name == 'ubo-basic-kyc-level':
        logger.info(f"Skipping event of levelName 'ubo-basic-kyc-level' for applicant ID {applicant_id}")
        return '', 200  # Exit early if event type is not in the allowed list

    # Check if reviewAnswer is in the allowed list
    review_result = data.get('reviewResult', {})
    review_answer = review_result.get('reviewAnswer')
    if ALLOWED_REVIEW_ANSWERS and review_answer not in ALLOWED_REVIEW_ANSWERS:
        logger.info(f"Skipping event for applicant ID {applicant_id} with reviewAnswer '{review_answer}'")
        return '', 200  # Exit early if reviewAnswer is not allowed

    # Offload the address scoring and Discord notification
    logger.info(f"Offloading processing for applicant ID: {applicant_id}")
    threading.Thread(target=process_webhook_data, args=(applicant_id, data)).start()

    return '', 200  # Respond immediately


def process_webhook_data(applicant_id, data):

    wallet_address = None
    signature_hash = None
    program_participation = None
    is_valid_signature = False
    address_score = None

    try:
        # Retrieve applicant data
        app_data = get_applicant_data(applicant_id)

        review_result = data.get('reviewResult', {})
        screening_status = review_result.get('reviewAnswer')

        event_type = data.get('type', 'Unknown Event')

        for questionnaire in app_data.get('questionnaires', []):
            if questionnaire.get('id') == 'web3Identity':
                sections = questionnaire.get('sections', {})
                identity_section = sections.get('identity', {})
                program_section = sections.get('program', {})
                proof_of_ownership_section = sections.get('proofOfOwnership', {})
                identity_items = identity_section.get('items', {})
                program_items = program_section.get('items', {})
                signature_items = proof_of_ownership_section.get('items', {})
                wallet_address = identity_items.get('walletAddress', {}).get('value', None)
                signature_hash = signature_items.get('signatureHash', {}).get('value', None)
                program_participation = program_items.get('programParticipation', {}).get('value', None)
                break  # Exit loop once the desired questionnaire is found

        # Log the wallet address and signature hash for debugging
        logger.debug(f"Wallet Address: {wallet_address}")
        logger.debug(f"Signature Hash: {signature_hash}")

        if screening_status == "GREEN":
            if wallet_address:
                if signature_message and signature_hash:
                    is_valid_signature = verify_ethereum_signature(
                        signature_message,
                        signature_hash,
                        wallet_address
                    )

                if is_valid_signature:
                    address_score = get_address_score(applicant_id, wallet_address)
                    if address_score <= acceptable_risk_score:
                        add_custom_tags(applicant_id, ['Verified Wallet'])
                else:
                    add_custom_tags(applicant_id, ['Invalid Hash'])
                    address_score = None

        # Prepare and send Discord message
        message = format_message(applicant_id, event_type, screening_status, wallet_address, is_valid_signature, address_score, program_participation)
        send_to_discord(message)

        logger.info(f"Successfully processed and sent data for applicant ID: {applicant_id}")
    except Exception as e:
        logger.error(f"Error processing webhook data for applicant ID {applicant_id}: {e}")


def submit_address_request(applicant_id, wallet_address):
    external_txn_id = generate_unique_id(20)

    url = f"{SUMSUB_BASE_URL}/resources/applicants/{applicant_id}/kyt/txns/-/data"

    payload = {
        "txnId": external_txn_id,
        "type": "finance",  # Transaction type
        "info": {
            "direction": "out",
            "currencyCode": "ETH",  # Ethereum
            "amount": "0.01"  # Fictional amount
        },
        "applicant": {
            "type": "company",
            "externalUserId": wallet_address,
            "fullName": ""
        },
        "counterparty": {
            "paymentMethod": {
                "type": "crypto",
                "accountId": wallet_address
            }
        }
    }
    logger.info(f"Submitting address for score: {wallet_address}")
    logger.debug(f"Payload:\n{json.dumps(payload, indent=4)}")

    headers = {
        'Content-Type': 'application/json',
        'Content-Encoding': 'utf-8'
    }

    resp = sign_request(requests.Request("POST", url, data=json.dumps(payload), headers=headers))
    s = requests.Session()
    response = s.send(resp, timeout=REQUEST_TIMEOUT)

    logger.debug(f"Response Status Code: {response.status_code}")
    logger.debug(f"Response Headers: {response.headers}")
    logger.debug(f"Response Content: {response.text}")

    if response.status_code == 200:
        try:
            result = response.json()

            logger.debug(f"Full Response: {json.dumps(result, indent=4)}")  # Pretty print the full response
            logger.info("Transaction submitted successfully.")

            return external_txn_id
        except ValueError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.error(f"Raw Response Content: {response.text}")
            return None
    else:
        logger.error(f"Failed to submit transaction. Status: {response.status_code}, Response: {response.text}")
        return None


def get_address_score(applicant_id, wallet_address):
    external_txn_id = submit_address_request(applicant_id, wallet_address)

    if external_txn_id:
        return poll_address_score(external_txn_id)


def poll_address_score(external_txn_id, max_retries=polling_max_retries, delay=polling_delay):
    path = f"/resources/kyt/txns/-;data.txnId={external_txn_id}/one"
    url = f"{SUMSUB_BASE_URL}{path}"

    logger.info(f"Polling transaction results for txnId: {external_txn_id}")
    logger.debug(f"URL: {url}")

    resp = sign_request(requests.Request("GET", url))
    s = requests.Session()

    for attempt in range(1, max_retries + 1):
        logger.info(f"Polling attempt {attempt}/{max_retries}...")
        response = s.send(resp, timeout=REQUEST_TIMEOUT)

        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Content: {response.text}")

        if response.status_code == 200:
            try:
                result = response.json()
                logger.info(f"Full Response JSON:\n{json.dumps(result, indent=4)}")

                # Check if the scoringResult is available
                score = result.get('scoringResult', {}).get('score')
                if score is not None:
                    logger.info(f"Risk Score: {score}")
                    return score

                logger.info("Results not ready yet. Retrying...")
            except ValueError as e:
                logger.error(f"Failed to parse JSON response: {e}")
        else:
            logger.error(f"Error fetching transaction results: {response.status_code}, {response.text}")

        # Wait before the next polling attempt
        time.sleep(delay)

    logger.error("Max polling attempts reached. Results not available.")
    return None


def get_applicant_data(app_id):
    """Retrieve applicant data from the external API."""
    url = SUMSUB_BASE_URL + '/resources/applicants/' + app_id + '/one'

    try:
        # Sign the request
        signed_req = sign_request(requests.Request('GET', url))

        # Send the request and handle possible network issues
        session = requests.Session()
        logger.info(f"Requesting applicant data from API for applicant {app_id}")
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


def format_message(applicant_id, event_type, screening_status, wallet_address, is_valid_signature, address_score, program_participation):

    current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    program_title = PROGRAM_PARTICIPATION_LOOKUP.get(program_participation, "Unknown Program")

    message = "### New Applicant Status\n"
    message += f"**Program:** {program_title}\n"

    message += "**Review Status:** "
    if screening_status == "GREEN":
        message += ":white_check_mark:\n"
    elif screening_status == "RED":
        message += ":x:\n"
    else:
        message += "N/A\n"

    message += "**Hash Status:**     "
    if screening_status == "GREEN":
            if is_valid_signature:
                message += "\U00002705\n"
            else:
                message += "\U0000274C\n"
    else:
        message += "N/A\n"

    message += "**Risk Score:**        "
    if screening_status == "GREEN" and address_score is not None:
        if address_score <= acceptable_risk_score:
            message += ":green_circle:\n"
        else:
            message += ":red_circle:\n"
    else:
        message += "N/A\n"

    message += "\n**Event:**\n"
    message += f"Applicant ID: {applicant_id}\n"
    message += f"Timestamp: {current_time} UTC\n"
    message += f"Event Type: {event_type}\n"

    message += "\n**Wallet:**\n"

    message += "Wallet Address: "
    if wallet_address:
        message += f"{wallet_address}\n"
    else:
        message += "N/A\n"

    message += "Risk Score: "
    if screening_status == "GREEN" and address_score is not None:
        message += f"{address_score}\n"
    else:
        message += "N/A\n"

    logging.debug(message)

    return message


def add_custom_tags(applicant_id, tags):
    url = SUMSUB_BASE_URL + '/resources/applicants/' + applicant_id + '/tags/add'

    logger.info(f"Adding tags for applicant: {applicant_id}")
    logger.debug(f"Payload:\n{json.dumps(tags, indent=4)}")

    headers = {
        'Content-Type': 'application/json',
        'Content-Encoding': 'utf-8'
    }

    resp = sign_request(requests.Request("POST", url, data=json.dumps(tags), headers=headers))

    session = requests.Session()
    response = session.send(resp, timeout=REQUEST_TIMEOUT)

    logger.debug(f"Response Status Code: {response.status_code}")
    logger.debug(f"Response Headers: {response.headers}")
    logger.debug(f"Response Content: {response.text}")

    if response.status_code == 200:
        try:
            result = response.json()
            logger.debug(f"Full Response: {json.dumps(result, indent=4)}")
            logger.info("Tags added successfully.")
            return result
        except ValueError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.error(f"Raw Response Content: {response.text}")
            return None
    else:
        logger.error(f"Failed to add tags. Status: {response.status_code}, Response: {response.text}")
        return None


def sign_request(request: requests.Request) -> requests.PreparedRequest:
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


def verify_ethereum_signature(message, signature, expected_address):

    logger.debug(f"Verifying signature against message: -{message}-")
    logger.debug(f"Signature hash: -{signature}-")
    logger.debug(f"Expected address: -{expected_address}-")

    try:
        # Prepare the message for signing
        message_encoded = encode_defunct(text=message)

        # Recover the address from the signature
        recovered_address = Account.recover_message(message_encoded, signature=signature)

        # Compare the recovered address with the expected address
        return recovered_address.lower() == expected_address.lower()
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return False


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