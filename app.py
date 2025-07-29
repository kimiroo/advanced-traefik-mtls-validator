import os
import re
import base64
import logging
from datetime import datetime, timezone

from ruamel.yaml import YAML
from flask import Flask, request, abort
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from werkzeug.exceptions import HTTPException


CA_CERT_PATH = '/ca.crt'
CONFIG_FILE_PATH = '/config.yaml'
CA_CERT = None
CONFIG = {}
LOG_LEVEL_ENV = os.getenv('LOG_LEVEL', 'INFO').upper()
VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

app = Flask(__name__)
log = logging.getLogger('main')
yaml = YAML(typ='safe')


### Load LOG_LEVEL
if LOG_LEVEL_ENV in VALID_LOG_LEVELS:
    logging_level = getattr(logging, LOG_LEVEL_ENV)
else:
    logging_level = logging.INFO # Default to INFO if environment variable is invalid
    log.warning(f'Invalid LOG_LEVEL \'{LOG_LEVEL_ENV}\' provided. Defaulting to INFO.')

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging_level,
    datefmt='%m/%d/%Y %I:%M:%S %p',
)

log.info(f'Starting Advanced mTLS Validator...')

### Load config
try:
    with open(CONFIG_FILE_PATH, 'r') as f:
        CONFIG = yaml.load(f)
        if not CONFIG:
            log.warning(f'Configuration empty. Using default settings for allowed clients.')
            CONFIG = {}
        else:
            log.info(f'Configuration file loaded.')
except FileNotFoundError:
    log.warning(f'Configuration file not found. Check volume mount configuration. Using default settings for allowed clients.')
except Exception as e:
    log.error(f'Failed to load or parse configuration file: \'{e}\'. Using default settings for allowed clients.')

HEADER_CONFIG: dict = CONFIG.get('bypass_header', {})

ALLOWED_CNS: list = CONFIG.get('allowed_cns', [])
ALLOWED_SANS: dict = CONFIG.get('allowed_sans', {})
ALLOWED_PATHS: list = CONFIG.get('allowed_paths', [])
ALLOWED_HEADER: str = HEADER_CONFIG.get('name', None)
ALLOWED_KEYS: list = HEADER_CONFIG.get('keys', [])

CHECK_CNS = len(ALLOWED_CNS) > 0
CHECK_SANS = len(ALLOWED_SANS.items()) > 0
CHECK_PATHS = len(ALLOWED_PATHS) > 0
CHECK_HEADER = len(ALLOWED_KEYS) > 0 and ALLOWED_HEADER is not None and ALLOWED_HEADER != ''

log.info(f"Loaded Configuration: Path Check: {CHECK_PATHS}, CN Check: {CHECK_CNS}, SAN Check: {CHECK_SANS}, Header Bypass Check: {CHECK_HEADER}")
if log.level <= logging.DEBUG: # Only log sensitive config details if DEBUG is enabled
    log.debug(f"Allowed Client Paths: {ALLOWED_PATHS}")
    log.debug(f"Allowed Client CNs: {ALLOWED_CNS}")
    log.debug(f"Allowed Client SANs by type: {ALLOWED_SANS}")
    log.debug(f"Allowed Bypass Header: {ALLOWED_HEADER}")
    log.debug(f"Allowed Bypass Keys: {ALLOWED_KEYS}")

### Load CA certificate
try:
    with open(CA_CERT_PATH, 'rb') as f:
        CA_CERT = load_pem_x509_certificate(f.read())
    log.info(f'CA certificate loaded.')
except FileNotFoundError:
    log.critical(f'CA certificate not found. Check volume mount configuration. mTLS validation will fail.')
    CA_CERT = None
except Exception as e:
    log.critical(f'Failed to load CA certificate: \'{e}\'. mTLS validation will fail.')
    CA_CERT = None

# Determine certificate's algorithm
SIGNATURE_ALGORITHM = None
CA_PUBLIC_KEY = None
try:
    if CA_CERT: # Only attempt to get public key if CA_CERT was loaded successfully
        CA_PUBLIC_KEY = CA_CERT.public_key()
except Exception as e:
    log.critical(f'Failed to load CA public key: \'{e}\'. mTLS validation will fail.')

if CA_PUBLIC_KEY:
    if isinstance(CA_PUBLIC_KEY, ec.EllipticCurvePublicKey):
        SIGNATURE_ALGORITHM = ec.ECDSA(hashes.SHA256())
    elif isinstance(CA_PUBLIC_KEY, rsa.RSAPublicKey):
        SIGNATURE_ALGORITHM = rsa.PSS(mgf=rsa.MGF1(hashes.SHA256()), salt_length=rsa.PSS.MAX_LENGTH)
    else:
        log.critical(f'Unsupported CA public key type for signature validation. mTLS validation will fail.')
else:
    log.critical(f'CA Public Key not available. mTLS validation will fail.')


def build_pem(stripped_pem: str) -> str:
    """
    Reconstructs a full PEM formatted certificate string from a potentially stripped Base64 string.
    Adds BEGIN/END CERTIFICATE boundaries and standard 64-character line breaks.
    Also attempts to clean the input string by removing whitespace.
    """
    # Remove all whitespace (spaces, newlines, tabs) from the input string
    cleaned_pem_data = re.sub(r'\s+', '', stripped_pem)

    # Attempt to decode the cleaned data to Base64 to catch invalid characters early
    try:
        base64.b64decode(cleaned_pem_data, validate=True)
        log.debug("Cleaned PEM data is valid Base64.")
    except base64.binascii.Error as e:
        log.error(f"Cleaned PEM data is NOT valid Base64: {e}. This indicates a problem with the source data from Traefik.", exc_info=True)
        # If the Base64 data itself is invalid, attempting to reconstruct PEM might still fail.
        # It's better to log and proceed, letting load_pem_x509_certificate raise the final error.
        # Or, you could raise an exception here to stop processing early.

    if not cleaned_pem_data.startswith("-----BEGIN CERTIFICATE-----"):
        # PEM data missing BEGIN/END boundaries.
        # Add line breaks every 64 characters (standard for Base64 in PEM)
        formatted_pem_data = '\n'.join([cleaned_pem_data[i:i+64] for i in range(0, len(cleaned_pem_data), 64)])
        return (
            "-----BEGIN CERTIFICATE-----\n"
            f"{formatted_pem_data}\n"
            "-----END CERTIFICATE-----\n"
        )
    else:
        # PEM data already contains BEGIN/END boundaries. No reconstruction needed.
        return cleaned_pem_data


@app.route('/health', methods=['GET'])
def health():
    # Check if all critical components (CA cert, public key, signature algorithm) are loaded.
    if CA_CERT is not None and CA_PUBLIC_KEY is not None and SIGNATURE_ALGORITHM is not None:
        return 'I\'m healthy!', 200
    else:
        return 'Unhealthy :(', 503

@app.route('/validate', methods=['GET', 'POST'])
def validate_mtls():
    # Get request datas
    remote_addr = request.headers.get('X-Forwarded-For')
    proto = request.headers.get('X-Forwarded-Proto')
    host = request.headers.get('X-Forwarded-Host')
    port = request.headers.get('X-Forwarded-Port')
    path = request.headers.get('X-Forwarded-Uri')
    url = ''

    if ((proto == 'http' and str(port) == '80') or
        (proto == 'https' and str(port) == '443')):
        url = f'{proto}://{host}{path}'
    else:
        url = f'{proto}://{host}:{port}{path}'

    # Traefik passes client certificate information in PEM format via this header.
    client_cert_pem = request.headers.get('X-Forwarded-Tls-Client-Cert')

    # Parse PEM
    if client_cert_pem:
        if ',' in client_cert_pem:
            log.debug("Multiple certificates detected in X-Forwarded-Tls-Client-Cert header. Processing only the first one.")
            client_cert_pem = client_cert_pem.split(',', 1)[0] # Take only the first certificate

        # Use the new build_pem function to ensure correct PEM format
        client_cert_pem = build_pem(client_cert_pem)

    # --- Start: Log all request headers for debugging ---
    log.debug("--- All Request Headers ---")
    for header_name, header_value in request.headers.items():
        # Log each header name and value.
        # Note: Sensitive headers (like Authorization, Cookies) might be present.
        # Adjust logging level or filter if needed for production.
        log.debug(f"  {header_name}: {header_value}")
    log.debug("--- End All Request Headers ---")
    # --- End: Log all request headers for debugging ---

    # Custom header for bypassing mTLS validation (for devices that don't support mTLS).
    bypass_key = request.headers.get(ALLOWED_HEADER, None)

    # Log incoming request details for debugging
    log.info(f'Incoming request from \'{remote_addr}\', URL: \'{url}\', Bypass Key: \'{bypass_key}\'')

    # Step 1: Handle bypass paths.
    if CHECK_PATHS:
        for rule in ALLOWED_PATHS:
            if host == rule['host'] and path.startswith(rule['pathPrefix']):
                log.info(f'Whitelisted path detected. Allowing \'{remote_addr}\' to access \'{url}\'...')
                return 'OK', 200

    # Step 2: Handle bypass headers.
    if CHECK_HEADER and bypass_key in ALLOWED_KEYS:
        log.info(f'Valid bypass header detected. Allowing \'{remote_addr}\' to access \'{url}\'...')
        return 'OK', 200

    # Step 3: Check if CA certificate was loaded successfully.
    if CA_CERT is None:
        log.critical(f'CA certificate not loaded. Cannot perform mTLS validation. Denying \'{remote_addr}\' from accessing \'{url}\' (500 Internal Server Error)...')
        abort(500) # Internal Server Error if validator itself is misconfigured

    # Step 4: Check for client certificate presence.
    if not client_cert_pem:
        log.info(f'Client certificate missing. Denying \'{remote_addr}\' from accessing \'{url}\' (401 Unauthorized)...')
        abort(401) # Unauthorized if mTLS is expected but cert is not provided

    try:
        # Step 5: Parse the client certificate from the PEM string.
        client_cert = load_pem_x509_certificate(client_cert_pem.encode('utf-8'))

        # Step 6: Verify the client certificate's signature against the CA certificate.
        # This checks if the client certificate was indeed signed by our trusted CA.
        try:
            CA_CERT.public_key().verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                SIGNATURE_ALGORITHM
            )
        except Exception as e:
            log.info(f"Client certificate signature validation failed: \'{e}\'. Denying \'{remote_addr}\' from accessing \'{url}\' (403 Forbidden)...")
            abort(403) # Forbidden if signature is invalid

        # Step 7: Check certificate validity period (expiration).
        now = datetime.now(timezone.utc)
        if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
            log.info(f"Client certificate is expired or not yet valid. Not valid before: {client_cert.not_valid_before}, Not valid after: {client_cert.not_valid_after}. Denying \'{remote_addr}\' from accessing \'{url}\' (403 Forbidden)...")
            abort(403) # Forbidden if certificate is expired

        # Step 8: Validate Common Name (CN) or Subject Alternative Names (SANs).
        # Extract CN
        cn = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        client_cn = cn[0].value if cn else None

        # Extract SANs (RFC822Name, DNSName, IPAddress) and store them with their types.
        extracted_client_sans = {}
        try:
            alt_names = client_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for general_name in alt_names.value:
                if isinstance(general_name, x509.RFC822Name): # Email address
                    extracted_client_sans.setdefault('RFC822Name', []).append(general_name.value)
                elif isinstance(general_name, x509.DNSName): # DNS name
                    extracted_client_sans.setdefault('DNSName', []).append(general_name.value)
                elif isinstance(general_name, x509.IPAddress): # IP address
                    # Convert ipaddress object to string for comparison
                    extracted_client_sans.setdefault('IPAddress', []).append(str(general_name.value))
                # Other GeneralName types are ignored for this specific validation logic
        except x509.ExtensionNotFound:
            pass # No SAN extension

        log.debug(f'Client certificate CN: \'{client_cn}\', SANs: \'{extracted_client_sans}\'')

        # Step 8-1. Validate Common Name (CN)
        is_cn_ok = False
        if not CHECK_CNS:
            log.debug(f'Allowed CNs not set. Skipping CN validation...')
        elif CHECK_CNS and client_cn and client_cn in ALLOWED_CNS:
            is_cn_ok = True
            log.debug(f'Client CN \'{client_cn}\' is allowed.')
        else:
            log.debug(f'Client CN \'{client_cn}\' is not allowed.')

        # Step 8-2. Validate Subject Alternative Names (SANs)
        is_san_ok = False
        if not CHECK_SANS:
            log.debug(f'Allowed SANs not set. Skipping SAN validation...')
        else:
            for san_type, allowed_values in ALLOWED_SANS.items():
                client_san_values = extracted_client_sans.get(san_type, [])
                for client_san_value in client_san_values:
                    if client_san_value in allowed_values:
                        is_san_ok = True
                        log.debug(f'Client SAN of type \'{san_type}\', value \'{client_san_value}\' is allowed.')
                        break

        # Decide whether to allow or not
        is_allowed = False
        if CHECK_CNS or CHECK_SANS:
            is_allowed = is_cn_ok or is_san_ok
        else:
            is_allowed = True

        if not is_allowed:
            log.info(f'Client certificate CN \'{client_cn}\' or SANs \'{extracted_client_sans}\' is not allowed. Denying \'{remote_addr}\' from accessing \'{url}\' (403 Forbidden)...')
            abort(403) # Forbidden if CN/SAN is not allowed

        # If all checks pass, allow the request.
        log.info(f'All mTLS validation checks passed. \'{remote_addr}\' from accessing \'{url}\' (200 OK)...')
        return 'OK', 200

    except HTTPException as e:
        # If it's an HTTPException raised by abort(), re-raise it so Flask handles it correctly.
        raise e
    except Exception as e:
        log.error(f'An unexpected error occurred during mTLS validation: \'{e}\'. Denying \'{remote_addr}\' from accessing \'{url}\' (500 Internal Server Error)...', exc_info=True)
        abort(500)

if __name__ == '__main__':
    log.warning(f'This script is intended to be run with a WSGI server like Gunicorn in production.')
    log.warning(f'For local development, you can uncomment app.run() below, but it\'s not recommended for production.')
    app.run(host='0.0.0.0', port=18000, debug=True)
