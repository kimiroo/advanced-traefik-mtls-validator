import os
import logging
from datetime import datetime, timezone

from ruamel.yaml import YAML
from flask import Flask, request, abort
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID


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
    log.info(f'Configuration file loaded.')
except FileNotFoundError:
    log.warning(f'Configuration file not found. Check volume mount configuration. Using default settings for allowed clients.')
except Exception as e:
    log.error(f'Failed to load or parse configuration file: \'{e}\'. Using default settings for allowed clients.')

HEADER_CONFIG: dict = CONFIG.get('bypass_header', {})

ALLOWED_CNS: list = CONFIG.get('allowed_cns', [])
ALLOWED_SANS: dict = CONFIG.get('allowed_sans', {})
ALLOWED_HEADER: str = HEADER_CONFIG.get('name', None)
ALLOWED_KEYS: list = HEADER_CONFIG.get('keys', [])

CHECK_CNS = len(ALLOWED_CNS) > 0
CHECK_SANS = len(ALLOWED_SANS.items()) > 0
CHECK_HEADER = len(ALLOWED_KEYS) > 0 and ALLOWED_HEADER is not None and ALLOWED_HEADER != ''

log.info(f"Loaded Configuration: CN Check: {CHECK_CNS}, SAN Check: {CHECK_SANS}, Header Bypass Check: {CHECK_HEADER}")
if log.level <= logging.DEBUG: # Only log sensitive config details if DEBUG is enabled
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


@app.route('/health', methods=['GET'])
def health():
    # Check if all critical components (CA cert, public key, signature algorithm) are loaded.
    if CA_CERT is not None and CA_PUBLIC_KEY is not None and SIGNATURE_ALGORITHM is not None:
        return 'I\'m healthy!', 200
    else:
        return 'Unhealthy :(', 503

@app.route('/validate', methods=['GET', 'POST'])
def validate_mtls():
    # Traefik passes client certificate information in PEM format via this header.
    client_cert_pem = request.headers.get('X-Forwarded-Tls-Client-Cert')

    # Custom header for bypassing mTLS validation (for devices that don't support mTLS).
    bypass_key = request.headers.get(ALLOWED_HEADER, None)

    # Log incoming request details for debugging
    log.info(f'Incoming request from \'{request.remote_addr}\', Path: \'{request.path}\', Bypass Key: \'{bypass_key}\'')

    # Step 1: Handle bypass condition first.
    if CHECK_HEADER and bypass_key in ALLOWED_KEYS:
        log.info(f'Valid X-Bypass-Mtls key detected. Allowing \'{request.remote_addr}\' to access \'{request.path}\'...')
        return 'OK', 200

    # Step 2: Check if CA certificate was loaded successfully.
    if CA_CERT is None:
        log.critical(f'CA certificate not loaded. Cannot perform mTLS validation. Denying \'{request.remote_addr}\' from accessing \'{request.path}\' (500 Internal Server Error)...')
        abort(500) # Internal Server Error if validator itself is misconfigured

    # Step 3: Check for client certificate presence.
    if not client_cert_pem:
        log.info(f'Client certificate missing. Denying \'{request.remote_addr}\' from accessing \'{request.path}\' (401 Unauthorized)...')
        abort(401) # Unauthorized if mTLS is expected but cert is not provided

    try:
        # Step 4: Parse the client certificate from the PEM string.
        client_cert = load_pem_x509_certificate(client_cert_pem.encode('utf-8'))

        # Step 5: Verify the client certificate's signature against the CA certificate.
        # This checks if the client certificate was indeed signed by our trusted CA.
        try:
            CA_CERT.public_key().verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                SIGNATURE_ALGORITHM
            )
        except Exception as e:
            log.info(f"Client certificate signature validation failed: \'{e}\'. Denying \'{request.remote_addr}\' from accessing \'{request.path}\' (403 Forbidden)...")
            abort(403) # Forbidden if signature is invalid

        # Step 6: Check certificate validity period (expiration).
        now = datetime.now(timezone.utc)
        if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
            log.info(f"Client certificate is expired or not yet valid. Not valid before: {client_cert.not_valid_before}, Not valid after: {client_cert.not_valid_after}. Denying \'{request.remote_addr}\' from accessing \'{request.path}\' (403 Forbidden)...")
            abort(403) # Forbidden if certificate is expired

        # Step 7: Validate Common Name (CN) or Subject Alternative Names (SANs).
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

        # Step 7-1. Validate Common Name (CN)
        is_allowed = False
        if not CHECK_CNS:
            log.debug(f'Allowed CNs not set. Skipping CN validation...')
        if CHECK_CNS and client_cn and client_cn in ALLOWED_CNS:
            is_allowed = True
            log.debug(f'Client CN \'{client_cn}\' is allowed.')
        else:
            log.debug(f'Client CN \'{client_cn}\' is not allowed.')

        # Step 7-2. Validate Subject Alternative Names (SANs)
        if not CHECK_SANS:
            log.debug(f'Allowed SANs not set. Skipping SAN validation...')
        else:
            for san_type, allowed_values in ALLOWED_SANS.items():
                client_san_values = extracted_client_sans.get(san_type, [])
                for client_san_value in client_san_values:
                    if client_san_value in allowed_values:
                        is_allowed = True
                        log.debug(f'Client SAN of type \'{san_type}\', value \'{client_san_value}\' is allowed.')
                        break

        if not is_allowed:
            log.info(f'Client certificate CN \'{client_cn}\' or SANs \'{extracted_client_sans}\' is not allowed. Denying \'{request.remote_addr}\' from accessing \'{request.path}\' (403 Forbidden)...')
            abort(403) # Forbidden if CN/SAN is not allowed

        # If all checks pass, allow the request.
        log.info(f'All mTLS validation checks passed. \'{request.remote_addr}\' from accessing \'{request.path}\' (200 OK)...')
        return 'OK', 200

    except Exception as e:
        log.error(f'An unexpected error occurred during mTLS validation: \'{e}\'. Denying \'{request.remote_addr}\' from accessing \'{request.path}\' (500 Internal Server Error)...', exc_info=True)
        abort(500)

if __name__ == '__main__':
    log.warning(f'This script is intended to be run with a WSGI server like Gunicorn in production.')
    log.warning(f'For local development, you can uncomment app.run() below, but it\'s not recommended for production.')
    app.run(host='0.0.0.0', port=18000, debug=True)
