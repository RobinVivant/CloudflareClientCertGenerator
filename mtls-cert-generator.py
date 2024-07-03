import os
import sys
import requests
import json
from datetime import datetime, timedelta
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

# File paths
CONFIG_FILE = "config.json"
CONFIG_TEMPLATE_FILE = "config.json.template"
OUTPUT_DIR = "mtls_cert_output"
CERT_FILE = os.path.join(OUTPUT_DIR, "client.pem")
KEY_FILE = os.path.join(OUTPUT_DIR, "client_key.pem")
FINGERPRINT_FILE = os.path.join(OUTPUT_DIR, "fingerprint.txt")
README_FILE = os.path.join(OUTPUT_DIR, "README.md")

# Default expiry in days (5 years)
DEFAULT_EXPIRY_DAYS = 5 * 365

def generate_config_from_template():
    try:
        with open(CONFIG_TEMPLATE_FILE, 'r') as template_file:
            config_template = json.load(template_file)

        print("Config file not found. Generating from template.")
        print("Please provide the following information:")

        for key in config_template:
            if key == "COMMON_NAME":
                config_template[key] = input(f"Enter {key} (press Enter for default: client-{datetime.now().strftime('%Y%m%d%H%M%S')}): ")
                if not config_template[key]:
                    config_template[key] = f"client-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            elif key == "COUNTRY":
                config_template[key] = input(f"Enter {key} (press Enter for default: US): ")
                if not config_template[key]:
                    config_template[key] = "US"
            else:
                config_template[key] = input(f"Enter {key}: ")

        with open(CONFIG_FILE, 'w') as config_file:
            json.dump(config_template, config_file, indent=2)

        print(f"Config file '{CONFIG_FILE}' has been generated.")
        return config_template
    except FileNotFoundError:
        print(f"Error: {CONFIG_TEMPLATE_FILE} not found. Please ensure the template file exists.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: {CONFIG_TEMPLATE_FILE} is not a valid JSON file.")
        sys.exit(1)
    except IOError as e:
        print(f"Error generating config file: {str(e)}")
        sys.exit(1)

def load_config(config_file):
    if not os.path.exists(config_file):
        return generate_config_from_template()

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        required_keys = ['CF_API_TOKEN', 'CF_ZONE_ID']
        missing_keys = [key for key in required_keys if key not in config]
        if missing_keys:
            raise KeyError(f"Missing required keys in {config_file}: {', '.join(missing_keys)}")

        # Set default values if not provided
        if 'COMMON_NAME' not in config:
            config['COMMON_NAME'] = f"client-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            print(f"No COMMON_NAME provided. Using default: {config['COMMON_NAME']}")

        if 'COUNTRY' not in config:
            config['COUNTRY'] = 'US'
            print(f"No COUNTRY provided. Using default: {config['COUNTRY']}")

        return config
    except FileNotFoundError:
        return generate_config_from_template()
    except json.JSONDecodeError:
        print(f"Error: {config_file} is not a valid JSON file.")
        sys.exit(1)
    except KeyError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def generate_csr(common_name, country):
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hashes.SHA256())

    # Serialize the CSR to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Serialize the private key to PEM format
    pkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return csr_pem.decode('utf-8'), pkey_pem.decode('utf-8')

def create_mtls_cert(config, expiry_days):
    url = f"https://api.cloudflare.com/client/v4/zones/{config['CF_ZONE_ID']}/client_certificates"
    headers = {
        "Authorization": f"Bearer {config['CF_API_TOKEN']}",
        "Content-Type": "application/json"
    }

    csr, private_key = generate_csr(config['COMMON_NAME'], config['COUNTRY'])

    data = {
        "name": f"mTLS Cert {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "validity_days": expiry_days,
        "csr": csr
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()['result']
        result['private_key'] = private_key  # Add the private key to the result
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error creating mTLS certificate: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            print(f"Response body: {e.response.text}")
        sys.exit(1)

def save_cert_and_key(cert_data):
    try:
        with open(CERT_FILE, 'w') as f:
            f.write(cert_data['certificate'])
        with open(KEY_FILE, 'w') as f:
            f.write(cert_data['private_key'])
    except IOError as e:
        print(f"Error saving certificate or key: {str(e)}")
        sys.exit(1)

def get_fingerprint():
    try:
        with open(CERT_FILE, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert.fingerprint(hashes.SHA256()).hex(':')
    except Exception as e:
        print(f"Error calculating fingerprint: {str(e)}")
        sys.exit(1)

def save_fingerprint(fingerprint):
    try:
        with open(FINGERPRINT_FILE, 'w') as f:
            f.write(fingerprint)
    except IOError as e:
        print(f"Error saving fingerprint: {str(e)}")
        sys.exit(1)

def create_readme(cert_data):
    readme_content = f"""
# mTLS Certificate Package

This package contains the necessary files for setting up mutual TLS (mTLS) authentication with our service.

## Contents

1. `client.pem`: The client certificate file.
2. `client_key.pem`: The private key for the client certificate.

## Certificate Details

"""
    # Add certificate details if available
    if 'id' in cert_data:
        readme_content += f"- Certificate ID: {cert_data['id']}\n"
    if 'name' in cert_data:
        readme_content += f"- Certificate Name: {cert_data['name']}\n"
    if 'expires_on' in cert_data:
        readme_content += f"- Expires On: {cert_data['expires_on']}\n"
    if 'serial_number' in cert_data:
        readme_content += f"- Serial Number: {cert_data['serial_number']}\n"
    if 'fingerprint' in cert_data:
        readme_content += f"- Fingerprint: {cert_data['fingerprint']}\n"

    readme_content += """
## Setup Instructions

1. Store these files securely. The private key (`client_key.pem`) should be kept secret.
2. Configure your client to use these files when making HTTPS requests to our service.
3. Ensure that your client validates the server's certificate as well.

## Security Notes

- Do not share the private key with anyone.
- If you suspect the private key has been compromised, contact us immediately for a new certificate.
- This certificate has a validity as specified in the 'Expires On' field above. We will contact you before it expires to arrange renewal.

For any questions or issues, please contact our support team.
    """
    try:
        with open(README_FILE, 'w') as f:
            f.write(readme_content)
    except IOError as e:
        print(f"Error creating README: {str(e)}")
        sys.exit(1)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate mTLS certificate and related files")
    parser.add_argument("-c", "--config", default=CONFIG_FILE, help="Path to the configuration file")
    parser.add_argument("-o", "--output", default=OUTPUT_DIR, help="Output directory for generated files")
    parser.add_argument("-e", "--expiry", type=int, default=DEFAULT_EXPIRY_DAYS,
                        help=f"Certificate expiry in days (default: {DEFAULT_EXPIRY_DAYS})")
    return parser.parse_args()

def main():
    args = parse_arguments()

    # Update global variables based on command-line arguments
    global CONFIG_FILE, OUTPUT_DIR, CERT_FILE, KEY_FILE, FINGERPRINT_FILE, README_FILE
    CONFIG_FILE = args.config
    OUTPUT_DIR = args.output
    CERT_FILE = os.path.join(OUTPUT_DIR, "client.pem")
    KEY_FILE = os.path.join(OUTPUT_DIR, "client_key.pem")
    FINGERPRINT_FILE = os.path.join(OUTPUT_DIR, "fingerprint.txt")
    README_FILE = os.path.join(OUTPUT_DIR, "README.md")

    # Load configuration
    config = load_config(CONFIG_FILE)

    # Print loaded configuration (without sensitive info)
    print("Loaded configuration:")
    print(f"  CF_ZONE_ID: {config['CF_ZONE_ID']}")
    print(f"  COMMON_NAME: {config['COMMON_NAME']}")
    print(f"  COUNTRY: {config['COUNTRY']}")
    print(f"  CF_API_TOKEN: {'*' * len(config['CF_API_TOKEN'])}")

    # Create output directory
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    except OSError as e:
        print(f"Error creating output directory: {str(e)}")
        sys.exit(1)

    # Create mTLS cert in Cloudflare
    print(f"Creating mTLS certificate in Cloudflare (valid for {args.expiry} days)...")
    cert_data = create_mtls_cert(config, args.expiry)

    # Save cert and key locally
    print("Saving certificate and key locally...")
    save_cert_and_key(cert_data)

    # Get and save fingerprint
    print("Calculating and saving fingerprint...")
    fingerprint = get_fingerprint()
    save_fingerprint(fingerprint)

    # Create README
    print("Creating README file...")
    create_readme(cert_data)

    print(f"\nDone! Files have been saved in the '{OUTPUT_DIR}' directory.")
    print(f"Fingerprint: {fingerprint}")
    print("Please securely share the contents of this directory with the third-party service.")

    # Print certificate details for verification
    print("\nCertificate Details:")
    for key, value in cert_data.items():
        if key != 'private_key':  # Don't print the private key
            print(f"  {key}: {value}")

if __name__ == "__main__":
    main()
