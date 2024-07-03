# Cloudflare Client Certificate Generator

This project provides a Python script to generate mTLS (mutual TLS) client certificates using the Cloudflare API. It automates the process of creating, downloading, and organizing client certificates for use with Cloudflare's mTLS feature.

## Features

- Generates mTLS client certificates using the Cloudflare API
- Saves the certificate, private key, and fingerprint locally
- Creates a detailed README file for each generated certificate
- Supports custom configuration via a JSON file
- Automatically generates a config file from a template if not found

## Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/CloudflareClientCertGenerator.git
   cd CloudflareClientCertGenerator
   ```

2. Ensure you have Python 3.6 or later installed on your system.

3. Install the required Python packages:
   ```
   pip install requests cryptography
   ```

4. (Optional) If you don't have a `config.json` file, the script will generate one for you based on the `config.json.template`. You can also create it manually with the following structure:
   ```json
   {
     "CF_API_TOKEN": "your_cloudflare_api_token",
     "CF_ZONE_ID": "your_cloudflare_zone_id",
     "COMMON_NAME": "your_common_name",
     "COUNTRY": "US"
   }
   ```

## Usage

Run the script with Python:

```
python mtls-cert-generator.py
```

### Command-line Options

- `-c`, `--config`: Specify a custom path for the config file (default: `config.json`)
- `-o`, `--output`: Specify a custom output directory for generated files (default: `mtls_cert_output`)
- `-e`, `--expiry`: Set the certificate expiry in days (default: 1825 days, which is 5 years)

Example with custom options:

```
python mtls-cert-generator.py -c my_config.json -o my_output_dir -e 365
```

## Output

The script generates the following files in the output directory:

- `client.pem`: The client certificate
- `client_key.pem`: The private key for the client certificate
- `fingerprint.txt`: The SHA256 fingerprint of the certificate
- `README.md`: Instructions and details about the generated certificate

## Security Notes

- Keep the private key (`client_key.pem`) secure and confidential.
- If you suspect the private key has been compromised, revoke the certificate and generate a new one.
- Ensure that the Cloudflare API token used has the necessary permissions to create client certificates.

## Contributing

Contributions to improve the script are welcome. Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
