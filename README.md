# Digital Signature Validator

A Python-based cryptographic tool for creating and verifying digital signatures using RSA asymmetric encryption and SHA-256 hashing. This tool demonstrates core concepts of digital signatures including message authenticity, integrity verification, and non-repudiation.

**NEW: Modern Next.js Frontend** - Professional web interface for all cryptographic operations.

## Features

- **RSA Key Pair Generation**: Generate secure 2048-bit (or larger) RSA key pairs with optional passphrase protection
- **Message Signing**: Sign text messages and files using your private key
- **Signature Verification**: Verify signatures using the corresponding public key
- **Multiple Padding Schemes**: Support for both PKCS#1 v1.5 (deterministic) and PSS (randomized) padding
- **Verification Logging**: Automatic audit trail of all verification attempts
- **Certificate Authority Simulation**: Create and verify X.509-like certificates for demonstrating trust chains
- **Secure Key Storage**: Private keys stored with restricted file permissions and optional AES-256 encryption

## Installation

### Backend (Python)

#### Prerequisites

- Python 3.8 or higher
- pip package manager

#### Install Dependencies

```bash
pip install -r requirements.txt
```

The main dependency is `cryptography` library, which provides cryptographic primitives.

### Frontend (Next.js)

#### Prerequisites

- Node.js 18+ and npm
- Python backend running on http://localhost:8000

#### Install Frontend

```bash
cd frontend
npm install
```

#### Run Frontend

```bash
npm run dev
```

Frontend will be available at [http://localhost:3000](http://localhost:3000)

#### Build Frontend for Production

```bash
npm run build
npm start
```

npm run build
npm start
```

## Configuration

The application can be configured using environment variables, typically stored in a `.env` file in the root directory.

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOWED_ORIGINS` | JSON list or comma-separated list of allowed CORS origins | `["http://localhost:3000", "http://localhost:3001"]` |
| `DEBUG` | Enable debug mode (true/false) | `false` |

## Setup Guide

### Backend CORS Configuration

The backend needs CORS enabled to allow requests from the frontend. Add this to `server.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Frontend Configuration

Create `.env.local` in the `frontend/` directory:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### Run Full Stack

**Terminal 1 - Start Backend:**
```bash
cd "Cyber Security Project"
python server.py
```

**Terminal 2 - Start Frontend:**
```bash
cd "Cyber Security Project/frontend"
npm run dev
```

Now access [http://localhost:3000](http://localhost:3000) to use the web interface.

### Deployment

#### Development

- **Backend**: Python backend runs on port 8000
- **Frontend**: Next.js dev server runs on port 3000
- **API Proxy**: Next.js rewrites `/api/*` to backend

#### Production

Option 1: **Serve from Same Domain (Recommended)**
```
https://cybersign.com/
  → /api/*  → Python backend (port 8000)
  → /*       → Next.js frontend (port 3000)
```

Option 2: **Serve from Different Domains**
```
Frontend: https://app.cybersign.com
Backend:  https://api.cybersign.com
```

See `frontend/README.md` for detailed deployment instructions.

## Usage

### Web Interface (Recommended)

Navigate to [http://localhost:3000](http://localhost:3000) and use the modern web interface to:
- Generate RSA key pairs
- Sign and verify text messages
- Sign and verify files
- Manage certificates through CA
- View audit logs

All features accessible through intuitive UI with real-time feedback.

### Command Line Interface (CLI)

**Generate Key Pair**

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

The main dependency is the `cryptography` library, which provides the cryptographic primitives.

## Usage

The Digital Signature Validator provides a command-line interface with several subcommands:

### Generate Key Pair

Generate a new RSA key pair with optional passphrase protection:

```bash
python main.py generate-keys --output-dir ./keys
```

With passphrase protection:

```bash
python main.py generate-keys --output-dir ./keys --passphrase "your-secure-passphrase"
```

With custom key size:

```bash
python main.py generate-keys --output-dir ./keys --key-size 4096
```

### Sign a Message

Sign a text message:

```bash
python main.py sign --message "Hello, World!" --private-key ./keys/private_key.pem --output ./signature.json
```

With PSS padding (default, recommended):

```bash
python main.py sign --message "Hello, World!" --private-key ./keys/private_key.pem --output ./signature.json --padding PSS
```

With PKCS#1 v1.5 padding (deterministic):

```bash
python main.py sign --message "Hello, World!" --private-key ./keys/private_key.pem --output ./signature.json --padding PKCS1
```

### Sign a File

Sign a file:

```bash
python main.py sign-file --file ./document.pdf --private-key ./keys/private_key.pem --output ./signature.json
```

### Verify a Message Signature

Verify a signature for a text message:

```bash
python main.py verify --message "Hello, World!" --signature ./signature.json --public-key ./keys/public_key.pem
```

### Verify a File Signature

Verify a signature for a file:

```bash
python main.py verify-file --file ./document.pdf --signature ./signature.json --public-key ./keys/public_key.pem
```

### View Verification Logs

Display all verification attempts:

```bash
python main.py show-logs
```

Filter logs by date range:

```bash
python main.py show-logs --start-date 2024-01-01 --end-date 2024-12-31
```

### Certificate Authority Operations

Create a Certificate Authority:

```bash
python main.py create-ca --output-dir ./ca
```

Sign a public key to create a certificate:

```bash
python main.py sign-certificate --public-key ./keys/public_key.pem --ca-key ./ca/ca_private_key.pem --subject "John Doe" --output ./certificate.json --days 365
```

Verify a certificate:

```bash
python main.py verify-certificate --certificate ./certificate.json --ca-public-key ./ca/ca_public_key.pem
```

## Security Considerations

### Key Management

- **Private Key Protection**: Private keys are stored with restrictive file permissions (0600 on Unix/Linux)
- **Passphrase Encryption**: Use strong passphrases to encrypt private keys at rest
- **Key Size**: Minimum 2048-bit keys are enforced; 4096-bit keys recommended for long-term security
- **Key Storage**: Never share or transmit private keys; only distribute public keys

### Padding Schemes

- **PSS (Probabilistic Signature Scheme)**: Recommended for new applications. Provides better security properties through randomization
- **PKCS#1 v1.5**: Deterministic padding scheme. Use only when compatibility with legacy systems is required

### Hash Function

- **SHA-256**: Provides 128-bit security level, matching the security of 2048-bit RSA keys
- The hash function is applied to messages before signing to ensure fixed-size input to the RSA algorithm

### Input Validation

- All file paths are validated to prevent directory traversal attacks
- Key sizes are validated to ensure minimum security requirements
- Certificate dates are validated to prevent invalid validity periods
- User inputs are sanitized to prevent injection attacks

### Verification Logging

- All verification attempts are logged with timestamps and outcomes
- Logs include message and signature identifiers (first 16 characters of hashes)
- Logs are stored in append-only format to maintain audit trail integrity

## Troubleshooting

### "Incorrect passphrase or corrupted key file"

This error occurs when:
- The passphrase provided is incorrect
- The key file is corrupted or in an invalid format
- The key file was encrypted but no passphrase was provided

**Solution**: Ensure you're using the correct passphrase. If you've forgotten the passphrase, you'll need to generate a new key pair.

### "Key size must be at least 2048 bits"

RSA keys smaller than 2048 bits are considered insecure by modern standards.

**Solution**: Use a key size of at least 2048 bits (default) or larger (e.g., 4096 bits).

### "Signature verification failed"

This error indicates that the signature does not match the message.

**Possible causes**:
- The message was modified after signing
- The wrong public key is being used
- The signature file is corrupted
- The padding scheme doesn't match (PSS vs PKCS1)

**Solution**: Ensure you're using the correct public key, the original unmodified message, and the same padding scheme used for signing.

### "Certificate expired or not yet valid"

The certificate's validity period doesn't include the current date.

**Solution**: Check the certificate's valid_from and valid_until dates. Generate a new certificate if needed.

### Permission Errors on Windows

On Windows, setting file permissions may require administrator privileges or may not work as expected.

**Solution**: The application will attempt to set permissions but will continue if it fails. Ensure you're storing private keys in a secure location with appropriate Windows ACLs.

### "File not found" Errors

**Solution**: Verify that all file paths are correct and that files exist. Use absolute paths if relative paths are causing issues.

## Project Structure

```
digital-signature-validator/
├── src/
│   ├── __init__.py
│   ├── key_manager.py          # RSA key generation and management
│   ├── signature_service.py    # Signing and verification operations
│   ├── logger_service.py       # Verification audit logging
│   ├── certificate_service.py  # Certificate Authority operations
│   ├── models.py               # Data models (SignatureResult, Certificate, etc.)
│   ├── exceptions.py           # Custom exception classes
│   ├── validation.py           # Input validation utilities
│   └── cli.py                  # Command-line interface
├── tests/
│   ├── __init__.py
│   ├── test_key_manager.py
│   ├── test_signature_service.py
│   ├── test_logger_service.py
│   ├── test_certificate_service.py
│   └── test_cli.py
├── data/
│   └── verification_logs.json  # Verification audit log
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── main.py                     # Application entry point
```

## How It Works

### Digital Signatures

1. **Signing Process**:
   - Compute SHA-256 hash of the message
   - Apply padding scheme (PSS or PKCS#1 v1.5)
   - Encrypt the padded hash with the private key
   - Store the signature along with metadata (timestamp, hash, padding scheme)

2. **Verification Process**:
   - Compute SHA-256 hash of the received message
   - Decrypt the signature using the public key
   - Compare the decrypted hash with the computed hash
   - Log the verification attempt and result

### Certificate Authority

The CA functionality simulates a simplified X.509 certificate workflow:

1. **Certificate Creation**:
   - CA signs a public key along with subject information and validity period
   - The signature proves the CA vouches for the public key's authenticity

2. **Certificate Verification**:
   - Verify the CA's signature on the certificate
   - Check that the current date falls within the validity period
   - If both checks pass, the public key can be trusted

## Examples

### Complete Workflow Example

```bash
# 1. Generate a key pair
python main.py generate-keys --output-dir ./alice_keys

# 2. Sign a message
python main.py sign --message "This is a secret message" --private-key ./alice_keys/private_key.pem --output ./message_signature.json

# 3. Verify the signature
python main.py verify --message "This is a secret message" --signature ./message_signature.json --public-key ./alice_keys/public_key.pem

# 4. View verification logs
python main.py show-logs
```

### Certificate Authority Example

```bash
# 1. Create a Certificate Authority
python main.py create-ca --output-dir ./ca

# 2. Generate a user key pair
python main.py generate-keys --output-dir ./bob_keys

# 3. Sign Bob's public key to create a certificate
python main.py sign-certificate --public-key ./bob_keys/public_key.pem --ca-key ./ca/ca_private_key.pem --subject "Bob Smith" --output ./bob_certificate.json

# 4. Verify Bob's certificate
python main.py verify-certificate --certificate ./bob_certificate.json --ca-public-key ./ca/ca_public_key.pem
```

## Testing

Run the test suite:

```bash
pytest tests/
```

Run tests with coverage:

```bash
pytest tests/ --cov=src --cov-report=html
```

## License

This project is for educational purposes to demonstrate digital signature concepts.

## Contributing

This is an educational project. Feel free to fork and modify for your learning purposes.

## Acknowledgments

Built using the `cryptography` library, which provides robust cryptographic primitives for Python.
