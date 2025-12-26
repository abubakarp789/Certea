"""
Pytest Configuration and Shared Fixtures

Provides common test fixtures for the Digital Signature Validator test suite.
"""

import os
import sys
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Tuple, Generator
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.key_manager import KeyManager
from src.signature_service import SignatureService
from src.certificate_service import CertificateAuthority
from src.logger_service import VerificationLogger
from src.models import Certificate


# --- Pytest Markers ---
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "security: marks tests as security-focused tests")
    config.addinivalue_line("markers", "concurrent: marks tests as concurrent/parallel tests")


# --- Temporary Directory Fixtures ---
@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Create a temporary directory for test files."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def keys_dir(temp_dir: str) -> str:
    """Create a temporary directory for key storage."""
    keys_path = os.path.join(temp_dir, 'keys')
    os.makedirs(keys_path, exist_ok=True)
    return keys_path


@pytest.fixture
def data_dir(temp_dir: str) -> str:
    """Create a temporary directory for data storage."""
    data_path = os.path.join(temp_dir, 'data')
    os.makedirs(data_path, exist_ok=True)
    return data_path


# --- Service Fixtures ---
@pytest.fixture
def key_manager() -> KeyManager:
    """Create a KeyManager instance."""
    return KeyManager()


@pytest.fixture
def signature_service(data_dir: str) -> SignatureService:
    """Create a SignatureService instance with a test logger."""
    log_file = os.path.join(data_dir, 'test_logs.json')
    logger = VerificationLogger(log_file)
    return SignatureService(logger)


@pytest.fixture
def verification_logger(data_dir: str) -> VerificationLogger:
    """Create a VerificationLogger instance."""
    log_file = os.path.join(data_dir, 'verification_logs.json')
    return VerificationLogger(log_file)


# --- Key Pair Fixtures ---
@pytest.fixture
def key_pair_2048(key_manager: KeyManager) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a 2048-bit RSA key pair."""
    return key_manager.generate_key_pair(2048)


@pytest.fixture
def key_pair_3072(key_manager: KeyManager) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a 3072-bit RSA key pair."""
    return key_manager.generate_key_pair(3072)


@pytest.fixture
def key_pair_4096(key_manager: KeyManager) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a 4096-bit RSA key pair."""
    return key_manager.generate_key_pair(4096)


@pytest.fixture
def private_key(key_pair_2048) -> rsa.RSAPrivateKey:
    """Get just the private key from a 2048-bit pair."""
    return key_pair_2048[0]


@pytest.fixture
def public_key(key_pair_2048) -> rsa.RSAPublicKey:
    """Get just the public key from a 2048-bit pair."""
    return key_pair_2048[1]


@pytest.fixture
def saved_key_pair(key_manager: KeyManager, keys_dir: str, key_pair_2048) -> Tuple[str, str]:
    """Save a key pair to files and return the paths."""
    private_key, public_key = key_pair_2048
    
    private_key_path = os.path.join(keys_dir, 'private_key.pem')
    public_key_path = os.path.join(keys_dir, 'public_key.pem')
    
    key_manager.save_private_key(private_key, private_key_path)
    key_manager.save_public_key(public_key, public_key_path)
    
    return private_key_path, public_key_path


@pytest.fixture
def encrypted_private_key_path(key_manager: KeyManager, keys_dir: str, key_pair_2048) -> Tuple[str, str]:
    """Save an encrypted private key and return path and passphrase."""
    private_key, _ = key_pair_2048
    passphrase = "test_passphrase_123"
    
    private_key_path = os.path.join(keys_dir, 'encrypted_private_key.pem')
    key_manager.save_private_key(private_key, private_key_path, passphrase)
    
    return private_key_path, passphrase


# --- CA Fixtures ---
@pytest.fixture
def ca_key_pair(key_manager: KeyManager) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a CA key pair."""
    return key_manager.generate_key_pair(2048)


@pytest.fixture
def certificate_authority(ca_key_pair) -> CertificateAuthority:
    """Create a CertificateAuthority instance."""
    ca_private_key, ca_public_key = ca_key_pair
    return CertificateAuthority(ca_private_key, ca_public_key, "Test CA")


@pytest.fixture
def valid_certificate(certificate_authority: CertificateAuthority, public_key: rsa.RSAPublicKey) -> Certificate:
    """Create a valid certificate."""
    return certificate_authority.sign_public_key(public_key, "Test Subject", 365)


# --- Sample Data Fixtures ---
@pytest.fixture
def sample_message() -> str:
    """Return a sample message for signing."""
    return "This is a test message for digital signature verification."


@pytest.fixture
def sample_unicode_message() -> str:
    """Return a sample message with unicode characters."""
    return "Hello World! 你好世界! مرحبا بالعالم! 🔐🔑✅"


@pytest.fixture
def sample_binary_data() -> bytes:
    """Return sample binary data."""
    return bytes(range(256)) * 100


@pytest.fixture
def empty_message() -> str:
    """Return an empty message."""
    return ""


@pytest.fixture
def large_message() -> str:
    """Return a large message (1MB)."""
    return "X" * (1024 * 1024)


@pytest.fixture
def sample_file_path(temp_dir: str) -> str:
    """Create a sample file and return its path."""
    filepath = os.path.join(temp_dir, 'sample.txt')
    with open(filepath, 'w') as f:
        f.write("This is sample file content for signing tests.")
    return filepath


@pytest.fixture
def empty_file_path(temp_dir: str) -> str:
    """Create an empty file and return its path."""
    filepath = os.path.join(temp_dir, 'empty.txt')
    with open(filepath, 'w') as f:
        pass  # Create empty file
    return filepath


@pytest.fixture
def large_file_path(temp_dir: str) -> str:
    """Create a large file (10MB) and return its path."""
    filepath = os.path.join(temp_dir, 'large_file.bin')
    with open(filepath, 'wb') as f:
        # Write 10MB of data
        f.write(b'X' * (10 * 1024 * 1024))
    return filepath


@pytest.fixture
def binary_file_path(temp_dir: str, sample_binary_data: bytes) -> str:
    """Create a binary file and return its path."""
    filepath = os.path.join(temp_dir, 'binary.bin')
    with open(filepath, 'wb') as f:
        f.write(sample_binary_data)
    return filepath


# --- Malformed Data Fixtures ---
@pytest.fixture
def invalid_pem_content() -> str:
    """Return invalid PEM content."""
    return "-----BEGIN INVALID KEY-----\nNOT_VALID_BASE64_DATA\n-----END INVALID KEY-----"


@pytest.fixture
def invalid_pem_file(temp_dir: str, invalid_pem_content: str) -> str:
    """Create a file with invalid PEM content."""
    filepath = os.path.join(temp_dir, 'invalid.pem')
    with open(filepath, 'w') as f:
        f.write(invalid_pem_content)
    return filepath


@pytest.fixture
def corrupted_signature() -> bytes:
    """Return a corrupted signature (random bytes)."""
    import random
    return bytes([random.randint(0, 255) for _ in range(256)])


# --- Certificate Fixtures ---
@pytest.fixture
def expired_certificate(ca_key_pair, public_key: rsa.RSAPublicKey) -> Certificate:
    """Create an expired certificate (for testing)."""
    ca_private_key, ca_public_key = ca_key_pair
    
    # Create certificate with past dates
    valid_from = datetime.now() - timedelta(days=365)
    valid_until = datetime.now() - timedelta(days=1)
    
    certificate = Certificate(
        public_key=public_key,
        subject="Expired Subject",
        issuer="Test CA",
        valid_from=valid_from,
        valid_until=valid_until,
        signature=b''
    )
    certificate.sign(ca_private_key)
    return certificate


@pytest.fixture
def future_certificate(ca_key_pair, public_key: rsa.RSAPublicKey) -> Certificate:
    """Create a not-yet-valid certificate."""
    ca_private_key, ca_public_key = ca_key_pair
    
    # Create certificate with future dates
    valid_from = datetime.now() + timedelta(days=1)
    valid_until = datetime.now() + timedelta(days=365)
    
    certificate = Certificate(
        public_key=public_key,
        subject="Future Subject",
        issuer="Test CA",
        valid_from=valid_from,
        valid_until=valid_until,
        signature=b''
    )
    certificate.sign(ca_private_key)
    return certificate


# --- Passphrase Fixtures ---
@pytest.fixture
def simple_passphrase() -> str:
    """Return a simple passphrase."""
    return "password123"


@pytest.fixture
def special_chars_passphrase() -> str:
    """Return a passphrase with special characters."""
    return "P@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"


@pytest.fixture
def unicode_passphrase() -> str:
    """Return a passphrase with unicode characters."""
    return "密码مرور🔐パスワード"


@pytest.fixture
def long_passphrase() -> str:
    """Return a very long passphrase (1000+ chars)."""
    return "A" * 1000 + "B" * 100


# --- Utility Functions ---
def get_key_pem_bytes(key, is_private: bool = False, passphrase: str = None) -> bytes:
    """Convert a key to PEM bytes."""
    if is_private:
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode())
            if passphrase else serialization.NoEncryption()
        )
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
