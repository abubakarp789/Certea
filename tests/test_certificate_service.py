"""Unit tests for Certificate Service."""

import pytest
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from src.certificate_service import CertificateAuthority
from src.models import Certificate
from src.exceptions import CertificateError


class TestCertificateAuthority:
    """Test cases for CertificateAuthority class."""
    
    @pytest.fixture
    def ca_key_pair(self):
        """Generate CA key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @pytest.fixture
    def user_key_pair(self):
        """Generate user key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @pytest.fixture
    def ca(self, ca_key_pair):
        """Create CertificateAuthority instance."""
        ca_private_key, ca_public_key = ca_key_pair
        return CertificateAuthority(ca_private_key, ca_public_key, "Test CA")
    
    def test_ca_initialization(self, ca_key_pair):
        """Test CA initialization with key pair."""
        ca_private_key, ca_public_key = ca_key_pair
        ca = CertificateAuthority(ca_private_key, ca_public_key, "Test CA")
        
        assert ca.ca_private_key == ca_private_key
        assert ca.ca_public_key == ca_public_key
        assert ca.ca_name == "Test CA"
    
    def test_sign_public_key(self, ca, user_key_pair):
        """Test certificate creation by signing a public key."""
        _, user_public_key = user_key_pair
        
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=365
        )
        
        assert certificate.public_key == user_public_key
        assert certificate.subject == "Test User"
        assert certificate.issuer == "Test CA"
        assert certificate.signature is not None
        assert len(certificate.signature) > 0
        
        # Check validity period
        assert certificate.valid_from <= datetime.now()
        assert certificate.valid_until > datetime.now()
        assert (certificate.valid_until - certificate.valid_from).days == 365
    
    def test_sign_public_key_custom_validity(self, ca, user_key_pair):
        """Test certificate creation with custom validity period."""
        _, user_public_key = user_key_pair
        
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=30
        )
        
        assert (certificate.valid_until - certificate.valid_from).days == 30
    
    def test_verify_valid_certificate(self, ca, user_key_pair):
        """Test verification of a valid certificate."""
        _, user_public_key = user_key_pair
        
        # Create certificate
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=365
        )
        
        # Verify certificate
        result = ca.verify_certificate(certificate)
        assert result is True
    
    def test_verify_expired_certificate(self, ca, user_key_pair):
        """Test rejection of expired certificate."""
        _, user_public_key = user_key_pair
        
        # Create certificate with 1 day validity
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=1
        )
        
        # Manually set validity to past dates to simulate an expired certificate
        certificate.valid_from = datetime.now() - timedelta(days=365)
        certificate.valid_until = datetime.now() - timedelta(days=1)
        
        # Verify certificate should fail
        with pytest.raises(CertificateError) as exc_info:
            ca.verify_certificate(certificate)
        
        assert "expired or not yet valid" in str(exc_info.value).lower()
    
    def test_verify_not_yet_valid_certificate(self, ca, user_key_pair):
        """Test rejection of certificate that is not yet valid."""
        _, user_public_key = user_key_pair
        
        # Create certificate
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=365
        )
        
        # Manually set validity to future dates
        certificate.valid_from = datetime.now() + timedelta(days=1)
        certificate.valid_until = datetime.now() + timedelta(days=365)
        
        # Verify certificate should fail
        with pytest.raises(CertificateError) as exc_info:
            ca.verify_certificate(certificate)
        
        assert "expired or not yet valid" in str(exc_info.value).lower()
    
    def test_verify_tampered_certificate(self, ca, user_key_pair):
        """Test rejection of certificate with tampered data."""
        _, user_public_key = user_key_pair
        
        # Create valid certificate
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=365
        )
        
        # Tamper with certificate data
        certificate.subject = "Tampered User"
        
        # Verify certificate should fail
        with pytest.raises(CertificateError) as exc_info:
            ca.verify_certificate(certificate)
        
        assert "Invalid CA signature" in str(exc_info.value)
    
    def test_verify_certificate_wrong_ca(self, ca, user_key_pair, ca_key_pair):
        """Test rejection of certificate signed by different CA."""
        _, user_public_key = user_key_pair
        
        # Create certificate with first CA
        certificate = ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=365
        )
        
        # Create different CA
        different_ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        different_ca_public_key = different_ca_private_key.public_key()
        different_ca = CertificateAuthority(
            different_ca_private_key,
            different_ca_public_key,
            "Different CA"
        )
        
        # Verify with different CA should fail
        with pytest.raises(CertificateError) as exc_info:
            different_ca.verify_certificate(certificate)
        
        assert "Invalid CA signature" in str(exc_info.value)


class TestCertificate:
    """Test cases for Certificate class."""
    
    @pytest.fixture
    def user_key_pair(self):
        """Generate user key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def test_certificate_is_valid_current_time(self, user_key_pair):
        """Test validity period checking with current time."""
        _, public_key = user_key_pair
        
        valid_from = datetime.now() - timedelta(days=1)
        valid_until = datetime.now() + timedelta(days=365)
        
        certificate = Certificate(
            public_key=public_key,
            subject="Test User",
            issuer="Test CA",
            valid_from=valid_from,
            valid_until=valid_until,
            signature=b'test_signature'
        )
        
        assert certificate.is_valid(datetime.now()) is True
    
    def test_certificate_is_valid_before_start(self, user_key_pair):
        """Test validity check before certificate start date."""
        _, public_key = user_key_pair
        
        valid_from = datetime.now() + timedelta(days=1)
        valid_until = datetime.now() + timedelta(days=365)
        
        certificate = Certificate(
            public_key=public_key,
            subject="Test User",
            issuer="Test CA",
            valid_from=valid_from,
            valid_until=valid_until,
            signature=b'test_signature'
        )
        
        assert certificate.is_valid(datetime.now()) is False
    
    def test_certificate_is_valid_after_expiry(self, user_key_pair):
        """Test validity check after certificate expiry."""
        _, public_key = user_key_pair
        
        valid_from = datetime.now() - timedelta(days=365)
        valid_until = datetime.now() - timedelta(days=1)
        
        certificate = Certificate(
            public_key=public_key,
            subject="Test User",
            issuer="Test CA",
            valid_from=valid_from,
            valid_until=valid_until,
            signature=b'test_signature'
        )
        
        assert certificate.is_valid(datetime.now()) is False
    
    def test_certificate_serialization(self, user_key_pair):
        """Test certificate to_dict and from_dict methods."""
        _, public_key = user_key_pair
        
        valid_from = datetime.now()
        valid_until = datetime.now() + timedelta(days=365)
        
        original_cert = Certificate(
            public_key=public_key,
            subject="Test User",
            issuer="Test CA",
            valid_from=valid_from,
            valid_until=valid_until,
            signature=b'test_signature_data'
        )
        
        # Serialize to dict
        cert_dict = original_cert.to_dict()
        
        # Deserialize from dict
        restored_cert = Certificate.from_dict(cert_dict)
        
        # Verify all fields match
        assert restored_cert.subject == original_cert.subject
        assert restored_cert.issuer == original_cert.issuer
        assert restored_cert.valid_from == original_cert.valid_from
        assert restored_cert.valid_until == original_cert.valid_until
        assert restored_cert.signature == original_cert.signature
        
        # Verify public keys match by comparing their serialized forms
        assert restored_cert.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) == original_cert.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
