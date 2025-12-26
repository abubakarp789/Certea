"""
Certificate Expiry Tests

Tests for certificate validity period handling including:
- Valid certificate
- Expired certificate
- Not yet valid certificate
- Zero-day validity
- Maximum validity period
- Edge of validity (exact timestamps)
"""

import pytest
from datetime import datetime, timedelta
from freezegun import freeze_time

from src.certificate_service import CertificateAuthority
from src.models import Certificate
from src.exceptions import CertificateError


class TestValidCertificate:
    """Test valid certificate within validity period."""
    
    def test_valid_certificate_verifies(self, certificate_authority, public_key, ca_key_pair):
        """Current date within validity period should verify."""
        _, ca_public_key = ca_key_pair
        
        cert = certificate_authority.sign_public_key(public_key, "Valid Subject", 365)
        
        # Should verify successfully
        is_valid = certificate_authority.verify_certificate(cert)
        assert is_valid is True
    
    def test_newly_created_certificate(self, certificate_authority, public_key):
        """Newly created certificate should be valid."""
        cert = certificate_authority.sign_public_key(public_key, "New Subject", 365)
        
        # Check validity
        assert cert.is_valid(datetime.now()) is True
    
    def test_certificate_attributes(self, certificate_authority, public_key):
        """Certificate should have correct attributes."""
        subject = "Test Subject"
        days = 365
        
        cert = certificate_authority.sign_public_key(public_key, subject, days)
        
        assert cert.subject == subject
        assert cert.issuer == "Test CA"
        assert cert.signature is not None
        assert len(cert.signature) > 0


class TestExpiredCertificate:
    """Test expired certificate handling."""
    
    def test_expired_certificate_fails(self, certificate_authority, expired_certificate, ca_key_pair):
        """Expired certificate should fail verification."""
        _, ca_public_key = ca_key_pair
        
        with pytest.raises(CertificateError):
            certificate_authority.verify_certificate(expired_certificate)
    
    def test_expired_certificate_is_valid_check(self, expired_certificate):
        """is_valid() should return False for expired certificate."""
        assert expired_certificate.is_valid(datetime.now()) is False
    
    @freeze_time("2025-01-01 12:00:00")
    def test_certificate_expires_after_validity(self, certificate_authority, public_key):
        """Certificate should be invalid after validity period ends."""
        # Create certificate valid for 30 days
        cert = certificate_authority.sign_public_key(public_key, "Expiring Subject", 30)
        
        # Should be valid now
        assert cert.is_valid(datetime.now()) is True
        
        # Check at expiration + 1 day
        future = datetime.now() + timedelta(days=31)
        assert cert.is_valid(future) is False


class TestNotYetValidCertificate:
    """Test not-yet-valid certificate handling."""
    
    def test_future_certificate_fails(self, certificate_authority, future_certificate, ca_key_pair):
        """Certificate with valid_from in the future should fail verification."""
        with pytest.raises(CertificateError):
            certificate_authority.verify_certificate(future_certificate)
    
    def test_future_certificate_is_valid_check(self, future_certificate):
        """is_valid() should return False for not-yet-valid certificate."""
        assert future_certificate.is_valid(datetime.now()) is False
    
    @freeze_time("2025-01-01 12:00:00")
    def test_certificate_becomes_valid(self, ca_key_pair, public_key):
        """Certificate should become valid when valid_from is reached."""
        ca_private_key, ca_public_key = ca_key_pair
        
        # Create certificate that starts tomorrow
        valid_from = datetime.now() + timedelta(days=1)
        valid_until = datetime.now() + timedelta(days=365)
        
        cert = Certificate(
            public_key=public_key,
            subject="Future Subject",
            issuer="Test CA",
            valid_from=valid_from,
            valid_until=valid_until,
            signature=b''
        )
        cert.sign(ca_private_key)
        
        # Not valid now
        assert cert.is_valid(datetime.now()) is False
        
        # Valid tomorrow
        tomorrow = datetime.now() + timedelta(days=1, hours=1)
        assert cert.is_valid(tomorrow) is True


class TestZeroDayValidity:
    """Test zero-day validity edge case."""
    
    def test_one_day_validity(self, certificate_authority, public_key):
        """Minimum validity (1 day) should work."""
        cert = certificate_authority.sign_public_key(public_key, "Short Validity", 1)
        
        assert cert.is_valid(datetime.now()) is True
        
        # Should be invalid after 2 days
        future = datetime.now() + timedelta(days=2)
        assert cert.is_valid(future) is False
    
    def test_zero_days_rejected(self, certificate_authority, public_key):
        """Zero days validity should be rejected."""
        with pytest.raises(CertificateError):
            certificate_authority.sign_public_key(public_key, "Zero Days", 0)
    
    def test_negative_days_rejected(self, certificate_authority, public_key):
        """Negative days validity should be rejected."""
        with pytest.raises(CertificateError):
            certificate_authority.sign_public_key(public_key, "Negative Days", -1)


class TestMaximumValidity:
    """Test maximum validity period."""
    
    def test_ten_year_validity(self, certificate_authority, public_key):
        """Certificate valid for 10+ years should work."""
        days = 365 * 10  # 10 years
        cert = certificate_authority.sign_public_key(public_key, "Long Validity", days)
        
        assert cert.is_valid(datetime.now()) is True
        
        # Should still be valid in 5 years
        future = datetime.now() + timedelta(days=365 * 5)
        assert cert.is_valid(future) is True
    
    def test_hundred_year_validity_rejected(self, certificate_authority, public_key):
        """Validity period exceeding 100 years should be rejected."""
        # 36500 days = ~100 years is the maximum allowed
        # Anything over that should be rejected
        days = 36501  # Just over the limit
        
        with pytest.raises(CertificateError):
            certificate_authority.sign_public_key(public_key, "Too Long", days)


class TestEdgeOfValidity:
    """Test exact validity boundary timestamps."""
    
    @freeze_time("2025-06-15 12:00:00")
    def test_exact_valid_from_timestamp(self, ca_key_pair, public_key):
        """Verify at exact valid_from timestamp."""
        ca_private_key, ca_public_key = ca_key_pair
        
        now = datetime.now()
        valid_until = now + timedelta(days=30)
        
        cert = Certificate(
            public_key=public_key,
            subject="Edge Test",
            issuer="Test CA",
            valid_from=now,
            valid_until=valid_until,
            signature=b''
        )
        cert.sign(ca_private_key)
        
        # Exactly at valid_from should be valid
        assert cert.is_valid(now) is True
        
        # One second before should be invalid
        before = now - timedelta(seconds=1)
        assert cert.is_valid(before) is False
    
    @freeze_time("2025-06-15 12:00:00")
    def test_exact_valid_until_timestamp(self, ca_key_pair, public_key):
        """Verify at exact valid_until timestamp."""
        ca_private_key, ca_public_key = ca_key_pair
        
        now = datetime.now()
        valid_until = now + timedelta(days=30)
        
        cert = Certificate(
            public_key=public_key,
            subject="Edge Test",
            issuer="Test CA",
            valid_from=now,
            valid_until=valid_until,
            signature=b''
        )
        cert.sign(ca_private_key)
        
        # Exactly at valid_until should be valid (inclusive)
        assert cert.is_valid(valid_until) is True
        
        # One second after should be invalid
        after = valid_until + timedelta(seconds=1)
        assert cert.is_valid(after) is False


class TestCertificateSerialization:
    """Test certificate serialization with expiry dates."""
    
    def test_serialize_deserialize_preserves_dates(self, valid_certificate):
        """Serialization should preserve validity dates."""
        # Serialize
        cert_dict = valid_certificate.to_dict()
        
        # Deserialize
        loaded_cert = Certificate.from_dict(cert_dict)
        
        # Check dates are preserved
        assert loaded_cert.valid_from == valid_certificate.valid_from
        assert loaded_cert.valid_until == valid_certificate.valid_until
    
    def test_expired_certificate_serialization(self, expired_certificate):
        """Expired certificate can be serialized/deserialized."""
        cert_dict = expired_certificate.to_dict()
        loaded_cert = Certificate.from_dict(cert_dict)
        
        # Should still be expired after loading
        assert loaded_cert.is_valid(datetime.now()) is False


class TestCertificateSignatureVerification:
    """Test certificate signature verification with various validity states."""
    
    def test_tampered_certificate_fails(self, certificate_authority, public_key, ca_key_pair):
        """Certificate with tampered signature should fail."""
        _, ca_public_key = ca_key_pair
        
        cert = certificate_authority.sign_public_key(public_key, "Original", 365)
        
        # Tamper with signature
        tampered_sig = list(cert.signature)
        tampered_sig[0] = (tampered_sig[0] + 1) % 256
        cert.signature = bytes(tampered_sig)
        
        # Should fail verification
        with pytest.raises(CertificateError):
            certificate_authority.verify_certificate(cert)
    
    def test_wrong_ca_fails(self, key_manager, public_key):
        """Certificate verified with wrong CA key should fail."""
        # Create two different CAs
        ca1_private, ca1_public = key_manager.generate_key_pair(2048)
        ca2_private, ca2_public = key_manager.generate_key_pair(2048)
        
        ca1 = CertificateAuthority(ca1_private, ca1_public, "CA1")
        ca2 = CertificateAuthority(ca2_private, ca2_public, "CA2")
        
        # Sign with CA1
        cert = ca1.sign_public_key(public_key, "Subject", 365)
        
        # Verify with CA2 - should fail
        with pytest.raises(CertificateError):
            ca2.verify_certificate(cert)


class TestTimeBasedVerification:
    """Test time-based certificate verification."""
    
    @freeze_time("2025-06-15 12:00:00")
    def test_verification_at_specific_time(self, certificate_authority, public_key):
        """Certificate verification at frozen time."""
        cert = certificate_authority.sign_public_key(public_key, "Frozen Time Test", 30)
        
        # Should be valid now
        assert certificate_authority.verify_certificate(cert) is True
    
    def test_verification_respects_current_time(self, ca_key_pair, public_key):
        """Certificate verification should use current system time."""
        ca_private_key, ca_public_key = ca_key_pair
        
        # Create expired certificate
        past_start = datetime.now() - timedelta(days=10)
        past_end = datetime.now() - timedelta(days=5)
        
        cert = Certificate(
            public_key=public_key,
            subject="Past Certificate",
            issuer="Test CA",
            valid_from=past_start,
            valid_until=past_end,
            signature=b''
        )
        cert.sign(ca_private_key)
        
        ca = CertificateAuthority(ca_private_key, ca_public_key, "Test CA")
        
        # Should fail because certificate is expired
        with pytest.raises(CertificateError):
            ca.verify_certificate(cert)
