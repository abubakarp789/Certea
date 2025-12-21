"""
Integration and security tests for Digital Signature Validator.

This module contains comprehensive tests for:
- Complete signing workflows with passphrase-protected keys
- Security verification of private key file permissions
- Passphrase protection validation
- Tampered message detection
- Wrong public key rejection
- Expired certificate rejection

Requirements: 1.3, 1.5, 3.5, 3.6, 4.5, 8.6
"""

import os
import stat
import tempfile
import pytest
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.key_manager import KeyManager
from src.signature_service import SignatureService
from src.certificate_service import CertificateAuthority
from src.models import Certificate
from src.exceptions import KeyManagementError, CertificateError


class TestIntegrationWorkflows:
    """Integration tests for complete signing workflows."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager()
        self.signature_service = SignatureService()
    
    def teardown_method(self):
        """Clean up test files."""
        for filename in os.listdir(self.temp_dir):
            filepath = os.path.join(self.temp_dir, filename)
            try:
                os.remove(filepath)
            except Exception:
                pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass
    
    def test_complete_signing_workflow_with_passphrase(self):
        """
        Test complete end-to-end signing workflow with passphrase-protected keys.
        
        Requirements: 1.5, 4.5
        """
        # Step 1: Generate key pair
        private_key, public_key = self.key_manager.generate_key_pair(key_size=2048)
        
        # Step 2: Save keys with passphrase protection
        passphrase = "secure_test_passphrase_123"
        private_key_path = os.path.join(self.temp_dir, "private_key.pem")
        public_key_path = os.path.join(self.temp_dir, "public_key.pem")
        
        self.key_manager.save_private_key(private_key, private_key_path, passphrase=passphrase)
        self.key_manager.save_public_key(public_key, public_key_path)
        
        # Step 3: Load keys with passphrase
        loaded_private_key = self.key_manager.load_private_key(private_key_path, passphrase=passphrase)
        loaded_public_key = self.key_manager.load_public_key(public_key_path)
        
        # Step 4: Sign a message with loaded private key
        message = "This is a test message for complete workflow"
        sign_result = self.signature_service.sign_message(
            message, loaded_private_key, padding_scheme='PSS'
        )
        
        assert sign_result.signature is not None
        assert sign_result.padding_scheme == 'PSS'
        assert sign_result.timestamp is not None
        
        # Step 5: Verify signature with loaded public key
        verify_result = self.signature_service.verify_signature(
            message, sign_result.signature, loaded_public_key, padding_scheme='PSS'
        )
        
        assert verify_result.is_valid is True
        assert verify_result.error_message is None
        assert verify_result.message_digest == sign_result.message_digest
    
    def test_complete_file_signing_workflow_with_passphrase(self):
        """
        Test complete file signing workflow with passphrase-protected keys.
        
        Requirements: 1.5, 4.5
        """
        # Generate and save keys with passphrase
        private_key, public_key = self.key_manager.generate_key_pair()
        passphrase = "file_signing_passphrase"
        
        private_key_path = os.path.join(self.temp_dir, "private_key.pem")
        public_key_path = os.path.join(self.temp_dir, "public_key.pem")
        
        self.key_manager.save_private_key(private_key, private_key_path, passphrase=passphrase)
        self.key_manager.save_public_key(public_key, public_key_path)
        
        # Create a test file
        test_file_path = os.path.join(self.temp_dir, "test_document.txt")
        with open(test_file_path, 'w') as f:
            f.write("Important document content that needs to be signed")
        
        # Load keys and sign file
        loaded_private_key = self.key_manager.load_private_key(private_key_path, passphrase=passphrase)
        loaded_public_key = self.key_manager.load_public_key(public_key_path)
        
        sign_result = self.signature_service.sign_file(
            test_file_path, loaded_private_key, padding_scheme='PKCS1'
        )
        
        # Verify file signature
        verify_result = self.signature_service.verify_file_signature(
            test_file_path, sign_result.signature, loaded_public_key, padding_scheme='PKCS1'
        )
        
        assert verify_result.is_valid is True
        assert verify_result.error_message is None


class TestSecurityValidation:
    """Security tests for cryptographic operations."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager()
        self.signature_service = SignatureService()
    
    def teardown_method(self):
        """Clean up test files."""
        for filename in os.listdir(self.temp_dir):
            filepath = os.path.join(self.temp_dir, filename)
            try:
                os.remove(filepath)
            except Exception:
                pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass
    
    def test_private_key_file_permissions_security(self):
        """
        Test that private key files have restrictive permissions (0600).
        
        Requirements: 1.3
        """
        # Generate and save private key
        private_key, _ = self.key_manager.generate_key_pair()
        private_key_path = os.path.join(self.temp_dir, "secure_private_key.pem")
        
        self.key_manager.save_private_key(private_key, private_key_path)
        
        # Verify file exists
        assert os.path.exists(private_key_path)
        
        # Check file permissions (Unix/Linux systems only)
        if os.name != 'nt':  # Not Windows
            file_stat = os.stat(private_key_path)
            file_mode = stat.S_IMODE(file_stat.st_mode)
            
            # Should be 0o600 (owner read/write only)
            assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"
            
            # Verify no group or other permissions
            assert not (file_mode & stat.S_IRGRP), "Group should not have read permission"
            assert not (file_mode & stat.S_IWGRP), "Group should not have write permission"
            assert not (file_mode & stat.S_IXGRP), "Group should not have execute permission"
            assert not (file_mode & stat.S_IROTH), "Others should not have read permission"
            assert not (file_mode & stat.S_IWOTH), "Others should not have write permission"
            assert not (file_mode & stat.S_IXOTH), "Others should not have execute permission"
    
    def test_passphrase_protection_security(self):
        """
        Test that passphrase-protected keys cannot be loaded without correct passphrase.
        
        Requirements: 1.5, 4.5
        """
        # Generate and save key with passphrase
        private_key, _ = self.key_manager.generate_key_pair()
        correct_passphrase = "correct_secure_passphrase"
        private_key_path = os.path.join(self.temp_dir, "protected_key.pem")
        
        self.key_manager.save_private_key(
            private_key, private_key_path, passphrase=correct_passphrase
        )
        
        # Test 1: Loading without passphrase should fail
        with pytest.raises(KeyManagementError):
            self.key_manager.load_private_key(private_key_path)
        
        # Test 2: Loading with wrong passphrase should fail
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.load_private_key(
                private_key_path, passphrase="wrong_passphrase"
            )
        assert "passphrase" in str(exc_info.value).lower()
        
        # Test 3: Loading with correct passphrase should succeed
        loaded_key = self.key_manager.load_private_key(
            private_key_path, passphrase=correct_passphrase
        )
        assert loaded_key.private_numbers() == private_key.private_numbers()
    
    def test_tampered_message_detection_security(self):
        """
        Test that tampered messages are detected during verification.
        
        Requirements: 3.5, 3.6
        """
        # Generate key pair
        private_key, public_key = self.key_manager.generate_key_pair()
        
        # Sign original message
        original_message = "This is the original authentic message"
        sign_result = self.signature_service.sign_message(
            original_message, private_key, padding_scheme='PSS'
        )
        
        # Test 1: Verify original message succeeds
        verify_original = self.signature_service.verify_signature(
            original_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_original.is_valid is True
        
        # Test 2: Tampered message should fail verification
        tampered_message = "This is the original authentic message!"  # Added exclamation
        verify_tampered = self.signature_service.verify_signature(
            tampered_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_tampered.is_valid is False
        assert verify_tampered.error_message is not None
        assert "failed" in verify_tampered.error_message.lower()
        
        # Test 3: Completely different message should fail
        different_message = "Completely different message"
        verify_different = self.signature_service.verify_signature(
            different_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_different.is_valid is False
        
        # Test 4: Empty message should fail
        verify_empty = self.signature_service.verify_signature(
            "", sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_empty.is_valid is False
    
    def test_tampered_file_detection_security(self):
        """
        Test that tampered files are detected during signature verification.
        
        Requirements: 3.5, 3.6
        """
        # Generate key pair
        private_key, public_key = self.key_manager.generate_key_pair()
        
        # Create and sign original file
        original_file_path = os.path.join(self.temp_dir, "original_file.txt")
        with open(original_file_path, 'w') as f:
            f.write("Original file content for signing")
        
        sign_result = self.signature_service.sign_file(
            original_file_path, private_key, padding_scheme='PSS'
        )
        
        # Verify original file succeeds
        verify_original = self.signature_service.verify_file_signature(
            original_file_path, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_original.is_valid is True
        
        # Tamper with file content
        with open(original_file_path, 'w') as f:
            f.write("Tampered file content")
        
        # Verify tampered file fails
        verify_tampered = self.signature_service.verify_file_signature(
            original_file_path, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_tampered.is_valid is False
        assert verify_tampered.error_message is not None
    
    def test_wrong_public_key_rejection_security(self):
        """
        Test that signatures are rejected when verified with wrong public key.
        
        Requirements: 3.6
        """
        # Generate two different key pairs
        private_key1, public_key1 = self.key_manager.generate_key_pair()
        private_key2, public_key2 = self.key_manager.generate_key_pair()
        
        message = "Test message for key mismatch"
        
        # Sign with first private key
        sign_result = self.signature_service.sign_message(
            message, private_key1, padding_scheme='PSS'
        )
        
        # Test 1: Verify with correct public key succeeds
        verify_correct = self.signature_service.verify_signature(
            message, sign_result.signature, public_key1, padding_scheme='PSS'
        )
        assert verify_correct.is_valid is True
        
        # Test 2: Verify with wrong public key fails
        verify_wrong = self.signature_service.verify_signature(
            message, sign_result.signature, public_key2, padding_scheme='PSS'
        )
        assert verify_wrong.is_valid is False
        assert verify_wrong.error_message is not None
        
        # Test 3: Test with PKCS1 padding as well
        sign_result_pkcs1 = self.signature_service.sign_message(
            message, private_key1, padding_scheme='PKCS1'
        )
        verify_wrong_pkcs1 = self.signature_service.verify_signature(
            message, sign_result_pkcs1.signature, public_key2, padding_scheme='PKCS1'
        )
        assert verify_wrong_pkcs1.is_valid is False
    
    def test_multiple_key_pairs_isolation_security(self):
        """
        Test that multiple key pairs are properly isolated.
        
        Requirements: 3.6
        """
        # Generate three different key pairs
        key_pairs = [
            self.key_manager.generate_key_pair(),
            self.key_manager.generate_key_pair(),
            self.key_manager.generate_key_pair()
        ]
        
        message = "Test message for key isolation"
        
        # Sign with each private key
        signatures = []
        for private_key, _ in key_pairs:
            sign_result = self.signature_service.sign_message(
                message, private_key, padding_scheme='PSS'
            )
            signatures.append(sign_result.signature)
        
        # Verify each signature only works with its corresponding public key
        for i, (_, public_key) in enumerate(key_pairs):
            # Correct key should verify
            verify_result = self.signature_service.verify_signature(
                message, signatures[i], public_key, padding_scheme='PSS'
            )
            assert verify_result.is_valid is True
            
            # Wrong keys should not verify
            for j, other_signature in enumerate(signatures):
                if i != j:
                    verify_result = self.signature_service.verify_signature(
                        message, other_signature, public_key, padding_scheme='PSS'
                    )
                    assert verify_result.is_valid is False


class TestCertificateSecurity:
    """Security tests for certificate operations."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Generate CA key pair
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.ca_public_key = self.ca_private_key.public_key()
        self.ca = CertificateAuthority(self.ca_private_key, self.ca_public_key, "Test CA")
    
    def teardown_method(self):
        """Clean up test files."""
        for filename in os.listdir(self.temp_dir):
            filepath = os.path.join(self.temp_dir, filename)
            try:
                os.remove(filepath)
            except Exception:
                pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass
    
    def test_expired_certificate_rejection_security(self):
        """
        Test that expired certificates are rejected during verification.
        
        Requirements: 8.6
        """
        # Generate user key pair
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        user_public_key = user_private_key.public_key()
        
        # Create certificate with short validity period
        certificate = self.ca.sign_public_key(
            public_key=user_public_key,
            subject="Test User",
            validity_days=1
        )
        
        # Test 1: Certificate should be valid now
        assert certificate.is_valid(datetime.now()) is True
        result = self.ca.verify_certificate(certificate)
        assert result is True
        
        # Test 2: Simulate expired certificate by setting past dates
        certificate.valid_from = datetime.now() - timedelta(days=365)
        certificate.valid_until = datetime.now() - timedelta(days=1)
        
        # Certificate validity check should fail
        assert certificate.is_valid(datetime.now()) is False
        
        # CA verification should reject expired certificate
        with pytest.raises(CertificateError) as exc_info:
            self.ca.verify_certificate(certificate)
        assert "expired or not yet valid" in str(exc_info.value).lower()
    
    def test_not_yet_valid_certificate_rejection_security(self):
        """
        Test that certificates not yet valid are rejected.
        
        Requirements: 8.6
        """
        # Generate user key pair
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        user_public_key = user_private_key.public_key()
        
        # Create certificate
        certificate = self.ca.sign_public_key(
            public_key=user_public_key,
            subject="Future User",
            validity_days=365
        )
        
        # Simulate future certificate by setting future dates
        certificate.valid_from = datetime.now() + timedelta(days=10)
        certificate.valid_until = datetime.now() + timedelta(days=375)
        
        # Certificate validity check should fail
        assert certificate.is_valid(datetime.now()) is False
        
        # CA verification should reject not-yet-valid certificate
        with pytest.raises(CertificateError) as exc_info:
            self.ca.verify_certificate(certificate)
        assert "expired or not yet valid" in str(exc_info.value).lower()
    
    def test_certificate_validity_boundary_conditions(self):
        """
        Test certificate validity at exact boundary times.
        
        Requirements: 8.6
        """
        # Generate user key pair
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        user_public_key = user_private_key.public_key()
        
        # Create certificate with specific validity period
        valid_from = datetime(2024, 1, 1, 0, 0, 0)
        valid_until = datetime(2024, 12, 31, 23, 59, 59)
        
        certificate = Certificate(
            public_key=user_public_key,
            subject="Boundary Test User",
            issuer="Test CA",
            valid_from=valid_from,
            valid_until=valid_until,
            signature=b'test_signature'
        )
        
        # Test before validity period
        assert certificate.is_valid(datetime(2023, 12, 31, 23, 59, 59)) is False
        
        # Test at start of validity period
        assert certificate.is_valid(datetime(2024, 1, 1, 0, 0, 0)) is True
        
        # Test during validity period
        assert certificate.is_valid(datetime(2024, 6, 15, 12, 0, 0)) is True
        
        # Test at end of validity period
        assert certificate.is_valid(datetime(2024, 12, 31, 23, 59, 59)) is True
        
        # Test after validity period
        assert certificate.is_valid(datetime(2025, 1, 1, 0, 0, 0)) is False
    
    def test_tampered_certificate_rejection_security(self):
        """
        Test that tampered certificates are rejected.
        
        Requirements: 8.6
        """
        # Generate user key pair
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        user_public_key = user_private_key.public_key()
        
        # Create valid certificate
        certificate = self.ca.sign_public_key(
            public_key=user_public_key,
            subject="Original User",
            validity_days=365
        )
        
        # Verify original certificate is valid
        result = self.ca.verify_certificate(certificate)
        assert result is True
        
        # Tamper with certificate subject
        certificate.subject = "Tampered User"
        
        # Verification should fail for tampered certificate
        with pytest.raises(CertificateError) as exc_info:
            self.ca.verify_certificate(certificate)
        assert "Invalid CA signature" in str(exc_info.value)
    
    def test_certificate_signed_by_wrong_ca_rejection(self):
        """
        Test that certificates signed by different CA are rejected.
        
        Requirements: 8.6
        """
        # Generate user key pair
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        user_public_key = user_private_key.public_key()
        
        # Create certificate with first CA
        certificate = self.ca.sign_public_key(
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
        
        # Verification with different CA should fail
        with pytest.raises(CertificateError) as exc_info:
            different_ca.verify_certificate(certificate)
        assert "Invalid CA signature" in str(exc_info.value)
