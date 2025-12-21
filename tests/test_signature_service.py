"""Unit tests for SignatureService."""

import pytest
import os
import tempfile
from src.signature_service import SignatureService
from src.key_manager import KeyManager
from src.exceptions import SignatureError


class TestSignatureService:
    """Test suite for SignatureService class."""
    
    @pytest.fixture
    def signature_service(self):
        """Create a SignatureService instance."""
        return SignatureService()
    
    @pytest.fixture
    def key_pair(self):
        """Generate a test RSA key pair."""
        key_manager = KeyManager()
        private_key, public_key = key_manager.generate_key_pair(key_size=2048)
        return private_key, public_key
    
    def test_sign_message_with_pss(self, signature_service, key_pair):
        """Test signing a message with PSS padding."""
        private_key, public_key = key_pair
        message = "Test message for signing"
        
        result = signature_service.sign_message(message, private_key, padding_scheme='PSS')
        
        assert result.signature is not None
        assert len(result.signature) > 0
        assert result.padding_scheme == 'PSS'
        assert result.message_digest is not None
        assert len(result.message_digest) == 64  # SHA-256 hex digest is 64 chars
        assert result.timestamp is not None
    
    def test_sign_message_with_pkcs1(self, signature_service, key_pair):
        """Test signing a message with PKCS#1 v1.5 padding."""
        private_key, public_key = key_pair
        message = "Test message for signing"
        
        result = signature_service.sign_message(message, private_key, padding_scheme='PKCS1')
        
        assert result.signature is not None
        assert len(result.signature) > 0
        assert result.padding_scheme == 'PKCS1'
        assert result.message_digest is not None
        assert result.timestamp is not None
    
    def test_sign_file(self, signature_service, key_pair):
        """Test signing a file."""
        private_key, public_key = key_pair
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content for signing")
            temp_file = f.name
        
        try:
            result = signature_service.sign_file(temp_file, private_key, padding_scheme='PSS')
            
            assert result.signature is not None
            assert len(result.signature) > 0
            assert result.padding_scheme == 'PSS'
            assert result.message_digest is not None
            assert result.timestamp is not None
        finally:
            os.unlink(temp_file)
    
    def test_sign_file_not_found(self, signature_service, key_pair):
        """Test signing a non-existent file raises error."""
        private_key, public_key = key_pair
        
        with pytest.raises(SignatureError, match="File not found"):
            signature_service.sign_file("nonexistent_file.txt", private_key)
    
    def test_verify_signature_valid(self, signature_service, key_pair):
        """Test verifying a valid signature."""
        private_key, public_key = key_pair
        message = "Test message for verification"
        
        # Sign the message
        sign_result = signature_service.sign_message(message, private_key, padding_scheme='PSS')
        
        # Verify the signature
        verify_result = signature_service.verify_signature(
            message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        
        assert verify_result.is_valid is True
        assert verify_result.error_message is None
        assert verify_result.message_digest == sign_result.message_digest
    
    def test_verify_signature_tampered_message(self, signature_service, key_pair):
        """Test verification fails with tampered message."""
        private_key, public_key = key_pair
        original_message = "Original message"
        tampered_message = "Tampered message"
        
        # Sign the original message
        sign_result = signature_service.sign_message(original_message, private_key, padding_scheme='PSS')
        
        # Try to verify with tampered message
        verify_result = signature_service.verify_signature(
            tampered_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        
        assert verify_result.is_valid is False
        assert verify_result.error_message is not None
        assert "failed" in verify_result.error_message.lower()
    
    def test_verify_signature_wrong_public_key(self, signature_service):
        """Test verification fails with wrong public key."""
        key_manager = KeyManager()
        
        # Generate two different key pairs
        private_key1, public_key1 = key_manager.generate_key_pair()
        private_key2, public_key2 = key_manager.generate_key_pair()
        
        message = "Test message"
        
        # Sign with first private key
        sign_result = signature_service.sign_message(message, private_key1, padding_scheme='PSS')
        
        # Try to verify with second public key
        verify_result = signature_service.verify_signature(
            message, sign_result.signature, public_key2, padding_scheme='PSS'
        )
        
        assert verify_result.is_valid is False
        assert verify_result.error_message is not None
    
    def test_verify_file_signature_valid(self, signature_service, key_pair):
        """Test verifying a valid file signature."""
        private_key, public_key = key_pair
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content")
            temp_file = f.name
        
        try:
            # Sign the file
            sign_result = signature_service.sign_file(temp_file, private_key, padding_scheme='PSS')
            
            # Verify the signature
            verify_result = signature_service.verify_file_signature(
                temp_file, sign_result.signature, public_key, padding_scheme='PSS'
            )
            
            assert verify_result.is_valid is True
            assert verify_result.error_message is None
        finally:
            os.unlink(temp_file)
    
    def test_pkcs1_deterministic_behavior(self, signature_service, key_pair):
        """Test that PKCS#1 v1.5 produces deterministic signatures."""
        private_key, public_key = key_pair
        message = "Test message for deterministic signing"
        
        # Sign the same message twice with PKCS1
        result1 = signature_service.sign_message(message, private_key, padding_scheme='PKCS1')
        result2 = signature_service.sign_message(message, private_key, padding_scheme='PKCS1')
        
        # Signatures should be identical (deterministic)
        assert result1.signature == result2.signature
        assert result1.message_digest == result2.message_digest
    
    def test_pss_randomized_behavior(self, signature_service, key_pair):
        """Test that PSS produces randomized signatures."""
        private_key, public_key = key_pair
        message = "Test message for randomized signing"
        
        # Sign the same message twice with PSS
        result1 = signature_service.sign_message(message, private_key, padding_scheme='PSS')
        result2 = signature_service.sign_message(message, private_key, padding_scheme='PSS')
        
        # Signatures should be different (randomized due to salt)
        assert result1.signature != result2.signature
        # But message digests should be the same
        assert result1.message_digest == result2.message_digest
        
        # Both signatures should verify successfully
        verify1 = signature_service.verify_signature(message, result1.signature, public_key, 'PSS')
        verify2 = signature_service.verify_signature(message, result2.signature, public_key, 'PSS')
        
        assert verify1.is_valid is True
        assert verify2.is_valid is True
    
    def test_unsupported_padding_scheme(self, signature_service, key_pair):
        """Test that unsupported padding scheme raises error."""
        private_key, public_key = key_pair
        message = "Test message"
        
        with pytest.raises(SignatureError, match="Unsupported padding scheme"):
            signature_service.sign_message(message, private_key, padding_scheme='INVALID')
    
    def test_verify_with_both_padding_schemes(self, signature_service, key_pair):
        """Test verification works correctly with both padding schemes."""
        private_key, public_key = key_pair
        message = "Test message"
        
        # Test PSS
        pss_result = signature_service.sign_message(message, private_key, 'PSS')
        pss_verify = signature_service.verify_signature(message, pss_result.signature, public_key, 'PSS')
        assert pss_verify.is_valid is True
        
        # Test PKCS1
        pkcs1_result = signature_service.sign_message(message, private_key, 'PKCS1')
        pkcs1_verify = signature_service.verify_signature(message, pkcs1_result.signature, public_key, 'PKCS1')
        assert pkcs1_verify.is_valid is True
        
        # Cross-verification should fail (PSS signature with PKCS1 verification)
        cross_verify = signature_service.verify_signature(message, pss_result.signature, public_key, 'PKCS1')
        assert cross_verify.is_valid is False
