"""
Key Size and Padding Scheme Tests

Tests for different RSA key sizes (2048, 3072, 4096) and padding schemes (PSS, PKCS1).
Includes cross-verification and mixed padding rejection tests.
"""

import pytest
from src.key_manager import KeyManager
from src.signature_service import SignatureService


class TestRSA2048WithPSS:
    """Test RSA-2048 with PSS padding."""
    
    def test_sign_verify_2048_pss(self, signature_service, key_pair_2048, sample_message):
        """Sign and verify with RSA-2048 + PSS."""
        private_key, public_key = key_pair_2048
        
        # Sign
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PSS'
        )
        assert sign_result.padding_scheme == 'PSS'
        
        # Verify
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_result.is_valid is True
    
    def test_signature_length_2048(self, signature_service, key_pair_2048, sample_message):
        """Verify signature length for RSA-2048."""
        private_key, _ = key_pair_2048
        result = signature_service.sign_message(sample_message, private_key, 'PSS')
        # RSA-2048 produces 256-byte signatures
        assert len(result.signature) == 256


class TestRSA2048WithPKCS1:
    """Test RSA-2048 with PKCS#1 v1.5 padding."""
    
    def test_sign_verify_2048_pkcs1(self, signature_service, key_pair_2048, sample_message):
        """Sign and verify with RSA-2048 + PKCS1."""
        private_key, public_key = key_pair_2048
        
        # Sign
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PKCS1'
        )
        assert sign_result.padding_scheme == 'PKCS1'
        
        # Verify
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PKCS1'
        )
        assert verify_result.is_valid is True
    
    def test_pkcs1_deterministic(self, signature_service, key_pair_2048, sample_message):
        """Verify PKCS#1 produces same signature for same input."""
        private_key, _ = key_pair_2048
        
        sig1 = signature_service.sign_message(sample_message, private_key, 'PKCS1')
        sig2 = signature_service.sign_message(sample_message, private_key, 'PKCS1')
        
        # PKCS#1 v1.5 is deterministic - same signature each time
        assert sig1.signature == sig2.signature


class TestRSA3072WithPSS:
    """Test RSA-3072 with PSS padding."""
    
    @pytest.mark.slow
    def test_sign_verify_3072_pss(self, signature_service, key_pair_3072, sample_message):
        """Sign and verify with RSA-3072 + PSS."""
        private_key, public_key = key_pair_3072
        
        # Sign
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PSS'
        )
        
        # Verify
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_result.is_valid is True
    
    @pytest.mark.slow
    def test_signature_length_3072(self, signature_service, key_pair_3072, sample_message):
        """Verify signature length for RSA-3072."""
        private_key, _ = key_pair_3072
        result = signature_service.sign_message(sample_message, private_key, 'PSS')
        # RSA-3072 produces 384-byte signatures
        assert len(result.signature) == 384


class TestRSA4096WithPSS:
    """Test RSA-4096 with PSS padding."""
    
    @pytest.mark.slow
    def test_sign_verify_4096_pss(self, signature_service, key_pair_4096, sample_message):
        """Sign and verify with RSA-4096 + PSS."""
        private_key, public_key = key_pair_4096
        
        # Sign
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PSS'
        )
        
        # Verify
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_result.is_valid is True
    
    @pytest.mark.slow
    def test_signature_length_4096(self, signature_service, key_pair_4096, sample_message):
        """Verify signature length for RSA-4096."""
        private_key, _ = key_pair_4096
        result = signature_service.sign_message(sample_message, private_key, 'PSS')
        # RSA-4096 produces 512-byte signatures
        assert len(result.signature) == 512


class TestRSA4096WithPKCS1:
    """Test RSA-4096 with PKCS#1 v1.5 padding."""
    
    @pytest.mark.slow
    def test_sign_verify_4096_pkcs1(self, signature_service, key_pair_4096, sample_message):
        """Sign and verify with RSA-4096 + PKCS1."""
        private_key, public_key = key_pair_4096
        
        # Sign
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PKCS1'
        )
        
        # Verify
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PKCS1'
        )
        assert verify_result.is_valid is True


class TestMixedPaddingRejection:
    """Test that mixing padding schemes fails verification."""
    
    def test_sign_pss_verify_pkcs1(self, signature_service, key_pair_2048, sample_message):
        """Sign with PSS, verify with PKCS1 - should fail."""
        private_key, public_key = key_pair_2048
        
        # Sign with PSS
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PSS'
        )
        
        # Verify with PKCS1 - should fail
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PKCS1'
        )
        assert verify_result.is_valid is False
    
    def test_sign_pkcs1_verify_pss(self, signature_service, key_pair_2048, sample_message):
        """Sign with PKCS1, verify with PSS - should fail."""
        private_key, public_key = key_pair_2048
        
        # Sign with PKCS1
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme='PKCS1'
        )
        
        # Verify with PSS - should fail
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme='PSS'
        )
        assert verify_result.is_valid is False


class TestCrossKeyVerification:
    """Test that signatures from one key can't be verified with another."""
    
    def test_different_key_pairs_fail(self, key_manager, signature_service, sample_message):
        """Signatures can't be verified with different key pairs."""
        # Generate two different key pairs
        private_key1, public_key1 = key_manager.generate_key_pair(2048)
        private_key2, public_key2 = key_manager.generate_key_pair(2048)
        
        # Sign with key1
        sign_result = signature_service.sign_message(
            sample_message, private_key1, 'PSS'
        )
        
        # Try to verify with key2 - should fail
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key2, 'PSS'
        )
        assert verify_result.is_valid is False
    
    def test_correct_key_pair_succeeds(self, key_manager, signature_service, sample_message):
        """Signatures can be verified with matching key pair."""
        private_key, public_key = key_manager.generate_key_pair(2048)
        
        sign_result = signature_service.sign_message(
            sample_message, private_key, 'PSS'
        )
        
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, 'PSS'
        )
        assert verify_result.is_valid is True


class TestPSSRandomization:
    """Test PSS padding randomization."""
    
    def test_pss_produces_different_signatures(self, signature_service, key_pair_2048, sample_message):
        """PSS should produce different signatures for same input (randomized)."""
        private_key, public_key = key_pair_2048
        
        sig1 = signature_service.sign_message(sample_message, private_key, 'PSS')
        sig2 = signature_service.sign_message(sample_message, private_key, 'PSS')
        
        # PSS is randomized - signatures should be different
        assert sig1.signature != sig2.signature
    
    def test_both_pss_signatures_verify(self, signature_service, key_pair_2048, sample_message):
        """Both different PSS signatures should verify correctly."""
        private_key, public_key = key_pair_2048
        
        sig1 = signature_service.sign_message(sample_message, private_key, 'PSS')
        sig2 = signature_service.sign_message(sample_message, private_key, 'PSS')
        
        # Both should verify
        verify1 = signature_service.verify_signature(
            sample_message, sig1.signature, public_key, 'PSS'
        )
        verify2 = signature_service.verify_signature(
            sample_message, sig2.signature, public_key, 'PSS'
        )
        
        assert verify1.is_valid is True
        assert verify2.is_valid is True


class TestInvalidPaddingScheme:
    """Test invalid padding scheme handling."""
    
    def test_invalid_padding_sign(self, signature_service, private_key, sample_message):
        """Signing with invalid padding scheme should raise error."""
        from src.exceptions import SignatureError
        
        with pytest.raises(SignatureError):
            signature_service.sign_message(sample_message, private_key, 'INVALID')
    
    def test_invalid_padding_verify(self, signature_service, private_key, public_key, sample_message):
        """Verifying with invalid padding scheme should raise error."""
        from src.exceptions import SignatureError
        
        # First sign with valid padding
        sign_result = signature_service.sign_message(sample_message, private_key, 'PSS')
        
        # Try to verify with invalid padding - this should raise SignatureError
        # or return a verification result with is_valid=False
        try:
            result = signature_service.verify_signature(
                sample_message, sign_result.signature, public_key, 'INVALID'
            )
            # If it doesn't raise, it should at least return invalid
            assert result.is_valid is False
        except SignatureError:
            pass  # Expected behavior


@pytest.mark.parametrize("key_size,padding", [
    (2048, 'PSS'),
    (2048, 'PKCS1'),
    (3072, 'PSS'),
    (4096, 'PSS'),
    (4096, 'PKCS1'),
])
class TestParameterizedSignVerify:
    """Parameterized tests for all key size and padding combinations."""
    
    @pytest.mark.slow
    def test_sign_verify_combination(self, key_manager, signature_service, sample_message, key_size, padding):
        """Test sign and verify for all combinations."""
        # Generate key pair of specified size
        private_key, public_key = key_manager.generate_key_pair(key_size)
        
        # Sign
        sign_result = signature_service.sign_message(
            sample_message, private_key, padding_scheme=padding
        )
        assert sign_result.signature is not None
        
        # Verify
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key, padding_scheme=padding
        )
        assert verify_result.is_valid is True
