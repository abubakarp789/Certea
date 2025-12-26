"""
Edge Case Tests

Tests for handling edge cases including:
- Empty file signing
- Large file signing
- Corrupted signatures
- Invalid PEM format
- Empty messages
- Unicode messages
- Binary data
"""

import os
import pytest
from src.key_manager import KeyManager
from src.signature_service import SignatureService
from src.exceptions import KeyManagementError, SignatureError


class TestEmptyFileHandling:
    """Test cases for empty file operations."""
    
    def test_sign_empty_file(self, signature_service, private_key, empty_file_path):
        """Sign a 0-byte file - should handle gracefully."""
        result = signature_service.sign_file(empty_file_path, private_key)
        assert result.signature is not None
        assert len(result.signature) > 0
        assert result.message_digest is not None
    
    def test_verify_empty_file_signature(self, signature_service, private_key, public_key, empty_file_path):
        """Verify signature of an empty file."""
        # Sign empty file
        sign_result = signature_service.sign_file(empty_file_path, private_key)
        
        # Verify
        verify_result = signature_service.verify_file_signature(
            empty_file_path, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True


class TestLargeFileHandling:
    """Test cases for large file operations."""
    
    @pytest.mark.slow
    def test_sign_large_file(self, signature_service, private_key, large_file_path):
        """Sign a large file (10MB) - should work with reasonable memory usage."""
        result = signature_service.sign_file(large_file_path, private_key)
        assert result.signature is not None
        assert len(result.signature) > 0
        assert result.message_digest is not None
    
    @pytest.mark.slow
    def test_verify_large_file_signature(self, signature_service, private_key, public_key, large_file_path):
        """Verify signature of a large file."""
        # Sign large file
        sign_result = signature_service.sign_file(large_file_path, private_key)
        
        # Verify
        verify_result = signature_service.verify_file_signature(
            large_file_path, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True


class TestCorruptedSignature:
    """Test cases for corrupted/tampered signatures."""
    
    def test_verify_corrupted_signature(self, signature_service, public_key, sample_message, corrupted_signature):
        """Verify with tampered signature bytes - should return is_valid=False."""
        result = signature_service.verify_signature(
            sample_message, corrupted_signature, public_key
        )
        assert result.is_valid is False
        assert result.error_message is not None
    
    def test_verify_truncated_signature(self, signature_service, private_key, public_key, sample_message):
        """Verify with truncated signature."""
        # Generate valid signature
        sign_result = signature_service.sign_message(sample_message, private_key)
        
        # Truncate signature
        truncated = sign_result.signature[:len(sign_result.signature) // 2]
        
        # Verify
        result = signature_service.verify_signature(
            sample_message, truncated, public_key
        )
        assert result.is_valid is False
    
    def test_verify_modified_signature(self, signature_service, private_key, public_key, sample_message):
        """Verify with modified signature (bit flip)."""
        # Generate valid signature
        sign_result = signature_service.sign_message(sample_message, private_key)
        
        # Modify one byte
        sig_list = list(sign_result.signature)
        sig_list[0] = (sig_list[0] + 1) % 256
        modified = bytes(sig_list)
        
        # Verify
        result = signature_service.verify_signature(
            sample_message, modified, public_key
        )
        assert result.is_valid is False
    
    def test_verify_empty_signature(self, signature_service, public_key, sample_message):
        """Verify with empty signature."""
        result = signature_service.verify_signature(
            sample_message, b'', public_key
        )
        assert result.is_valid is False


class TestInvalidPEMFormat:
    """Test cases for invalid PEM format handling."""
    
    def test_load_invalid_pem_private_key(self, key_manager, invalid_pem_file):
        """Load malformed private key file - should raise KeyManagementError."""
        with pytest.raises(KeyManagementError):
            key_manager.load_private_key(invalid_pem_file)
    
    def test_load_invalid_pem_public_key(self, key_manager, invalid_pem_file):
        """Load malformed public key file - should raise KeyManagementError."""
        with pytest.raises(KeyManagementError):
            key_manager.load_public_key(invalid_pem_file)
    
    def test_load_nonexistent_key_file(self, key_manager):
        """Load non-existent key file."""
        with pytest.raises(KeyManagementError):
            key_manager.load_private_key('/nonexistent/path/key.pem')
    
    def test_load_corrupted_base64_key(self, key_manager, temp_dir):
        """Load key file with corrupted base64 content."""
        filepath = os.path.join(temp_dir, 'corrupted.pem')
        with open(filepath, 'w') as f:
            f.write("-----BEGIN PRIVATE KEY-----\n")
            f.write("NOT!VALID!BASE64!CONTENT!!!\n")
            f.write("-----END PRIVATE KEY-----\n")
        
        with pytest.raises(KeyManagementError):
            key_manager.load_private_key(filepath)


class TestEmptyMessage:
    """Test cases for empty message signing."""
    
    def test_sign_empty_message(self, signature_service, private_key, empty_message):
        """Sign empty string - should handle gracefully."""
        result = signature_service.sign_message(empty_message, private_key)
        assert result.signature is not None
        assert len(result.signature) > 0
    
    def test_verify_empty_message(self, signature_service, private_key, public_key, empty_message):
        """Verify signature of empty message."""
        sign_result = signature_service.sign_message(empty_message, private_key)
        verify_result = signature_service.verify_signature(
            empty_message, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True


class TestUnicodeMessages:
    """Test cases for unicode message handling."""
    
    def test_sign_unicode_message(self, signature_service, private_key, sample_unicode_message):
        """Sign messages with emojis/special chars - should work correctly."""
        result = signature_service.sign_message(sample_unicode_message, private_key)
        assert result.signature is not None
        assert len(result.signature) > 0
    
    def test_verify_unicode_message(self, signature_service, private_key, public_key, sample_unicode_message):
        """Verify signature of unicode message."""
        sign_result = signature_service.sign_message(sample_unicode_message, private_key)
        verify_result = signature_service.verify_signature(
            sample_unicode_message, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True
    
    def test_sign_chinese_message(self, signature_service, private_key):
        """Sign message with Chinese characters."""
        message = "这是一条中文测试消息"
        result = signature_service.sign_message(message, private_key)
        assert result.signature is not None
    
    def test_sign_arabic_message(self, signature_service, private_key):
        """Sign message with Arabic characters."""
        message = "هذه رسالة اختبار عربية"
        result = signature_service.sign_message(message, private_key)
        assert result.signature is not None
    
    def test_sign_emoji_only_message(self, signature_service, private_key):
        """Sign message with only emojis."""
        message = "🔐🔑✅❌🛡️📜🏛️"
        result = signature_service.sign_message(message, private_key)
        assert result.signature is not None


class TestBinaryData:
    """Test cases for binary data handling."""
    
    def test_sign_binary_file(self, signature_service, private_key, binary_file_path):
        """Sign raw binary content file - should work correctly."""
        result = signature_service.sign_file(binary_file_path, private_key)
        assert result.signature is not None
        assert len(result.signature) > 0
    
    def test_verify_binary_file(self, signature_service, private_key, public_key, binary_file_path):
        """Verify signature of binary file."""
        sign_result = signature_service.sign_file(binary_file_path, private_key)
        verify_result = signature_service.verify_file_signature(
            binary_file_path, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True
    
    def test_binary_file_modification_detected(self, signature_service, private_key, public_key, temp_dir):
        """Verify modified binary file is detected."""
        # Create original file
        filepath = os.path.join(temp_dir, 'test.bin')
        with open(filepath, 'wb') as f:
            f.write(bytes(range(256)))
        
        # Sign it
        sign_result = signature_service.sign_file(filepath, private_key)
        
        # Modify the file
        with open(filepath, 'wb') as f:
            f.write(bytes(range(255, -1, -1)))  # Reversed
        
        # Verify should fail
        verify_result = signature_service.verify_file_signature(
            filepath, sign_result.signature, public_key
        )
        assert verify_result.is_valid is False


class TestMessageTampering:
    """Test cases for message tampering detection."""
    
    def test_detect_message_modification(self, signature_service, private_key, public_key):
        """Verify modified message is detected."""
        original = "Original message"
        modified = "Modified message"
        
        sign_result = signature_service.sign_message(original, private_key)
        verify_result = signature_service.verify_signature(
            modified, sign_result.signature, public_key
        )
        assert verify_result.is_valid is False
    
    def test_detect_whitespace_modification(self, signature_service, private_key, public_key):
        """Verify whitespace changes are detected."""
        original = "Hello World"
        modified = "Hello  World"  # Extra space
        
        sign_result = signature_service.sign_message(original, private_key)
        verify_result = signature_service.verify_signature(
            modified, sign_result.signature, public_key
        )
        assert verify_result.is_valid is False
    
    def test_detect_case_modification(self, signature_service, private_key, public_key):
        """Verify case changes are detected."""
        original = "Hello World"
        modified = "hello world"  # Lowercase
        
        sign_result = signature_service.sign_message(original, private_key)
        verify_result = signature_service.verify_signature(
            modified, sign_result.signature, public_key
        )
        assert verify_result.is_valid is False


class TestLargeMessage:
    """Test cases for large message handling."""
    
    @pytest.mark.slow
    def test_sign_large_message(self, signature_service, private_key, large_message):
        """Sign a large message (1MB)."""
        result = signature_service.sign_message(large_message, private_key)
        assert result.signature is not None
        assert len(result.signature) > 0
    
    @pytest.mark.slow
    def test_verify_large_message(self, signature_service, private_key, public_key, large_message):
        """Verify signature of a large message."""
        sign_result = signature_service.sign_message(large_message, private_key)
        verify_result = signature_service.verify_signature(
            large_message, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True
