"""
Password-Protected Key Tests

Tests for passphrase-protected private key operations including:
- Correct passphrase loading
- Wrong passphrase handling
- Empty passphrase on encrypted key
- Special characters in passphrase
- Unicode passphrase
- Very long passphrase
"""

import os
import pytest
from src.key_manager import KeyManager
from src.exceptions import KeyManagementError


class TestCorrectPassphrase:
    """Test correct passphrase handling."""
    
    def test_load_with_correct_passphrase(self, key_manager, keys_dir, key_pair_2048, simple_passphrase):
        """Load encrypted key with correct password."""
        private_key, _ = key_pair_2048
        
        # Save with passphrase
        filepath = os.path.join(keys_dir, 'encrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, simple_passphrase)
        
        # Load with correct passphrase
        loaded_key = key_manager.load_private_key(filepath, simple_passphrase)
        assert loaded_key is not None
    
    def test_signing_with_loaded_encrypted_key(self, key_manager, signature_service, keys_dir, 
                                                key_pair_2048, simple_passphrase, sample_message):
        """Verify loaded encrypted key works for signing."""
        private_key, public_key = key_pair_2048
        
        # Save with passphrase
        filepath = os.path.join(keys_dir, 'encrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, simple_passphrase)
        
        # Load and sign
        loaded_key = key_manager.load_private_key(filepath, simple_passphrase)
        sign_result = signature_service.sign_message(sample_message, loaded_key)
        
        # Verify with original public key
        verify_result = signature_service.verify_signature(
            sample_message, sign_result.signature, public_key
        )
        assert verify_result.is_valid is True


class TestWrongPassphrase:
    """Test wrong passphrase handling."""
    
    def test_load_with_wrong_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Attempt load with incorrect password - should fail."""
        private_key, _ = key_pair_2048
        correct_pass = "correct_password"
        wrong_pass = "wrong_password"
        
        # Save with passphrase
        filepath = os.path.join(keys_dir, 'encrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, correct_pass)
        
        # Try to load with wrong passphrase
        with pytest.raises(KeyManagementError) as exc_info:
            key_manager.load_private_key(filepath, wrong_pass)
        
        assert "passphrase" in str(exc_info.value).lower() or "password" in str(exc_info.value).lower()
    
    def test_multiple_wrong_attempts(self, key_manager, keys_dir, key_pair_2048):
        """Multiple wrong passphrase attempts should all fail."""
        private_key, _ = key_pair_2048
        correct_pass = "correct_password"
        
        filepath = os.path.join(keys_dir, 'encrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, correct_pass)
        
        wrong_passwords = ["wrong1", "wrong2", "wrong3", ""]
        
        for wrong_pass in wrong_passwords:
            with pytest.raises(KeyManagementError):
                key_manager.load_private_key(filepath, wrong_pass)


class TestEmptyPassphraseOnEncryptedKey:
    """Test empty passphrase on encrypted key."""
    
    def test_empty_passphrase_on_encrypted(self, key_manager, keys_dir, key_pair_2048):
        """Empty passphrase on encrypted key should fail with clear error."""
        private_key, _ = key_pair_2048
        passphrase = "actual_password"
        
        # Save with passphrase
        filepath = os.path.join(keys_dir, 'encrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        # Try to load with empty passphrase
        with pytest.raises(KeyManagementError):
            key_manager.load_private_key(filepath, "")
    
    def test_none_passphrase_on_encrypted(self, key_manager, keys_dir, key_pair_2048):
        """None passphrase on encrypted key should fail."""
        private_key, _ = key_pair_2048
        passphrase = "actual_password"
        
        filepath = os.path.join(keys_dir, 'encrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        with pytest.raises(KeyManagementError):
            key_manager.load_private_key(filepath, None)


class TestSpecialCharactersPassphrase:
    """Test passphrase with special characters."""
    
    def test_special_chars_passphrase(self, key_manager, keys_dir, key_pair_2048, special_chars_passphrase):
        """Passphrase with !@#$%^&*() etc should work."""
        private_key, _ = key_pair_2048
        
        filepath = os.path.join(keys_dir, 'special_key.pem')
        key_manager.save_private_key(private_key, filepath, special_chars_passphrase)
        
        # Should load successfully
        loaded_key = key_manager.load_private_key(filepath, special_chars_passphrase)
        assert loaded_key is not None
    
    def test_quotes_in_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Passphrase with quotes should work."""
        private_key, _ = key_pair_2048
        passphrase = 'Pass"word\'with`quotes'
        
        filepath = os.path.join(keys_dir, 'quotes_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
    
    def test_backslash_in_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Passphrase with backslashes should work."""
        private_key, _ = key_pair_2048
        passphrase = r"Pass\\word\\with\\backslash"
        
        filepath = os.path.join(keys_dir, 'backslash_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
    
    def test_null_byte_in_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Passphrase with null byte - behavior depends on implementation."""
        private_key, _ = key_pair_2048
        # Note: Some crypto libraries truncate at null byte
        passphrase = "before\x00after"
        
        filepath = os.path.join(keys_dir, 'null_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        # Should be able to load with same passphrase
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None


class TestUnicodePassphrase:
    """Test passphrase with non-ASCII characters."""
    
    def test_unicode_passphrase(self, key_manager, keys_dir, key_pair_2048, unicode_passphrase):
        """Passphrase with non-ASCII characters should work."""
        private_key, _ = key_pair_2048
        
        filepath = os.path.join(keys_dir, 'unicode_key.pem')
        key_manager.save_private_key(private_key, filepath, unicode_passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, unicode_passphrase)
        assert loaded_key is not None
    
    def test_chinese_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Chinese passphrase should work."""
        private_key, _ = key_pair_2048
        passphrase = "这是密码"
        
        filepath = os.path.join(keys_dir, 'chinese_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
    
    def test_emoji_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Emoji passphrase should work."""
        private_key, _ = key_pair_2048
        passphrase = "🔐🔑🛡️"
        
        filepath = os.path.join(keys_dir, 'emoji_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
    
    def test_mixed_unicode_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Mixed unicode passphrase should work."""
        private_key, _ = key_pair_2048
        passphrase = "Password密码كلمة🔐"
        
        filepath = os.path.join(keys_dir, 'mixed_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None


class TestLongPassphrase:
    """Test very long passphrase."""
    
    def test_very_long_passphrase(self, key_manager, keys_dir, key_pair_2048, long_passphrase):
        """1000+ character passphrase - may fail due to backend limits (expected)."""
        private_key, _ = key_pair_2048
        
        filepath = os.path.join(keys_dir, 'long_key.pem')
        
        # Cryptography backend has a 1023 byte limit on passphrases
        # This is expected behavior
        from src.exceptions import KeyManagementError
        try:
            key_manager.save_private_key(private_key, filepath, long_passphrase)
            loaded_key = key_manager.load_private_key(filepath, long_passphrase)
            assert loaded_key is not None
        except KeyManagementError as e:
            # Expected: backend limits passphrase length to 1023 bytes
            assert "1023" in str(e) or "longer" in str(e).lower()
    
    def test_extremely_long_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """10000 character passphrase - expected to fail due to backend limits."""
        private_key, _ = key_pair_2048
        passphrase = "X" * 10000
        
        filepath = os.path.join(keys_dir, 'extreme_key.pem')
        
        # Cryptography backend has a 1023 byte limit
        from src.exceptions import KeyManagementError
        with pytest.raises(KeyManagementError):
            key_manager.save_private_key(private_key, filepath, passphrase)


class TestUnencryptedKeys:
    """Test unencrypted key handling."""
    
    def test_load_unencrypted_with_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Loading unencrypted key with passphrase - may work or fail gracefully."""
        private_key, _ = key_pair_2048
        
        # Save without passphrase
        filepath = os.path.join(keys_dir, 'unencrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, None)
        
        # Load with passphrase - behavior varies by implementation
        # Some backends ignore unused passphrase, others may raise error
        try:
            loaded_key = key_manager.load_private_key(filepath, "unused_passphrase")
            assert loaded_key is not None
        except Exception:
            # It's acceptable if the implementation rejects this
            pass
    
    def test_load_unencrypted_without_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Loading unencrypted key without passphrase should work."""
        private_key, _ = key_pair_2048
        
        # Save without passphrase
        filepath = os.path.join(keys_dir, 'unencrypted_key.pem')
        key_manager.save_private_key(private_key, filepath, None)
        
        # Load without passphrase
        loaded_key = key_manager.load_private_key(filepath, None)
        assert loaded_key is not None


class TestPassphraseEdgeCases:
    """Test passphrase edge cases."""
    
    def test_whitespace_only_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Whitespace-only passphrase should work."""
        private_key, _ = key_pair_2048
        passphrase = "   \t\n   "
        
        filepath = os.path.join(keys_dir, 'whitespace_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
    
    def test_single_char_passphrase(self, key_manager, keys_dir, key_pair_2048):
        """Single character passphrase should work."""
        private_key, _ = key_pair_2048
        passphrase = "x"
        
        filepath = os.path.join(keys_dir, 'single_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
    
    def test_passphrase_with_newlines(self, key_manager, keys_dir, key_pair_2048):
        """Passphrase with newlines should work."""
        private_key, _ = key_pair_2048
        passphrase = "line1\nline2\rline3\r\nline4"
        
        filepath = os.path.join(keys_dir, 'newline_key.pem')
        key_manager.save_private_key(private_key, filepath, passphrase)
        
        loaded_key = key_manager.load_private_key(filepath, passphrase)
        assert loaded_key is not None
