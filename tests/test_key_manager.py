"""
Unit tests for KeyManager component
"""

import os
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from src.key_manager import KeyManager
from src.exceptions import KeyManagementError


class TestKeyManager:
    """Test suite for KeyManager class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.key_manager = KeyManager()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test files"""
        # Remove all files in temp directory
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
    
    def test_generate_key_pair_default_size(self):
        """Test key generation with default 2048-bit size"""
        private_key, public_key = self.key_manager.generate_key_pair()
        
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert private_key.key_size == 2048
        assert public_key.key_size == 2048
    
    def test_generate_key_pair_custom_size(self):
        """Test key generation with custom key size"""
        private_key, public_key = self.key_manager.generate_key_pair(key_size=3072)
        
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert private_key.key_size == 3072
        assert public_key.key_size == 3072
    
    def test_generate_key_pair_invalid_size(self):
        """Test that key generation fails with key size below 2048 bits"""
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.generate_key_pair(key_size=1024)
        
        assert "at least 2048 bits" in str(exc_info.value)
    
    def test_save_and_load_private_key_without_passphrase(self):
        """Test saving and loading private key without passphrase"""
        private_key, _ = self.key_manager.generate_key_pair()
        filepath = os.path.join(self.temp_dir, "private_key.pem")
        
        # Save the key
        self.key_manager.save_private_key(private_key, filepath)
        
        # Verify file exists
        assert os.path.exists(filepath)
        
        # Load the key
        loaded_key = self.key_manager.load_private_key(filepath)
        
        # Verify it's the same key by comparing key numbers
        assert loaded_key.private_numbers() == private_key.private_numbers()
    
    def test_save_and_load_private_key_with_passphrase(self):
        """Test saving and loading private key with passphrase encryption"""
        private_key, _ = self.key_manager.generate_key_pair()
        filepath = os.path.join(self.temp_dir, "private_key_encrypted.pem")
        passphrase = "test_passphrase_123"
        
        # Save the key with passphrase
        self.key_manager.save_private_key(private_key, filepath, passphrase=passphrase)
        
        # Verify file exists
        assert os.path.exists(filepath)
        
        # Load the key with correct passphrase
        loaded_key = self.key_manager.load_private_key(filepath, passphrase=passphrase)
        
        # Verify it's the same key
        assert loaded_key.private_numbers() == private_key.private_numbers()
    
    def test_load_private_key_wrong_passphrase(self):
        """Test that loading fails with incorrect passphrase"""
        private_key, _ = self.key_manager.generate_key_pair()
        filepath = os.path.join(self.temp_dir, "private_key_encrypted.pem")
        passphrase = "correct_passphrase"
        
        # Save the key with passphrase
        self.key_manager.save_private_key(private_key, filepath, passphrase=passphrase)
        
        # Try to load with wrong passphrase
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.load_private_key(filepath, passphrase="wrong_passphrase")
        
        assert "passphrase" in str(exc_info.value).lower()
    
    def test_load_private_key_missing_passphrase(self):
        """Test that loading fails when passphrase is required but not provided"""
        private_key, _ = self.key_manager.generate_key_pair()
        filepath = os.path.join(self.temp_dir, "private_key_encrypted.pem")
        passphrase = "required_passphrase"
        
        # Save the key with passphrase
        self.key_manager.save_private_key(private_key, filepath, passphrase=passphrase)
        
        # Try to load without passphrase
        with pytest.raises(KeyManagementError):
            self.key_manager.load_private_key(filepath)
    
    def test_save_and_load_public_key(self):
        """Test saving and loading public key"""
        _, public_key = self.key_manager.generate_key_pair()
        filepath = os.path.join(self.temp_dir, "public_key.pem")
        
        # Save the key
        self.key_manager.save_public_key(public_key, filepath)
        
        # Verify file exists
        assert os.path.exists(filepath)
        
        # Load the key
        loaded_key = self.key_manager.load_public_key(filepath)
        
        # Verify it's the same key by comparing key numbers
        assert loaded_key.public_numbers() == public_key.public_numbers()
    
    def test_private_key_file_permissions(self):
        """Test that private key files have restrictive permissions (Unix/Linux)"""
        private_key, _ = self.key_manager.generate_key_pair()
        filepath = os.path.join(self.temp_dir, "private_key.pem")
        
        # Save the key
        self.key_manager.save_private_key(private_key, filepath)
        
        # Check file permissions (only on Unix-like systems)
        if os.name != 'nt':  # Not Windows
            file_stat = os.stat(filepath)
            file_mode = file_stat.st_mode & 0o777
            assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"
    
    def test_load_private_key_file_not_found(self):
        """Test error handling when private key file doesn't exist"""
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.load_private_key("nonexistent_file.pem")
        
        assert "does not exist" in str(exc_info.value).lower() or "not found" in str(exc_info.value).lower()
    
    def test_load_public_key_file_not_found(self):
        """Test error handling when public key file doesn't exist"""
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.load_public_key("nonexistent_file.pem")
        
        assert "does not exist" in str(exc_info.value).lower() or "not found" in str(exc_info.value).lower()
    
    def test_load_private_key_invalid_format(self):
        """Test error handling when loading invalid key file"""
        filepath = os.path.join(self.temp_dir, "invalid_key.pem")
        
        # Write invalid data to file
        with open(filepath, 'w') as f:
            f.write("This is not a valid key file")
        
        # Try to load
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.load_private_key(filepath)
        
        assert "format" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()
    
    def test_load_public_key_invalid_format(self):
        """Test error handling when loading invalid public key file"""
        filepath = os.path.join(self.temp_dir, "invalid_public_key.pem")
        
        # Write invalid data to file
        with open(filepath, 'w') as f:
            f.write("This is not a valid public key file")
        
        # Try to load
        with pytest.raises(KeyManagementError) as exc_info:
            self.key_manager.load_public_key(filepath)
        
        assert "format" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()
    
    def test_key_pair_relationship(self):
        """Test that generated private and public keys are properly related"""
        private_key, public_key = self.key_manager.generate_key_pair()
        
        # The public key from the private key should match the generated public key
        derived_public_key = private_key.public_key()
        
        assert derived_public_key.public_numbers() == public_key.public_numbers()
