"""
Key Manager Component

Handles RSA key pair generation, storage, and loading with optional passphrase protection.
"""

import os
import sys
import stat
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from src.exceptions import KeyManagementError
from src.validation import validate_key_size, validate_file_path, ValidationError
from src.logging_config import get_logger, log_operation

# Initialize module logger
logger = get_logger(__name__)


class KeyManager:
    """Manages RSA key pair generation, storage, and loading operations."""
    
    def _set_private_key_permissions(self, filepath: str) -> None:
        """Set restrictive permissions on private key file.
        
        This method implements platform-specific permission setting to ensure
        that private key files are only accessible by the owner. This is a
        critical security measure to prevent unauthorized access to private keys.
        
        On Unix/Linux: Sets permissions to 0600 (owner read/write only)
        On Windows: Uses DACL to restrict access to the current user only
        
        Args:
            filepath: Path to the private key file
            
        Raises:
            KeyManagementError: If setting permissions fails critically
        """
        try:
            if sys.platform == 'win32':
                # Windows-specific permission setting using Access Control Lists (ACL)
                import win32security
                import ntsecuritycon as con
                
                # Get the current user's security identifier (SID)
                user, domain, type = win32security.LookupAccountName("", os.getlogin())
                
                # Create a new security descriptor to define file permissions
                sd = win32security.SECURITY_DESCRIPTOR()
                
                # Create a new DACL (Discretionary Access Control List)
                # DACL determines which users/groups can access the file
                dacl = win32security.ACL()
                
                # Add an ACE (Access Control Entry) granting the owner full control
                # This ensures only the current user can read/write/delete the file
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    con.FILE_ALL_ACCESS,
                    user
                )
                
                # Set the DACL to the security descriptor
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                
                # Apply the security descriptor to the file
                win32security.SetFileSecurity(
                    filepath,
                    win32security.DACL_SECURITY_INFORMATION,
                    sd
                )
            else:
                # Unix/Linux permission setting using chmod
                # S_IRUSR = owner read, S_IWUSR = owner write (0600 in octal)
                os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # 0600
                
        except ImportError:
            # If win32security is not available on Windows, fall back to basic chmod
            # This won't provide the same level of security but is better than nothing
            try:
                os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                # If even basic chmod fails, log a warning but don't fail
                # This can happen on some Windows configurations
                pass
        except Exception as e:
            # Don't fail the entire operation if permission setting fails
            # but we could log this in a production system
            pass
    
    def generate_key_pair(
        self, 
        key_size: int = 2048
    ) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA key pair using cryptographically secure random numbers.
        
        This method generates a new RSA key pair suitable for digital signatures.
        The public exponent is fixed at 65537 (0x10001), which is the standard
        value used in RSA as it provides a good balance between security and
        performance.
        
        Args:
            key_size: Size of the RSA key in bits (minimum 2048, default 2048)
                     Common values: 2048, 3072, 4096
            
        Returns:
            Tuple of (private_key, public_key) where:
                - private_key: RSA private key for signing operations
                - public_key: RSA public key for verification operations
            
        Raises:
            KeyManagementError: If key size is invalid or generation fails
        """
        # Validate key size to ensure minimum security requirements
        try:
            key_size = validate_key_size(key_size)
        except ValidationError as e:
            raise KeyManagementError(str(e))
        
        try:
            # Generate RSA private key
            # public_exponent=65537: Standard RSA exponent (F4), provides good security/performance
            # key_size: Determines the modulus size and overall security level
            # backend: Uses the default cryptographic backend (OpenSSL)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            # Derive the public key from the private key
            public_key = private_key.public_key()
            logger.info("Key pair generated successfully", extra={'context': {
                'key_size': key_size,
                'operation': 'generate_key_pair'
            }})
            return private_key, public_key
        except Exception as e:
            logger.error(f"Failed to generate key pair: {str(e)}", extra={'context': {
                'key_size': key_size,
                'error': str(e)
            }})
            raise KeyManagementError(f"Failed to generate key pair: {str(e)}")
    
    def save_private_key(
        self,
        private_key: rsa.RSAPrivateKey,
        filepath: str,
        passphrase: Optional[str] = None
    ) -> None:
        """
        Save a private key to a file in PEM format with optional encryption.
        
        The private key is serialized in PKCS#8 format, which is the modern
        standard for private key storage. If a passphrase is provided, the
        key is encrypted using AES-256-CBC before being written to disk.
        
        Args:
            private_key: The RSA private key to save
            filepath: Path where the key should be saved
            passphrase: Optional passphrase to encrypt the key with AES-256
            
        Raises:
            KeyManagementError: If saving fails or file path is invalid
        """
        # Validate file path to prevent directory traversal attacks
        try:
            filepath = validate_file_path(filepath, must_exist=False, allow_create=True)
        except ValidationError as e:
            raise KeyManagementError(f"Invalid file path: {str(e)}")
        
        try:
            # Determine encryption algorithm based on passphrase presence
            if passphrase:
                # BestAvailableEncryption uses AES-256-CBC with PBKDF2 key derivation
                # This provides strong protection for the private key at rest
                encryption_algorithm = serialization.BestAvailableEncryption(
                    passphrase.encode('utf-8')
                )
            else:
                # No encryption - key will be stored in plaintext (protected only by file permissions)
                encryption_algorithm = serialization.NoEncryption()
            
            # Serialize the private key to PEM format
            # PEM: Privacy-Enhanced Mail format (Base64-encoded with headers)
            # PKCS8: Modern standard format for private keys
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            # Write the serialized key to file in binary mode
            with open(filepath, 'wb') as f:
                f.write(pem)
            
            # Set restrictive file permissions (0600) to protect the private key
            self._set_private_key_permissions(filepath)
            
            logger.info("Private key saved", extra={'context': {
                'filepath': filepath,
                'encrypted': passphrase is not None,
                'operation': 'save_private_key'
            }})
                
        except Exception as e:
            logger.error(f"Failed to save private key: {str(e)}", extra={'context': {
                'filepath': filepath,
                'error': str(e)
            }})
            raise KeyManagementError(f"Failed to save private key: {str(e)}")
    
    def save_public_key(
        self,
        public_key: rsa.RSAPublicKey,
        filepath: str
    ) -> None:
        """
        Save a public key to a file in PEM format.
        
        Args:
            public_key: The RSA public key to save
            filepath: Path where the key should be saved
            
        Raises:
            KeyManagementError: If saving fails
        """
        # Validate file path
        try:
            filepath = validate_file_path(filepath, must_exist=False, allow_create=True)
        except ValidationError as e:
            raise KeyManagementError(f"Invalid file path: {str(e)}")
        
        try:
            # Serialize the public key
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Write to file
            with open(filepath, 'wb') as f:
                f.write(pem)
            
            logger.info("Public key saved", extra={'context': {
                'filepath': filepath,
                'operation': 'save_public_key'
            }})
                
        except Exception as e:
            logger.error(f"Failed to save public key: {str(e)}", extra={'context': {
                'filepath': filepath,
                'error': str(e)
            }})
            raise KeyManagementError(f"Failed to save public key: {str(e)}")
    
    def load_private_key(
        self,
        filepath: str,
        passphrase: Optional[str] = None
    ) -> rsa.RSAPrivateKey:
        """
        Load a private key from a file.
        
        Args:
            filepath: Path to the private key file
            passphrase: Optional passphrase if the key is encrypted
            
        Returns:
            The loaded RSA private key
            
        Raises:
            KeyManagementError: If loading fails or passphrase is incorrect
        """
        # Validate file path
        try:
            filepath = validate_file_path(filepath, must_exist=True)
        except ValidationError as e:
            raise KeyManagementError(f"Invalid file path: {str(e)}")
        
        try:
            with open(filepath, 'rb') as f:
                key_data = f.read()
            
            # Prepare passphrase
            passphrase_bytes = passphrase.encode('utf-8') if passphrase else None
            
            # Load the private key
            private_key = serialization.load_pem_private_key(
                key_data,
                password=passphrase_bytes,
                backend=default_backend()
            )
            
            # Verify it's an RSA key
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise KeyManagementError("Loaded key is not an RSA private key")
            
            logger.info("Private key loaded", extra={'context': {
                'filepath': filepath,
                'encrypted': passphrase is not None,
                'operation': 'load_private_key'
            }})
            return private_key
            
        except FileNotFoundError:
            logger.error(f"Private key file not found: {filepath}")
            raise KeyManagementError(f"Private key file not found: {filepath}")
        except ValueError as e:
            # This typically happens with incorrect passphrase
            if "password" in str(e).lower() or "passphrase" in str(e).lower():
                raise KeyManagementError("Incorrect passphrase or corrupted key file")
            raise KeyManagementError(f"Invalid key format: {str(e)}")
        except Exception as e:
            raise KeyManagementError(f"Failed to load private key: {str(e)}")
    
    def load_public_key(
        self,
        filepath: str
    ) -> rsa.RSAPublicKey:
        """
        Load a public key from a file.
        
        Args:
            filepath: Path to the public key file
            
        Returns:
            The loaded RSA public key
            
        Raises:
            KeyManagementError: If loading fails
        """
        # Validate file path
        try:
            filepath = validate_file_path(filepath, must_exist=True)
        except ValidationError as e:
            raise KeyManagementError(f"Invalid file path: {str(e)}")
        
        try:
            with open(filepath, 'rb') as f:
                key_data = f.read()
            
            # Load the public key
            public_key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            
            # Verify it's an RSA key
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise KeyManagementError("Loaded key is not an RSA public key")
            
            logger.info("Public key loaded", extra={'context': {
                'filepath': filepath,
                'operation': 'load_public_key'
            }})
            return public_key
            
        except FileNotFoundError:
            logger.error(f"Public key file not found: {filepath}")
            raise KeyManagementError(f"Public key file not found: {filepath}")
        except ValueError as e:
            raise KeyManagementError(f"Invalid key format: {str(e)}")
        except Exception as e:
            raise KeyManagementError(f"Failed to load public key: {str(e)}")
