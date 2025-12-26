"""
Signature Service Component

Handles digital signature creation and verification using RSA with SHA-256 hashing.
Supports both PKCS#1 v1.5 (deterministic) and PSS (randomized) padding schemes.
"""

import hashlib
from datetime import datetime
from typing import Union, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from src.models import SignatureResult, VerificationResult
from src.exceptions import SignatureError, VerificationError
from src.logger_service import VerificationLogger
from src.logging_config import get_logger

# Initialize module logger
logger = get_logger(__name__)


class SignatureService:
    """Service for creating and verifying digital signatures."""
    
    def __init__(self, logger: Optional[VerificationLogger] = None):
        """Initialize the SignatureService.
        
        Args:
            logger: Optional VerificationLogger instance. If not provided, creates a default one.
        """
        self.logger = logger if logger is not None else VerificationLogger()
    
    def _get_padding_scheme(self, padding_scheme: str) -> Union[padding.PSS, padding.PKCS1v15]:
        """
        Get the appropriate padding scheme object for RSA signature operations.
        
        Two padding schemes are supported:
        
        1. PSS (Probabilistic Signature Scheme):
           - Randomized padding using a salt value
           - Provides better security properties (provably secure)
           - Recommended for new applications
           - Each signature is different even for the same message
        
        2. PKCS#1 v1.5:
           - Deterministic padding scheme
           - Same message always produces the same signature
           - Widely supported for legacy compatibility
           - Less secure than PSS but still acceptable
        
        Args:
            padding_scheme: Either 'PSS' or 'PKCS1'
            
        Returns:
            Padding scheme object configured for SHA-256
            
        Raises:
            SignatureError: If padding scheme is unsupported
        """
        if padding_scheme.upper() == 'PSS':
            # PSS padding with MGF1 mask generation function
            # MGF1: Mask Generation Function based on SHA-256
            # MAX_LENGTH: Use maximum salt length for optimal security
            return padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        elif padding_scheme.upper() == 'PKCS1':
            # PKCS#1 v1.5 padding (deterministic)
            return padding.PKCS1v15()
        else:
            raise SignatureError(
                f"Unsupported padding scheme: {padding_scheme}. Use 'PSS' or 'PKCS1'"
            )
    
    def _compute_message_digest(self, message: Union[str, bytes]) -> str:
        """
        Compute SHA-256 hash of a message.
        
        Args:
            message: Message to hash (string or bytes)
            
        Returns:
            Hexadecimal string representation of the hash
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        digest = hashlib.sha256(message).hexdigest()
        return digest
    
    def sign_message(
        self,
        message: str,
        private_key: rsa.RSAPrivateKey,
        padding_scheme: str = 'PSS'
    ) -> SignatureResult:
        """
        Sign a text message using the private key with RSA-SHA256.
        
        The signing process:
        1. Convert message to UTF-8 bytes
        2. Compute SHA-256 hash of the message
        3. Apply padding scheme (PSS or PKCS#1 v1.5)
        4. Encrypt the padded hash with the private key
        5. Return signature with metadata
        
        Args:
            message: Text message to sign
            private_key: RSA private key for signing
            padding_scheme: 'PSS' (default, recommended) or 'PKCS1'
            
        Returns:
            SignatureResult containing:
                - signature: The digital signature bytes
                - timestamp: When the signature was created
                - message_digest: SHA-256 hash of the message (hex)
                - padding_scheme: The padding scheme used
            
        Raises:
            SignatureError: If signing fails
        """
        try:
            # Convert message to bytes using UTF-8 encoding
            message_bytes = message.encode('utf-8')
            
            # Compute SHA-256 hash of the message
            # This creates a fixed-size digest regardless of message length
            message_digest = self._compute_message_digest(message_bytes)
            
            # Get the configured padding scheme object
            padding_obj = self._get_padding_scheme(padding_scheme)
            
            # Sign the message using RSA with SHA-256
            # The cryptography library handles:
            # 1. Hashing the message with SHA-256
            # 2. Applying the padding scheme
            # 3. Encrypting with the private key
            signature = private_key.sign(
                message_bytes,
                padding_obj,
                hashes.SHA256()
            )
            
            # Create result with timestamp for audit trail
            result = SignatureResult(
                signature=signature,
                timestamp=datetime.now(),
                message_digest=message_digest,
                padding_scheme=padding_scheme.upper()
            )
            
            return result
            
        except SignatureError:
            raise
        except Exception as e:
            logger.error(f"Failed to sign message: {str(e)}", extra={'context': {
                'operation': 'sign_message',
                'error': str(e)
            }})
            raise SignatureError(f"Failed to sign message: {str(e)}")

    def sign_file(
        self,
        filepath: str,
        private_key: rsa.RSAPrivateKey,
        padding_scheme: str = 'PSS'
    ) -> SignatureResult:
        """
        Sign a file using the private key.
        
        Args:
            filepath: Path to the file to sign
            private_key: RSA private key for signing
            padding_scheme: 'PSS' (default) or 'PKCS1'
            
        Returns:
            SignatureResult containing signature and metadata
            
        Raises:
            SignatureError: If file not found or signing fails
        """
        try:
            # Read file contents
            with open(filepath, 'rb') as f:
                file_contents = f.read()
            
            # Compute message digest
            message_digest = self._compute_message_digest(file_contents)
            
            # Get padding scheme
            padding_obj = self._get_padding_scheme(padding_scheme)
            
            # Sign the file contents
            signature = private_key.sign(
                file_contents,
                padding_obj,
                hashes.SHA256()
            )
            
            # Create result with timestamp
            result = SignatureResult(
                signature=signature,
                timestamp=datetime.now(),
                message_digest=message_digest,
                padding_scheme=padding_scheme.upper()
            )
            
            logger.info("File signed successfully", extra={'context': {
                'operation': 'sign_file',
                'filepath': filepath,
                'padding': padding_scheme.upper(),
                'message_digest': message_digest[:16] + '...'
            }})
            
            return result
            
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            raise SignatureError(f"File not found: {filepath}")
        except SignatureError:
            raise
        except Exception as e:
            logger.error(f"Failed to sign file: {str(e)}", extra={'context': {
                'operation': 'sign_file',
                'filepath': filepath,
                'error': str(e)
            }})
            raise SignatureError(f"Failed to sign file: {str(e)}")
    
    def verify_signature(
        self,
        message: str,
        signature: bytes,
        public_key: rsa.RSAPublicKey,
        padding_scheme: str = 'PSS'
    ) -> VerificationResult:
        """
        Verify a signature for a text message using RSA-SHA256.
        
        The verification process:
        1. Convert message to UTF-8 bytes
        2. Compute SHA-256 hash of the message
        3. Decrypt the signature using the public key
        4. Compare the decrypted hash with the computed hash
        5. Log the verification attempt
        
        This method automatically logs all verification attempts to the
        verification logger for audit trail purposes.
        
        Args:
            message: Original text message that was signed
            signature: Digital signature bytes to verify
            public_key: RSA public key corresponding to the signing private key
            padding_scheme: 'PSS' (default) or 'PKCS1' - must match signing scheme
            
        Returns:
            VerificationResult containing:
                - is_valid: True if signature is valid, False otherwise
                - timestamp: When verification was performed
                - message_digest: SHA-256 hash of the message
                - error_message: Details if verification failed
        """
        try:
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            # Compute message digest
            message_digest = self._compute_message_digest(message_bytes)
            
            # Compute signature hash for logging
            signature_hash = hashlib.sha256(signature).hexdigest()
            
            # Get padding scheme
            padding_obj = self._get_padding_scheme(padding_scheme)
            
            # Attempt to verify the signature
            try:
                public_key.verify(
                    signature,
                    message_bytes,
                    padding_obj,
                    hashes.SHA256()
                )
                # Verification succeeded
                result = VerificationResult(
                    is_valid=True,
                    timestamp=datetime.now(),
                    message_digest=message_digest,
                    error_message=None
                )
            except InvalidSignature:
                # Verification failed
                result = VerificationResult(
                    is_valid=False,
                    timestamp=datetime.now(),
                    message_digest=message_digest,
                    error_message="Signature verification failed: signature does not match message"
                )
            
            # Log the verification attempt
            self.logger.log_verification(
                message_id=message_digest[:16],
                signature_id=signature_hash[:16],
                result=result.is_valid,
                timestamp=result.timestamp,
                padding_scheme=padding_scheme.upper()
            )
            
            return result
                
        except VerificationError:
            raise
        except Exception as e:
            # Return verification failure for unexpected errors
            result = VerificationResult(
                is_valid=False,
                timestamp=datetime.now(),
                message_digest="",
                error_message=f"Verification error: {str(e)}"
            )
            
            # Log the failed verification attempt
            try:
                signature_hash = hashlib.sha256(signature).hexdigest()
                self.logger.log_verification(
                    message_id="error",
                    signature_id=signature_hash[:16],
                    result=False,
                    timestamp=result.timestamp,
                    padding_scheme=padding_scheme.upper()
                )
            except:
                pass  # Don't fail if logging fails
            
            return result
    
    def verify_file_signature(
        self,
        filepath: str,
        signature: bytes,
        public_key: rsa.RSAPublicKey,
        padding_scheme: str = 'PSS'
    ) -> VerificationResult:
        """
        Verify a signature for a file.
        
        Args:
            filepath: Path to the file to verify
            signature: Digital signature to verify
            public_key: RSA public key for verification
            padding_scheme: 'PSS' (default) or 'PKCS1'
            
        Returns:
            VerificationResult with verification outcome
            
        Raises:
            VerificationError: If file not found
        """
        try:
            # Read file contents
            try:
                with open(filepath, 'rb') as f:
                    file_contents = f.read()
            except FileNotFoundError:
                raise VerificationError(f"File not found: {filepath}")
            
            # Compute message digest
            message_digest = self._compute_message_digest(file_contents)
            
            # Compute signature hash for logging
            signature_hash = hashlib.sha256(signature).hexdigest()
            
            # Get padding scheme
            padding_obj = self._get_padding_scheme(padding_scheme)
            
            # Attempt to verify the signature
            try:
                public_key.verify(
                    signature,
                    file_contents,
                    padding_obj,
                    hashes.SHA256()
                )
                # Verification succeeded
                result = VerificationResult(
                    is_valid=True,
                    timestamp=datetime.now(),
                    message_digest=message_digest,
                    error_message=None
                )
            except InvalidSignature:
                # Verification failed
                result = VerificationResult(
                    is_valid=False,
                    timestamp=datetime.now(),
                    message_digest=message_digest,
                    error_message="Signature verification failed: signature does not match file"
                )
            
            # Log the verification attempt
            self.logger.log_verification(
                message_id=message_digest[:16],
                signature_id=signature_hash[:16],
                result=result.is_valid,
                timestamp=result.timestamp,
                padding_scheme=padding_scheme.upper()
            )
            
            return result
                
        except VerificationError:
            raise
        except Exception as e:
            # Return verification failure for unexpected errors
            result = VerificationResult(
                is_valid=False,
                timestamp=datetime.now(),
                message_digest="",
                error_message=f"Verification error: {str(e)}"
            )
            
            # Log the failed verification attempt
            try:
                signature_hash = hashlib.sha256(signature).hexdigest()
                self.logger.log_verification(
                    message_id="error",
                    signature_id=signature_hash[:16],
                    result=False,
                    timestamp=result.timestamp,
                    padding_scheme=padding_scheme.upper()
                )
            except:
                pass  # Don't fail if logging fails
            
            return result
