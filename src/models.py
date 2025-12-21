"""Data models for the Digital Signature Validator."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@dataclass
class SignatureResult:
    """Result of a signature operation.
    
    Attributes:
        signature: The digital signature bytes
        timestamp: When the signature was created
        message_digest: SHA-256 hash (hex) of the original message
        padding_scheme: 'PSS' or 'PKCS1'
    """
    signature: bytes
    timestamp: datetime
    message_digest: str
    padding_scheme: str
    
    def to_file(self, filepath: str) -> None:
        """Save signature result to a JSON file.
        
        Args:
            filepath: Path to save the signature result
        """
        data = {
            'signature': base64.b64encode(self.signature).decode('utf-8'),
            'timestamp': self.timestamp.isoformat(),
            'message_digest': self.message_digest,
            'padding_scheme': self.padding_scheme
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def from_file(filepath: str) -> 'SignatureResult':
        """Load signature result from a JSON file.
        
        Args:
            filepath: Path to the signature result file
            
        Returns:
            SignatureResult object
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return SignatureResult(
            signature=base64.b64decode(data['signature']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            message_digest=data['message_digest'],
            padding_scheme=data['padding_scheme']
        )


@dataclass
class VerificationResult:
    """Result of a signature verification operation.
    
    Attributes:
        is_valid: True if signature is valid
        timestamp: When verification was performed
        message_digest: SHA-256 hash (hex) of the message
        error_message: Error details if verification failed
    """
    is_valid: bool
    timestamp: datetime
    message_digest: str
    error_message: Optional[str] = None


@dataclass
class LogEntry:
    """Entry in the verification log.
    
    Attributes:
        timestamp: When the verification occurred
        message_id: First 16 chars of message hash
        signature_id: First 16 chars of signature hash
        result: Verification outcome (True/False)
        padding_scheme: 'PSS' or 'PKCS1'
    """
    timestamp: datetime
    message_id: str
    signature_id: str
    result: bool
    padding_scheme: str
    
    def to_dict(self) -> dict:
        """Convert log entry to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'message_id': self.message_id,
            'signature_id': self.signature_id,
            'result': self.result,
            'padding_scheme': self.padding_scheme
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'LogEntry':
        """Create log entry from dictionary."""
        return LogEntry(
            timestamp=datetime.fromisoformat(data['timestamp']),
            message_id=data['message_id'],
            signature_id=data['signature_id'],
            result=data['result'],
            padding_scheme=data['padding_scheme']
        )


@dataclass
class Certificate:
    """X.509-like certificate structure.
    
    Attributes:
        public_key: RSA public key
        subject: Certificate subject name
        issuer: CA name
        valid_from: Certificate validity start date
        valid_until: Certificate validity end date
        signature: CA signature over certificate data
    """
    public_key: rsa.RSAPublicKey
    subject: str
    issuer: str
    valid_from: datetime
    valid_until: datetime
    signature: bytes
    
    def _serialize_data(self) -> bytes:
        """Serialize certificate data for signing/verification.
        
        This method serializes the certificate data (excluding the signature)
        into a canonical JSON format for cryptographic operations. The
        serialization must be deterministic (always produce the same output
        for the same input) to ensure signature verification works correctly.
        
        Returns:
            Serialized certificate data as bytes
        """
        # Serialize public key to PEM format (Base64-encoded with headers)
        # This ensures the public key can be reliably reconstructed
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Create data structure without signature
        # The signature is excluded because we're creating the data to be signed
        data = {
            'public_key': public_key_pem,
            'subject': self.subject,
            'issuer': self.issuer,
            'valid_from': self.valid_from.isoformat(),
            'valid_until': self.valid_until.isoformat()
        }
        
        # Convert to JSON with sorted keys for deterministic output
        # Sorting keys ensures the same data always produces the same JSON string
        return json.dumps(data, sort_keys=True).encode('utf-8')
    
    def sign(self, ca_private_key: rsa.RSAPrivateKey) -> None:
        """Sign the certificate data with a CA private key.
        
        This method computes a signature over the serialized certificate data
        using PSS padding and SHA-256 hashing. The signature proves that the
        CA vouches for the authenticity of the certificate.
        
        The signing process:
        1. Serialize certificate data to canonical format
        2. Hash the data with SHA-256
        3. Apply PSS padding with maximum salt length
        4. Encrypt with CA's private key
        5. Store signature in certificate
        
        Args:
            ca_private_key: CA's private key for signing
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        # Serialize certificate data (excluding signature)
        cert_data = self._serialize_data()
        
        # Sign the certificate data using RSA-PSS with SHA-256
        # PSS provides better security properties than PKCS#1 v1.5
        self.signature = ca_private_key.sign(
            cert_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function
                salt_length=padding.PSS.MAX_LENGTH  # Maximum salt for optimal security
            ),
            hashes.SHA256()  # Hash algorithm
        )
    
    def verify(self, ca_public_key: rsa.RSAPublicKey) -> bool:
        """Verify the certificate signature using a CA public key.
        
        This method verifies that the certificate was signed by the CA and
        checks if the certificate is within its validity period. Both checks
        must pass for the certificate to be considered valid.
        
        The verification process:
        1. Check validity period (current time must be within valid_from and valid_until)
        2. Serialize certificate data to canonical format
        3. Verify CA's signature using RSA-PSS with SHA-256
        
        Args:
            ca_public_key: CA's public key for verification
            
        Returns:
            True if signature is valid and certificate is within validity period
            
        Raises:
            ValueError: If certificate is expired or not yet valid
            InvalidSignature: If the CA signature is invalid
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.exceptions import InvalidSignature
        
        # Check validity period against current time
        # This ensures the certificate hasn't expired and is currently valid
        current_time = datetime.now()
        if not self.is_valid(current_time):
            raise ValueError(
                f"Certificate expired or not yet valid. "
                f"Valid from {self.valid_from} to {self.valid_until}, "
                f"current time: {current_time}"
            )
        
        # Serialize certificate data (without signature)
        # Must use the same serialization method as signing
        cert_data = self._serialize_data()
        
        # Verify the CA signature using RSA-PSS
        try:
            ca_public_key.verify(
                self.signature,  # The signature to verify
                cert_data,  # The data that was signed
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),  # Same MGF as signing
                    salt_length=padding.PSS.MAX_LENGTH  # Same salt length as signing
                ),
                hashes.SHA256()  # Same hash algorithm as signing
            )
            return True
        except InvalidSignature:
            # Signature verification failed - certificate is not authentic
            raise InvalidSignature("Invalid CA signature on certificate")
    
    def is_valid(self, current_time: datetime) -> bool:
        """Check if certificate is within its validity period.
        
        Args:
            current_time: Time to check validity against
            
        Returns:
            True if certificate is valid at the given time
        """
        return self.valid_from <= current_time <= self.valid_until
    
    def to_dict(self) -> dict:
        """Convert certificate to dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of the certificate
        """
        # Serialize public key to PEM format
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return {
            'public_key': public_key_pem,
            'subject': self.subject,
            'issuer': self.issuer,
            'valid_from': self.valid_from.isoformat(),
            'valid_until': self.valid_until.isoformat(),
            'signature': base64.b64encode(self.signature).decode('utf-8')
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'Certificate':
        """Create certificate from dictionary.
        
        Args:
            data: Dictionary containing certificate data
            
        Returns:
            Certificate object
        """
        # Deserialize public key from PEM format
        public_key = serialization.load_pem_public_key(
            data['public_key'].encode('utf-8')
        )
        
        return Certificate(
            public_key=public_key,
            subject=data['subject'],
            issuer=data['issuer'],
            valid_from=datetime.fromisoformat(data['valid_from']),
            valid_until=datetime.fromisoformat(data['valid_until']),
            signature=base64.b64decode(data['signature'])
        )
