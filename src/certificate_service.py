"""
Certificate Service Component

Handles Certificate Authority operations and X.509-like certificate structures.
Provides functionality for signing public keys and verifying certificates.
"""

import json
from datetime import datetime, timedelta
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from src.models import Certificate
from src.exceptions import CertificateError
from src.validation import validate_certificate_dates, validate_validity_days, ValidationError


class CertificateAuthority:
    """Certificate Authority for signing and verifying certificates."""
    
    def __init__(self, ca_private_key: rsa.RSAPrivateKey, ca_public_key: rsa.RSAPublicKey, ca_name: str = "Digital Signature CA"):
        """Initialize the Certificate Authority.
        
        A Certificate Authority (CA) is a trusted entity that signs public keys
        to create certificates. This establishes a chain of trust where anyone
        who trusts the CA can trust the certificates it issues.
        
        Args:
            ca_private_key: CA's private key for signing certificates
            ca_public_key: CA's public key for verification
            ca_name: Name of the Certificate Authority (appears in certificates)
        """
        self.ca_private_key = ca_private_key
        self.ca_public_key = ca_public_key
        self.ca_name = ca_name
    
    def sign_public_key(
        self,
        public_key: rsa.RSAPublicKey,
        subject: str,
        validity_days: int = 365
    ) -> Certificate:
        """Sign a public key to create a certificate.
        
        This method creates an X.509-like certificate by:
        1. Creating a certificate structure with the public key and metadata
        2. Serializing the certificate data to a canonical format
        3. Signing the serialized data with the CA's private key
        4. Attaching the signature to the certificate
        
        The resulting certificate proves that the CA vouches for the binding
        between the subject name and the public key.
        
        Args:
            public_key: Public key to certify
            subject: Certificate subject name (e.g., "John Doe", "example.com")
            validity_days: Number of days the certificate is valid (default 365)
            
        Returns:
            Signed Certificate object containing:
                - public_key: The certified public key
                - subject: The subject name
                - issuer: The CA name
                - valid_from: Certificate start date
                - valid_until: Certificate expiration date
                - signature: CA's signature over the certificate data
            
        Raises:
            CertificateError: If certificate creation or signing fails
        """
        try:
            # Validate validity days
            try:
                validity_days = validate_validity_days(validity_days)
            except ValidationError as e:
                raise CertificateError(str(e))
            
            # Set validity period
            valid_from = datetime.now()
            valid_until = valid_from + timedelta(days=validity_days)
            
            # Validate certificate dates
            try:
                valid_from, valid_until = validate_certificate_dates(valid_from, valid_until)
            except ValidationError as e:
                raise CertificateError(str(e))
            
            # Create certificate without signature
            certificate = Certificate(
                public_key=public_key,
                subject=subject,
                issuer=self.ca_name,
                valid_from=valid_from,
                valid_until=valid_until,
                signature=b''  # Placeholder
            )
            
            # Sign the certificate using the Certificate's sign method
            certificate.sign(self.ca_private_key)
            
            return certificate
            
        except Exception as e:
            raise CertificateError(f"Failed to sign public key: {str(e)}")
    
    def verify_certificate(self, certificate: Certificate) -> bool:
        """Verify a certificate's CA signature and validity period.
        
        This method performs two critical checks:
        1. Cryptographic verification: Validates the CA's signature on the certificate
        2. Temporal verification: Checks that the current date is within the validity period
        
        Both checks must pass for the certificate to be considered valid.
        
        Args:
            certificate: Certificate to verify
            
        Returns:
            True if certificate is valid and signature is correct
            
        Raises:
            CertificateError: If certificate verification fails, including:
                - Invalid CA signature
                - Certificate expired or not yet valid
                - Malformed certificate data
        """
        try:
            # Use the Certificate's verify method
            return certificate.verify(self.ca_public_key)
                
        except ValueError as e:
            # Certificate expired or not yet valid
            raise CertificateError(str(e))
        except InvalidSignature as e:
            # Invalid CA signature
            raise CertificateError(str(e))
        except Exception as e:
            raise CertificateError(f"Certificate verification failed: {str(e)}")
