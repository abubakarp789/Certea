"""Custom exceptions for the Digital Signature Validator."""


class DigitalSignatureError(Exception):
    """Base exception for all digital signature related errors."""
    pass


class KeyManagementError(DigitalSignatureError):
    """Exception raised for key management related errors.
    
    Examples:
        - Invalid key file format
        - Incorrect passphrase
        - Insufficient file permissions
        - Key size too small
    """
    pass


class SignatureError(DigitalSignatureError):
    """Exception raised for signature creation errors.
    
    Examples:
        - File not found
        - Invalid private key
        - Unsupported padding scheme
    """
    pass


class VerificationError(DigitalSignatureError):
    """Exception raised for signature verification errors.
    
    Examples:
        - Signature format invalid
        - Public key mismatch
        - Message tampered
    """
    pass


class CertificateError(DigitalSignatureError):
    """Exception raised for certificate related errors.
    
    Examples:
        - Certificate expired
        - Invalid CA signature
        - Malformed certificate structure
    """
    pass
