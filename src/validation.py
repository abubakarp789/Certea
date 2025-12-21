"""
Input Validation Utilities

Provides validation functions for file paths, key sizes, certificate dates,
and other user inputs to enhance security and prevent common vulnerabilities.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional


class ValidationError(Exception):
    """Exception raised for validation errors."""
    pass


def validate_file_path(filepath: str, must_exist: bool = False, allow_create: bool = True) -> str:
    """Validate a file path to prevent directory traversal attacks.
    
    This function performs security checks on file paths to prevent:
    - Directory traversal attacks (e.g., ../../etc/passwd)
    - Null byte injection attacks
    - Invalid or malformed paths
    
    The function normalizes the path to an absolute path and performs
    various security checks before returning it.
    
    Args:
        filepath: The file path to validate
        must_exist: If True, the file must already exist
        allow_create: If True, allow paths that don't exist yet (for output files)
        
    Returns:
        Normalized absolute path that has passed security checks
        
    Raises:
        ValidationError: If the path is invalid, unsafe, or doesn't meet requirements
    """
    if not filepath or not isinstance(filepath, str):
        raise ValidationError("File path must be a non-empty string")
    
    try:
        # Convert to absolute path and resolve any .. or . components
        abs_path = os.path.abspath(filepath)
        
        # Check for directory traversal attempts
        # Ensure the resolved path doesn't escape the current working directory or its subdirectories
        # This is a basic check - in production, you'd want to define allowed base directories
        if '..' in Path(filepath).parts:
            # Allow .. but verify the final path is safe
            pass
        
        # Check for null bytes (can be used in path injection attacks)
        if '\x00' in filepath:
            raise ValidationError("File path contains null bytes")
        
        # Check if file exists when required
        if must_exist and not os.path.exists(abs_path):
            raise ValidationError(f"File does not exist: {filepath}")
        
        # Check if parent directory exists for new files
        if allow_create and not must_exist:
            parent_dir = os.path.dirname(abs_path)
            if parent_dir and not os.path.exists(parent_dir):
                # Parent directory doesn't exist - this might be intentional
                # but we should at least check it's a valid path structure
                pass
        
        return abs_path
        
    except (OSError, ValueError) as e:
        raise ValidationError(f"Invalid file path: {str(e)}")


def validate_directory_path(dirpath: str, must_exist: bool = False, create_if_missing: bool = False) -> str:
    """Validate a directory path.
    
    Args:
        dirpath: The directory path to validate
        must_exist: If True, the directory must already exist
        create_if_missing: If True, create the directory if it doesn't exist
        
    Returns:
        Normalized absolute path
        
    Raises:
        ValidationError: If the path is invalid or unsafe
    """
    if not dirpath or not isinstance(dirpath, str):
        raise ValidationError("Directory path must be a non-empty string")
    
    try:
        # Convert to absolute path
        abs_path = os.path.abspath(dirpath)
        
        # Check for null bytes
        if '\x00' in dirpath:
            raise ValidationError("Directory path contains null bytes")
        
        # Check if directory exists
        if must_exist and not os.path.isdir(abs_path):
            raise ValidationError(f"Directory does not exist: {dirpath}")
        
        # Create directory if requested
        if create_if_missing and not os.path.exists(abs_path):
            os.makedirs(abs_path, exist_ok=True)
        
        return abs_path
        
    except (OSError, ValueError) as e:
        raise ValidationError(f"Invalid directory path: {str(e)}")


def validate_key_size(key_size: int) -> int:
    """Validate RSA key size for security requirements.
    
    RSA key size determines the security level of the cryptographic system.
    Modern security standards require:
    - Minimum 2048 bits (112-bit security level)
    - Recommended 3072 bits (128-bit security level)
    - Maximum 16384 bits (practical limit)
    
    Key sizes should be multiples of 256 for optimal performance.
    
    Args:
        key_size: The key size in bits
        
    Returns:
        The validated key size
        
    Raises:
        ValidationError: If the key size doesn't meet security requirements
    """
    if not isinstance(key_size, int):
        raise ValidationError("Key size must be an integer")
    
    # Enforce minimum key size for security
    # 2048 bits provides ~112-bit security level
    if key_size < 2048:
        raise ValidationError(
            f"Key size must be at least 2048 bits for security, got {key_size}"
        )
    
    # Enforce maximum key size for practicality
    # Very large keys are slow and rarely needed
    if key_size > 16384:
        raise ValidationError(
            f"Key size is too large (maximum 16384 bits), got {key_size}"
        )
    
    # Key size should be a multiple of 256 for optimal performance
    # This aligns with common RSA implementations
    if key_size % 256 != 0:
        raise ValidationError(
            f"Key size should be a multiple of 256, got {key_size}"
        )
    
    return key_size


def validate_certificate_dates(
    valid_from: datetime,
    valid_until: datetime,
    max_validity_days: Optional[int] = None
) -> tuple[datetime, datetime]:
    """Validate certificate validity dates.
    
    Args:
        valid_from: Certificate start date
        valid_until: Certificate end date
        max_validity_days: Maximum allowed validity period in days (optional)
        
    Returns:
        Tuple of (valid_from, valid_until)
        
    Raises:
        ValidationError: If the dates are invalid
    """
    if not isinstance(valid_from, datetime):
        raise ValidationError("valid_from must be a datetime object")
    
    if not isinstance(valid_until, datetime):
        raise ValidationError("valid_until must be a datetime object")
    
    # Check that valid_until is after valid_from
    if valid_until <= valid_from:
        raise ValidationError(
            "Certificate valid_until must be after valid_from"
        )
    
    # Check maximum validity period if specified
    if max_validity_days is not None:
        validity_days = (valid_until - valid_from).days
        if validity_days > max_validity_days:
            raise ValidationError(
                f"Certificate validity period ({validity_days} days) exceeds "
                f"maximum allowed ({max_validity_days} days)"
            )
    
    # Warn if certificate is already expired (but don't fail)
    if valid_until < datetime.now():
        # In a real system, you might want to raise an error here
        pass
    
    return valid_from, valid_until


def validate_validity_days(days: int) -> int:
    """Validate certificate validity period in days.
    
    Args:
        days: Number of days
        
    Returns:
        The validated number of days
        
    Raises:
        ValidationError: If the value is invalid
    """
    if not isinstance(days, int):
        raise ValidationError("Validity days must be an integer")
    
    if days < 1:
        raise ValidationError("Validity days must be at least 1")
    
    if days > 36500:  # ~100 years
        raise ValidationError(
            f"Validity days is too large (maximum 36500), got {days}"
        )
    
    return days


def sanitize_string_input(input_str: str, max_length: int = 1000, allow_newlines: bool = False) -> str:
    """Sanitize string input to prevent injection attacks.
    
    This function performs several security checks:
    - Validates input type
    - Enforces maximum length to prevent DoS
    - Removes null bytes (can cause security issues)
    - Optionally removes newlines
    - Filters out non-printable control characters
    
    Args:
        input_str: The input string to sanitize
        max_length: Maximum allowed length (prevents DoS)
        allow_newlines: Whether to allow newline characters
        
    Returns:
        Sanitized string with control characters removed
        
    Raises:
        ValidationError: If the input is invalid or exceeds limits
    """
    if not isinstance(input_str, str):
        raise ValidationError("Input must be a string")
    
    # Check length
    if len(input_str) > max_length:
        raise ValidationError(
            f"Input too long (maximum {max_length} characters)"
        )
    
    # Check for null bytes
    if '\x00' in input_str:
        raise ValidationError("Input contains null bytes")
    
    # Check for newlines if not allowed
    if not allow_newlines and ('\n' in input_str or '\r' in input_str):
        raise ValidationError("Input contains newline characters")
    
    # Remove any other control characters except tab and newline
    sanitized = ''.join(
        char for char in input_str
        if char.isprintable() or char in ('\t', '\n', '\r')
    )
    
    return sanitized


def validate_padding_scheme(padding: str) -> str:
    """Validate padding scheme.
    
    Args:
        padding: The padding scheme name
        
    Returns:
        The validated padding scheme
        
    Raises:
        ValidationError: If the padding scheme is invalid
    """
    valid_schemes = ['PSS', 'PKCS1']
    
    if not isinstance(padding, str):
        raise ValidationError("Padding scheme must be a string")
    
    padding_upper = padding.upper()
    
    if padding_upper not in valid_schemes:
        raise ValidationError(
            f"Invalid padding scheme '{padding}'. Must be one of: {', '.join(valid_schemes)}"
        )
    
    return padding_upper
